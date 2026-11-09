//! Capture Session： レコーダの中核（プラットフォーム非依存部分）。
//!
//! 1 セッションは「Trace ファイル 1 本」と「Ring の集合」を所有し、
//! 状態機械（Created → Recording → Stopped → Finished）で進む。
//! 各 Ring は、Agent が Control 領域を初期化した（Magic が現れた）
//! 時点で DrainWorker を遅延生成して回収を始める。未初期化の Ring を
//! 先に検証すると BadMagic で恒久停止してしまうため、この遅延が要る。
//!
//! 異常系の扱い:
//! - Ring の共有メモリに矛盾が出たら、その Ring だけを止めて
//!   Event Integrity = Lost とし、他の Ring と Trace の確定は続ける。
//! - 終了不明（Enter のみ）の呼出は finalize_thread で Loss 化する。
//!   対象プロセスが途中で死んでも、回収済み分はそのまま Trace に残る。
//! - 引数値列として復号できない Payload は Blob として保持し、
//!   Semantic Completeness の劣化として数える（trace_convert の方針）。
//!
//! プロセスの起動・アタッチと DLL 注入は Windows 側の
//! `recorder_launch`（cfg(windows)）が担い、本モジュールは
//! 「Mapping が用意された後」の回収と Trace 化に集中する。

use crate::trace_convert::{ArgsConversionStats, TraceBatchContext, TraceRecorder};
use crate::{DrainWorker, IntegrityLevel, IntegrityReport, RingIdentity};
use shirusu_hook::api as hook_api;
use shirusu_trace::proto::CaptureEnvironment;
use shirusu_transport::layout;
use shirusu_transport::ring::SharedRegion;
use shirusu_transport::RingConfig;
#[cfg(windows)]
use shirusu_transport_win::SharedMapping;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SessionError {
    /// 状態機械に反する操作（開始前の poll、二重の start など）。
    InvalidTransition {
        from: &'static str,
        op: &'static str,
    },
    /// 設定の不整合（Session ID の不一致など）。
    Config(String),
    Io(std::io::Error),
    Trace(shirusu_trace::TraceError),
    #[cfg(windows)]
    Win(shirusu_transport_win::WinError),
    /// DLL 注入や初期化の失敗（Windows ドライバ側）。
    Injection(String),
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, op } => {
                write!(f, "invalid session operation {op} in state {from}")
            }
            Self::Config(m) => write!(f, "session config error: {m}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Trace(e) => write!(f, "trace error: {e}"),
            #[cfg(windows)]
            Self::Win(e) => write!(f, "windows error: {e}"),
            Self::Injection(m) => write!(f, "injection failed: {m}"),
        }
    }
}
impl std::error::Error for SessionError {}
impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<shirusu_trace::TraceError> for SessionError {
    fn from(e: shirusu_trace::TraceError) -> Self {
        Self::Trace(e)
    }
}
#[cfg(windows)]
impl From<shirusu_transport_win::WinError> for SessionError {
    fn from(e: shirusu_transport_win::WinError) -> Self {
        Self::Win(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Recording,
    Stopped,
    Finished,
}
impl SessionState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Recording => "Recording",
            Self::Stopped => "Stopped",
            Self::Finished => "Finished",
        }
    }
}

/// Capture Session の設定。environment の SessionMetadata.session_id は
/// `session_id` と一致させること（TraceWriter が Header に使う）。
#[derive(Debug, Clone)]
pub struct CaptureSessionConfig {
    pub session_id: u64,
    pub ring_config: RingConfig,
    pub environment: CaptureEnvironment,
    pub qpc_frequency: u64,
}

/// Ring 1 本の登録仕様。thread_id は Trace 内の Writer ID（Ring の
/// 通し番号でよい。Descriptor は OS のスレッド ID を運ばない）。
#[derive(Debug, Clone, Copy)]
pub struct RingSpec {
    pub process_id: u64,
    pub raw_pid: u32,
    pub thread_id: u64,
    /// Agent 側 Slot の Generation（初期 Pool は 1、Bootstrap で
    /// 追加された Slot は 0 = EXPANDED_SLOT_GENERATION）。
    pub expected_generation: u64,
}

/// Ring の裏付けメモリ。
enum RingMapping {
    /// Host が所有する共有領域（同一プロセスの記録用）。
    Local(Box<SharedRegion>),
    /// 呼び出し側が所有する領域への借用ビュー。テストと同一プロセス
    /// ホスティング用。存続期間は呼び出し側が保証する。
    Borrowed { base: *mut u8, len: usize },
    /// Windows の File Mapping（Host が作成し対象へ複製したもの）。
    #[cfg(windows)]
    Win(SharedMapping),
}
impl RingMapping {
    fn base(&self) -> *mut u8 {
        match self {
            Self::Local(r) => r.base(),
            Self::Borrowed { base, .. } => *base,
            #[cfg(windows)]
            Self::Win(m) => m.as_ptr(),
        }
    }
    fn len(&self) -> usize {
        match self {
            Self::Local(r) => r.config.required_len(),
            Self::Borrowed { len, .. } => *len,
            #[cfg(windows)]
            Self::Win(m) => m.len(),
        }
    }
    fn as_slice(&self) -> &[u8] {
        // SAFETY: どの裏付けでも base から len 分は有効な共有領域。
        unsafe { std::slice::from_raw_parts(self.base(), self.len()) }
    }
    /// Agent が Control 領域を初期化済みか（Magic の出現で判定する）。
    fn agent_initialized(&self) -> bool {
        let s = self.as_slice();
        s.len() >= layout::OFF_MAGIC + 8
            && u64::from_le_bytes(
                s[layout::OFF_MAGIC..layout::OFF_MAGIC + 8]
                    .try_into()
                    .unwrap(),
            ) == layout::MAGIC
    }
}

struct RingEndpoint {
    spec: RingSpec,
    mapping: RingMapping,
    /// space_available 通知（Host → Agent）。回収で空きができたら鳴らす。
    space_notify: Option<std::sync::Arc<shirusu_transport_win::RingNotify>>,
    worker: Option<DrainWorker>,
    /// 完全性喪失で停止したか（worker.is_stopped と同期させる）。
    stopped: bool,
    events: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollStats {
    pub events: usize,
    pub active_rings: usize,
    pub pending_rings: usize,
    pub stopped_rings: usize,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub trace_path: PathBuf,
    pub total_events: u64,
    pub total_loss_records: u64,
    pub rings_total: usize,
    pub rings_active: usize,
    pub rings_never_initialized: usize,
    pub rings_stopped: usize,
    pub args_attached: usize,
    pub args_fallback_blob: usize,
    /// Agent DLL が報告したフック設置結果 (設置数, 欠落数)。
    /// プロセス間記録で DLL から読み戻せた場合のみ Some
    /// (レビュー #4 の #8)。
    pub hook_coverage: Option<(usize, usize)>,
    pub integrity: IntegrityReport,
}

fn level_severity(l: IntegrityLevel) -> u8 {
    match l {
        IntegrityLevel::Complete => 0,
        IntegrityLevel::Unknown => 1,
        IntegrityLevel::Degraded => 2,
        IntegrityLevel::Lost => 3,
    }
}
fn worst(a: IntegrityLevel, b: IntegrityLevel) -> IntegrityLevel {
    if level_severity(a) >= level_severity(b) {
        a
    } else {
        b
    }
}
fn combine_reports(reports: &[IntegrityReport]) -> IntegrityReport {
    let mut out = IntegrityReport::default();
    for r in reports {
        out.capture_coverage = worst(out.capture_coverage, r.capture_coverage);
        out.event_integrity = worst(out.event_integrity, r.event_integrity);
        out.semantic_completeness = worst(out.semantic_completeness, r.semantic_completeness);
        out.finalized = out.finalized && r.finalized;
        out.notes.extend(r.notes.iter().cloned());
    }
    out
}

pub struct CaptureSession {
    config: CaptureSessionConfig,
    recorder: TraceRecorder<File>,
    rings: Vec<RingEndpoint>,
    state: SessionState,
    trace_path: PathBuf,
    args_stats: ArgsConversionStats,
    /// 同一プロセス記録の場合に呼び出し側が知らせる Slot 不足数。
    /// プロセス間では Agent 内カウンタに留まり Host からは見えない
    /// （Phase 3 の制約として summary の注記にも残す）。
    coverage_missing_calls: u64,
    /// Agent DLL が Bootstrap 経由で報告したフック設置結果
    /// (設置数, 欠落数)。プロセス間記録でのみ設定される。
    hook_coverage: Option<(usize, usize)>,
}

impl CaptureSession {
    /// Trace ファイルを作り、フック Schema を登録してセッションを用意する。
    pub fn create_file(
        path: impl AsRef<Path>,
        config: CaptureSessionConfig,
    ) -> Result<Self, SessionError> {
        if config.environment.session.session_id != config.session_id {
            return Err(SessionError::Config(format!(
                "environment session_id {} != config session_id {}",
                config.environment.session.session_id, config.session_id
            )));
        }
        let file = File::create(path.as_ref())?;
        let mut recorder = TraceRecorder::from_environment(file, config.environment.clone())?;
        for def in hook_api::all_schemas() {
            recorder.register_schema(def)?;
        }
        Ok(Self {
            config,
            recorder,
            rings: Vec::new(),
            state: SessionState::Created,
            trace_path: path.as_ref().to_path_buf(),
            args_stats: ArgsConversionStats::default(),
            coverage_missing_calls: 0,
            hook_coverage: None,
        })
    }

    pub fn state(&self) -> SessionState {
        self.state
    }
    pub fn trace_path(&self) -> &Path {
        &self.trace_path
    }
    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }
    /// 同一プロセス記録で判明している Slot 不足数を知らせる
    /// （Capture Coverage の劣化として Finalization に写す）。
    pub fn set_coverage_missing_calls(&mut self, n: u64) {
        self.coverage_missing_calls = n;
    }

    /// Agent DLL が報告したフック設置結果を知らせる (レビュー #4 の
    /// #8)。欠落がある場合は Capture Coverage の劣化として
    /// Finalization に写す。対象 API を 1 つもインポートしていない
    /// 正常なアプリは「0 件設置・全件欠落」としてここへ届く。
    pub fn set_hook_coverage(&mut self, hooked: usize, missing: usize) {
        self.hook_coverage = Some((hooked, missing));
    }

    fn ensure_state(&self, want: SessionState, op: &'static str) -> Result<(), SessionError> {
        if self.state == want {
            Ok(())
        } else {
            Err(SessionError::InvalidTransition {
                from: self.state.name(),
                op,
            })
        }
    }

    /// Host 所有の共有領域を Ring として登録する（同一プロセス用）。
    pub fn add_local_ring(
        &mut self,
        region: SharedRegion,
        spec: RingSpec,
    ) -> Result<usize, SessionError> {
        self.add_ring(RingMapping::Local(Box::new(region)), spec, None)
    }

    /// 呼び出し側所有の領域を借用ビューで登録する。
    ///
    /// # Safety
    /// `base` は `len` 分の共有領域を指し、セッションが終わるまで
    /// 有効であること。Agent 側の領域（Agent が保持する SharedRegion）を
    /// Host と同一プロセスで回収する場合に使う。
    pub unsafe fn add_borrowed_ring(
        &mut self,
        base: *mut u8,
        len: usize,
        spec: RingSpec,
    ) -> Result<usize, SessionError> {
        self.add_ring(RingMapping::Borrowed { base, len }, spec, None)
    }

    /// Windows の File Mapping を Ring として登録する。space_available
    /// 通知（対象へ複製したのと同じ RingNotify）を渡すと、回収時に
    /// 空き通知を結線する。
    #[cfg(windows)]
    pub fn add_shared_mapping(
        &mut self,
        mapping: SharedMapping,
        spec: RingSpec,
        space_notify: Option<std::sync::Arc<shirusu_transport_win::RingNotify>>,
    ) -> Result<usize, SessionError> {
        self.add_ring(RingMapping::Win(mapping), spec, space_notify)
    }

    fn add_ring(
        &mut self,
        mapping: RingMapping,
        spec: RingSpec,
        space_notify: Option<std::sync::Arc<shirusu_transport_win::RingNotify>>,
    ) -> Result<usize, SessionError> {
        self.ensure_state(SessionState::Created, "add_ring")?;
        if mapping.len() < self.config.ring_config.required_len() {
            return Err(SessionError::Config(format!(
                "ring mapping too small: {} < {}",
                mapping.len(),
                self.config.ring_config.required_len()
            )));
        }
        let index = self.rings.len();
        self.rings.push(RingEndpoint {
            spec,
            mapping,
            space_notify,
            worker: None,
            stopped: false,
            events: 0,
        });
        Ok(index)
    }

    /// 記録開始。以後は Ring の追加はできない。
    pub fn start(&mut self) -> Result<(), SessionError> {
        self.ensure_state(SessionState::Created, "start")?;
        self.state = SessionState::Recording;
        Ok(())
    }

    /// 全 Ring を 1 回ずつ回収し、Trace へ変換して書く。
    pub fn poll_once(&mut self) -> Result<PollStats, SessionError> {
        self.ensure_state(SessionState::Recording, "poll_once")?;
        let mut stats = PollStats::default();
        for ring in &mut self.rings {
            if ring.worker.is_none() {
                if !ring.mapping.agent_initialized() {
                    stats.pending_rings += 1;
                    continue;
                }
                // SAFETY: mapping は RingConfig 分の共有領域を指し、
                // セッションの存続期間中有効（add_ring の契約）。
                let mut worker = unsafe {
                    DrainWorker::new(
                        ring.mapping.base(),
                        self.config.ring_config,
                        ring.spec.expected_generation,
                    )
                };
                worker.set_identity(RingIdentity::new(
                    crate::ProcessInstanceId(ring.spec.process_id),
                    crate::RingId(ring.spec.thread_id),
                    ring.spec.expected_generation,
                ));
                ring.worker = Some(worker);
            }
            let worker = ring.worker.as_mut().expect("worker just ensured");
            if worker.is_stopped() {
                ring.stopped = true;
                stats.stopped_rings += 1;
                continue;
            }
            let batch = match &ring.space_notify {
                Some(notify) => {
                    let notify = std::sync::Arc::clone(notify);
                    worker.drain_all_with_space_notify(move || {
                        let _ = notify.notify_space();
                    })
                }
                None => worker.drain_all(),
            };
            if worker.is_stopped() {
                ring.stopped = true;
                stats.stopped_rings += 1;
            }
            if !batch.events.is_empty() {
                let ctx = TraceBatchContext {
                    session_id: self.config.session_id,
                    process_id: ring.spec.process_id,
                    raw_pid: ring.spec.raw_pid,
                    thread_id: ring.spec.thread_id,
                    qpc_frequency: self.config.qpc_frequency,
                };
                let s = self.recorder.record_batch_with_args(&ctx, &batch.events)?;
                self.args_stats.args_attached += s.args_attached;
                self.args_stats.args_fallback_blob += s.args_fallback_blob;
                ring.events += batch.events.len() as u64;
                stats.events += batch.events.len();
            }
            if ring.worker.as_ref().is_some_and(|w| !w.is_stopped()) {
                stats.active_rings += 1;
            }
        }
        Ok(stats)
    }

    /// 記録を止め、最終回収・Loss 確定・Finalization までを行って
    /// Trace を閉じる。Created（未開始）からでも呼べ、その場合は
    /// 空の Trace が確定する。
    pub fn stop(mut self) -> Result<SessionSummary, SessionError> {
        if self.state == SessionState::Recording {
            // 最終回収： 残っているイベントを可能な限り拾う
            let _ = self.poll_once()?;
            self.state = SessionState::Stopped;
        } else if self.state == SessionState::Created {
            self.state = SessionState::Stopped;
        } else {
            return Err(SessionError::InvalidTransition {
                from: self.state.name(),
                op: "stop",
            });
        }
        let mut reports = Vec::new();
        let mut total_loss_records = 0u64;
        let mut rings_active = 0usize;
        let mut rings_never = 0usize;
        let mut rings_stopped = 0usize;
        for ring in &mut self.rings {
            let Some(worker) = ring.worker.as_mut() else {
                rings_never += 1;
                continue;
            };
            rings_active += 1;
            if ring.stopped || worker.is_stopped() {
                rings_stopped += 1;
            }
            let _unterminated = worker.finalize_thread();
            // integrity_report は loss_events / unknown_terminations を
            // 見るため、取り出す前に呼ぶこと。
            reports.push(worker.integrity_report(
                self.coverage_missing_calls,
                ring.stopped || worker.is_stopped(),
            ));
            let losses = std::mem::take(&mut worker.loss_events);
            total_loss_records += losses.len() as u64;
            if !losses.is_empty() {
                self.recorder
                    .record_losses(&losses, ring.spec.process_id, ring.spec.thread_id)?;
            }
        }
        let mut report = combine_reports(&reports);
        if self.args_stats.args_fallback_blob > 0 {
            report.semantic_completeness =
                worst(report.semantic_completeness, IntegrityLevel::Degraded);
            report.notes.push(format!(
                "args payloads kept as blobs (undecodable): {}",
                self.args_stats.args_fallback_blob
            ));
        }
        if self.coverage_missing_calls == 0 {
            report.notes.push(
                "note: cross-process slot exhaustion is counted only inside the agent \
                 and is not visible to the host in this version"
                    .into(),
            );
        }
        if let Some((hooked, missing)) = self.hook_coverage {
            if missing > 0 {
                report.capture_coverage = worst(report.capture_coverage, IntegrityLevel::Degraded);
                let total = hooked + missing;
                if hooked == 0 {
                    report.notes.push(format!(
                        "hook coverage: 0/{total} target APIs hooked in the main module; \
                         the target imports none of them, so it ran unrecorded"
                    ));
                } else {
                    report.notes.push(format!(
                        "hook coverage: {hooked}/{total} target APIs hooked in the main \
                         module; {missing} not imported"
                    ));
                }
            }
        }
        let total_events: u64 = self.rings.iter().map(|r| r.events).sum();
        let trace_path = self.trace_path.clone();
        let mut file = self.recorder.finish(&report)?;
        file.flush()?;
        self.state = SessionState::Finished;
        Ok(SessionSummary {
            trace_path,
            total_events,
            total_loss_records,
            rings_total: self.rings.len(),
            rings_active,
            rings_never_initialized: rings_never,
            rings_stopped,
            args_attached: self.args_stats.args_attached,
            args_fallback_blob: self.args_stats.args_fallback_blob,
            hook_coverage: self.hook_coverage,
            integrity: report,
        })
    }
}
