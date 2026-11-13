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

use crate::trace_convert::{RecordMode, TraceBatchContext, TraceRecorder};
pub use crate::trace_pipeline::HostPipelineStats;
use crate::trace_pipeline::TracePipeline;
use crate::{DrainWorker, IntegrityLevel, IntegrityReport};
use shirusu_hook::api as hook_api;
use shirusu_hook::callback as hook_callback;
use shirusu_hook::com as hook_com;
use shirusu_hook::winrt as hook_winrt;
use shirusu_trace::proto::{CaptureEnvironment, ProfileSummary};
use shirusu_trace::writer::{Durability, WriterOptions};
use shirusu_transport::layout;
use shirusu_transport::ring::SharedRegion;
use shirusu_transport::RingConfig;
#[cfg(windows)]
use shirusu_transport_win::SharedMapping;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

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
    /// Target initialization succeeded, but preparation or recording failed. Keep the
    /// original error and the independently observed cleanup result together.
    PostInitialization {
        source: Box<SessionError>,
        rollback: ShutdownOutcome,
    },
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
            Self::PostInitialization { source, rollback } => {
                write!(
                    f,
                    "capture failed after initialization: {source}; rollback: {rollback:?}"
                )
            }
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
    /// Trace ファイルへの永続化の強さ（F21）。既定は
    /// [`Durability::Buffered`]（`flush` のみ）。
    pub durability: Durability,
    /// `--order=global` (L11)。有効にすると Agent が観測点で全スレッド
    /// 共通の番号を採番し、Descriptor の `global_order` に刻む。
    /// Host はこの設定で Descriptor の検証（非 0 の受理可否）を決め、
    /// Agent DLL へは Bootstrap 経由で伝える。既定は false。
    pub order_global: bool,
    /// Runtime 独自の API も記録するか（L07、overview「記録境界と
    /// モジュール分類」節）。既定は false（記録しない）。設定そのものが
    /// ここにあり、CLI の `--record-runtime-apis` から渡す。フック時の
    /// 呼び出し元分類による強制は Windows 側の残作業（L23）。
    pub record_runtime_apis: bool,
    /// 診断用の追加 QueryInterface を有効にするか（L02、overview
    /// COM 節）。有効にすると Interceptor は新規発見のインターフェイスに
    /// 対して自身で `QueryInterface(IID_IUnknown)` を呼んで同一性を
    /// 確認する（参照カウントを一時的に増やすため、実行に影響し得る）。
    /// 既定は false（標準では呼ばない）。CLI の
    /// `--diagnostic-query-interface` から渡す。
    pub diagnostic_query_interface: bool,
    /// 記録モード（L09、overview「記録モードと性能目標」節）。既定は
    /// `RecordMode::Full`。CLI の `--mode` / `--api` から渡す。
    pub record_mode: RecordMode,
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
    /// Agent が Control 領域を初期化済みか（Magic の出現で判定する）。
    ///
    /// 判定は通常のバイト読みではなく Magic の `Acquire` 読みで行う
    /// (レビュー第5回 #4)。書き手 (init_control) は全フィールドを
    /// 書いてから Magic を `Release` で公開するため、この Acquire
    /// 読みで Magic を観測した時点で、初期化済みの全フィールドが
    /// 見えることが保証される。
    fn agent_initialized(&self) -> bool {
        self.len() >= layout::OFF_MAGIC + 8
            && layout::load(self.base(), layout::OFF_MAGIC, Ordering::Acquire) == layout::MAGIC
    }
}

struct RingEndpoint {
    spec: RingSpec,
    mapping: RingMapping,
    /// space_available 通知（Host → Agent）。回収で空きができたら鳴らす。
    space_notify: Option<std::sync::Arc<shirusu_transport_win::RingNotify>>,
    worker: Option<DrainWorker>,
    /// 現在の Worker が対象としている Slot 世代 (レビュー #6 P1-4)。
    /// 初めは `spec.expected_generation`。Agent が Slot を回収して
    /// 別のスレッドが同じ Mapping を再初期化すると Control の世代が
    /// 進むため、poll のたびに照合し、進んでいれば Worker を張り替える。
    generation: u64,
    /// Trace 上のスレッド ID (レビュー #6 P1-4)。初代は
    /// `spec.thread_id`、世代交代のたびにセッションが新しい合成 ID
    /// を割り当てる。Trace の Sequence はスレッド単位で単調でなけ
    /// ればならず、新しい incarnation (別の OS スレッド) の Sequence
    /// は 1 から再開するため、スレッドとしても別に扱うのが正しい。
    trace_thread_id: u64,
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
    /// Target exit status, when observed by the process driver. None for a
    /// still-running target or an in-process session; independent of integrity.
    pub target_exit_code: Option<u32>,
    pub total_events: u64,
    pub total_loss_records: u64,
    pub rings_total: usize,
    pub rings_active: usize,
    pub rings_never_initialized: usize,
    pub rings_stopped: usize,
    pub args_attached: usize,
    pub args_fallback_blob: usize,
    pub host_pipeline: HostPipelineStats,
    /// Agent DLL が報告したフック設置結果 (設置数, 欠落数)。
    /// プロセス間記録で DLL から読み戻せた場合のみ Some
    /// (レビュー #4 の #8)。
    pub hook_coverage: Option<(usize, usize)>,
    /// Agent DLL が報告した COM Factory 関数の設置数（L02。0〜2）。
    /// プロセス間記録で DLL から読み戻せた場合のみ Some。
    pub com_factory_count: Option<usize>,
    /// Agent DLL が報告した WinRT アクティベーション関数の設置数
    /// （L14。0〜2）。プロセス間記録で DLL から読み戻せた場合のみ Some。
    pub winrt_activation_count: Option<usize>,
    /// Agent DLL が報告した内部 API (Nt*) の設置数（L15。0〜7）。
    /// 詳細調査モードでのみ設置される。プロセス間記録で DLL から
    /// 読み戻せた場合のみ Some。
    pub internal_hook_count: Option<usize>,
    /// Agent DLL が報告したコールバック検出フックの設置数（L16。0〜4）。
    /// プロセス間記録で DLL から読み戻せた場合のみ Some。
    pub callback_hook_count: Option<usize>,
    /// 注入できなかった子プロセス (pid, 理由)。L05: 保護されたプロセス
    /// や注入前に終了した子はここに残り、Capture Coverage の劣化として
    /// Finalization の注記にも写る。
    pub uninjectable_children: Vec<(u32, String)>,
    /// `profile` モードの集計（L09）。`profile` 以外のモードでは None。
    /// `total_events` は回収したイベント数（`profile` では個別イベント
    /// を保存しないため、Finalization の `total_events` は 0 になる。
    /// 集計の `total_events_seen` が回収数と一致する）。
    pub profile_summary: Option<ProfileSummary>,
    pub integrity: IntegrityReport,
}

/// Agent 終了手順（`shirusu_agent_shutdown`）の結果
/// （レビュー第5回 #6）。`LaunchedCapture::finish` が知らせ、
/// [`CaptureSession::stop`] が Event Integrity へ写す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// 対象プロセスが既に終了していた（書き手はおらず呼び出し不要）。
    NotRequired,
    /// 終了エントリを解決できなかった（旧 DLL 等）。フック解除を
    /// 確認する手段が無い。
    ExportUnavailable,
    /// Agent が完全停止を報告した。
    Confirmed,
    /// 終了エントリの呼び出し自体に失敗した（理由付き）。
    CallFailed(String),
    /// Agent は応答したが、進行中 Detour の完了待ちまたは Hook の
    /// 復元が完了していない。
    AgentIncomplete,
    /// Agent は「アクティブなセッションが無い」と報告した
    /// （Host 側の見立てと食い違う異常系）。
    AgentNotInitialized,
    /// 未知の状態コードが返った。
    UnexpectedStatus(u32),
}

/// A completed incomplete cleanup can be retried once. Other outcomes may
/// have an executing remote worker or a different lifecycle state; do not retry.
#[cfg(any(windows, test))]
pub(crate) fn retry_incomplete_shutdown(
    mut call: impl FnMut() -> ShutdownOutcome,
) -> ShutdownOutcome {
    let first = call();
    if first == ShutdownOutcome::AgentIncomplete {
        std::thread::sleep(std::time::Duration::from_millis(20));
        call()
    } else {
        first
    }
}

/// 終了結果 → Event Integrity への影響（純粋関数）。
/// 完全停止を確認できた場合は None（影響なし）。確認できなかった
/// 場合は、理由に応じて Degraded（止め損ねが記録の欠落・不完全さに
/// 直結する）または Unknown（確認する手段自体が無かった）を返す。
pub fn shutdown_integrity_impact(outcome: &ShutdownOutcome) -> Option<(IntegrityLevel, String)> {
    match outcome {
        ShutdownOutcome::NotRequired | ShutdownOutcome::Confirmed => None,
        ShutdownOutcome::CallFailed(reason) => Some((
            IntegrityLevel::Degraded,
            format!(
                "agent shutdown: remote call failed ({reason}); hooks may remain \
                 in the target and writes after the final drain are not in this trace"
            ),
        )),
        ShutdownOutcome::AgentIncomplete => Some((
            IntegrityLevel::Degraded,
            "agent shutdown: in-flight detours did not drain within the timeout; \
             the IAT was restored anyway and in-flight events may be incomplete"
                .to_string(),
        )),
        ShutdownOutcome::ExportUnavailable => Some((
            IntegrityLevel::Unknown,
            "agent shutdown: shutdown entry point unavailable (older agent dll); \
             hook removal could not be confirmed"
                .to_string(),
        )),
        ShutdownOutcome::AgentNotInitialized => Some((
            IntegrityLevel::Unknown,
            "agent shutdown: agent reported no active session; \
             hook removal could not be confirmed"
                .to_string(),
        )),
        ShutdownOutcome::UnexpectedStatus(code) => Some((
            IntegrityLevel::Unknown,
            format!(
                "agent shutdown: unexpected status {code}; \
                 hook removal could not be confirmed"
            ),
        )),
    }
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

/// 世代交代した Ring の旧 Worker を確定させる (レビュー #6
/// P1-4)。`stop` での確定と同じ手順: スレッド表を閉じ、完全性
/// 報告を保持し、Loss を記録する。`ring.generation` は共有
/// Control の現在値へ進める。
fn retire_ring_worker(
    recorder: &mut TracePipeline<File>,
    retired_reports: &mut Vec<IntegrityReport>,
    retired_loss_records: &mut u64,
    coverage_missing_calls: u64,
    ring: &mut RingEndpoint,
) -> Result<(), SessionError> {
    let Some(mut worker) = ring.worker.take() else {
        return Ok(());
    };
    let _ = worker.finalize_thread();
    retired_reports
        .push(worker.integrity_report(coverage_missing_calls, ring.stopped || worker.is_stopped()));
    let losses = std::mem::take(&mut worker.loss_events);
    if !losses.is_empty() {
        *retired_loss_records += losses.len() as u64;
        recorder.record_losses(losses, ring.spec.process_id, ring.trace_thread_id)?;
    }
    ring.stopped = false;
    ring.generation = layout::load(
        ring.mapping.base(),
        layout::OFF_GENERATION,
        Ordering::Acquire,
    );
    Ok(())
}

pub struct CaptureSession {
    config: CaptureSessionConfig,
    recorder: TracePipeline<File>,
    rings: Vec<RingEndpoint>,
    state: SessionState,
    trace_path: PathBuf,
    /// 同一プロセス記録の場合に呼び出し側が知らせる Slot 不足数。
    /// プロセス間では Agent 内カウンタに留まり Host からは見えない
    /// （Phase 3 の制約として summary の注記にも残す）。
    coverage_missing_calls: u64,
    /// Agent DLL が Bootstrap 経由で報告したフック設置結果
    /// (設置数, 欠落数)。プロセス間記録でのみ設定される。
    hook_coverage: Option<(usize, usize)>,
    /// Agent DLL が Bootstrap 経由で報告した COM Factory 関数の設置数
    /// （L02。0〜2）。プロセス間記録でのみ設定される。
    com_factory_count: Option<usize>,
    /// Agent DLL が Bootstrap 経由で報告した WinRT アクティベーション
    /// 関数の設置数（L14。0〜2）。プロセス間記録でのみ設定される。
    winrt_activation_count: Option<usize>,
    /// Agent DLL が Bootstrap 経由で報告した内部 API (Nt*) の設置数
    /// （L15。0〜7）。詳細調査モードでのみ設定される。プロセス間記録
    /// でのみ設定される。
    internal_hook_count: Option<usize>,
    /// Agent DLL が Bootstrap 経由で報告したコールバック検出フックの
    /// 設置数（L16。0〜4）。プロセス間記録でのみ設定される。
    callback_hook_count: Option<usize>,
    /// Agent 終了手順の結果（レビュー第5回 #6）。プロセス間記録で
    /// 対象を生かしたまま閉じる場合のみ設定される。
    shutdown_outcome: Option<ShutdownOutcome>,
    /// 世代交代で張り替えた旧 Worker の完全性報告 (レビュー #6
    /// P1-4)。`stop` の集計へ合算する。
    retired_reports: Vec<IntegrityReport>,
    /// 世代交代で張り替えた旧 Worker の Loss 件数。`stop` の
    /// `total_loss_records` へ合算する。
    retired_loss_records: u64,
    /// 世代交代した Ring へ割り当てる次の合成 Trace スレッド ID。
    /// `add_ring` で全 spec の最大値 + 1 へ追随させる。
    next_trace_thread_id: u64,
    /// 注入できなかった子プロセス (pid, 理由)。L05。TreeCapture が
    /// 注入の失敗時に知らせる。`stop` で Capture Coverage の劣化と
    /// 注記に写す。
    uninjectable_children: Vec<(u32, String)>,
}

impl CaptureSession {
    /// Trace ファイルを作り、フック Schema を登録してセッションを用意する。
    pub fn create_file(
        path: impl AsRef<Path>,
        mut config: CaptureSessionConfig,
    ) -> Result<Self, SessionError> {
        if config.environment.session.session_id != config.session_id {
            return Err(SessionError::Config(format!(
                "environment session_id {} != config session_id {}",
                config.environment.session.session_id, config.session_id
            )));
        }
        config.environment.capture_config.push_str(&format!(
            "; host_pipeline=async-fifo; host_queue_commands={}; host_event_compression=backlog-adaptive; ring_descriptors={}; ring_payload_bytes={}",
            crate::trace_pipeline::QUEUED_BATCHES,
            config.ring_config.descriptor_capacity,
            config.ring_config.payload_capacity,
        ));
        let file = File::create(path.as_ref())?;
        let mut recorder = TraceRecorder::from_environment_with_options(
            file,
            config.environment.clone(),
            WriterOptions {
                durability: config.durability,
                ..Default::default()
            },
        )?;
        // L09: 記録モードを TraceRecorder へ渡す。
        recorder.set_record_mode(config.record_mode.clone());
        for def in hook_api::all_schemas() {
            recorder.register_schema(def)?;
        }
        // L02: COM メソッドイベントの Schema も登録する（未登録だと
        // Payload が Blob へ逃げ、args として読めなくなる）。
        for def in hook_com::com_schemas() {
            recorder.register_schema(def)?;
        }
        // L14: WinRT アクティベーションイベントの Schema も登録する
        // （COM と同じ理由）。
        for def in hook_winrt::winrt_schemas() {
            recorder.register_schema(def)?;
        }
        // L16: コールバックイベントの Schema も登録する（COM と同じ理由）。
        for def in hook_callback::callback_schemas() {
            recorder.register_schema(def)?;
        }
        Ok(Self {
            config,
            recorder: TracePipeline::new(recorder)?,
            rings: Vec::new(),
            state: SessionState::Created,
            trace_path: path.as_ref().to_path_buf(),
            coverage_missing_calls: 0,
            hook_coverage: None,
            com_factory_count: None,
            winrt_activation_count: None,
            internal_hook_count: None,
            callback_hook_count: None,
            shutdown_outcome: None,
            retired_reports: Vec::new(),
            retired_loss_records: 0,
            next_trace_thread_id: 0,
            uninjectable_children: Vec::new(),
        })
    }

    /// Publish late module discovery without delaying Ring consumption.
    pub fn update_modules(
        &mut self,
        modules: Vec<shirusu_trace::module::ModuleClassification>,
    ) -> Result<(), SessionError> {
        self.ensure_state(SessionState::Recording, "update_modules")?;
        let environment = &mut self.config.environment;
        if modules.is_empty() {
            environment
                .capture_config
                .push_str("; module_scan=unavailable");
        } else {
            environment.modules = crate::modules::merge_environment_modules(
                std::mem::take(&mut environment.modules),
                modules,
            );
            environment.capture_config.push_str(&format!(
                "; modules={} (L23 async)",
                environment.modules.len()
            ));
        }
        self.recorder.update_environment(environment)?;
        Ok(())
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

    /// Agent DLL が報告した COM Factory 関数の設置数を知らせる (L02)。
    pub fn set_com_factory_count(&mut self, count: usize) {
        self.com_factory_count = Some(count);
    }

    /// Agent DLL が報告した WinRT アクティベーション関数の設置数を
    /// 知らせる (L14)。
    pub fn set_winrt_activation_count(&mut self, count: usize) {
        self.winrt_activation_count = Some(count);
    }

    /// Agent DLL が報告した内部 API (Nt*) の設置数を知らせる (L15)。
    pub fn set_internal_hook_count(&mut self, count: usize) {
        self.internal_hook_count = Some(count);
    }

    /// L16: コールバック検出フックの設置数を記録する。
    pub fn set_callback_hook_count(&mut self, count: usize) {
        self.callback_hook_count = Some(count);
    }

    /// Agent 終了手順の結果を知らせる (レビュー第5回 #6)。
    /// 完全停止を確認できなかった場合、Finalization の Event
    /// Integrity が劣化する（[`shutdown_integrity_impact`]）。
    pub fn set_shutdown_outcome(&mut self, outcome: ShutdownOutcome) {
        self.shutdown_outcome = Some(outcome);
    }

    /// 注入できなかった子プロセスを知らせる (L05)。保護されたプロセスや
    /// 注入前に終了した子など、記録できなかった子はここに残す。
    /// 同じ pid は最初の理由のまま 1 件にまとめる。
    pub fn note_uninjectable_child(&mut self, pid: u32, reason: &str) {
        if !self.uninjectable_children.iter().any(|(p, _)| *p == pid) {
            self.uninjectable_children.push((pid, reason.to_string()));
        }
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
        self.next_trace_thread_id = self.next_trace_thread_id.max(spec.thread_id + 1);
        let index = self.rings.len();
        self.rings.push(RingEndpoint {
            generation: spec.expected_generation,
            trace_thread_id: spec.thread_id,
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

    /// 全 Ring を 1 回ずつ回収し、検証済みの所有バッチを変換 worker へ渡す。
    /// 戻り値は受理件数であり、ファイルへの書き込み完了ではない。
    /// キュー満杯時は回収側が待機する。stop が全件の書き込みと確定を待つ。
    pub fn poll_once(&mut self) -> Result<PollStats, SessionError> {
        self.ensure_state(SessionState::Recording, "poll_once")?;
        self.recorder.check_health()?;
        let mut stats = PollStats::default();
        for ring in &mut self.rings {
            // 世代交代の検出 (レビュー #6 P1-4): Agent が Slot を
            // 回収して別のスレッドが同じ Mapping を再初期化すると
            // Control の世代が進む。Worker を張り替えないと世代
            // 不一致で Ring が止まってしまうため、旧 Worker を
            // ここで確定させる。なお、再初期化が進行中の drain と
            // 競合した場合は従来どおり当該 Ring の完全性喪失として
            // 閉じる (fail-closed)。張り替えは世代が安定してから
            // 次の poll で効く。
            if ring.worker.is_some() && ring.mapping.agent_initialized() {
                let found = layout::load(
                    ring.mapping.base(),
                    layout::OFF_GENERATION,
                    Ordering::Acquire,
                );
                if found != ring.generation {
                    retire_ring_worker(
                        &mut self.recorder,
                        &mut self.retired_reports,
                        &mut self.retired_loss_records,
                        self.coverage_missing_calls,
                        ring,
                    )?;
                    // 新しい incarnation は Trace 上の別スレッドとして
                    // 記録する (Sequence が 1 から再開するため)。
                    ring.trace_thread_id = self.next_trace_thread_id;
                    self.next_trace_thread_id += 1;
                }
            }
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
                        ring.generation,
                    )
                }
                .without_completion_history();
                // L11: セッション設定で Descriptor の global_order 検証を決める。
                worker.set_global_order(self.config.order_global);
                // This pipeline transfers each validated payload with its event;
                // there is no separate pending-blob lookup. Do not enable the
                // opt-in diagnostic key history: it would retain one unused key
                // per payload for the entire Ring lifetime. Event context and
                // generation validation remain independent of that history.
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
                    thread_id: ring.trace_thread_id,
                    qpc_frequency: self.config.qpc_frequency,
                };
                let event_count = batch.events.len();
                self.recorder
                    .record_owned_batch_with_args(&ctx, batch.events)?;
                ring.events += event_count as u64;
                stats.events += event_count;
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
        // 世代交代で確定済みの旧 Worker 分も集計へ含める (P1-4)。
        let mut total_loss_records = self.retired_loss_records;
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
                    .record_losses(losses, ring.spec.process_id, ring.trace_thread_id)?;
            }
        }
        let (mut recorder, pipeline_report) = self.recorder.finish()?;
        let args_stats = pipeline_report.args;
        let host_pipeline = pipeline_report.metrics;
        self.config.environment.capture_config.push_str(&format!(
            "; host_commands={}; host_events_received={}; host_conversion_wall_ns={}; host_queue_full={}; host_drain_wait_ns={}; host_merged_event_commands={}; host_compression_bypass_requests={}",
            host_pipeline.commands_processed, host_pipeline.events_received,
            host_pipeline.conversion_wall_ns, host_pipeline.queue_full_count, host_pipeline.drain_wait_ns, host_pipeline.merged_event_commands, host_pipeline.compression_bypass_requests,
        ));
        recorder.update_environment(&self.config.environment)?;
        reports.append(&mut self.retired_reports);
        let mut report = combine_reports(&reports);
        if args_stats.args_incomplete > 0 {
            report.semantic_completeness =
                worst(report.semantic_completeness, IntegrityLevel::Degraded);
            report.notes.push(format!(
                "args payloads with incomplete field capture: {}",
                args_stats.args_incomplete
            ));
        }
        if args_stats.args_fallback_blob > 0 {
            report.semantic_completeness =
                worst(report.semantic_completeness, IntegrityLevel::Degraded);
            report.notes.push(format!(
                "args payloads kept as blobs (undecodable): {}",
                args_stats.args_fallback_blob
            ));
        }
        if self.coverage_missing_calls == 0 {
            report.notes.push(
                "note: cross-process slot exhaustion is counted only inside the agent \
                 and is not visible to the host in this version"
                    .into(),
            );
        }
        if let Some(outcome) = &self.shutdown_outcome {
            if let Some((level, note)) = shutdown_integrity_impact(outcome) {
                report.event_integrity = worst(report.event_integrity, level);
                report.notes.push(note);
            }
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
        if self.com_factory_count.is_some() || self.winrt_activation_count.is_some() {
            report.capture_coverage = worst(report.capture_coverage, IntegrityLevel::Degraded);
            report.notes.push(
                "COM/WinRT method coverage is partial: image-backed-iunknown-only; \
                 heap/private vtables and remaining methods are unsupported"
                    .into(),
            );
        }
        // L05: 注入できなかった子は記録の欠落として Capture Coverage を
        // 劣化させ、pid と理由を注記に残す（値は捏造しない）。
        if !self.uninjectable_children.is_empty() {
            report.capture_coverage = worst(report.capture_coverage, IntegrityLevel::Degraded);
            for (pid, reason) in &self.uninjectable_children {
                report.notes.push(format!(
                    "child process {pid} could not be injected ({reason}); \
                     its calls are not in this trace"
                ));
            }
        }
        let total_events: u64 = self.rings.iter().map(|r| r.events).sum();
        let trace_path = self.trace_path.clone();
        // L09: `profile` の集計は `finish` で Trace へ書く前に読む
        //（`finish` は recorder を消費する）。
        let profile_summary = recorder.profile_summary();
        let mut file = recorder.finish(&report)?;
        file.flush()?;
        self.state = SessionState::Finished;
        Ok(SessionSummary {
            trace_path,
            target_exit_code: None,
            total_events,
            total_loss_records,
            rings_total: self.rings.len(),
            rings_active,
            rings_never_initialized: rings_never,
            rings_stopped,
            args_attached: args_stats.args_attached,
            args_fallback_blob: args_stats.args_fallback_blob,
            host_pipeline,
            hook_coverage: self.hook_coverage,
            com_factory_count: self.com_factory_count,
            winrt_activation_count: self.winrt_activation_count,
            internal_hook_count: self.internal_hook_count,
            callback_hook_count: self.callback_hook_count,
            uninjectable_children: std::mem::take(&mut self.uninjectable_children),
            profile_summary,
            integrity: report,
        })
    }
}

#[cfg(test)]
mod shutdown_retry_tests {
    use super::*;
    #[test]
    fn cleanup_retry_is_bounded_and_requires_explicit_incomplete() {
        let mut calls = 0;
        assert_eq!(
            retry_incomplete_shutdown(|| {
                calls += 1;
                if calls == 1 {
                    ShutdownOutcome::AgentIncomplete
                } else {
                    ShutdownOutcome::Confirmed
                }
            }),
            ShutdownOutcome::Confirmed
        );
        assert_eq!(calls, 2);
        calls = 0;
        assert_eq!(
            retry_incomplete_shutdown(|| {
                calls += 1;
                ShutdownOutcome::AgentIncomplete
            }),
            ShutdownOutcome::AgentIncomplete
        );
        assert_eq!(calls, 2);
        for outcome in [
            ShutdownOutcome::Confirmed,
            ShutdownOutcome::AgentNotInitialized,
            ShutdownOutcome::UnexpectedStatus(99),
            ShutdownOutcome::CallFailed("timeout".into()),
            ShutdownOutcome::NotRequired,
            ShutdownOutcome::ExportUnavailable,
        ] {
            calls = 0;
            let result = retry_incomplete_shutdown(|| {
                calls += 1;
                outcome.clone()
            });
            assert_eq!(result, outcome);
            assert_eq!(calls, 1);
        }
    }
}
