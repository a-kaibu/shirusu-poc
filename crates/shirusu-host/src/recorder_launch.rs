//! Capture Session の Windows ドライバ： 対象プロセスの起動 / アタッチ、
//! Agent DLL の注入、初期化確認、終了までの回収ループ。
//!
//! 手順（overview「プロセスの起動・アタッチと Agent の初期化」）:
//! 1. 起動は CREATE_SUSPENDED。対象のコードが動く前に Agent を準備する。
//! 2. Host が Ring 用 Mapping とイベント一式を作り、対象へ複製する。
//! 3. Agent DLL を LoadLibrary で注入し、Bootstrap を対象メモリへ
//!    書いて `shirusu_agent_init` をリモートスレッドで呼ぶ。
//! 4. DLL が init_done を立てるまで待ち、確認できたらメインスレッドを
//!    再開する（アタッチ時は再開は無い）。初期化の成否とは別に、
//!    DLL が Bootstrap へ書き戻したフック設置/欠落件数を読み戻し、
//!    Capture Coverage へ反映する（レビュー #4 の #8）。
//! 5. 対象を生かしたまま終える場合は `shirusu_agent_shutdown` を
//!    リモートスレッドで呼び、Agent 側の終了手順（記録無効化 →
//!    進行中 Detour の完了待ち → IAT 復元）を済ませてから最終回収・
//!    確定を行う（レビュー #4 の #9）。
//!
//! 制約（Phase 3 の範囲として正直に残す）:
//! - 注入は同一ビットネス間のみ（x64 Host → x64 対象、x86 → x86）。
//! - DLL の初期化エントリは PE エクスポート表から RVA を引き、
//!   Toolhelp で得たモジュールベースに足して解決する。x86 の
//!   stdcall 名デコレーション（`_shirusu_agent_init@4`）にも対応する。

use crate::recorder::{
    CaptureSession, CaptureSessionConfig, RingSpec, SessionError, SessionSummary, ShutdownOutcome,
};
use shirusu_hook::bootstrap::{
    AgentBootstrap, SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED, SHUTDOWN_OK,
};
use shirusu_hook::pe;
use shirusu_transport::EXPANDED_SLOT_GENERATION;
use shirusu_transport_win as win;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub session: CaptureSessionConfig,
    pub dll_path: PathBuf,
    /// 用意する Ring（= 対象スレッド数の上限）の本数。
    pub ring_count: usize,
    pub init_timeout: Duration,
}
impl LaunchConfig {
    pub fn new(session: CaptureSessionConfig, dll_path: PathBuf) -> Self {
        Self {
            session,
            dll_path,
            ring_count: 8,
            init_timeout: Duration::from_secs(30),
        }
    }
}

/// 初期化エントリの候補名（x64 は素の名前、x86 は stdcall デコレーション）。
const INIT_EXPORT_CANDIDATES: [&str; 2] = ["shirusu_agent_init", "_shirusu_agent_init@4"];
/// 終了エントリの候補名。引数なしのため x86 のデコレーションは `@0`。
/// 旧 DLL には無い場合があり、その場合は解決できなくても失敗にしない。
const SHUTDOWN_EXPORT_CANDIDATES: [&str; 2] =
    ["shirusu_agent_shutdown", "_shirusu_agent_shutdown@0"];
/// Trace 内の Process ID は対象 1 プロセス前提の固定値（Phase 3 の範囲）。
const TARGET_PROCESS_ID: u64 = 1;

pub struct LaunchedCapture {
    session: Option<CaptureSession>,
    process: win::HandleValue,
    pid: u32,
    /// 対象プロセス内での `shirusu_agent_shutdown` のアドレス。
    /// 解決できなかった（旧 DLL 等）場合は None で、finish は
    /// Agent 側の終了手順を呼ばずに従来どおり閉じる。
    shutdown_addr: Option<usize>,
}

impl LaunchedCapture {
    /// CREATE_SUSPENDED で起動し、Agent を初期化してから再開する。
    pub fn launch(
        cmdline: &str,
        trace_path: impl AsRef<Path>,
        cfg: LaunchConfig,
    ) -> Result<Self, SessionError> {
        let spawned = win::spawn_suspended(cmdline)?;
        let prepared = inject_and_prepare(trace_path, &cfg, spawned.process, spawned.pid);
        match prepared {
            Ok((session, shutdown_addr)) => {
                if let Err(e) = win::resume_main_thread(spawned.thread) {
                    // 再開できない対象は止めたまま放置しない
                    let _ = win::terminate_process(spawned.process, 1);
                    win::close_handle_value(spawned.thread);
                    win::close_handle_value(spawned.process);
                    return Err(e.into());
                }
                win::close_handle_value(spawned.thread);
                Ok(Self {
                    session: Some(session),
                    process: spawned.process,
                    pid: spawned.pid,
                    shutdown_addr,
                })
            }
            Err(e) => {
                let _ = win::terminate_process(spawned.process, 1);
                win::close_handle_value(spawned.thread);
                win::close_handle_value(spawned.process);
                Err(e)
            }
        }
    }

    /// 動作中のプロセスへ Agent を入れる。対象は終了させない。
    pub fn attach(
        pid: u32,
        trace_path: impl AsRef<Path>,
        cfg: LaunchConfig,
    ) -> Result<Self, SessionError> {
        let process = win::open_process_for_injection(pid)?;
        match inject_and_prepare(trace_path, &cfg, process, pid) {
            Ok((session, shutdown_addr)) => Ok(Self {
                session: Some(session),
                process,
                pid,
                shutdown_addr,
            }),
            Err(e) => {
                win::close_handle_value(process);
                Err(e)
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn target_exited(&self) -> bool {
        win::process_exited(self.process)
    }
    pub fn session(&mut self) -> &mut CaptureSession {
        self.session.as_mut().expect("session present")
    }

    /// 対象の終了まで回収を続け、終了したら最終回収して Trace を閉じる。
    /// 対象が途中で死んでも、回収済み分は Trace に残る（異常系の通常経路）。
    pub fn run_to_completion(
        mut self,
        poll_interval: Duration,
    ) -> Result<SessionSummary, SessionError> {
        loop {
            if self.target_exited() {
                break;
            }
            self.session().poll_once()?;
            std::thread::sleep(poll_interval);
        }
        // 終了直前に書かれた分を拾い切る
        for _ in 0..4 {
            let stats = self.session().poll_once()?;
            if stats.events == 0 {
                break;
            }
        }
        self.finish()
    }

    /// 対象を生かしたままセッションだけを閉じる。
    pub fn finish(mut self) -> Result<SessionSummary, SessionError> {
        // 対象が生きているなら、先に Agent 側の終了手順（記録無効化
        // → 進行中 Detour の完了待ち → IAT 復元）を呼んでから最終
        // 回収・確定を行う（レビュー #4 の #9）。これをしないと、
        // アタッチした対象はセッション終了後もフックされたまま
        // 誰も回収しない Ring へ書き続けてしまう。対象が既に終了
        // していれば書き手はおらず、呼び出し自体が不要。
        //
        // 終了手順の結果は捨てない（レビュー第5回 #6）: セッションへ
        // 知らせ、完全停止を確認できなかった場合は Finalization の
        // Event Integrity が劣化する。呼び出しに失敗しても確定自体は
        // 続ける（対象が終了処理中などで応答しない場合がある）が、
        // 「正常終了として確定」はしない。
        let outcome = if self.target_exited() {
            ShutdownOutcome::NotRequired
        } else if let Some(addr) = self.shutdown_addr {
            shutdown_outcome_from_call(win::remote_call(self.process, addr, 0))
        } else {
            ShutdownOutcome::ExportUnavailable
        };
        let mut session = self.session.take().expect("session present");
        session.set_shutdown_outcome(outcome);
        let summary = session.stop()?;
        win::close_handle_value(self.process);
        self.process = 0;
        Ok(summary)
    }
}

impl Drop for LaunchedCapture {
    fn drop(&mut self) {
        if self.process != 0 {
            win::close_handle_value(self.process);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小の PE ヘッダー (nt_headers が読める形) を合成する。
    fn synthetic_pe(magic: u16, opt_size: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        b[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        b
    }

    #[test]
    fn dll_pointer_width_follows_pe_bitness() {
        // レビュー第5回 #5 の記録側: pointer_width は DLL の PE が正。
        assert_eq!(dll_pointer_width(&synthetic_pe(0x20B, 240)), Some(64));
        assert_eq!(dll_pointer_width(&synthetic_pe(0x10B, 224)), Some(32));
        assert_eq!(dll_pointer_width(b"not a pe"), None);
        assert_eq!(dll_pointer_width(&[]), None);
    }

    #[test]
    fn shutdown_call_classification_distinguishes_failure_kinds() {
        // レビュー第5回 #6: 「呼べなかった」と「Agent が止め切れ
        // なかった」を区別する。
        use shirusu_transport_win::WinError;
        assert_eq!(
            shutdown_outcome_from_call(Ok(SHUTDOWN_OK)),
            ShutdownOutcome::Confirmed
        );
        assert_eq!(
            shutdown_outcome_from_call(Ok(SHUTDOWN_INCOMPLETE)),
            ShutdownOutcome::AgentIncomplete
        );
        assert_eq!(
            shutdown_outcome_from_call(Ok(SHUTDOWN_NOT_INITIALIZED)),
            ShutdownOutcome::AgentNotInitialized
        );
        assert_eq!(
            shutdown_outcome_from_call(Ok(99)),
            ShutdownOutcome::UnexpectedStatus(99)
        );
        assert!(matches!(
            shutdown_outcome_from_call(Err(WinError::Unsupported)),
            ShutdownOutcome::CallFailed(_)
        ));
    }
}

/// Bootstrap の初期化結果（設置数・欠落数・復元失敗数）。
struct BootstrapResult {
    hooked: usize,
    missing: usize,
    /// 設置失敗時にロールバックでも復元できず、対象に残存した
    /// IAT スロットの数 (レビュー第5回 #8)。通常は 0。
    unrestored: usize,
}

/// Bootstrap の初期化結果を対象メモリから読み戻す。
/// 読めない場合は None（Coverage は「不明」のままにする。値を
/// 捏造しない）。DLL は init_done を立てる前（成功時）か、失敗を
/// 返す直前（設置失敗の詳細）に書き戻すため、リモートスレッドの
/// 完了後には確定している。
fn read_bootstrap_result(process: win::HandleValue, remote: usize) -> Option<BootstrapResult> {
    let mut buf = AgentBootstrap::default();
    // SAFETY: AgentBootstrap は repr(C) の値型。バイト列として読み込む。
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            &mut buf as *mut AgentBootstrap as *mut u8,
            std::mem::size_of::<AgentBootstrap>(),
        )
    };
    win::read_process_memory(process, remote, bytes.as_mut_ptr(), bytes.len()).ok()?;
    let (hooked, missing) = buf.hook_outcome();
    let unrestored = buf.unrestored_count();
    // 対象 API の総数を超える報告は信用しない（書かれていない
    // 領域の読み違い等を Coverage として採用しない）。
    if hooked + missing > 64 || unrestored > 64 {
        return None;
    }
    Some(BootstrapResult {
        hooked: hooked as usize,
        missing: missing as usize,
        unrestored: unrestored as usize,
    })
}

/// Mapping とイベントを用意し、DLL を注入して初期化を確認する。
/// 起動（suspended）とアタッチで共通の手順。戻り値にはセッションと
/// Agent 終了エントリのアドレス（解決できた場合）を含む。
/// `shirusu_agent_shutdown` の呼び出し結果を終了結果へ分類する
/// （純粋関数。レビュー第5回 #6）。「呼べなかった」ことと「Agent が
/// 完全停止できなかった」ことを区別する。
fn shutdown_outcome_from_call(
    result: Result<u32, shirusu_transport_win::WinError>,
) -> ShutdownOutcome {
    match result {
        Ok(SHUTDOWN_OK) => ShutdownOutcome::Confirmed,
        Ok(SHUTDOWN_INCOMPLETE) => ShutdownOutcome::AgentIncomplete,
        Ok(SHUTDOWN_NOT_INITIALIZED) => ShutdownOutcome::AgentNotInitialized,
        Ok(code) => ShutdownOutcome::UnexpectedStatus(code),
        Err(e) => ShutdownOutcome::CallFailed(e.to_string()),
    }
}

/// Agent DLL の PE から対象プロセスのポインタ幅を決める
/// (レビュー第5回 #5)。DLL は対象プロセスの中で動くため、その
/// ビットネスが対象のビットネスである。パースできない場合は None。
fn dll_pointer_width(image: &[u8]) -> Option<u32> {
    pe::is_pe64(image).map(|is64| if is64 { 64 } else { 32 })
}

fn inject_and_prepare(
    trace_path: impl AsRef<Path>,
    cfg: &LaunchConfig,
    process: win::HandleValue,
    pid: u32,
) -> Result<(CaptureSession, Option<usize>), SessionError> {
    // Agent DLL の PE は先に読んでおく (後段のエクスポート解決でも使う)。
    let file_bytes = std::fs::read(&cfg.dll_path)?;
    let image = pe::map_file_to_image(&file_bytes)
        .ok_or_else(|| SessionError::Injection("agent dll is not a valid PE".into()))?;
    // Trace の CaptureEnvironment.pointer_width は、呼び出し側の申告
    // ではなく DLL の PE を正として上書きする (レビュー第5回 #5)。
    // 比較側の INVALID_HANDLE_VALUE 判定がこの値に依存するため、
    // 対象の実際のビットネスと食い違うと x86 の失敗ハンドルを
    // オブジェクト生成と誤判定する。
    let mut session_cfg = cfg.session.clone();
    if let Some(width) = dll_pointer_width(&image) {
        session_cfg.environment.pointer_width = width;
    }
    let ring_len = session_cfg.ring_config.required_len();
    let mut session = CaptureSession::create_file(trace_path, session_cfg)?;

    let notify = win::ProcessNotify::new()?;
    let init_done = win::EventObject::new(false, false)?;
    // Host プロセスへのハンドルを対象へ渡す（Agent の生存確認用）
    let host_proc = win::open_process_for_injection(std::process::id())?;
    let host_dup = win::duplicate_handle_to_process(host_proc, pid);
    win::close_handle_value(host_proc);
    let host_dup = host_dup?;

    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(cfg.ring_count);
    for i in 0..cfg.ring_count {
        let mapping = win::SharedMapping::create(ring_len)?;
        let ring_notify = std::sync::Arc::new(win::RingNotify::new()?);
        let mapping_dup = mapping.duplicate_to_process(pid)?;
        let space_dup = ring_notify.space_available.duplicate_to_process(pid)?;
        session.add_shared_mapping(
            mapping,
            RingSpec {
                process_id: TARGET_PROCESS_ID,
                raw_pid: pid,
                thread_id: (i + 1) as u64,
                expected_generation: EXPANDED_SLOT_GENERATION,
            },
            Some(ring_notify),
        )?;
        pairs.push((mapping_dup as u64, space_dup as u64));
    }
    let data_dup = notify.data_ready.duplicate_to_process(pid)?;
    let init_dup = init_done.duplicate_to_process(pid)?;

    let mut bootstrap =
        AgentBootstrap::new(cfg.session.session_id, cfg.session.ring_config, &pairs);
    bootstrap.data_ready_handle = data_dup as u64;
    bootstrap.init_done_handle = init_dup as u64;
    bootstrap.host_process_handle = host_dup as u64;

    session.start()?;

    let dll_path_str = cfg.dll_path.to_string_lossy().into_owned();
    win::remote_load_library(process, &dll_path_str)?;
    let dll_name = cfg
        .dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| SessionError::Injection("dll path has no file name".into()))?;
    let base = win::module_base(pid, &dll_name)?;
    let rva = INIT_EXPORT_CANDIDATES
        .iter()
        .find_map(|name| pe::find_export(&image, name))
        .ok_or_else(|| SessionError::Injection("shirusu_agent_init export not found".into()))?;
    // 終了エントリは任意（旧 DLL には無い）。解決できなければ
    // finish は Agent 終了手順を呼ばずに従来どおり閉じる。
    let shutdown_addr = SHUTDOWN_EXPORT_CANDIDATES
        .iter()
        .find_map(|name| pe::find_export(&image, name))
        .map(|r| base + r as usize);

    let remote = win::remote_alloc(process, std::mem::size_of::<AgentBootstrap>())?;
    let write_result = (|| -> Result<(), SessionError> {
        // SAFETY: AgentBootstrap は repr(C) の値型。バイト列として書き込む。
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &bootstrap as *const AgentBootstrap as *const u8,
                std::mem::size_of::<AgentBootstrap>(),
            )
        };
        win::write_process_memory(process, remote, bytes.as_ptr(), bytes.len())?;
        Ok(())
    })();
    if let Err(e) = write_result {
        win::remote_free(process, remote);
        return Err(e);
    }
    let status = win::remote_call(process, base + rva as usize, remote);
    // 初期化結果の読み戻しは、Bootstrap 領域の解放より前に行う
    // （レビュー #4 の #8）。失敗時も読み戻す: 設置失敗の詳細
    // （復元失敗スロット数）が書き戻されている場合がある
    // （レビュー第5回 #8）。
    let outcome = if status.is_ok() {
        read_bootstrap_result(process, remote)
    } else {
        None
    };
    win::remote_free(process, remote);
    let status = status?;
    if status != 0 {
        if let Some(result) = outcome.filter(|r| r.unrestored > 0) {
            return Err(SessionError::Injection(format!(
                "shirusu_agent_init returned status {status}; {} IAT slot(s) \
                 could not be restored and remain detoured in the target process",
                result.unrestored
            )));
        }
        return Err(SessionError::Injection(format!(
            "shirusu_agent_init returned status {status}"
        )));
    }
    if !init_done.wait_timeout(cfg.init_timeout) {
        return Err(SessionError::Injection(
            "agent did not signal init_done before timeout".into(),
        ));
    }
    if let Some(result) = outcome {
        session.set_hook_coverage(result.hooked, result.missing);
    }
    Ok((session, shutdown_addr))
}
