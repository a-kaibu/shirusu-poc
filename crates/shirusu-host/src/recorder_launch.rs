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
//! 5. L23: 再開後にロード済みモジュールを列挙（安定化待ち）し、注入
//!    直後の分と合成して Environment の modules へ載せてから Trace
//!    ファイルを作る（Environment ブロックは作成時に書き込まれるため、
//!    列挙は作成の前に済ませる必要がある）。列挙に失敗しても capture
//!    は失敗させない（CLI の exe 分類だけが残る）。
//! 6. 対象を生かしたまま終える場合は `shirusu_agent_shutdown` を
//!    リモートスレッドで呼び、Agent 側の終了手順（記録無効化 →
//!    進行中 Detour の完了待ち → IAT 復元）を済ませてから最終回収・
//!    確定を行う（レビュー #4 の #9）。
//!
//! 子プロセス追跡（L05）は `TreeCapture` が担う： ルートの起動後に
//! プロセス一覧を定期的に見て、ルートの子孫として新しく現れた
//! プロセスへ Agent を自動注入する（対象はルートのツリーに限る）。
//!
//! 制約（Phase 3 の範囲として正直に残す）:
//! - 注入は同一ビットネス間のみ（x64 Host → x64 対象、x86 → x86）。
//! - DLL の初期化エントリは PE エクスポート表から RVA を引き、
//!   Toolhelp で得たモジュールベースに足して解決する。x86 の
//!   stdcall 名デコレーション（`_shirusu_agent_init@4`）にも対応する。

use crate::child_tree::{child_trace_path, ChildTracker, ProcessEntry};
use crate::recorder::{
    CaptureSession, CaptureSessionConfig, RingSpec, SessionError, SessionSummary, ShutdownOutcome,
};
use shirusu_hook::api::API_COUNT;
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
    /// L23: 注入と初期化を先に行い、モジュール列挙は Trace ファイルの
    /// 作成の前に済ませる。列挙は対象の実行開始後にしか完全にならない
    /// ため、注入直後の分と再開後の安定化待ちの分を合成する。
    pub fn launch(
        cmdline: &str,
        trace_path: impl AsRef<Path>,
        cfg: LaunchConfig,
    ) -> Result<Self, SessionError> {
        let spawned = win::spawn_suspended(cmdline)?;
        let injected = match inject_and_init(&cfg, spawned.process, spawned.pid) {
            Ok(i) => i,
            Err(e) => {
                let _ = win::terminate_process(spawned.process, 1);
                win::close_handle_value(spawned.thread);
                win::close_handle_value(spawned.process);
                return Err(e);
            }
        };
        // 注入直後（再開前）の列挙。対象はまだ停止中のため、exe と ntdll、
        // Agent DLL とその依存だけが見える。失敗しても空のまま進む
        // （再開後の列挙が本命）。
        let pre_modules = crate::modules::enumerate_modules_for_process(spawned.pid);
        if let Err(e) = win::resume_main_thread(spawned.thread) {
            // 再開できない対象は止めたまま放置しない
            let _ = win::terminate_process(spawned.process, 1);
            win::close_handle_value(spawned.thread);
            win::close_handle_value(spawned.process);
            return Err(e.into());
        }
        win::close_handle_value(spawned.thread);
        let (session, shutdown_addr) =
            match finalize_session(trace_path, spawned.pid, injected, pre_modules) {
                Ok(v) => v,
                Err(e) => {
                    let _ = win::terminate_process(spawned.process, 1);
                    win::close_handle_value(spawned.process);
                    return Err(e);
                }
            };
        Ok(Self {
            session: Some(session),
            process: spawned.process,
            pid: spawned.pid,
            shutdown_addr,
        })
    }

    /// 動作中のプロセスへ Agent を入れる。対象は終了させない。
    /// アタッチ対象は既に実行中のため、注入直後の列挙は不要で、再開後
    /// の安定化待ち列挙だけで完全な一覧が得られる。
    pub fn attach(
        pid: u32,
        trace_path: impl AsRef<Path>,
        cfg: LaunchConfig,
    ) -> Result<Self, SessionError> {
        let process = win::open_process_for_injection(pid)?;
        match inject_and_init(&cfg, process, pid) {
            Ok(injected) => match finalize_session(trace_path, pid, injected, Vec::new()) {
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
            },
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

/// 子プロセス追跡付きの記録（L05）の集計。ルートの要約と、注入に
/// 成功した子ごとの (pid, 要約)、注入できなかった子の (pid, 理由)。
#[derive(Debug)]
pub struct TreeSummary {
    pub root: SessionSummary,
    pub children: Vec<(u32, SessionSummary)>,
    pub uninjectable: Vec<(u32, String)>,
}

/// 子プロセス追跡付きの起動ドライバ（L05）。
///
/// ルートを `LaunchedCapture::launch` で起動し、回収ループの中で
/// プロセス一覧を定期的に見て、ルートの子孫として新しく現れた
/// プロセスへ Agent を自動注入する。対象はルートのプロセスツリーに
/// 限り、無関係なプロセスは決して注入しない（`ChildTracker` が
/// ppid の連鎖で判定する）。注入できなかった子は記録の欠落として
/// ルートの Capture Coverage に残す。
///
/// 子はルートとは別の Trace ファイル
/// (`<stem>.child-<pid><ext>`) に記録する（1 プロセス 1 Trace の
/// 前提を保つため）。子の session_id はルートのものに pid を足して
/// 派生させる（Trace 間の取り違えを避ける）。
pub struct TreeCapture {
    root: LaunchedCapture,
    children: Vec<LaunchedCapture>,
    child_summaries: Vec<(u32, SessionSummary)>,
    tracker: ChildTracker,
    launch_cfg: LaunchConfig,
    root_trace: PathBuf,
    uninjectable: Vec<(u32, String)>,
    /// プロセス一覧の取得に連続で失敗した回数。一時的な失敗
    /// （CreateToolhelp32Snapshot は負荷時に失敗することがある）は
    /// 許容し、一定回数を超えたらエラーとして返す。
    scan_failures: u32,
}

/// プロセス一覧の取得失敗を連続で許容する回数。
const MAX_CONSECUTIVE_SCAN_FAILURES: u32 = 50;

/// 子用の起動設定をルートの設定から派生させる。session_id は
/// ルートのものに pid を足して一意にし、Environment の session_id
/// と来歴（capture_config）も合わせて更新する。
fn child_launch_config(base: &LaunchConfig, pid: u32, root_pid: u32) -> LaunchConfig {
    let mut cfg = base.clone();
    cfg.session.session_id = base.session.session_id.wrapping_add(pid as u64);
    cfg.session.environment.session.session_id = cfg.session.session_id;
    cfg.session.environment.capture_config = format!(
        "child process pid={pid} of root pid={root_pid}; discovered by child tracking (L05)"
    );
    cfg
}

impl TreeCapture {
    /// ルートを起動して Agent を注入し、追跡を開始する。
    pub fn launch(
        cmdline: &str,
        trace_path: impl AsRef<Path>,
        cfg: LaunchConfig,
    ) -> Result<Self, SessionError> {
        let root_trace = trace_path.as_ref().to_path_buf();
        let root = LaunchedCapture::launch(cmdline, &root_trace, cfg.clone())?;
        let tracker = ChildTracker::new(root.pid());
        Ok(Self {
            root,
            children: Vec::new(),
            child_summaries: Vec::new(),
            tracker,
            launch_cfg: cfg,
            root_trace,
            uninjectable: Vec::new(),
            scan_failures: 0,
        })
    }

    pub fn root_pid(&self) -> u32 {
        self.root.pid()
    }

    /// プロセス一覧から新しい子を探し、見つけた子へ Agent を注入する。
    /// 注入に失敗した子は Coverage に残すため記録だけして続ける。
    fn scan_once(&mut self) -> Result<(), SessionError> {
        let entries = win::enumerate_processes()?;
        let snapshot: Vec<ProcessEntry> = entries
            .iter()
            .map(|(pid, ppid)| ProcessEntry {
                pid: *pid,
                ppid: *ppid,
            })
            .collect();
        for pid in self.tracker.update(&snapshot) {
            let child_trace = child_trace_path(&self.root_trace, pid);
            let child_cfg = child_launch_config(&self.launch_cfg, pid, self.root.pid());
            match LaunchedCapture::attach(pid, &child_trace, child_cfg) {
                Ok(child) => self.children.push(child),
                Err(e) => self.uninjectable.push((pid, e.to_string())),
            }
        }
        Ok(())
    }

    /// ルートと全ての子が終了するまで回収を続け、終了した子の Trace を
    /// 順次閉じる。ルートが終了しても生きている子がいれば、その子が
    /// 終了する（または新しい孫が現れる）まで続ける。最後の掃引で
    /// 新しい子が見つからなければ終わる。
    pub fn run_tree_to_completion(
        mut self,
        poll_interval: Duration,
    ) -> Result<TreeSummary, SessionError> {
        loop {
            // 終了した子を回収して Trace を閉じる
            let mut i = 0;
            while i < self.children.len() {
                if self.children[i].target_exited() {
                    let child = self.children.remove(i);
                    let pid = child.pid();
                    let summary = child.finish()?;
                    self.child_summaries.push((pid, summary));
                } else {
                    i += 1;
                }
            }
            let root_exited = self.root.target_exited();
            match self.scan_once() {
                Ok(()) => self.scan_failures = 0,
                Err(e) => {
                    self.scan_failures += 1;
                    if self.scan_failures >= MAX_CONSECUTIVE_SCAN_FAILURES {
                        return Err(e);
                    }
                }
            }
            self.root.session().poll_once()?;
            for child in &mut self.children {
                child.session().poll_once()?;
            }
            if root_exited && self.children.is_empty() {
                break;
            }
            std::thread::sleep(poll_interval);
        }
        self.finish()
    }

    /// 注入できなかった子をルートの Coverage に残してから、ルートと
    /// 残っている子の Trace を閉じる。
    pub fn finish(mut self) -> Result<TreeSummary, SessionError> {
        for (pid, reason) in &self.uninjectable {
            self.root.session().note_uninjectable_child(*pid, reason);
        }
        let root = self.root.finish()?;
        let mut children = std::mem::take(&mut self.child_summaries);
        for child in self.children.drain(..) {
            let pid = child.pid();
            children.push((pid, child.finish()?));
        }
        Ok(TreeSummary {
            root,
            children,
            uninjectable: std::mem::take(&mut self.uninjectable),
        })
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

    /// テスト用の最小セッション設定（実記録はしない）。
    fn test_session_config() -> CaptureSessionConfig {
        use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
        use shirusu_trace::writer::Durability;
        use shirusu_transport::RingConfig;
        CaptureSessionConfig {
            session_id: 4242,
            ring_config: RingConfig::new(64, 4096),
            environment: CaptureEnvironment {
                session: SessionMetadata {
                    session_id: 4242,
                    created_by: "shirusu-host test (recorder_launch)".into(),
                    qpc_frequency: 10_000_000,
                },
                ..Default::default()
            },
            qpc_frequency: 10_000_000,
            durability: Durability::Buffered,
            order_global: false,
            record_runtime_apis: false,
            diagnostic_query_interface: false,
            record_mode: crate::trace_convert::RecordMode::Full,
        }
    }

    #[test]
    fn child_launch_config_derives_distinct_session_ids() {
        // L05: 子の session_id はルートのものから pid で派生させ、
        // Environment の session_id と来歴も合わせて更新する。
        let base = LaunchConfig::new(test_session_config(), PathBuf::from("agent.dll"));
        let c1 = child_launch_config(&base, 111, 100);
        let c2 = child_launch_config(&base, 222, 100);
        assert_ne!(c1.session.session_id, base.session.session_id);
        assert_ne!(c1.session.session_id, c2.session.session_id);
        assert_eq!(
            c1.session.environment.session.session_id,
            c1.session.session_id
        );
        assert!(c1
            .session
            .environment
            .capture_config
            .contains("child process pid=111 of root pid=100"));
    }

    #[test]
    fn tree_capture_launch_with_bad_exe_fails() {
        // L05: 存在しない exe の起動は失敗する（Windows 実働の入口）。
        let cfg = LaunchConfig::new(test_session_config(), PathBuf::from("no-such-agent.dll"));
        let r = TreeCapture::launch(
            "no-such-target.exe",
            std::env::temp_dir().join("shirusu-tree-test.trace"),
            cfg,
        );
        assert!(r.is_err());
    }
}

/// Bootstrap の初期化結果（設置数・欠落数・復元失敗数・COM Factory 設置数）。
struct BootstrapResult {
    hooked: usize,
    missing: usize,
    /// 設置失敗時にロールバックでも復元できず、対象に残存した
    /// IAT スロットの数 (レビュー第5回 #8)。通常は 0。
    unrestored: usize,
    /// DLL が設置した COM Factory 関数の Detour の数 (L02)。通常は 2。
    com_factories: usize,
    /// DLL が設置した WinRT アクティベーション関数の Detour の数
    /// (L14)。通常は 2。
    winrt_activations: usize,
    /// DLL が設置した内部 API (Nt*) の Inline Hook の数 (L15)。
    /// 詳細調査モードでのみ 0 より大きくなる。通常は 7。
    internal_hooks: usize,
    /// DLL が設置したコールバック検出フックの数 (L16)。通常は 4。
    callback_hooks: usize,
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
    let com_factories = buf.com_factory_count();
    let winrt_activations = buf.winrt_activation_count();
    let internal_hooks = buf.internal_hook_count();
    let callback_hooks = buf.callback_hook_count();
    // 対象 API の総数を超える報告は信用しない（書かれていない
    // 領域の読み違い等を Coverage として採用しない）。上限は表の
    // API 数（API_COUNT）に連動させる。旧値は 64 の固定値で、L03 で
    // 表が 78 件になった時点で合計が常に上限を超え、報告が常に破棄
    // される状態になっていた（L01 で発見し修正）。
    if hooked as usize + missing as usize > API_COUNT || unrestored as usize > API_COUNT {
        return None;
    }
    // L02: COM Factory の設置数は Factory 関数の数（2）を超えない。
    if com_factories as usize > shirusu_hook::com::COM_FACTORY_COUNT {
        return None;
    }
    // L14: WinRT アクティベーション関数の設置数は関数の数（2）を超えない。
    if winrt_activations as usize > shirusu_hook::winrt::WINRT_ACTIVATION_COUNT {
        return None;
    }
    // L15: 内部 API (Nt*) の設置数は内部 API の数（7）を超えない。
    if internal_hooks as usize > shirusu_hook::api::INTERNAL_API_COUNT {
        return None;
    }
    // L16: コールバック検出フックの設置数はフック関数の数（4）を超えない。
    if callback_hooks as usize > shirusu_hook::callback::CALLBACK_HOOK_COUNT {
        return None;
    }
    Some(BootstrapResult {
        hooked: hooked as usize,
        missing: missing as usize,
        unrestored: unrestored as usize,
        com_factories: com_factories as usize,
        winrt_activations: winrt_activations as usize,
        internal_hooks: internal_hooks as usize,
        callback_hooks: callback_hooks as usize,
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

/// 注入済みの対象と、セッション確定に必要な材料。L23 の分割で
/// `inject_and_prepare` を 2 段にした：注入・初期化（`inject_and_init`）
/// と、モジュール列挙後のセッション作成（`finalize_session`）。
struct InjectedTarget {
    /// Trace 作成時に使うセッション設定（DLL の PE から決めた
    /// pointer_width を反映済み）。
    session_cfg: CaptureSessionConfig,
    /// Ring ごとの共有 Mapping・space_available 通知・登録仕様。
    rings: Vec<(
        win::SharedMapping,
        std::sync::Arc<win::RingNotify>,
        RingSpec,
    )>,
    /// DLL が Bootstrap へ書き戻したフック設置/欠落件数。
    hook_coverage: Option<(usize, usize)>,
    /// DLL が Bootstrap へ書き戻した COM Factory 関数の設置数 (L02)。
    com_factory_count: Option<usize>,
    /// DLL が Bootstrap へ書き戻した WinRT アクティベーション関数の
    /// 設置数 (L14)。
    winrt_activation_count: Option<usize>,
    /// DLL が Bootstrap へ書き戻した内部 API (Nt*) の設置数 (L15)。
    internal_hook_count: Option<usize>,
    /// DLL が Bootstrap へ書き戻したコールバック検出フックの設置数 (L16)。
    callback_hook_count: Option<usize>,
    /// Agent 終了エントリのアドレス（解決できた場合）。
    shutdown_addr: Option<usize>,
}

/// Mapping とイベントを用意し、DLL を注入して初期化を確認する。
/// 起動（suspended）とアタッチで共通の手順。Trace ファイルはまだ作ら
/// ない（L23：Environment へ載せるモジュール列挙は、対象の実行開始
/// 後にしか完全にならないため、作成は `finalize_session` へ遅らせる）。
fn inject_and_init(
    cfg: &LaunchConfig,
    process: win::HandleValue,
    pid: u32,
) -> Result<InjectedTarget, SessionError> {
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

    let notify = win::ProcessNotify::new()?;
    let init_done = win::EventObject::new(false, false)?;
    // Host プロセスへのハンドルを対象へ渡す（Agent の生存確認用）
    let host_proc = win::open_process_for_injection(std::process::id())?;
    let host_dup = win::duplicate_handle_to_process(host_proc, pid);
    win::close_handle_value(host_proc);
    let host_dup = host_dup?;

    let mut rings = Vec::with_capacity(cfg.ring_count);
    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(cfg.ring_count);
    for i in 0..cfg.ring_count {
        let mapping = win::SharedMapping::create(ring_len)?;
        let ring_notify = std::sync::Arc::new(win::RingNotify::new()?);
        let mapping_dup = mapping.duplicate_to_process(pid)?;
        let space_dup = ring_notify.space_available.duplicate_to_process(pid)?;
        let spec = RingSpec {
            process_id: TARGET_PROCESS_ID,
            raw_pid: pid,
            thread_id: (i + 1) as u64,
            expected_generation: EXPANDED_SLOT_GENERATION,
        };
        rings.push((mapping, ring_notify, spec));
        pairs.push((mapping_dup as u64, space_dup as u64));
    }
    let data_dup = notify.data_ready.duplicate_to_process(pid)?;
    let init_dup = init_done.duplicate_to_process(pid)?;

    let mut bootstrap =
        AgentBootstrap::new(cfg.session.session_id, cfg.session.ring_config, &pairs);
    bootstrap.data_ready_handle = data_dup as u64;
    bootstrap.init_done_handle = init_dup as u64;
    bootstrap.host_process_handle = host_dup as u64;
    // L11: セッションの --order=global を Agent DLL へ伝える (Bootstrap v4)。
    bootstrap.order_global = u32::from(cfg.session.order_global);
    // L23: Runtime 独自の API の記録可否を Agent DLL へ伝える (Bootstrap v5)。
    bootstrap.record_runtime_apis = u32::from(cfg.session.record_runtime_apis);
    // L02: 診断用の追加 QueryInterface の可否を Agent DLL へ伝える
    // (Bootstrap v6, bit0)。
    bootstrap.com_options = u32::from(cfg.session.diagnostic_query_interface);
    // L15: 詳細調査モードを Agent DLL へ伝える (Bootstrap v8)。
    // `RecordMode::Detailed` のときだけ有効にする。
    bootstrap.detailed_mode = u32::from(matches!(
        cfg.session.record_mode,
        crate::trace_convert::RecordMode::Detailed
    ));

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
    let hook_coverage = outcome
        .as_ref()
        .map(|result| (result.hooked, result.missing));
    let com_factory_count = outcome.as_ref().map(|result| result.com_factories);
    let winrt_activation_count = outcome.as_ref().map(|result| result.winrt_activations);
    let internal_hook_count = outcome.as_ref().map(|result| result.internal_hooks);
    let callback_hook_count = outcome.as_ref().map(|result| result.callback_hooks);
    Ok(InjectedTarget {
        session_cfg,
        rings,
        hook_coverage,
        com_factory_count,
        winrt_activation_count,
        internal_hook_count,
        callback_hook_count,
        shutdown_addr,
    })
}

/// Trace ファイルを作り、Ring を結線して記録を開始する。L23: 作成前に
/// 対象プロセスのモジュールを列挙して Environment へ載せる（Header と
/// Environment は作成時に書き込まれるため、列挙はこの前に済ませる）。
/// `pre_modules` は注入直後（起動時は再開前）に取ったスナップショット
/// で、再開後の安定化待ち列挙と合成する（起動対象が再開直後に終了して
/// しまった場合でも、注入直後の分は残る）。列挙に失敗・空の場合は CLI
/// が作った `environment.modules` をそのまま使う（capture を失敗させない）。
fn finalize_session(
    trace_path: impl AsRef<Path>,
    pid: u32,
    injected: InjectedTarget,
    pre_modules: Vec<shirusu_transport_win::modules::LoadedModule>,
) -> Result<(CaptureSession, Option<usize>), SessionError> {
    let mut session_cfg = injected.session_cfg;
    let settled = crate::modules::enumerate_modules_settled(pid);
    let merged = crate::modules::merge_module_snapshots(pre_modules, settled);
    if !merged.is_empty() {
        let classified = crate::modules::classify_module_list(&merged);
        let existing = std::mem::take(&mut session_cfg.environment.modules);
        session_cfg.environment.modules =
            crate::modules::merge_environment_modules(existing, classified);
        session_cfg.environment.capture_config = format!(
            "{}; modules={} (L23)",
            session_cfg.environment.capture_config,
            session_cfg.environment.modules.len()
        );
    } else {
        session_cfg.environment.capture_config = format!(
            "{}; modules=unavailable (L23 enumeration failed)",
            session_cfg.environment.capture_config
        );
    }
    let mut session = CaptureSession::create_file(trace_path, session_cfg)?;
    for (mapping, notify, spec) in injected.rings {
        session.add_shared_mapping(mapping, spec, Some(notify))?;
    }
    if let Some((hooked, missing)) = injected.hook_coverage {
        session.set_hook_coverage(hooked, missing);
    }
    if let Some(count) = injected.com_factory_count {
        session.set_com_factory_count(count);
    }
    if let Some(count) = injected.winrt_activation_count {
        session.set_winrt_activation_count(count);
    }
    if let Some(count) = injected.internal_hook_count {
        session.set_internal_hook_count(count);
    }
    if let Some(count) = injected.callback_hook_count {
        session.set_callback_hook_count(count);
    }
    session.start()?;
    Ok((session, injected.shutdown_addr))
}
