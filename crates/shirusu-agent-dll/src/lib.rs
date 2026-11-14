//! shirusu Agent DLL。対象プロセスへ注入される cdylib。
//!
//! 初期化の段階分け（overview「プロセスの起動・アタッチと Agent の
//! 初期化」）:
//! 1. `DllMain` では何もしない（Loader Lock の下で複雑な処理をしない）。
//!    スレッド終了は native TLS callback で通知する。
//! 2. Host が Bootstrap（Mapping とイベントのハンドル一式）を対象
//!    プロセスへ書き込み、`shirusu_agent_init` をリモートスレッドで
//!    呼ぶ。ここで Slot への Mapping 登録、ランタイム構築、メイン
//!    モジュールへの IAT フック設置までを行う（Loader Lock の外）。
//! 3. 初期化が終わったら init_done イベントを立て、Host はそれを
//!    確認してから対象のメインスレッドを再開する。
//!
//! エクスポート:
//! - `shirusu_agent_init(*const AgentBootstrap) -> u32`（状態コード）
//! - `shirusu_agent_shutdown() -> u32`（IAT の巻き戻し。戻り値は
//!   `shirusu_hook::bootstrap` の SHUTDOWN_* 状態コード）
//!
//! セッションは init → shutdown の往復を繰り返せる（レビュー第5回
//! #7）: shutdown が IAT 復元後にランタイム登録を解除するため、
//! 同じプロセスへの再初期化が可能。`STATUS_ALREADY_INITIALIZED` は
//! 「アクティブなセッションがある」場合にだけ返る。

use shirusu_hook::bootstrap::AgentBootstrap;

#[cfg(windows)]
mod diagnostics;

pub const STATUS_OK: u32 = 0;
pub const STATUS_BAD_BOOTSTRAP: u32 = 1;
pub const STATUS_MAPPING_FAILED: u32 = 2;
pub const STATUS_HOOK_FAILED: u32 = shirusu_hook::bootstrap::INIT_HOOK_FAILED;
pub const STATUS_ALREADY_INITIALIZED: u32 = 4;
pub const STATUS_UNSUPPORTED: u32 = 5;
/// Initialization panicked. The panic was contained inside the DLL so it did
/// not unwind across `extern "system"` (which aborts the target process).
pub const STATUS_PANICKED: u32 = 6;
/// Agent DLL の API Catalog が Host と異なる（Bootstrap v15）。フックを
/// 設置する前に拒否する。
pub const STATUS_CATALOG_MISMATCH: u32 = shirusu_hook::bootstrap::INIT_CATALOG_MISMATCH;
/// Capture Policy の API 一覧が不正（Bootstrap v15）。フック設置前に拒否する。
pub const STATUS_BAD_CAPTURE_POLICY: u32 = shirusu_hook::bootstrap::INIT_BAD_CAPTURE_POLICY;
/// Shutdown panicked. The Host must not treat this as a confirmed shutdown.
pub const SHUTDOWN_PANICKED: u32 = 3;

/// Run an exported entry point without letting a Rust panic unwind into the
/// caller's (non-Rust) frame.
#[cfg_attr(not(windows), allow(dead_code))]
fn contain_panic(on_panic: u32, f: impl FnOnce() -> u32) -> u32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(on_panic)
}

/// Capture Policy の API 一覧を検証して記録対象の集合にする（純粋関数）。
/// 未知の api_id を 1 つでも含めば None（Host と Agent の表の食い違いを
/// 記録範囲の黙った縮小にしない）。
#[cfg_attr(not(windows), allow(dead_code))]
fn capture_selection(ids: &[u32]) -> Option<std::collections::HashSet<u32>> {
    ids.iter()
        .map(|&id| shirusu_hook::api::api_by_id(id).map(|api| api.api_id))
        .collect()
}

/// 終了手順の状態コード決定（純粋関数。レビュー第5回 #6）。
/// - セッションが無い → `SHUTDOWN_NOT_INITIALIZED`
/// - セッションがあり、進行中 Detour が完了し、IAT 復元も全件できた
///   → `SHUTDOWN_OK`
/// - 完了しなかった（完了待ちタイムアウト）、または IAT 復元に
///   失敗したスロットが残った (レビュー #6 P1-6) →
///   `SHUTDOWN_INCOMPLETE`
///
/// 旧実装はタイムアウトを無視して常に成功を返していた。Host は
/// この区別を Trace の Event Integrity へ写す。
/// (非 Windows では win::shutdown 自体が無いためテストからのみ使われる)
#[cfg_attr(not(windows), allow(dead_code))]
fn shutdown_status(has_session: bool, drained: bool, unrestored: usize) -> u32 {
    use shirusu_hook::bootstrap::{SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED, SHUTDOWN_OK};
    if !has_session {
        SHUTDOWN_NOT_INITIALIZED
    } else if drained && unrestored == 0 {
        SHUTDOWN_OK
    } else {
        SHUTDOWN_INCOMPLETE
    }
}

/// Agent DLL の初期化エントリ。Host が Bootstrap を対象プロセスの
/// メモリへ書いてからリモートスレッドで呼ぶ想定であり、DllMain から
/// 直接呼んではならない（Loader Lock の外で動くことが前提）。
///
/// # Safety
/// `bootstrap` は読み取り可能な AgentBootstrap を指すこと（呼び出しは
/// 初期化が戻るまで構造体を有効に保つこと）。
#[no_mangle]
pub extern "system" fn shirusu_agent_init(bootstrap: *const AgentBootstrap) -> u32 {
    #[cfg(windows)]
    {
        contain_panic(STATUS_PANICKED, || win::init(bootstrap))
    }
    #[cfg(not(windows))]
    {
        let _ = bootstrap;
        STATUS_UNSUPPORTED
    }
}

/// 終了手順（レビュー #4 の #9）: 記録の無効化 → 進行中 Detour の
/// 完了待ち → IAT の巻き戻し → ランタイム登録の解除、の順に行う。
/// Host は対象プロセスを生かしたまま記録だけを終える場合
/// （LaunchedCapture::finish）にこれをリモートスレッドで呼んでから
/// 最終回収・確定を行う。対象が既に終了している場合は呼ばれない
/// （呼ぶ必要もない）。
///
/// 戻り値は `shirusu_hook::bootstrap` の SHUTDOWN_* 状態コード
/// （レビュー第5回 #6）: 完全停止か、完了待ちタイムアウトか、
/// セッション無しかを区別して返す。
#[no_mangle]
pub extern "system" fn shirusu_agent_shutdown() -> u32 {
    #[cfg(windows)]
    {
        contain_panic(SHUTDOWN_PANICKED, win::shutdown)
    }
    #[cfg(not(windows))]
    {
        STATUS_UNSUPPORTED
    }
}

/// 1 when this process's Agent has finished initialization (hooks
/// installed and the session state published), else 0. A target can poll it
/// to wait for an attach that started after it was created.
#[no_mangle]
pub extern "system" fn shirusu_agent_ready() -> u32 {
    #[cfg(windows)]
    {
        u32::from(win::ready())
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// DllMain では初期化を行わない。静的 TLS を使用するため、
/// DisableThreadLibraryCalls は呼ばず、native thread-detach callback を保つ。
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut std::ffi::c_void,
    _reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    1
}

#[cfg(windows)]
mod win {
    use super::*;
    use shirusu_agent::Agent;
    use shirusu_hook::api::api_table;
    use shirusu_hook::bootstrap::BOOTSTRAP_VERSION;
    use shirusu_hook::engine::{self, EngineError, InlineHook, InstalledHooks};
    use shirusu_hook::runtime::HookRuntime;
    use shirusu_transport::context::HostMonitor;
    use shirusu_transport::expansion::ExpansionDelivery;
    use shirusu_transport::slot::SlotPool;
    use shirusu_transport::EXPANDED_SLOT_GENERATION;
    use shirusu_transport_win::{EventObject, ProcessNotify, QpcTimestampSource, RingNotify};
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    struct DllState {
        installed: InstalledHooks,
        /// L01: Inline Hook の設置状態（解除時にプロローグを戻すため保持）。
        inline: Vec<InlineHook>,
        /// L02: COM Factory 関数の Inline Hook の設置状態。
        com_factories: Vec<InlineHook>,
        /// L14: WinRT アクティベーション関数の Inline Hook の設置状態。
        winrt_activations: Vec<InlineHook>,
        /// L15: 内部 API (Nt*) の Inline Hook の設置状態（詳細調査
        /// モードでのみ設置する）。
        internal_hooks: Vec<InlineHook>,
        /// L16: コールバック検出フック関数の Inline Hook の設置状態。
        callbacks: Vec<InlineHook>,
    }
    static STATE: Mutex<Option<DllState>> = Mutex::new(None);
    // Serialize complete lifecycle operations, including initialization before
    // STATE is populated and restoration retries after recording is disabled.
    static CONTROL: Mutex<()> = Mutex::new(());

    fn retain_failed_installation(rt: &Arc<HookRuntime>, pending: InstalledHooks) {
        rt.shutdown_recording();
        if pending.slots.is_empty() && rt.in_flight() == 0 {
            engine::clear_runtime(rt);
        } else {
            // Recovery includes old flights even when all pointer restores won.
            *STATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(DllState {
                installed: pending,
                inline: Vec::new(),
                com_factories: Vec::new(),
                winrt_activations: Vec::new(),
                internal_hooks: Vec::new(),
                callbacks: Vec::new(),
            });
        }
    }

    pub fn init(bootstrap: *const AgentBootstrap) -> u32 {
        if bootstrap.is_null() {
            return STATUS_BAD_BOOTSTRAP;
        }
        // Read only the common prefix before copying the versioned structure:
        // an older Host allocated a smaller Bootstrap.
        if unsafe { bootstrap.cast::<u32>().read_unaligned() } != BOOTSTRAP_VERSION {
            return STATUS_BAD_BOOTSTRAP;
        }
        // SAFETY: caller supplies this version's structure until init returns.
        let b = unsafe { *bootstrap };
        if b.version != BOOTSTRAP_VERSION {
            return STATUS_BAD_BOOTSTRAP;
        }
        crate::diagnostics::install();
        let config = match b.validate() {
            Ok(c) => c,
            Err(_) => return STATUS_BAD_BOOTSTRAP,
        };
        // v15: API Catalog の照合。自分の Fingerprint は照合の成否に関係なく
        // 書き戻し、一致しなければフックを設置する前に拒否する（別ビルドの
        // 表で符号化したイベントを Host が別の Schema で解釈しないため）。
        let own_catalog = shirusu_hook::api_catalog_fingerprint();
        // SAFETY: bootstrap は Host が書き込み可能に確保した領域で、
        // 初期化が戻るまで有効 (呼び出し側の契約)。
        unsafe {
            (*(bootstrap as *mut AgentBootstrap)).result_api_catalog_fingerprint = own_catalog;
        }
        if b.api_catalog_fingerprint != own_catalog {
            return STATUS_CATALOG_MISMATCH;
        }
        // v15: Capture Policy。選択モードでは Host が対象プロセス内に置いた
        // api_id 配列を読み、範囲外の API を記録せず素通しにする。
        let selection = if b.capture_policy == shirusu_hook::bootstrap::CAPTURE_POLICY_SELECTED {
            let ids: &[u32] = if b.capture_api_count == 0 {
                &[]
            } else {
                // SAFETY: Host が capture_api_count 個の u32 を書き込んだ領域で、
                // 初期化が戻るまで解放しない（Bootstrap と同じ寿命）。件数は
                // validate() が上限内であることを確認済み。
                unsafe {
                    std::slice::from_raw_parts(
                        b.capture_api_ids as usize as *const u32,
                        b.capture_api_count as usize,
                    )
                }
            };
            match capture_selection(ids) {
                Some(set) => Some(set),
                None => return STATUS_BAD_CAPTURE_POLICY,
            }
        } else {
            None
        };
        let captured_api_count = match &selection {
            Some(set) => set.len(),
            None => api_table().count(),
        } as u32;
        // SAFETY: 上と同じ。
        unsafe {
            (*(bootstrap as *mut AgentBootstrap)).result_capture_api_count = captured_api_count;
        }
        let _control = CONTROL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            return STATUS_ALREADY_INITIALIZED;
        }
        // Host 生存確認： Bootstrap で渡された Host プロセスへのハンドルが
        // シグナル状態（= Host 終了）になったら記録を止める。
        let host_monitor = if b.host_process_handle != 0 {
            let hv = b.host_process_handle as usize;
            Arc::new(HostMonitor::new(move || {
                // SAFETY: hv は Host が複製して渡した、このプロセスで有効な
                // プロセスハンドル。WAIT_TIMEOUT (0x102) の間は生存。
                unsafe { WaitForSingleObject(hv as HANDLE, 0) == 0x102 }
            }))
        } else {
            Arc::new(HostMonitor::always_alive())
        };
        // 初期 Slot 0： Ring は全て Bootstrap の Mapping から得る（A70 と
        // 同じ登録経路）。Slot はスレッド終了 (FLS で検出) と Host の
        // drain 完了で回収され再利用される（レビュー #6 P1-4）。回収が
        // 間に合わない間の不足は Capture Coverage の欠落として数える。
        let pool = Arc::new(SlotPool::new(0).with_ring_config(config));
        let agent = Arc::new(
            Agent::new(pool, config, host_monitor)
                // A detour can run from someone else's DllMain. Initialization
                // outside Loader Lock does not prove later callers are outside.
                .with_loader_lock_state(shirusu_transport::LoaderLockState::Unknown)
                // A full Ring checks the PEB Loader Lock owner before waiting:
                // writes proven outside Loader Lock wait (up to max_wait) for
                // the Host to collect instead of dropping events.
                .with_loader_lock_probe(shirusu_transport_win::loader_lock_held_by_current_thread)
                .with_timestamp_source(Arc::new(QpcTimestampSource::new()))
                // Wake the Host at a quarter full: a writer inside Loader Lock
                // cannot wait, so the remaining three quarters are all the
                // margin collection has there.
                .with_policy(shirusu_transport::ring::WriterPolicy {
                    notify_threshold_percent: 25,
                    ..Default::default()
                })
                // L11: Host が Bootstrap v4 で指定した --order=global を Agent へ渡す。
                .with_order_global(b.order_global != 0),
        );
        for &mapping in b.mapping_handles.iter().take(b.ring_count as usize) {
            let delivery = ExpansionDelivery {
                len: config.required_len(),
                base: None,
                handle_value: Some(mapping as usize),
                generation: EXPANDED_SLOT_GENERATION,
            };
            if agent.register_slot_mapping(delivery).is_none() {
                return STATUS_MAPPING_FAILED;
            }
        }
        let data_ready = if b.data_ready_handle != 0 {
            Some(ProcessNotify {
                // SAFETY: Host が複製して渡した、このプロセスで有効なイベント。
                data_ready: unsafe {
                    EventObject::from_handle_value(b.data_ready_handle as usize, true)
                },
            })
        } else {
            None
        };
        let mut space_notifies = Vec::with_capacity(b.ring_count as usize);
        for &h in b.space_handles.iter().take(b.ring_count as usize) {
            let notify = if h != 0 {
                RingNotify {
                    // SAFETY: 同上（auto-reset イベント）。
                    space_available: unsafe { EventObject::from_handle_value(h as usize, true) },
                }
            } else {
                // 結線なしの Ring はダミーで埋めて index の対応を保つ
                match RingNotify::new() {
                    Ok(n) => n,
                    Err(_) => return STATUS_MAPPING_FAILED,
                }
            };
            space_notifies.push(Arc::new(notify));
        }
        let rt = Arc::new(
            HookRuntime::new(agent, space_notifies, data_ready)
                // L23: Bootstrap v5 で Host から渡された
                // record_runtime_apis をランタイムへ渡す（既定は記録しない）。
                .with_record_runtime_apis(b.record_runtime_apis != 0)
                // L02: Bootstrap v6 で Host から渡された診断用 QI
                // オプションをランタイムへ渡す（既定は無効）。
                .with_diagnostic_query_interface(b.com_options & 1 != 0)
                // L15: Bootstrap v8 で Host から渡された詳細調査モードを
                // ランタイムへ渡す（既定は無効。内部 API を記録しない）。
                .with_detailed_mode(b.detailed_mode != 0)
                // v15: Capture Policy（filtered）を Agent 側で適用する。
                .with_capture_selection(selection.as_ref()),
        );
        // L23: 呼び出し元分類のためのモジュール一覧を初期化時に作る。
        // 列挙に失敗しても一覧が空のままになるだけで、呼び出し元不明
        // として記録を続ける（fail-open）。
        rt.refresh_caller_modules();
        if engine::set_runtime(Arc::clone(&rt)).is_err() {
            return STATUS_ALREADY_INITIALIZED;
        }
        // Hook installation uses the same heap, handle and memory APIs that
        // become intercepted below. Those operations belong to the Agent and
        // must stay on the passthrough path throughout initialization.
        let _initialization_guard = shirusu_hook::runtime::ReentrancyGuard::try_enter();
        // OS-thread detach is delivered by the native TLS callback, not FLS:
        // fiber deletion must not finalize a still-running thread's capture.
        // Resolve the current runtime so this registration survives reattach.
        let _ = shirusu_hook::fls::install_thread_exit_handler(Arc::new(|tid| {
            if let Some(rt) = engine::runtime() {
                rt.thread_exit(tid);
            }
        }));
        // メインモジュール（対象 EXE）の IAT をパッチする。
        // SAFETY: GetModuleHandleW(NULL) はメインモジュールを返す。
        let main_base = unsafe { GetModuleHandleW(std::ptr::null()) };
        if main_base.is_null() {
            // 登録したまま失敗すると再初期化が永久に塞がれる
            engine::clear_runtime(&rt);
            return STATUS_HOOK_FAILED;
        }
        // SAFETY: main_base はロード済みメインモジュール。対象のメイン
        // スレッドは Host が停止させたままか、アタッチ時は初期化専用
        // スレッドからの呼び出しであり、IAT 書き換えの競合は設置対象を
        // メインモジュールに限ることで抑える（Phase 3 の範囲）。
        let installed = match unsafe { engine::install_hooks(main_base as *mut u8, &rt) } {
            Ok(i) => i,
            // フック対象が 0 件（レビュー #4 の #8）: 対象 API を 1 つも
            // インポートしていない正常なアプリである。初期化失敗には
            // せず、空の設置状態で成功として継続する。欠落は下の
            // Bootstrap 書き戻し経由で Host の Capture Coverage へ
            // 記録される。
            Err(EngineError::NoTargets(plan)) => InstalledHooks {
                module_base: main_base as usize,
                slots: Vec::new(),
                plan,
            },
            // 設置途中の失敗 (レビュー第5回 #8): ロールバック済みなら
            // 対象は元の状態に戻っているが、復元も失敗したスロットが
            // ある場合はその件数を Bootstrap へ書き戻し、Host が
            // 「対象に Detour が残存する初期化失敗」として扱えるように
            // する (書き戻し欄の前提は write_hook_outcome と同じ)。
            Err(EngineError::InstallFailed {
                unrestored,
                pending,
                ..
            }) => {
                // SAFETY: bootstrap は Host が書き込み可能に確保した
                // 領域で、初期化が戻るまで有効 (呼び出し側の契約)。
                unsafe {
                    AgentBootstrap::write_install_failure(
                        bootstrap as *mut AgentBootstrap,
                        unrestored.len() as u32,
                    );
                }
                retain_failed_installation(&rt, *pending);
                return STATUS_HOOK_FAILED;
            }
            Err(_) => {
                engine::clear_runtime(&rt);
                return STATUS_HOOK_FAILED;
            }
        };
        // L01: Inline Hook を IAT の後で設置する。IAT が 0 件でも
        // GetProcAddress 経由の呼び出しは Inline で捕捉できるため、
        // NoTargets の場合も試みる。Inline は API ごとの best-effort
        // であり、見送りがあっても初期化は成功として継続する。
        // SAFETY: 初期化専用スレッドからの呼び出し。対象のメイン
        // スレッドは Host が停止させたままか、アタッチ時は他スレッドを
        // 一時停止してからパッチするため、競合しない。
        let inline_outcome = unsafe { engine::install_inline_hooks(&rt) };
        crate::diagnostics::report_inline(&inline_outcome);
        // L02: COM Factory 関数の Inline Hook を Inline の後で設置する。
        // Inline と同じく best-effort であり、見送りがあっても初期化は
        // 成功として継続する。Factory 関数が 1 つもフックできなくても、
        // Win32 API の記録は続く（COM メソッドの記録だけが無い）。
        // SAFETY: 初期化専用スレッドからの呼び出し（L01 と同じ前提）。
        // Cold initialization outside DllMain, before any factory can publish
        // an adapter. Failure leaves factory observation available with skips.
        let _ = shirusu_hook::shared_com::initialize();
        let com_factory_outcome = unsafe { engine::install_com_factory_hooks(&rt) };
        // L14: WinRT アクティベーション関数の Inline Hook を COM Factory
        // の後で設置する。COM Factory と同じく best-effort であり、
        // 見送りがあっても初期化は成功として継続する。アクティベーション
        // 関数が 1 つもフックできなくても、Win32 API と COM の記録は続く
        // （WinRT の記録だけが無い）。
        // SAFETY: 初期化専用スレッドからの呼び出し（L01 と同じ前提）。
        let winrt_activation_outcome = unsafe { engine::install_winrt_activation_hooks(&rt) };
        // L15: 内部 API (Nt*) の Inline Hook を詳細調査モードでのみ設置
        // する。無効な場合は設置自体をしない（通常モードの Detour
        // オーバーヘッドは増えない）。Inline と同じく best-effort であり、
        // 見送りがあっても初期化は成功として継続する。内部 API が 1 つも
        // フックできなくても、Win32 API の記録は続く（内部呼び出しの記録
        // だけが無い）。詳細調査モードが有効でも、記録可否はランタイムの
        // detailed_mode が決める（prepare のゲート）。
        // SAFETY: 初期化専用スレッドからの呼び出し（L01 と同じ前提）。
        let internal_hook_outcome = if b.detailed_mode != 0 {
            unsafe { engine::install_internal_inline_hooks(&rt) }
        } else {
            engine::InlineInstallOutcome::default()
        };
        // L16: コールバック検出フック関数の Inline Hook を WinRT の後で
        // 設置する。COM Factory と同じく best-effort であり、見送りが
        // あっても初期化は成功として継続する。1 つもフックできなくても、
        // Win32 API と COM の記録は続く（コールバックの記録だけが無い）。
        // SAFETY: 初期化専用スレッドからの呼び出し（L01 と同じ前提）。
        let callback_outcome = unsafe { engine::install_callback_hooks(&rt) };
        // 設置済み API の合算（IAT と Inline の和集合）で Bootstrap へ
        // 書き戻す。IAT では欠落していた API も Inline で捕捉できれば
        // 「設置済み」になり、Coverage の欠落は正直に減る。
        let iat_ids: std::collections::HashSet<u32> = installed
            .plan
            .entries
            .iter()
            .map(|e| e.api.api_id)
            .collect();
        let inline_ids: std::collections::HashSet<u32> =
            inline_outcome.installed.iter().map(|h| h.api_id).collect();
        let hooked = iat_ids.union(&inline_ids).count();
        // L15: 内部 API (Nt*) は通常の Coverage 欠落に数えない（詳細調査
        // モードでの設置数は別欄で報告する）。
        let missing = api_table()
            .filter(|a| {
                !shirusu_hook::api::is_internal_api(a.api_id)
                    && !iat_ids.contains(&a.api_id)
                    && !inline_ids.contains(&a.api_id)
            })
            .count();
        // Preserve actual initialization evidence, independently of observations.
        // Index outcomes once: the table holds thousands of APIs.
        let preserved_ids: std::collections::HashSet<u32> = installed
            .plan
            .preserved
            .iter()
            .map(|e| e.api.api_id)
            .collect();
        let index_outcome = |outcome: &engine::InlineInstallOutcome| {
            let mut reasons: std::collections::HashMap<u32, &'static str> =
                std::collections::HashMap::new();
            for (api_id, reason) in outcome.skipped.iter().rev() {
                reasons.insert(*api_id, reason);
            }
            for hook in outcome.installed.iter().rev() {
                reasons.insert(
                    hook.api_id,
                    if hook.maintenance_pending() {
                        "installed-restoration-pending"
                    } else {
                        "installed"
                    },
                );
            }
            reasons
        };
        let inline_reasons = index_outcome(&inline_outcome);
        let internal_reasons = index_outcome(&internal_hook_outcome);
        use shirusu_hook::bootstrap as boot;
        let mut records = Vec::new();
        for api in api_table() {
            let internal = shirusu_hook::api::is_internal_api(api.api_id);
            let iat = if internal {
                boot::IAT_INTERNAL
            } else if preserved_ids.contains(&api.api_id) {
                if iat_ids.contains(&api.api_id) {
                    boot::IAT_PARTIAL_PRESERVED
                } else {
                    boot::IAT_PRESERVED
                }
            } else if iat_ids.contains(&api.api_id) {
                boot::IAT_INSTALLED
            } else {
                boot::IAT_NOT_IMPORTED
            };
            let iat_only = shirusu_hook::api::is_iat_only_api(api.api_id);
            // A broad-tier API the main module does not import has nothing to
            // report beyond its scope; thousands of such records are omitted.
            if iat_only && iat == boot::IAT_NOT_IMPORTED {
                continue;
            }
            let reason = if internal && b.detailed_mode == 0 {
                "detailed-mode-disabled"
            } else if iat_only {
                "not-attempted-iat-only-scope"
            } else {
                let reasons = if internal {
                    &internal_reasons
                } else {
                    &inline_reasons
                };
                reasons.get(&api.api_id).copied().unwrap_or("unknown")
            };
            records.push(boot::HookEvidenceRecord {
                api_id: api.api_id,
                iat,
                // Reasons outside the fixed code table are reported as unknown.
                inline: boot::inline_reason_code(reason),
                reserved: 0,
            });
        }
        // SAFETY: writable Bootstrap owned by Host until initialization
        // returns; Host allocated `evidence_capacity` records at
        // `evidence_address` in the same region.
        unsafe { AgentBootstrap::write_hook_evidence(bootstrap.cast_mut(), &records) };
        // Host が読み戻せるよう、init_done を立てる前に Bootstrap へ
        // 設置/欠落件数を書き戻す。
        // SAFETY: bootstrap は Host が書き込み可能に確保した領域で、
        // 初期化が戻るまで有効（呼び出し側の契約）。書き戻し欄は
        // バージョン 2 で追加された結果専用の欄である。
        unsafe {
            AgentBootstrap::write_hook_outcome(
                bootstrap as *mut AgentBootstrap,
                hooked as u32,
                missing as u32,
            );
            // L02: COM Factory 関数の設置数も書き戻す（Host の Coverage へ）。
            AgentBootstrap::write_com_factory_count(
                bootstrap as *mut AgentBootstrap,
                com_factory_outcome.installed.len() as u32,
            );
            // L14: WinRT アクティベーション関数の設置数も書き戻す
            // （Host の Coverage へ）。
            AgentBootstrap::write_winrt_activation_count(
                bootstrap as *mut AgentBootstrap,
                winrt_activation_outcome.installed.len() as u32,
            );
            // L15: 内部 API (Nt*) の設置数も書き戻す（Host の Coverage へ。
            // 詳細調査モードが無効な場合は 0）。
            AgentBootstrap::write_internal_hook_count(
                bootstrap as *mut AgentBootstrap,
                internal_hook_outcome.installed.len() as u32,
            );
            // L16: コールバック検出フックの設置数も書き戻す（Host の Coverage へ）。
            AgentBootstrap::write_callback_hook_count(
                bootstrap as *mut AgentBootstrap,
                callback_outcome.installed.len() as u32,
            );
        }
        *STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(DllState {
            installed,
            inline: inline_outcome.installed,
            com_factories: com_factory_outcome.installed,
            winrt_activations: winrt_activation_outcome.installed,
            internal_hooks: internal_hook_outcome.installed,
            callbacks: callback_outcome.installed,
        });
        // This is the dedicated remote injection worker, not an application
        // thread. Its return through ExitThread must not become an unmatched
        // application call or block replay of an otherwise complete trace.
        shirusu_hook::runtime::ReentrancyGuard::mark_thread_exiting();
        if b.init_done_handle != 0 {
            // SAFETY: Host が複製して渡したイベント。立てた後は所有を
            // 持たないよう forget する（Host 側の実体を閉じない）。
            let ev = unsafe { EventObject::from_handle_value(b.init_done_handle as usize, false) };
            let _ = ev.set();
            std::mem::forget(ev);
        }
        STATUS_OK
    }

    pub fn ready() -> bool {
        STATE
            .try_lock()
            .map(|state| state.is_some())
            .unwrap_or(false)
    }

    pub fn shutdown() -> u32 {
        shutdown_with_timeout(std::time::Duration::from_secs(5))
    }

    fn shutdown_with_timeout(timeout: std::time::Duration) -> u32 {
        let _shutdown_guard = shirusu_hook::runtime::ReentrancyGuard::try_enter();
        let _control = CONTROL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shirusu_hook::fls::drain_pending_exits();
        let mut state_slot = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(state) = state_slot.as_mut() else {
            return shutdown_status(false, false, 0);
        };
        let rt = engine::runtime();
        let drained = rt.as_ref().is_some_and(|rt| {
            rt.shutdown_recording();
            rt.wait_in_flight_drained(timeout)
        });
        // Restore even after a flight timeout, but do not retire the session
        // until both restoration and flight draining are confirmed. Removing
        // successful entries prevents retries from rewriting unrelated changes.
        // SAFETY: lifecycle operations are serialized and descriptors are kept
        // only for installed hooks in their original, still-loaded modules.
        let unrestored = unsafe {
            shirusu_hook::shared_com::restore_all()
                + engine::uninstall_pending_inline_hooks(&mut state.com_factories)
                + engine::uninstall_pending_inline_hooks(&mut state.winrt_activations)
                + engine::uninstall_pending_inline_hooks(&mut state.internal_hooks)
                + engine::uninstall_pending_inline_hooks(&mut state.callbacks)
                + engine::uninstall_pending_inline_hooks(&mut state.inline)
                + engine::uninstall_pending_hooks(&mut state.installed)
        };
        if drained && unrestored == 0 {
            if let Some(rt) = &rt {
                engine::clear_runtime(rt);
            }
            *state_slot = None;
        }
        // On failure STATE and the disabled runtime survive. Another shutdown
        // can retry; another init remains rejected until cleanup is confirmed.
        shutdown_status(true, drained, unrestored)
    }
    #[cfg(test)]
    mod lifecycle_tests {
        use super::*;
        use shirusu_hook::bootstrap::{SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED, SHUTDOWN_OK};
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        };

        fn runtime() -> Arc<HookRuntime> {
            Arc::new(HookRuntime::new(
                Arc::new(Agent::new(
                    Arc::new(SlotPool::new(1)),
                    shirusu_transport::RingConfig::new(64, 4096),
                    Arc::new(HostMonitor::always_alive()),
                )),
                Vec::new(),
                None,
            ))
        }
        #[test]
        fn shutdown_retries_only_failed_slots_and_waits_for_old_flights() {
            // Reserve two pages, but commit only the first. Protection changes
            // on the uncommitted second page deterministically fail.
            let base = unsafe { VirtualAlloc(std::ptr::null(), 8192, MEM_RESERVE, PAGE_READWRITE) };
            assert!(!base.is_null());
            assert_eq!(
                unsafe { VirtualAlloc(base, 4096, MEM_COMMIT, PAGE_READWRITE) },
                base
            );
            let first = base.cast::<usize>();
            let second = unsafe { base.cast::<u8>().add(4096) }.cast::<usize>();
            unsafe { first.write(0xaaaa) };
            let rt = runtime();
            assert!(engine::set_runtime(rt.clone()).is_ok());
            retain_failed_installation(
                &rt,
                InstalledHooks {
                    module_base: base as usize,
                    slots: vec![
                        engine::IatSlot::installed(0, 0x1111, 0xaaaa),
                        engine::IatSlot::installed(4096, 0x2222, 0xbbbb),
                    ],
                    plan: Default::default(),
                },
            );
            assert!(!rt.recording_active());
            assert_eq!(shutdown(), SHUTDOWN_INCOMPLETE);
            let bootstrap =
                AgentBootstrap::new(11, shirusu_transport::RingConfig::new(64, 4096), &[(1, 2)]);
            assert_eq!(init(&bootstrap), STATUS_ALREADY_INITIALIZED);
            assert!(!rt.recording_active());
            assert!(engine::runtime().is_some());
            assert_eq!(
                STATE
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .installed
                    .slots
                    .iter()
                    .map(|s| (s.rva, s.original))
                    .collect::<Vec<_>>(),
                vec![(4096, 0x2222)]
            );
            assert_eq!(unsafe { first.read() }, 0x1111);
            // Simulate an application changing an already restored slot.
            unsafe { first.write(0x3333) };
            assert_eq!(
                unsafe { VirtualAlloc(second.cast(), 4096, MEM_COMMIT, PAGE_READWRITE) },
                second.cast()
            );
            unsafe { second.write(0xbbbb) };
            assert_eq!(shutdown(), SHUTDOWN_OK);
            assert_eq!(unsafe { first.read() }, 0x3333);
            assert_eq!(unsafe { second.read() }, 0x2222);
            assert!(STATE.lock().unwrap().is_none());
            assert!(engine::runtime().is_none());
            assert_eq!(shutdown(), SHUTDOWN_NOT_INITIALIZED);
            assert_ne!(unsafe { VirtualFree(base, 0, MEM_RELEASE) }, 0);

            // Successful restoration alone cannot complete a timed-out shutdown.
            let next = runtime();
            assert!(engine::set_runtime(next.clone()).is_ok());
            let flight = shirusu_hook::runtime::DetourFlight::begin(&next).unwrap();
            retain_failed_installation(
                &next,
                InstalledHooks {
                    module_base: 0,
                    slots: Vec::new(),
                    plan: Default::default(),
                },
            );
            assert_eq!(
                shutdown_with_timeout(std::time::Duration::ZERO),
                SHUTDOWN_INCOMPLETE
            );
            assert!(STATE.lock().unwrap().is_some());
            assert!(engine::runtime().is_some());
            drop(flight);
            assert_eq!(shutdown(), SHUTDOWN_OK);
            assert!(STATE.lock().unwrap().is_none());
            assert!(engine::runtime().is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_selection_rejects_unknown_api_ids() {
        use shirusu_hook::api::{API_CLOSE_HANDLE, API_CREATE_FILE_W};
        let set = capture_selection(&[API_CREATE_FILE_W, API_CLOSE_HANDLE, API_CREATE_FILE_W])
            .expect("known ids");
        assert_eq!(set.len(), 2);
        assert!(capture_selection(&[]).expect("empty").is_empty());
        assert!(capture_selection(&[API_CREATE_FILE_W, 0]).is_none());
        assert!(capture_selection(&[u32::MAX]).is_none());
    }

    #[test]
    fn init_status_codes_are_distinct() {
        let codes = [
            STATUS_OK,
            STATUS_BAD_BOOTSTRAP,
            STATUS_MAPPING_FAILED,
            STATUS_HOOK_FAILED,
            STATUS_ALREADY_INITIALIZED,
            STATUS_UNSUPPORTED,
            STATUS_PANICKED,
            STATUS_CATALOG_MISMATCH,
            STATUS_BAD_CAPTURE_POLICY,
        ];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }
    use shirusu_hook::bootstrap::{SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED, SHUTDOWN_OK};

    #[cfg(windows)]
    #[test]
    fn old_bootstrap_is_rejected_before_reading_new_fields() {
        for version in [9u32, 10] {
            assert_eq!(
                super::win::init((&version as *const u32).cast()),
                STATUS_BAD_BOOTSTRAP
            );
        }
    }

    #[test]
    fn exported_entry_points_contain_panics() {
        assert_eq!(contain_panic(STATUS_PANICKED, || STATUS_OK), STATUS_OK);
        assert_eq!(
            contain_panic(STATUS_PANICKED, || panic!("injected init panic")),
            STATUS_PANICKED
        );
        assert_eq!(
            contain_panic(SHUTDOWN_PANICKED, || panic!("injected shutdown panic")),
            SHUTDOWN_PANICKED
        );
        assert!(
            ![SHUTDOWN_OK, SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED]
                .contains(&SHUTDOWN_PANICKED)
        );
    }

    #[test]
    fn shutdown_status_distinguishes_outcomes() {
        assert_eq!(shutdown_status(false, true, 0), SHUTDOWN_NOT_INITIALIZED);
        assert_eq!(shutdown_status(false, false, 3), SHUTDOWN_NOT_INITIALIZED);
        assert_eq!(shutdown_status(true, true, 0), SHUTDOWN_OK);
        assert_eq!(shutdown_status(true, false, 0), SHUTDOWN_INCOMPLETE);
        // レビュー #6 P1-6: IAT 復元に失敗したスロットが残れば、
        // 進行中 Detour が完了していても完全停止とは言えない。
        assert_eq!(shutdown_status(true, true, 1), SHUTDOWN_INCOMPLETE);
        assert_eq!(shutdown_status(true, false, 2), SHUTDOWN_INCOMPLETE);
    }
}
