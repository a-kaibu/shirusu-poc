//! shirusu Agent DLL。対象プロセスへ注入される cdylib。
//!
//! 初期化の段階分け（overview「プロセスの起動・アタッチと Agent の
//! 初期化」）:
//! 1. `DllMain` では何もしない（Loader Lock の下で複雑な処理をしない）。
//!    スレッドごとの通知を止めるだけに留める。
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

pub const STATUS_OK: u32 = 0;
pub const STATUS_BAD_BOOTSTRAP: u32 = 1;
pub const STATUS_MAPPING_FAILED: u32 = 2;
pub const STATUS_HOOK_FAILED: u32 = 3;
pub const STATUS_ALREADY_INITIALIZED: u32 = 4;
pub const STATUS_UNSUPPORTED: u32 = 5;

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
        win::init(bootstrap)
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
        win::shutdown()
    }
    #[cfg(not(windows))]
    {
        STATUS_UNSUPPORTED
    }
}

/// DllMain では初期化を行わない（overview の段階分け）。スレッド
/// 通知を止めるだけに留める。
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllMain(
    hinst: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: hinst はこの DLL のインスタンスハンドル。
        unsafe {
            windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls(hinst);
        }
    }
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

    pub fn init(bootstrap: *const AgentBootstrap) -> u32 {
        if bootstrap.is_null() {
            return STATUS_BAD_BOOTSTRAP;
        }
        // SAFETY: 呼び出し側の契約（初期化が戻るまで有効）に従い値をコピーする。
        let b = unsafe { *bootstrap };
        if b.version != BOOTSTRAP_VERSION {
            return STATUS_BAD_BOOTSTRAP;
        }
        let config = match b.validate() {
            Ok(c) => c,
            Err(_) => return STATUS_BAD_BOOTSTRAP,
        };
        if STATE.lock().unwrap().is_some() {
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
        let pool = Arc::new(SlotPool::new(0));
        let agent = Arc::new(
            Agent::new(pool, config, host_monitor)
                .with_timestamp_source(Arc::new(QpcTimestampSource::new()))
                // L11: Host が Bootstrap v4 で指定した --order=global を Agent へ渡す。
                .with_order_global(b.order_global != 0),
        );
        for i in 0..b.ring_count as usize {
            let delivery = ExpansionDelivery {
                len: config.required_len(),
                base: None,
                handle_value: Some(b.mapping_handles[i] as usize),
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
        for i in 0..b.ring_count as usize {
            let h = b.space_handles[i];
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
                .with_detailed_mode(b.detailed_mode != 0),
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
            Err(EngineError::InstallFailed { unrestored, .. }) => {
                // SAFETY: bootstrap は Host が書き込み可能に確保した
                // 領域で、初期化が戻るまで有効 (呼び出し側の契約)。
                unsafe {
                    AgentBootstrap::write_install_failure(
                        bootstrap as *mut AgentBootstrap,
                        unrestored.len() as u32,
                    );
                }
                engine::clear_runtime(&rt);
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
        // L02: COM Factory 関数の Inline Hook を Inline の後で設置する。
        // Inline と同じく best-effort であり、見送りがあっても初期化は
        // 成功として継続する。Factory 関数が 1 つもフックできなくても、
        // Win32 API の記録は続く（COM メソッドの記録だけが無い）。
        // SAFETY: 初期化専用スレッドからの呼び出し（L01 と同じ前提）。
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
        *STATE.lock().unwrap() = Some(DllState {
            installed,
            inline: inline_outcome.installed,
            com_factories: com_factory_outcome.installed,
            winrt_activations: winrt_activation_outcome.installed,
            internal_hooks: internal_hook_outcome.installed,
            callbacks: callback_outcome.installed,
        });
        if b.init_done_handle != 0 {
            // SAFETY: Host が複製して渡したイベント。立てた後は所有を
            // 持たないよう forget する（Host 側の実体を閉じない）。
            let ev = unsafe { EventObject::from_handle_value(b.init_done_handle as usize, false) };
            let _ = ev.set();
            std::mem::forget(ev);
        }
        STATUS_OK
    }

    pub fn shutdown() -> u32 {
        // 順序（レビュー #4 の #9 + 第5回 #6/#7 + #6 の P1-6 + L01 + L02）:
        // (1) 新規記録を無効化し、以後の Detour は元関数を素通しで
        // 呼ぶ。(2) 進行中の Detour が完了するまで待つ。(3) COM Factory
        // と Inline のプロローグを復元する。(4) IAT を復元する。(5) 復元が全件
        // できた場合にだけ、ランタイム登録を解除して再初期化を受け入れる。
        // Host はこの後に Ring の最終回収と Trace の確定を行う。
        //
        // 戻り値は状態を区別する（レビュー第5回 #6）: 完了待ちが
        // タイムアウトした場合と、IAT 復元に失敗したスロットが
        // 残った場合 (P1-6) は SHUTDOWN_INCOMPLETE を返し、Host が
        // Event Integrity を劣化させられるようにする。セッションが
        // 無ければ SHUTDOWN_NOT_INITIALIZED。
        let state = STATE.lock().unwrap().take();
        let Some(state) = state else {
            return shutdown_status(false, false, 0);
        };
        let drained;
        let mut unrestored: Vec<u32> = Vec::new();
        match engine::runtime() {
            Some(rt) => {
                rt.shutdown_recording();
                // 待ち上限を超えても復元は試みる（対象プロセスの終了を
                // 妨げるより、復元を優先する）。その場合に書き込み途中
                // だった Detour のイベントは不完全なまま Ring に残り、
                // Host 側の完全性評価で扱われる。
                drained = rt.wait_in_flight_drained(std::time::Duration::from_secs(5));
                // L02: COM Factory のプロローグ復元を Inline と同じく
                // IAT 復元より先に行う。
                // SAFETY: 設置時に保存した Inline Hook 情報。対象モジュールは
                // まだロードされている前提（DLL のアンロード直前に呼ばれる）。
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.com_factories) });
                // L14: WinRT アクティベーションのプロローグ復元も同じく
                // IAT 復元より先に行う。
                // SAFETY: 同上。
                unrestored
                    .extend(unsafe { engine::uninstall_inline_hooks(&state.winrt_activations) });
                // L15: 内部 API (Nt*) のプロローグ復元も同じく
                // IAT 復元より先に行う。
                // SAFETY: 同上。
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.internal_hooks) });
                // L16: コールバック検出フックのプロローグ復元も同じく
                // IAT 復元より先に行う。
                // SAFETY: 同上。
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.callbacks) });
                // L01: Inline プロローグの復元を IAT 復元より先に行う。
                // SAFETY: 設置時に保存した Inline Hook 情報。対象モジュールは
                // まだロードされている前提（DLL のアンロード直前に呼ばれる）。
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.inline) });
                // SAFETY: 設置時に保存したスロット情報。対象モジュールは
                // まだロードされている前提（DLL のアンロード直前に呼ばれる）。
                unrestored.extend(unsafe { engine::uninstall_hooks(&state.installed) });
                if unrestored.is_empty() {
                    // 登録解除は IAT 復元の後（RuntimeSlot の安全性契約）。
                    engine::clear_runtime(&rt);
                }
                // 復元できなかったスロットが残る間は登録を解除しない
                // (P1-6): IAT がまだ Detour を指しており、登録が無いと
                // 到達した Detour が元関数を引けず、対象 API が失敗値
                // を返してアプリの挙動が変わる。記録は無効化済みの
                // ため、以後の Detour は元関数へ素通しし挙動は保た
                // れる。副作用として、この状態で再初期化すると
                // ALREADY_INITIALIZED になる (Detour 残存下で新しい
                // 設置が現在の IAT 値を「元の値」と誤認するため、
                // 安全側の帰結である)。
            }
            None => {
                // 設置状態はあるのにランタイム登録が無い異常系。
                // 復元だけは行い、完了確認はできないため未完了とする。
                // SAFETY: 同上。
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.com_factories) });
                unrestored
                    .extend(unsafe { engine::uninstall_inline_hooks(&state.winrt_activations) });
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.internal_hooks) });
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.callbacks) });
                unrestored.extend(unsafe { engine::uninstall_inline_hooks(&state.inline) });
                unrestored.extend(unsafe { engine::uninstall_hooks(&state.installed) });
                drained = false;
            }
        }
        shutdown_status(true, drained, unrestored.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_hook::bootstrap::{SHUTDOWN_INCOMPLETE, SHUTDOWN_NOT_INITIALIZED, SHUTDOWN_OK};

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
