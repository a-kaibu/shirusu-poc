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
//! - `shirusu_agent_shutdown() -> u32`（IAT の巻き戻し）

use shirusu_hook::bootstrap::AgentBootstrap;

pub const STATUS_OK: u32 = 0;
pub const STATUS_BAD_BOOTSTRAP: u32 = 1;
pub const STATUS_MAPPING_FAILED: u32 = 2;
pub const STATUS_HOOK_FAILED: u32 = 3;
pub const STATUS_ALREADY_INITIALIZED: u32 = 4;
pub const STATUS_UNSUPPORTED: u32 = 5;

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
/// 完了待ち → IAT の巻き戻し、の順に行う。Host は対象プロセスを
/// 生かしたまま記録だけを終える場合（LaunchedCapture::finish）に
/// これをリモートスレッドで呼んでから最終回収・確定を行う。
/// 対象が既に終了している場合は呼ばれない（呼ぶ必要もない）。
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
    use shirusu_hook::bootstrap::BOOTSTRAP_VERSION;
    use shirusu_hook::engine::{self, EngineError, InstalledHooks};
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
        // 同じ登録経路）。スロットは使い切りであり、使い果たしたら
        // Capture Coverage の欠落として数える（Phase 3 の範囲）。
        let pool = Arc::new(SlotPool::new(0));
        let agent = Arc::new(
            Agent::new(pool, config, host_monitor)
                .with_timestamp_source(Arc::new(QpcTimestampSource::new())),
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
        let rt = Arc::new(HookRuntime::new(agent, space_notifies, data_ready));
        if engine::set_runtime(Arc::clone(&rt)).is_err() {
            return STATUS_ALREADY_INITIALIZED;
        }
        // メインモジュール（対象 EXE）の IAT をパッチする。
        // SAFETY: GetModuleHandleW(NULL) はメインモジュールを返す。
        let main_base = unsafe { GetModuleHandleW(std::ptr::null()) };
        if main_base.is_null() {
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
            Err(_) => return STATUS_HOOK_FAILED,
        };
        // Host が読み戻せるよう、init_done を立てる前に Bootstrap へ
        // 設置/欠落件数を書き戻す。
        // SAFETY: bootstrap は Host が書き込み可能に確保した領域で、
        // 初期化が戻るまで有効（呼び出し側の契約）。書き戻し欄は
        // バージョン 2 で追加された結果専用の欄である。
        unsafe {
            AgentBootstrap::write_hook_outcome(
                bootstrap as *mut AgentBootstrap,
                installed.slots.len() as u32,
                installed.plan.missing.len() as u32,
            );
        }
        *STATE.lock().unwrap() = Some(DllState { installed });
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
        // 順序（レビュー #4 の #9）: (1) 新規記録を無効化し、以後の
        // Detour は元関数を素通しで呼ぶ。(2) 進行中の Detour が完了
        // するまで待つ。(3) IAT を復元する。Host はこの後に Ring の
        // 最終回収と Trace の確定を行う。
        if let Some(rt) = engine::runtime() {
            rt.shutdown_recording();
            // 待ち上限を超えても復元は試みる（対象プロセスの終了を
            // 妨げるより、復元を優先する）。その場合に書き込み途中
            // だった Detour のイベントは不完全なまま Ring に残り、
            // Host 側の完全性評価で扱われる。
            let _ = rt.wait_in_flight_drained(std::time::Duration::from_secs(5));
        }
        let state = STATE.lock().unwrap().take();
        if let Some(s) = state {
            // SAFETY: 設置時に保存したスロット情報。対象モジュールは
            // まだロードされている前提（DLL のアンロード直前に呼ばれる）。
            unsafe { engine::uninstall_hooks(&s.installed) };
        }
        STATUS_OK
    }
}
