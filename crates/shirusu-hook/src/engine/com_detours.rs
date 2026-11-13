//! COM Factory と WinRT アクティベーションの Detour（L02 / L14）。

use super::*;

// ---- L02: COM メソッド・Factory の Detour ----
//
// COM メソッドの Detour は (vtable インデックス, arity) の組ごとに
// 1 個の `extern "system-unwind" fn` である。Detour は `this` から追跡表を
// 引き、インターフェイス名・メソッド名を復元して記録する。同じ
// (index, arity) の組は全インターフェイスで共有できる（例：index 6
// arity 2 は IShellLinkW::GetDescription と IPersistFile::Save の両方）。
// 元のメソッドは複製 vtable のアドレスを鍵に ComCloneRegistry から引く
// ため、ランタイムが無いセッション終了後でも素通しで呼べる。
//
// 記録の手順は Win32 Detour と同じ（prepare 相当 → enter 取得 → 元の
// 呼び出し → leave 取得 → LastError 復元）。例外で中断した場合は
// ComCallGuard が CallAborted を記録する（L08）。

/// COM の失敗値（E_FAIL）。
pub(super) const COM_E_FAIL: i32 = 0x8000_4005u32 as i32;

/// Factory 関数の Detour 共通の前処理。Win32 の `prepare` と同じ
/// 判定だが、ApiDef を持たないため元関数は Factory 別表から引く。
pub(super) enum ComPrepare {
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

pub(super) fn prepare_com(factory_index: usize) -> ComPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return ComPrepare::Unavailable;
        };
        let original = rt.com_original(factory_index);
        if original == 0 {
            return ComPrepare::Unavailable;
        }
        le.restore_before_original();
        return ComPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return ComPrepare::Unavailable;
    };
    let original = rt.com_original(factory_index);
    if original == 0 {
        return ComPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            ComPrepare::Passthrough { original }
        }
    }
}

pub(super) type CoCreateInstanceFn = unsafe extern "system-unwind" fn(
    *const Guid,
    *mut c_void,
    u32,
    *const Guid,
    *mut *mut c_void,
) -> i32;
pub(super) type CoGetClassObjectFn = unsafe extern "system-unwind" fn(
    *const Guid,
    u32,
    *mut c_void,
    *const Guid,
    *mut *mut c_void,
) -> i32;

/// Factory 呼び出しが返したインターフェイスを追跡対象に加え、既知
/// インターフェイスなら vtable 複製による Detour を設置する。
/// 設置の成否は呼び出しの成否に影響しない（best-effort）。
pub(super) fn on_factory_result(
    rt: &Arc<HookRuntime>,
    factory: &'static str,
    iid: Guid,
    ptr: usize,
) {
    rt.with_com_tracker(|t| {
        retire_unloaded_com_address(t, ptr as u64);
        t.note_factory_result(ptr as u64, iid, factory);
    });
    if interface_by_iid(&iid).is_some() {
        // SAFETY: successful factory returned an owned live COM reference.
        let _ = unsafe { intercept_object(rt, ptr, iid) };
    }
}

pub(super) unsafe extern "system-unwind" fn detour_co_create_instance(
    clsid: *const Guid,
    unk_outer: *mut c_void,
    cls_context: u32,
    iid: *const Guid,
    ppv: *mut *mut c_void,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) =
        match prepare_com(COM_FACTORY_CO_CREATE_INSTANCE) {
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, flight, guard, last_error),
            ComPrepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: CoCreateInstanceFn = unsafe { std::mem::transmute(original) };
                return unsafe { orig(clsid, unk_outer, cls_context, iid, ppv) };
            }
            ComPrepare::Unavailable => return COM_E_FAIL,
        };
    // SAFETY: 設置時に保存した本物の CoCreateInstance。
    let orig: CoCreateInstanceFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let requested = read_guid(iid as u64);
    let values = crate::com::com_factory_enter_values(&crate::com::ComFactoryArgs {
        method: "CoCreateInstance",
        clsid: read_guid(clsid as u64),
        iid: requested,
        context: cls_context,
        outer: unk_outer as u64,
        server_info: 0,
        output_address: ppv as u64,
        clsid_address: clsid as u64,
        iid_address: iid as u64,
    });
    if let Ok(bytes) = crate::com::encode_com_factory_enter(&values) {
        rt.record_com_factory_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        crate::com::COM_METHOD_API_ID,
        crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(clsid, unk_outer, cls_context, iid, ppv) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !ppv.is_null() {
        if let Some(ptr) = read_usize(ppv as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(iid_guid) = requested {
                on_factory_result(&rt, "CoCreateInstance", iid_guid, ptr);
            }
        }
    }
    let values = crate::com::com_factory_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_factory_leave(&values) {
        rt.record_com_factory_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

pub(super) unsafe extern "system-unwind" fn detour_co_get_class_object(
    clsid: *const Guid,
    cls_context: u32,
    server_info: *mut c_void,
    iid: *const Guid,
    ppv: *mut *mut c_void,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) =
        match prepare_com(COM_FACTORY_CO_GET_CLASS_OBJECT) {
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, flight, guard, last_error),
            ComPrepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: CoGetClassObjectFn = unsafe { std::mem::transmute(original) };
                return unsafe { orig(clsid, cls_context, server_info, iid, ppv) };
            }
            ComPrepare::Unavailable => return COM_E_FAIL,
        };
    // SAFETY: 設置時に保存した本物の CoGetClassObject。
    let orig: CoGetClassObjectFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let requested = read_guid(iid as u64);
    let values = crate::com::com_factory_enter_values(&crate::com::ComFactoryArgs {
        method: "CoGetClassObject",
        clsid: read_guid(clsid as u64),
        iid: requested,
        context: cls_context,
        outer: 0,
        server_info: server_info as u64,
        output_address: ppv as u64,
        clsid_address: clsid as u64,
        iid_address: iid as u64,
    });
    if let Ok(bytes) = crate::com::encode_com_factory_enter(&values) {
        rt.record_com_factory_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        crate::com::COM_METHOD_API_ID,
        crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(clsid, cls_context, server_info, iid, ppv) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !ppv.is_null() {
        if let Some(ptr) = read_usize(ppv as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(iid_guid) = requested {
                on_factory_result(&rt, "CoGetClassObject", iid_guid, ptr);
            }
        }
    }
    let values = crate::com::com_factory_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_factory_leave(&values) {
        rt.record_com_factory_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

pub(super) type RoActivateInstanceFn =
    unsafe extern "system-unwind" fn(usize, *mut *mut c_void) -> i32;
pub(super) type RoGetActivationFactoryFn =
    unsafe extern "system-unwind" fn(usize, *const Guid, *mut *mut c_void) -> i32;

/// WinRT アクティベーション関数の Detour 共通の前処理。COM の
/// `prepare_com` と同じ判定だが、元関数は WinRT 別表から引く。
pub(super) enum WinRtPrepare {
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

pub(super) fn prepare_winrt(activation_index: usize) -> WinRtPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return WinRtPrepare::Unavailable;
        };
        let original = rt.winrt_original(activation_index);
        if original == 0 {
            return WinRtPrepare::Unavailable;
        }
        le.restore_before_original();
        return WinRtPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return WinRtPrepare::Unavailable;
    };
    let original = rt.winrt_original(activation_index);
    if original == 0 {
        return WinRtPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            WinRtPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            WinRtPrepare::Passthrough { original }
        }
    }
}

// Share recording mechanics, but invoke each activation API with its own ABI.
pub(super) fn detour_winrt_activation(
    activation_index: usize,
    function: &'static str,
    class_id: usize,
    iid: Option<*const Guid>,
    out: *mut *mut c_void,
    invoke: impl FnOnce(usize) -> i32 + Copy,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) = match prepare_winrt(activation_index) {
        WinRtPrepare::Record {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        WinRtPrepare::Passthrough { original } => {
            return invoke(original);
        }
        WinRtPrepare::Unavailable => return COM_E_FAIL,
    };
    let requested_iid = match iid {
        Some(address) => read_guid(address as u64),
        None => Some(IID_IINSPECTABLE),
    };
    let raw = match iid {
        Some(address) => [class_id, address as usize, out as usize],
        None => [class_id, out as usize, 0],
    };
    let call_id = rt.alloc_call_id();
    // HSTRING からクラス名を読む。読めなければ空のまま記録する
    // （クラス名の読み取り失敗で呼び出し自体を失敗させない）。
    let class_name = crate::winrt::read_hstring_string(class_id).unwrap_or_default();
    let values = crate::winrt::winrt_activation_enter_values(
        0,
        &class_name,
        function,
        &crate::com::raw_arg_slots(&raw[..if iid.is_some() { 3 } else { 2 }]),
    );
    if let Ok(bytes) = crate::winrt::encode_winrt_activation_enter(&values) {
        rt.record_winrt_activation_enter(tid, call_id, &bytes);
    }
    drop(values);
    drop(class_name);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        WINRT_ACTIVATION_API_ID,
        WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| invoke(original),
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // WinRT は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !out.is_null() {
        if let Some(ptr) = read_usize(out as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(requested_iid) = requested_iid {
                on_factory_result(&rt, function, requested_iid, ptr);
            }
        }
    }
    let values = crate::winrt::winrt_activation_leave_values(hr, returned_object);
    if let Ok(bytes) = crate::winrt::encode_winrt_activation_leave(&values) {
        rt.record_winrt_activation_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

pub(super) unsafe extern "system-unwind" fn detour_ro_activate_instance(
    class_id: usize,
    out: *mut *mut c_void,
) -> i32 {
    detour_winrt_activation(
        WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE,
        "RoActivateInstance",
        class_id,
        None,
        out,
        |original| {
            let original: RoActivateInstanceFn = unsafe { std::mem::transmute(original) };
            unsafe { original(class_id, out) }
        },
    )
}

pub(super) unsafe extern "system-unwind" fn detour_ro_get_activation_factory(
    class_id: usize,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    detour_winrt_activation(
        WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
        "RoGetActivationFactory",
        class_id,
        Some(iid),
        out,
        |original| {
            let original: RoGetActivationFactoryFn = unsafe { std::mem::transmute(original) };
            unsafe { original(class_id, iid, out) }
        },
    )
}
