//! コールバック検出と WndProc ラッパー（L16）。

use super::*;

// ---- コールバック (L16) ----

/// コールバック検出フックと WndProc ラッパー共通の前処理。
/// `prepare_com` / `prepare_winrt` と同じ判定だが、元関数は呼び出し側が
/// 解決して渡す（検出フック関数はランタイムの別表、WndProc はスロット表から）。
///
/// WndProc の入口では Unavailable を返さない：ランタイムが無くても元の
/// プロシージャはスロット表から判明しているため、記録せず素通しで呼ぶ。
/// WndProc が 0 を返すとウィンドウ作成の失敗（WM_NCCREATE / WM_CREATE）
/// などアプリの挙動が変わるため、元のプロシージャを呼ばずに失敗値を
/// 返す経路は作らない。
pub(super) enum CallbackPrepare {
    Proceed {
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

/// コールバック検出フック関数の Detour 共通の前処理。元関数はランタイムの
/// コールバック別表から引く（`prepare_com` と同じ形）。
pub(super) fn prepare_callback_hook(hook_index: usize) -> CallbackPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return CallbackPrepare::Unavailable;
        };
        let original = rt.callback_original(hook_index);
        if original == 0 {
            return CallbackPrepare::Unavailable;
        }
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return CallbackPrepare::Unavailable;
    };
    let original = rt.callback_original(hook_index);
    if original == 0 {
        return CallbackPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            CallbackPrepare::Proceed {
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
            CallbackPrepare::Passthrough { original }
        }
    }
}

/// WndProc ラッパーの前処理。元関数はスロット表から判明済みのため、
/// ランタイムが無くても Passthrough で元のプロシージャを呼ぶ。
pub(super) fn prepare_callback_dispatch(original: usize) -> CallbackPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        // ランタイムが無い（終了手順の後など）：記録せず素通しで呼ぶ。
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    // L23: 呼び出し元は user32.dll の DispatchMessageW（Windows 分類）の
    // ため通常は抑制されない。Runtime 分類の場合は記録しない。
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            CallbackPrepare::Proceed {
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
            CallbackPrepare::Passthrough { original }
        }
    }
}

/// WndProc の型（`extern "system-unwind" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT`）。
pub(super) type WndProcFn =
    unsafe extern "system-unwind" fn(*mut c_void, u32, usize, isize) -> isize;
pub(super) type RegisterClassExFn = unsafe extern "system-unwind" fn(*const c_void) -> u16;
pub(super) type SetWindowLongPtrFn =
    unsafe extern "system-unwind" fn(*mut c_void, i32, usize) -> usize;

/// WndProc ラッパー 1 件。スロット番号を固定で持ち、共通の dispatch へ渡す。
macro_rules! wnd_proc_wrapper {
    ($name:ident, $slot:expr) => {
        unsafe extern "system-unwind" fn $name(
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> isize {
            unsafe { wnd_proc_dispatch($slot, hwnd, msg, wparam, lparam) }
        }
    };
}

macro_rules! wnd_proc_wrappers {
    ($($name:ident = $slot:expr),* $(,)?) => {
        $(wnd_proc_wrapper!($name, $slot);)*
        /// スロット番号順の WndProc ラッパー関数列。
        static CALLBACK_WRAPPERS: [WndProcFn; CALLBACK_PROC_SLOTS] = [
            $($name as WndProcFn),*
        ];
    };
}

wnd_proc_wrappers!(
    wnd_proc_wrapper_00 = 0,
    wnd_proc_wrapper_01 = 1,
    wnd_proc_wrapper_02 = 2,
    wnd_proc_wrapper_03 = 3,
    wnd_proc_wrapper_04 = 4,
    wnd_proc_wrapper_05 = 5,
    wnd_proc_wrapper_06 = 6,
    wnd_proc_wrapper_07 = 7,
    wnd_proc_wrapper_08 = 8,
    wnd_proc_wrapper_09 = 9,
    wnd_proc_wrapper_10 = 10,
    wnd_proc_wrapper_11 = 11,
    wnd_proc_wrapper_12 = 12,
    wnd_proc_wrapper_13 = 13,
    wnd_proc_wrapper_14 = 14,
    wnd_proc_wrapper_15 = 15,
    wnd_proc_wrapper_16 = 16,
    wnd_proc_wrapper_17 = 17,
    wnd_proc_wrapper_18 = 18,
    wnd_proc_wrapper_19 = 19,
    wnd_proc_wrapper_20 = 20,
    wnd_proc_wrapper_21 = 21,
    wnd_proc_wrapper_22 = 22,
    wnd_proc_wrapper_23 = 23,
    wnd_proc_wrapper_24 = 24,
    wnd_proc_wrapper_25 = 25,
    wnd_proc_wrapper_26 = 26,
    wnd_proc_wrapper_27 = 27,
    wnd_proc_wrapper_28 = 28,
    wnd_proc_wrapper_29 = 29,
    wnd_proc_wrapper_30 = 30,
    wnd_proc_wrapper_31 = 31,
);

/// スロット番号からラッパー関数のアドレスを引く。
pub(super) fn wrapper_for_slot(slot: usize) -> Option<usize> {
    CALLBACK_WRAPPERS.get(slot).map(|f| *f as usize)
}

/// ラッパー関数のアドレスからスロット番号を引く。ラッパーでなければ None。
pub(super) fn slot_for_wrapper(wrapper: usize) -> Option<usize> {
    CALLBACK_WRAPPERS
        .iter()
        .position(|f| *f as usize == wrapper)
}

/// ラッパー関数のアドレスから元の WndProc を引く。ラッパーでなければ None。
pub(super) fn original_for_wrapper(wrapper: usize) -> Option<usize> {
    slot_for_wrapper(wrapper).and_then(|slot| callback_procs().original(slot))
}

/// ラップされた WndProc の本体。コールバック enter を記録し、呼出スタックへ
/// 積んでから元のプロシージャを呼ぶ。コールバック中の API 呼び出しは
/// このイベントを親として入れ子に記録される（A43 / C18）。
/// 元のプロシージャが例外で中断したら、ComCallGuard が CallAborted を
/// 記録する（L08。例外は捕捉しない）。
pub(super) unsafe fn wnd_proc_dispatch(
    slot: usize,
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let Some(original) = callback_procs().original(slot) else {
        // 到達しないはずの防御：スロットが空なら元のプロシージャは
        // 呼べない。0 を返す（呼ぶ先が無いため他に手段が無い）。
        return 0;
    };
    // SAFETY: スロット表から引いた元のプロシージャ。
    let orig: WndProcFn = unsafe { std::mem::transmute(original) };
    let (rt, tid, _flight, mut guard, mut le) = match prepare_callback_dispatch(original) {
        CallbackPrepare::Proceed {
            rt,
            original: _,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: スロット表から引いた元のプロシージャ。
            let orig: WndProcFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(hwnd, msg, wparam, lparam) };
        }
        CallbackPrepare::Unavailable => return 0,
    };
    let call_id = rt.alloc_call_id();
    let values = crate::callback::callback_enter_values(
        hwnd as u64,
        CallbackKind::WndProc,
        msg,
        wparam as u64,
        lparam as i64,
        original as u64,
    );
    if let Ok(bytes) = crate::callback::encode_callback_enter(&values) {
        rt.record_callback_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元のプロシージャが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard =
        ComCallGuard::new_for(&rt, tid, call_id, CALLBACK_API_ID, CALLBACK_LEAVE_SCHEMA_ID);
    le.restore_before_original();
    guard.suspend();
    // SAFETY: スロット表から引いた元のプロシージャ。
    let (result, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(hwnd, msg, wparam, lparam) },
        (call_guard, rt, _flight, guard),
    );
    let _ = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let values = crate::callback::callback_leave_values(result as i64);
    if let Ok(bytes) = crate::callback::encode_callback_leave(&values) {
        rt.record_callback_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    result
}

/// `RegisterClassExW/A` の構造体バイト列を読む。`cbSize` が範囲外・
/// 読めない場合は None（素通し）。
pub(super) fn read_class_bytes(wc: *const c_void) -> Option<Vec<u8>> {
    if wc.is_null() {
        return None;
    }
    let mut size_buf = [0u8; 4];
    if !ProcessMemory.read_exact(wc as u64, &mut size_buf) {
        return None;
    }
    let cb_size = u32::from_le_bytes(size_buf) as usize;
    if !(16..=MAX_WNDCLASSEX_BYTES).contains(&cb_size) {
        return None;
    }
    let mut buf = vec![0u8; cb_size];
    if !ProcessMemory.read_exact(wc as u64, &mut buf) {
        return None;
    }
    Some(buf)
}

/// `RegisterClassExW/A` の Detour 本体。アプリが渡した構造体のコピーを
/// 作り、コピー内の `lpfnWndProc` だけをラッパーへすり替えて元の関数へ
/// 渡す。読めない・`cbSize` が範囲外・ラップできない場合は素通しする
/// （クラス登録自体は成功させ、コールバックの記録だけが無い）。
/// この Detour 自体は API 呼び出しイベントを記録しない（RegisterClassEx
/// は API 表に無い）。記録されるのはラッパー経由のコールバックである。
pub(super) unsafe fn detour_register_class_ex(hook_index: usize, wc: *const c_void) -> u16 {
    let (_rt, original, _tid, _flight, mut guard, mut le) = match prepare_callback_hook(hook_index)
    {
        CallbackPrepare::Proceed {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: ランタイムの別表から引いた元の関数。
            let orig: RegisterClassExFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(wc) };
        }
        CallbackPrepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した元の RegisterClassEx。
    let orig: RegisterClassExFn = unsafe { std::mem::transmute(original) };
    // 構造体をコピーし、コピー内の lpfnWndProc だけをラッパーへすり替える。
    // 読めない・cbSize が範囲外・ラップできない場合は None（素通し）。
    let replaced: Option<Vec<u8>> = read_class_bytes(wc).and_then(|bytes| {
        let original_proc = read_usize(wc as u64 + WNDPROC_FIELD_OFFSET as u64)?;
        let slot = callback_procs().wrap(original_proc)?;
        let wrapper = wrapper_for_slot(slot)?;
        wrap_wndproc_in_class(&bytes, wrapper).map(|(_, replaced)| replaced)
    });
    let call_with: *const c_void = match &replaced {
        Some(bytes) => bytes.as_ptr() as *const c_void,
        None => wc,
    };
    le.restore_before_original();
    guard.suspend();
    // SAFETY: コピーした構造体（または元の構造体）を渡す。
    let (result, (_rt, _flight, mut guard, replaced)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(call_with) },
        (_rt, _flight, guard, replaced),
    );
    let _ = le.capture_after_original();
    guard.resume();
    drop(replaced);
    le.restore_for_return();
    result
}

pub(super) unsafe extern "system-unwind" fn detour_register_class_ex_w(wc: *const c_void) -> u16 {
    unsafe { detour_register_class_ex(CALLBACK_HOOK_REGISTER_CLASS_EX_W, wc) }
}

pub(super) unsafe extern "system-unwind" fn detour_register_class_ex_a(wc: *const c_void) -> u16 {
    unsafe { detour_register_class_ex(CALLBACK_HOOK_REGISTER_CLASS_EX_A, wc) }
}

/// `SetWindowLongPtrW/A` の Detour 本体。`GWLP_WNDPROC` の差し替えだけを
/// ラップする。それ以外（他のインデックス・0 の指定）は素通しする。
/// 戻り値が shirusu のラッパーだった場合は元のプロシージャへ解決して
/// アプリへ返す（アプリはラッパーの存在を観測しない）。
/// この Detour 自体は API 呼び出しイベントを記録しない（SetWindowLongPtr
/// は API 表に無い）。記録されるのはラッパー経由のコールバックである。
pub(super) unsafe fn detour_set_window_long_ptr(
    hook_index: usize,
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    let (_rt, original, _tid, _flight, mut guard, mut le) = match prepare_callback_hook(hook_index)
    {
        CallbackPrepare::Proceed {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: ランタイムの別表から引いた元の関数。
            let orig: SetWindowLongPtrFn = unsafe { std::mem::transmute(original) };
            let prev = unsafe { orig(hwnd, n_index, new_long) };
            let last_error = crate::last_error::get();
            let prev = resolve_window_long(n_index, prev);
            crate::last_error::set(last_error);
            return prev;
        }
        CallbackPrepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した元の SetWindowLongPtr。
    let orig: SetWindowLongPtrFn = unsafe { std::mem::transmute(original) };
    let mut call_with = new_long;
    if should_wrap_set_window_long(n_index, new_long) {
        // 既にラッパーになっている値（アプリが GetWindowLongPtrW で
        // 読み戻したもの）をそのまま渡した場合は二重ラップしない。
        if slot_for_wrapper(new_long).is_none() {
            if let Some(slot) = callback_procs().wrap(new_long) {
                if let Some(wrapper) = wrapper_for_slot(slot) {
                    call_with = wrapper;
                }
            }
        }
    }
    le.restore_before_original();
    guard.suspend();
    // SAFETY: ラップ済みまたは元の値を渡す。
    let (prev, (_rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(hwnd, n_index, call_with) },
        (_rt, _flight, guard),
    );
    let _ = le.capture_after_original();
    guard.resume();
    // Only GWLP_WNDPROC contains a procedure. User data and other fields must
    // remain bit-for-bit identical even if they happen to equal a wrapper.
    let prev = resolve_window_long(n_index, prev);
    le.restore_for_return();
    prev
}

pub(super) fn resolve_window_long(field: i32, value: usize) -> usize {
    if field == crate::callback::GWLP_WNDPROC {
        resolve_prev_proc(value, original_for_wrapper)
    } else {
        value
    }
}

pub(super) type GetLongPtrFn = unsafe extern "system-unwind" fn(*mut c_void, i32) -> usize;

pub(super) unsafe fn detour_get_long_ptr(
    index: usize,
    hwnd: *mut c_void,
    field: i32,
    proc_field: i32,
) -> usize {
    let (original, state) = match prepare_callback_hook(index) {
        CallbackPrepare::Proceed {
            original,
            rt,
            tid: _,
            flight,
            guard,
            last_error,
        } => (original, Some((rt, flight, guard, last_error))),
        CallbackPrepare::Passthrough { original } => (original, None),
        CallbackPrepare::Unavailable => return 0,
    };
    let original: GetLongPtrFn = unsafe { std::mem::transmute(original) };
    let mut state = state;
    if let Some((_, _, guard, le)) = state.as_mut() {
        le.restore_before_original();
        guard.suspend();
    }
    let (value, mut state) = crate::seh::invoke(0, |_| unsafe { original(hwnd, field) }, state);
    // LastError must be captured before table lookups or synchronization.
    let saved_error = crate::last_error::get();
    if let Some((_, _, guard, _)) = state.as_mut() {
        guard.resume();
    }
    let value = if field == proc_field {
        resolve_prev_proc(value, original_for_wrapper)
    } else {
        value
    };
    crate::last_error::set(saved_error);
    value
}
pub(super) unsafe extern "system-unwind" fn detour_get_window_long_ptr_w(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_WINDOW_LONG_PTR_W, hwnd, field, -4) }
}
pub(super) unsafe extern "system-unwind" fn detour_get_window_long_ptr_a(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_WINDOW_LONG_PTR_A, hwnd, field, -4) }
}
pub(super) unsafe extern "system-unwind" fn detour_get_class_long_ptr_w(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_CLASS_LONG_PTR_W, hwnd, field, -24) }
}
pub(super) unsafe extern "system-unwind" fn detour_get_class_long_ptr_a(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_CLASS_LONG_PTR_A, hwnd, field, -24) }
}

pub(super) unsafe extern "system-unwind" fn detour_set_window_long_ptr_w(
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    unsafe {
        detour_set_window_long_ptr(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W, hwnd, n_index, new_long)
    }
}

pub(super) unsafe extern "system-unwind" fn detour_set_window_long_ptr_a(
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    unsafe {
        detour_set_window_long_ptr(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A, hwnd, n_index, new_long)
    }
}
