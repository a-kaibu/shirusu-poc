//! COM メソッドの Detour と dispatch（L02）。

use super::*;

/// 元の COM メソッドを呼ぶ。`args` は `this` を除く引数（最大 4 個）。
///
/// # Safety
/// `original` はこの引数個数の `extern "system-unwind" fn` であること
/// （呼び出し側は追跡表のメソッド定義で arity を確認している）。
pub(super) unsafe fn call_com_original(original: usize, this: usize, args: &[usize]) -> i32 {
    // SAFETY: 各分岐は引数個数に対応する関数型へ transmute し、その個数で呼ぶ。
    // 戻り値は HRESULT（i32）の下位 32 ビット。
    unsafe {
        match args.len() {
            0 => call_original::<1>(original, &[this]) as i32,
            1 => call_original::<2>(original, &[this, args[0]]) as i32,
            2 => call_original::<3>(original, &[this, args[0], args[1]]) as i32,
            3 => call_original::<4>(original, &[this, args[0], args[1], args[2]]) as i32,
            4 => call_original::<5>(original, &[this, args[0], args[1], args[2], args[3]]) as i32,
            _ => COM_E_FAIL,
        }
    }
}

/// 元の COM メソッド呼び出しの後の追跡更新（QI / AddRef / Release）。
/// 戻り値は (returned_object, refcount) で leave 値列へ載せる。
pub(super) fn com_method_post_call(
    rt: &Arc<HookRuntime>,
    this: usize,
    instance: &crate::com::ComInstanceToken,
    method_index: u32,
    args: &[usize],
    ret: i32,
) -> (u64, u32) {
    match method_index {
        0 => {
            // QueryInterface: 成功時に返されたポインタを追跡対象に加え、
            // 既知インターフェイスなら Detour を設置する（アプリへ返す前）。
            if ret != 0 || args.len() < 2 {
                return (0, 0);
            }
            let Some(iid) = read_guid(args[0] as u64) else {
                return (0, 0);
            };
            let Some(out) = read_usize(args[1] as u64) else {
                return (0, 0);
            };
            if out == 0 {
                return (0, 0);
            }
            rt.with_com_tracker(|t| {
                retire_unloaded_com_address(t, this as u64);
                retire_unloaded_com_address(t, out as u64);
                if t.instance_matches(this as u64, instance) {
                    t.note_query_interface(this as u64, out as u64, iid, true);
                } else {
                    // A later discovery has replaced this address while the
                    // original call was in progress. Do not merge lifetimes.
                    t.note_discovered(out as u64, iid);
                }
            });
            if interface_by_iid(&iid).is_some() {
                // SAFETY: out は元の QI が返した有効なインターフェイス。
                // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
                let _ = unsafe { intercept_object(rt, out, iid) };
            }
            (out as u64, 0)
        }
        1 => {
            // AddRef: 戻り値が新しい参照カウント。
            let count = ret as u32;
            rt.with_com_tracker(|t| {
                if t.instance_matches(this as u64, instance) {
                    t.note_add_ref(this as u64, count);
                }
            });
            (0, count)
        }
        2 => {
            // Release: 戻り値が新しい参照カウント。0 なら寿命終了。
            let count = ret as u32;
            rt.with_com_tracker(|t| {
                if t.instance_matches(this as u64, instance) {
                    t.note_release(this as u64, count);
                }
            });
            (0, count)
        }
        _ => {
            // L14: WinRT のインターフェイス返却メソッド（ActivateInstance /
            // CreateUri / CreateWithRelativeUri / CombineUri）。成功時に
            // out 引数のインターフェイスを追跡対象に加え、既知なら Detour
            // を設置する（アプリへ返す前）。表に無いメソッドは (0, 0)。
            if ret != 0 {
                return (0, 0);
            }
            let Some((method_name, out_arg, iid)) = rt.with_com_tracker(|t| {
                if !t.instance_matches(this as u64, instance) {
                    return None;
                }
                t.lookup(this as u64).and_then(|o| {
                    interface_by_iid(&o.iid).and_then(|d| {
                        d.method(method_index).and_then(|m| {
                            winrt_method_return(d.name, method_index)
                                .map(|(out_arg, iid)| (m.name, out_arg, iid))
                        })
                    })
                })
            }) else {
                return (0, 0);
            };
            let Some(ptr) = args
                .get(out_arg)
                .and_then(|&a| read_usize(a as u64))
                .filter(|p| *p != 0)
            else {
                return (0, 0);
            };
            rt.with_com_tracker(|t| {
                retire_unloaded_com_address(t, ptr as u64);
                t.note_method_returned(ptr as u64, iid, this as u64, method_name);
            });
            if interface_by_iid(&iid).is_some() {
                // SAFETY: ptr は元のメソッドが返した有効なインターフェイス。
                // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
                let _ = unsafe { intercept_object(rt, ptr, iid) };
            }
            (ptr as u64, 0)
        }
    }
}

/// COM メソッドの Detour 本体。`this` から複製 vtable を引き、元の
/// メソッドを呼ぶ。追跡表に無いオブジェクト（前セッションで設置された
/// 複製 vtable を持つ等）は、元のメソッドを素通しで呼ぶ（記録しない）。
pub(super) fn com_method_dispatch(this: usize, method_index: u32, args: &[usize]) -> i32 {
    // 複製 vtable から元のメソッドを引く（ランタイムが無くても引ける。
    // セッション終了後にアプリが COM メソッドを呼んだ場合の素通し用）。
    let vtbl = match read_usize(this as u64) {
        Some(v) if v != 0 => v,
        _ => return COM_E_FAIL,
    };
    let original = match ComCloneRegistry::original(vtbl as u64, method_index) {
        Some(o) if o != 0 => o as usize,
        _ => return COM_E_FAIL,
    };
    com_method_dispatch_with(this, method_index, args, original, None, |original| {
        // SAFETY: the exclusive-object adapter supplies this exact ABI.
        unsafe { call_com_original(original, this, args) }
    })
}

/// Shared IUnknown adapters supply typed invokers and their installation's
/// owner. Old cached wrappers never attach themselves to a newer session.
pub(crate) fn com_method_dispatch_with(
    this: usize,
    method_index: u32,
    args: &[usize],
    original: usize,
    owner: Option<&std::sync::Weak<HookRuntime>>,
    invoke: impl FnOnce(usize) -> i32 + Copy,
) -> i32 {
    let mut le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(mut guard) = ReentrancyGuard::try_enter() else {
        le.restore_before_original();
        // SAFETY: original はこの引数個数の COM メソッド。
        return invoke(original);
    };
    let rt = match owner {
        Some(owner) => owner.upgrade(),
        None => crate::runtime::runtime_slot().for_detour(),
    };
    let Some(rt) = rt else {
        le.restore_before_original();
        // SAFETY: 同上。
        return invoke(original);
    };
    // COM methods are observable even when called through a runtime.
    let Some(flight) = crate::runtime::DetourFlight::begin(&rt) else {
        le.restore_before_original();
        // SAFETY: 同上。
        return invoke(original);
    };
    let _flight = flight;
    // 追跡対象の確認：このセッションで追跡していないオブジェクトは
    // 元のメソッドを素通しで呼ぶ（記録しない）。
    let (iid, interface_name, method_name, instance) = match rt.with_com_tracker(|t| {
        retire_unloaded_com_address(t, this as u64);
        let instance = t.instance_token(this as u64)?;
        t.lookup(this as u64).and_then(|o| {
            interface_by_iid(&o.iid).and_then(|d| {
                d.method(method_index)
                    .map(|m| (o.iid, d.name, m.name, instance))
            })
        })
    }) {
        Some(v) => v,
        None => {
            le.restore_before_original();
            // SAFETY: original はこの引数個数の COM メソッド。
            return invoke(original);
        }
    };
    let tid = crate::thread_id::current() as u64;
    rt.ensure_thread(tid);
    let call_id = rt.alloc_call_id();
    // enter: QI では target_iid に要求された IID を読む。
    let target_iid: Vec<u8> = if method_index == 0 && !args.is_empty() {
        read_guid(args[0] as u64)
            .map(|g| g.bytes.to_vec())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let method_display = format!("{interface_name}::{method_name}");
    let values = crate::com::com_method_enter_values(
        this as u64,
        &iid.bytes,
        method_index,
        &method_display,
        &crate::com::raw_arg_slots(args),
        &target_iid,
    );
    if let Ok(bytes) = crate::com::encode_com_enter(&values) {
        rt.record_com_enter(tid, call_id, &bytes);
    }
    drop(values);
    drop(target_iid);
    drop(method_display);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new(&rt, tid, call_id);
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: original はこの引数個数の COM メソッド。
    let (ret, (mut call_guard, rt, _flight, mut guard, instance)) =
        crate::seh::invoke(original, invoke, (call_guard, rt, _flight, guard, instance));
    let last_error = le.capture_after_original();
    call_guard.complete();
    if !crate::runtime::native_tls_available() {
        le.restore_for_return();
        return ret;
    }
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let (returned_object, refcount) =
        com_method_post_call(&rt, this, &instance, method_index, args, ret);
    let values =
        crate::com::com_method_leave_values_for(method_index, ret, returned_object, refcount);
    if let Ok(bytes) = crate::com::encode_com_leave(&values) {
        rt.record_com_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

macro_rules! com_method_detour {
    ($name:ident, $index:expr, 0) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void) -> i32 {
            com_method_dispatch(this as usize, $index, &[])
        }
    };
    ($name:ident, $index:expr, 1) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void, a0: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0])
        }
    };
    ($name:ident, $index:expr, 2) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void, a0: usize, a1: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1])
        }
    };
    ($name:ident, $index:expr, 3) => {
        unsafe extern "system-unwind" fn $name(
            this: *mut c_void,
            a0: usize,
            a1: usize,
            a2: usize,
        ) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1, a2])
        }
    };
    ($name:ident, $index:expr, 4) => {
        unsafe extern "system-unwind" fn $name(
            this: *mut c_void,
            a0: usize,
            a1: usize,
            a2: usize,
            a3: usize,
        ) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1, a2, a3])
        }
    };
}

// (vtable インデックス, arity) の組ごとの Detour。同じ組は全
// インターフェイスで共有する（Detour は `this` から追跡表を引くため）。
com_method_detour!(com_d_0_2, 0, 2);
com_method_detour!(com_d_1_0, 1, 0);
com_method_detour!(com_d_2_0, 2, 0);
com_method_detour!(com_d_3_4, 3, 4);
com_method_detour!(com_d_3_1, 3, 1);
com_method_detour!(com_d_3_2, 3, 2);
com_method_detour!(com_d_4_1, 4, 1);
com_method_detour!(com_d_4_0, 4, 0);
com_method_detour!(com_d_5_1, 5, 1);
com_method_detour!(com_d_5_2, 5, 2);
com_method_detour!(com_d_6_2, 6, 2);
com_method_detour!(com_d_6_1, 6, 1);
com_method_detour!(com_d_7_1, 7, 1);
com_method_detour!(com_d_7_2, 7, 2);
com_method_detour!(com_d_7_3, 7, 3);
com_method_detour!(com_d_8_2, 8, 2);
com_method_detour!(com_d_8_1, 8, 1);
com_method_detour!(com_d_9_1, 9, 1);
com_method_detour!(com_d_9_2, 9, 2);
com_method_detour!(com_d_10_2, 10, 2);
com_method_detour!(com_d_10_1, 10, 1);
com_method_detour!(com_d_11_1, 11, 1);
com_method_detour!(com_d_11_2, 11, 2);
com_method_detour!(com_d_12_1, 12, 1);
com_method_detour!(com_d_12_2, 12, 2);
com_method_detour!(com_d_13_1, 13, 1);
com_method_detour!(com_d_14_1, 14, 1);
com_method_detour!(com_d_15_1, 15, 1);
com_method_detour!(com_d_16_3, 16, 3);
com_method_detour!(com_d_16_1, 16, 1);
com_method_detour!(com_d_17_2, 17, 2);
com_method_detour!(com_d_17_1, 17, 1);
com_method_detour!(com_d_18_2, 18, 2);
com_method_detour!(com_d_18_1, 18, 1);
com_method_detour!(com_d_19_2, 19, 2);
com_method_detour!(com_d_19_1, 19, 1);
com_method_detour!(com_d_20_1, 20, 1);
com_method_detour!(com_d_21_2, 21, 2);
com_method_detour!(com_d_22_2, 22, 2);

pub(super) type ComDetourFn0 = unsafe extern "system-unwind" fn(*mut c_void) -> i32;
pub(super) type ComDetourFn1 = unsafe extern "system-unwind" fn(*mut c_void, usize) -> i32;
pub(super) type ComDetourFn2 = unsafe extern "system-unwind" fn(*mut c_void, usize, usize) -> i32;
pub(super) type ComDetourFn3 =
    unsafe extern "system-unwind" fn(*mut c_void, usize, usize, usize) -> i32;
pub(super) type ComDetourFn4 =
    unsafe extern "system-unwind" fn(*mut c_void, usize, usize, usize, usize) -> i32;

/// (vtable インデックス, arity) の組に対応する Detour を引く。
/// 既知インターフェイスの全メソッドに Detour があること。
pub(super) fn com_detour_for(index: u32, arity: usize) -> Option<usize> {
    Some(match (index, arity) {
        (0, 2) => com_d_0_2 as ComDetourFn2 as usize,
        (1, 0) => com_d_1_0 as ComDetourFn0 as usize,
        (2, 0) => com_d_2_0 as ComDetourFn0 as usize,
        (3, 4) => com_d_3_4 as ComDetourFn4 as usize,
        (3, 1) => com_d_3_1 as ComDetourFn1 as usize,
        (3, 2) => com_d_3_2 as ComDetourFn2 as usize,
        (4, 1) => com_d_4_1 as ComDetourFn1 as usize,
        (4, 0) => com_d_4_0 as ComDetourFn0 as usize,
        (5, 1) => com_d_5_1 as ComDetourFn1 as usize,
        (5, 2) => com_d_5_2 as ComDetourFn2 as usize,
        (6, 2) => com_d_6_2 as ComDetourFn2 as usize,
        (6, 1) => com_d_6_1 as ComDetourFn1 as usize,
        (7, 1) => com_d_7_1 as ComDetourFn1 as usize,
        (7, 2) => com_d_7_2 as ComDetourFn2 as usize,
        (7, 3) => com_d_7_3 as ComDetourFn3 as usize,
        (8, 2) => com_d_8_2 as ComDetourFn2 as usize,
        (8, 1) => com_d_8_1 as ComDetourFn1 as usize,
        (9, 1) => com_d_9_1 as ComDetourFn1 as usize,
        (9, 2) => com_d_9_2 as ComDetourFn2 as usize,
        (10, 2) => com_d_10_2 as ComDetourFn2 as usize,
        (10, 1) => com_d_10_1 as ComDetourFn1 as usize,
        (11, 1) => com_d_11_1 as ComDetourFn1 as usize,
        (11, 2) => com_d_11_2 as ComDetourFn2 as usize,
        (12, 1) => com_d_12_1 as ComDetourFn1 as usize,
        (12, 2) => com_d_12_2 as ComDetourFn2 as usize,
        (13, 1) => com_d_13_1 as ComDetourFn1 as usize,
        (14, 1) => com_d_14_1 as ComDetourFn1 as usize,
        (15, 1) => com_d_15_1 as ComDetourFn1 as usize,
        (16, 3) => com_d_16_3 as ComDetourFn3 as usize,
        (16, 1) => com_d_16_1 as ComDetourFn1 as usize,
        (17, 2) => com_d_17_2 as ComDetourFn2 as usize,
        (17, 1) => com_d_17_1 as ComDetourFn1 as usize,
        (18, 2) => com_d_18_2 as ComDetourFn2 as usize,
        (18, 1) => com_d_18_1 as ComDetourFn1 as usize,
        (19, 2) => com_d_19_2 as ComDetourFn2 as usize,
        (19, 1) => com_d_19_1 as ComDetourFn1 as usize,
        (20, 1) => com_d_20_1 as ComDetourFn1 as usize,
        (21, 2) => com_d_21_2 as ComDetourFn2 as usize,
        (22, 2) => com_d_22_2 as ComDetourFn2 as usize,
        _ => return None,
    })
}
