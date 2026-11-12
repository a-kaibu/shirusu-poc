//! Execute generated wrappers against typed originals on every CI architecture.
#![allow(dead_code)]
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
static SLEPT: AtomicU32 = AtomicU32::new(0);
unsafe extern "system-unwind" fn sleep(milliseconds: u32) {
    if milliseconds == u32::MAX {
        panic!("original function unwind probe");
    }
    SLEPT.store(milliseconds, Ordering::Relaxed);
}
unsafe extern "system-unwind" fn pid() -> u32 {
    0xFEED_BEEF
}
unsafe extern "system-unwind" fn std_handle() -> *mut c_void {
    usize::MAX as *mut c_void
}
unsafe extern "system-unwind" fn set_event(handle: *mut c_void) -> i32 {
    assert_eq!(handle as usize, usize::MAX);
    -123
}
fn generic_detour_with<const N: usize>(
    api_id: u32,
    _: &[usize; N],
    invoke: impl FnOnce(usize) -> usize,
) -> usize {
    let api = shirusu_hook::api::api_by_id(api_id).unwrap();
    let original = match api.function {
        "Sleep" => sleep as *const () as usize,
        "GetCurrentProcessId" => pid as *const () as usize,
        "GetCurrentProcess" => std_handle as *const () as usize,
        "SetEvent" => set_event as *const () as usize,
        other => panic!("unexpected original: {other}"),
    };
    invoke(original)
}
include!("../src/engine_generated.inc");
#[test]
fn void_integer_and_pointer_returns_preserve_abi() {
    let sleep: unsafe extern "system-unwind" fn(u32) = detour_generated_kernel32_sleep;
    let pid: unsafe extern "system-unwind" fn() -> u32 =
        detour_generated_kernel32_get_current_process_id;
    let handle: unsafe extern "system-unwind" fn() -> *mut c_void =
        detour_generated_kernel32_get_current_process;
    let event: unsafe extern "system-unwind" fn(*mut c_void) -> i32 =
        detour_generated_kernel32_set_event;
    unsafe {
        assert_eq!(event(usize::MAX as *mut c_void), -123);
        sleep(0xABCD_1234);
        assert_eq!(pid(), 0xFEED_BEEF);
        assert_eq!(handle() as usize, usize::MAX);
    }
    assert_eq!(SLEPT.load(Ordering::Relaxed), 0xABCD_1234);
}

#[test]
fn generated_wrapper_allows_unwinding_to_original_caller() {
    let result = std::panic::catch_unwind(|| unsafe { detour_generated_kernel32_sleep(u32::MAX) });
    assert!(result.is_err());
}
