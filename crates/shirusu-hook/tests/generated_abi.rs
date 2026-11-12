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
    raw: &[u64; N],
    invoke: impl FnOnce(usize) -> u64,
) -> u64 {
    let api = shirusu_hook::api::api_by_id(api_id).unwrap();
    let original = match api.function {
        "Sleep" => sleep as *const () as usize,
        "GetCurrentProcessId" => pid as *const () as usize,
        "GetCurrentProcess" => std_handle as *const () as usize,
        "SetEvent" => set_event as *const () as usize,
        "ldap_initW" | "ldap_openW" => ldap_init as *const () as usize,
        "ldap_unbind" => ldap_unbind as *const () as usize,
        "GetLastError" => get_error as *const () as usize,
        "SetLastError" => set_error as *const () as usize,
        "GetTickCount64" => tick64 as *const () as usize,
        "SetFilePointerEx" => {
            assert_eq!(raw[1], i64::MIN as u64);
            file_pointer as *const () as usize
        }
        "GetKeyState" => key_state as *const () as usize,
        "AngleArc" => {
            assert_eq!(raw[4], 0x8000_0000);
            assert_eq!(raw[5], 0x7fc0_1234);
            angle_arc as *const () as usize
        }
        "D2D1ComputeMaximumScaleFactor" => float_return as *const () as usize,
        "glDepthRange" => {
            assert_eq!(
                raw.as_slice(),
                &[0x8000_0000_0000_0000, 0x7ff8_0000_0000_1234]
            );
            depth_range as *const () as usize
        }
        other => panic!("unexpected original: {other}"),
    };
    invoke(original)
}
include!("../src/engine_generated.inc");

thread_local! {
    static ERROR_CELL: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
unsafe extern "system-unwind" fn get_error() -> u32 {
    ERROR_CELL.with(std::cell::Cell::get)
}
unsafe extern "system-unwind" fn set_error(value: u32) {
    ERROR_CELL.with(|cell| cell.set(value));
}
#[test]
fn last_error_apis_are_generated_with_void_and_dword_signatures() {
    for code in [0, 5, 0x8000_0001, u32::MAX] {
        unsafe {
            detour_generated_kernel32_set_last_error(code);
            assert_eq!(detour_generated_kernel32_get_last_error(), code);
        }
    }
}

unsafe extern "C-unwind" fn ldap_init(host: *mut c_void, port: u32) -> *mut c_void {
    assert_eq!(host as usize, 0x1234);
    assert_eq!(port, u32::MAX);
    0x5678usize as *mut c_void
}
unsafe extern "C-unwind" fn ldap_unbind(handle: *mut c_void) -> u32 {
    assert_eq!(handle as usize, 0x5678);
    0x8123_4567
}

#[test]
fn cdecl_wrappers_keep_caller_stack_cleanup_and_return_width() {
    let init: unsafe extern "C-unwind" fn(*mut c_void, u32) -> *mut c_void =
        detour_generated_wldap32_ldap_init_w;
    let open: unsafe extern "C-unwind" fn(*mut c_void, u32) -> *mut c_void =
        detour_generated_wldap32_ldap_open_w;
    let close: unsafe extern "C-unwind" fn(*mut c_void) -> u32 =
        detour_generated_wldap32_ldap_unbind;
    for _ in 0..1024 {
        unsafe {
            let handle = init(0x1234usize as *mut c_void, u32::MAX);
            assert_eq!(open(0x1234usize as *mut c_void, u32::MAX), handle);
            assert_eq!(close(handle), 0x8123_4567);
        }
    }
}
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

unsafe extern "system-unwind" fn tick64() -> u64 {
    0xfedc_ba98_7654_3210
}
unsafe extern "system-unwind" fn file_pointer(
    h: *mut c_void,
    offset: i64,
    out: *mut c_void,
    mode: u32,
) -> i32 {
    assert_eq!(h as usize, 123);
    assert_eq!(offset, i64::MIN);
    assert_eq!(out as usize, 456);
    assert_eq!(mode, 2);
    -123
}
unsafe extern "system-unwind" fn key_state(key: i32) -> i16 {
    assert_eq!(key, -17);
    -32767
}
unsafe extern "system-unwind" fn angle_arc(
    h: *mut c_void,
    x: i32,
    y: i32,
    radius: u32,
    start: f32,
    sweep: f32,
) -> i32 {
    assert_eq!((h as usize, x, y, radius), (123, -3, 4, u32::MAX));
    assert_eq!(start.to_bits(), 0x8000_0000);
    assert_eq!(sweep.to_bits(), 0x7fc0_1234);
    1
}
unsafe extern "system-unwind" fn float_return(p: *mut c_void) -> f32 {
    assert_eq!(p as usize, 456);
    f32::from_bits(0x7fc0_5678)
}
unsafe extern "system-unwind" fn depth_range(near: f64, far: f64) {
    assert_eq!(near.to_bits(), 0x8000_0000_0000_0000);
    assert_eq!(far.to_bits(), 0x7ff8_0000_0000_1234);
}
#[test]
fn generated_abi_preserves_wide_narrow_and_floating_values() {
    unsafe {
        assert_eq!(
            detour_generated_kernel32_get_tick_count64(),
            0xfedc_ba98_7654_3210
        );
        assert_eq!(
            detour_generated_kernel32_set_file_pointer_ex(
                123usize as *mut c_void,
                i64::MIN,
                456usize as *mut c_void,
                2
            ),
            -123
        );
        assert_eq!(detour_generated_user32_get_key_state(-17), -32767);
        assert_eq!(
            detour_generated_gdi32_angle_arc(
                123usize as *mut c_void,
                -3,
                4,
                u32::MAX,
                f32::from_bits(0x8000_0000),
                f32::from_bits(0x7fc0_1234)
            ),
            1
        );
        assert_eq!(
            detour_generated_d2d1_d2_d1_compute_maximum_scale_factor(456usize as *mut c_void)
                .to_bits(),
            0x7fc0_5678
        );
        detour_generated_opengl32_gl_depth_range(
            f64::from_bits(0x8000_0000_0000_0000),
            f64::from_bits(0x7ff8_0000_0000_1234),
        );
    }
}

#[test]
fn captured_floating_values_roundtrip_without_nan_canonicalization() {
    use shirusu_hook::{api::api_by_import, capture};
    use shirusu_trace::{
        compact::decode_values,
        schema::{schema_types, TypedValue},
    };
    let api = api_by_import("opengl32", "glDepthRange").unwrap();
    for bits in [
        0,
        1,
        0x8000_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff8_0000_0000_1234,
        0x7ff0_0000_0000_0001,
    ] {
        let values = capture::generic_enter(api, &[bits, bits]);
        let bytes = capture::encode_enter(api, &values).unwrap();
        let decoded = decode_values(&schema_types(&api.enter_schema()).unwrap(), &bytes).unwrap();
        assert_eq!(decoded[0].value, TypedValue::F64Bits(bits));
        assert_eq!(decoded[1].value, TypedValue::F64Bits(bits));
    }
}
