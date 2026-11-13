//! Direct-callsite state for native entry wrappers. A native stack frame owns
//! each entry; __finally restores the previous pointer even on Windows SEH.
//! This foundation is not yet used to suppress standard capture events.
use std::cell::Cell;

#[repr(C)]
pub(crate) struct NativeCallsite {
    pub address: usize,
    pub api_id: u32,
}

thread_local! {
    // No allocation, destructor registration, or lock in the native entry path.
    static CURRENT: Cell<*const NativeCallsite> = const { Cell::new(std::ptr::null()) };
}

/// Swap the native entry context, retaining the preceding context for nesting.
///
/// # Safety
/// A non-null pointer must refer to an initialized immutable NativeCallsite on
/// this thread. It must remain alive until the previous pointer is restored,
/// including exception paths. Native wrappers must restore it in __finally.
#[no_mangle]
pub(crate) unsafe extern "C" fn shirusu_swap_callsite(
    frame: *const NativeCallsite,
) -> *const NativeCallsite {
    if !crate::runtime::native_tls_available() {
        return std::ptr::null();
    }
    CURRENT
        .try_with(|current| current.replace(frame))
        .unwrap_or(std::ptr::null())
}

// Used by native boundary tests until typed wrappers are connected. Never
// inherit an outer API's caller for an unwrapped/different API.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn direct_caller(api_id: u32) -> Option<usize> {
    if !crate::runtime::native_tls_available() {
        return None;
    }
    CURRENT
        .try_with(|current| {
            let pointer = current.get();
            // SAFETY: shirusu_swap_callsite's native-frame lifetime contract.
            let frame = unsafe { pointer.as_ref() }?;
            (frame.api_id == api_id && frame.address != 0).then_some(frame.address)
        })
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_callers_are_api_specific_and_thread_local() {
        let outer = NativeCallsite {
            address: 0x1234,
            api_id: 1,
        };
        let inner = NativeCallsite {
            address: 0x5678,
            api_id: 2,
        };
        let previous = unsafe { shirusu_swap_callsite(&outer) };
        let first = (direct_caller(1), direct_caller(2));
        let child = std::thread::spawn(|| direct_caller(1)).join();
        let saved = unsafe { shirusu_swap_callsite(&inner) };
        let second = (direct_caller(1), direct_caller(2));
        unsafe { shirusu_swap_callsite(saved) };
        let restored = direct_caller(1);
        unsafe { shirusu_swap_callsite(previous) };
        assert_eq!(first, (Some(0x1234), None));
        assert_eq!(child.unwrap(), None);
        assert_eq!(second, (None, Some(0x5678)));
        assert_eq!(restored, Some(0x1234));
        assert_eq!(direct_caller(1), None);
    }

    #[cfg(windows)]
    mod native {
        use super::*;
        use std::ffi::c_void;
        type Invoke = unsafe extern "C-unwind" fn(*mut c_void) -> u64;
        extern "C-unwind" {
            fn shirusu_test_with_callsite(api_id: u32, invoke: Invoke, context: *mut c_void)
                -> u64;
            fn shirusu_test_raise_seh() -> u64;
            fn shirusu_test_catch_seh(invoke: Invoke, context: *mut c_void) -> u32;
        }

        unsafe extern "C-unwind" fn observe(_: *mut c_void) -> u64 {
            use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
            let input_preserved = unsafe { GetLastError() } == 0x1234;
            let address = direct_caller(72).unwrap_or(0);
            unsafe { SetLastError(0x5678) };
            if input_preserved {
                address as u64
            } else {
                0
            }
        }
        #[inline(never)]
        fn native_caller() -> usize {
            let address = unsafe { shirusu_test_with_callsite(72, observe, std::ptr::null_mut()) };
            // Prevent a tail call: this function must own the return address.
            std::hint::black_box(address as usize)
        }
        #[test]
        fn native_entry_observes_its_direct_return_address() {
            use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
            unsafe { SetLastError(0x1234) };
            crate::heap_watch::begin();
            let address = native_caller();
            let error = unsafe { GetLastError() };
            crate::heap_watch::end();
            let start = native_caller as *const () as usize;
            assert!(
                address >= start && address - start < 1024,
                "{address:x} outside caller {start:x}"
            );
            assert_eq!(direct_caller(72), None);
            assert_eq!(error, 0x5678);
        }

        unsafe extern "C-unwind" fn raise(_: *mut c_void) -> u64 {
            unsafe { shirusu_test_raise_seh() }
        }
        unsafe extern "C-unwind" fn scoped_raise(context: *mut c_void) -> u64 {
            unsafe { shirusu_test_with_callsite(73, raise, context) }
        }
        unsafe extern "C-unwind" fn outer(_: *mut c_void) -> u64 {
            let before = direct_caller(72);
            let code = unsafe { shirusu_test_catch_seh(scoped_raise, std::ptr::null_mut()) };
            u64::from(
                code == 0xe0424242
                    && before.is_some()
                    && direct_caller(72) == before
                    && direct_caller(73).is_none(),
            )
        }
        #[test]
        fn native_exception_restores_outer_callsite() {
            let restored = unsafe { shirusu_test_with_callsite(72, outer, std::ptr::null_mut()) };
            assert_eq!(restored, 1);
            assert_eq!(direct_caller(72), None);
            assert_eq!(direct_caller(73), None);
        }
    }
}
