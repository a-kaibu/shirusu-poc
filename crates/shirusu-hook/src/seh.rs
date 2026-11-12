//! Native SEH cleanup for owned recording state. Rust's unwind ABI alone does
//! not guarantee Drop for Windows structured exceptions.
use std::ffi::c_void;

extern "C-unwind" {
    fn shirusu_invoke_with_finally(
        invoke: unsafe extern "C-unwind" fn(*mut c_void) -> u64,
        context: *mut c_void,
        cleanup: unsafe extern "C" fn(*mut c_void),
    ) -> u64;
}

struct Invocation<F, S> {
    invoke: F,
    original: usize,
    state: Option<S>,
}

/// `invoke` must contain only Copy arguments: a foreign SEH unwind may skip
/// the Rust callback's destructors. Owned state stays in the outer context,
/// where the native finally block takes it exactly once before unwinding out.
pub(crate) fn invoke<F: FnOnce(usize) -> u64 + Copy, S>(
    original: usize,
    invoke: F,
    state: S,
) -> (u64, S) {
    unsafe extern "C-unwind" fn call<F: FnOnce(usize) -> u64 + Copy, S>(
        context: *mut c_void,
    ) -> u64 {
        let context = unsafe { &*context.cast::<Invocation<F, S>>() };
        (context.invoke)(context.original)
    }
    unsafe extern "C" fn cleanup<F, S>(context: *mut c_void) {
        let context = unsafe { &mut *context.cast::<Invocation<F, S>>() };
        let last_error = crate::last_error::get();
        drop(context.state.take());
        crate::last_error::set(last_error);
    }
    let mut context = Invocation {
        invoke,
        original,
        state: Some(state),
    };
    let result = unsafe {
        shirusu_invoke_with_finally(
            call::<F, S>,
            (&mut context as *mut Invocation<F, S>).cast(),
            cleanup::<F, S>,
        )
    };
    (
        result,
        context
            .state
            .take()
            .expect("normal return retains recording state"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountDrop<'a>(&'a AtomicUsize);
    impl Drop for CountDrop<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    extern "C-unwind" {
        fn shirusu_test_raise_seh() -> u64;
        fn shirusu_test_catch_seh(
            invoke: unsafe extern "C-unwind" fn(*mut c_void) -> u64,
            context: *mut c_void,
        ) -> u32;
    }
    #[test]
    fn normal_return_retains_state_until_caller_drops_it() {
        let drops = AtomicUsize::new(0);
        let (result, state) = invoke(41, |value| value as u64 + 1, CountDrop(&drops));
        assert_eq!(result, 42);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(state);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn rust_panic_cleans_state_exactly_once_and_keeps_payload() {
        let drops = AtomicUsize::new(0);
        let result = std::panic::catch_unwind(|| {
            invoke(0, |_| panic!("native-finally-payload"), CountDrop(&drops));
        });
        assert_eq!(
            result.unwrap_err().downcast_ref::<&str>(),
            Some(&"native-finally-payload")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn structured_exception_cleans_state_once_and_reaches_native_caller() {
        unsafe extern "C-unwind" fn run(context: *mut c_void) -> u64 {
            let drops = unsafe { &*context.cast::<AtomicUsize>() };
            invoke(0, |_| unsafe { shirusu_test_raise_seh() }, CountDrop(drops)).0
        }
        let mut drops = AtomicUsize::new(0);
        let code = unsafe { shirusu_test_catch_seh(run, (&mut drops as *mut AtomicUsize).cast()) };
        assert_eq!(code, 0xe0424242);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
