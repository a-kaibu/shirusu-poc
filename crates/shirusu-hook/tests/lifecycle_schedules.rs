//! Deterministic schedules of real registry operations, not timing-based sleeps.
use shirusu_hook::capture::{OverlappedDirection, OverlappedRegistry, PendingOverlapped};
use std::sync::{Arc, Barrier};
fn op(id: u64) -> PendingOverlapped {
    PendingOverlapped {
        api_id: 2,
        call_id: id,
        handle: 1,
        buffer: 2,
        requested_len: 4,
        direction: OverlappedDirection::Read,
        bytes_addr: 0,
    }
}
#[test]
fn completion_before_submitter_returns_and_address_reuse() {
    let registry = Arc::new(OverlappedRegistry::new());
    let gate = Arc::new(Barrier::new(2));
    // This registration must precede exposing the operation to the OS.
    registry.register(100, op(1));
    let r = registry.clone();
    let g = gate.clone();
    let completion = std::thread::spawn(move || {
        assert_eq!(r.take(100).unwrap().call_id, 1);
        r.register(100, op(2)); // completion consumer immediately reuses OVERLAPPED
        g.wait();
    });
    gate.wait();
    registry.cancel(100, 1); // old submitter now returns: cannot erase operation 2
    assert_eq!(registry.take(100).unwrap().call_id, 2);
    completion.join().unwrap();
}
#[test]
fn pending_completion_and_synchronous_cancel_schedules() {
    for completion_first in [false, true] {
        let r = OverlappedRegistry::new();
        r.register(100, op(1));
        if completion_first {
            assert!(r.take(100).is_some());
        }
        r.cancel(100, 1);
        assert!(r.is_empty());
        assert!(r.take(100).is_none());
    }
}
#[cfg(windows)]
#[test]
fn deleting_fiber_does_not_end_thread_capture() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Threading::{
        ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
    };
    let exits = Arc::new(AtomicUsize::new(0));
    let seen = exits.clone();
    shirusu_hook::fls::install_thread_exit_handler(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    }));
    let observed = exits.clone();
    std::thread::spawn(move || unsafe {
        unsafe extern "system" fn fiber(parent: *mut std::ffi::c_void) {
            shirusu_hook::fls::arm_current_thread(77);
            unsafe {
                SwitchToFiber(parent);
            }
        }
        let parent = ConvertThreadToFiber(std::ptr::null());
        assert!(!parent.is_null());
        let child = CreateFiber(0, Some(fiber), parent);
        assert!(!child.is_null());
        SwitchToFiber(child);
        DeleteFiber(child);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        assert!(shirusu_hook::runtime::ReentrancyGuard::try_enter().is_some());
    })
    .join()
    .unwrap();
    assert_eq!(exits.load(Ordering::SeqCst), 1);
}

#[test]
fn submission_unwind_cancels_only_its_own_generation() {
    let registry = OverlappedRegistry::new();
    let result = std::panic::catch_unwind(|| {
        let _submission = registry.submit(100, op(1));
        panic!("original API unwinds");
    });
    assert!(result.is_err());
    assert!(registry.is_empty());
    let result = std::panic::catch_unwind(|| {
        let _submission = registry.submit(100, op(2));
        assert!(registry.take(100).is_some());
        registry.register(100, op(3));
        panic!("older submitter unwinds after address reuse");
    });
    assert!(result.is_err());
    assert_eq!(registry.take(100).unwrap().call_id, 3);
}
