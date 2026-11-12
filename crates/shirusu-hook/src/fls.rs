//! OS-thread exit notification. Windows Rust TLS destructors deliberately
//! skip fiber threads, so use a native TLS callback there. Deleting a fiber
//! must neither close the capture slot nor consume the eventual thread exit.
use std::sync::{Arc, OnceLock};
pub type ThreadExitHandler = Arc<dyn Fn(u64) + Send + Sync>;
static HANDLER: OnceLock<ThreadExitHandler> = OnceLock::new();

fn notify_exit(thread_id: u64) {
    crate::runtime::ReentrancyGuard::mark_thread_exiting();
    if let Some(handler) = HANDLER.get() {
        handler(thread_id);
    }
}

#[cfg(windows)]
thread_local! {
    // No destructor: the callback runs exactly on DLL_THREAD_DETACH, including
    // when the first registration was performed inside a subsequently deleted fiber.
    static THREAD_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(windows)]
unsafe extern "system" fn thread_callback(
    _: *mut std::ffi::c_void,
    reason: u32,
    _: *mut std::ffi::c_void,
) {
    const DLL_THREAD_DETACH: u32 = 3;
    if reason == DLL_THREAD_DETACH {
        let _ = THREAD_ID.try_with(|slot| {
            let id = slot.replace(0);
            if id != 0 {
                notify_exit(id);
            }
        });
    }
}

// The PE TLS directory contains the .CRT$XL* callback array. Unlike FLS,
// this callback is tied to OS-thread detach and never to DeleteFiber.
#[cfg(windows)]
#[used]
#[link_section = ".CRT$XLB"]
static THREAD_CALLBACK: unsafe extern "system" fn(
    *mut std::ffi::c_void,
    u32,
    *mut std::ffi::c_void,
) = thread_callback;

#[cfg(not(windows))]
struct ThreadExit(u64);
#[cfg(not(windows))]
impl Drop for ThreadExit {
    fn drop(&mut self) {
        notify_exit(self.0);
    }
}
#[cfg(not(windows))]
thread_local! {
    static EXIT: std::cell::RefCell<Option<ThreadExit>> = const { std::cell::RefCell::new(None) };
}
pub fn install_thread_exit_handler(handler: ThreadExitHandler) -> bool {
    let _ = HANDLER.set(handler);
    true
}
pub fn arm_current_thread(thread_id: u64) {
    if thread_id == 0 {
        return;
    }
    #[cfg(windows)]
    let _ = THREAD_ID.try_with(|slot| {
        if slot.get() == 0 {
            slot.set(thread_id);
        }
    });
    #[cfg(not(windows))]
    let _ = EXIT.try_with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(ThreadExit(thread_id));
        }
    });
}
