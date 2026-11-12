//! OS-thread exit notification. Windows Rust TLS destructors deliberately
//! skip fiber threads, so use a native TLS callback there. Deleting a fiber
//! must neither close the capture slot nor consume the eventual thread exit.
use std::sync::{Arc, OnceLock};
pub type ThreadExitHandler = Arc<dyn Fn(u64) + Send + Sync>;
static HANDLER: OnceLock<ThreadExitHandler> = OnceLock::new();

fn notify_exit(thread_id: u64) {
    if let Some(handler) = HANDLER.get() {
        handler(thread_id);
    }
}

#[cfg(windows)]
thread_local! {
    // No destructor: the callback runs exactly on DLL_THREAD_DETACH, including
    // when the first registration was performed inside a subsequently deleted fiber.
    static THREAD_NODE: std::cell::Cell<*mut ExitNode> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

#[cfg(windows)]
struct ExitNode {
    thread_id: u64,
    next: *mut ExitNode,
}
#[cfg(windows)]
static PENDING: std::sync::atomic::AtomicPtr<ExitNode> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Run exit handlers outside the native TLS callback. That callback holds the
/// loader lock, so it must not allocate, free, or acquire runtime locks.
/// Call from the recording management path or explicit shutdown.
pub fn drain_pending_exits() {
    #[cfg(windows)]
    {
        use std::sync::atomic::Ordering;
        let mut node = PENDING.swap(std::ptr::null_mut(), Ordering::Acquire);
        while !node.is_null() {
            // The atomic swap grants sole ownership of this detached list.
            let owned = unsafe { Box::from_raw(node) };
            node = owned.next;
            notify_exit(owned.thread_id);
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn thread_callback(
    _: *mut std::ffi::c_void,
    reason: u32,
    _: *mut std::ffi::c_void,
) {
    const DLL_THREAD_DETACH: u32 = 3;
    if reason == DLL_THREAD_DETACH {
        if !crate::runtime::native_tls_available() {
            return;
        }
        crate::runtime::ReentrancyGuard::mark_thread_exiting();
        let _ = THREAD_NODE.try_with(|slot| {
            let node = slot.replace(std::ptr::null_mut());
            if node.is_null() {
                return;
            }
            use std::sync::atomic::Ordering;
            let mut head = PENDING.load(Ordering::Relaxed);
            loop {
                // This node was allocated when arming, and is exclusively ours
                // until the successful release CAS publishes it to a consumer.
                unsafe {
                    (*node).next = head;
                }
                match PENDING.compare_exchange_weak(
                    head,
                    node,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => head = current,
                }
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
        crate::runtime::ReentrancyGuard::mark_thread_exiting();
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
    let _ = THREAD_NODE.try_with(|slot| {
        if slot.get().is_null() {
            slot.set(Box::into_raw(Box::new(ExitNode {
                thread_id,
                next: std::ptr::null_mut(),
            })));
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
