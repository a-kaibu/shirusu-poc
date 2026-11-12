//! Thread exit notification. Rust TLS destructors follow OS-thread lifetime,
//! unlike FLS callbacks, which also execute when an individual fiber is deleted.
use std::sync::{Arc, OnceLock};
pub type ThreadExitHandler = Arc<dyn Fn(u64) + Send + Sync>;
static HANDLER: OnceLock<ThreadExitHandler> = OnceLock::new();
struct ThreadExit(u64);
impl Drop for ThreadExit {
    fn drop(&mut self) {
        crate::runtime::ReentrancyGuard::mark_thread_exiting();
        if let Some(handler) = HANDLER.get() {
            handler(self.0);
        }
    }
}
thread_local! {
    static EXIT: std::cell::RefCell<Option<ThreadExit>> = const { std::cell::RefCell::new(None) };
}
pub fn install_thread_exit_handler(handler: ThreadExitHandler) -> bool {
    let _ = HANDLER.set(handler);
    true
}
pub fn arm_current_thread(thread_id: u64) {
    if thread_id != 0 {
        let _ = EXIT.try_with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(ThreadExit(thread_id));
            }
        });
    }
}
