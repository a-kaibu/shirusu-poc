//! Read the current thread's TEB ClientId.UniqueThread without entering an API
//! that the recorder may itself intercept. The TEB belongs to the executing
//! Windows thread throughout this read, including Rust TLS teardown.

#[inline(always)]
pub fn current() -> u32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u32;
        // NT_TIB (0x38), EnvironmentPointer (0x08), then CLIENT_ID:
        // UniqueProcess at 0x40 and UniqueThread at 0x48. Win32 TIDs are DWORDs.
        core::arch::asm!("mov {value:e}, gs:[0x48]", value = out(reg) value,
            options(nostack, preserves_flags, readonly));
        value
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        let value: u32;
        // 32-bit TEB, including WoW64: ClientId.UniqueThread is at 0x24.
        core::arch::asm!("mov {value:e}, fs:[0x24]", value = out(reg) value,
            options(nostack, preserves_flags, readonly));
        value
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    unsafe {
        windows_sys::Win32::System::Threading::GetCurrentThreadId()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    #[test]
    fn direct_id_matches_windows_across_live_threads_and_preserves_last_error() {
        let parent = unsafe { GetCurrentThreadId() };
        assert_eq!(current(), parent);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let expected = unsafe { GetCurrentThreadId() };
                    barrier.wait();
                    let saved = crate::last_error::get();
                    let values = [0, 5, u32::MAX];
                    let observed = values.map(|value| {
                        crate::last_error::set(value);
                        (current(), crate::last_error::get())
                    });
                    crate::last_error::set(saved);
                    // Release every participant before assertions, so a mismatch
                    // reports a failure instead of stranding peers at the barrier.
                    barrier.wait();
                    for ((actual, error), value) in observed.into_iter().zip(values) {
                        assert_eq!(actual, expected);
                        assert_eq!(error, value);
                    }
                    assert_ne!(expected, parent);
                    expected
                })
            })
            .collect();
        barrier.wait();
        let observed_parent = current();
        barrier.wait();
        assert_eq!(observed_parent, parent);
        let ids: std::collections::BTreeSet<_> =
            workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(ids.len(), 8);
    }
}
