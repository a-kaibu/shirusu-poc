//! Direct access to the current Windows thread's TEB LastErrorValue.
//! Recording must not call the API that it may itself intercept.

#[inline(always)]
pub fn get() -> u32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u32;
        core::arch::asm!("mov {value:e}, gs:[0x68]", value = out(reg) value, options(nostack, preserves_flags, readonly));
        value
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        let value: u32;
        core::arch::asm!("mov {value:e}, fs:[0x34]", value = out(reg) value, options(nostack, preserves_flags, readonly));
        value
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    unsafe {
        windows_sys::Win32::Foundation::GetLastError()
    }
}

#[inline(always)]
pub fn set(value: u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov gs:[0x68], {value:e}", value = in(reg) value, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!("mov fs:[0x34], {value:e}", value = in(reg) value, options(nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    unsafe {
        windows_sys::Win32::Foundation::SetLastError(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};

    #[test]
    fn direct_cell_matches_windows_and_is_thread_local() {
        let saved = get();
        for value in [0, 5, 0x8000_0001, u32::MAX] {
            unsafe {
                SetLastError(value);
            }
            assert_eq!(get(), value);
            set(!value);
            assert_eq!(unsafe { GetLastError() }, !value);
        }
        use std::sync::atomic::{AtomicBool, Ordering};
        let flags = std::sync::Arc::new((AtomicBool::new(false), AtomicBool::new(false)));
        let gate = flags.clone();
        let child = std::thread::spawn(move || {
            set(123);
            gate.0.store(true, Ordering::Release);
            while !gate.1.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            assert_eq!(get(), 123);
        });
        while !flags.0.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        set(456);
        flags.1.store(true, Ordering::Release);
        assert_eq!(get(), 456);
        child.join().unwrap();
        set(saved);
    }
}
