//! Recheck the live thread set without allocating while other threads are frozen.
//! Toolhelp can allocate internally, so reserve a native query buffer beforehand.

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::System::WindowsProgramming::{
    SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION,
};

pub(crate) struct ThreadSnapshot {
    // Native output requires aligned storage. u64 has no invalid bit patterns.
    words: Vec<u64>,
}

impl ThreadSnapshot {
    pub(crate) fn new() -> Result<Self, ()> {
        const LIMIT: usize = 16 * 1024 * 1024;
        let mut required = 0u32;
        unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                std::ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required == 0 || required as usize > LIMIT {
            return Err(());
        }
        // Growth during collection is allowed; exhausting this bound refuses
        // the patch rather than reallocating under suspension.
        let size = (required as usize)
            .saturating_mul(2)
            .clamp(1024 * 1024, LIMIT);
        Ok(Self {
            words: vec![0; size.div_ceil(8)],
        })
    }

    pub(crate) fn only_known_threads(
        &mut self,
        pid: u32,
        current: u32,
        stopped: &[u32],
    ) -> Result<bool, ()> {
        let capacity = self.words.len() * 8;
        let mut written = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                self.words.as_mut_ptr().cast(),
                capacity as u32,
                &mut written,
            )
        };
        if status < 0 || written == 0 || written as usize > capacity {
            return Err(());
        }
        // SAFETY: the native call succeeded within the initialized allocation.
        let bytes =
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), written as usize) };
        only_known_threads(bytes, pid, current, stopped)
    }
}

fn only_known_threads(bytes: &[u8], pid: u32, current: u32, stopped: &[u32]) -> Result<bool, ()> {
    let header_size = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
    let thread_size = std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();
    let mut offset = 0usize;
    loop {
        let remaining = bytes.get(offset..).ok_or(())?;
        if remaining.len() < header_size {
            return Err(());
        }
        // This copies plain integer/pointer fields; pointers in native records
        // (including ImageName) are never dereferenced.
        let process = unsafe {
            remaining
                .as_ptr()
                .cast::<SYSTEM_PROCESS_INFORMATION>()
                .read_unaligned()
        };
        let length = if process.NextEntryOffset == 0 {
            remaining.len()
        } else {
            process.NextEntryOffset as usize
        };
        if length < header_size || length > remaining.len() {
            return Err(());
        }
        if process.UniqueProcessId as usize == pid as usize {
            let threads_len = (process.NumberOfThreads as usize)
                .checked_mul(thread_size)
                .ok_or(())?;
            let end = header_size.checked_add(threads_len).ok_or(())?;
            if end > length {
                return Err(());
            }
            let mut saw_current = false;
            for chunk in remaining[header_size..end].chunks_exact(thread_size) {
                let thread = unsafe {
                    chunk
                        .as_ptr()
                        .cast::<SYSTEM_THREAD_INFORMATION>()
                        .read_unaligned()
                };
                if thread.ClientId.UniqueProcess as usize != pid as usize {
                    return Err(());
                }
                let tid = u32::try_from(thread.ClientId.UniqueThread as usize).map_err(|_| ())?;
                if tid == current {
                    saw_current = true;
                } else if !stopped.contains(&tid) {
                    return Ok(false);
                }
            }
            return if saw_current { Ok(true) } else { Err(()) };
        }
        if process.NextEntryOffset == 0 {
            return Err(());
        }
        offset = offset.checked_add(length).ok_or(())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_record(pid: u32, ids: &[u32]) -> Vec<u8> {
        let header_size = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
        let thread_size = std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();
        let mut bytes = vec![0u8; header_size + ids.len() * thread_size];
        let mut process: SYSTEM_PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        process.UniqueProcessId = pid as usize as _;
        process.NumberOfThreads = ids.len() as u32;
        unsafe {
            bytes
                .as_mut_ptr()
                .cast::<SYSTEM_PROCESS_INFORMATION>()
                .write_unaligned(process)
        };
        for (index, id) in ids.iter().enumerate() {
            let mut thread: SYSTEM_THREAD_INFORMATION = unsafe { std::mem::zeroed() };
            thread.ClientId.UniqueProcess = pid as usize as _;
            thread.ClientId.UniqueThread = *id as usize as _;
            unsafe {
                bytes
                    .as_mut_ptr()
                    .add(header_size + index * thread_size)
                    .cast::<SYSTEM_THREAD_INFORMATION>()
                    .write_unaligned(thread);
            }
        }
        bytes
    }

    #[test]
    fn detects_threads_missing_from_the_stopped_set_without_allocating() {
        let bytes = process_record(7, &[9, 10, 11]);
        crate::heap_watch::begin();
        let complete = only_known_threads(&bytes, 7, 9, &[10, 11]);
        let raced = only_known_threads(&bytes, 7, 9, &[10]);
        crate::heap_watch::end();
        assert_eq!(complete, Ok(true));
        assert_eq!(raced, Ok(false));
    }

    #[test]
    fn malformed_or_missing_native_records_refuse_the_patch() {
        let mut bytes = process_record(7, &[9, 10]);
        assert_eq!(
            only_known_threads(&bytes[..bytes.len() - 1], 7, 9, &[10]),
            Err(())
        );
        assert_eq!(only_known_threads(&bytes, 8, 9, &[10]), Err(()));
        assert_eq!(only_known_threads(&bytes, 7, 20, &[9, 10]), Err(()));
        bytes[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(only_known_threads(&bytes, 7, 9, &[10]), Err(()));
    }
}
