//! フック E2E の対象プロセス。
//!
//! CreateFileW / WriteFile / ReadFile / CloseHandle を直接 FFI で呼び、
//! 一時ファイルへ既知の内容を書いて読み戻す。自前の IAT に 4 API の
//! インポートが載るよう、あえて std::fs を使わずに書く。
//! Windows 以外では何もせず終了する（CI の Linux ジョブでも
//! ビルドだけは通る）。

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn WriteFile(
            h: *mut c_void,
            buf: *const u8,
            n: u32,
            written: *mut u32,
            ovl: *mut c_void,
        ) -> i32;
        fn ReadFile(h: *mut c_void, buf: *mut u8, n: u32, read: *mut u32, ovl: *mut c_void) -> i32;
        fn SetFilePointer(h: *mut c_void, dist: i32, high: *mut i32, method: u32) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub const CONTENT: &[u8] = b"shirusu-hook-e2e-content";

    pub fn run() -> i32 {
        let path =
            std::env::temp_dir().join(format!("shirusu-hook-target-{}.tmp", std::process::id()));
        println!("TARGET_PATH {}", path.display());
        let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
        // SAFETY: ポインタはいずれも生存期間内のローカルを指す。
        unsafe {
            let h = CreateFileW(
                wide.as_ptr(),
                0xC000_0000, // GENERIC_READ | GENERIC_WRITE
                0,
                std::ptr::null_mut(),
                2,    // CREATE_ALWAYS
                0x80, // FILE_ATTRIBUTE_NORMAL
                std::ptr::null_mut(),
            );
            if h.is_null() || h as usize == usize::MAX {
                println!("TARGET_FAIL create error={}", GetLastError());
                return 2;
            }
            let mut written = 0u32;
            if WriteFile(
                h,
                CONTENT.as_ptr(),
                CONTENT.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            ) == 0
                || written as usize != CONTENT.len()
            {
                println!("TARGET_FAIL write error={}", GetLastError());
                return 3;
            }
            if SetFilePointer(h, 0, std::ptr::null_mut(), 0) == u32::MAX {
                println!("TARGET_FAIL seek error={}", GetLastError());
                return 4;
            }
            let mut buf = [0u8; 64];
            let mut read = 0u32;
            if ReadFile(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            ) == 0
            {
                println!("TARGET_FAIL read error={}", GetLastError());
                return 5;
            }
            if &buf[..read as usize] != CONTENT {
                println!("TARGET_FAIL content mismatch read={read}");
                return 6;
            }
            if CloseHandle(h) == 0 {
                println!("TARGET_FAIL close error={}", GetLastError());
                return 7;
            }
        }
        println!("TARGET_DONE ok");
        0
    }
}

fn main() {
    #[cfg(windows)]
    std::process::exit(win::run());
    #[cfg(not(windows))]
    println!("SKIP shirusu-hook-target (windows only)");
}
