//! L17 検証用アプリ (1): ファイル・レジストリ・スレッドを使うコンソールアプリ。
//!
//! overview 初期マイルストーン節の「ファイル・レジストリ・スレッドを使う
//! コンソールアプリ」。各ステップは `VERIFY console <step> ok` 行を出す
//! （`--verify-out <path>` 指定時はファイルにも書く）。
//! レジストリ・スレッドの API は現行フック表に無いため Trace には現れない
//! （L03 待ち）。ファイルの往復はフック対象 API を通るため、Trace には
//! 4 API × enter/leave ＝ 8 イベントが残る（capture-e2e --verify-apps が確認）。
//! Windows 以外では何もせず終了する（CI の Linux ジョブでもビルドだけは通る）。

#[cfg(windows)]
mod win {
    use shirusu_e2e::verify_win::{self, wide};
    use shirusu_e2e::VerifyOut;
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateThread(
            sa: *mut c_void,
            stack: usize,
            start: extern "system" fn(*mut c_void) -> u32,
            param: *mut c_void,
            flags: u32,
            id: *mut u32,
        ) -> *mut c_void;
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn GetExitCodeThread(h: *mut c_void, code: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hkey: *mut c_void,
            subkey: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            sam: u32,
            sa: *mut c_void,
            result: *mut *mut c_void,
            disposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hkey: *mut c_void,
            name: *const u16,
            reserved: u32,
            ty: u32,
            data: *const u8,
            cb: u32,
        ) -> i32;
        fn RegQueryValueExW(
            hkey: *mut c_void,
            name: *const u16,
            reserved: *mut u32,
            ty: *mut u32,
            data: *mut u8,
            cb: *mut u32,
        ) -> i32;
        fn RegDeleteValueW(hkey: *mut c_void, name: *const u16) -> i32;
        fn RegCloseKey(hkey: *mut c_void) -> i32;
        fn RegDeleteKeyW(hkey: *mut c_void, subkey: *const u16) -> i32;
    }

    const HKEY_CURRENT_USER: *mut c_void = 0x8000_0001usize as *mut c_void;
    const KEY_ALL_ACCESS: u32 = 0xF003F;
    const REG_SZ: u32 = 1;
    const CONTENT: &[u8] = b"shirusu-verify-console";

    /// HKCU\Software\ShirusuVerify\console-<pid> へ REG_SZ を書いて読み戻し、
    /// 値が一致すれば Ok("value ok")。書き込んだ値とキーは最後に消す。
    fn registry_step(pid: u32) -> Result<String, String> {
        let subkey = format!("Software\\ShirusuVerify\\console-{pid}");
        let subkey_w = wide(&subkey);
        let name_w = wide("greeting");
        let value = "hello-from-shirusu";
        let value_w: Vec<u16> = value.encode_utf16().chain([0]).collect();
        let mut hkey: *mut c_void = std::ptr::null_mut();
        let mut disposition = 0u32;
        // SAFETY: ポインタはいずれも生存期間内のローカルを指す。
        unsafe {
            let rc = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                std::ptr::null_mut(),
                0, // REG_OPTION_NON_VOLATILE
                KEY_ALL_ACCESS,
                std::ptr::null_mut(),
                &mut hkey,
                &mut disposition,
            );
            if rc != 0 {
                return Err(format!("create key rc={rc}"));
            }
            let rc = RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                REG_SZ,
                value_w.as_ptr() as *const u8,
                (value_w.len() * 2) as u32,
            );
            if rc != 0 {
                RegCloseKey(hkey);
                return Err(format!("set value rc={rc}"));
            }
            let mut ty = 0u32;
            let mut buf = [0u16; 64];
            let mut cb = (buf.len() * 2) as u32;
            let rc = RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr() as *mut u8,
                &mut cb,
            );
            if rc != 0 {
                RegCloseKey(hkey);
                return Err(format!("query value rc={rc}"));
            }
            if ty != REG_SZ {
                RegCloseKey(hkey);
                return Err(format!("value type={ty}"));
            }
            let n = (cb as usize) / 2;
            let read = String::from_utf16_lossy(&buf[..n])
                .trim_end_matches('\0')
                .to_string();
            let rc = RegDeleteValueW(hkey, name_w.as_ptr());
            RegCloseKey(hkey);
            let rc_del = RegDeleteKeyW(HKEY_CURRENT_USER, subkey_w.as_ptr());
            if read != value {
                return Err(format!("value mismatch: {read}"));
            }
            if rc != 0 {
                return Err(format!("delete value rc={rc}"));
            }
            if rc_del != 0 {
                return Err(format!("delete key rc={rc_del}"));
            }
        }
        Ok("value ok".to_string())
    }

    /// 別スレッドでカウンタへ 42 を書き、終了コード 42 で戻ることを見る。
    extern "system" fn thread_proc(param: *mut c_void) -> u32 {
        // SAFETY: 呼び出し元が param の指す u32 の生存期間を保証する
        // （メインスレッドが WaitForSingleObject で完了を待つ）。
        unsafe {
            *(param as *mut u32) = 42;
        }
        42
    }

    fn thread_step() -> Result<String, String> {
        let mut counter = 0u32;
        // SAFETY: counter はスレッド完了まで生存し、待機で保証する。
        unsafe {
            let h = CreateThread(
                std::ptr::null_mut(),
                0,
                thread_proc,
                &mut counter as *mut u32 as *mut c_void,
                0,
                std::ptr::null_mut(),
            );
            if verify_win::is_invalid_handle(h) {
                return Err(format!("create thread error={}", GetLastError()));
            }
            let waited = WaitForSingleObject(h, 10_000);
            let mut code = 0u32;
            let ok = GetExitCodeThread(h, &mut code) != 0;
            CloseHandle(h);
            if waited != 0 {
                return Err(format!("thread wait failed: {waited}"));
            }
            if !ok {
                return Err("GetExitCodeThread failed".into());
            }
            if code != 42 {
                return Err(format!("thread exit={code}"));
            }
            if counter != 42 {
                return Err(format!("thread counter={counter}"));
            }
        }
        Ok("exit=42".to_string())
    }

    pub fn run(verify_out: Option<&str>) -> i32 {
        let pid = std::process::id();
        let mut v = VerifyOut::new("console");
        let path = verify_win::temp_path("console", pid);
        v.step("file", verify_win::write_and_read_back(&path, CONTENT));
        let _ = std::fs::remove_file(&path);
        v.step("registry", registry_step(pid));
        v.step("thread", thread_step());
        v.finish(verify_out)
    }
}

fn main() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        let out = args
            .windows(2)
            .find(|w| w[0] == "--verify-out")
            .map(|w| w[1].as_str());
        std::process::exit(win::run(out));
    }
    #[cfg(not(windows))]
    println!("SKIP shirusu-verify-console (windows only)");
}
