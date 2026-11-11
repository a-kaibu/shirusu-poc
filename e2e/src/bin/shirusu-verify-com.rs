//! L17 検証用アプリ (3): COM を使うアプリ。
//!
//! overview 初期マイルストーン節の「COM を使うアプリ」。CoInitializeEx で
//! STA を初期化し、ShellLink（CLSID_ShellLink）の CoCreateInstance、
//! SetPath/GetPath の往復、IPersistFile への QueryInterface を行う。
//! 各ステップは `VERIFY com <step> ok` 行を出す（`--verify-out <path>`
//! 指定時はファイルにも書く）。
//! COM の API は現行フック表に無いため Trace には現れない（L02・L03 待ち）。
//! ファイルの往復はフック対象 API を通るため、Trace には 4 API ×
//! enter/leave ＝ 8 イベントが残る（capture-e2e --verify-apps が確認）。
//! Windows 以外では何もせず終了する（CI の Linux ジョブでもビルドだけは通る）。

#[cfg(windows)]
mod win {
    use shirusu_e2e::verify_win::{self, wide};
    use shirusu_e2e::VerifyOut;
    use std::ffi::c_void;

    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
        fn CoUninitialize();
        fn CoCreateInstance(
            clsid: *const Guid,
            unk: *mut c_void,
            ctx: u32,
            iid: *const Guid,
            out: *mut *mut c_void,
        ) -> i32;
    }

    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const CLSCTX_INPROC_SERVER: u32 = 0x1;
    const CONTENT: &[u8] = b"shirusu-verify-com";

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const CLSID_SHELL_LINK: Guid = Guid {
        data1: 0x00021401,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    const IID_ISHELL_LINK_W: Guid = Guid {
        data1: 0x000214F9,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    const IID_IPERSIST_FILE: Guid = Guid {
        data1: 0x0000010B,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    /// IShellLinkW の vtable（使うのは IUnknown 3 件＋GetPath＋SetPath だけ
    /// だが、SetPath までの位置を合わせるため全エントリを並べる）。
    /// 位置: 0 QueryInterface, 1 AddRef, 2 Release, 3 GetPath,
    /// 4 GetIDList, 5 SetIDList, 6 GetDescription, 7 SetDescription,
    /// 8 GetWorkingDirectory, 9 SetWorkingDirectory, 10 GetArguments,
    /// 11 SetArguments, 12 GetHotkey, 13 SetHotkey, 14 GetShowCmd,
    /// 15 SetShowCmd, 16 GetIconLocation, 17 SetIconLocation,
    /// 18 SetRelativePath, 19 Resolve, 20 SetPath.
    #[repr(C)]
    struct IShellLinkWVtbl {
        query_interface: extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        add_ref: extern "system" fn(*mut c_void) -> u32,
        release: extern "system" fn(*mut c_void) -> u32,
        get_path: extern "system" fn(*mut c_void, *mut u16, i32, *mut c_void, u32) -> i32,
        get_id_list: extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
        set_id_list: extern "system" fn(*mut c_void, *const c_void) -> i32,
        get_description: extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_description: extern "system" fn(*mut c_void, *const u16) -> i32,
        get_working_directory: extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_working_directory: extern "system" fn(*mut c_void, *const u16) -> i32,
        get_arguments: extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_arguments: extern "system" fn(*mut c_void, *const u16) -> i32,
        get_hotkey: extern "system" fn(*mut c_void, *mut u16) -> i32,
        set_hotkey: extern "system" fn(*mut c_void, u16) -> i32,
        get_show_cmd: extern "system" fn(*mut c_void, *mut i32) -> i32,
        set_show_cmd: extern "system" fn(*mut c_void, i32) -> i32,
        get_icon_location: extern "system" fn(*mut c_void, *mut u16, i32, *mut i32) -> i32,
        set_icon_location: extern "system" fn(*mut c_void, *const u16, i32) -> i32,
        set_relative_path: extern "system" fn(*mut c_void, *const u16, u32) -> i32,
        resolve: extern "system" fn(*mut c_void, *mut c_void, u32) -> i32,
        set_path: extern "system" fn(*mut c_void, *const u16) -> i32,
    }

    #[repr(C)]
    struct IShellLinkW {
        vtbl: *const IShellLinkWVtbl,
    }

    fn com_init_step() -> Result<String, String> {
        // SAFETY: reserved は NULL 可。S_OK(0)・S_FALSE(1) とも成功扱い。
        let hr = unsafe { CoInitializeEx(std::ptr::null_mut(), COINIT_APARTMENTTHREADED) };
        if hr != 0 && hr != 1 {
            return Err(format!("CoInitializeEx hr={hr:#x}"));
        }
        Ok("init ok".to_string())
    }

    /// ShellLink を作り、一時ファイルのパスを SetPath/GetPath で往復させる。
    /// 値は定数（パスを含まない）。link は呼び出し元が persist ステップと
    /// 解放で使うため out 引数で返す。
    fn shelllink_step(
        path: &std::path::Path,
        link_out: &mut *mut c_void,
    ) -> Result<String, String> {
        let path_w = wide(&path.to_string_lossy());
        let mut link: *mut c_void = std::ptr::null_mut();
        // SAFETY: CLSID/IID は有効な定数、link は out 引数。
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_SHELL_LINK,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ISHELL_LINK_W,
                &mut link,
            )
        };
        if hr != 0 || link.is_null() {
            return Err(format!("CoCreateInstance hr={hr:#x}"));
        }
        // SAFETY: link は CoCreateInstance の戻りで有効。
        let r = unsafe {
            let shell = link as *const IShellLinkW;
            let vtbl = (*shell).vtbl;
            let hr = ((*vtbl).set_path)(link, path_w.as_ptr());
            if hr != 0 {
                ((*vtbl).release)(link);
                return Err(format!("SetPath hr={hr:#x}"));
            }
            let mut buf = [0u16; 260];
            let hr = ((*vtbl).get_path)(link, buf.as_mut_ptr(), 260, std::ptr::null_mut(), 0);
            if hr != 0 {
                ((*vtbl).release)(link);
                return Err(format!("GetPath hr={hr:#x}"));
            }
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let got = String::from_utf16_lossy(&buf[..n]);
            let want = path.to_string_lossy();
            // ドライブ文字の大文字小文字など、表記の揺れは吸収する。
            // 往復したパスそのものが一致することが検査対象。
            if !got.eq_ignore_ascii_case(&want) {
                ((*vtbl).release)(link);
                return Err(format!("path mismatch: got {got}"));
            }
            *link_out = link;
            Ok(())
        };
        r.map(|()| "path ok".to_string())
    }

    /// IPersistFile への QueryInterface が成功し、参照カウントが
    /// 壊れずに解放できることを見る（同一性・寿命を壊さない。L02 の前提）。
    fn persist_step(link: *mut c_void) -> Result<String, String> {
        if link.is_null() {
            return Err("no shelllink (previous step failed)".into());
        }
        // SAFETY: link は shelllink ステップで取得した有効なポインタ。
        unsafe {
            let shell = link as *const IShellLinkW;
            let vtbl = (*shell).vtbl;
            let mut persist: *mut c_void = std::ptr::null_mut();
            let hr = ((*vtbl).query_interface)(link, &IID_IPERSIST_FILE, &mut persist);
            if hr != 0 || persist.is_null() {
                ((*vtbl).release)(link);
                return Err(format!("QueryInterface IPersistFile hr={hr:#x}"));
            }
            // IPersistFile の IUnknown::Release（vtable 先頭 3 件は共通）。
            let persist_unk = persist as *const IShellLinkW;
            let persist_vtbl = (*persist_unk).vtbl;
            ((*persist_vtbl).release)(persist);
            ((*vtbl).release)(link);
        }
        Ok("qi ok".to_string())
    }

    pub fn run(verify_out: Option<&str>) -> i32 {
        let pid = std::process::id();
        let mut v = VerifyOut::new("com");
        let path = verify_win::temp_path("com", pid);
        v.step("file", verify_win::write_and_read_back(&path, CONTENT));
        let _ = std::fs::remove_file(&path);
        // COM の初期化に失敗したら、後続の 2 ステップは実行せず終了する
        // （CoUninitialize は初期化成功時のみ呼ぶ）。
        match com_init_step() {
            Ok(msg) => {
                v.step("com-init", Ok(msg));
                let mut link: *mut c_void = std::ptr::null_mut();
                v.step("shelllink", shelllink_step(&path, &mut link));
                v.step("persist", persist_step(link));
                // SAFETY: CoInitializeEx が成功している。
                unsafe {
                    CoUninitialize();
                }
            }
            Err(e) => {
                v.step("com-init", Err(e));
                v.step("shelllink", Err("skipped (com-init failed)".into()));
                v.step("persist", Err("skipped (com-init failed)".into()));
            }
        }
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
    println!("SKIP shirusu-verify-com (windows only)");
}
