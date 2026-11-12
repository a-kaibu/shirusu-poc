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
        fn SetLastError(code: u32);
        fn CreateThread(
            sa: *mut c_void,
            stack: usize,
            start: extern "system" fn(*mut c_void) -> u32,
            param: *mut c_void,
            flags: u32,
            id: *mut u32,
        ) -> *mut c_void;
        fn GetExitCodeThread(h: *mut c_void, code: *mut u32) -> i32;
        fn CreateProcessW(
            app: *const u16,
            cmdline: *mut u16,
            pa: *mut c_void,
            ta: *mut c_void,
            inherit: i32,
            flags: u32,
            env: *mut c_void,
            dir: *const u16,
            si: *const c_void,
            pi: *mut ProcessInformation,
        ) -> i32;
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn GetExitCodeProcess(h: *mut c_void, code: *mut u32) -> i32;
        fn Sleep(ms: u32);
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    // Keep advapi32 loaded before injection so the dynamic-export fixture
    // tests an installed Inline Hook, not late module discovery.
    #[link(name = "advapi32")]
    extern "system" {
        fn RegCloseKey(key: *mut c_void) -> i32;
    }

    // CRT のファイル I/O（ucrtbase.dll）。`fopen` は内部で `CreateFileW`
    // を呼ぶが、その呼び出しは ucrtbase.dll 自身の IAT 経由のため、
    // 現行のメインモジュール限定 IAT では Detour に届かない。
    // L23 の呼び出し元分類の検証対象（L01 後に抑制の実動を確認する）。
    extern "C" {
        fn fopen(path: *const std::ffi::c_char, mode: *const std::ffi::c_char) -> *mut c_void;
        fn fwrite(ptr: *const c_void, size: usize, count: usize, stream: *mut c_void) -> usize;
        fn fclose(stream: *mut c_void) -> i32;
    }

    /// STARTUPINFOW（CreateProcessW 用。cb だけが必須）。
    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_count: u32,
        y_count: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        reserved2: u16,
        reserved2_bytes: *mut u8,
        std_input: *mut c_void,
        std_output: *mut c_void,
        std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: *mut c_void,
        thread: *mut c_void,
        process_id: u32,
        thread_id: u32,
    }

    /// 自分自身を `--child` 付きで子プロセスとして起動し、終了を待つ
    /// （L05 の E2E 用。子は 500ms 待ってからファイル操作をするため、
    /// ドライバが発見・注入する時間がある）。
    pub fn spawn_child_and_wait() -> i32 {
        let exe = std::env::current_exe().expect("current exe");
        let mut cmdline: Vec<u16> = format!("\"{}\" --child", exe.display())
            .encode_utf16()
            .chain([0])
            .collect();
        let mut si: StartupInfoW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        let mut pi: ProcessInformation = unsafe { std::mem::zeroed() };
        // SAFETY: si/pi は有効なローカルを指し、cmdline は書き換え可能。
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null(),
                &si as *const StartupInfoW as *const c_void,
                &mut pi,
            )
        };
        if ok == 0 {
            println!("TARGET_FAIL spawn error={}", unsafe { GetLastError() });
            return 8;
        }
        unsafe {
            WaitForSingleObject(pi.process, 0xFFFF_FFFF);
            let mut code = 0u32;
            GetExitCodeProcess(pi.process, &mut code);
            CloseHandle(pi.process);
            CloseHandle(pi.thread);
            if code != 0 {
                println!("TARGET_FAIL child exit={code}");
                return 9;
            }
        }
        println!("TARGET_CHILD_DONE ok");
        0
    }

    /// 子プロセスとして起動された場合の待ち（ドライバの発見・注入用）。
    pub fn wait_as_child() {
        unsafe { Sleep(500) };
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

    /// L23: 直接呼び出しと CRT 経由の呼び出しを両方行う。直接の方は
    /// exe の IAT 経由で Detour が見て、呼び出し元は Application。
    /// CRT 経由の方は ucrtbase.dll 内の呼び出しで、L01 の Inline Hook
    /// で Detour に届き、L23 の呼び出し元分類で抑制される（既定では
    /// 記録されない。capture-e2e --modules が両方を検証する）。
    /// `dir` に 2 つの一時ファイルを作り、パスを標準出力へ出す。
    pub fn run_runtime_caller(dir: &str) -> i32 {
        let pid = std::process::id();
        let direct =
            std::path::PathBuf::from(dir).join(format!("shirusu-runtime-caller-direct-{pid}.tmp"));
        let crt =
            std::path::PathBuf::from(dir).join(format!("shirusu-runtime-caller-crt-{pid}.tmp"));
        if let Err(e) = write_and_read_back(&direct, CONTENT) {
            println!("TARGET_FAIL direct: {e}");
            return 2;
        }
        // CRT 経由。fopen/fwrite/fclose は ucrtbase.dll 内で CreateFileW /
        // WriteFile / CloseHandle を呼ぶ。
        let Ok(crt_c) = std::ffi::CString::new(crt.to_string_lossy().as_bytes()) else {
            println!("TARGET_FAIL crt path");
            return 3;
        };
        let Ok(mode_c) = std::ffi::CString::new("wb") else {
            println!("TARGET_FAIL crt mode");
            return 3;
        };
        // SAFETY: crt_c/mode_c は NUL 終端の有効な文字列。
        let stream = unsafe { fopen(crt_c.as_ptr(), mode_c.as_ptr()) };
        if stream.is_null() {
            println!("TARGET_FAIL fopen");
            return 4;
        }
        // SAFETY: stream は fopen の戻り、CONTENT は生存期間内。
        let n = unsafe { fwrite(CONTENT.as_ptr() as *const c_void, 1, CONTENT.len(), stream) };
        // SAFETY: stream は fopen の戻り。
        let closed = unsafe { fclose(stream) };
        if n != CONTENT.len() || closed != 0 {
            println!("TARGET_FAIL crt write n={n} closed={closed}");
            return 5;
        }
        println!("RUNTIME_CALLER direct {}", direct.display());
        println!("RUNTIME_CALLER crt {}", crt.display());
        println!("RUNTIME_CALLER_DONE ok");
        0
    }

    /// L01: `GetProcAddress` で取得した関数ポインタ経由の呼び出し。
    /// IAT を通らないため、Inline Hook だけが捕捉できる。ファイル 4 API
    /// （kernel32）と RegCreateKeyExW / RegCloseKey（advapi32）を動的
    /// 解決し、通常のファイル操作とレジストリ 1 件を行う。成功すれば
    /// `GETPROCADDRESS_DONE ok` を出し終了 0。
    pub fn run_getprocaddress() -> i32 {
        std::hint::black_box(RegCloseKey as unsafe extern "system" fn(*mut c_void) -> i32);
        type CreateFileWFn = unsafe extern "system" fn(
            *const u16,
            u32,
            u32,
            *mut c_void,
            u32,
            u32,
            *mut c_void,
        ) -> *mut c_void;
        type WriteFileFn =
            unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
        type ReadFileFn =
            unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut c_void) -> i32;
        type SetFilePointerFn = unsafe extern "system" fn(*mut c_void, i32, *mut i32, u32) -> u32;
        type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
        type RegCreateKeyExWFn = unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            u32,
            *mut u16,
            u32,
            u32,
            *mut c_void,
            *mut *mut c_void,
            *mut u32,
        ) -> i32;
        type RegCloseKeyFn = unsafe extern "system" fn(*mut c_void) -> i32;

        fn resolve(module: &str, name: &str) -> Option<*mut c_void> {
            let wide: Vec<u16> = module.encode_utf16().chain([0]).collect();
            // SAFETY: モジュール名はヌル終端済み。
            let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
            if handle.is_null() {
                return None;
            }
            let Ok(cname) = std::ffi::CString::new(name) else {
                return None;
            };
            // SAFETY: handle はロード済みモジュール、cname はヌル終端済み。
            let proc = unsafe { GetProcAddress(handle, cname.as_ptr() as *const u8) };
            if proc.is_null() {
                None
            } else {
                Some(proc)
            }
        }
        // SAFETY: 解決したアドレスを宣言した型の関数ポインタへ写す。
        // 名前と DLL が一致するため、型は対象 API のものと一致する。
        let create_file_w: CreateFileWFn = match resolve("kernel32.dll", "CreateFileW") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress CreateFileW");
                return 2;
            }
        };
        let write_file: WriteFileFn = match resolve("kernel32.dll", "WriteFile") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress WriteFile");
                return 2;
            }
        };
        let read_file: ReadFileFn = match resolve("kernel32.dll", "ReadFile") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress ReadFile");
                return 2;
            }
        };
        let set_file_pointer: SetFilePointerFn = match resolve("kernel32.dll", "SetFilePointer") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress SetFilePointer");
                return 2;
            }
        };
        let close_handle: CloseHandleFn = match resolve("kernel32.dll", "CloseHandle") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress CloseHandle");
                return 2;
            }
        };
        let reg_create: RegCreateKeyExWFn = match resolve("advapi32.dll", "RegCreateKeyExW") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress RegCreateKeyExW");
                return 2;
            }
        };
        let reg_close: RegCloseKeyFn = match resolve("advapi32.dll", "RegCloseKey") {
            Some(p) => unsafe { std::mem::transmute(p) },
            None => {
                println!("TARGET_FAIL getprocaddress RegCloseKey");
                return 2;
            }
        };

        let path = std::env::temp_dir().join(format!(
            "shirusu-hook-target-gpa-{}.tmp",
            std::process::id()
        ));
        let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
        // SAFETY: ポインタはいずれも生存期間内のローカルを指す。
        unsafe {
            let h = create_file_w(
                wide.as_ptr(),
                0xC000_0000,
                0,
                std::ptr::null_mut(),
                2,
                0x80,
                std::ptr::null_mut(),
            );
            if h.is_null() || h as usize == usize::MAX {
                println!("TARGET_FAIL create error={}", GetLastError());
                return 3;
            }
            let mut written = 0u32;
            if write_file(
                h,
                CONTENT.as_ptr(),
                CONTENT.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            ) == 0
                || written as usize != CONTENT.len()
            {
                println!("TARGET_FAIL write error={}", GetLastError());
                return 4;
            }
            if set_file_pointer(h, 0, std::ptr::null_mut(), 0) == u32::MAX {
                println!("TARGET_FAIL seek error={}", GetLastError());
                return 5;
            }
            let mut buf = [0u8; 64];
            let mut read = 0u32;
            if read_file(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            ) == 0
            {
                println!("TARGET_FAIL read error={}", GetLastError());
                return 6;
            }
            if &buf[..read as usize] != CONTENT {
                println!("TARGET_FAIL content mismatch read={read}");
                return 7;
            }
            if close_handle(h) == 0 {
                println!("TARGET_FAIL close error={}", GetLastError());
                return 8;
            }
            // レジストリ 1 件（生成 API 経由の Inline Hook も確認する）。
            let subkey: Vec<u16> = "Software\\ShirusuInlineHookTest"
                .encode_utf16()
                .chain([0])
                .collect();
            let mut key: *mut c_void = std::ptr::null_mut();
            let mut disp = 0u32;
            let rc = reg_create(
                0x8000_0001 as *mut c_void, // HKEY_CURRENT_USER
                subkey.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0x0002_0000, // KEY_SET_VALUE
                std::ptr::null_mut(),
                &mut key,
                &mut disp,
            );
            if rc != 0 || key.is_null() {
                println!("TARGET_FAIL regcreate rc={rc}");
                return 9;
            }
            if reg_close(key) != 0 {
                println!("TARGET_FAIL regclose");
                return 10;
            }
        }
        let _ = std::fs::remove_file(&path);
        println!("TARGET_PATH {}", path.display());
        println!("GETPROCADDRESS_DONE ok");
        0
    }

    // ---- L06: ABI 適合性 Probe ----
    //
    // overview「Hookの透明性」節：浮動小数点引数、構造体の戻り値、
    // コールバック、例外、`LastError` を扱う Probe を Hook ありとなしで
    // 実行して結果を比べる。各 Probe は `ABI_PROBE <name> <value>` を
    // 1 行出し、比較は値のビット単位の一致を見る（capture-e2e --abi）。
    // Probe 自体の成否はファイル I/O の成否だけで決め、期待値は
    // ハードコードしない——Hook ありとなしの「差」こそが検査対象のため。
    //
    // 境界：SEH 例外が Detour の実行中に起きる経路（L08 の CallAborted
    // の実動）は、現行 4 API の呼び出しでは SEH を起こす引数が作れず
    // （不正なバッファはカーネルがエラーで返す）、ここでは扱わない。
    // 例外 Probe は Rust のパニックの伝播と、巻き戻し後のフック健全性を
    // 見る。可変長引数 API は現行フック対象に無く、対象外。

    /// Probe 用の一時ファイル名（Probe 名と pid で一意にする）。
    fn probe_path(name: &str, pid: u32) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("shirusu-abi-{name}-{pid}.tmp"))
    }

    fn is_invalid_handle(h: *mut c_void) -> bool {
        h.is_null() || h as usize == usize::MAX
    }

    fn create_file_w(path: &std::path::Path, disposition: u32) -> *mut c_void {
        let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
        // SAFETY: wide は生存期間内のローカルを指す。
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                0xC000_0000, // GENERIC_READ | GENERIC_WRITE
                0,
                std::ptr::null_mut(),
                disposition,
                0x80, // FILE_ATTRIBUTE_NORMAL
                std::ptr::null_mut(),
            )
        }
    }

    fn write_all(h: *mut c_void, data: &[u8]) -> bool {
        let mut written = 0u32;
        // SAFETY: h は直前の CreateFileW の戻り、data は生存期間内。
        let ok = unsafe {
            WriteFile(
                h,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        ok != 0 && written as usize == data.len()
    }

    fn read_exact(h: *mut c_void, buf: &mut [u8]) -> bool {
        let mut read = 0u32;
        // SAFETY: h は有効、buf は生存期間内の書き込み先。
        let ok = unsafe {
            ReadFile(
                h,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        ok != 0 && read as usize == buf.len()
    }

    fn close(h: *mut c_void) {
        // SAFETY: h は有効なハンドル。
        unsafe {
            CloseHandle(h);
        }
    }

    /// 書いて読み戻す（内容の往復確認つき）。CreateFileW / WriteFile /
    /// ReadFile / CloseHandle の 4 API をすべて通る。
    fn write_and_read_back(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
        let h = create_file_w(path, 2 /* CREATE_ALWAYS */);
        if is_invalid_handle(h) {
            return Err(format!("create error={}", unsafe { GetLastError() }));
        }
        if !write_all(h, data) {
            let e = unsafe { GetLastError() };
            close(h);
            return Err(format!("write error={e}"));
        }
        // SAFETY: h は有効、dist/high は仕様どおり（high は NULL 可）。
        if unsafe { SetFilePointer(h, 0, std::ptr::null_mut(), 0) } == u32::MAX {
            let e = unsafe { GetLastError() };
            close(h);
            return Err(format!("seek error={e}"));
        }
        let mut buf = vec![0u8; data.len()];
        if !read_exact(h, &mut buf) {
            let e = unsafe { GetLastError() };
            close(h);
            return Err(format!("read error={e}"));
        }
        close(h);
        if buf != data {
            return Err("content mismatch".into());
        }
        Ok(())
    }

    /// 8 個の f64 引数（x64 では先頭 4 個が XMM0-3、残りはスタック渡し）
    /// と f32 1 個を、フックされた呼び出しの前後で生かす。呼び出し規約・
    /// 浮動小数点レジスタ・スタックの整合性が壊れれば、Hook ありとなしで
    /// ビット列が変わる。`#[inline(never)]` で畳み込みを防ぐ。
    #[inline(never)]
    fn float_many_args(
        a: f64,
        b: f64,
        c: f64,
        d: f64,
        e: f64,
        f: f64,
        g: f64,
        h: f64,
        path: &std::path::Path,
    ) -> Option<(u64, u32, u64)> {
        let x = 1.23456789012345f64;
        let y = 9.87654321098765f64;
        let z = 3.14159265358979f32;
        // フックされた呼び出しの前後で値を生かす。black_box で定数畳み込み
        // を防ぎ、計算が実行時に起きるようにする。
        let handle = create_file_w(path, 2 /* CREATE_ALWAYS */);
        let (a, b, c, d, e, f, g, h) = (
            std::hint::black_box(a),
            std::hint::black_box(b),
            std::hint::black_box(c),
            std::hint::black_box(d),
            std::hint::black_box(e),
            std::hint::black_box(f),
            std::hint::black_box(g),
            std::hint::black_box(h),
        );
        let x = std::hint::black_box(x);
        let y = std::hint::black_box(y);
        let z = std::hint::black_box(z);
        if is_invalid_handle(handle) {
            return None;
        }
        if !write_all(handle, b"float") {
            close(handle);
            return None;
        }
        close(handle);
        let sum = a + b + c + d + e + f + g + h;
        let after = x * 3.0 + y;
        let z2 = z * 2.5f32 + 1.0f32;
        Some((sum.to_bits(), z2.to_bits(), after.to_bits()))
    }

    fn float_probe(pid: u32) -> Result<String, String> {
        let path = probe_path("float", pid);
        let (sum, z2, after) = float_many_args(
            1.5, 2.25, 3.125, 4.0625, 5.03125, 6.015625, 7.0078125, 8.00390625, &path,
        )
        .ok_or_else(|| "float probe io failed".to_string())?;
        let _ = std::fs::remove_file(&path);
        Ok(format!("sum={sum:016x} f32={z2:08x} after={after:016x}"))
    }

    /// 24 B の構造体は x64/x86 とも隠しポインタ経由で返る（呼び出し元が
    /// 確保した領域へのポインタが第 1 引数）。フックされた呼び出しの後で
    /// 返す構造体が壊れていないことを見る。
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProbeStruct {
        tag: u64,
        ratio: f64,
        lo: u32,
        hi: u32,
    }

    #[inline(never)]
    fn struct_probe_inner(path: &std::path::Path) -> ProbeStruct {
        let handle = create_file_w(path, 2 /* CREATE_ALWAYS */);
        let s = ProbeStruct {
            tag: 0x0123_4567_89AB_CDEF,
            ratio: 2.718281828459045,
            lo: 0xDEAD_BEEF,
            hi: 0xCAFE_F00D,
        };
        let s = std::hint::black_box(s);
        if !is_invalid_handle(handle) {
            let _ = write_all(handle, b"struct");
            close(handle);
        }
        s
    }

    fn struct_return_probe(pid: u32) -> Result<String, String> {
        let path = probe_path("struct", pid);
        let s = struct_probe_inner(&path);
        let _ = std::fs::remove_file(&path);
        if s.tag != 0x0123_4567_89AB_CDEF
            || s.ratio.to_bits() != 2.718281828459045f64.to_bits()
            || s.lo != 0xDEAD_BEEF
            || s.hi != 0xCAFE_F00D
        {
            return Err(format!(
                "struct fields corrupted: tag={:016x} ratio={:016x} lo={:08x} hi={:08x}",
                s.tag,
                s.ratio.to_bits(),
                s.lo,
                s.hi
            ));
        }
        Ok(format!(
            "tag={:016x} ratio={:016x} lo={:08x} hi={:08x}",
            s.tag,
            s.ratio.to_bits(),
            s.lo,
            s.hi
        ))
    }

    const CALLBACK_CONTENT: &[u8] = b"shirusu-abi-callback";
    const THREAD_CONTENT: &[u8] = b"shirusu-abi-thread";

    /// 関数ポインタ経由のコールバック中でフックされた API を呼ぶ。
    /// 戻り値は書いたバイト数。`PathBuf` へのポインタを渡す（`Path` は
    /// DST でワイドポインタのため `*mut c_void` との往復ができない）。
    fn callback_fn(path: *const std::path::PathBuf) -> u32 {
        // SAFETY: 呼び出し元が path の生存期間を保証する。
        let path = unsafe { &*path };
        match write_and_read_back(path.as_path(), CALLBACK_CONTENT) {
            Ok(()) => CALLBACK_CONTENT.len() as u32,
            Err(_) => 0,
        }
    }

    #[inline(never)]
    fn invoke_callback(cb: fn(*const std::path::PathBuf) -> u32, path: &std::path::PathBuf) -> u32 {
        cb(path as *const std::path::PathBuf)
    }

    /// Windows から呼ばれるスレッドプロシージャ。別スレッドでフックされた
    /// API を呼ぶ（コールバックの入れ子記録と、別スレッドでの Detour の
    /// 動作を見る）。戻り値は書いたバイト数。
    extern "system" fn thread_proc(param: *mut c_void) -> u32 {
        // SAFETY: 呼び出し元が param の指す PathBuf の生存期間を保証する
        // （メインスレッドが WaitForSingleObject で完了を待つ）。
        let path = unsafe { &*(param as *const std::path::PathBuf) };
        match write_and_read_back(path.as_path(), THREAD_CONTENT) {
            Ok(()) => THREAD_CONTENT.len() as u32,
            Err(_) => 0,
        }
    }

    fn callback_probe(pid: u32) -> Result<String, String> {
        let fnptr_path = probe_path("callback-fnptr", pid);
        let n = invoke_callback(callback_fn, &fnptr_path);
        let _ = std::fs::remove_file(&fnptr_path);
        if n as usize != CALLBACK_CONTENT.len() {
            return Err(format!("fnptr callback wrote {n} bytes"));
        }
        let thread_path = probe_path("callback-thread", pid);
        // SAFETY: thread_path はスレッド完了まで生存し、待機で保証する。
        let thread = unsafe {
            CreateThread(
                std::ptr::null_mut(),
                0,
                thread_proc,
                &thread_path as *const std::path::PathBuf as *mut c_void,
                0,
                std::ptr::null_mut(),
            )
        };
        if is_invalid_handle(thread) {
            return Err(format!("CreateThread error={}", unsafe { GetLastError() }));
        }
        let waited = unsafe { WaitForSingleObject(thread, 10_000) };
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeThread(thread, &mut code) } != 0;
        close(thread);
        let _ = std::fs::remove_file(&thread_path);
        if waited != 0 {
            return Err(format!("thread wait failed: {waited}"));
        }
        if !ok {
            return Err("GetExitCodeThread failed".into());
        }
        if code as usize != THREAD_CONTENT.len() {
            return Err(format!("thread callback wrote {code} bytes"));
        }
        Ok(format!("fnptr={n} thread={code}"))
    }

    fn exception_probe(pid: u32) -> Result<String, String> {
        let path = probe_path("exception", pid);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_and_read_back(&path, b"exception").expect("exception probe io");
            panic!("abi-probe-panic-payload");
        }));
        let payload = match caught {
            Err(e) => {
                if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    return Err("panic payload is not a string".into());
                }
            }
            Ok(()) => return Err("panic did not propagate".into()),
        };
        if payload != "abi-probe-panic-payload" {
            return Err(format!("panic payload changed: {payload}"));
        }
        let _ = std::fs::remove_file(&path);
        // パニックの巻き戻し後もフックが壊れていないこと（後続の呼び出しが
        // 正常に記録・実行されること）を、もう一度ファイル操作して確認する。
        let path2 = probe_path("exception-after", pid);
        write_and_read_back(&path2, b"exception-after")?;
        let _ = std::fs::remove_file(&path2);
        Ok(format!("payload={payload} after=ok"))
    }

    fn lasterror_success_probe(pid: u32) -> Result<String, String> {
        // Success need not preserve entry LastError: CREATE_ALWAYS explicitly
        // sets it to zero for a new file. Capture immediately after each API;
        // the supervisor compares these observations with the no-hook baseline.
        let path = probe_path("lasterror", pid);
        let _ = std::fs::remove_file(&path);
        let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
        let (h, created_error) = unsafe {
            SetLastError(0x1234);
            let h = CreateFileW(
                wide.as_ptr(),
                0xC000_0000,
                0,
                std::ptr::null_mut(),
                2,
                0x80,
                std::ptr::null_mut(),
            );
            (h, GetLastError())
        };
        if is_invalid_handle(h) {
            return Err(format!("create error={created_error}"));
        }
        let mut byte = 0u8;
        let mut read = 0u32;
        let (read_ok, read_error) = unsafe {
            SetLastError(0x5678);
            let ok = ReadFile(h, &mut byte, 0, &mut read, std::ptr::null_mut());
            (ok, GetLastError())
        };
        let (close_ok, close_error) = unsafe {
            SetLastError(0x9ABC);
            let ok = CloseHandle(h);
            (ok, GetLastError())
        };
        let _ = std::fs::remove_file(&path);
        if created_error != 0 || read_ok == 0 || read != 0 || close_ok == 0 {
            return Err(format!("success probe failed: create={created_error} read={read_ok}/{read} close={close_ok}"));
        }
        Ok(format!(
            "create={created_error:#x} read={read_error:#x} close={close_error:#x}"
        ))
    }

    fn lasterror_failure_probe() -> Result<String, String> {
        // 存在しないファイルを開く（OPEN_EXISTING）。失敗のエラーコードが
        // Hook ありとなしで同じこと。
        let path = std::env::temp_dir().join("shirusu-abi-definitely-missing-9f3a2b1c.tmp");
        let _ = std::fs::remove_file(&path);
        let h = create_file_w(&path, 3 /* OPEN_EXISTING */);
        if !is_invalid_handle(h) {
            close(h);
            return Err("open of missing file unexpectedly succeeded".into());
        }
        let err = unsafe { GetLastError() };
        if err != 2 {
            return Err(format!("expected ERROR_FILE_NOT_FOUND(2), got {err}"));
        }
        Ok(format!("{err}"))
    }

    fn emit_probe(
        lines: &mut Vec<String>,
        failures: &mut Vec<&'static str>,
        name: &'static str,
        result: Result<String, String>,
    ) {
        match result {
            Ok(v) => lines.push(format!("ABI_PROBE {name} {v}")),
            Err(e) => {
                lines.push(format!("ABI_PROBE {name} FAIL {e}"));
                failures.push(name);
            }
        }
    }

    /// L06: ABI 適合性 Probe の実行。`ABI_PROBE <name> <value>` 行を
    /// stdout と --abi-out ファイル（指定時）へ出す。すべて通れば
    /// `ABI_PROBE_DONE ok` を出して 0 を返す。1 件でも失敗すれば
    /// TARGET_FAIL を出して 11 を返す。
    pub fn run_abi_probe(abi_out: Option<&str>) -> i32 {
        let pid = std::process::id();
        let mut lines: Vec<String> = Vec::new();
        let mut failures: Vec<&'static str> = Vec::new();
        // 各 Probe は失敗しても残りを続ける（どこが壊れたか分かるように）。
        emit_probe(&mut lines, &mut failures, "float", float_probe(pid));
        emit_probe(
            &mut lines,
            &mut failures,
            "struct-return",
            struct_return_probe(pid),
        );
        emit_probe(&mut lines, &mut failures, "callback", callback_probe(pid));
        emit_probe(&mut lines, &mut failures, "exception", exception_probe(pid));
        emit_probe(
            &mut lines,
            &mut failures,
            "lasterror-success",
            lasterror_success_probe(pid),
        );
        emit_probe(
            &mut lines,
            &mut failures,
            "lasterror-failure",
            lasterror_failure_probe(),
        );
        for line in &lines {
            println!("{line}");
        }
        let mut text = lines.join("\n");
        text.push('\n');
        if failures.is_empty() {
            println!("ABI_PROBE_DONE ok");
            text.push_str("ABI_PROBE_DONE ok\n");
            if let Some(out) = abi_out {
                if let Err(e) = std::fs::write(out, text) {
                    println!("TARGET_FAIL abi-out write error={e}");
                    return 10;
                }
            }
            0
        } else {
            println!("TARGET_FAIL abi probes failed: {}", failures.join(","));
            if let Some(out) = abi_out {
                if let Err(e) = std::fs::write(out, text) {
                    println!("TARGET_FAIL abi-out write error={e}");
                }
            }
            11
        }
    }
}

fn main() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--abi-probe") {
            // L06: ABI 適合性 Probe。--abi-out <path> があれば Probe 行を
            // そのファイルにも書く（capture-e2e --abi が比較に使う）。
            let out = args
                .windows(2)
                .find(|w| w[0] == "--abi-out")
                .map(|w| w[1].as_str());
            std::process::exit(win::run_abi_probe(out));
        }
        if args.iter().any(|a| a == "--runtime-caller") {
            // L23: 直接呼び出しと CRT 経由の呼び出し。--runtime-caller <dir>
            // が無ければ一時ディレクトリを使う。
            let dir = args
                .windows(2)
                .find(|w| w[0] == "--runtime-caller")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned());
            std::process::exit(win::run_runtime_caller(&dir));
        }
        if args.iter().any(|a| a == "--getprocaddress") {
            // L01: GetProcAddress 経由の呼び出し（Inline Hook の検証用）。
            std::process::exit(win::run_getprocaddress());
        }
        if args.iter().any(|a| a == "--child") {
            // 子プロセスとして起動された場合：ドライバの発見・注入に
            // 時間を稼ぐため少し待ってからファイル操作をする。
            win::wait_as_child();
            std::process::exit(win::run());
        }
        if args.iter().any(|a| a == "--spawn-child") {
            let rc = win::spawn_child_and_wait();
            if rc != 0 {
                std::process::exit(rc);
            }
            std::process::exit(win::run());
        }
        std::process::exit(win::run());
    }
    #[cfg(not(windows))]
    println!("SKIP shirusu-hook-target (windows only)");
}
