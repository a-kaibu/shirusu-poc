//! L17 検証用アプリ (2): USER32・GDI・DIB を使う GUI アプリ。
//!
//! overview 初期マイルストーン節の「USER32・GDI・DIB を使う GUI アプリ」。
//! 各ステップは `VERIFY gui <step> ok` 行を出す（`--verify-out <path>`
//! 指定時はファイルにも書く）。
//!
//! 対話は一切しない。ウィンドウはメッセージ専用ウィンドウ（HWND_MESSAGE）
//! で、WM_CLOSE を自分へ送ってメッセージループを回して終わる。GDI は
//! メモリ DC 上でのみ描き、DIB は CreateDIBSection のビットへ直接書いて
//! 読み戻す。表示 DC を使わないため、ヘッドレスな CI ランナーでも動く。
//! USER32・GDI・DIB の API は現行フック表に無いため Trace には現れない
//! （L03 待ち）。ファイルの往復はフック対象 API を通るため、Trace には
//! 4 API × enter/leave ＝ 8 イベントが残る（capture-e2e --verify-apps が確認）。
//! Windows 以外では何もせず終了する（CI の Linux ジョブでもビルドだけは通る）。

#[cfg(windows)]
mod win {
    use shirusu_e2e::verify_win::{self, wide};
    use shirusu_e2e::VerifyOut;
    use std::ffi::c_void;

    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassExW(wc: *const WndClassExW) -> u16;
        fn CreateWindowExW(
            exstyle: u32,
            class: *const u16,
            title: *const u16,
            style: u32,
            x: i32,
            y: i32,
            w: i32,
            h: i32,
            parent: *mut c_void,
            menu: *mut c_void,
            inst: *mut c_void,
            param: *mut c_void,
        ) -> *mut c_void;
        fn DefWindowProcW(hwnd: *mut c_void, msg: u32, w: usize, l: isize) -> isize;
        fn PostMessageW(hwnd: *mut c_void, msg: u32, w: usize, l: isize) -> i32;
        fn PostQuitMessage(code: i32);
        fn GetMessageW(msg: *mut Msg, hwnd: *mut c_void, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    #[link(name = "gdi32")]
    extern "system" {
        fn CreateCompatibleDC(hdc: *mut c_void) -> *mut c_void;
        fn CreateBitmap(w: i32, h: i32, planes: u32, bpp: u32, bits: *const c_void) -> *mut c_void;
        fn SelectObject(hdc: *mut c_void, obj: *mut c_void) -> *mut c_void;
        fn BitBlt(
            dst: *mut c_void,
            x: i32,
            y: i32,
            w: i32,
            h: i32,
            src: *mut c_void,
            sx: i32,
            sy: i32,
            rop: u32,
        ) -> i32;
        fn DeleteObject(obj: *mut c_void) -> i32;
        fn DeleteDC(hdc: *mut c_void) -> i32;
        fn CreateDIBSection(
            hdc: *mut c_void,
            bmi: *const BitmapInfo,
            usage: u32,
            bits: *mut *mut c_void,
            section: *mut c_void,
            offset: u32,
        ) -> *mut c_void;
    }

    const WM_CLOSE: u32 = 0x0010;
    const WM_DESTROY: u32 = 0x0002;
    const HWND_MESSAGE: *mut c_void = -3isize as *mut c_void;
    const SRCCOPY: u32 = 0x00CC_0020;
    const CONTENT: &[u8] = b"shirusu-verify-gui";

    #[repr(C)]
    struct WndClassExW {
        cb_size: u32,
        style: u32,
        wnd_proc: Option<extern "system" fn(*mut c_void, u32, usize, isize) -> isize>,
        cls_extra: i32,
        wnd_extra: i32,
        instance: *mut c_void,
        icon: *mut c_void,
        cursor: *mut c_void,
        background: *mut c_void,
        menu_name: *const u16,
        class_name: *const u16,
        small_icon: *mut c_void,
    }

    #[repr(C)]
    struct Msg {
        hwnd: *mut c_void,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        pt_x: i32,
        pt_y: i32,
    }

    #[repr(C)]
    struct BitmapInfoHeader {
        bi_size: u32,
        bi_width: i32,
        bi_height: i32,
        bi_planes: u16,
        bi_bit_count: u16,
        bi_compression: u32,
        bi_size_image: u32,
        bi_x_pels_per_meter: i32,
        bi_y_pels_per_meter: i32,
        bi_clr_used: u32,
        bi_clr_important: u32,
    }

    #[repr(C)]
    struct BitmapInfo {
        bmi_header: BitmapInfoHeader,
        bmi_colors: [u32; 1],
    }

    /// WM_DESTROY で PostQuitMessage し、それ以外は既定処理へ回す。
    extern "system" fn wnd_proc(hwnd: *mut c_void, msg: u32, w: usize, l: isize) -> isize {
        if msg == WM_DESTROY {
            // SAFETY: PostQuitMessage は引数を取らない。
            unsafe {
                PostQuitMessage(0);
            }
            return 0;
        }
        // SAFETY: hwnd/msg/w/l は GetMessageW 経由の有効な値。
        unsafe { DefWindowProcW(hwnd, msg, w, l) }
    }

    /// クラス登録→メッセージ専用ウィンドウ作成→WM_CLOSE を送って
    /// メッセージループを回し、WM_QUIT で抜けることを見る。
    fn window_step() -> Result<String, String> {
        let class_w = wide("ShirusuVerifyGui");
        let title_w = wide("shirusu-verify-gui");
        // SAFETY: wc の各ポインタは生存期間内のローカルを指す。
        unsafe {
            let inst = GetModuleHandleW(std::ptr::null());
            let wc = WndClassExW {
                cb_size: std::mem::size_of::<WndClassExW>() as u32,
                style: 0,
                wnd_proc: Some(wnd_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance: inst,
                icon: std::ptr::null_mut(),
                cursor: std::ptr::null_mut(),
                background: std::ptr::null_mut(),
                menu_name: std::ptr::null(),
                class_name: class_w.as_ptr(),
                small_icon: std::ptr::null_mut(),
            };
            if RegisterClassExW(&wc) == 0 {
                return Err(format!("register class error={}", GetLastError()));
            }
            let hwnd = CreateWindowExW(
                0,
                class_w.as_ptr(),
                title_w.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                inst,
                std::ptr::null_mut(),
            );
            if hwnd.is_null() {
                return Err(format!("create window error={}", GetLastError()));
            }
            if PostMessageW(hwnd, WM_CLOSE, 0, 0) == 0 {
                return Err(format!("post close error={}", GetLastError()));
            }
            // WM_CLOSE → DefWindowProc → DestroyWindow → WM_DESTROY →
            // PostQuitMessage → GetMessageW が 0 を返す。
            let mut msg: Msg = std::mem::zeroed();
            let mut pumped = 0u32;
            loop {
                let r = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                if r == 0 {
                    break; // WM_QUIT
                }
                if r == -1 {
                    return Err(format!("get message error={}", GetLastError()));
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                pumped += 1;
                if pumped > 100 {
                    return Err("message loop did not quit".into());
                }
            }
            if pumped == 0 {
                return Err("no messages pumped".into());
            }
        }
        Ok("loop ok".to_string())
    }

    /// メモリ DC へビットマップを選び、自分自身へ BitBlt する。
    fn gdi_step() -> Result<String, String> {
        // SAFETY: dc/bmp は直前の作成の戻りで、解放前に使う。
        unsafe {
            let dc = CreateCompatibleDC(std::ptr::null_mut());
            if dc.is_null() {
                return Err(format!("create dc error={}", GetLastError()));
            }
            let bmp = CreateBitmap(64, 64, 1, 32, std::ptr::null());
            if bmp.is_null() {
                let e = GetLastError();
                DeleteDC(dc);
                return Err(format!("create bitmap error={e}"));
            }
            let prev = SelectObject(dc, bmp);
            if prev.is_null() {
                let e = GetLastError();
                DeleteObject(bmp);
                DeleteDC(dc);
                return Err(format!("select object error={e}"));
            }
            if BitBlt(dc, 0, 0, 64, 64, dc, 0, 0, SRCCOPY) == 0 {
                let e = GetLastError();
                SelectObject(dc, prev);
                DeleteObject(bmp);
                DeleteDC(dc);
                return Err(format!("bitblt error={e}"));
            }
            SelectObject(dc, prev);
            DeleteObject(bmp);
            DeleteDC(dc);
        }
        Ok("blit ok".to_string())
    }

    /// CreateDIBSection で 32bpp の DIB を作り、1 ピクセル目へ書いて読み戻す。
    fn dib_step() -> Result<String, String> {
        let info = BitmapInfo {
            bmi_header: BitmapInfoHeader {
                bi_size: std::mem::size_of::<BitmapInfoHeader>() as u32,
                bi_width: 64,
                bi_height: -64, // top-down
                bi_planes: 1,
                bi_bit_count: 32,
                bi_compression: 0, // BI_RGB
                bi_size_image: 0,
                bi_x_pels_per_meter: 0,
                bi_y_pels_per_meter: 0,
                bi_clr_used: 0,
                bi_clr_important: 0,
            },
            bmi_colors: [0],
        };
        let mut bits: *mut c_void = std::ptr::null_mut();
        // SAFETY: info/bits は生存期間内のローカルを指す。
        unsafe {
            let bmp = CreateDIBSection(
                std::ptr::null_mut(),
                &info,
                0, // DIB_RGB_COLORS
                &mut bits,
                std::ptr::null_mut(),
                0,
            );
            if bmp.is_null() || bits.is_null() {
                return Err(format!("create dib error={}", GetLastError()));
            }
            *(bits as *mut u32) = 0xFF11_2233;
            let read = *(bits as *const u32);
            DeleteObject(bmp);
            if read != 0xFF11_2233 {
                return Err(format!("dib pixel mismatch: {read:#x}"));
            }
        }
        Ok("pixel ok".to_string())
    }

    pub fn run(verify_out: Option<&str>) -> i32 {
        let pid = std::process::id();
        let mut v = VerifyOut::new("gui");
        let path = verify_win::temp_path("gui", pid);
        v.step("file", verify_win::write_and_read_back(&path, CONTENT));
        let _ = std::fs::remove_file(&path);
        v.step("window", window_step());
        v.step("gdi", gdi_step());
        v.step("dib", dib_step());
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
    println!("SKIP shirusu-verify-gui (windows only)");
}
