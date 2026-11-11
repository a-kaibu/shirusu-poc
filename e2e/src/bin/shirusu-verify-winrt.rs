//! L17 検証用アプリ (4): WinRT を使うアプリ。
//!
//! overview 初期マイルストーン節の「WinRT を使うアプリ」。RoInitialize で
//! MTA を初期化し、Windows.Data.Json.JsonObject の RoActivateInstance、
//! 同クラスの RoGetActivationFactory＋IActivationFactory::ActivateInstance、
//! Windows.Foundation.Uri の RoGetActivationFactory＋
//! IUriRuntimeClassFactory::CreateUri＋IUriRuntimeClass::get_AbsoluteUri
//! を行う。各ステップは `VERIFY winrt <step> ok` 行を出す（`--verify-out <path>`
//! 指定時はファイルにも書く）。
//! WinRT の API は現行フック表に無いが、L14 のアクティベーション関数
//! （Inline Hook）と vtable メソッド（COM と同じ複製方式）で記録される。
//! Windows 以外では何もせず終了する（CI の Linux ジョブでもビルドだけは通る）。

#[cfg(windows)]
mod win {
    use shirusu_e2e::verify_win::{self};
    use shirusu_e2e::VerifyOut;
    use std::ffi::c_void;

    #[link(name = "combase")]
    extern "system" {
        fn RoInitialize(init_type: u32) -> i32;
        fn RoUninitialize();
        fn RoActivateInstance(activatable_class_id: *mut c_void, instance: *mut *mut c_void)
            -> i32;
        fn RoGetActivationFactory(
            activatable_class_id: *mut c_void,
            iid: *const Guid,
            factory: *mut *mut c_void,
        ) -> i32;
        fn WindowsCreateString(source: *const u16, length: u32, string: *mut *mut c_void) -> i32;
        fn WindowsDeleteString(string: *mut c_void) -> i32;
        fn WindowsGetStringRawBuffer(string: *mut c_void, length: *mut u32) -> *const u16;
    }

    const RO_INIT_MULTITHREADED: u32 = 1;
    const CONTENT: &[u8] = b"shirusu-verify-winrt";
    const URI_TEXT: &str = "https://example.com/path?q=1";

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const IID_IACTIVATION_FACTORY: Guid = Guid {
        data1: 0x0000_0035,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    const IID_IURI_RUNTIME_CLASS_FACTORY: Guid = Guid {
        data1: 0x44A9_796F,
        data2: 0x723E,
        data3: 0x4FDF,
        data4: [0xA2, 0x18, 0x03, 0x3E, 0x75, 0xB0, 0xC0, 0x84],
    };

    /// `IInspectable` の vtable（0 QueryInterface, 1 AddRef, 2 Release,
    /// 3 GetIids, 4 GetRuntimeClassName, 5 GetTrustLevel）。
    #[repr(C)]
    struct IInspectableVtbl {
        query_interface: extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
        add_ref: extern "system" fn(*mut c_void) -> u32,
        release: extern "system" fn(*mut c_void) -> u32,
        get_iids: extern "system" fn(*mut c_void, *mut u32, *mut *mut Guid) -> i32,
        get_runtime_class_name: extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
        get_trust_level: extern "system" fn(*mut c_void, *mut i32) -> i32,
    }

    #[repr(C)]
    struct IInspectable {
        vtbl: *const IInspectableVtbl,
    }

    /// `IActivationFactory` の vtable（`IInspectable` + 6 ActivateInstance）。
    #[repr(C)]
    struct IActivationFactoryVtbl {
        base: IInspectableVtbl,
        activate_instance: extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
    }

    #[repr(C)]
    struct IActivationFactory {
        vtbl: *const IActivationFactoryVtbl,
    }

    /// `IUriRuntimeClassFactory` の vtable（`IInspectable` +
    /// 6 CreateUri, 7 CreateWithRelativeUri）。
    #[repr(C)]
    struct IUriRuntimeClassFactoryVtbl {
        base: IInspectableVtbl,
        create_uri: extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32,
        create_with_relative_uri:
            extern "system" fn(*mut c_void, *mut c_void, *mut c_void, *mut *mut c_void) -> i32,
    }

    #[repr(C)]
    struct IUriRuntimeClassFactory {
        vtbl: *const IUriRuntimeClassFactoryVtbl,
    }

    /// `IUriRuntimeClass` の vtable（`IInspectable` + 6 AbsoluteUri。
    /// 7 番目以降は使わないため並べない）。
    #[repr(C)]
    struct IUriRuntimeClassVtbl {
        base: IInspectableVtbl,
        absolute_uri: extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
    }

    #[repr(C)]
    struct IUriRuntimeClass {
        vtbl: *const IUriRuntimeClassVtbl,
    }

    /// 文字列から HSTRING を作る。呼び出し側が `WindowsDeleteString` で解放する。
    fn create_hstring(s: &str) -> Result<*mut c_void, String> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut h: *mut c_void = std::ptr::null_mut();
        // SAFETY: units は生存期間内のローカル、h は out 引数。
        let hr = unsafe { WindowsCreateString(units.as_ptr(), units.len() as u32, &mut h) };
        if hr != 0 || h.is_null() {
            return Err(format!("WindowsCreateString({s}) hr={hr:#x}"));
        }
        Ok(h)
    }

    /// HSTRING の中身を読む（所有権は移らない）。
    fn read_hstring(h: *mut c_void) -> String {
        if h.is_null() {
            return String::new();
        }
        let mut len: u32 = 0;
        // SAFETY: h は有効な HSTRING。
        let ptr = unsafe { WindowsGetStringRawBuffer(h, &mut len) };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: ptr は長さ len の UTF-16 バッファ。
        let units = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        String::from_utf16_lossy(units)
    }

    /// IInspectable の GetRuntimeClassName を読む。返す HSTRING はこの
    /// 関数内で解放する。
    fn runtime_class_name(obj: *mut c_void) -> Result<String, String> {
        if obj.is_null() {
            return Err("null object".into());
        }
        // SAFETY: obj は有効な IInspectable。
        unsafe {
            let inspectable = obj as *const IInspectable;
            let vtbl = (*inspectable).vtbl;
            let mut h: *mut c_void = std::ptr::null_mut();
            let hr = ((*vtbl).get_runtime_class_name)(obj, &mut h);
            if hr != 0 || h.is_null() {
                return Err(format!("GetRuntimeClassName hr={hr:#x}"));
            }
            let name = read_hstring(h);
            WindowsDeleteString(h);
            Ok(name)
        }
    }

    /// IUnknown::Release を呼ぶ（vtable 先頭 3 件は全インターフェイス共通）。
    fn release(obj: *mut c_void) {
        if obj.is_null() {
            return;
        }
        // SAFETY: obj は有効な IUnknown 派生インターフェイス。
        unsafe {
            let inspectable = obj as *const IInspectable;
            let vtbl = (*inspectable).vtbl;
            ((*vtbl).release)(obj);
        }
    }

    fn winrt_init_step() -> Result<String, String> {
        // SAFETY: RO_INIT_MULTITHREADED で初期化する。S_OK(0)・S_FALSE(1)
        // とも成功扱い。
        let hr = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        if hr != 0 && hr != 1 {
            return Err(format!("RoInitialize hr={hr:#x}"));
        }
        Ok("init ok".to_string())
    }

    /// JsonObject を RoActivateInstance で作り、ランタイムクラス名を確認する。
    fn activate_json_step() -> Result<String, String> {
        let class = create_hstring("Windows.Data.Json.JsonObject")?;
        let mut obj: *mut c_void = std::ptr::null_mut();
        // SAFETY: class は有効な HSTRING、obj は out 引数。
        let hr = unsafe { RoActivateInstance(class, &mut obj) };
        // SAFETY: class はこの後不要。
        unsafe { WindowsDeleteString(class) };
        if hr != 0 || obj.is_null() {
            return Err(format!("RoActivateInstance(JsonObject) hr={hr:#x}"));
        }
        let name = runtime_class_name(obj);
        release(obj);
        let name = name?;
        if name != "Windows.Data.Json.JsonObject" {
            return Err(format!("runtime class mismatch: got {name}"));
        }
        Ok("activate ok".to_string())
    }

    /// JsonObject のファクトリを取り、IActivationFactory::ActivateInstance
    /// で作ったオブジェクトのランタイムクラス名を確認する。
    fn activate_factory_step() -> Result<String, String> {
        let class = create_hstring("Windows.Data.Json.JsonObject")?;
        let mut factory: *mut c_void = std::ptr::null_mut();
        // SAFETY: class は有効な HSTRING、factory は out 引数。
        let hr = unsafe { RoGetActivationFactory(class, &IID_IACTIVATION_FACTORY, &mut factory) };
        // SAFETY: class はこの後不要。
        unsafe { WindowsDeleteString(class) };
        if hr != 0 || factory.is_null() {
            return Err(format!("RoGetActivationFactory(JsonObject) hr={hr:#x}"));
        }
        let mut obj: *mut c_void = std::ptr::null_mut();
        // SAFETY: factory は有効な IActivationFactory。
        let hr = unsafe {
            let f = factory as *const IActivationFactory;
            let vtbl = (*f).vtbl;
            ((*vtbl).activate_instance)(factory, &mut obj)
        };
        if hr != 0 || obj.is_null() {
            release(factory);
            return Err(format!("ActivateInstance(JsonObject) hr={hr:#x}"));
        }
        let name = runtime_class_name(obj);
        release(obj);
        release(factory);
        let name = name?;
        if name != "Windows.Data.Json.JsonObject" {
            return Err(format!("runtime class mismatch: got {name}"));
        }
        Ok("factory ok".to_string())
    }

    /// Uri のファクトリから IUriRuntimeClassFactory::CreateUri で Uri を作る。
    /// 作った Uri は呼び出し元が absolute-uri ステップと解放で使うため
    /// out 引数で返す。
    fn create_uri_step(uri_out: &mut *mut c_void) -> Result<String, String> {
        let class = create_hstring("Windows.Foundation.Uri")?;
        let mut factory: *mut c_void = std::ptr::null_mut();
        // SAFETY: class は有効な HSTRING、factory は out 引数。
        let hr = unsafe { RoGetActivationFactory(class, &IID_IACTIVATION_FACTORY, &mut factory) };
        // SAFETY: class はこの後不要。
        unsafe { WindowsDeleteString(class) };
        if hr != 0 || factory.is_null() {
            return Err(format!("RoGetActivationFactory(Uri) hr={hr:#x}"));
        }
        let mut factory_iface: *mut c_void = std::ptr::null_mut();
        // SAFETY: factory は有効な IActivationFactory。
        let hr = unsafe {
            let f = factory as *const IActivationFactory;
            let vtbl = (*f).vtbl;
            ((*vtbl).base.query_interface)(
                factory,
                &IID_IURI_RUNTIME_CLASS_FACTORY,
                &mut factory_iface,
            )
        };
        if hr != 0 || factory_iface.is_null() {
            release(factory);
            return Err(format!(
                "QueryInterface(IUriRuntimeClassFactory) hr={hr:#x}"
            ));
        }
        let uri_text = create_hstring(URI_TEXT)?;
        let mut uri: *mut c_void = std::ptr::null_mut();
        // SAFETY: factory_iface は有効な IUriRuntimeClassFactory。
        let hr = unsafe {
            let f = factory_iface as *const IUriRuntimeClassFactory;
            let vtbl = (*f).vtbl;
            ((*vtbl).create_uri)(factory_iface, uri_text, &mut uri)
        };
        // SAFETY: uri_text はこの後不要。
        unsafe { WindowsDeleteString(uri_text) };
        release(factory_iface);
        release(factory);
        if hr != 0 || uri.is_null() {
            return Err(format!("CreateUri hr={hr:#x}"));
        }
        *uri_out = uri;
        Ok("create ok".to_string())
    }

    /// IUriRuntimeClass::get_AbsoluteUri が入力と同じ URI を返すことを見る。
    fn absolute_uri_step(uri: *mut c_void) -> Result<String, String> {
        if uri.is_null() {
            return Err("no uri (previous step failed)".into());
        }
        // SAFETY: uri は create-uri ステップで取得した有効なポインタ。
        let got = unsafe {
            let u = uri as *const IUriRuntimeClass;
            let vtbl = (*u).vtbl;
            let mut h: *mut c_void = std::ptr::null_mut();
            let hr = ((*vtbl).absolute_uri)(uri, &mut h);
            if hr != 0 || h.is_null() {
                release(uri);
                return Err(format!("AbsoluteUri hr={hr:#x}"));
            }
            let got = read_hstring(h);
            WindowsDeleteString(h);
            got
        };
        release(uri);
        if got != URI_TEXT {
            return Err(format!("absolute uri mismatch: got {got}"));
        }
        Ok("uri ok".to_string())
    }

    pub fn run(verify_out: Option<&str>) -> i32 {
        let pid = std::process::id();
        let mut v = VerifyOut::new("winrt");
        let path = verify_win::temp_path("winrt", pid);
        v.step("file", verify_win::write_and_read_back(&path, CONTENT));
        let _ = std::fs::remove_file(&path);
        // WinRT の初期化に失敗したら、後続のステップは実行せず終了する
        // （RoUninitialize は初期化成功時のみ呼ぶ）。
        match winrt_init_step() {
            Ok(msg) => {
                v.step("winrt-init", Ok(msg));
                v.step("activate-json", activate_json_step());
                v.step("activate-factory", activate_factory_step());
                let mut uri: *mut c_void = std::ptr::null_mut();
                v.step("create-uri", create_uri_step(&mut uri));
                v.step("absolute-uri", absolute_uri_step(uri));
                // SAFETY: RoInitialize が成功している。
                unsafe {
                    RoUninitialize();
                }
            }
            Err(e) => {
                v.step("winrt-init", Err(e));
                v.step("activate-json", Err("skipped (winrt-init failed)".into()));
                v.step(
                    "activate-factory",
                    Err("skipped (winrt-init failed)".into()),
                );
                v.step("create-uri", Err("skipped (winrt-init failed)".into()));
                v.step("absolute-uri", Err("skipped (winrt-init failed)".into()));
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
    println!("SKIP shirusu-verify-winrt (windows only)");
}
