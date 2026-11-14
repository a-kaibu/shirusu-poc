//! WinRT の定義と検出（L14・overview 観測レベル節・Trace 形式の API Schema 層）。
//!
//! WinRT API は COM を基盤とする：全ての WinRT インターフェイスは
//! `IInspectable`（`IUnknown` + GetIids / GetRuntimeClassName /
//! GetTrustLevel）から派生し、ランタイムクラスはアクティベーション関数
//! `RoActivateInstance` / `RoGetActivationFactory`（combase.dll）経由で
//! 取得する。返されたポインタと IID は `crate::com` の追跡表へ記録する。
//! 共有オブジェクトの vtable 差し替えは安全性未確認のため見送り、
//! Coverage に理由を残す。WinRT 固有の部分はこのファイルが持つ：
//!
//! - **定義**：既知の WinRT インターフェイス表（IID と vtable のメソッド表）
//!   と、ランタイムクラス名から既定インターフェイスを引く表。
//! - **検出**：アクティベーション関数の Inline Hook（engine.rs）と、
//!   HSTRING のクラス名の読み取り。アクティベーション呼び出しは COM
//!   メソッドイベントとは別の WinRT 専用 Schema で記録する
//!   （クラス名を文字列で載せるため）。
//!
//! 定義表の出所：WinRT の定義は Windows.winmd にあるが、これは Windows SDK
//! にしか同梱されず、NuGet パッケージとしては配布されていない
//! （2026-11-12 に確認：`Microsoft.Windows.SDK.WinRTMetadata` は NuGet に
//! 存在せず、Microsoft.Windows.CppWinRT の nupkg にも .winmd は含まれない）。
//! そのため L03 のような WinMD からの生成はできず、表は手書きの厳選表と
//! する。IID と vtable のメソッド順は `windows` クレート 0.61.3 / 0.62
//! （Windows.winmd からの生成物）の Vtbl 構造体と照合して確認した
//! （`IUriRuntimeClass_Vtbl` のフィールド順＝vtable 順）。
//! Windows.winmd を入手できる環境では、この表を WinMD からの生成へ
//! 置き換えることが将来の拡張（生成器は shirusu-metadata-gen）。
//!
//! 制限：
//! - `RoActivateInstance` の返却 IID は `IInspectable`、
//!   `RoGetActivationFactory` は呼び出し側が要求した IID として追跡する。
//!   クラス名から返却インターフェイスを推測しない。
//!   クラス名自体はアクティベーションイベントに残る。
//! - メソッドが返すインターフェイスの追跡は、表に載せた返却メソッド
//!   （`winrt_method_return`）に限る。それ以外のメソッドが返す
//!   インターフェイスは、アプリが `QueryInterface` で取り直さない限り
//!   追跡対象にならない。
//! - アタッチ前に既に存在していた WinRT オブジェクトは発見できない
//!   （L02 と同じ）。

use crate::com::{ComInterfaceDef, ComMethodDef, Guid};
/// イベント識別子と Schema は API Catalog の共有定義を使う。
pub use shirusu_api_catalog::winrt::*;
use shirusu_trace::compact::encode_values;
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::CompactError;

// ---- 既知の WinRT インターフェイス ----

/// `IInspectable`。全ての WinRT インターフェイスの基底
/// （`IUnknown` + 3 メソッド）。
pub const IID_IINSPECTABLE: Guid = Guid::new(
    0xAF86_E2E0,
    0xB12D,
    0x4C6A,
    [0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90],
);
/// `IActivationFactory`。`RoGetActivationFactory` が返すファクトリ。
pub const IID_IACTIVATION_FACTORY: Guid = Guid::new(
    0x0000_0035,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);
/// `Windows.Foundation.IUriRuntimeClass`（`Windows.Foundation.Uri` の
/// 既定インターフェイス）。
pub const IID_IURI_RUNTIME_CLASS: Guid = Guid::new(
    0x9E36_5E57,
    0x48B2,
    0x4160,
    [0x95, 0x6F, 0xC7, 0x38, 0x51, 0x20, 0xBB, 0xFC],
);
/// `Windows.Foundation.IUriRuntimeClassFactory`。
pub const IID_IURI_RUNTIME_CLASS_FACTORY: Guid = Guid::new(
    0x44A9_796F,
    0x723E,
    0x4FDF,
    [0xA2, 0x18, 0x03, 0x3E, 0x75, 0xB0, 0xC0, 0x84],
);
/// `Windows.Data.Json.IJsonObject`（`Windows.Data.Json.JsonObject` の
/// 既定インターフェイス）。
pub const IID_IJSON_OBJECT: Guid = Guid::new(
    0x064E_24DD,
    0x29C2,
    0x4F83,
    [0x9A, 0xC1, 0x9E, 0xE1, 0x15, 0x78, 0xBE, 0xB3],
);
/// `Windows.Foundation.IStringable`。
pub const IID_ISTRINGABLE: Guid = Guid::new(
    0x9636_9F54,
    0x8EB6,
    0x48F0,
    [0xAB, 0xCE, 0xC1, 0xB2, 0x11, 0xE6, 0x27, 0xC3],
);

/// `IInspectable` のメソッド表（0〜2 は `IUnknown`、3〜5 が固有）。
const IINSPECTABLE_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
];

pub const IINSPECTABLE_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IINSPECTABLE,
    name: "IInspectable",
    methods: IINSPECTABLE_METHODS,
};

/// `IActivationFactory` のメソッド表。`ActivateInstance` は 6 番目。
const IACTIVATION_FACTORY_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "ActivateInstance",
        arity: 1,
    },
];

pub const IACTIVATION_FACTORY_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IACTIVATION_FACTORY,
    name: "IActivationFactory",
    methods: IACTIVATION_FACTORY_METHODS,
};

/// `IUriRuntimeClass` のメソッド表。メソッド順は `windows` クレートの
/// `IUriRuntimeClass_Vtbl` のフィールド順（＝vtable 順）。
/// プロパティの getter が名前順に並び、最後に `Equals` / `CombineUri`。
const IURI_RUNTIME_CLASS_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "AbsoluteUri",
        arity: 1,
    },
    ComMethodDef {
        index: 7,
        name: "DisplayUri",
        arity: 1,
    },
    ComMethodDef {
        index: 8,
        name: "Domain",
        arity: 1,
    },
    ComMethodDef {
        index: 9,
        name: "Extension",
        arity: 1,
    },
    ComMethodDef {
        index: 10,
        name: "Fragment",
        arity: 1,
    },
    ComMethodDef {
        index: 11,
        name: "Host",
        arity: 1,
    },
    ComMethodDef {
        index: 12,
        name: "Password",
        arity: 1,
    },
    ComMethodDef {
        index: 13,
        name: "Path",
        arity: 1,
    },
    ComMethodDef {
        index: 14,
        name: "Query",
        arity: 1,
    },
    ComMethodDef {
        index: 15,
        name: "QueryParsed",
        arity: 1,
    },
    ComMethodDef {
        index: 16,
        name: "RawUri",
        arity: 1,
    },
    ComMethodDef {
        index: 17,
        name: "SchemeName",
        arity: 1,
    },
    ComMethodDef {
        index: 18,
        name: "UserName",
        arity: 1,
    },
    ComMethodDef {
        index: 19,
        name: "Port",
        arity: 1,
    },
    ComMethodDef {
        index: 20,
        name: "Suspicious",
        arity: 1,
    },
    ComMethodDef {
        index: 21,
        name: "Equals",
        arity: 2,
    },
    ComMethodDef {
        index: 22,
        name: "CombineUri",
        arity: 2,
    },
];

pub const IURI_RUNTIME_CLASS_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IURI_RUNTIME_CLASS,
    name: "IUriRuntimeClass",
    methods: IURI_RUNTIME_CLASS_METHODS,
};

/// `IUriRuntimeClassFactory` のメソッド表。
const IURI_RUNTIME_CLASS_FACTORY_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "CreateUri",
        arity: 2,
    },
    ComMethodDef {
        index: 7,
        name: "CreateWithRelativeUri",
        arity: 3,
    },
];

pub const IURI_RUNTIME_CLASS_FACTORY_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IURI_RUNTIME_CLASS_FACTORY,
    name: "IUriRuntimeClassFactory",
    methods: IURI_RUNTIME_CLASS_FACTORY_METHODS,
};

/// `IJsonObject` のメソッド表。メソッド順は `windows` クレートの
/// `IJsonObject_Vtbl` のフィールド順（＝vtable 順）。
const IJSON_OBJECT_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "GetNamedValue",
        arity: 2,
    },
    ComMethodDef {
        index: 7,
        name: "SetNamedValue",
        arity: 2,
    },
    ComMethodDef {
        index: 8,
        name: "GetNamedObject",
        arity: 2,
    },
    ComMethodDef {
        index: 9,
        name: "GetNamedArray",
        arity: 2,
    },
    ComMethodDef {
        index: 10,
        name: "GetNamedString",
        arity: 2,
    },
    ComMethodDef {
        index: 11,
        name: "GetNamedNumber",
        arity: 2,
    },
    ComMethodDef {
        index: 12,
        name: "GetNamedBoolean",
        arity: 2,
    },
];

pub const IJSON_OBJECT_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IJSON_OBJECT,
    name: "IJsonObject",
    methods: IJSON_OBJECT_METHODS,
};

/// `IStringable` のメソッド表。
const ISTRINGABLE_METHODS: &[ComMethodDef] = &[
    ComMethodDef {
        index: 0,
        name: "QueryInterface",
        arity: 2,
    },
    ComMethodDef {
        index: 1,
        name: "AddRef",
        arity: 0,
    },
    ComMethodDef {
        index: 2,
        name: "Release",
        arity: 0,
    },
    ComMethodDef {
        index: 3,
        name: "GetIids",
        arity: 2,
    },
    ComMethodDef {
        index: 4,
        name: "GetRuntimeClassName",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "GetTrustLevel",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "ToString",
        arity: 1,
    },
];

pub const ISTRINGABLE_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_ISTRINGABLE,
    name: "IStringable",
    methods: ISTRINGABLE_METHODS,
};

/// 既知の WinRT インターフェイス表。`crate::com::interface_by_iid` は
/// ここも引く（`com.rs` の既知 COM インターフェイスに無ければ）。
pub const WINRT_INTERFACES: &[ComInterfaceDef] = &[
    IINSPECTABLE_DEF,
    IACTIVATION_FACTORY_DEF,
    IURI_RUNTIME_CLASS_DEF,
    IURI_RUNTIME_CLASS_FACTORY_DEF,
    IJSON_OBJECT_DEF,
    ISTRINGABLE_DEF,
];

pub fn winrt_interface_by_iid(iid: &Guid) -> Option<&'static ComInterfaceDef> {
    WINRT_INTERFACES.iter().find(|d| d.iid == *iid)
}

// ---- ランタイムクラス → 既定インターフェイス ----

/// ランタイムクラス 1 件の定義。既定インターフェイスは、そのクラスの
/// `RoActivateInstance` が返すインターフェイス。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinRtClassDef {
    pub class_name: &'static str,
    pub default_interface: &'static ComInterfaceDef,
}

/// 既知のランタイムクラス表（L17 の検証用 WinRT アプリが使うもの）。
/// クラス名は WinRT の規則で大文字小文字を区別するため、照合も厳密一致。
pub const WINRT_CLASSES: &[WinRtClassDef] = &[
    WinRtClassDef {
        class_name: "Windows.Foundation.Uri",
        default_interface: &IURI_RUNTIME_CLASS_DEF,
    },
    WinRtClassDef {
        class_name: "Windows.Data.Json.JsonObject",
        default_interface: &IJSON_OBJECT_DEF,
    },
];

pub fn default_interface_for_class(class_name: &str) -> Option<&'static ComInterfaceDef> {
    WINRT_CLASSES
        .iter()
        .find(|c| c.class_name == class_name)
        .map(|c| c.default_interface)
}

// ---- メソッド戻りのインターフェイス ----

/// メソッド戻りでインターフェイスを返す WinRT メソッド。
/// (インターフェイス名, vtable インデックス, out 引数の位置,
/// 返されるインターフェイスの IID)。
/// `com_method_post_call` が成功時に out 引数を読んで追跡対象に加える。
/// out 引数は `this` を除く引数列での位置。
const WINRT_INTERFACE_RETURNS: &[(&str, u32, usize, Guid)] = &[
    // IActivationFactory::ActivateInstance(out) -> IInspectable。
    ("IActivationFactory", 6, 0, IID_IINSPECTABLE),
    // IUriRuntimeClassFactory::CreateUri(uri, out) -> IUriRuntimeClass。
    ("IUriRuntimeClassFactory", 6, 1, IID_IURI_RUNTIME_CLASS),
    // IUriRuntimeClassFactory::CreateWithRelativeUri(base, rel, out)。
    ("IUriRuntimeClassFactory", 7, 2, IID_IURI_RUNTIME_CLASS),
    // IUriRuntimeClass::CombineUri(relative, out) -> IUriRuntimeClass。
    ("IUriRuntimeClass", 22, 1, IID_IURI_RUNTIME_CLASS),
];

/// (インターフェイス名, メソッド) がインターフェイスを返す場合、
/// (out 引数の位置, 返される IID) を返す。
pub fn winrt_method_return(interface_name: &str, method_index: u32) -> Option<(usize, Guid)> {
    WINRT_INTERFACE_RETURNS
        .iter()
        .find(|(name, index, _, _)| *name == interface_name && *index == method_index)
        .map(|(_, _, out_arg, iid)| (*out_arg, *iid))
}

// ---- アクティベーション関数（検出の起点） ----

/// WinRT アクティベーション関数の Detour のスロット番号。
pub const WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE: usize = 0;
pub const WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY: usize = 1;
/// WinRT アクティベーション関数の数。
pub const WINRT_ACTIVATION_COUNT: usize = 2;
/// WinRT アクティベーション関数の Inline Hook を報告するときの ID 基準値
/// （`InlineHook.api_id` 用。COM Factory の予約値とは別の予約値）。
pub const WINRT_ACTIVATION_REPORT_ID_BASE: u32 = 0xC001_0000;

/// WinRT アクティベーション関数 1 件の定義。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinRtActivationDef {
    pub module: &'static str,
    pub function: &'static str,
}

pub const WINRT_ACTIVATIONS: &[WinRtActivationDef] = &[
    WinRtActivationDef {
        module: "combase.dll",
        function: "RoActivateInstance",
    },
    WinRtActivationDef {
        module: "combase.dll",
        function: "RoGetActivationFactory",
    },
];

pub fn activation_by_name(
    module: &str,
    function: &str,
) -> Option<(usize, &'static WinRtActivationDef)> {
    WINRT_ACTIVATIONS
        .iter()
        .enumerate()
        .find(|(_, d)| d.module.eq_ignore_ascii_case(module) && d.function == function)
}

/// enter 値列を作る。`args` は引数の生スロット値列。
pub fn winrt_activation_enter_values(
    object: u64,
    class_name: &str,
    method_name: &str,
    args: &[u8],
) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::U64(object)),
        CapturedValue::captured(TypedValue::Str(class_name.to_string())),
        CapturedValue::captured(TypedValue::Str(method_name.to_string())),
        CapturedValue::captured(TypedValue::Bytes(args.to_vec())),
    ]
}

/// leave 値列を作る。
pub fn winrt_activation_leave_values(hresult: i32, returned_object: u64) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::I32(hresult)),
        CapturedValue::captured(TypedValue::U64(returned_object)),
        CapturedValue::captured(TypedValue::U32(0)),
    ]
}

pub fn encode_winrt_activation_enter(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, winrt_activation_enter_schema),
        values,
    )
}

pub fn encode_winrt_activation_leave(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, winrt_activation_leave_schema),
        values,
    )
}

// ---- HSTRING の読み取り ----

/// HSTRING の中身（UTF-16 単位列）を String へ変換する。
/// 不正なサロゲートは U+FFFD に置き換える（`String::from_utf16_lossy`）。
pub fn hstring_units_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// HSTRING ポインタから文字列を読む（Windows のみ）。
///
/// `WindowsGetStringRawBuffer`（combase.dll）を遅延解決して呼ぶ。
/// HSTRING は Windows ランタイムが管理する参照カウント付き文字列で、
/// この関数は中身を読むだけの純粋関数であり、Detour の中から呼んでも
/// アプリの状態を変えない。解決・読み取りに失敗したら None を返す
/// （呼び出し自体はクラス名なしで記録を続ける）。
#[cfg(windows)]
pub fn read_hstring_string(hstring: usize) -> Option<String> {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    if hstring == 0 {
        return None;
    }
    type WindowsGetStringRawBufferFn = unsafe extern "system" fn(usize, *mut u32) -> *const u16;
    static FN_PTR: OnceLock<usize> = OnceLock::new();
    let f = *FN_PTR.get_or_init(|| {
        // SAFETY: "combase.dll" はヌル終端済みのモジュール名。
        // 解決できなければ 0 を入れて以後は読まない。
        let wide: Vec<u16> = "combase.dll".encode_utf16().chain([0]).collect();
        let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if handle.is_null() {
            return 0;
        }
        let name = match std::ffi::CString::new("WindowsGetStringRawBuffer") {
            Ok(n) => n,
            Err(_) => return 0,
        };
        // SAFETY: handle はロード済みモジュール、name はヌル終端済み。
        let proc = unsafe { GetProcAddress(handle, name.as_ptr() as *const u8) };
        proc.map(|p| p as usize).unwrap_or(0)
    });
    if f == 0 {
        return None;
    }
    // SAFETY: f は WindowsGetStringRawBuffer の実アドレス。
    let func: WindowsGetStringRawBufferFn = unsafe { std::mem::transmute(f) };
    let mut len: u32 = 0;
    let ptr = unsafe { func(hstring, &mut len) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr は長さ len の UTF-16 バッファ。HSTRING の中身は
    // 呼び出し中は有効（所有者はアプリ側で保持している）。
    let units = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(hstring_units_to_string(units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::interface_by_iid;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::schema::schema_types;
    use shirusu_trace::schema::SchemaRegistry;

    #[test]
    fn winrt_iids_display_in_canonical_form() {
        assert_eq!(
            IID_IINSPECTABLE.to_string(),
            "{AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90}"
        );
        assert_eq!(
            IID_IACTIVATION_FACTORY.to_string(),
            "{00000035-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            IID_IURI_RUNTIME_CLASS.to_string(),
            "{9E365E57-48B2-4160-956F-C7385120BBFC}"
        );
        assert_eq!(
            IID_IURI_RUNTIME_CLASS_FACTORY.to_string(),
            "{44A9796F-723E-4FDF-A218-033E75B0C084}"
        );
        assert_eq!(
            IID_IJSON_OBJECT.to_string(),
            "{064E24DD-29C2-4F83-9AC1-9EE11578BEB3}"
        );
        assert_eq!(
            IID_ISTRINGABLE.to_string(),
            "{96369F54-8EB6-48F0-ABCE-C1B211E627C3}"
        );
    }

    #[test]
    fn winrt_interface_tables_are_complete() {
        // 全インターフェイスが 6 件（IUnknown 3 + IInspectable 3）から始まる。
        assert_eq!(IINSPECTABLE_DEF.methods.len(), 6);
        assert_eq!(IACTIVATION_FACTORY_DEF.methods.len(), 7);
        assert_eq!(IURI_RUNTIME_CLASS_DEF.methods.len(), 23);
        assert_eq!(IURI_RUNTIME_CLASS_FACTORY_DEF.methods.len(), 8);
        assert_eq!(IJSON_OBJECT_DEF.methods.len(), 13);
        assert_eq!(ISTRINGABLE_DEF.methods.len(), 7);
        for def in WINRT_INTERFACES {
            // インデックスは 0 から連番で、名前は重複しない。
            for (i, m) in def.methods.iter().enumerate() {
                assert_eq!(m.index as usize, i, "{} method {i}", def.name);
            }
            let mut names: Vec<&str> = def.methods.iter().map(|m| m.name).collect();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), def.methods.len(), "{}", def.name);
            // 先頭 6 件は全インターフェイス共通。
            assert_eq!(def.methods[0].name, "QueryInterface");
            assert_eq!(def.methods[1].name, "AddRef");
            assert_eq!(def.methods[2].name, "Release");
            assert_eq!(def.methods[3].name, "GetIids");
            assert_eq!(def.methods[4].name, "GetRuntimeClassName");
            assert_eq!(def.methods[5].name, "GetTrustLevel");
        }
        // 代表的なメソッド位置（windows クレートの Vtbl 順と照合済み）。
        assert_eq!(
            IURI_RUNTIME_CLASS_DEF.method(6).map(|m| (m.name, m.arity)),
            Some(("AbsoluteUri", 1))
        );
        assert_eq!(
            IURI_RUNTIME_CLASS_DEF.method(22).map(|m| (m.name, m.arity)),
            Some(("CombineUri", 2))
        );
        assert_eq!(
            IURI_RUNTIME_CLASS_FACTORY_DEF
                .method(6)
                .map(|m| (m.name, m.arity)),
            Some(("CreateUri", 2))
        );
        assert_eq!(
            IACTIVATION_FACTORY_DEF.method(6).map(|m| (m.name, m.arity)),
            Some(("ActivateInstance", 1))
        );
        assert_eq!(
            IJSON_OBJECT_DEF.method(6).map(|m| (m.name, m.arity)),
            Some(("GetNamedValue", 2))
        );
        // 未知の IID は None。com.rs の lookup からも引ける（fallback）。
        assert!(winrt_interface_by_iid(&Guid::new(
            0x1234_5678,
            0x0000,
            0x0000,
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
        ))
        .is_none());
        assert_eq!(
            interface_by_iid(&IID_IURI_RUNTIME_CLASS).map(|d| d.name),
            Some("IUriRuntimeClass")
        );
        assert_eq!(
            interface_by_iid(&IID_IINSPECTABLE).map(|d| d.name),
            Some("IInspectable")
        );
    }

    #[test]
    fn class_table_resolves_default_interfaces() {
        assert_eq!(
            default_interface_for_class("Windows.Foundation.Uri").map(|d| d.name),
            Some("IUriRuntimeClass")
        );
        assert_eq!(
            default_interface_for_class("Windows.Data.Json.JsonObject").map(|d| d.name),
            Some("IJsonObject")
        );
        // 未知のクラスは None（IInspectable として追跡する）。
        assert!(default_interface_for_class("Windows.Storage.StorageFile").is_none());
        // クラス名は大文字小文字を区別する。
        assert!(default_interface_for_class("windows.foundation.uri").is_none());
    }

    #[test]
    fn activation_table_lists_both_functions() {
        assert_eq!(WINRT_ACTIVATIONS.len(), WINRT_ACTIVATION_COUNT);
        assert_eq!(
            activation_by_name("combase.dll", "RoActivateInstance").map(|(i, _)| i),
            Some(WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE)
        );
        assert_eq!(
            activation_by_name("COMBASE.DLL", "RoGetActivationFactory").map(|(i, _)| i),
            Some(WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY)
        );
        assert!(activation_by_name("combase.dll", "WindowsCreateString").is_none());
        assert!(activation_by_name("ole32.dll", "RoActivateInstance").is_none());
    }

    #[test]
    fn winrt_method_return_table() {
        // IActivationFactory::ActivateInstance は out 引数 0 で IInspectable を返す。
        assert_eq!(
            winrt_method_return("IActivationFactory", 6),
            Some((0, IID_IINSPECTABLE))
        );
        // IUriRuntimeClassFactory::CreateUri は out 引数 1 で IUriRuntimeClass を返す。
        assert_eq!(
            winrt_method_return("IUriRuntimeClassFactory", 6),
            Some((1, IID_IURI_RUNTIME_CLASS))
        );
        assert_eq!(
            winrt_method_return("IUriRuntimeClassFactory", 7),
            Some((2, IID_IURI_RUNTIME_CLASS))
        );
        // IInspectable のメソッドはインターフェイスを返さない。
        assert!(winrt_method_return("IInspectable", 4).is_none());
        assert!(winrt_method_return("IUriRuntimeClass", 6).is_none());
        assert!(winrt_method_return("IUnknown", 0).is_none());
    }

    #[test]
    fn winrt_schemas_register_cleanly() {
        let mut reg = SchemaRegistry::new();
        for def in winrt_schemas() {
            reg.register(def).expect("winrt schemas must register");
        }
        // COM Schema と同じ登録表に入れても衝突しない。
        for def in crate::com::com_schemas() {
            reg.register(def).expect("com schemas must register");
        }
        assert_eq!(reg.len(), 6);
        // 再登録は冪等。
        for def in winrt_schemas() {
            reg.register(def).expect("re-register is idempotent");
        }
        // API 表の Schema ID と衝突しない。
        let api_ids: std::collections::HashSet<u32> = crate::api::all_schemas()
            .iter()
            .map(|s| s.schema_id)
            .collect();
        assert!(!api_ids.contains(&WINRT_ACTIVATION_ENTER_SCHEMA_ID));
        assert!(!api_ids.contains(&WINRT_ACTIVATION_LEAVE_SCHEMA_ID));
    }

    #[test]
    fn winrt_activation_values_encode_decode_roundtrip() {
        let enter = winrt_activation_enter_values(
            0,
            "Windows.Foundation.Uri",
            "RoActivateInstance",
            &crate::com::raw_arg_slots(&[0xABCD, 0x1234]),
        );
        let bytes = encode_winrt_activation_enter(&enter).expect("encode enter");
        let types = schema_types(&winrt_activation_enter_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode enter");
        assert_eq!(back.len(), 4);
        assert_eq!(back[0].value, TypedValue::U64(0));
        assert_eq!(
            back[1].value,
            TypedValue::Str("Windows.Foundation.Uri".to_string())
        );
        assert_eq!(
            back[2].value,
            TypedValue::Str("RoActivateInstance".to_string())
        );
        assert_eq!(
            back[3].value,
            TypedValue::Bytes(
                [0xABCDusize, 0x1234usize]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect()
            )
        );
        let leave = winrt_activation_leave_values(0, 0x5678);
        let bytes = encode_winrt_activation_leave(&leave).expect("encode leave");
        let types = schema_types(&winrt_activation_leave_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode leave");
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].value, TypedValue::I32(0));
        assert_eq!(back[1].value, TypedValue::U64(0x5678));
        assert_eq!(back[2].value, TypedValue::U32(0));
    }

    #[test]
    fn hstring_units_to_string_handles_utf16() {
        assert_eq!(
            hstring_units_to_string(
                "Windows.Foundation.Uri"
                    .encode_utf16()
                    .collect::<Vec<_>>()
                    .as_slice()
            ),
            "Windows.Foundation.Uri"
        );
        // サロゲートペア（絵文字）と日本語。
        let units: Vec<u16> = "a\u{1F600}あ".encode_utf16().collect();
        assert_eq!(hstring_units_to_string(&units), "a\u{1F600}あ");
        // 不正な単独サロゲートは U+FFFD になる。
        assert_eq!(hstring_units_to_string(&[0xD800]), "\u{FFFD}");
        assert_eq!(hstring_units_to_string(&[]), "");
    }
}
