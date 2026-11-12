//! COM Interception（L02・overview COM 節・フック実装順序 3・段階 6）。
//!
//! 既知の Factory 関数（`CoCreateInstance` / `CoGetClassObject`）が
//! 返したインターフェイスを起点に追跡し、その vtable のメソッド呼び出しを
//! 記録する。メソッドが返すインターフェイスや `QueryInterface` の結果も
//! 追跡対象に加えていく。同一性は対象アプリが実際に実行した
//! `QueryInterface` の結果だけで判定し（標準では追加で呼ばない）、
//! `AddRef` / `Release` で寿命を追う。同一性を確定できない
//! インターフェイスは別々に保持し、関係を未確認とする。型不明のカスタム
//! インターフェイスは未対応として明記する。
//!
//! Interception 方式は「オブジェクト単位の vtable 複製」である：
//! - 追跡対象のオブジェクトごとに vtable を複製し、複製のスロットを
//!   Detour へ向け、オブジェクトの vtable ポインタだけを複製へ向ける。
//! - 共有 vtable そのものは書き換えないため、同じ実装を共有する別の
//!   オブジェクトには及ばない（overview が副作用として挙げる共有
//!   vtable 書き換えの波及は起きない）。
//! - Proxy を使わないため、アプリへ返すポインタの同一性は壊れない
//!   （オブジェクトのポインタ値そのものは変えない）。
//! - 代償として、複製した vtable とその登録は解放しない（Release で
//!   寿命が終わった後も、他スレッドが呼び出し中かもしれないため。
//!   1 オブジェクトあたり最大で (メソッド数 + 登録) × 8 バイト程度）。
//!   プロセス終了時に OS が回収する。
//!
//! 制限（このファイルと engine.rs の Windows 実装に共通）:
//! - 既知インターフェイスは IUnknown / IShellLinkW / IPersistFile の
//!   3 つに加え、WinRT の 6 つ（`crate::winrt::WINRT_INTERFACES`。
//!   IInspectable / IActivationFactory / IUriRuntimeClass /
//!   IUriRuntimeClassFactory / IJsonObject / IStringable。L14）。
//!   それ以外の IID は追跡対象として記録するが、メソッドの Detour は
//!   設置しない。
//! - `Direct3DCreate9` は既知の Factory 関数として表に載せるが、
//!   返す IDirect3D9 のメソッド表が未定義のため、この版ではフック
//!   しない（Factory 呼び出しの記録もしない）。
//! - アタッチ前に既に存在していたオブジェクトは発見できない
//!   （Factory / QueryInterface / メソッド戻りを観測して初めて追跡
//!   対象になる）。途中から発見したポインタは来歴不明として扱う。
//! - COM メソッドの記録は L1（引数は生のスロット値列。型付きの
//!   取得は将来の拡張）。`QueryInterface` の要求 IID と Factory
//!   呼び出しの CLSID は `target_iid` に読んで記録する。
//! - 診断用オプション（`diagnostic_query_interface`）が有効な場合
//!   にだけ、Interceptor 自身が `QueryInterface(IID_IUnknown)` を
//   呼んで正規の同一性を確認する。標準では呼ばない（参照カウントを
//!   増やし、アプリがしなかった COM 操作になるため）。

use shirusu_trace::compact::encode_values;
use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{
    make_schema, schema_types, CaptureTiming, CapturedValue, Ty, TypedValue, ValueKind,
};
use shirusu_trace::CompactError;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// COM メソッド呼び出しイベントの api_id。API 表（api.rs）の ID 空間
/// とは別の予約値（表が伸びても衝突しないよう、表の連番とは離す）。
/// TraceEvent.api_id に載り、`--api` による Filtered 記録では
/// API 表に無いため一致しない（COM イベントは落とされる）。
pub const COM_METHOD_API_ID: u32 = 1000;
/// COM メソッド呼び出しの enter / leave Schema の ID。API 表の
/// Schema ID（1〜2×API_COUNT）とは別の予約ブロック。表が 5000 API
/// に達しない限り衝突せず、万一衝突しても SchemaRegistry が
/// 同一 ID の異内容登録を拒否してセッション開始時に失敗する。
pub const COM_METHOD_ENTER_SCHEMA_ID: u32 = 10_001;
pub const COM_METHOD_LEAVE_SCHEMA_ID: u32 = 10_002;
/// Factory 呼び出しを COM メソッドイベントとして記録するときの
/// `method_index`。vtable の実インデックスとは区別する番兵。
pub const FACTORY_METHOD_INDEX: u32 = u32::MAX;
/// 既知の Factory 関数の数（CoCreateInstance / CoGetClassObject）。
pub const COM_FACTORY_COUNT: usize = 2;
/// COM Factory 関数の Detour が元関数を引くための、ランタイム内の
/// スロット番号（CoCreateInstance = 0、CoGetClassObject = 1）。
pub const COM_FACTORY_CO_CREATE_INSTANCE: usize = 0;
pub const COM_FACTORY_CO_GET_CLASS_OBJECT: usize = 1;
/// Factory 関数の Inline Hook を報告するときの ID 基準値
/// （`InlineHook.api_id` 用。API 表の ID とは別の予約値）。
pub const COM_FACTORY_REPORT_ID_BASE: u32 = 0xC000_0000;

/// COM の GUID（16 バイト。メモリ上の配置と同じく data1 LE u32 +
/// data2 LE u16 + data3 LE u16 + data4 8 バイトで保持する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Guid {
    pub bytes: [u8; 16],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = data1 as u8;
        bytes[1] = (data1 >> 8) as u8;
        bytes[2] = (data1 >> 16) as u8;
        bytes[3] = (data1 >> 24) as u8;
        bytes[4] = data2 as u8;
        bytes[5] = (data2 >> 8) as u8;
        bytes[6] = data3 as u8;
        bytes[7] = (data3 >> 8) as u8;
        bytes[8] = data4[0];
        bytes[9] = data4[1];
        bytes[10] = data4[2];
        bytes[11] = data4[3];
        bytes[12] = data4[4];
        bytes[13] = data4[5];
        bytes[14] = data4[6];
        bytes[15] = data4[7];
        Self { bytes }
    }
}

impl std::fmt::Display for Guid {
    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` 形式。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.bytes;
        write!(
            f,
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15]
        )
    }
}

pub const IID_IUNKNOWN: Guid = Guid::new(
    0x0000_0000,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);
pub const IID_ISHELL_LINK_W: Guid = Guid::new(
    0x0002_14F9,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);
pub const IID_IPERSIST_FILE: Guid = Guid::new(
    0x0000_010B,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);
pub const CLSID_SHELL_LINK: Guid = Guid::new(
    0x0002_1401,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

/// 既知インターフェイスの 1 メソッド。`arity` は `this` を除く引数個数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComMethodDef {
    pub index: u32,
    pub name: &'static str,
    pub arity: usize,
}

/// 既知インターフェイスの定義。メソッドは vtable インデックス順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComInterfaceDef {
    pub iid: Guid,
    pub name: &'static str,
    pub methods: &'static [ComMethodDef],
}

const IUNKNOWN_METHODS: &[ComMethodDef] = &[
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
];

pub const IUNKNOWN_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IUNKNOWN,
    name: "IUnknown",
    methods: IUNKNOWN_METHODS,
};

/// IShellLinkW のメソッド表。vtable 位置は L17 の検証用アプリの
/// 注釈と同じ（0 QueryInterface, 1 AddRef, 2 Release, 3 GetPath,
/// 4 GetIDList, 5 SetIDList, 6 GetDescription, 7 SetDescription,
/// 8 GetWorkingDirectory, 9 SetWorkingDirectory, 10 GetArguments,
/// 11 SetArguments, 12 GetHotkey, 13 SetHotkey, 14 GetShowCmd,
/// 15 SetShowCmd, 16 GetIconLocation, 17 SetIconLocation,
/// 18 SetRelativePath, 19 Resolve, 20 SetPath）。
const ISHELL_LINK_W_METHODS: &[ComMethodDef] = &[
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
        name: "GetPath",
        arity: 4,
    },
    ComMethodDef {
        index: 4,
        name: "GetIDList",
        arity: 1,
    },
    ComMethodDef {
        index: 5,
        name: "SetIDList",
        arity: 1,
    },
    ComMethodDef {
        index: 6,
        name: "GetDescription",
        arity: 2,
    },
    ComMethodDef {
        index: 7,
        name: "SetDescription",
        arity: 1,
    },
    ComMethodDef {
        index: 8,
        name: "GetWorkingDirectory",
        arity: 2,
    },
    ComMethodDef {
        index: 9,
        name: "SetWorkingDirectory",
        arity: 1,
    },
    ComMethodDef {
        index: 10,
        name: "GetArguments",
        arity: 2,
    },
    ComMethodDef {
        index: 11,
        name: "SetArguments",
        arity: 1,
    },
    ComMethodDef {
        index: 12,
        name: "GetHotkey",
        arity: 1,
    },
    ComMethodDef {
        index: 13,
        name: "SetHotkey",
        arity: 1,
    },
    ComMethodDef {
        index: 14,
        name: "GetShowCmd",
        arity: 1,
    },
    ComMethodDef {
        index: 15,
        name: "SetShowCmd",
        arity: 1,
    },
    ComMethodDef {
        index: 16,
        name: "GetIconLocation",
        arity: 3,
    },
    ComMethodDef {
        index: 17,
        name: "SetIconLocation",
        arity: 2,
    },
    ComMethodDef {
        index: 18,
        name: "SetRelativePath",
        arity: 2,
    },
    ComMethodDef {
        index: 19,
        name: "Resolve",
        arity: 2,
    },
    ComMethodDef {
        index: 20,
        name: "SetPath",
        arity: 1,
    },
];

pub const ISHELL_LINK_W_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_ISHELL_LINK_W,
    name: "IShellLinkW",
    methods: ISHELL_LINK_W_METHODS,
};

/// IPersistFile のメソッド表（0〜2 は IUnknown、3 GetClassID,
/// 4 IsDirty, 5 Load, 6 Save, 7 SaveCompleted, 8 GetCurFile）。
const IPERSIST_FILE_METHODS: &[ComMethodDef] = &[
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
        name: "GetClassID",
        arity: 1,
    },
    ComMethodDef {
        index: 4,
        name: "IsDirty",
        arity: 0,
    },
    ComMethodDef {
        index: 5,
        name: "Load",
        arity: 2,
    },
    ComMethodDef {
        index: 6,
        name: "Save",
        arity: 2,
    },
    ComMethodDef {
        index: 7,
        name: "SaveCompleted",
        arity: 1,
    },
    ComMethodDef {
        index: 8,
        name: "GetCurFile",
        arity: 1,
    },
];

pub const IPERSIST_FILE_DEF: ComInterfaceDef = ComInterfaceDef {
    iid: IID_IPERSIST_FILE,
    name: "IPersistFile",
    methods: IPERSIST_FILE_METHODS,
};

/// 既知インターフェイスの表（メソッド表を持つものだけ）。
pub const KNOWN_INTERFACES: &[ComInterfaceDef] =
    &[IUNKNOWN_DEF, ISHELL_LINK_W_DEF, IPERSIST_FILE_DEF];

/// IID から既知インターフェイスの定義を引く。COM の表に無ければ
/// WinRT の表（`crate::winrt::WINRT_INTERFACES`）も引く（L14）。
/// WinRT インターフェイスも COM と同じ vtable 複製・Detour で追跡する。
pub fn interface_by_iid(iid: &Guid) -> Option<&'static ComInterfaceDef> {
    KNOWN_INTERFACES
        .iter()
        .find(|d| d.iid == *iid)
        .or_else(|| crate::winrt::winrt_interface_by_iid(iid))
}

impl ComInterfaceDef {
    pub fn method(&self, index: u32) -> Option<&ComMethodDef> {
        self.methods.iter().find(|m| m.index == index)
    }
}

/// 既知の Factory 関数。`interface` は返すインターフェイスの
/// IID が呼び出し時に決まるもの（CoCreateInstance / CoGetClassObject）
/// には None（呼び出し側が riid から読む）。`Direct3DCreate9` は
/// 返す IDirect3D9 のメソッド表が未定義のため、表には載せるが
/// フックはしない（`hookable` が false）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComFactoryDef {
    pub module: &'static str,
    pub function: &'static str,
    /// この Factory 関数に Detour を設置するか。
    pub hookable: bool,
}

pub const KNOWN_FACTORIES: &[ComFactoryDef] = &[
    ComFactoryDef {
        module: "ole32.dll",
        function: "CoCreateInstance",
        hookable: true,
    },
    ComFactoryDef {
        module: "ole32.dll",
        function: "CoGetClassObject",
        hookable: true,
    },
    ComFactoryDef {
        module: "d3d9.dll",
        function: "Direct3DCreate9",
        hookable: false,
    },
];

pub fn factory_by_name(module: &str, function: &str) -> Option<&'static ComFactoryDef> {
    KNOWN_FACTORIES
        .iter()
        .find(|f| f.module.eq_ignore_ascii_case(module) && f.function == function)
}

// ---- COM メソッドイベントの Schema ----

fn before() -> u32 {
    CaptureTiming::Before.flags()
}
fn after() -> u32 {
    CaptureTiming::After.flags()
}

/// COM メソッド呼び出しの enter Schema。
///
/// フィールド:
/// - `object` (U64, Pointer): メソッドを呼んだインターフェイスの
///   ポインタ（`this`）。Factory 呼び出しでは 0（enter 時点では
///   返されるポインタがまだ無い）。
/// - `iid` (Bytes): `object` のインターフェイス IID（16 バイト）。
///   Factory 呼び出しでは要求された IID。読めなければ空。
/// - `method_index` (U32): vtable インデックス。Factory 呼び出し
///   では `FACTORY_METHOD_INDEX` (u32::MAX)。
/// - `method_name` (Str): `IShellLinkW::SetPath` / `CoCreateInstance`
///   のような表示名。
/// - `args` (Bytes): `this` を除く引数の生スロット値列（native 幅
///   の usize を LE で並べたもの。上限は 4 スロット = 32 バイト。
///   ポインタの中身は読まない）。
/// - `target_iid` (Bytes): もう一方の GUID がある場合に 16 バイト。
///   `QueryInterface` では要求された IID、Factory 呼び出しでは
///   CLSID、それ以外は空。
pub fn com_method_enter_schema() -> SchemaDef {
    let mut def = make_schema(
        COM_METHOD_ENTER_SCHEMA_ID,
        "com!method/enter",
        vec![
            (
                "object".to_string(),
                Ty::U64,
                ValueKind::Pointer.flags() | before(),
            ),
            (
                "iid".to_string(),
                Ty::Bytes,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "method_index".to_string(),
                Ty::U32,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "method_name".to_string(),
                Ty::Str,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "args".to_string(),
                Ty::Bytes,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "target_iid".to_string(),
                Ty::Bytes,
                ValueKind::Scalar.flags() | before(),
            ),
        ],
    );
    def.annotation = "L1 (COM): vtable method call. args are raw slots; \
        target_iid is the requested IID (QueryInterface) or CLSID (factory)"
        .to_string();
    def
}

/// COM メソッド呼び出しの leave Schema。
///
/// フィールド:
/// - `hresult` (I32): メソッドの HRESULT。AddRef / Release では
///   返された参照カウント（ULONG）を I32 へ写したもの（この 2 メソッド
///   では HRESULT ではない）。
/// - `returned_object` (U64, CreatedObject): 新しく得られた
///   インターフェイスのポインタ。Factory 呼び出しの成功時と
///   `QueryInterface` の成功時に有効で、それ以外は 0。
/// - `refcount` (U32): AddRef / Release が返した参照カウント。
///   それ以外のメソッドでは 0（「対象外」を表す）。
pub fn com_method_leave_schema() -> SchemaDef {
    let mut def = make_schema(
        COM_METHOD_LEAVE_SCHEMA_ID,
        "com!method/leave",
        vec![
            (
                "hresult".to_string(),
                Ty::I32,
                ValueKind::Scalar.flags() | after(),
            ),
            (
                "returned_object".to_string(),
                Ty::U64,
                ValueKind::CreatedObject.flags() | after(),
            ),
            (
                "refcount".to_string(),
                Ty::U32,
                ValueKind::Scalar.flags() | after(),
            ),
        ],
    );
    def.annotation = "L1 (COM): hresult is the refcount for AddRef/Release; \
        returned_object is set for factory calls and successful QueryInterface"
        .to_string();
    def
}

/// Host がセッション開始時に登録する COM 用 Schema（enter / leave）。
pub fn com_schemas() -> Vec<SchemaDef> {
    vec![com_method_enter_schema(), com_method_leave_schema()]
}

/// enter 値列を作る。`args` は `this` を除く引数の生スロット値列。
pub fn com_method_enter_values(
    object: u64,
    iid: &[u8],
    method_index: u32,
    method_name: &str,
    args: &[u8],
    target_iid: &[u8],
) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::U64(object)),
        CapturedValue::captured(TypedValue::Bytes(iid.to_vec())),
        CapturedValue::captured(TypedValue::U32(method_index)),
        CapturedValue::captured(TypedValue::Str(method_name.to_string())),
        CapturedValue::captured(TypedValue::Bytes(args.to_vec())),
        CapturedValue::captured(TypedValue::Bytes(target_iid.to_vec())),
    ]
}

/// leave 値列を作る。
pub fn com_method_leave_values(
    hresult: i32,
    returned_object: u64,
    refcount: u32,
) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::I32(hresult)),
        CapturedValue::captured(TypedValue::U64(returned_object)),
        CapturedValue::captured(TypedValue::U32(refcount)),
    ]
}

pub fn encode_com_enter(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types = schema_types(&com_method_enter_schema()).expect("com enter schema is well-formed");
    encode_values(&types, values)
}

pub fn encode_com_leave(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types = schema_types(&com_method_leave_schema()).expect("com leave schema is well-formed");
    encode_values(&types, values)
}

/// 引数の生スロット値列を作る（native 幅の usize を LE で並べる）。
/// スロット数が 4 を超える分は切り捨てる（既知インターフェイスの
/// 最大 arity は 4 のため、到達しないはずの防御）。
pub fn raw_arg_slots(args: &[usize]) -> Vec<u8> {
    let mut out = Vec::with_capacity(args.len().min(4) * std::mem::size_of::<usize>());
    for a in args.iter().take(4) {
        out.extend_from_slice(&a.to_le_bytes());
    }
    out
}

// ---- 追跡対象オブジェクトの記録（ComTracker） ----

/// オブジェクトの発見経路。来歴が分からないものは `Discovered`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComDiscovery {
    Factory { factory: &'static str },
    QueryInterface { from: u64 },
    MethodReturn { from: u64, method: &'static str },
    Discovered,
}

/// 追跡対象の COM インターフェイス 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComObject {
    pub ptr: u64,
    pub iid: Guid,
    /// 既知インターフェイス名。未知の IID では "unknown"。
    pub interface_name: &'static str,
    /// 同一性キー。`QueryInterface(IID_IUnknown)` で確認できた場合は
    /// その返す IUnknown ポインタ、未確認の場合は最初の発見時の
    /// ポインタ（自分自身）。未確認のもの同士の関係は未確認のまま。
    pub identity: u64,
    /// `QueryInterface(IID_IUnknown)` の結果で同一性が確定したか。
    /// 標準では shirusu 自身は QI を呼ばないため、アプリが
    /// IUnknown への QI を実行した場合にだけ真になる。診断用
    /// オプションが有効な場合に限り、Interceptor 自身の QI でも
    /// 確定する。
    pub identity_confirmed: bool,
    /// 最後に観測した参照カウント（AddRef / Release の戻り値）。
    /// まだ観測していなければ None。
    pub refcount: Option<u32>,
    pub discovered: ComDiscovery,
    /// vtable 複製による Detour が設置済みか。
    pub intercepted: bool,
    /// Why standard observation did not install method interception.
    pub interception_skip_reason: Option<&'static str>,
    /// Release が 0 を返して寿命が終わったか（記録は残す）。
    pub destroyed: bool,
    /// 設置前に読んだ元の vtable アドレス（0 = 未読）。
    pub original_vtable: u64,
    /// 複製した vtable のアドレス（None = 未設置）。
    pub cloned_vtable: Option<u64>,
    /// 複製前の元のメソッドポインタ列（vtable インデックス順）。
    pub original_methods: Vec<u64>,
}

/// `QueryInterface` 観測の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryInterfaceOutcome {
    /// 成功し、返されたポインタが呼び出し元と同じ（同一インターフェイス）。
    SamePointer,
    /// 成功し、別ポインタが返された（別インターフェイス。同一オブジェクト
    /// の別面として追跡対象に加えた）。
    NewInterface { ptr: u64 },
    /// 失敗（HRESULT != S_OK）または out が NULL。追跡対象は増えない。
    Failed,
}

/// 追跡対象インターフェイスの登録表（セッション単位。HookRuntime が持つ）。
#[derive(Debug, Default)]
pub struct ComTracker {
    objects: HashMap<u64, ComObject>,
    /// 診断用オプション：有効な場合、Interceptor は新規発見の
    /// インターフェイスに対して自身で `QueryInterface(IID_IUnknown)`
    /// を呼んで同一性を確認する（既定は false。標準では呼ばない）。
    diagnostic_query_interface: bool,
}

impl ComTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_diagnostic_query_interface(&mut self, enabled: bool) {
        self.diagnostic_query_interface = enabled;
    }

    pub fn diagnostic_query_interface(&self) -> bool {
        self.diagnostic_query_interface
    }

    pub fn note_interception_skipped(&mut self, ptr: u64) {
        if let Some(object) = self.objects.get_mut(&ptr) {
            object.interception_skip_reason = Some("shared-object-safety-unproven");
        }
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn live_count(&self) -> usize {
        self.objects.values().filter(|o| !o.destroyed).count()
    }

    pub fn intercepted_count(&self) -> usize {
        self.objects.values().filter(|o| o.intercepted).count()
    }

    pub fn lookup(&self, ptr: u64) -> Option<&ComObject> {
        self.objects.get(&ptr)
    }

    fn insert(&mut self, obj: ComObject) -> u64 {
        let identity = obj.identity;
        self.objects.insert(obj.ptr, obj);
        identity
    }

    /// Factory 呼び出しが返したインターフェイスを登録する。
    /// 既に登録済みのポインタ（再利用されたアドレス等）は、既存の
    /// 記録を残して identity だけ返す（上書きしない）。
    pub fn note_factory_result(&mut self, ptr: u64, iid: Guid, factory: &'static str) -> u64 {
        if let Some(o) = self.objects.get(&ptr) {
            return o.identity;
        }
        let name = interface_by_iid(&iid).map(|d| d.name).unwrap_or("unknown");
        self.insert(ComObject {
            ptr,
            iid,
            interface_name: name,
            identity: ptr,
            identity_confirmed: false,
            refcount: None,
            discovered: ComDiscovery::Factory { factory },
            intercepted: false,
            interception_skip_reason: None,
            destroyed: false,
            original_vtable: 0,
            cloned_vtable: None,
            original_methods: Vec::new(),
        })
    }

    /// アプリが実行した `QueryInterface` の結果を反映する。成功時は
    /// 返されたポインタを追跡対象に加える（同一オブジェクトの別面）。
    /// - `iid == IID_IUnknown` の成功は同一性の確定：返す IUnknown
    ///   ポインタを正規キーにし、呼び出し元と同じ identity キーを
    ///   持つ全ての記録（呼び出し元自身と、そこから QI で派生した
    ///   別面）を付け替える。返すポインタが既に別キーで追跡されて
    ///   いた場合、そのキーを持つ記録も同じ正規キーへ付け替える
    ///   （同一オブジェクトの別面だったことの確定）。
    /// - それ以外の IID の成功は、呼び出し元の identity を引き継ぐ
    ///   （未確認のまま。COM の契約上は同一オブジェクトだが、shirusu
    ///   の同一性判定は QI(IUnknown) の結果だけを確定根拠にする）。
    /// - 失敗時は何もしない。
    pub fn note_query_interface(
        &mut self,
        this: u64,
        out: u64,
        iid: Guid,
        succeeded: bool,
    ) -> QueryInterfaceOutcome {
        if !succeeded || out == 0 {
            return QueryInterfaceOutcome::Failed;
        }
        if iid == IID_IUNKNOWN {
            // 同一性の確定：正規キーへ付け替える対象は、呼び出し元の
            // キーと、返すポインタの従来のキー（既に追跡されていた場合）。
            let mut keys: Vec<u64> = Vec::new();
            if let Some(o) = self.objects.get(&this) {
                keys.push(o.identity);
            }
            if let Some(o) = self.objects.get(&out) {
                if !keys.contains(&o.identity) {
                    keys.push(o.identity);
                }
            }
            for o in self.objects.values_mut() {
                if keys.contains(&o.identity) {
                    o.identity = out;
                    o.identity_confirmed = true;
                }
            }
            if out == this {
                return QueryInterfaceOutcome::SamePointer;
            }
            if !self.objects.contains_key(&out) {
                self.insert(ComObject {
                    ptr: out,
                    iid,
                    interface_name: "IUnknown",
                    identity: out,
                    identity_confirmed: true,
                    refcount: None,
                    discovered: ComDiscovery::QueryInterface { from: this },
                    intercepted: false,
                    interception_skip_reason: None,
                    destroyed: false,
                    original_vtable: 0,
                    cloned_vtable: None,
                    original_methods: Vec::new(),
                });
            }
            return QueryInterfaceOutcome::NewInterface { ptr: out };
        }
        if out == this {
            return QueryInterfaceOutcome::SamePointer;
        }
        let (identity, confirmed) = match self.objects.get(&this) {
            Some(o) => (o.identity, o.identity_confirmed),
            None => (this, false),
        };
        if self.objects.contains_key(&out) {
            return QueryInterfaceOutcome::NewInterface { ptr: out };
        }
        let name = interface_by_iid(&iid).map(|d| d.name).unwrap_or("unknown");
        self.insert(ComObject {
            ptr: out,
            iid,
            interface_name: name,
            identity,
            identity_confirmed: confirmed,
            refcount: None,
            discovered: ComDiscovery::QueryInterface { from: this },
            intercepted: false,
            interception_skip_reason: None,
            destroyed: false,
            original_vtable: 0,
            cloned_vtable: None,
            original_methods: Vec::new(),
        });
        QueryInterfaceOutcome::NewInterface { ptr: out }
    }

    /// メソッドが返したインターフェイスを追跡対象に加える（将来の
    /// インターフェイス用。現行の既知メソッドでインターフェイスを
    /// 返すのは `QueryInterface` だけだが、入口は用意する）。
    /// 同一性は未確認のまま別々に保持する。
    pub fn note_method_returned(
        &mut self,
        ptr: u64,
        iid: Guid,
        from: u64,
        method: &'static str,
    ) -> Option<u64> {
        if ptr == 0 || self.objects.contains_key(&ptr) {
            return self.objects.get(&ptr).map(|o| o.identity);
        }
        let name = interface_by_iid(&iid).map(|d| d.name).unwrap_or("unknown");
        Some(self.insert(ComObject {
            ptr,
            iid,
            interface_name: name,
            identity: ptr,
            identity_confirmed: false,
            refcount: None,
            discovered: ComDiscovery::MethodReturn { from, method },
            intercepted: false,
            interception_skip_reason: None,
            destroyed: false,
            original_vtable: 0,
            cloned_vtable: None,
            original_methods: Vec::new(),
        }))
    }

    /// 来歴不明のポインタを追跡対象に加える（途中から発見した場合）。
    /// 同一性は未確認のまま別々に保持する。
    pub fn note_discovered(&mut self, ptr: u64, iid: Guid) -> u64 {
        if let Some(o) = self.objects.get(&ptr) {
            return o.identity;
        }
        let name = interface_by_iid(&iid).map(|d| d.name).unwrap_or("unknown");
        self.insert(ComObject {
            ptr,
            iid,
            interface_name: name,
            identity: ptr,
            identity_confirmed: false,
            refcount: None,
            discovered: ComDiscovery::Discovered,
            intercepted: false,
            interception_skip_reason: None,
            destroyed: false,
            original_vtable: 0,
            cloned_vtable: None,
            original_methods: Vec::new(),
        })
    }

    /// 診断用オプションによる `QueryInterface(IID_IUnknown)` の結果で
    /// 同一性を確定する。`canonical` は返された IUnknown ポインタ。
    /// 対象が未登録なら何もしない。
    pub fn note_identity_confirmed(&mut self, ptr: u64, canonical: u64) {
        if let Some(o) = self.objects.get_mut(&ptr) {
            o.identity = canonical;
            o.identity_confirmed = true;
        }
    }

    /// `AddRef` の戻り値（新しい参照カウント）を記録する。
    pub fn note_add_ref(&mut self, ptr: u64, new_count: u32) {
        if let Some(o) = self.objects.get_mut(&ptr) {
            o.refcount = Some(new_count);
        }
    }

    /// `Release` の戻り値（新しい参照カウント）を記録する。
    /// 0 になったら寿命終了として印を付ける（記録は残す）。
    /// 戻り値は寿命が終わったかどうか。
    pub fn note_release(&mut self, ptr: u64, new_count: u32) -> bool {
        match self.objects.get_mut(&ptr) {
            Some(o) => {
                o.refcount = Some(new_count);
                if new_count == 0 {
                    o.destroyed = true;
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// vtable 複製による Detour の設置を記録する。設置済みの場合は
    /// 何も変えず false を返す。
    pub fn note_intercepted(
        &mut self,
        ptr: u64,
        original_vtable: u64,
        cloned_vtable: u64,
        original_methods: Vec<u64>,
    ) -> bool {
        match self.objects.get_mut(&ptr) {
            Some(o) if !o.intercepted => {
                o.intercepted = true;
                o.original_vtable = original_vtable;
                o.cloned_vtable = Some(cloned_vtable);
                o.original_methods = original_methods;
                true
            }
            _ => false,
        }
    }
}

// ---- vtable 複製（純粋関数。Windows 側の設置は engine.rs） ----

/// 元の vtable（メソッドポインタ列）を複製し、`detours` の
/// (vtable インデックス, Detour アドレス) でスロットを置き換えた
/// 新しい vtable を作る。範囲外のインデックスは無視する。
/// 呼び出し側は返された列を読み取り可能なメモリへ書き、対象
/// オブジェクトの vtable ポインタをそこへ向ける。
pub fn build_cloned_vtable(original_methods: &[usize], detours: &[(u32, usize)]) -> Vec<usize> {
    let mut clone = original_methods.to_vec();
    for &(index, detour) in detours {
        if (index as usize) < clone.len() {
            clone[index as usize] = detour;
        }
    }
    clone
}

// ---- 複製 vtable の登録表（プロセス全体） ----
//
// Detour は `this` から複製 vtable のアドレスしか分からないため、
// 元のメソッドポインタは複製 vtable のアドレスを鍵にして引く。
// この登録表はセッションをまたいで残る：終了手順ではオブジェクトの
// vtable ポインタを元へ戻さないため、セッション終了後にアプリが
// COM メソッドを呼んでも Detour が元のメソッドを引ける必要がある。
// その場合はランタイムが無いため素通しで呼ぶ（記録はしない）。
// 登録は解放しない（複製 vtable 自体も解放しないのと同じ理由）。
#[derive(Debug, Default)]
pub struct ComCloneRegistry {
    clones: HashMap<u64, Vec<u64>>,
}

impl ComCloneRegistry {
    fn global() -> &'static Mutex<ComCloneRegistry> {
        static REGISTRY: OnceLock<Mutex<ComCloneRegistry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(ComCloneRegistry::default()))
    }

    /// 複製 vtable と元のメソッド列を登録する。
    pub fn register(clone_addr: u64, original_methods: Vec<u64>) {
        Self::global()
            .lock()
            .unwrap()
            .clones
            .insert(clone_addr, original_methods);
    }

    /// 複製 vtable の `index` 番目の元のメソッドポインタを引く。
    pub fn original(clone_addr: u64, index: u32) -> Option<u64> {
        Self::global()
            .lock()
            .unwrap()
            .clones
            .get(&clone_addr)
            .and_then(|m| m.get(index as usize).copied())
    }

    /// 複製 vtable の元のメソッド列全体を引く（テスト・診断用）。
    pub fn originals(clone_addr: u64) -> Option<Vec<u64>> {
        Self::global()
            .lock()
            .unwrap()
            .clones
            .get(&clone_addr)
            .cloned()
    }

    /// 登録済みの複製 vtable の数（テスト用）。
    pub fn len() -> usize {
        Self::global().lock().unwrap().clones.len()
    }

    /// テスト用に登録を消す（実運用では呼ばない）。
    #[cfg(test)]
    pub fn clear_for_test() {
        Self::global().lock().unwrap().clones.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::schema::{LastErrorMeaning, SchemaRegistry};

    #[test]
    fn guid_display_matches_canonical_form() {
        assert_eq!(
            IID_ISHELL_LINK_W.to_string(),
            "{000214F9-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            CLSID_SHELL_LINK.to_string(),
            "{00021401-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            IID_IUNKNOWN.to_string(),
            "{00000000-0000-0000-C000-000000000046}"
        );
        // メモリ上のバイト列は LE 配置（data1 の下位バイトが先頭）。
        assert_eq!(IID_ISHELL_LINK_W.bytes[0], 0xF9);
        assert_eq!(IID_ISHELL_LINK_W.bytes[3], 0x00);
        assert_eq!(IID_ISHELL_LINK_W.bytes[8], 0xC0);
    }

    #[test]
    fn known_interfaces_have_complete_method_tables() {
        // IUnknown 3 件、IShellLinkW 21 件、IPersistFile 9 件。
        assert_eq!(IUNKNOWN_DEF.methods.len(), 3);
        assert_eq!(ISHELL_LINK_W_DEF.methods.len(), 21);
        assert_eq!(IPERSIST_FILE_DEF.methods.len(), 9);
        for def in KNOWN_INTERFACES {
            // インデックスは 0 から連番で、名前は重複しない。
            for (i, m) in def.methods.iter().enumerate() {
                assert_eq!(m.index as usize, i, "{} method {i}", def.name);
            }
            let mut names: Vec<&str> = def.methods.iter().map(|m| m.name).collect();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), def.methods.len(), "{}", def.name);
            // IUnknown の 3 件は全インターフェイス共通の先頭。
            assert_eq!(def.methods[0].name, "QueryInterface");
            assert_eq!(def.methods[1].name, "AddRef");
            assert_eq!(def.methods[2].name, "Release");
        }
        assert_eq!(
            ISHELL_LINK_W_DEF.method(20).map(|m| (m.name, m.arity)),
            Some(("SetPath", 1))
        );
        assert_eq!(
            ISHELL_LINK_W_DEF.method(3).map(|m| (m.name, m.arity)),
            Some(("GetPath", 4))
        );
        assert_eq!(
            IPERSIST_FILE_DEF.method(5).map(|m| (m.name, m.arity)),
            Some(("Load", 2))
        );
        // 未知の IID は None。カスタムインターフェイスは未対応。
        assert!(interface_by_iid(&Guid::new(
            0x1234_5678,
            0x0000,
            0x0000,
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
        ))
        .is_none());
        assert_eq!(
            interface_by_iid(&IID_ISHELL_LINK_W).map(|d| d.name),
            Some("IShellLinkW")
        );
    }

    #[test]
    fn factory_table_lists_known_factories() {
        assert_eq!(
            factory_by_name("ole32.dll", "CoCreateInstance").map(|f| f.hookable),
            Some(true)
        );
        assert_eq!(
            factory_by_name("OLE32.DLL", "CoGetClassObject").map(|f| f.hookable),
            Some(true)
        );
        // Direct3DCreate9 は既知だがメソッド表が無いためフックしない。
        assert_eq!(
            factory_by_name("d3d9.dll", "Direct3DCreate9").map(|f| f.hookable),
            Some(false)
        );
        assert!(factory_by_name("ole32.dll", "CoInitializeEx").is_none());
    }

    #[test]
    fn com_schemas_register_cleanly() {
        let mut reg = SchemaRegistry::new();
        for def in com_schemas() {
            reg.register(def).expect("com schemas must register");
        }
        assert_eq!(reg.len(), 2);
        // 再登録は冪等。
        for def in com_schemas() {
            reg.register(def).expect("re-register is idempotent");
        }
        // API 表の Schema ID と衝突しない。
        let api_ids: std::collections::HashSet<u32> = crate::api::all_schemas()
            .iter()
            .map(|s| s.schema_id)
            .collect();
        assert!(!api_ids.contains(&COM_METHOD_ENTER_SCHEMA_ID));
        assert!(!api_ids.contains(&COM_METHOD_LEAVE_SCHEMA_ID));
    }

    #[test]
    fn com_method_values_encode_decode_roundtrip() {
        let enter = com_method_enter_values(
            0x1234_5678,
            &IID_ISHELL_LINK_W.bytes,
            20,
            "IShellLinkW::SetPath",
            &raw_arg_slots(&[0xABCD]),
            &[],
        );
        let bytes = encode_com_enter(&enter).expect("encode enter");
        let types = schema_types(&com_method_enter_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode enter");
        assert_eq!(back.len(), 6);
        assert_eq!(back[0].value, TypedValue::U64(0x1234_5678));
        assert_eq!(
            back[1].value,
            TypedValue::Bytes(IID_ISHELL_LINK_W.bytes.to_vec())
        );
        assert_eq!(back[2].value, TypedValue::U32(20));
        assert_eq!(
            back[3].value,
            TypedValue::Str("IShellLinkW::SetPath".to_string())
        );
        assert_eq!(
            back[4].value,
            TypedValue::Bytes(0xABCDusize.to_le_bytes().to_vec())
        );
        assert_eq!(back[5].value, TypedValue::Bytes(Vec::new()));

        let leave = com_method_leave_values(0, 0x9999, 0);
        let bytes = encode_com_leave(&leave).expect("encode leave");
        let types = schema_types(&com_method_leave_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode leave");
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].value, TypedValue::I32(0));
        assert_eq!(back[1].value, TypedValue::U64(0x9999));
        assert_eq!(back[2].value, TypedValue::U32(0));
    }

    #[test]
    fn raw_arg_slots_cap_at_four_and_use_native_width() {
        let slots = raw_arg_slots(&[1, 2, 3, 4, 5]);
        assert_eq!(slots.len(), 4 * std::mem::size_of::<usize>());
        assert_eq!(raw_arg_slots(&[]).len(), 0);
    }

    #[test]
    fn tracker_factory_registers_object_with_own_identity() {
        let mut t = ComTracker::new();
        assert!(!t.diagnostic_query_interface());
        let id = t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        assert_eq!(id, 0x1000);
        let o = t.lookup(0x1000).unwrap();
        assert_eq!(o.interface_name, "IShellLinkW");
        assert_eq!(o.identity, 0x1000);
        assert!(!o.identity_confirmed);
        assert_eq!(
            o.discovered,
            ComDiscovery::Factory {
                factory: "CoCreateInstance"
            }
        );
        assert!(!o.intercepted);
        assert_eq!(t.object_count(), 1);
        assert_eq!(t.live_count(), 1);
        // 既知でない IID は unknown として登録される（追跡はする）。
        let unknown = Guid::new(
            0xDEAD_BEEF,
            0x0000,
            0x0000,
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        );
        t.note_factory_result(0x2000, unknown, "CoCreateInstance");
        assert_eq!(t.lookup(0x2000).unwrap().interface_name, "unknown");
        // 二重登録は上書きしない。
        t.note_factory_result(0x1000, IID_IPERSIST_FILE, "CoCreateInstance");
        assert_eq!(t.lookup(0x1000).unwrap().iid, IID_ISHELL_LINK_W);
    }

    #[test]
    fn tracker_query_interface_links_identity_only_via_iunknown() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        // IPersistFile への QI：別ポインタが返され、同一オブジェクトの
        // 別面として追跡対象に加わる。identity は呼び出し元を引き継ぐ
        // が、未確認のまま。
        let out = t.note_query_interface(0x1000, 0x2000, IID_IPERSIST_FILE, true);
        assert_eq!(out, QueryInterfaceOutcome::NewInterface { ptr: 0x2000 });
        let p = t.lookup(0x2000).unwrap();
        assert_eq!(p.interface_name, "IPersistFile");
        assert_eq!(p.identity, 0x1000);
        assert!(!p.identity_confirmed);
        assert_eq!(p.discovered, ComDiscovery::QueryInterface { from: 0x1000 });
        // 失敗した QI は何も増やさない。
        assert_eq!(
            t.note_query_interface(0x1000, 0, IID_IPERSIST_FILE, false),
            QueryInterfaceOutcome::Failed
        );
        assert_eq!(t.object_count(), 2);
        // IUnknown への QI：返すポインタが正規の同一性キーになる。
        // そこから派生した別面（IPersistFile 側）も同じ正規キーへ
        // 付け替わり、確定する（推移的な同一性の確定）。
        let out = t.note_query_interface(0x1000, 0x3000, IID_IUNKNOWN, true);
        assert_eq!(out, QueryInterfaceOutcome::NewInterface { ptr: 0x3000 });
        assert_eq!(t.lookup(0x1000).unwrap().identity, 0x3000);
        assert!(t.lookup(0x1000).unwrap().identity_confirmed);
        assert_eq!(t.lookup(0x2000).unwrap().identity, 0x3000);
        assert!(t.lookup(0x2000).unwrap().identity_confirmed);
        assert_eq!(t.lookup(0x3000).unwrap().identity, 0x3000);
        assert!(t.lookup(0x3000).unwrap().identity_confirmed);
        // 同じポインタへの QI は SamePointer。
        assert_eq!(
            t.note_query_interface(0x1000, 0x1000, IID_ISHELL_LINK_W, true),
            QueryInterfaceOutcome::SamePointer
        );
    }

    #[test]
    fn tracker_add_ref_release_track_lifetime() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        t.note_add_ref(0x1000, 2);
        assert_eq!(t.lookup(0x1000).unwrap().refcount, Some(2));
        assert!(!t.note_release(0x1000, 1));
        assert!(!t.lookup(0x1000).unwrap().destroyed);
        assert_eq!(t.live_count(), 1);
        assert!(t.note_release(0x1000, 0));
        assert!(t.lookup(0x1000).unwrap().destroyed);
        assert_eq!(t.live_count(), 0);
        assert_eq!(
            t.object_count(),
            1,
            "destroyed record stays for correlation"
        );
        // 未登録ポインタの AddRef/Release は無視される。
        t.note_add_ref(0x9999, 1);
        assert!(!t.note_release(0x9999, 0));
    }

    #[test]
    fn tracker_unconfirmed_interfaces_stay_separate() {
        // メソッド戻りや途中発見のポインタは、同一性を確定できない
        // ため別々に保持される（関係は未確認）。
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        let id = t
            .note_method_returned(0x4000, IID_IPERSIST_FILE, 0x1000, "GetSomething")
            .unwrap();
        assert_eq!(id, 0x4000);
        assert!(!t.lookup(0x4000).unwrap().identity_confirmed);
        let id2 = t.note_discovered(0x5000, IID_ISHELL_LINK_W);
        assert_eq!(id2, 0x5000);
        assert_ne!(
            t.lookup(0x4000).unwrap().identity,
            t.lookup(0x1000).unwrap().identity
        );
        // 診断用オプションによる確定は、対象の identity を正規キーへ変える。
        t.set_diagnostic_query_interface(true);
        assert!(t.diagnostic_query_interface());
        t.note_identity_confirmed(0x4000, 0x3000);
        assert_eq!(t.lookup(0x4000).unwrap().identity, 0x3000);
        assert!(t.lookup(0x4000).unwrap().identity_confirmed);
    }

    #[test]
    fn tracker_intercepted_flag_is_set_once() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        assert!(t.note_intercepted(0x1000, 0x7000, 0x8000, vec![1, 2, 3]));
        assert!(t.lookup(0x1000).unwrap().intercepted);
        assert_eq!(t.lookup(0x1000).unwrap().original_vtable, 0x7000);
        assert_eq!(t.lookup(0x1000).unwrap().cloned_vtable, Some(0x8000));
        assert_eq!(t.intercepted_count(), 1);
        // 二重設置は拒否される。
        assert!(!t.note_intercepted(0x1000, 0x7000, 0x9000, vec![1, 2, 3]));
        assert_eq!(t.lookup(0x1000).unwrap().cloned_vtable, Some(0x8000));
        // 未登録ポインタへの設置記録は拒否される。
        assert!(!t.note_intercepted(0x9999, 0, 0, vec![]));
    }

    #[test]
    fn cloned_vtable_replaces_only_listed_slots() {
        let originals = vec![0x10usize, 0x20, 0x30, 0x40];
        let clone = build_cloned_vtable(&originals, &[(1, 0xAAAA), (3, 0xBBBB), (9, 0xCCCC)]);
        assert_eq!(clone, vec![0x10, 0xAAAA, 0x30, 0xBBBB]);
        // 元の列は変わらない。
        assert_eq!(originals, vec![0x10, 0x20, 0x30, 0x40]);
        // 全スロット置き換え（既知インターフェイスの全メソッド）。
        let all: Vec<(u32, usize)> = (0..4).map(|i| (i, 0xF000 + i as usize)).collect();
        assert_eq!(
            build_cloned_vtable(&originals, &all),
            vec![0xF000, 0xF001, 0xF002, 0xF003]
        );
    }

    #[test]
    fn clone_registry_roundtrip() {
        ComCloneRegistry::clear_for_test();
        assert_eq!(ComCloneRegistry::len(), 0);
        ComCloneRegistry::register(0x8000, vec![0x11, 0x22, 0x33]);
        assert_eq!(ComCloneRegistry::len(), 1);
        assert_eq!(ComCloneRegistry::original(0x8000, 1), Some(0x22));
        assert_eq!(ComCloneRegistry::original(0x8000, 3), None);
        assert_eq!(ComCloneRegistry::original(0x9999, 0), None);
        ComCloneRegistry::clear_for_test();
    }

    #[test]
    fn last_error_meaning_unused_for_com_leave() {
        // COM の leave Schema は HRESULT を運び、GetLastError の
        // 意味条件を持たない（F20 の対象は Win32 API のみ）。
        let leave = com_method_leave_schema();
        for f in &leave.fields {
            assert_eq!(
                LastErrorMeaning::from_flags(f.flags),
                LastErrorMeaning::Unspecified,
                "field {}",
                f.name
            );
        }
        // 既知インターフェイスの最大 arity は 4（GetPath）。
        let max = KNOWN_INTERFACES
            .iter()
            .flat_map(|d| d.methods.iter().map(|m| m.arity))
            .max()
            .unwrap();
        assert_eq!(max, 4);
    }
}
