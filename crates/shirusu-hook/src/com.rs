//! COM Factory observation, identity tracking, and interception metadata.
//!
//! Standard capture observes factories and intercepts image-backed IUnknown
//! slots with typed adapters while preserving object vptr identity. Heap/private
//! tables and derived methods remain unsupported; Host reports partial Coverage.
//!
//! The method tables and clone registry also support the experimental unsafe
//! `engine::intercept_exclusive_object` path. Its caller must independently
//! guarantee exclusive access and a matching ABI. Standard factory observation
//! does not call that path. Clone storage is retained until process exit.
//!
//! Known interface metadata covers IUnknown, IShellLinkW, IPersistFile and the
//! six WinRT interfaces in `crate::winrt::WINRT_INTERFACES`. Unknown interfaces
//! retain their identity without method interception. Objects that existed
//! before attachment have unknown provenance until a factory result is observed.
//!
//! Direct3DCreate9 is listed as a known factory but is not intercepted in this
//! version. COM method schemas describe raw argument slots (L1); they do not
//! establish semantic output capture for derived methods.

/// イベント識別子と Schema は API Catalog の共有定義を使う。
pub use shirusu_api_catalog::com::*;
use shirusu_trace::compact::encode_values;
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::CompactError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

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

/// Identify interfaces beyond the small, explicitly supported interception table.
/// Catalog membership never enables the unsafe exclusive-object interceptor.
pub fn interface_name_for_iid(iid: &Guid) -> &'static str {
    interface_by_iid(iid)
        .map(|d| d.name)
        .or_else(|| {
            shirusu_trace::com_catalog::interface_by_iid(&iid.bytes)
                .and_then(|entry| entry.names.first())
                .and_then(|name| name.rsplit('.').next())
        })
        .unwrap_or("unknown")
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

/// Factory arguments separate GUID contents/scalars from process-local addresses.
pub struct ComFactoryArgs {
    pub method: &'static str,
    pub clsid: Option<Guid>,
    pub iid: Option<Guid>,
    pub context: u32,
    pub outer: u64,
    pub server_info: u64,
    pub output_address: u64,
    pub clsid_address: u64,
    pub iid_address: u64,
}
pub fn com_factory_enter_values(args: &ComFactoryArgs) -> Vec<CapturedValue> {
    use shirusu_trace::schema::ValueCapture;
    let guid = |g: Option<Guid>| CapturedValue {
        capture: if g.is_some() {
            ValueCapture::Captured
        } else {
            ValueCapture::Unreadable
        },
        value: TypedValue::Bytes(g.map(|g| g.bytes.to_vec()).unwrap_or_default()),
    };
    let cv = CapturedValue::captured;
    vec![
        guid(args.clsid),
        guid(args.iid),
        cv(TypedValue::U32(args.context)),
        cv(TypedValue::Str(args.method.into())),
        cv(TypedValue::U64(args.outer)),
        cv(TypedValue::U64(args.server_info)),
        cv(TypedValue::U64(args.output_address)),
        cv(TypedValue::U64(args.clsid_address)),
        cv(TypedValue::U64(args.iid_address)),
    ]
}
pub fn encode_com_factory_enter(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, com_factory_enter_schema),
        values,
    )
}
pub fn encode_com_factory_leave(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, com_factory_leave_schema),
        values,
    )
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
pub fn com_factory_leave_values(
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
/// For callers with an independently known HRESULT-returning method.
pub fn com_method_leave_values(
    hresult: i32,
    returned_object: u64,
    refcount: u32,
) -> Vec<CapturedValue> {
    method_result_values("hresult", hresult, returned_object, refcount)
}
pub fn com_method_leave_values_for(
    method_index: u32,
    bits: i32,
    returned_object: u64,
    refcount: u32,
) -> Vec<CapturedValue> {
    let kind = match method_index {
        0 => "hresult",
        1 | 2 => "refcount",
        _ => "opaque-32",
    };
    method_result_values(kind, bits, returned_object, refcount)
}
fn method_result_values(
    kind: &str,
    bits: i32,
    returned_object: u64,
    refcount: u32,
) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::I32(bits)),
        CapturedValue::captured(TypedValue::U64(returned_object)),
        CapturedValue::captured(TypedValue::U32(refcount)),
        CapturedValue::captured(TypedValue::Str(kind.into())),
    ]
}

pub fn encode_com_enter(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, com_method_enter_schema),
        values,
    )
}

pub fn encode_com_leave(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    static TYPES: std::sync::OnceLock<Vec<shirusu_trace::schema::Ty>> = std::sync::OnceLock::new();
    encode_values(
        crate::callback::cached_schema_types(&TYPES, com_method_leave_schema),
        values,
    )
}

/// 引数の生スロット値列を作る（native 幅の usize を LE で並べる）。
/// Factory の引数も含めて全て保存する（CoCreateInstance は 5 引数）。
pub fn raw_arg_slots(args: &[usize]) -> Vec<u8> {
    let mut out = Vec::with_capacity(std::mem::size_of_val(args));
    for a in args {
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
    // Pointer values can be reused. These allocation identities distinguish
    // a record's lifetime and its QI-equivalence group without wrapping counters.
    instance: Arc<()>,
    identity_group: Arc<()>,
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
    /// First three image-backed slots are intercepted without replacing vptr.
    pub iunknown_intercepted: bool,
    /// Published adapter identity, retained on skips to detect module unload.
    pub iunknown_slot: Option<u32>,
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

impl ComObject {
    fn fresh(ptr: u64, iid: Guid, discovered: ComDiscovery) -> Self {
        let instance = Arc::new(());
        Self {
            identity_group: Arc::clone(&instance),
            instance,
            ptr,
            iid,
            interface_name: interface_name_for_iid(&iid),
            identity: ptr,
            identity_confirmed: false,
            refcount: None,
            discovered,
            intercepted: false,
            iunknown_intercepted: false,
            iunknown_slot: None,
            interception_skip_reason: None,
            destroyed: false,
            original_vtable: 0,
            cloned_vtable: None,
            original_methods: Vec::new(),
        }
    }
}

/// Identifies one observed interface lifetime across a call to user code.
#[derive(Debug, Clone)]
pub struct ComInstanceToken(Arc<()>);

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

/// Retired (Release(0) or unloaded) records kept before they are dropped.
pub const MAX_RETIRED_COM_RECORDS: usize = 4096;

fn group_key(group: &Arc<()>) -> usize {
    Arc::as_ptr(group) as usize
}

/// 追跡対象インターフェイスの登録表（セッション単位。HookRuntime が持つ）。
#[derive(Debug, Default)]
pub struct ComTracker {
    objects: HashMap<u64, ComObject>,
    /// Records per QI-equivalence group (keyed by the group allocation), so
    /// confirming an identity touches one group, not the whole table
    /// (review 2026-11-14 P2-6: QI(IUnknown) scanned every record).
    groups: HashMap<usize, Vec<u64>>,
    /// Records whose lifetime ended since the last prune.
    retired_records: usize,
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
        self.note_interception_skipped_with_reason(ptr, "shared-object-safety-unproven");
    }

    pub fn note_interception_skipped_with_reason(&mut self, ptr: u64, reason: &'static str) {
        if let Some(object) = self.objects.get_mut(&ptr) {
            object.interception_skip_reason = Some(reason);
            object.iunknown_intercepted = false;
        }
    }

    pub fn note_iunknown_intercepted(&mut self, ptr: u64, table: u64, slot: u32) {
        if let Some(object) = self.objects.get_mut(&ptr).filter(|o| !o.destroyed) {
            object.iunknown_intercepted = true;
            object.iunknown_slot = Some(slot);
            object.original_vtable = table;
            object.interception_skip_reason = interface_by_iid(&object.iid)
                .filter(|def| def.methods.len() > 3)
                .map(|_| "remaining-methods-unsupported");
        }
    }

    /// Module unload ends this implementation lifetime, without inventing a
    /// Release return value. A later discovery must create a new instance.
    pub fn note_implementation_unloaded(&mut self, ptr: u64) {
        if let Some(object) = self.objects.get_mut(&ptr) {
            let was_live = !object.destroyed;
            object.destroyed = true;
            object.refcount = None;
            object.iunknown_intercepted = false;
            object.interception_skip_reason = Some("implementation-unloaded");
            if was_live {
                self.note_retired();
            }
        }
    }

    /// Number of indexed addresses, including retired records until reuse
    /// or until [`MAX_RETIRED_COM_RECORDS`] of them are pruned.
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

    /// Check that the object now at `ptr` still has the vptr this record
    /// was installed with. Release through an unpatched path leaves the
    /// record live; a different object at the same address would then be
    /// recorded with the old IID. A mismatch ends the record's lifetime and
    /// returns false (2026-11-14 review P3-8). A record with no known vptr
    /// passes.
    pub fn confirm_vptr(&mut self, ptr: u64, observed: Option<u64>) -> bool {
        let Some(object) = self.objects.get(&ptr).filter(|o| !o.destroyed) else {
            return true;
        };
        let expected = object.cloned_vtable.unwrap_or(object.original_vtable);
        if expected == 0 || observed == Some(expected) {
            return true;
        }
        if let Some(object) = self.objects.get_mut(&ptr) {
            object.destroyed = true;
            object.refcount = None;
            object.interception_skip_reason = Some("address-reused");
        }
        self.note_retired();
        false
    }

    fn insert(&mut self, obj: ComObject) -> u64 {
        let identity = obj.identity;
        let (ptr, key) = (obj.ptr, group_key(&obj.identity_group));
        if let Some(old) = self.objects.insert(ptr, obj) {
            self.unindex(ptr, group_key(&old.identity_group));
        }
        self.groups.entry(key).or_default().push(ptr);
        identity
    }

    fn unindex(&mut self, ptr: u64, key: usize) {
        if let Some(members) = self.groups.get_mut(&key) {
            members.retain(|&p| p != ptr);
            if members.is_empty() {
                self.groups.remove(&key);
            }
        }
    }

    /// A record's lifetime ended. Retired records stay for lookups until
    /// [`MAX_RETIRED_COM_RECORDS`] accumulate, then all are dropped
    /// (review 2026-11-14 P2-6: the table grew for the whole session).
    fn note_retired(&mut self) {
        self.retired_records += 1;
        if self.retired_records > MAX_RETIRED_COM_RECORDS {
            let retired: Vec<(u64, usize)> = self
                .objects
                .values()
                .filter(|o| o.destroyed)
                .map(|o| (o.ptr, group_key(&o.identity_group)))
                .collect();
            for (ptr, key) in retired {
                self.objects.remove(&ptr);
                self.unindex(ptr, key);
            }
            self.retired_records = 0;
        }
    }

    /// Register a factory result. Preserve an already-live object, but a
    /// pointer observed after Release(0) starts a fresh lifetime and hook state.
    pub fn note_factory_result(&mut self, ptr: u64, iid: Guid, factory: &'static str) -> u64 {
        if ptr == 0 {
            return 0;
        }
        if let Some(o) = self.objects.get(&ptr).filter(|o| !o.destroyed) {
            return o.identity;
        }
        self.insert(ComObject::fresh(
            ptr,
            iid,
            ComDiscovery::Factory { factory },
        ))
    }

    pub fn instance_token(&self, ptr: u64) -> Option<ComInstanceToken> {
        self.objects
            .get(&ptr)
            .filter(|o| !o.destroyed)
            .map(|o| ComInstanceToken(Arc::clone(&o.instance)))
    }

    pub fn instance_matches(&self, ptr: u64, token: &ComInstanceToken) -> bool {
        self.objects
            .get(&ptr)
            .is_some_and(|o| !o.destroyed && Arc::ptr_eq(&o.instance, &token.0))
    }

    /// アプリが実行した `QueryInterface` の結果を反映する。成功時は
    /// 返されたポインタを追跡対象に加える（同一オブジェクトの別面）。
    /// - `iid == IID_IUnknown` の成功は同一性の確定：返す IUnknown
    ///   ポインタを正規キーにし、同じ寿命グループの生存中の記録
    ///   （呼び出し元自身と、そこから QI で派生した別面）を付け替える。
    ///   返すポインタが別の生存グループに属する場合も明示的に結合する。
    ///   アドレスが同じでも以前の寿命のグループは結合しない
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
        let source = self.objects.get(&this).filter(|o| !o.destroyed);
        let source_identity = source.map(|o| {
            (
                o.identity,
                o.identity_confirmed,
                Arc::clone(&o.identity_group),
            )
        });
        if iid == IID_IUNKNOWN {
            let existing = self.objects.get(&out).filter(|o| !o.destroyed);
            let mut groups: Vec<Arc<()>> = source_identity
                .as_ref()
                .map(|(_, _, group)| vec![Arc::clone(group)])
                .unwrap_or_default();
            if let Some(o) = existing {
                groups.push(Arc::clone(&o.identity_group));
            }
            let canonical_group = existing
                .map(|o| Arc::clone(&o.identity_group))
                .or_else(|| groups.first().cloned())
                .unwrap_or_else(|| Arc::new(()));
            let canonical_key = group_key(&canonical_group);
            let mut members: Vec<u64> = Vec::new();
            for group in &groups {
                if let Some(m) = self.groups.get(&group_key(group)) {
                    members.extend_from_slice(m);
                }
            }
            members.sort_unstable();
            members.dedup();
            for ptr in members {
                let Some(o) = self.objects.get_mut(&ptr) else {
                    continue;
                };
                if o.destroyed
                    || !groups
                        .iter()
                        .any(|group| Arc::ptr_eq(group, &o.identity_group))
                {
                    continue;
                }
                o.identity = out;
                o.identity_confirmed = true;
                let old_key = group_key(&o.identity_group);
                if old_key != canonical_key {
                    o.identity_group = Arc::clone(&canonical_group);
                    self.unindex(ptr, old_key);
                    self.groups.entry(canonical_key).or_default().push(ptr);
                }
            }
            if !self.objects.get(&out).is_some_and(|o| !o.destroyed) {
                let mut object =
                    ComObject::fresh(out, iid, ComDiscovery::QueryInterface { from: this });
                object.identity_confirmed = true;
                object.identity_group = canonical_group;
                self.insert(object);
            }
        } else if !self.objects.get(&out).is_some_and(|o| !o.destroyed) {
            let mut object =
                ComObject::fresh(out, iid, ComDiscovery::QueryInterface { from: this });
            if let Some((identity, confirmed, group)) = source_identity {
                object.identity = identity;
                object.identity_confirmed = confirmed;
                object.identity_group = group;
            } else {
                object.identity = this;
            }
            self.insert(object);
        }
        if out == this {
            QueryInterfaceOutcome::SamePointer
        } else {
            QueryInterfaceOutcome::NewInterface { ptr: out }
        }
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
        if ptr == 0 {
            return None;
        }
        if let Some(o) = self.objects.get(&ptr).filter(|o| !o.destroyed) {
            return Some(o.identity);
        }
        Some(self.insert(ComObject::fresh(
            ptr,
            iid,
            ComDiscovery::MethodReturn { from, method },
        )))
    }

    /// Register an otherwise discovered pointer; a retired address is a fresh
    /// lifetime, with identity unconfirmed until a new QI observation.
    pub fn note_discovered(&mut self, ptr: u64, iid: Guid) -> u64 {
        if ptr == 0 {
            return 0;
        }
        if let Some(o) = self.objects.get(&ptr).filter(|o| !o.destroyed) {
            return o.identity;
        }
        self.insert(ComObject::fresh(ptr, iid, ComDiscovery::Discovered))
    }

    /// 診断用オプションによる `QueryInterface(IID_IUnknown)` の結果で
    /// 同一性を確定する。`canonical` は返された IUnknown ポインタ。
    /// 対象が未登録なら何もしない。
    pub fn note_identity_confirmed(&mut self, ptr: u64, canonical: u64) {
        if canonical != 0 && self.objects.get(&ptr).is_some_and(|o| !o.destroyed) {
            self.note_query_interface(ptr, canonical, IID_IUNKNOWN, true);
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
                    let was_live = !o.destroyed;
                    o.destroyed = true;
                    if was_live {
                        self.note_retired();
                    }
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clones
            .insert(clone_addr, original_methods);
    }

    /// 複製 vtable の `index` 番目の元のメソッドポインタを引く。
    pub fn original(clone_addr: u64, index: u32) -> Option<u64> {
        Self::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clones
            .get(&clone_addr)
            .and_then(|m| m.get(index as usize).copied())
    }

    /// 複製 vtable の元のメソッド列全体を引く（テスト・診断用）。
    pub fn originals(clone_addr: u64) -> Option<Vec<u64>> {
        Self::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clones
            .get(&clone_addr)
            .cloned()
    }

    /// 登録済みの複製 vtable の数（テスト用）。
    pub fn len() -> usize {
        Self::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clones
            .len()
    }

    /// テスト用に登録を消す（実運用では呼ばない）。
    #[cfg(test)]
    pub fn clear_for_test() {
        Self::global()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clones
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::schema::schema_types;
    use shirusu_trace::schema::{LastErrorMeaning, SchemaRegistry};

    #[test]
    fn metadata_identifies_stream_without_enabling_unsafe_interception() {
        let iid = Guid::new(12, 0, 0, [192, 0, 0, 0, 0, 0, 0, 70]);
        assert_eq!(interface_name_for_iid(&iid), "IStream");
        assert!(interface_by_iid(&iid).is_none());
        let mut tracker = ComTracker::new();
        tracker.note_factory_result(123, iid, "CoCreateInstance");
        assert_eq!(tracker.lookup(123).unwrap().interface_name, "IStream");
        assert!(!tracker.lookup(123).unwrap().intercepted);
    }

    #[test]
    fn a_different_vptr_at_a_tracked_address_ends_the_record() {
        // P3-8: Release through an unpatched path, then another object at
        // the same address, must not be recorded under the old IID.
        let mut t = ComTracker::new();
        t.note_factory_result(0x5000, IID_ISHELL_LINK_W, "CoCreateInstance");
        assert!(t.confirm_vptr(0x5000, None), "no vptr known yet");
        t.note_iunknown_intercepted(0x5000, 0x7000, 1);
        assert!(t.confirm_vptr(0x5000, Some(0x7000)));
        assert!(t.instance_token(0x5000).is_some());
        assert!(!t.confirm_vptr(0x5000, Some(0x7100)));
        assert!(t.instance_token(0x5000).is_none(), "the record ended");
        assert_eq!(
            t.lookup(0x5000).unwrap().interception_skip_reason,
            Some("address-reused")
        );
        // The next discovery starts a fresh lifetime.
        t.note_factory_result(0x5000, IID_ISHELL_LINK_W, "CoCreateInstance");
        assert!(t.instance_token(0x5000).is_some());
    }

    #[test]
    fn retired_records_are_pruned_and_groups_stay_indexed() {
        // P2-6: Release(0) records no longer accumulate for the session.
        let mut t = ComTracker::new();
        let base = 0x10_0000u64;
        for i in 0..(MAX_RETIRED_COM_RECORDS as u64 + 1) {
            let ptr = base + i * 16;
            t.note_factory_result(ptr, IID_ISHELL_LINK_W, "CoCreateInstance");
            assert!(t.note_release(ptr, 0));
        }
        let live = 0x9000u64;
        t.note_factory_result(live, IID_ISHELL_LINK_W, "CoCreateInstance");
        assert_eq!(t.object_count(), 1, "retired records were pruned");
        assert_eq!(t.groups.len(), 1);
        assert_eq!(t.groups.values().map(Vec::len).sum::<usize>(), 1);
        assert!(t.lookup(live).is_some());
    }

    #[test]
    fn identity_confirmation_touches_only_its_groups() {
        let mut t = ComTracker::new();
        for i in 0..64u64 {
            let link = 0x1000 + i * 0x100;
            t.note_factory_result(link, IID_ISHELL_LINK_W, "CoCreateInstance");
            t.note_query_interface(link, link + 8, IID_IPERSIST_FILE, true);
        }
        // Confirm one object's identity through its IPersistFile face.
        t.note_query_interface(0x1008, 0x1000, IID_IUNKNOWN, true);
        for ptr in [0x1000, 0x1008] {
            let o = t.lookup(ptr).unwrap();
            assert_eq!(o.identity, 0x1000);
            assert!(o.identity_confirmed);
        }
        let other = t.lookup(0x1108).unwrap();
        assert_eq!(other.identity, 0x1100);
        assert!(!other.identity_confirmed);
        // Merging two groups re-indexes the members under one key.
        t.note_query_interface(0x1108, 0x1000, IID_IUNKNOWN, true);
        let merged = t.lookup(0x1100).unwrap();
        assert_eq!(merged.identity, 0x1000);
        let key = group_key(&t.lookup(0x1000).unwrap().identity_group);
        let mut members = t.groups[&key].clone();
        members.sort_unstable();
        assert_eq!(members, vec![0x1000, 0x1008, 0x1100, 0x1108]);
        let indexed: usize = t.groups.values().map(Vec::len).sum();
        assert_eq!(indexed, t.object_count());
    }

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
        assert_eq!(reg.len(), 4);
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
        assert_eq!(back.len(), 4);
        assert_eq!(back[3].value, TypedValue::Str("hresult".into()));
        assert_eq!(back[0].value, TypedValue::I32(0));
        assert_eq!(back[1].value, TypedValue::U64(0x9999));
        assert_eq!(back[2].value, TypedValue::U32(0));
    }

    #[test]
    fn method_return_kind_preserves_unsigned_refcounts_and_factory_hresult() {
        let method = com_method_leave_schema();
        assert_eq!(method.fields[0].name, "return_i32_bits");
        assert_eq!(method.fields[3].name, "return_kind");
        let types = schema_types(&method).unwrap();
        for index in [1, 2] {
            for count in [0, 1, 0x80000001, u32::MAX] {
                let values = com_method_leave_values_for(index, count as i32, 0, count);
                let decoded = decode_values(&types, &encode_com_leave(&values).unwrap()).unwrap();
                assert_eq!(decoded[0].value, TypedValue::I32(count as i32));
                assert_eq!(decoded[2].value, TypedValue::U32(count));
                assert_eq!(decoded[3].value, TypedValue::Str("refcount".into()));
            }
        }
        let query = com_method_leave_values_for(0, 0x80004002u32 as i32, 0, 0);
        assert_eq!(query[3].value, TypedValue::Str("hresult".into()));
        let unknown = com_method_leave_values_for(3, -1, 0, 0);
        assert_eq!(unknown[3].value, TypedValue::Str("opaque-32".into()));
        let factory = com_factory_leave_schema();
        assert_eq!(factory.fields.len(), 3);
        assert_eq!(factory.fields[0].name, "hresult");
        let values = com_factory_leave_values(0x80004002u32 as i32, 0, 0);
        assert_eq!(
            decode_values(
                &schema_types(&factory).unwrap(),
                &encode_com_factory_leave(&values).unwrap()
            )
            .unwrap(),
            values
        );
    }

    #[test]
    fn raw_arg_slots_preserve_all_factory_arguments() {
        let slots = raw_arg_slots(&[1, 2, 3, 4, 5]);
        assert_eq!(slots.len(), 5 * std::mem::size_of::<usize>());
        assert!(slots.ends_with(&5usize.to_le_bytes()));
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
    fn unloaded_implementation_retires_identity_without_fabricating_release() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "fixture");
        let old = t.instance_token(0x1000).unwrap();
        t.note_add_ref(0x1000, 7);
        t.note_iunknown_intercepted(0x1000, 0x7000, 12);
        let object = t.lookup(0x1000).unwrap();
        assert!(object.iunknown_intercepted);
        assert_eq!(
            object.interception_skip_reason,
            Some("remaining-methods-unsupported")
        );
        assert_eq!(object.cloned_vtable, None);
        t.note_interception_skipped_with_reason(0x1000, "iunknown-installation-incomplete");
        assert_eq!(t.lookup(0x1000).unwrap().iunknown_slot, Some(12));
        t.note_implementation_unloaded(0x1000);
        assert!(!t.instance_matches(0x1000, &old));
        assert_eq!(t.lookup(0x1000).unwrap().refcount, None);
        t.note_factory_result(0x1000, IID_IUNKNOWN, "fixture");
        assert!(!t.instance_matches(0x1000, &old));
        let fresh = t.lookup(0x1000).unwrap();
        assert!(!fresh.iunknown_intercepted);
        assert_eq!(fresh.iunknown_slot, None);
        t.note_iunknown_intercepted(0x1000, 0x7000, 13);
        assert_eq!(t.lookup(0x1000).unwrap().interception_skip_reason, None);
    }

    #[test]
    fn recycled_factory_pointer_discards_old_lifetime_and_hook_metadata() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        t.note_intercepted(0x1000, 0x7000, 0x8000, vec![1, 2, 3]);
        t.note_release(0x1000, 0);
        t.note_factory_result(0x1000, IID_IPERSIST_FILE, "CoCreateInstance");
        let object = t.lookup(0x1000).unwrap();
        assert!(!object.destroyed);
        assert_eq!(object.iid, IID_IPERSIST_FILE);
        assert_eq!(object.refcount, None);
        assert!(!object.intercepted);
        assert_eq!(object.original_vtable, 0);
        assert_eq!(object.cloned_vtable, None);
        assert!(object.original_methods.is_empty());
        assert_eq!(t.live_count(), 1);
    }

    #[test]
    fn recycled_pointer_does_not_merge_previous_lifetimes_aliases() {
        let mut t = ComTracker::new();
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        t.note_query_interface(0x1000, 0x2000, IID_IPERSIST_FILE, true);
        t.note_release(0x1000, 0);
        t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
        t.note_query_interface(0x1000, 0x3000, IID_IUNKNOWN, true);
        assert_eq!(t.lookup(0x1000).unwrap().identity, 0x3000);
        assert_eq!(t.lookup(0x3000).unwrap().identity, 0x3000);
        let old_alias = t.lookup(0x2000).unwrap();
        assert_eq!(old_alias.identity, 0x1000);
        assert!(!old_alias.identity_confirmed);
    }

    #[test]
    fn every_discovery_path_replaces_retired_pointer_metadata() {
        for mode in 0..4 {
            let mut t = ComTracker::new();
            t.note_factory_result(0x1000, IID_ISHELL_LINK_W, "CoCreateInstance");
            let old = t.instance_token(0x1000).unwrap();
            t.note_interception_skipped(0x1000);
            t.note_release(0x1000, 0);
            match mode {
                0 => {
                    t.note_discovered(0x1000, IID_IPERSIST_FILE);
                }
                1 => {
                    t.note_method_returned(0x1000, IID_IPERSIST_FILE, 0x2000, "GetSomething");
                }
                2 => {
                    t.note_query_interface(0x2000, 0x1000, IID_IPERSIST_FILE, true);
                }
                _ => {
                    t.note_query_interface(0x2000, 0x1000, IID_IUNKNOWN, true);
                }
            }
            let current = t.lookup(0x1000).unwrap();
            assert!(!current.destroyed);
            assert_eq!(current.interception_skip_reason, None);
            assert!(!t.instance_matches(0x1000, &old));
            assert!(t.instance_matches(0x1000, &t.instance_token(0x1000).unwrap()));
        }
    }

    #[test]
    fn null_discovery_is_not_an_object() {
        let mut t = ComTracker::new();
        t.note_factory_result(0, IID_IUNKNOWN, "CoCreateInstance");
        t.note_discovered(0, IID_IUNKNOWN);
        assert_eq!(
            t.note_method_returned(0, IID_IUNKNOWN, 1, "GetSomething"),
            None
        );
        assert_eq!(t.object_count(), 0);
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
