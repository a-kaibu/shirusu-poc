//! COM メソッド・Factory イベントの識別子と Schema（Capture と Host が共有する契約）。

use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, CaptureTiming, Ty, ValueKind};

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
pub const COM_FACTORY_ENTER_SCHEMA_ID: u32 = 10_007;
pub const COM_FACTORY_LEAVE_SCHEMA_ID: u32 = 10_008;

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

/// COM method result with explicit return interpretation. `return_i32_bits`
/// preserves all 32 bits; only QueryInterface is classified as HRESULT by the
/// method-index adapter. AddRef/Release have an unsigned `refcount` result.
fn com_result_fields(return_name: &str) -> Vec<(String, Ty, u32)> {
    vec![
        (
            return_name.into(),
            Ty::I32,
            ValueKind::Scalar.flags() | after(),
        ),
        (
            "returned_object".into(),
            Ty::U64,
            ValueKind::CreatedObject.flags() | after(),
        ),
        (
            "refcount".into(),
            Ty::U32,
            ValueKind::Scalar.flags() | after(),
        ),
    ]
}
pub fn com_method_leave_schema() -> SchemaDef {
    let mut fields = com_result_fields("return_i32_bits");
    fields.push((
        "return_kind".into(),
        Ty::Str,
        ValueKind::Scalar.flags() | after(),
    ));
    let mut def = make_schema(COM_METHOD_LEAVE_SCHEMA_ID, "com!method/leave", fields);
    def.annotation = "L1 (COM): return_kind distinguishes hresult, refcount and opaque-32; \
        return_i32_bits preserves raw 32-bit bits, refcount is ULONG for AddRef/Release"
        .into();
    def
}

/// Host がセッション開始時に登録する COM 用 Schema（enter / leave）。
pub fn com_schemas() -> Vec<SchemaDef> {
    vec![
        com_method_enter_schema(),
        com_method_leave_schema(),
        com_factory_enter_schema(),
        com_factory_leave_schema(),
    ]
}

pub fn com_factory_enter_schema() -> SchemaDef {
    let fields = [
        ("clsid", Ty::Bytes, ValueKind::Scalar),
        ("iid", Ty::Bytes, ValueKind::Scalar),
        ("context", Ty::U32, ValueKind::Scalar),
        ("method_name", Ty::Str, ValueKind::Scalar),
        ("outer", Ty::U64, ValueKind::Handle),
        ("server_info", Ty::U64, ValueKind::Pointer),
        ("output_address", Ty::U64, ValueKind::Pointer),
        ("clsid_address", Ty::U64, ValueKind::Pointer),
        ("iid_address", Ty::U64, ValueKind::Pointer),
    ];
    let mut schema = make_schema(
        COM_FACTORY_ENTER_SCHEMA_ID,
        "com!factory/enter",
        fields
            .into_iter()
            .map(|(n, t, k)| (n.into(), t, k.flags() | before()))
            .collect(),
    );
    schema.annotation =
        "COM factory: GUID contents and context captured; server_info pointee is not expanded"
            .into();
    schema
}
pub fn com_factory_leave_schema() -> SchemaDef {
    let mut def = make_schema(
        COM_FACTORY_LEAVE_SCHEMA_ID,
        "com!factory/leave",
        com_result_fields("hresult"),
    );
    def.annotation =
        "L1 (COM factory): HRESULT and returned interface; refcount is not observed".into();
    def
}
