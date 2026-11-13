//! WinRT アクティベーションイベントの識別子と Schema（Capture と Host が共有する契約）。

use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, CaptureTiming, Ty, ValueKind};

// ---- WinRT アクティベーションイベントの Schema ----

/// WinRT アクティベーション呼び出しイベントの api_id。COM メソッド
/// イベント（1000）とは別の予約値。
pub const WINRT_ACTIVATION_API_ID: u32 = 1001;
/// WinRT アクティベーション呼び出しの enter / leave Schema の ID。
/// COM メソッドイベント（10001 / 10002）とは別の予約ブロック。
pub const WINRT_ACTIVATION_ENTER_SCHEMA_ID: u32 = 10_011;
pub const WINRT_ACTIVATION_LEAVE_SCHEMA_ID: u32 = 10_012;

fn before() -> u32 {
    CaptureTiming::Before.flags()
}
fn after() -> u32 {
    CaptureTiming::After.flags()
}

/// WinRT アクティベーション呼び出しの enter Schema。
///
/// フィールド:
/// - `object` (U64, Pointer): 常に 0（enter 時点では返されるポインタが
///   まだ無い。COM Factory イベントと同じ）。
/// - `class_name` (Str): HSTRING から読んだランタイムクラス名
///   （例 `Windows.Foundation.Uri`）。読めなければ空。
/// - `method_name` (Str): `RoActivateInstance` /
///   `RoGetActivationFactory`。
/// - `args` (Bytes): 引数の生スロット値列（HSTRING ポインタと out
///   ポインタ。上限は 4 スロット。ポインタの中身は読まない）。
pub fn winrt_activation_enter_schema() -> SchemaDef {
    let mut def = make_schema(
        WINRT_ACTIVATION_ENTER_SCHEMA_ID,
        "winrt!activation/enter",
        vec![
            (
                "object".to_string(),
                Ty::U64,
                ValueKind::Pointer.flags() | before(),
            ),
            (
                "class_name".to_string(),
                Ty::Str,
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
        ],
    );
    def.annotation =
        "L1 (WinRT): activation call. class_name is read from the HSTRING argument".to_string();
    def
}

/// WinRT アクティベーション呼び出しの leave Schema。
///
/// フィールド:
/// - `hresult` (I32): アクティベーション関数の HRESULT。
/// - `returned_object` (U64, CreatedObject): 成功時に返された
///   インターフェイスのポインタ。それ以外は 0。
/// - `refcount` (U32): 常に 0（「対象外」を表す。COM leave と同じ形）。
pub fn winrt_activation_leave_schema() -> SchemaDef {
    let mut def = make_schema(
        WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
        "winrt!activation/leave",
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
    def.annotation =
        "L1 (WinRT): hresult is the activation result; returned_object is set on success"
            .to_string();
    def
}

/// Host がセッション開始時に登録する WinRT 用 Schema（enter / leave）。
pub fn winrt_schemas() -> Vec<SchemaDef> {
    vec![
        winrt_activation_enter_schema(),
        winrt_activation_leave_schema(),
    ]
}
