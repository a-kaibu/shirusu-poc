//! コールバックイベントの識別子と Schema（Capture と Host が共有する契約）。

use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, CaptureTiming, Ty, ValueKind};

/// コールバックイベントの api_id。API 表（api.rs）の ID 空間とは別の
/// 予約値（COM メソッドイベント 1000、WinRT アクティベーション 1001 の次）。
/// TraceEvent.api_id に載る。
pub const CALLBACK_API_ID: u32 = 1002;
/// コールバックの enter / leave Schema の ID。COM（10001 / 10002）・
/// WinRT（10011 / 10012）とは別の予約ブロック。
pub const CALLBACK_ENTER_SCHEMA_ID: u32 = 10_021;
pub const CALLBACK_LEAVE_SCHEMA_ID: u32 = 10_022;

// ---- コールバックイベントの Schema ----

fn before() -> u32 {
    CaptureTiming::Before.flags()
}
fn after() -> u32 {
    CaptureTiming::After.flags()
}

/// コールバックの enter Schema。
///
/// フィールド:
/// - `hwnd` (U64, Pointer): メッセージを受け取るウィンドウ。
/// - `kind` (U32): コールバック種別コード（`CallbackKind::code`）。
/// - `message` (U32): WM_* メッセージ番号。
/// - `wparam` (U64): WndProc の wParam（生値）。
/// - `lparam` (I64): WndProc の lParam（生値）。
/// - `proc` (U64, Pointer): 元の WndProc のアドレス（ラッパーではない）。
pub fn callback_enter_schema() -> SchemaDef {
    let mut def = make_schema(
        CALLBACK_ENTER_SCHEMA_ID,
        "callback!enter",
        vec![
            (
                "hwnd".to_string(),
                Ty::U64,
                ValueKind::Pointer.flags() | before(),
            ),
            (
                "kind".to_string(),
                Ty::U32,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "message".to_string(),
                Ty::U32,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "wparam".to_string(),
                Ty::U64,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "lparam".to_string(),
                Ty::I64,
                ValueKind::Scalar.flags() | before(),
            ),
            (
                "proc".to_string(),
                Ty::U64,
                ValueKind::Pointer.flags() | before(),
            ),
        ],
    );
    def.annotation = "L1 (callback): Windows-to-app callback entry. \
        proc is the original WndProc address, not the wrapper"
        .to_string();
    def
}

/// コールバックの leave Schema。
///
/// フィールド:
/// - `result` (I64): WndProc の戻り値（LRESULT）。
pub fn callback_leave_schema() -> SchemaDef {
    let mut def = make_schema(
        CALLBACK_LEAVE_SCHEMA_ID,
        "callback!leave",
        vec![(
            "result".to_string(),
            Ty::I64,
            ValueKind::Scalar.flags() | after(),
        )],
    );
    def.annotation = "L1 (callback): LRESULT returned by the original WndProc".to_string();
    def
}

/// Host がセッション開始時に登録するコールバック用 Schema（enter / leave）。
pub fn callback_schemas() -> Vec<SchemaDef> {
    vec![callback_enter_schema(), callback_leave_schema()]
}
