//! コールバックの別種イベント化（L16・overview 記録境界とモジュール分類節）。
//!
//! Windows からアプリへ入るコールバック（WndProc など）を、API 呼び出し
//! とは別種のイベントとして記録する。検出は WndProc のラップで行う：
//! `RegisterClassExW/A` で登録されるクラスプロシージャと、
//! `SetWindowLongPtrW/A (GWLP_WNDPROC)` で差し替えられるプロシージャを、
//! shirusu のラッパーへすり替える。ラッパーはコールバック enter/leave
//! を記録してから元のプロシージャを呼ぶ。コールバック中の API 呼び出しは
//! 呼出スタックに積まれたコールバックイベントを親として入れ子に記録される
//! （A43 / C18 の仕組みをそのまま使う）。
//!
//! ラッパーはスロット表（`CallbackProcTable`）で元のプロシージャと
//! 1 対 1 に対応づける。ラッパー関数自体はスロット番号を固定で持つため、
//! ディスパッチ時の引数だけでは判別できない「どの元のプロシージャを呼ぶか」
//! がスロット番号で決まる。同じ元のプロシージャは同じスロットを再利用し、
//! スロットが尽きた場合はラップせず素通しにする（fail-open）。
//!
//! 透明性：
//! - `RegisterClassEx` にはアプリが渡した構造体のコピーを渡す（アプリの
//!   構造体自体は書き換えない）。コピー内の `lpfnWndProc` だけをラッパーへ
//!   すり替える。
//! - `SetWindowLongPtr` は以前のプロシージャを返すが、以前の値が shirusu
//!   のラッパーだった場合は元のプロシージャへ解決して返す（アプリは
//!   ラッパーの存在を観測しない）。
//!
//! 制限（将来の拡張）：
//! - 検出は WndProc のみ。DialogProc（`DialogBoxIndirectParam` 等）、
//!   タイマープロシージャ、列挙コールバックは未対応。`CallbackKind` に
//!   種別コードを持たせてあるため、形式を変えずに追加できる。
//! - `RegisterClassW/A`（旧式のクラス登録）と `SetWindowLongW/A` は
//!   フックしない。`GetWindowLongPtrW/A` もフックしないため、アプリが
//!   現在のプロシージャを読み戻すとラッパーのアドレスが見える（その値を
//!   そのまま `SetWindowLongPtr` へ渡した場合は再利用して二重ラップしない）。
//! - ラップできる WndProc は最大 `CALLBACK_PROC_SLOTS` 件（32）。超えた分は
//!   ラップせず、コールバックの記録だけが無い（アプリの動作は変わらない）。

use shirusu_trace::compact::encode_values;
use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{
    make_schema, schema_types, CaptureTiming, CapturedValue, Ty, TypedValue, ValueKind,
};
use shirusu_trace::CompactError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// コールバックイベントの api_id。API 表（api.rs）の ID 空間とは別の
/// 予約値（COM メソッドイベント 1000、WinRT アクティベーション 1001 の次）。
/// TraceEvent.api_id に載る。
pub const CALLBACK_API_ID: u32 = 1002;
/// コールバックの enter / leave Schema の ID。COM（10001 / 10002）・
/// WinRT（10011 / 10012）とは別の予約ブロック。
pub const CALLBACK_ENTER_SCHEMA_ID: u32 = 10_021;
pub const CALLBACK_LEAVE_SCHEMA_ID: u32 = 10_022;
/// コールバック検出フックの数（RegisterClassExW/A + SetWindowLongPtrW/A）。
pub const CALLBACK_HOOK_COUNT: usize = 4;
/// コールバック検出フックの Inline Hook を報告するときの ID 基準値
/// （`InlineHook.api_id` 用。COM Factory / WinRT の予約値とは別の予約値）。
pub const CALLBACK_HOOK_REPORT_ID_BASE: u32 = 0xC002_0000;
/// `GWLP_WNDPROC`（`SetWindowLongPtr` の nIndex）。
pub const GWLP_WNDPROC: i32 = -4;
/// WNDCLASS / WNDCLASSEX 構造体の `lpfnWndProc` フィールドのオフセット。
/// `cbSize` (u32) + `style` (u32) の後で、A/W・x86/x64 共通。
pub const WNDPROC_FIELD_OFFSET: usize = 8;
/// ラップする WndProc の最大同時数（スロット表の容量）。
pub const CALLBACK_PROC_SLOTS: usize = 32;
/// WNDCLASSEX の最大バイト数（x64: 80、x86: 48）。構造体コピー時の上限。
pub const MAX_WNDCLASSEX_BYTES: usize = 80;

// ---- コールバック種別 ----

/// コールバックの種別。現行は WndProc のみ。種別コードは enter Schema の
/// `kind` フィールドに載り、将来の種別追加で形式は変わらない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackKind {
    WndProc,
}

impl CallbackKind {
    pub const fn code(self) -> u32 {
        match self {
            Self::WndProc => 1,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WndProc => "WndProc",
        }
    }

    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::WndProc),
            _ => None,
        }
    }
}

// ---- 検出フックの定義表 ----

/// コールバック検出フックの Detour のスロット番号。
pub const CALLBACK_HOOK_REGISTER_CLASS_EX_W: usize = 0;
pub const CALLBACK_HOOK_REGISTER_CLASS_EX_A: usize = 1;
pub const CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W: usize = 2;
pub const CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A: usize = 3;

/// コールバック検出フック 1 件の定義。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackHookDef {
    pub module: &'static str,
    pub function: &'static str,
}

pub const CALLBACK_HOOKS: &[CallbackHookDef] = &[
    CallbackHookDef {
        module: "user32.dll",
        function: "RegisterClassExW",
    },
    CallbackHookDef {
        module: "user32.dll",
        function: "RegisterClassExA",
    },
    CallbackHookDef {
        module: "user32.dll",
        function: "SetWindowLongPtrW",
    },
    CallbackHookDef {
        module: "user32.dll",
        function: "SetWindowLongPtrA",
    },
];

pub fn callback_hook_by_name(
    module: &str,
    function: &str,
) -> Option<(usize, &'static CallbackHookDef)> {
    CALLBACK_HOOKS
        .iter()
        .enumerate()
        .find(|(_, d)| d.module.eq_ignore_ascii_case(module) && d.function == function)
}

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

/// enter 値列を作る。
pub fn callback_enter_values(
    hwnd: u64,
    kind: CallbackKind,
    message: u32,
    wparam: u64,
    lparam: i64,
    proc_addr: u64,
) -> Vec<CapturedValue> {
    vec![
        CapturedValue::captured(TypedValue::U64(hwnd)),
        CapturedValue::captured(TypedValue::U32(kind.code())),
        CapturedValue::captured(TypedValue::U32(message)),
        CapturedValue::captured(TypedValue::U64(wparam)),
        CapturedValue::captured(TypedValue::I64(lparam)),
        CapturedValue::captured(TypedValue::U64(proc_addr)),
    ]
}

/// leave 値列を作る。
pub fn callback_leave_values(result: i64) -> Vec<CapturedValue> {
    vec![CapturedValue::captured(TypedValue::I64(result))]
}

pub fn encode_callback_enter(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types =
        schema_types(&callback_enter_schema()).expect("callback enter schema is well-formed");
    encode_values(&types, values)
}

pub fn encode_callback_leave(values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types =
        schema_types(&callback_leave_schema()).expect("callback leave schema is well-formed");
    encode_values(&types, values)
}

// ---- WndProc スロット表 ----

/// 元の WndProc とラッパーの対応表（プロセス全体。セッションをまたいで残る。
/// 終了手順では WndProc のラップを外さないため、セッション終了後にアプリが
/// メッセージを受けてもラッパーが元のプロシージャを引ける必要がある。
/// その場合はランタイムが無いため素通しで呼ぶ（記録はしない）。
/// 登録は解放しない（ComCloneRegistry と同じ理由）。
/// スロットは元のプロシージャのアドレスを保持し、0 = 空き。
/// ラッパー関数自体は engine 側がスロット番号ごとに用意し、この表は
/// スロット番号 → 元のプロシージャの対応だけを持つ。
#[derive(Debug)]
pub struct CallbackProcTable<const N: usize> {
    slots: [AtomicUsize; N],
}

impl<const N: usize> CallbackProcTable<N> {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    /// 元の WndProc をスロットへ登録し、スロット番号を返す。既に登録済みの
    /// 元プロシージャは既存のスロットを返す（重複登録・二重ラップを防ぐ）。
    /// 空きが無ければ None を返す（呼び出し側はラップせず素通しすること）。
    /// 0 は登録しない。並行する同一プロシージャの登録は best-effort で
    /// 重複しうる（どちらも正しい対応であり、実害は無い）。
    pub fn wrap(&self, original: usize) -> Option<usize> {
        if original == 0 {
            return None;
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.load(Ordering::Acquire) == original {
                return Some(i);
            }
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(0, original, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(i);
            }
        }
        None
    }

    /// スロット番号から元の WndProc のアドレスを引く。空き・範囲外は None。
    pub fn original(&self, slot: usize) -> Option<usize> {
        self.slots.get(slot).and_then(|s| {
            let v = s.load(Ordering::Acquire);
            if v == 0 {
                None
            } else {
                Some(v)
            }
        })
    }

    /// 登録済みの WndProc の数（テスト・診断用）。
    pub fn wrapped_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.load(Ordering::Acquire) != 0)
            .count()
    }

    /// テスト用に登録を消す（実運用では呼ばない）。
    #[cfg(test)]
    pub fn clear_for_test(&self) {
        for s in &self.slots {
            s.store(0, Ordering::Release);
        }
    }
}

impl<const N: usize> Default for CallbackProcTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// プロセス全体の WndProc スロット表。
pub fn callback_procs() -> &'static CallbackProcTable<CALLBACK_PROC_SLOTS> {
    static TABLE: OnceLock<CallbackProcTable<CALLBACK_PROC_SLOTS>> = OnceLock::new();
    TABLE.get_or_init(CallbackProcTable::new)
}

// ---- Detour のための純粋ヘルパー ----

/// WNDCLASS(E)X 構造体のバイト列から `lpfnWndProc` を読み、`wrapper` で
/// 置き換えたコピーを返す。戻り値は (元のプロシージャ, 置き換え後のバイト列)。
/// 構造体が短い（`lpfnWndProc` が読めない）場合や、元のプロシージャが
/// 0 の場合は None を返す（呼び出し側はラップせず素通しすること）。
pub fn wrap_wndproc_in_class(bytes: &[u8], wrapper: usize) -> Option<(usize, Vec<u8>)> {
    let width = std::mem::size_of::<usize>();
    let end = WNDPROC_FIELD_OFFSET.checked_add(width)?;
    if bytes.len() < end {
        return None;
    }
    let original = usize::from_le_bytes(bytes[WNDPROC_FIELD_OFFSET..end].try_into().ok()?);
    if original == 0 {
        return None;
    }
    let mut replaced = bytes.to_vec();
    replaced[WNDPROC_FIELD_OFFSET..end].copy_from_slice(&wrapper.to_le_bytes());
    Some((original, replaced))
}

/// `SetWindowLongPtr` の引数が WndProc の差し替えかどうか。
/// `GWLP_WNDPROC` かつ新しいプロシージャが非 0 の場合に真。
pub fn should_wrap_set_window_long(n_index: i32, new_proc: usize) -> bool {
    n_index == GWLP_WNDPROC && new_proc != 0
}

/// `SetWindowLongPtr` の戻り値（以前のプロシージャ）が shirusu のラッパー
/// だった場合に、アプリへ返す元のプロシージャへ解決する。ラッパーで
/// なければそのまま返す（0 もそのまま）。
pub fn resolve_prev_proc(
    prev: usize,
    original_for_wrapper: impl Fn(usize) -> Option<usize>,
) -> usize {
    if prev == 0 {
        return 0;
    }
    original_for_wrapper(prev).unwrap_or(prev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::schema::{SchemaRegistry, TypedValue};

    #[test]
    fn callback_ids_are_reserved_and_distinct() {
        assert_eq!(CALLBACK_API_ID, 1002);
        assert_eq!(CALLBACK_ENTER_SCHEMA_ID, 10_021);
        assert_eq!(CALLBACK_LEAVE_SCHEMA_ID, 10_022);
        // COM (1000 / 10001 / 10002)・WinRT (1001 / 10011 / 10012) と
        // 衝突しない。
        assert_ne!(CALLBACK_API_ID, crate::com::COM_METHOD_API_ID);
        assert_ne!(CALLBACK_API_ID, crate::winrt::WINRT_ACTIVATION_API_ID);
        assert_ne!(
            CALLBACK_ENTER_SCHEMA_ID,
            crate::com::COM_METHOD_ENTER_SCHEMA_ID
        );
        assert_ne!(
            CALLBACK_LEAVE_SCHEMA_ID,
            crate::com::COM_METHOD_LEAVE_SCHEMA_ID
        );
        assert_ne!(
            CALLBACK_ENTER_SCHEMA_ID,
            crate::winrt::WINRT_ACTIVATION_ENTER_SCHEMA_ID
        );
        assert_ne!(
            CALLBACK_LEAVE_SCHEMA_ID,
            crate::winrt::WINRT_ACTIVATION_LEAVE_SCHEMA_ID
        );
        assert_eq!(CALLBACK_HOOK_COUNT, 4);
        assert_eq!(GWLP_WNDPROC, -4);
        assert_eq!(WNDPROC_FIELD_OFFSET, 8);
    }

    #[test]
    fn callback_hook_table_lists_four_hooks() {
        assert_eq!(CALLBACK_HOOKS.len(), CALLBACK_HOOK_COUNT);
        assert_eq!(
            callback_hook_by_name("user32.dll", "RegisterClassExW").map(|(i, _)| i),
            Some(CALLBACK_HOOK_REGISTER_CLASS_EX_W)
        );
        assert_eq!(
            callback_hook_by_name("USER32.DLL", "RegisterClassExA").map(|(i, _)| i),
            Some(CALLBACK_HOOK_REGISTER_CLASS_EX_A)
        );
        assert_eq!(
            callback_hook_by_name("user32.dll", "SetWindowLongPtrW").map(|(i, _)| i),
            Some(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W)
        );
        assert_eq!(
            callback_hook_by_name("user32.dll", "SetWindowLongPtrA").map(|(i, _)| i),
            Some(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A)
        );
        assert!(callback_hook_by_name("user32.dll", "RegisterClassW").is_none());
        assert!(callback_hook_by_name("user32.dll", "GetWindowLongPtrW").is_none());
    }

    #[test]
    fn callback_kind_codes_roundtrip() {
        assert_eq!(CallbackKind::WndProc.code(), 1);
        assert_eq!(CallbackKind::WndProc.name(), "WndProc");
        assert_eq!(CallbackKind::from_code(1), Some(CallbackKind::WndProc));
        assert_eq!(CallbackKind::from_code(99), None);
        assert_eq!(CallbackKind::from_code(0), None);
    }

    #[test]
    fn callback_schemas_register_cleanly() {
        let mut reg = SchemaRegistry::new();
        for def in callback_schemas() {
            reg.register(def).expect("callback schemas must register");
        }
        assert_eq!(reg.len(), 2);
        // 再登録は冪等。
        for def in callback_schemas() {
            reg.register(def).expect("re-register is idempotent");
        }
        // API 表の Schema ID と衝突しない。
        let api_ids: std::collections::HashSet<u32> = crate::api::all_schemas()
            .iter()
            .map(|s| s.schema_id)
            .collect();
        assert!(!api_ids.contains(&CALLBACK_ENTER_SCHEMA_ID));
        assert!(!api_ids.contains(&CALLBACK_LEAVE_SCHEMA_ID));
    }

    #[test]
    fn callback_values_encode_decode_roundtrip() {
        // WM_CLOSE (0x0010) を受ける WndProc の enter。
        let enter = callback_enter_values(
            0x0000_0000_0001_0020,
            CallbackKind::WndProc,
            0x0010,
            0,
            0,
            0x0000_7FFA_1234_5678,
        );
        let bytes = encode_callback_enter(&enter).expect("encode enter");
        let types = shirusu_trace::schema::schema_types(&callback_enter_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode enter");
        assert_eq!(back.len(), 6);
        assert_eq!(back[0].value, TypedValue::U64(0x0000_0000_0001_0020));
        assert_eq!(back[1].value, TypedValue::U32(1));
        assert_eq!(back[2].value, TypedValue::U32(0x0010));
        assert_eq!(back[3].value, TypedValue::U64(0));
        assert_eq!(back[4].value, TypedValue::I64(0));
        assert_eq!(back[5].value, TypedValue::U64(0x0000_7FFA_1234_5678));

        let leave = callback_leave_values(0);
        let bytes = encode_callback_leave(&leave).expect("encode leave");
        let types = shirusu_trace::schema::schema_types(&callback_leave_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode leave");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].value, TypedValue::I64(0));
    }

    #[test]
    fn proc_table_wrap_dedupes_and_exhausts() {
        // 容量 2 の表で枯渇まで見る（実表は 32）。
        let t = CallbackProcTable::<2>::new();
        assert_eq!(t.wrapped_count(), 0);
        assert_eq!(t.wrap(0), None, "null proc is never wrapped");
        assert_eq!(t.wrap(0x1000), Some(0));
        assert_eq!(t.wrap(0x1000), Some(0), "same proc reuses its slot");
        assert_eq!(t.wrap(0x2000), Some(1));
        assert_eq!(t.wrap(0x3000), None, "no free slot left (fail-open)");
        assert_eq!(t.original(0), Some(0x1000));
        assert_eq!(t.original(1), Some(0x2000));
        assert_eq!(t.original(2), None);
        assert_eq!(t.wrapped_count(), 2);
    }

    #[test]
    fn wrap_wndproc_in_class_replaces_proc() {
        // WNDCLASSEX 相当の 80 バイト。lpfnWndProc はオフセット 8。
        let mut bytes = vec![0u8; 80];
        bytes[0] = 80; // cbSize
        bytes[8..8 + std::mem::size_of::<usize>()].copy_from_slice(&0x1234_5678usize.to_le_bytes());
        bytes[16] = 0xAB; // 他のフィールドは変わらないこと
        let (original, replaced) =
            wrap_wndproc_in_class(&bytes, 0xAAAA_BBBB).expect("wrap succeeds");
        assert_eq!(original, 0x1234_5678);
        assert_eq!(replaced.len(), 80);
        assert_eq!(replaced[0], 80);
        assert_eq!(replaced[16], 0xAB);
        assert_eq!(
            usize::from_le_bytes(
                replaced[8..8 + std::mem::size_of::<usize>()]
                    .try_into()
                    .unwrap()
            ),
            0xAAAA_BBBB
        );
        // 構造体が短い・proc が 0 の場合は素通し（None）。
        assert!(wrap_wndproc_in_class(&bytes[..8], 0xAAAA_BBBB).is_none());
        let mut null_proc = bytes.clone();
        null_proc[8..8 + std::mem::size_of::<usize>()].fill(0);
        assert!(wrap_wndproc_in_class(&null_proc, 0xAAAA_BBBB).is_none());
    }

    #[test]
    fn should_wrap_set_window_long_only_for_gwlp_wndproc() {
        assert!(should_wrap_set_window_long(GWLP_WNDPROC, 0x1000));
        assert!(!should_wrap_set_window_long(GWLP_WNDPROC, 0));
        assert!(!should_wrap_set_window_long(0, 0x1000));
        assert!(!should_wrap_set_window_long(-3, 0x1000));
        assert!(!should_wrap_set_window_long(8, 0x1000));
    }

    #[test]
    fn resolve_prev_proc_unwraps_known_wrappers() {
        // ラッパー 0xB000 を元の 0x1234 へ解決する。
        let resolve = |prev: usize| {
            resolve_prev_proc(prev, |w| if w == 0xB000usize { Some(0x1234) } else { None })
        };
        assert_eq!(resolve(0xB000), 0x1234);
        assert_eq!(resolve(0x5678), 0x5678, "unknown proc passes through");
        assert_eq!(resolve(0), 0);
    }
}
