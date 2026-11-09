//! フック対象 API の定義表。Phase 3 の初期 API セットはファイル I/O の
//! 4 API に絞り、パイプライン全体（フック → 型付き取得 → Compact Binary
//! → 公開 Trace）を通すことを優先する（GOAL.md Phase 3 の定義）。
//!
//! Schema ID はファイル内連番であり、Agent 側（取得）と Host 側
//! （Trace への Schema 登録）で同じ定義表から同じ順序で割り当てるため、
//! この表の並びが ID を決める。並びを変えることは既存 Trace の意味を
//! 変えるため、API の追加は末尾への追加のみとする。
//!
//! 観測レベル（overview の L0〜L4）との対応:
//! - 全 API 共通で L1（型付き引数・戻り値・GetLastError の捕捉）。
//! - CreateFileW はパス文字列を復元するため L2。返した HANDLE の生値は
//!   後続イベントの引数と突き合わせられるが、Object ID の割当はまだ
//!   行わないため L3 は「相関可能」の部分達成に留まる。
//! - ReadFile は呼び出し後の出力バッファ内容、WriteFile は呼び出し前の
//!   入力バッファ内容を上限付きで復元するため L2。
//! - CloseHandle は L1（対象 HANDLE の生値で CreateFileW の戻り値と
//!   相関できる）。

use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, Ty, ValueKind};

pub const API_CREATE_FILE_W: u32 = 1;
pub const API_READ_FILE: u32 = 2;
pub const API_WRITE_FILE: u32 = 3;
pub const API_CLOSE_HANDLE: u32 = 4;

/// 1 API の定義。`enter_fields` / `leave_fields` は Compact Binary の
/// 値列の順序そのものである（Schema が型と順序を定める）。各
/// フィールドは型に加えて意味種別 (ValueKind) を持ち、Schema の
/// flags へ格納される（比較エンジンは型ではなく意味で正規化する。
/// レビュー #4 の #7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiDef {
    pub api_id: u32,
    /// インポート元 DLL のファイル名（例 "kernel32.dll"）。IAT 照合は
    /// 大文字小文字と ".dll" の有無を吸収する。
    pub module: &'static str,
    pub function: &'static str,
    /// overview の観測レベル（この API の取得が到達する深さ）。
    pub level: u8,
    /// 到達範囲と未達部分の正直な注記。SchemaDef.annotation へ写す。
    pub level_note: &'static str,
    pub enter_fields: &'static [(&'static str, Ty, ValueKind)],
    pub leave_fields: &'static [(&'static str, Ty, ValueKind)],
}

impl ApiDef {
    /// ファイル内 Schema ID: 表の順に enter = 2n-1, leave = 2n。
    pub fn enter_schema_id(&self) -> u32 {
        (self.api_id - 1) * 2 + 1
    }
    pub fn leave_schema_id(&self) -> u32 {
        (self.api_id - 1) * 2 + 2
    }
    pub fn schema_base_name(&self) -> String {
        let stem = self.module.strip_suffix(".dll").unwrap_or(self.module);
        format!("{stem}!{}", self.function)
    }
    pub fn enter_schema(&self) -> SchemaDef {
        let mut def = make_schema(
            self.enter_schema_id(),
            &format!("{}/enter", self.schema_base_name()),
            self.enter_fields
                .iter()
                .map(|(n, t, k)| (n.to_string(), *t, k.flags()))
                .collect(),
        );
        def.annotation = format!("L{} (enter): {}", self.level, self.level_note);
        def
    }
    pub fn leave_schema(&self) -> SchemaDef {
        let mut def = make_schema(
            self.leave_schema_id(),
            &format!("{}/leave", self.schema_base_name()),
            self.leave_fields
                .iter()
                .map(|(n, t, k)| (n.to_string(), *t, k.flags()))
                .collect(),
        );
        def.annotation = format!("L{} (leave): {}", self.level, self.level_note);
        def
    }
}

const HANDLE: Ty = Ty::U64; // HANDLE / ポインタの生値。幅は Trace の cpu_arch / pointer_width で解釈する
const DWORD: Ty = Ty::U32;
const BOOL: Ty = Ty::I32; // Win32 BOOL は int

pub const API_TABLE: &[ApiDef] = &[
    ApiDef {
        api_id: API_CREATE_FILE_W,
        module: "kernel32.dll",
        function: "CreateFileW",
        level: 2,
        level_note: "パス文字列 (Str16) を復元する。lpSecurityAttributes と \
                     hTemplateFile は生ポインタ値のみ。返した HANDLE は生値で \
                     後続イベントと相関可能だが Object ID は未割当 (L3 部分達成)",
        enter_fields: &[
            ("lpFileName", Ty::Str16, ValueKind::Scalar),
            ("dwDesiredAccess", DWORD, ValueKind::Scalar),
            ("dwShareMode", DWORD, ValueKind::Scalar),
            ("lpSecurityAttributes", HANDLE, ValueKind::Pointer),
            ("dwCreationDisposition", DWORD, ValueKind::Scalar),
            ("dwFlagsAndAttributes", DWORD, ValueKind::Scalar),
            ("hTemplateFile", HANDLE, ValueKind::Handle),
        ],
        leave_fields: &[
            ("return", HANDLE, ValueKind::CreatedObject),
            ("last_error", DWORD, ValueKind::Scalar),
        ],
    },
    ApiDef {
        api_id: API_READ_FILE,
        module: "kernel32.dll",
        function: "ReadFile",
        level: 2,
        level_note: "同期完了時の出力バッファ内容を上限付きで復元する \
                     (上限超過は Truncated)。OVERLAPPED 指定時は完了が非同期の \
                     ためバッファ内容と読取バイト数は Unsupported として記録する",
        enter_fields: &[
            ("hFile", HANDLE, ValueKind::Handle),
            ("lpBuffer", HANDLE, ValueKind::Pointer),
            ("nNumberOfBytesToRead", DWORD, ValueKind::Scalar),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar),
            ("lpNumberOfBytesRead", DWORD, ValueKind::Scalar),
            ("data", Ty::Bytes, ValueKind::Scalar),
            ("last_error", DWORD, ValueKind::Scalar),
        ],
    },
    ApiDef {
        api_id: API_WRITE_FILE,
        module: "kernel32.dll",
        function: "WriteFile",
        level: 2,
        level_note: "入力バッファ内容を呼び出し前に上限付きで復元する \
                     (上限超過は Truncated)",
        enter_fields: &[
            ("hFile", HANDLE, ValueKind::Handle),
            ("data", Ty::Bytes, ValueKind::Scalar),
            ("nNumberOfBytesToWrite", DWORD, ValueKind::Scalar),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar),
            ("lpNumberOfBytesWritten", DWORD, ValueKind::Scalar),
            ("last_error", DWORD, ValueKind::Scalar),
        ],
    },
    ApiDef {
        api_id: API_CLOSE_HANDLE,
        module: "kernel32.dll",
        function: "CloseHandle",
        level: 1,
        level_note: "型付き引数・戻り値のみ。対象 HANDLE の生値で生成側 \
                     イベントと相関可能 (Object ID は未割当)",
        enter_fields: &[("hObject", HANDLE, ValueKind::Handle)],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar),
            ("last_error", DWORD, ValueKind::Scalar),
        ],
    },
];

pub fn api_by_id(api_id: u32) -> Option<&'static ApiDef> {
    API_TABLE.iter().find(|a| a.api_id == api_id)
}

/// インポート名からの照合。DLL 名は大文字小文字と拡張子 ".dll" の有無を
/// 吸収し、関数名は完全一致（Win32 のエクスポート名はケース敏感）。
pub fn api_by_import(dll: &str, function: &str) -> Option<&'static ApiDef> {
    let stem = |s: &str| {
        s.rsplit(['\\', '/'])
            .next()
            .unwrap_or(s)
            .to_ascii_lowercase()
            .strip_suffix(".dll")
            .map(str::to_string)
            .unwrap_or_else(|| {
                s.rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(s)
                    .to_ascii_lowercase()
            })
    };
    let want = stem(dll);
    API_TABLE
        .iter()
        .find(|a| stem(a.module) == want && a.function == function)
}

/// 定義表の全 Schema（enter/leave を api_id 順に並べたもの）。
/// Host は Capture Session 開始時にこの順で TraceWriter へ登録し、
/// Agent 側の Descriptor が指す schema_id と一致させる。
pub fn all_schemas() -> Vec<SchemaDef> {
    let mut v = Vec::with_capacity(API_TABLE.len() * 2);
    for api in API_TABLE {
        v.push(api.enter_schema());
        v.push(api.leave_schema());
    }
    v
}

/// フック由来イベントの schema_id かどうか（Host 変換で Payload を
/// 引数値列として扱うかの判定に使う）。
pub fn is_hook_schema(schema_id: u32) -> bool {
    schema_id >= 1 && schema_id <= (API_TABLE.len() * 2) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::schema::SchemaRegistry;

    #[test]
    fn table_ids_are_unique_and_contiguous() {
        let mut ids: Vec<u32> = API_TABLE.iter().map(|a| a.api_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=API_TABLE.len() as u32).collect::<Vec<_>>());
        let mut sids: Vec<u32> = all_schemas().iter().map(|s| s.schema_id).collect();
        sids.sort_unstable();
        assert_eq!(sids, (1..=(API_TABLE.len() * 2) as u32).collect::<Vec<_>>());
    }

    #[test]
    fn schemas_register_cleanly() {
        let mut reg = SchemaRegistry::new();
        for def in all_schemas() {
            reg.register(def).expect("hook schemas must register");
        }
        assert_eq!(reg.len(), API_TABLE.len() * 2);
        // 再登録は冪等（Checkpoint 複製と同じ性質）
        for def in all_schemas() {
            reg.register(def).expect("re-register is idempotent");
        }
    }

    #[test]
    fn import_matching_tolerates_case_and_extension() {
        assert_eq!(
            api_by_import("KERNEL32.DLL", "CreateFileW").map(|a| a.api_id),
            Some(API_CREATE_FILE_W)
        );
        assert_eq!(
            api_by_import("kernel32", "ReadFile").map(|a| a.api_id),
            Some(API_READ_FILE)
        );
        assert_eq!(
            api_by_import("C:\\Windows\\System32\\KERNEL32.DLL", "WriteFile").map(|a| a.api_id),
            Some(API_WRITE_FILE)
        );
        // 関数名はケース敏感、未知 API / 未知 DLL は対象外
        assert!(api_by_import("kernel32.dll", "createfilew").is_none());
        assert!(api_by_import("kernel32.dll", "CreateFileA").is_none());
        assert!(api_by_import("user32.dll", "CreateFileW").is_none());
    }

    #[test]
    fn every_leave_schema_ends_with_last_error() {
        for api in API_TABLE {
            let last = api.leave_fields.last().expect("leave fields");
            assert_eq!(
                last.0, "last_error",
                "{} leave must capture GetLastError",
                api.function
            );
            assert_eq!(last.1, Ty::U32);
        }
    }

    #[test]
    fn schemas_carry_value_kinds() {
        // レビュー #4 の #7: 意味種別が Schema の flags へ格納される。
        // CreateFileW の戻りは生成、ReadFile のバイト数はスカラー。
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let leave = create.leave_schema();
        assert_eq!(leave.fields[0].name, "return");
        assert_eq!(
            ValueKind::from_flags(leave.fields[0].flags),
            ValueKind::CreatedObject
        );
        let read = api_by_id(API_READ_FILE).unwrap();
        let enter = read.enter_schema();
        assert_eq!(
            ValueKind::from_flags(enter.fields[0].flags),
            ValueKind::Handle,
            "hFile"
        );
        assert_eq!(
            ValueKind::from_flags(enter.fields[1].flags),
            ValueKind::Pointer,
            "lpBuffer"
        );
        let kinds: Vec<ValueKind> = read
            .leave_schema()
            .fields
            .iter()
            .map(|f| ValueKind::from_flags(f.flags))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ValueKind::Scalar,
                ValueKind::Scalar, // lpNumberOfBytesRead は個数 (スカラー)
                ValueKind::Scalar,
                ValueKind::Scalar,
            ]
        );
    }

    #[test]
    fn schema_names_follow_trace_convention() {
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        assert_eq!(create.enter_schema().name, "kernel32!CreateFileW/enter");
        assert_eq!(create.leave_schema().name, "kernel32!CreateFileW/leave");
        assert!(create.enter_schema().annotation.contains("L2"));
    }
}
