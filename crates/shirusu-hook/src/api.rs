//! フック対象 API の定義表。Phase 3 の初期 API セットはファイル I/O の
//! 4 API に、非同期 I/O の完了を観測する 2 API（GetOverlappedResult /
//! GetQueuedCompletionStatus。F27）を加えた 6 API とし、パイプライン全体
//! （フック → 型付き取得 → Compact Binary → 公開 Trace）を通すことを優先する
//! （GOAL.md Phase 3 の定義）。
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
use shirusu_trace::schema::{make_schema, CaptureTiming, LastErrorMeaning, Ty, ValueKind};

pub const API_CREATE_FILE_W: u32 = 1;
pub const API_READ_FILE: u32 = 2;
pub const API_WRITE_FILE: u32 = 3;
pub const API_CLOSE_HANDLE: u32 = 4;
/// 非同期 I/O の完了を観測する API（F27）。OVERLAPPED 指定の ReadFile /
/// WriteFile の完了を `CallCompleted` として記録するためにフックする。
pub const API_GET_OVERLAPPED_RESULT: u32 = 5;
pub const API_GET_QUEUED_COMPLETION_STATUS: u32 = 6;

/// 1 API の定義。`enter_fields` / `leave_fields` は Compact Binary の
/// 値列の順序そのものである（Schema が型と順序を定める）。各
/// フィールドは型に加えて意味種別 (ValueKind) と取得タイミング
/// (CaptureTiming) を持ち、Schema の flags へ格納される（比較エンジン
/// は型ではなく意味で正規化する。レビュー #4 の #7。取得タイミングは
/// F19: 入力は呼び出し前、出力は呼び出し後に取る）。
/// `last_error_meaning` は leave の `last_error` フィールドが「API 仕様上
/// 意味のあるエラー値」である条件（F20。戻り値が失敗を示す場合等）。
/// leave Schema の `last_error` フィールドの flags (bit8..=10) へ格納
/// され、content_hash の入力になる。
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
    pub enter_fields: &'static [(&'static str, Ty, ValueKind, CaptureTiming)],
    pub leave_fields: &'static [(&'static str, Ty, ValueKind, CaptureTiming)],
    /// この API の GetLastError 生値が意味を持つ条件。
    pub last_error_meaning: LastErrorMeaning,
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
                .map(|(n, t, k, timing)| (n.to_string(), *t, k.flags() | timing.flags()))
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
                .map(|(n, t, k, timing)| {
                    let mut flags = k.flags() | timing.flags();
                    // F20: last_error フィールドに意味条件を格納する。
                    if *n == "last_error" {
                        flags |= self.last_error_meaning.flags();
                    }
                    (n.to_string(), *t, flags)
                })
                .collect(),
        );
        def.annotation = format!("L{} (leave): {}", self.level, self.level_note);
        def
    }
}

const HANDLE: Ty = Ty::U64; // HANDLE / ポインタの生値。幅は Trace の cpu_arch / pointer_width で解釈する
const DWORD: Ty = Ty::U32;
const BOOL: Ty = Ty::I32; // Win32 BOOL は int
                          // 取得タイミングの短縮名。enter 側は呼び出し前、leave 側は呼び出し後。
const BEFORE: CaptureTiming = CaptureTiming::Before;
const AFTER: CaptureTiming = CaptureTiming::After;

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
            ("lpFileName", Ty::Str16, ValueKind::Scalar, BEFORE),
            ("dwDesiredAccess", DWORD, ValueKind::Scalar, BEFORE),
            ("dwShareMode", DWORD, ValueKind::Scalar, BEFORE),
            ("lpSecurityAttributes", HANDLE, ValueKind::Pointer, BEFORE),
            ("dwCreationDisposition", DWORD, ValueKind::Scalar, BEFORE),
            ("dwFlagsAndAttributes", DWORD, ValueKind::Scalar, BEFORE),
            ("hTemplateFile", HANDLE, ValueKind::Handle, BEFORE),
        ],
        leave_fields: &[
            ("return", HANDLE, ValueKind::CreatedObject, AFTER),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: CreateFileW は失敗時に INVALID_HANDLE_VALUE を返す場合に
        // だけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsInvalidHandle,
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
            ("hFile", HANDLE, ValueKind::Handle, BEFORE),
            ("lpBuffer", HANDLE, ValueKind::Pointer, BEFORE),
            ("nNumberOfBytesToRead", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar, AFTER),
            ("lpNumberOfBytesRead", DWORD, ValueKind::Scalar, AFTER),
            ("data", Ty::Bytes, ValueKind::Scalar, AFTER),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: ReadFile は FALSE を返す場合にだけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: API_WRITE_FILE,
        module: "kernel32.dll",
        function: "WriteFile",
        level: 2,
        level_note: "入力バッファ内容を呼び出し前に上限付きで復元する \
                     (上限超過は Truncated)",
        enter_fields: &[
            ("hFile", HANDLE, ValueKind::Handle, BEFORE),
            ("data", Ty::Bytes, ValueKind::Scalar, BEFORE),
            ("nNumberOfBytesToWrite", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar, AFTER),
            ("lpNumberOfBytesWritten", DWORD, ValueKind::Scalar, AFTER),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: WriteFile は FALSE を返す場合にだけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: API_CLOSE_HANDLE,
        module: "kernel32.dll",
        function: "CloseHandle",
        level: 1,
        level_note: "型付き引数・戻り値のみ。対象 HANDLE の生値で生成側 \
                     イベントと相関可能 (Object ID は未割当)",
        enter_fields: &[("hObject", HANDLE, ValueKind::Handle, BEFORE)],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar, AFTER),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: CloseHandle は FALSE を返す場合にだけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: API_GET_OVERLAPPED_RESULT,
        module: "kernel32.dll",
        function: "GetOverlappedResult",
        level: 1,
        level_note: "完了の観測 (F27)。成功時に、待っていた OVERLAPPED \
                     操作の完了を CallCompleted として記録する。転送バイト数 \
                     は完了時点の値。ERROR_IO_INCOMPLETE の場合は未完了で \
                     何も記録しない",
        enter_fields: &[
            ("hFile", HANDLE, ValueKind::Handle, BEFORE),
            ("lpOverlapped", HANDLE, ValueKind::Pointer, BEFORE),
            ("bWait", BOOL, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar, AFTER),
            (
                "lpNumberOfBytesTransferred",
                DWORD,
                ValueKind::Scalar,
                AFTER,
            ),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: GetOverlappedResult は FALSE を返す場合にだけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: API_GET_QUEUED_COMPLETION_STATUS,
        module: "kernel32.dll",
        function: "GetQueuedCompletionStatus",
        level: 1,
        level_note: "完了の観測 (F27)。完了ポートから取り出した OVERLAPPED \
                     操作の完了を CallCompleted として記録する。戻り値が \
                     FALSE でも lpOverlapped が非 NULL なら完了した I/O の \
                     失敗として記録する。タイムアウト (lpOverlapped が NULL) \
                     は何も記録しない",
        enter_fields: &[
            ("hCompletionPort", HANDLE, ValueKind::Handle, BEFORE),
            (
                "lpNumberOfBytesTransferred",
                HANDLE,
                ValueKind::Pointer,
                BEFORE,
            ),
            ("lpCompletionKey", HANDLE, ValueKind::Pointer, BEFORE),
            ("lpOverlapped", HANDLE, ValueKind::Pointer, BEFORE),
            ("dwMilliseconds", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[
            ("return", BOOL, ValueKind::Scalar, AFTER),
            (
                "lpNumberOfBytesTransferred",
                DWORD,
                ValueKind::Scalar,
                AFTER,
            ),
            ("last_error", DWORD, ValueKind::Scalar, AFTER),
        ],
        // F20: GetQueuedCompletionStatus は FALSE を返す場合にだけ LastError が意味を持つ。
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
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

/// CLI の `--api` 等で使う名前解決（L09）。素の関数名
/// （`CreateFileW`）と `module!関数` 形式（`kernel32!CreateFileW`）
/// の両方を受け付ける。関数名はケース敏感（Win32 のエクスポート名と
/// 同じ規約）。素の関数名が複数のモジュールに現れる場合は最初に
/// 見つかったものを返す（現行の 6 API には重複は無い）。
pub fn api_by_name(name: &str) -> Option<&'static ApiDef> {
    if let Some((module, function)) = name.split_once('!') {
        return api_by_import(module, function);
    }
    API_TABLE.iter().find(|a| a.function == name)
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
    fn name_lookup_accepts_bare_and_qualified_names() {
        assert_eq!(api_by_name("CreateFileW").map(|a| a.api_id), Some(1));
        assert_eq!(api_by_name("kernel32!ReadFile").map(|a| a.api_id), Some(2));
        assert_eq!(
            api_by_name("KERNEL32.DLL!WriteFile").map(|a| a.api_id),
            Some(3)
        );
        assert!(api_by_name("NoSuchApi").is_none());
        assert!(api_by_name("kernel32!createfilew").is_none());
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
    fn leave_schemas_declare_last_error_meaning() {
        // F20: 全 API の leave Schema の last_error フィールドに、その
        // API の意味条件が宣言される。条件は content_hash の入力。
        let cases = [
            (
                API_CREATE_FILE_W,
                LastErrorMeaning::WhenReturnIsInvalidHandle,
            ),
            (API_READ_FILE, LastErrorMeaning::WhenReturnIsFalse),
            (API_WRITE_FILE, LastErrorMeaning::WhenReturnIsFalse),
            (API_CLOSE_HANDLE, LastErrorMeaning::WhenReturnIsFalse),
            (
                API_GET_OVERLAPPED_RESULT,
                LastErrorMeaning::WhenReturnIsFalse,
            ),
            (
                API_GET_QUEUED_COMPLETION_STATUS,
                LastErrorMeaning::WhenReturnIsFalse,
            ),
        ];
        for (api_id, expected) in cases {
            let api = api_by_id(api_id).unwrap();
            assert_eq!(api.last_error_meaning, expected, "{}", api.function);
            let leave = api.leave_schema();
            let last = leave.fields.last().unwrap();
            assert_eq!(last.name, "last_error");
            assert_eq!(
                LastErrorMeaning::from_flags(last.flags),
                expected,
                "{} leave last_error flags",
                api.function
            );
            // 他のフィールドに意味条件ビットが漏れていない
            for f in &leave.fields {
                if f.name != "last_error" {
                    assert_eq!(
                        LastErrorMeaning::from_flags(f.flags),
                        LastErrorMeaning::Unspecified,
                        "{} leave field {}",
                        api.function,
                        f.name
                    );
                }
            }
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

    #[test]
    fn schemas_declare_capture_timing() {
        // F19: メモリの取得タイミングは Schema で引数ごとに定める。
        // enter は呼び出し前 (Before)、leave は元の API が書き込んだ後
        // (After)。現行の 6 API はすべてこの二分に従う。
        use shirusu_trace::schema::CaptureTiming;
        for api in API_TABLE {
            for f in api.enter_schema().fields {
                assert_eq!(
                    CaptureTiming::from_flags(f.flags),
                    CaptureTiming::Before,
                    "{} enter field {} must be Before",
                    api.function,
                    f.name
                );
            }
            for f in api.leave_schema().fields {
                assert_eq!(
                    CaptureTiming::from_flags(f.flags),
                    CaptureTiming::After,
                    "{} leave field {} must be After",
                    api.function,
                    f.name
                );
            }
        }
        // 入力バッファは呼び出し前、出力バッファは呼び出し後に取得する
        // という規則の両端。
        let write = api_by_id(API_WRITE_FILE).unwrap();
        let data_enter = write
            .enter_schema()
            .fields
            .into_iter()
            .find(|f| f.name == "data")
            .unwrap();
        assert_eq!(
            CaptureTiming::from_flags(data_enter.flags),
            CaptureTiming::Before
        );
        let read = api_by_id(API_READ_FILE).unwrap();
        let data_leave = read
            .leave_schema()
            .fields
            .into_iter()
            .find(|f| f.name == "data")
            .unwrap();
        assert_eq!(
            CaptureTiming::from_flags(data_leave.flags),
            CaptureTiming::After
        );
    }
}
