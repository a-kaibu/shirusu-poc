//! フック対象 API の定義表。Phase 3 の初期 API セットはファイル I/O の
//! 4 API に、非同期 I/O の完了を観測する 2 API（GetOverlappedResult /
//! GetQueuedCompletionStatus。F27）を加えた 6 API とし、パイプライン全体
//! （フック → 型付き取得 → Compact Binary → 公開 Trace）を通すことを優先する
//! （GOAL.md Phase 3 の定義）。
//!
//! L03 以降は、Win32 Metadata から生成した L1 API（`api_generated.inc`）
//! がこの表の末尾に続く。生成 API の追加は設定ファイル
//! （crates/shirusu-metadata-gen/apis.toml）の末尾へ追加し、
//! `win32-metadata-gen` で再生成する。手書き API と生成 API のどちらも、
//! 追加は末尾のみとする（Schema ID の安定性のため）。
//!
//! L15 以降は、詳細調査モード専用の内部 API（ntdll の Nt*。
//! `INTERNAL_API_TABLE`）がさらに末尾に続く。内部 API は通常モードの
//! Coverage 欠落には数えず、詳細調査モードでのみ記録する。
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
/// leave Schema の `last_error` フィールドの flags (bit8..=11) へ格納
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
    #[inline]
    pub fn enter_schema_id(&self) -> u32 {
        (self.api_id - 1) * 2 + 1
    }
    #[inline]
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

include!("api_file_io_generated.inc");

/// 手書き API の定義表（api_id 1〜6）。ファイル I/O の 4 API と非同期
/// 完了観測の 2 API。専用の Detour と専用の取得を持つ。
pub const HANDWRITTEN_API_TABLE: &[ApiDef] = &[
    FILE_IO_API_TABLE[0],
    FILE_IO_API_TABLE[1],
    FILE_IO_API_TABLE[2],
    FILE_IO_API_TABLE[3],
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

/// L15: 詳細調査モード専用の内部 API の api_id（ntdll.dll の Nt*）。
/// Win32 API 表（1〜78）の直後に置き、api_id は連続させる（表全体の
/// 連続性テストが通る）。Nt* は通常モードの Coverage 欠落には数えない
/// （plan.rs / agent-dll で除外する）。戻り値は NTSTATUS（U32）。
/// Nt* は GetLastError を使わないため leave には `last_error` が無く、
/// `last_error_meaning` は Never。
pub const API_NT_CREATE_FILE: u32 = 79;
pub const API_NT_OPEN_FILE: u32 = 80;
pub const API_NT_READ_FILE: u32 = 81;
pub const API_NT_WRITE_FILE: u32 = 82;
pub const API_NT_CLOSE: u32 = 83;
pub const API_NT_QUERY_INFORMATION_FILE: u32 = 84;
pub const API_NT_SET_INFORMATION_FILE: u32 = 85;

/// 内部 API の api_id 範囲（`INTERNAL_API_TABLE` と一致させること）。
pub const INTERNAL_API_ID_BASE: u32 = API_NT_CREATE_FILE;
pub const INTERNAL_API_COUNT: usize = 7;

/// L15: 詳細調査モードでだけ記録する Windows 内部 API の定義表。
/// `CreateFileW` → `NtCreateFile` のように、Win32 API の内側で実際に
/// 起きた呼び出しを、親子関係付きの別の呼び出しとして記録するための
/// 表。手書きの厳選表である（WinMD の生成対象は Win32 公開 API であり、
/// ntdll の Nt* は生成器の対象外。L14 の WinRT 表と同じ方針）。
/// 引数は全て 1 スロット（HANDLE / ポインタは U64、ULONG 等は U32）。
/// 設置は Inline Hook のみ（IAT は対象プロセスの ntdll への直接
/// インポートには使わない）。詳細調査モードが無効な場合、Detour は
/// 設置されても記録せず素通しにする（engine の prepare で判定）。
/// 再実行では下位呼び出しを重ねて実行しない（trace-format.md 参照）。
pub const INTERNAL_API_TABLE: &[ApiDef] = &[
    ApiDef {
        api_id: API_NT_CREATE_FILE,
        module: "ntdll.dll",
        function: "NtCreateFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：CreateFileW 等の内側で起きる \
                     ファイル生成・オープン。親は呼び出し元の Win32 API。\
                     NTSTATUS を返す（LastError は使わない）",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Pointer, BEFORE),
            ("DesiredAccess", DWORD, ValueKind::Scalar, BEFORE),
            ("ObjectAttributes", HANDLE, ValueKind::Pointer, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("AllocationSize", HANDLE, ValueKind::Pointer, BEFORE),
            ("FileAttributes", DWORD, ValueKind::Scalar, BEFORE),
            ("ShareAccess", DWORD, ValueKind::Scalar, BEFORE),
            ("CreateDisposition", DWORD, ValueKind::Scalar, BEFORE),
            ("CreateOptions", DWORD, ValueKind::Scalar, BEFORE),
            ("EaBuffer", HANDLE, ValueKind::Pointer, BEFORE),
            ("EaLength", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_OPEN_FILE,
        module: "ntdll.dll",
        function: "NtOpenFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：Win32 の Open 系 API の内側で \
                     起きるファイルオープン。親は呼び出し元の Win32 API",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Pointer, BEFORE),
            ("DesiredAccess", DWORD, ValueKind::Scalar, BEFORE),
            ("ObjectAttributes", HANDLE, ValueKind::Pointer, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("ShareAccess", DWORD, ValueKind::Scalar, BEFORE),
            ("OpenOptions", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_READ_FILE,
        module: "ntdll.dll",
        function: "NtReadFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：ReadFile 等の内側で起きる \
                     ファイル読み取り。親は呼び出し元の Win32 API",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Handle, BEFORE),
            ("Event", HANDLE, ValueKind::Handle, BEFORE),
            ("ApcRoutine", HANDLE, ValueKind::Pointer, BEFORE),
            ("ApcContext", HANDLE, ValueKind::Pointer, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("Buffer", HANDLE, ValueKind::Pointer, BEFORE),
            ("Length", DWORD, ValueKind::Scalar, BEFORE),
            ("ByteOffset", HANDLE, ValueKind::Pointer, BEFORE),
            ("Key", HANDLE, ValueKind::Pointer, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_WRITE_FILE,
        module: "ntdll.dll",
        function: "NtWriteFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：WriteFile 等の内側で起きる \
                     ファイル書き込み。親は呼び出し元の Win32 API",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Handle, BEFORE),
            ("Event", HANDLE, ValueKind::Handle, BEFORE),
            ("ApcRoutine", HANDLE, ValueKind::Pointer, BEFORE),
            ("ApcContext", HANDLE, ValueKind::Pointer, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("Buffer", HANDLE, ValueKind::Pointer, BEFORE),
            ("Length", DWORD, ValueKind::Scalar, BEFORE),
            ("ByteOffset", HANDLE, ValueKind::Pointer, BEFORE),
            ("Key", HANDLE, ValueKind::Pointer, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_CLOSE,
        module: "ntdll.dll",
        function: "NtClose",
        level: 1,
        level_note: "L15（詳細調査モード専用）：CloseHandle 等の内側で起きる \
                     ハンドルクローズ。親は呼び出し元の Win32 API",
        enter_fields: &[("Handle", HANDLE, ValueKind::Handle, BEFORE)],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_QUERY_INFORMATION_FILE,
        module: "ntdll.dll",
        function: "NtQueryInformationFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：GetFileInformation 系の内側で \
                     起きるファイル情報の問い合わせ。親は呼び出し元の Win32 API",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Handle, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("FileInformation", HANDLE, ValueKind::Pointer, BEFORE),
            ("Length", DWORD, ValueKind::Scalar, BEFORE),
            ("FileInformationClass", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
    ApiDef {
        api_id: API_NT_SET_INFORMATION_FILE,
        module: "ntdll.dll",
        function: "NtSetInformationFile",
        level: 1,
        level_note: "L15（詳細調査モード専用）：SetFileInformation 系の内側で \
                     起きるファイル情報の設定。親は呼び出し元の Win32 API",
        enter_fields: &[
            ("FileHandle", HANDLE, ValueKind::Handle, BEFORE),
            ("IoStatusBlock", HANDLE, ValueKind::Pointer, BEFORE),
            ("FileInformation", HANDLE, ValueKind::Pointer, BEFORE),
            ("Length", DWORD, ValueKind::Scalar, BEFORE),
            ("FileInformationClass", DWORD, ValueKind::Scalar, BEFORE),
        ],
        leave_fields: &[("return", DWORD, ValueKind::Scalar, AFTER)],
        last_error_meaning: LastErrorMeaning::Never,
    },
];

/// L03: Win32 Metadata から生成した L1 API の定義表（api_id 7〜）。
/// 生成物は crates/shirusu-metadata-gen/apis.toml の記載順に並ぶ。
/// 再生成: cargo run -p shirusu-metadata-gen -- --winmd <path>
/// （--check で最新性を CI が検査する）。
pub const GENERATED_API_TABLE: &[ApiDef] = include!("api_generated.inc");

/// Shared note of every broad-tier API (Schema annotation and Coverage).
pub const BROAD_LEVEL_NOTE: &str = "L1 broad（Metadata 生成、メインモジュール IAT のみ）：型付き引数・戻り値のみ。動的解決・他モジュール経由は未捕捉";

/// IAT-only broad tier generated from `broad-apis.tsv` (api_id
/// [`BROAD_API_ID_BASE`]〜). These APIs replace only static imports of the
/// main module. No Inline Hook patches their export prologues, so a dynamic
/// or other-module call stays an explicit Coverage gap.
pub const BROAD_API_TABLE: &[ApiDef] = include!("api_broad_generated.inc");

/// First broad-tier ID. IDs 1000..=1002 are COM / WinRT / Callback event IDs
/// and curated tables stay below this base.
pub const BROAD_API_ID_BASE: u32 = 1003;

/// Generated APIs whose original never returns to the Detour.
pub const NO_RETURN_API_IDS: &[u32] = include!("api_traits_generated.inc");

/// 全 API 数（手書き + 生成 + 内部 + 広域層）。ID には予約の欠番がある。
pub const API_COUNT: usize = HANDWRITTEN_API_TABLE.len()
    + GENERATED_API_TABLE.len()
    + INTERNAL_API_TABLE.len()
    + BROAD_API_TABLE.len();

const API_TABLES: [&[ApiDef]; 4] = [
    HANDWRITTEN_API_TABLE,
    GENERATED_API_TABLE,
    INTERNAL_API_TABLE,
    BROAD_API_TABLE,
];

/// Largest assigned API ID. Runtime per-API arrays are indexed by ID and
/// sized `MAX_API_ID + 1`; reserved IDs remain empty.
pub const MAX_API_ID: usize = {
    let mut max = 0;
    let mut table = 0;
    while table < API_TABLES.len() {
        let mut entry = 0;
        while entry < API_TABLES[table].len() {
            let id = API_TABLES[table][entry].api_id as usize;
            if id > max {
                max = id;
            }
            entry += 1;
        }
        table += 1;
    }
    max
};

/// 全 API の定義表（手書き + 生成 + 内部 + 広域層）。
/// `&[ApiDef]` 1 枚では持てない（const でのスライス連結ができない）
/// ため、反復子で連結して見る。
pub fn api_table() -> impl Iterator<Item = &'static ApiDef> {
    HANDWRITTEN_API_TABLE
        .iter()
        .chain(GENERATED_API_TABLE.iter())
        .chain(INTERNAL_API_TABLE.iter())
        .chain(BROAD_API_TABLE.iter())
}

/// Broad-tier API: install through main-module IAT entries only.
pub fn is_iat_only_api(api_id: u32) -> bool {
    api_id >= BROAD_API_ID_BASE && api_by_id(api_id).is_some()
}

/// The original never returns to the Detour (thread or process exit).
#[inline]
pub fn is_no_return_api(api_id: u32) -> bool {
    NO_RETURN_API_IDS.contains(&api_id)
}

/// L15: 詳細調査モード専用の内部 API（Nt*）かどうか。詳細調査モードが
/// 無効な場合、この API の呼び出しは記録しない（素通しにする）。
/// Coverage の欠落にも数えない。
#[inline]
pub fn is_internal_api(api_id: u32) -> bool {
    (INTERNAL_API_ID_BASE..INTERNAL_API_ID_BASE + INTERNAL_API_COUNT as u32).contains(&api_id)
}

// Detour entry must not scan a growing generated table on every API call.
// Build this at compile time: no lazy initialization, allocation or TLS lifetime.
static API_BY_ID: [Option<&ApiDef>; MAX_API_ID + 1] = {
    let tables = API_TABLES;
    let mut indexed = [None; MAX_API_ID + 1];
    let mut table = 0;
    while table < tables.len() {
        let mut entry = 0;
        while entry < tables[table].len() {
            let api = &tables[table][entry];
            let id = api.api_id as usize;
            assert!(id > 0 && id <= MAX_API_ID);
            assert!(indexed[id].is_none());
            indexed[id] = Some(api);
            entry += 1;
        }
        table += 1;
    }
    indexed
};

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `kernel32.dll!ExitThread` の API ID。Detour の通常経路が毎回文字列を
/// 比較しないよう、コンパイル時に表から求める（無ければビルドを拒否）。
pub const EXIT_THREAD_API_ID: u32 = {
    let mut i = 0;
    let mut found = 0;
    while i < GENERATED_API_TABLE.len() {
        let api = &GENERATED_API_TABLE[i];
        if const_str_eq(api.module, "kernel32.dll") && const_str_eq(api.function, "ExitThread") {
            found = api.api_id;
        }
        i += 1;
    }
    assert!(found != 0);
    found
};

/// Compile-time API ID of `module!function` in any table (0 if absent).
const fn const_api_id(module: &str, function: &str) -> u32 {
    let tables = API_TABLES;
    let mut table = 0;
    while table < tables.len() {
        let mut entry = 0;
        while entry < tables[table].len() {
            let api = &tables[table][entry];
            if const_str_eq(api.module, module) && const_str_eq(api.function, function) {
                return api.api_id;
            }
            entry += 1;
        }
        table += 1;
    }
    0
}

/// `kernel32.dll!TerminateThread`: does not return when the handle names the
/// calling thread. Resolved at compile time (the build fails if absent).
pub const TERMINATE_THREAD_API_ID: u32 = {
    let id = const_api_id("kernel32.dll", "TerminateThread");
    assert!(id != 0);
    id
};
/// `kernel32.dll!TerminateJobObject`: does not return when the calling
/// process belongs to the job (the job terminates it).
pub const TERMINATE_JOB_OBJECT_API_ID: u32 = {
    let id = const_api_id("kernel32.dll", "TerminateJobObject");
    assert!(id != 0);
    id
};

/// APIs that return or not depending on their arguments (self-termination).
/// The Detour decides per call ([`is_no_return_api`] covers the APIs that
/// never return).
#[inline]
pub fn is_conditional_no_return_api(api_id: u32) -> bool {
    api_id == TERMINATE_THREAD_API_ID || api_id == TERMINATE_JOB_OBJECT_API_ID
}

#[inline]
pub fn api_by_id(api_id: u32) -> Option<&'static ApiDef> {
    API_BY_ID.get(api_id as usize).copied().flatten()
}

/// インポート名からの照合。DLL 名は大文字小文字と拡張子 ".dll" の有無を
/// 吸収し、関数名は完全一致（Win32 のエクスポート名はケース敏感）。
fn module_stem(s: &str) -> String {
    let name = s
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(s)
        .to_ascii_lowercase();
    match name.strip_suffix(".dll") {
        Some(stem) => stem.to_string(),
        None => name,
    }
}

// Cold-path index for import planning and CLI lookups; Detours never use it.
// Entries keep table order, so the first matching table entry still wins.
static API_BY_FUNCTION: std::sync::OnceLock<
    std::collections::HashMap<&'static str, Vec<&'static ApiDef>>,
> = std::sync::OnceLock::new();

fn apis_named(function: &str) -> &'static [&'static ApiDef] {
    let index = API_BY_FUNCTION.get_or_init(|| {
        let mut index: std::collections::HashMap<&'static str, Vec<&'static ApiDef>> =
            std::collections::HashMap::with_capacity(API_COUNT);
        for api in api_table() {
            index.entry(api.function).or_default().push(api);
        }
        index
    });
    index.get(function).map(Vec::as_slice).unwrap_or(&[])
}

pub fn api_by_import(dll: &str, function: &str) -> Option<&'static ApiDef> {
    let want = module_stem(dll);
    apis_named(function)
        .iter()
        .copied()
        .find(|a| module_stem(a.module) == want)
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
    apis_named(name).first().copied()
}

/// 手書き表だけの Schema（enter/leave を api_id 順に並べたもの）。
/// shirusu-emit の file_io 共有セットがこの 6 API と一致することを
/// 検査するために使う。
pub fn handwritten_schemas() -> Vec<SchemaDef> {
    let mut v = Vec::with_capacity(HANDWRITTEN_API_TABLE.len() * 2);
    for api in HANDWRITTEN_API_TABLE {
        v.push(api.enter_schema());
        v.push(api.leave_schema());
    }
    v
}

/// 定義表の全 Schema（enter/leave を api_id 順に並べたもの）。
/// Host は Capture Session 開始時にこの順で TraceWriter へ登録し、
/// Agent 側の Descriptor が指す schema_id と一致させる。
pub fn all_schemas() -> Vec<SchemaDef> {
    let mut v = Vec::with_capacity(API_COUNT * 2);
    for api in api_table() {
        v.push(api.enter_schema());
        v.push(api.leave_schema());
    }
    v
}

/// Schemas a Host registers at session start: every table except the
/// IAT-only broad tier, whose Schemas are registered on first use through
/// [`broad_schema`]. Thousands of unused definitions would otherwise add
/// megabytes to every Trace.
pub fn eager_schemas() -> Vec<SchemaDef> {
    let mut v = Vec::new();
    for api in api_table().filter(|api| !is_iat_only_api(api.api_id)) {
        v.push(api.enter_schema());
        v.push(api.leave_schema());
    }
    v
}

/// Enter or leave Schema of a broad-tier API, for lazy registration.
pub fn broad_schema(schema_id: u32) -> Option<SchemaDef> {
    let api = api_by_id(schema_id.div_ceil(2)).filter(|a| is_iat_only_api(a.api_id))?;
    Some(if schema_id == api.enter_schema_id() {
        api.enter_schema()
    } else {
        api.leave_schema()
    })
}

/// フック由来イベントの schema_id かどうか（Host 変換で Payload を
/// 引数値列として扱うかの判定に使う）。API 表の Schema（割り当て済み ID の 2n-1 / 2n）
/// と、COM メソッドイベントの Schema（com.rs の予約 ID）のどちらか。
pub fn is_hook_schema(schema_id: u32) -> bool {
    (schema_id >= 1
        && schema_id <= (MAX_API_ID * 2) as u32
        && api_by_id(schema_id.div_ceil(2)).is_some())
        || schema_id == crate::com::COM_METHOD_ENTER_SCHEMA_ID
        || schema_id == crate::com::COM_METHOD_LEAVE_SCHEMA_ID
        || schema_id == crate::com::COM_FACTORY_ENTER_SCHEMA_ID
        || schema_id == crate::com::COM_FACTORY_LEAVE_SCHEMA_ID
}

#[cfg(test)]
mod conditional_no_return_tests {
    use super::*;

    #[test]
    fn self_terminating_apis_are_known_and_distinct_from_no_return_apis() {
        for (id, function) in [
            (TERMINATE_THREAD_API_ID, "TerminateThread"),
            (TERMINATE_JOB_OBJECT_API_ID, "TerminateJobObject"),
        ] {
            let api = api_by_id(id).expect("in the table");
            assert_eq!((api.module, api.function), ("kernel32.dll", function));
            assert!(is_conditional_no_return_api(id));
            assert!(!is_no_return_api(id), "decided per call, not always");
        }
        assert!(!is_conditional_no_return_api(EXIT_THREAD_API_ID));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exit_thread_id_constant_matches_table_lookup() {
        let api = super::api_by_import("kernel32.dll", "ExitThread").unwrap();
        assert_eq!(api.api_id, super::EXIT_THREAD_API_ID);
        // Only this entry may take the ExitThread ownership-release path.
        let matches = super::api_table()
            .filter(|a| a.api_id == super::EXIT_THREAD_API_ID)
            .count();
        assert_eq!(matches, 1);
    }

    #[test]
    fn indexed_api_lookup_matches_all_tables_and_rejects_unknown_ids() {
        for expected in super::api_table() {
            let actual = super::api_by_id(expected.api_id).unwrap();
            assert_eq!(actual.enter_schema(), expected.enter_schema());
            assert_eq!(actual.leave_schema(), expected.leave_schema());
            assert_eq!(actual.module, expected.module);
            assert_eq!(actual.function, expected.function);
        }
        for id in [
            0,
            1000,
            1001,
            1002,
            5001,
            5011,
            super::MAX_API_ID as u32 + 1,
            u32::MAX,
        ] {
            assert!(super::api_by_id(id).is_none());
        }
    }

    use super::*;
    use shirusu_trace::schema::SchemaRegistry;

    #[test]
    fn table_ids_are_unique_and_contiguous_except_reserved_ids() {
        let mut ids: Vec<u32> = api_table().map(|a| a.api_id).collect();
        ids.sort_unstable();
        // Curated IDs are contiguous below the broad tier. The broad tier
        // starts at its base and skips only the IDs whose Schemas would
        // collide with the reserved COM / WinRT / Callback Schema block.
        let curated = (GENERATED_API_TABLE.len()
            + HANDWRITTEN_API_TABLE.len()
            + INTERNAL_API_TABLE.len()) as u32;
        let reserved = 5001..=5011u32;
        let expected: Vec<u32> = (1..=curated)
            .chain((BROAD_API_ID_BASE..=MAX_API_ID as u32).filter(|id| !reserved.contains(id)))
            .collect();
        assert_eq!(ids, expected);
        assert_eq!(ids.len(), API_COUNT);
        let mut sids: Vec<u32> = all_schemas().iter().map(|s| s.schema_id).collect();
        sids.sort_unstable();
        let expected: Vec<u32> = ids.iter().flat_map(|id| [id * 2 - 1, id * 2]).collect();
        assert_eq!(sids, expected);
        for special in [
            crate::com::COM_METHOD_ENTER_SCHEMA_ID,
            crate::com::COM_METHOD_LEAVE_SCHEMA_ID,
            crate::com::COM_FACTORY_ENTER_SCHEMA_ID,
            crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
            crate::winrt::WINRT_ACTIVATION_ENTER_SCHEMA_ID,
            crate::winrt::WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
            crate::callback::CALLBACK_ENTER_SCHEMA_ID,
            crate::callback::CALLBACK_LEAVE_SCHEMA_ID,
        ] {
            assert!(sids.binary_search(&special).is_err(), "{special}");
        }
        for special in [
            crate::com::COM_METHOD_API_ID,
            crate::winrt::WINRT_ACTIVATION_API_ID,
            crate::callback::CALLBACK_API_ID,
        ] {
            assert!(api_by_id(special).is_none(), "{special}");
        }
    }

    #[test]
    fn broad_tier_is_iat_only_and_never_shadows_dedicated_hooks() {
        assert!(BROAD_API_TABLE.len() > 5000);
        assert_eq!(BROAD_API_TABLE[0].api_id, BROAD_API_ID_BASE);
        let dedicated: Vec<(&str, &str)> = HANDWRITTEN_API_TABLE
            .iter()
            .chain(GENERATED_API_TABLE)
            .chain(INTERNAL_API_TABLE)
            .map(|a| (a.module, a.function))
            .chain([
                ("ole32.dll", "CoCreateInstance"),
                ("ole32.dll", "CoGetClassObject"),
            ])
            .chain(
                crate::callback::CALLBACK_HOOKS
                    .iter()
                    .map(|h| (h.module, h.function)),
            )
            .collect();
        for api in BROAD_API_TABLE {
            assert!(is_iat_only_api(api.api_id), "{}", api.function);
            assert_eq!(api.level_note, BROAD_LEVEL_NOTE);
            assert_eq!(api.module, api.module.to_ascii_lowercase());
            assert!(
                !dedicated
                    .iter()
                    .any(|(m, f)| m.eq_ignore_ascii_case(api.module) && *f == api.function),
                "{}!{} shadows a dedicated hook",
                api.module,
                api.function
            );
            assert!(!is_no_return_api(api.api_id), "{}", api.function);
            assert!(api.enter_fields.len() <= 12, "{}", api.function);
        }
        for api in HANDWRITTEN_API_TABLE.iter().chain(GENERATED_API_TABLE) {
            assert!(!is_iat_only_api(api.api_id), "{}", api.function);
        }
        // Frame-sensitive exports stay out of the tier (recorded as [[skip]]).
        for function in [
            "ExitProcess",
            "RtlCaptureContext",
            "RtlUnwind",
            "RaiseException",
            "SwitchToFiber",
        ] {
            assert!(
                api_by_import("kernel32.dll", function).is_none(),
                "{function}"
            );
        }
        assert_eq!(
            NO_RETURN_API_IDS,
            &[api_by_name("ExitThread").unwrap().api_id]
        );
        let get_message = api_by_import("USER32.dll", "MessageBeep").unwrap();
        assert!(is_iat_only_api(get_message.api_id));
    }

    #[test]
    fn generated_entries_are_l1_and_generic_capture_compatible() {
        // L03: 生成 API (api_id 7〜78) は全て L1 で、汎用取得が扱える型
        // (U32 / I32 / U64 / I64 / Bool) だけを使い、引数は 12 個以下。
        // 生成表の検査はここが担う（capture::generic_enter は対応外の
        // 型で panic するため、表の側で保証する）。L15 の内部 API
        // (79〜) は生成表ではないため対象外（別テストで検査する）。
        let generated: Vec<&ApiDef> = GENERATED_API_TABLE.iter().collect();
        assert!(!generated.is_empty(), "generated table must not be empty");
        assert_eq!(generated[0].api_id, 7);
        assert_eq!(generated[generated.len() - 1].api_id, 197);
        assert_eq!(
            api_by_import("kernel32", "GetTickCount").unwrap().api_id,
            78
        );
        for api in &generated {
            assert_eq!(api.level, 1, "{} must be L1", api.function);
            assert!(
                api.enter_fields.len() <= 12,
                "{} has {} params (max 12)",
                api.function,
                api.enter_fields.len()
            );
            for &(name, ty, _, _) in api.enter_fields.iter() {
                assert!(
                    matches!(
                        ty,
                        Ty::U32 | Ty::I32 | Ty::U64 | Ty::I64 | Ty::Bool | Ty::F32 | Ty::F64
                    ),
                    "{} enter field {name} uses unsupported {ty:?}",
                    api.function
                );
            }
            // leave は return (任意) + last_error のみ。
            assert_eq!(api.leave_fields.last().unwrap().0, "last_error");
            assert!(api.leave_fields.len() <= 2);
            for &(name, ty, _, _) in api.leave_fields.iter() {
                if name == "return" {
                    assert!(
                        matches!(
                            ty,
                            Ty::U32 | Ty::I32 | Ty::U64 | Ty::I64 | Ty::Bool | Ty::F32 | Ty::F64
                        ),
                        "{} return uses unsupported {ty:?}",
                        api.function
                    );
                }
            }
        }
    }

    #[test]
    fn internal_entries_are_l1_nt_apis_for_detailed_mode() {
        // L15: 内部 API 表は ntdll の Nt* 7 件で、api_id は 79〜85 の
        // 連続、表全体の連続性と合わせて 1〜85 になる。全て L1 で
        // 引数は 12 個以下、leave は NTSTATUS の return のみ
        // （last_error は無い。Nt* は GetLastError を使わない）。
        assert_eq!(INTERNAL_API_TABLE.len(), INTERNAL_API_COUNT);
        assert_eq!(INTERNAL_API_ID_BASE, 79);
        assert_eq!(API_COUNT - BROAD_API_TABLE.len(), 197);
        for (i, api) in INTERNAL_API_TABLE.iter().enumerate() {
            assert_eq!(api.api_id, INTERNAL_API_ID_BASE + i as u32);
            assert_eq!(api.module, "ntdll.dll");
            assert!(api.function.starts_with("Nt"), "{}", api.function);
            assert_eq!(api.level, 1, "{}", api.function);
            assert!(
                api.enter_fields.len() <= 12,
                "{} has {} params (max 12)",
                api.function,
                api.enter_fields.len()
            );
            for &(name, ty, _, _) in api.enter_fields.iter() {
                assert!(
                    matches!(
                        ty,
                        Ty::U32 | Ty::I32 | Ty::U64 | Ty::I64 | Ty::Bool | Ty::F32 | Ty::F64
                    ),
                    "{} enter field {name} uses unsupported {ty:?}",
                    api.function
                );
            }
            assert_eq!(api.leave_fields.len(), 1, "{}", api.function);
            assert_eq!(api.leave_fields[0].0, "return");
            assert_eq!(api.last_error_meaning, LastErrorMeaning::Never);
            assert!(is_internal_api(api.api_id));
            // Schema ID は表の順に enter = 2n-1, leave = 2n。COM (10001〜)
            // / WinRT (10011〜) の予約ブロックと衝突しない。
            assert_eq!(api.enter_schema_id(), (api.api_id - 1) * 2 + 1);
            assert_eq!(api.leave_schema_id(), (api.api_id - 1) * 2 + 2);
            assert!(api.leave_schema_id() < 1000, "{}", api.function);
        }
        // 境界：78 は Win32（生成）、79 と 85 は内部、86 は範囲外。
        assert!(!is_internal_api(78));
        assert!(is_internal_api(79));
        assert!(is_internal_api(85));
        assert!(!is_internal_api(86));
        assert!(!is_internal_api(0));
        // 内部 API も名前・インポート照合で引ける（--api / IAT 照合用）。
        assert_eq!(
            api_by_name("ntdll!NtCreateFile").map(|a| a.api_id),
            Some(API_NT_CREATE_FILE)
        );
        assert_eq!(api_by_name("NtClose").map(|a| a.api_id), Some(API_NT_CLOSE));
        assert_eq!(
            api_by_import("NTDLL.DLL", "NtReadFile").map(|a| a.api_id),
            Some(API_NT_READ_FILE)
        );
    }

    #[test]
    fn table_has_no_duplicate_module_function_pairs() {
        // L03: 手書きと生成を合わせても (module, function) は一意である。
        let mut seen = std::collections::HashSet::new();
        for api in api_table() {
            assert!(
                seen.insert((api.module, api.function)),
                "duplicate {}!{}",
                api.module,
                api.function
            );
        }
    }

    #[test]
    fn schemas_register_cleanly() {
        let mut reg = SchemaRegistry::new();
        for def in all_schemas() {
            reg.register(def).expect("hook schemas must register");
        }
        assert_eq!(reg.len(), API_COUNT * 2);
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
        assert_eq!(
            api_by_import("kernel32.dll", "CreateFileA").unwrap().api_id,
            150
        );
        assert!(api_by_import("kernel32.dll", "UnknownApi").is_none());
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
        // L15: 内部 API (Nt*) は GetLastError を使わないため leave には
        // last_error が無く、return のみ。Win32 API は全て last_error で
        // 終わる。
        for api in api_table() {
            if is_internal_api(api.api_id) {
                assert_eq!(api.leave_fields.len(), 1, "{}", api.function);
                assert_eq!(api.leave_fields[0].0, "return", "{}", api.function);
                continue;
            }
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
            (API_CREATE_FILE_W, LastErrorMeaning::DependsOnInputs),
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
        for api in api_table() {
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
