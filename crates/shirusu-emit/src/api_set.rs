//! 共有 API セット：外部レコーダ（sake 等）と shirusu 本体が「同じ
//! API を同じ Schema で記録する」ための定義。
//!
//! Schema ID の割当は shirusu-hook の API 表と同一の規約に従う：
//! API は登録順に api_id 1..=N を持ち、ファイル内 Schema ID は
//! enter = 2n−1、leave = 2n。Schema の同一性は名前とフィールド列
//! から決まる正規化ハッシュ（`SchemaDef.content_hash`）で判定され、
//! 別実装が同じ定義から生成した Schema は同じハッシュになる。
//! つまり「共有 API セットに適合している」とは、最低限この
//! ハッシュが一致することである（適合性チェッカの検査対象）。
//!
//! フィールド規約（compare が前提とする公開 Schema の規約）:
//! - Leave の戻り値は `return` という名前で記録する。オブジェクト
//!   （ハンドル）を生成する API は `return` を Ty::U64 とし、
//!   0 / 全ビット 1 は「生成しなかった」として区別される。
//! - Leave の最後のフィールドは `last_error`（Ty::U32）とする
//!   （shirusu-hook の表と同じ規約）。
//! - 各フィールドは意味種別 (ValueKind) を持つ。個数・カウンタは
//!   Ty が U64 でも Scalar と宣言し、ハンドルは Handle、生成 API の
//!   戻り値は CreatedObject と宣言する（compare の正規化は型では
//!   なく意味種別で判断する。レビュー #4 の #7）。種別が無い旧来の
//!   Schema に対しては、compare が「Ty::U64 はハンドル／ポインタ級」
//!   という従来規約へフォールバックする。
//! - 各フィールドは取得タイミング (CaptureTiming) を持つ。enter 側は
//!   呼び出し前 (Before)、leave 側は呼び出し後 (After)。入出力が同じ
//!   バッファなら Both、非同期 I/O の完了時取得は Completion と宣言
//!   する（F19）。
//! - Leave の `last_error` は、その API の GetLastError 生値が意味を
//!   持つ条件 (LastErrorMeaning) を持つ。戻り値が失敗を示す場合に
//!   だけ意味を持ち、成功時の生値は古い残留値として Stale になる
//!   （F20）。条件は leave Schema の `last_error` フィールドの flags
//!   へ格納され、content_hash の入力になる。

use crate::EmitError;
use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, CaptureTiming, LastErrorMeaning, Ty, ValueKind};

/// 1 API の Schema 仕様。enter / leave それぞれのフィールド列が
/// Compact Binary の値列の順序そのものを定める。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSpec {
    /// API 名。`モジュール!関数` 形式（例 `kernel32!CreateFileW`）。
    pub name: String,
    pub enter_fields: Vec<(String, Ty, ValueKind, CaptureTiming)>,
    pub leave_fields: Vec<(String, Ty, ValueKind, CaptureTiming)>,
    /// SchemaDef.annotation へ写される注記（観測レベル等）。
    pub annotation: String,
    /// この API の GetLastError 生値が意味を持つ条件（F20）。
    /// leave Schema の `last_error` フィールドの flags へ格納する。
    pub last_error_meaning: LastErrorMeaning,
}

impl ApiSpec {
    pub fn new(
        name: &str,
        enter_fields: &[(&str, Ty, ValueKind, CaptureTiming)],
        leave_fields: &[(&str, Ty, ValueKind, CaptureTiming)],
    ) -> Self {
        ApiSpec {
            name: name.to_string(),
            enter_fields: enter_fields
                .iter()
                .map(|(n, t, k, timing)| (n.to_string(), *t, *k, *timing))
                .collect(),
            leave_fields: leave_fields
                .iter()
                .map(|(n, t, k, timing)| (n.to_string(), *t, *k, *timing))
                .collect(),
            annotation: String::new(),
            last_error_meaning: LastErrorMeaning::Unspecified,
        }
    }

    pub fn with_annotation(mut self, annotation: &str) -> Self {
        self.annotation = annotation.to_string();
        self
    }

    pub fn with_last_error_meaning(mut self, meaning: LastErrorMeaning) -> Self {
        self.last_error_meaning = meaning;
        self
    }
}

/// API セット。登録順が api_id を決める。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiSet {
    specs: Vec<ApiSpec>,
}

impl ApiSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// API を末尾へ追加し、割り当てられた api_id（1 始まり）を返す。
    /// 同名の再登録は拒否する（ID の意味を後から変えないため）。
    pub fn add(&mut self, spec: ApiSpec) -> Result<u32, EmitError> {
        if spec.name.is_empty() {
            return Err(EmitError::InvalidSpec("api name is empty".into()));
        }
        if self.api_id(&spec.name).is_some() {
            return Err(EmitError::DuplicateApi(spec.name));
        }
        self.specs.push(spec);
        Ok(self.specs.len() as u32)
    }

    pub fn len(&self) -> usize {
        self.specs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    pub fn api_id(&self, name: &str) -> Option<u32> {
        self.specs
            .iter()
            .position(|s| s.name == name)
            .map(|i| i as u32 + 1)
    }

    pub fn spec(&self, api_id: u32) -> Option<&ApiSpec> {
        if api_id == 0 {
            return None;
        }
        self.specs.get((api_id - 1) as usize)
    }

    pub fn spec_by_name(&self, name: &str) -> Option<&ApiSpec> {
        self.api_id(name).and_then(|id| self.spec(id))
    }

    /// ファイル内 Schema ID の規約（本体のフック表と同一）。
    pub fn enter_schema_id(api_id: u32) -> u32 {
        (api_id - 1) * 2 + 1
    }

    pub fn leave_schema_id(api_id: u32) -> u32 {
        (api_id - 1) * 2 + 2
    }

    /// セットの全 Schema（api_id 順に enter、leave の並び）。
    /// TraceWriter へこの順で登録する。
    pub fn schemas(&self) -> Vec<SchemaDef> {
        let mut v = Vec::with_capacity(self.specs.len() * 2);
        for (i, spec) in self.specs.iter().enumerate() {
            let api_id = i as u32 + 1;
            let mut enter = make_schema(
                Self::enter_schema_id(api_id),
                &format!("{}/enter", spec.name),
                spec.enter_fields
                    .iter()
                    .map(|(n, t, k, timing)| (n.clone(), *t, k.flags() | timing.flags()))
                    .collect(),
            );
            enter.annotation = spec.annotation.clone();
            let mut leave = make_schema(
                Self::leave_schema_id(api_id),
                &format!("{}/leave", spec.name),
                spec.leave_fields
                    .iter()
                    .map(|(n, t, k, timing)| {
                        let mut flags = k.flags() | timing.flags();
                        // F20: last_error フィールドに意味条件を格納する。
                        if n == "last_error" {
                            flags |= spec.last_error_meaning.flags();
                        }
                        (n.clone(), *t, flags)
                    })
                    .collect(),
            );
            leave.annotation = spec.annotation.clone();
            v.push(enter);
            v.push(leave);
        }
        v
    }
}

/// shirusu 本体のフック表（shirusu-hook `HANDWRITTEN_API_TABLE`）と同一の
/// ファイル I/O 4 API と完了観測 2 API（GetOverlappedResult /
/// GetQueuedCompletionStatus）の 6 API セット。本体が記録した Trace と外部レコーダの
/// Trace を compare で突き合わせる場合の、共有セットの基準形。
/// フィールド定義が本体側と一致することは content_hash の一致で
/// テストが保証する（本体側の表が変わればこのテストが落ちる）。
pub fn file_io_api_set() -> ApiSet {
    const HANDLE: Ty = Ty::U64;
    const DWORD: Ty = Ty::U32;
    const BOOL: Ty = Ty::I32;
    let mut set = ApiSet::new();
    let defs = [
        ApiSpec::new(
            "kernel32!CreateFileW",
            &[
                (
                    "lpFileName",
                    Ty::Str16,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
                (
                    "dwDesiredAccess",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
                (
                    "dwShareMode",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
                (
                    "lpSecurityAttributes",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                (
                    "dwCreationDisposition",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
                (
                    "dwFlagsAndAttributes",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
                (
                    "hTemplateFile",
                    HANDLE,
                    ValueKind::Handle,
                    CaptureTiming::Before,
                ),
            ],
            &[
                (
                    "return",
                    HANDLE,
                    ValueKind::CreatedObject,
                    CaptureTiming::After,
                ),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsInvalidHandle),
        ApiSpec::new(
            "kernel32!ReadFile",
            &[
                ("hFile", HANDLE, ValueKind::Handle, CaptureTiming::Before),
                (
                    "lpBuffer",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                (
                    "nNumberOfBytesToRead",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar, CaptureTiming::After),
                (
                    "lpNumberOfBytesRead",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
                ("data", Ty::Bytes, ValueKind::Scalar, CaptureTiming::After),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsFalse),
        ApiSpec::new(
            "kernel32!WriteFile",
            &[
                ("hFile", HANDLE, ValueKind::Handle, CaptureTiming::Before),
                ("data", Ty::Bytes, ValueKind::Scalar, CaptureTiming::Before),
                (
                    "nNumberOfBytesToWrite",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar, CaptureTiming::After),
                (
                    "lpNumberOfBytesWritten",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsFalse),
        ApiSpec::new(
            "kernel32!CloseHandle",
            &[("hObject", HANDLE, ValueKind::Handle, CaptureTiming::Before)],
            &[
                ("return", BOOL, ValueKind::Scalar, CaptureTiming::After),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L1 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsFalse),
        ApiSpec::new(
            "kernel32!GetOverlappedResult",
            &[
                ("hFile", HANDLE, ValueKind::Handle, CaptureTiming::Before),
                (
                    "lpOverlapped",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                ("bWait", BOOL, ValueKind::Scalar, CaptureTiming::Before),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar, CaptureTiming::After),
                (
                    "lpNumberOfBytesTransferred",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L1 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsFalse),
        ApiSpec::new(
            "kernel32!GetQueuedCompletionStatus",
            &[
                (
                    "hCompletionPort",
                    HANDLE,
                    ValueKind::Handle,
                    CaptureTiming::Before,
                ),
                (
                    "lpNumberOfBytesTransferred",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                (
                    "lpCompletionKey",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                (
                    "lpOverlapped",
                    HANDLE,
                    ValueKind::Pointer,
                    CaptureTiming::Before,
                ),
                (
                    "dwMilliseconds",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::Before,
                ),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar, CaptureTiming::After),
                (
                    "lpNumberOfBytesTransferred",
                    DWORD,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
                ("last_error", DWORD, ValueKind::Scalar, CaptureTiming::After),
            ],
        )
        .with_annotation("L1 (file_io_api_set: shirusu-hook HANDWRITTEN_API_TABLE と同一定義)")
        .with_last_error_meaning(LastErrorMeaning::WhenReturnIsFalse),
    ];
    for def in defs {
        set.add(def)
            .expect("file_io_api_set definitions are unique");
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_hook_table_convention() {
        let set = file_io_api_set();
        assert_eq!(set.len(), 6);
        assert_eq!(set.api_id("kernel32!CreateFileW"), Some(1));
        assert_eq!(set.api_id("kernel32!CloseHandle"), Some(4));
        assert_eq!(set.api_id("kernel32!GetOverlappedResult"), Some(5));
        assert_eq!(set.api_id("kernel32!GetQueuedCompletionStatus"), Some(6));
        assert_eq!(set.api_id("kernel32!Nope"), None);
        let schemas = set.schemas();
        let ids: Vec<u32> = schemas.iter().map(|s| s.schema_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(schemas[0].name, "kernel32!CreateFileW/enter");
        assert_eq!(schemas[1].name, "kernel32!CreateFileW/leave");
    }

    #[test]
    fn duplicate_and_empty_names_rejected() {
        let mut set = ApiSet::new();
        let spec = ApiSpec::new(
            "a!B",
            &[],
            &[("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After)],
        );
        assert!(matches!(set.add(spec.clone()), Ok(1)));
        assert!(matches!(
            set.add(spec),
            Err(EmitError::DuplicateApi(ref n)) if n == "a!B"
        ));
        assert!(matches!(
            set.add(ApiSpec::new("", &[], &[])),
            Err(EmitError::InvalidSpec(_))
        ));
    }

    /// 共有セットの互換の定義：本体フック表と content_hash が一致する。
    #[test]
    fn file_io_schemas_match_hook_table_hashes() {
        let mine = file_io_api_set().schemas();
        // file_io セットは手書きの 6 API に対応する（生成 API は別物）。
        let hook = shirusu_hook::api::handwritten_schemas();
        assert_eq!(mine.len(), hook.len());
        for (a, b) in mine.iter().zip(hook.iter()) {
            assert_eq!(a.schema_id, b.schema_id);
            assert_eq!(a.name, b.name, "schema name drift at id {}", a.schema_id);
            assert_eq!(
                a.content_hash, b.content_hash,
                "schema content drift at {}",
                a.name
            );
        }
    }

    #[test]
    fn file_io_last_error_meanings_match_hook_table() {
        // F20: 共有セットの意味条件が本体フック表と一致する。
        // content_hash の一致テストが flags の一致を保証するが、ここでは
        // API ごとの意味を明示して固定する。
        use shirusu_trace::schema::LastErrorMeaning;
        let set = file_io_api_set();
        // file_io セットは手書きの 6 API に対応する（生成 API は別物）。
        let hook = shirusu_hook::api::HANDWRITTEN_API_TABLE;
        assert_eq!(set.len(), hook.len());
        for (spec, def) in set.specs.iter().zip(hook.iter()) {
            assert_eq!(
                spec.last_error_meaning, def.last_error_meaning,
                "{}",
                spec.name
            );
        }
        assert_eq!(
            set.spec(1).unwrap().last_error_meaning,
            LastErrorMeaning::WhenReturnIsInvalidHandle,
            "CreateFileW"
        );
        assert_eq!(
            set.spec(2).unwrap().last_error_meaning,
            LastErrorMeaning::WhenReturnIsFalse,
            "ReadFile"
        );
    }
}
