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

use crate::EmitError;
use shirusu_trace::proto::SchemaDef;
use shirusu_trace::schema::{make_schema, Ty, ValueKind};

/// 1 API の Schema 仕様。enter / leave それぞれのフィールド列が
/// Compact Binary の値列の順序そのものを定める。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSpec {
    /// API 名。`モジュール!関数` 形式（例 `kernel32!CreateFileW`）。
    pub name: String,
    pub enter_fields: Vec<(String, Ty, ValueKind)>,
    pub leave_fields: Vec<(String, Ty, ValueKind)>,
    /// SchemaDef.annotation へ写される注記（観測レベル等）。
    pub annotation: String,
}

impl ApiSpec {
    pub fn new(
        name: &str,
        enter_fields: &[(&str, Ty, ValueKind)],
        leave_fields: &[(&str, Ty, ValueKind)],
    ) -> Self {
        ApiSpec {
            name: name.to_string(),
            enter_fields: enter_fields
                .iter()
                .map(|(n, t, k)| (n.to_string(), *t, *k))
                .collect(),
            leave_fields: leave_fields
                .iter()
                .map(|(n, t, k)| (n.to_string(), *t, *k))
                .collect(),
            annotation: String::new(),
        }
    }

    pub fn with_annotation(mut self, annotation: &str) -> Self {
        self.annotation = annotation.to_string();
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
                    .map(|(n, t, k)| (n.clone(), *t, k.flags()))
                    .collect(),
            );
            enter.annotation = spec.annotation.clone();
            let mut leave = make_schema(
                Self::leave_schema_id(api_id),
                &format!("{}/leave", spec.name),
                spec.leave_fields
                    .iter()
                    .map(|(n, t, k)| (n.clone(), *t, k.flags()))
                    .collect(),
            );
            leave.annotation = spec.annotation.clone();
            v.push(enter);
            v.push(leave);
        }
        v
    }
}

/// shirusu 本体のフック表（shirusu-hook `API_TABLE`）と同一の
/// ファイル I/O 4 API セット。本体が記録した Trace と外部レコーダの
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
                ("lpFileName", Ty::Str16, ValueKind::Scalar),
                ("dwDesiredAccess", DWORD, ValueKind::Scalar),
                ("dwShareMode", DWORD, ValueKind::Scalar),
                ("lpSecurityAttributes", HANDLE, ValueKind::Pointer),
                ("dwCreationDisposition", DWORD, ValueKind::Scalar),
                ("dwFlagsAndAttributes", DWORD, ValueKind::Scalar),
                ("hTemplateFile", HANDLE, ValueKind::Handle),
            ],
            &[
                ("return", HANDLE, ValueKind::CreatedObject),
                ("last_error", DWORD, ValueKind::Scalar),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook API_TABLE と同一定義)"),
        ApiSpec::new(
            "kernel32!ReadFile",
            &[
                ("hFile", HANDLE, ValueKind::Handle),
                ("lpBuffer", HANDLE, ValueKind::Pointer),
                ("nNumberOfBytesToRead", DWORD, ValueKind::Scalar),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar),
                ("lpNumberOfBytesRead", DWORD, ValueKind::Scalar),
                ("data", Ty::Bytes, ValueKind::Scalar),
                ("last_error", DWORD, ValueKind::Scalar),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook API_TABLE と同一定義)"),
        ApiSpec::new(
            "kernel32!WriteFile",
            &[
                ("hFile", HANDLE, ValueKind::Handle),
                ("data", Ty::Bytes, ValueKind::Scalar),
                ("nNumberOfBytesToWrite", DWORD, ValueKind::Scalar),
            ],
            &[
                ("return", BOOL, ValueKind::Scalar),
                ("lpNumberOfBytesWritten", DWORD, ValueKind::Scalar),
                ("last_error", DWORD, ValueKind::Scalar),
            ],
        )
        .with_annotation("L2 (file_io_api_set: shirusu-hook API_TABLE と同一定義)"),
        ApiSpec::new(
            "kernel32!CloseHandle",
            &[("hObject", HANDLE, ValueKind::Handle)],
            &[
                ("return", BOOL, ValueKind::Scalar),
                ("last_error", DWORD, ValueKind::Scalar),
            ],
        )
        .with_annotation("L1 (file_io_api_set: shirusu-hook API_TABLE と同一定義)"),
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
        assert_eq!(set.len(), 4);
        assert_eq!(set.api_id("kernel32!CreateFileW"), Some(1));
        assert_eq!(set.api_id("kernel32!CloseHandle"), Some(4));
        assert_eq!(set.api_id("kernel32!Nope"), None);
        let schemas = set.schemas();
        let ids: Vec<u32> = schemas.iter().map(|s| s.schema_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(schemas[0].name, "kernel32!CreateFileW/enter");
        assert_eq!(schemas[1].name, "kernel32!CreateFileW/leave");
    }

    #[test]
    fn duplicate_and_empty_names_rejected() {
        let mut set = ApiSet::new();
        let spec = ApiSpec::new("a!B", &[], &[("return", Ty::I32, ValueKind::Scalar)]);
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
        let hook = shirusu_hook::api::all_schemas();
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
}
