//! Schema と型付き値のモデル。形式の正は `docs/trace-format.md` の
//! 「Compact Binary」節。
//!
//! Schema は「ファイル内連番の Schema ID」「名前」「フィールド列」で
//! 定義され、正規化内容の BLAKE3 ハッシュ（先頭 8 バイト）で別 Trace
//! 間の同一性を判定する。一度発行した Schema ID のレイアウトは変更
//! しない。

use crate::blob::BlobId;
use crate::proto::{FieldDef, SchemaDef};

/// フィールド型タグ（FieldDef.ty の値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ty {
    I32,
    I64,
    U32,
    U64,
    F32,
    F64,
    Bool,
    Str,
    Str16,
    Bytes,
    BlobRef,
    Ptr32,
    Ptr64,
}

impl Ty {
    pub fn tag(self) -> u32 {
        match self {
            Self::I32 => 1,
            Self::I64 => 2,
            Self::U32 => 3,
            Self::U64 => 4,
            Self::F32 => 5,
            Self::F64 => 6,
            Self::Bool => 7,
            Self::Str => 8,
            Self::Str16 => 9,
            Self::Bytes => 10,
            Self::BlobRef => 11,
            Self::Ptr32 => 12,
            Self::Ptr64 => 13,
        }
    }
    pub fn from_tag(tag: u32) -> Option<Self> {
        Some(match tag {
            1 => Self::I32,
            2 => Self::I64,
            3 => Self::U32,
            4 => Self::U64,
            5 => Self::F32,
            6 => Self::F64,
            7 => Self::Bool,
            8 => Self::Str,
            9 => Self::Str16,
            10 => Self::Bytes,
            11 => Self::BlobRef,
            12 => Self::Ptr32,
            13 => Self::Ptr64,
            _ => return None,
        })
    }
}

/// フィールド値の意味種別（FieldDef.flags の bit2..=4 に格納する）。
///
/// 型 (Ty) だけでは「64bit 整数が個数なのか、ハンドルなのか、
/// アドレスなのか」は決まらない。正規化や比較が型だけで推定すると
/// スカラーの変化を見落とすため (レビュー #4 の #7)、Schema が
/// 意味を宣言し、利用側はそれに従う。bit0/bit1 は形式仕様で
/// inout / 省略可能に予約済みのため、種別は bit2 から置く。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// 未指定（種別ビットが 0）。意味情報を持たない旧来の Schema 用。
    /// 利用側は型からの推定にフォールバックする（推定の限界は
    /// 利用側の文書に明記される）。
    Unspecified,
    /// 純粋なスカラー（個数・時刻・カウンタ・真理値など）。値を
    /// そのまま比較する。U64 でもポインタとして扱ってはいけない。
    Scalar,
    /// メモリアドレス。中身は環境依存のため比較せず、存在と
    /// Null/Invalid の区別だけを見る。
    Pointer,
    /// オブジェクトへのハンドル。生成イベントとの相関で同一性を
    /// 解決し、相関できなければポインタ級として扱う。
    Handle,
    /// このフィールドの値が新しいオブジェクトの生成である
    /// （生成 API の戻り値など）。相関の起点になる。
    CreatedObject,
}

/// ValueKind を格納するフラグビット範囲 (bit2..=4)。
pub const VALUE_KIND_SHIFT: u32 = 2;
pub const VALUE_KIND_MASK: u32 = 0b111 << VALUE_KIND_SHIFT;

impl ValueKind {
    pub fn from_flags(flags: u32) -> Self {
        match (flags & VALUE_KIND_MASK) >> VALUE_KIND_SHIFT {
            1 => Self::Scalar,
            2 => Self::Pointer,
            3 => Self::Handle,
            4 => Self::CreatedObject,
            _ => Self::Unspecified,
        }
    }
    /// flags へ埋め込む値（他のビットは含まない）。
    pub fn flags(self) -> u32 {
        let v = match self {
            Self::Unspecified => 0,
            Self::Scalar => 1,
            Self::Pointer => 2,
            Self::Handle => 3,
            Self::CreatedObject => 4,
        };
        v << VALUE_KIND_SHIFT
    }
}

/// 型付き値。生ビット列を保持する方針（浮動小数点はビットで保持し、
/// NaN ペイロードを失わない）に従い、F32/F64 はビット表現で持つ。
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32Bits(u32),
    F64Bits(u64),
    Bool(bool),
    Str(String),
    Str16(Vec<u16>),
    Bytes(Vec<u8>),
    BlobRef(BlobId),
    Ptr32(u32),
    Ptr64(u64),
}

impl TypedValue {
    pub fn ty(&self) -> Ty {
        match self {
            Self::I32(_) => Ty::I32,
            Self::I64(_) => Ty::I64,
            Self::U32(_) => Ty::U32,
            Self::U64(_) => Ty::U64,
            Self::F32Bits(_) => Ty::F32,
            Self::F64Bits(_) => Ty::F64,
            Self::Bool(_) => Ty::Bool,
            Self::Str(_) => Ty::Str,
            Self::Str16(_) => Ty::Str16,
            Self::Bytes(_) => Ty::Bytes,
            Self::BlobRef(_) => Ty::BlobRef,
            Self::Ptr32(_) => Ty::Ptr32,
            Self::Ptr64(_) => Ty::Ptr64,
        }
    }
}

/// 値ごとの取得状態（Compact Binary の値列で使う 1 バイト）。
/// 読めなかった値を NULL として保存しないための区別であり、
/// Unreadable / Unsupported の値本体はダミー（0 / 空）が入る。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueCapture {
    Captured,
    Unreadable,
    Truncated,
    Unsupported,
    LimitExceeded,
}

impl ValueCapture {
    pub fn code(self) -> u8 {
        match self {
            Self::Captured => 0,
            Self::Unreadable => 1,
            Self::Truncated => 2,
            Self::Unsupported => 3,
            Self::LimitExceeded => 4,
        }
    }
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Captured,
            1 => Self::Unreadable,
            2 => Self::Truncated,
            3 => Self::Unsupported,
            4 => Self::LimitExceeded,
            _ => return None,
        })
    }
}

/// 取得状態付きの値（値列の要素）。
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedValue {
    pub capture: ValueCapture,
    pub value: TypedValue,
}

impl CapturedValue {
    pub fn captured(value: TypedValue) -> Self {
        Self {
            capture: ValueCapture::Captured,
            value,
        }
    }
}

/// イベント単位の取得状態。転送 `CaptureState` の意味を保ち、本形式の
/// 連番で表す。未知の番号は `Other` として保持し、往復で失わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCapture {
    Captured,
    MemoryUnreadable,
    CaptureLimitExceeded,
    DroppedByBackpressure,
    Truncated,
    Unsupported,
    Other(u8),
}

impl EventCapture {
    pub fn code(self) -> u8 {
        match self {
            Self::Captured => 0,
            Self::MemoryUnreadable => 1,
            Self::CaptureLimitExceeded => 2,
            Self::DroppedByBackpressure => 3,
            Self::Truncated => 4,
            Self::Unsupported => 5,
            Self::Other(c) => c,
        }
    }
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Captured,
            1 => Self::MemoryUnreadable,
            2 => Self::CaptureLimitExceeded,
            3 => Self::DroppedByBackpressure,
            4 => Self::Truncated,
            5 => Self::Unsupported,
            c => Self::Other(c),
        }
    }
}

/// Schema の正規化内容ハッシュ（BLAKE3 先頭 8 バイト、LE u64）。
/// 正規化は「名前のバイト列＋フィールドごとに (名前, ty, flags) を
/// LEB128 で並べたもの」。別 Trace 間の同一性判定の目安であり、
/// セキュリティ用途ではない（trace-format.md の決定）。
pub fn schema_content_hash(name: &str, fields: &[FieldDef]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(name.as_bytes());
    h.update(&[0xff]); // 名前とフィールド列の境界を曖昧にしない区切り
    for f in fields {
        h.update(f.name.as_bytes());
        h.update(&[0]);
        h.update(&f.ty.to_le_bytes());
        h.update(&f.flags.to_le_bytes());
    }
    let digest = h.finalize();
    u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"))
}

/// 検証済み Schema 定義から Compact 用の型列を取り出す。
/// 未知の型タグが含まれていたら None（その Schema での復号は拒否）。
pub fn schema_types(def: &SchemaDef) -> Option<Vec<Ty>> {
    def.fields.iter().map(|f| Ty::from_tag(f.ty)).collect()
}

/// ファイル内の Schema 集合。定義の登録時に正規化ハッシュを検証する。
#[derive(Debug, Default)]
pub struct SchemaRegistry {
    by_id: std::collections::HashMap<u32, SchemaDef>,
    order: Vec<u32>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// 定義を登録する。content_hash が正規化ハッシュと一致しない定義、
    /// schema_id 0、既存 ID と異なる内容の再定義は拒否する。
    /// 同一内容の再登録（Checkpoint での複製）は冪等に成功する。
    pub fn register(&mut self, def: SchemaDef) -> Result<(), String> {
        if def.schema_id == 0 {
            return Err("schema_id 0 is reserved".into());
        }
        let expected = schema_content_hash(&def.name, &def.fields);
        if def.content_hash != expected {
            return Err(format!(
                "schema {} content_hash mismatch: stored {:#x}, computed {:#x}",
                def.schema_id, def.content_hash, expected
            ));
        }
        if let Some(existing) = self.by_id.get(&def.schema_id) {
            if existing == &def {
                return Ok(());
            }
            return Err(format!(
                "schema_id {} redefined with different content",
                def.schema_id
            ));
        }
        self.order.push(def.schema_id);
        self.by_id.insert(def.schema_id, def);
        Ok(())
    }
    pub fn get(&self, schema_id: u32) -> Option<&SchemaDef> {
        self.by_id.get(&schema_id)
    }
    pub fn types(&self, schema_id: u32) -> Option<Vec<Ty>> {
        self.by_id.get(&schema_id).and_then(schema_types)
    }
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
    /// 登録順の Schema ID 列。
    pub fn ids(&self) -> &[u32] {
        &self.order
    }
}

/// フィールド列から SchemaDef を組み立てる（content_hash を計算して埋める）。
pub fn make_schema(schema_id: u32, name: &str, fields: Vec<(String, Ty, u32)>) -> SchemaDef {
    let fields: Vec<FieldDef> = fields
        .into_iter()
        .map(|(name, ty, flags)| FieldDef {
            name,
            ty: ty.tag(),
            flags,
        })
        .collect();
    SchemaDef {
        schema_id,
        name: name.to_string(),
        content_hash: schema_content_hash(name, &fields),
        fields,
        annotation: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_kind_flags_roundtrip() {
        for kind in [
            ValueKind::Unspecified,
            ValueKind::Scalar,
            ValueKind::Pointer,
            ValueKind::Handle,
            ValueKind::CreatedObject,
        ] {
            assert_eq!(ValueKind::from_flags(kind.flags()), kind);
            // 種別は bit0/bit1 (形式仕様の予約) に触れない
            assert_eq!(kind.flags() & 0b11, 0);
            // 他のビットと合成しても読み戻せる
            assert_eq!(ValueKind::from_flags(kind.flags() | 0b11), kind);
        }
        // 未知の種別値は Unspecified として読む (前方互換)
        assert_eq!(
            ValueKind::from_flags(7 << VALUE_KIND_SHIFT),
            ValueKind::Unspecified
        );
        assert_eq!(ValueKind::from_flags(0), ValueKind::Unspecified);
    }

    #[test]
    fn value_kind_changes_content_hash() {
        // 意味が違う Schema は別物として判定される (flags は
        // content_hash の入力に含まれる)。
        let scalar = make_schema(
            1,
            "a!B/leave",
            vec![("return".into(), Ty::U64, ValueKind::Scalar.flags())],
        );
        let created = make_schema(
            1,
            "a!B/leave",
            vec![("return".into(), Ty::U64, ValueKind::CreatedObject.flags())],
        );
        assert_ne!(scalar.content_hash, created.content_hash);
    }
}
