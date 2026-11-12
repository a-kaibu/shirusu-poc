//! Trace 形式まわりのエラー型。各層（Protobuf / Compact / Container /
//! Blob / Reader）ごとに分け、呼び出し側が「破損の種類」を区別できる
//! ようにする。Reader の回復処理は、これらのエラーを issue として
//! 集めるため、エラーは値として完結している必要がある。

use std::fmt;

/// Protobuf ワイヤ形式の復号エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// varint が 10 バイトを超えた、または終端しなかった。
    VarintTooLong,
    /// 長さフィールドが残りバイト数を超えた。
    LengthOutOfRange { len: u64, remaining: usize },
    /// 未知の wire type（0..=5 の範囲外、または group の開始/終了）。
    InvalidWireType(u32),
    /// フィールド番号 0 は Protobuf では無効。
    InvalidFieldNumber,
    /// 固定長フィールドの途中切断。
    TruncatedFixed,
    /// 文字列フィールドが UTF-8 でない。
    InvalidUtf8,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarintTooLong => write!(f, "varint too long or unterminated"),
            Self::LengthOutOfRange { len, remaining } => {
                write!(f, "length {len} exceeds remaining {remaining} bytes")
            }
            Self::InvalidWireType(w) => write!(f, "invalid wire type {w}"),
            Self::InvalidFieldNumber => write!(f, "field number 0 is invalid"),
            Self::TruncatedFixed => write!(f, "fixed-width field truncated"),
            Self::InvalidUtf8 => write!(f, "string field is not valid UTF-8"),
        }
    }
}
impl std::error::Error for ProtoError {}

/// Compact Binary の符号化・復号エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactError {
    /// 入力が途中で終わった。
    Truncated,
    /// LEB128 が 10 バイトを超えた、または終端しなかった。
    Leb128TooLong,
    /// bool の値が 0 / 1 以外。
    InvalidBool(u8),
    /// 取得状態の値が未知（イベント単位の Other 保持とは別に、値列では拒否する）。
    InvalidCapture(u8),
    /// Str が UTF-8 でない。
    InvalidUtf8,
    /// 値の個数が Schema のフィールド数と一致しない。
    FieldCountMismatch { expected: usize, actual: usize },
    /// 値の型が Schema のフィールド型と一致しない。
    TypeMismatch { field: usize },
    /// 未知の型タグを持つ Schema で復号しようとした。
    UnknownType(u32),
    /// 復号後に余分なバイトが残った。
    TrailingBytes(usize),
}

impl fmt::Display for CompactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "compact input truncated"),
            Self::Leb128TooLong => write!(f, "LEB128 too long or unterminated"),
            Self::InvalidBool(v) => write!(f, "invalid bool value {v}"),
            Self::InvalidCapture(v) => write!(f, "invalid capture state {v}"),
            Self::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            Self::FieldCountMismatch { expected, actual } => {
                write!(f, "field count mismatch: expected {expected}, got {actual}")
            }
            Self::TypeMismatch { field } => write!(f, "type mismatch at field {field}"),
            Self::UnknownType(t) => write!(f, "unknown type tag {t}"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after values"),
        }
    }
}
impl std::error::Error for CompactError {}

/// Trace 全体の読み書きエラー。
#[derive(Debug)]
pub enum TraceError {
    Io(std::io::Error),
    Proto(ProtoError),
    Compact(CompactError),
    /// ファイル先頭が Header Block ではない（Trace ではない入力）。
    NotATrace,
    /// Block ヘッダーの CRC 不一致など、単一 Block の破損。
    CorruptBlock {
        offset: u64,
        reason: String,
    },
    /// 圧縮方式が未知。
    UnknownCompression(u8),
    /// Zstd 展開に失敗した。
    ZstdDecode(String),
    /// Blob の内容が ID（BLAKE3）と一致しない。
    BlobHashMismatch,
    /// Writer の不変条件違反（例: 未登録 Blob への参照、sequence 後退）。
    WriterInvariant(String),
    /// API の使い方の誤り（例: 復号対象の Schema が無い）。
    InvalidInput(String),
    /// Reader の上限（Block 数など）を超過した。
    LimitExceeded(&'static str),
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Proto(e) => write!(f, "protobuf error: {e}"),
            Self::Compact(e) => write!(f, "compact binary error: {e}"),
            Self::NotATrace => write!(f, "input does not start with a trace header block"),
            Self::CorruptBlock { offset, reason } => {
                write!(f, "corrupt block at {offset}: {reason}")
            }
            Self::UnknownCompression(c) => write!(f, "unknown compression {c}"),
            Self::ZstdDecode(m) => write!(f, "zstd decode failed: {m}"),
            Self::BlobHashMismatch => write!(f, "blob content does not match its BLAKE3 id"),
            Self::WriterInvariant(m) => write!(f, "writer invariant violated: {m}"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::LimitExceeded(what) => write!(f, "reader limit exceeded: {what}"),
        }
    }
}
impl std::error::Error for TraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Proto(e) => Some(e),
            Self::Compact(e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for TraceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ProtoError> for TraceError {
    fn from(e: ProtoError) -> Self {
        Self::Proto(e)
    }
}
impl From<CompactError> for TraceError {
    fn from(e: CompactError) -> Self {
        Self::Compact(e)
    }
}

pub type Result<T> = std::result::Result<T, TraceError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn proto_error_display_covers_all_variants() {
        assert_eq!(
            ProtoError::VarintTooLong.to_string(),
            "varint too long or unterminated"
        );
        assert_eq!(
            ProtoError::LengthOutOfRange {
                len: 10,
                remaining: 3
            }
            .to_string(),
            "length 10 exceeds remaining 3 bytes"
        );
        assert_eq!(
            ProtoError::InvalidWireType(7).to_string(),
            "invalid wire type 7"
        );
        assert_eq!(
            ProtoError::InvalidFieldNumber.to_string(),
            "field number 0 is invalid"
        );
        assert_eq!(
            ProtoError::TruncatedFixed.to_string(),
            "fixed-width field truncated"
        );
        assert_eq!(
            ProtoError::InvalidUtf8.to_string(),
            "string field is not valid UTF-8"
        );
    }

    #[test]
    fn compact_error_display_covers_all_variants() {
        assert_eq!(
            CompactError::Truncated.to_string(),
            "compact input truncated"
        );
        assert_eq!(
            CompactError::Leb128TooLong.to_string(),
            "LEB128 too long or unterminated"
        );
        assert_eq!(
            CompactError::InvalidBool(2).to_string(),
            "invalid bool value 2"
        );
        assert_eq!(
            CompactError::InvalidCapture(9).to_string(),
            "invalid capture state 9"
        );
        assert_eq!(
            CompactError::InvalidUtf8.to_string(),
            "string is not valid UTF-8"
        );
        assert_eq!(
            CompactError::FieldCountMismatch {
                expected: 3,
                actual: 2
            }
            .to_string(),
            "field count mismatch: expected 3, got 2"
        );
        assert_eq!(
            CompactError::TypeMismatch { field: 1 }.to_string(),
            "type mismatch at field 1"
        );
        assert_eq!(
            CompactError::UnknownType(99).to_string(),
            "unknown type tag 99"
        );
        assert_eq!(
            CompactError::TrailingBytes(5).to_string(),
            "5 trailing bytes after values"
        );
    }

    #[test]
    fn trace_error_display_covers_all_variants() {
        assert_eq!(
            TraceError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "nope")).to_string(),
            "io error: nope"
        );
        assert_eq!(
            TraceError::Proto(ProtoError::VarintTooLong).to_string(),
            "protobuf error: varint too long or unterminated"
        );
        assert_eq!(
            TraceError::Compact(CompactError::Truncated).to_string(),
            "compact binary error: compact input truncated"
        );
        assert_eq!(
            TraceError::NotATrace.to_string(),
            "input does not start with a trace header block"
        );
        assert_eq!(
            TraceError::CorruptBlock {
                offset: 128,
                reason: "crc mismatch".to_string()
            }
            .to_string(),
            "corrupt block at 128: crc mismatch"
        );
        assert_eq!(
            TraceError::UnknownCompression(7).to_string(),
            "unknown compression 7"
        );
        assert_eq!(
            TraceError::ZstdDecode("bad frame".to_string()).to_string(),
            "zstd decode failed: bad frame"
        );
        assert_eq!(
            TraceError::BlobHashMismatch.to_string(),
            "blob content does not match its BLAKE3 id"
        );
        assert_eq!(
            TraceError::WriterInvariant("seq regressed".to_string()).to_string(),
            "writer invariant violated: seq regressed"
        );
        assert_eq!(
            TraceError::InvalidInput("no schema".to_string()).to_string(),
            "invalid input: no schema"
        );
        assert_eq!(
            TraceError::LimitExceeded("blocks").to_string(),
            "reader limit exceeded: blocks"
        );
    }

    #[test]
    fn trace_error_source_links_wrapped_errors_only() {
        let io = TraceError::Io(std::io::Error::other("x"));
        assert!(io.source().is_some());
        assert_eq!(
            TraceError::Proto(ProtoError::InvalidUtf8)
                .source()
                .unwrap()
                .to_string(),
            "string field is not valid UTF-8"
        );
        assert_eq!(
            TraceError::Compact(CompactError::Truncated)
                .source()
                .unwrap()
                .to_string(),
            "compact input truncated"
        );
        assert!(TraceError::NotATrace.source().is_none());
        assert!(TraceError::BlobHashMismatch.source().is_none());
        assert!(TraceError::CorruptBlock {
            offset: 0,
            reason: String::new()
        }
        .source()
        .is_none());
    }

    #[test]
    fn trace_error_from_conversions_wrap_each_layer() {
        let io: TraceError =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into();
        assert!(matches!(io, TraceError::Io(_)));
        let proto: TraceError = ProtoError::TruncatedFixed.into();
        assert!(matches!(
            proto,
            TraceError::Proto(ProtoError::TruncatedFixed)
        ));
        let compact: TraceError = CompactError::Leb128TooLong.into();
        assert!(matches!(
            compact,
            TraceError::Compact(CompactError::Leb128TooLong)
        ));
    }
}
