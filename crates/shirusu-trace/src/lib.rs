//! shirusu-trace: 公開 Trace 形式 v1 の実装。
//!
//! 形式の正は `docs/trace-format.md`。構成は次のとおり。
//!
//! - [`container`]: Block Container（32 バイトヘッダー＋CRC32C）と
//!   チャンク単位の Zstd 圧縮。
//! - [`proto`]: Protobuf メタデータの手書きワイヤ形式符号化・復号。
//! - [`compact`]: スキーマ駆動 Compact Binary（値列とイベント列）。
//! - [`schema`]: Schema 定義・正規化ハッシュ・レジストリ。
//! - [`blob`]: BLAKE3 Blob ID とディレクトリ配置の Blob ストア。
//! - [`model`]: 公開 Trace のイベントモデル。A72 の不変条件として、
//!   このモデルに Host 内部の `TemporaryPayloadKey` は存在しない。
//!   Payload は Blob ID・インライン・欠落理由でのみ表す。
//! - [`writer`]: Trace Writer（前方参照禁止、チャンク分割、Index と
//!   Finalization の書出し）。
//! - [`reader`]: Trace Reader（回復意味論。壊れた入力は issue として
//!   記録し、読める範囲を返す）。

pub mod blob;
pub mod compact;
pub mod container;
pub mod error;
pub mod model;
pub mod proto;
pub mod reader;
pub mod schema;
pub mod writer;

pub use blob::{BlobId, BlobStore};
pub use error::{CompactError, ProtoError, Result, TraceError};
pub use model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
pub use reader::{
    read_trace, read_trace_with_limits, ReadTrace, ReaderLimits, RecoveryIssue, ScannedBlock,
};
pub use schema::{CapturedValue, EventCapture, SchemaRegistry, Ty, TypedValue, ValueCapture};
pub use writer::{FinalizationInfo, TraceWriter};

/// fuzz ターゲット `recover_trace` の入口であり、利用側の回復読みの
/// 既定経路。壊れた入力でも panic せず、Trace でなければ
/// `TraceError::NotATrace`、読める場合は issue 付きの結果を返す。
pub fn recover_trace(data: &[u8]) -> Result<ReadTrace> {
    reader::read_trace(data)
}
