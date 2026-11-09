//! shirusu-transport: Agent–Host 転送仕様 v0.4 の核（Windows 非依存）。
//!
//! - [`descriptor`]: 64B 固定 EventDescriptor と値ごとの取得結果
//! - [`layout`]: Control 領域のキャッシュライン分離と Cursor 演算
//! - [`ring`]: SPSC Ring（単一公開点の契約、満杯ポリシー状態機械）
//! - [`snapshot`]: 大きな Snapshot の Fragment 分割
//! - [`notify`]: 通知の純粋ロジック（2ms 再確認、閾値越え通知）
//! - [`slot`]: Slot 状態遷移（FREE→CLAIMED→ACTIVE→DRAINING→RECLAIMABLE→FREE）
//! - [`expansion`]: 低水位時の非同期 Mapping 追加フロー (A70) の受け渡し口
//! - [`context`]: 再入ガードと Host 停止確認
//! - [`validate`]: Host 側の共有メモリ検証（writer API とは分離した純粋関数）
//! - `crc32c`: CRC32C

pub mod clock;
pub mod context;
pub mod crc32c;
pub mod descriptor;
pub mod expansion;
pub mod layout;
pub mod notify;
pub mod ring;
pub mod slot;
pub mod snapshot;
pub mod validate;

pub use clock::{
    system_timestamp_source, Clock, ManualClock, ManualTimestampSource, SystemClock,
    SystemTimestampSource, TimestampSource,
};
pub use descriptor::{CaptureState, EventDescriptor, EventKind};
pub use expansion::{ExpansionDelivery, ExpansionRequest, EXPANDED_SLOT_GENERATION};
pub use layout::{LossCounters, RingConfig};
pub use ring::{
    DrainBatch, EventInput, LoaderLockState, OverflowState, ReceivedEvent, RingReader, RingWriter,
    SharedRegion, WriteOutcome, WriterPolicy,
};
pub use slot::{SlotHandle, SlotPool, SlotState};
