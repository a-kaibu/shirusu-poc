//! 公開 Trace のイベントモデル。Host が検証済みイベント列をこの形へ
//! 変換し、Trace Writer が書き、Trace Reader がこの形で返す。
//!
//! A72 の不変条件：このモデルに `TemporaryPayloadKey` は存在しない。
//! Payload は Blob ID・インライン・欠落理由のいずれかでしか表せない。

use crate::blob::BlobId;
use crate::schema::EventCapture;

/// 欠落した Payload の理由（Dropped の 1 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadLossReason {
    Backpressure,
    TooLarge,
    Overflow,
    HostStopped,
    Other,
}

impl PayloadLossReason {
    pub fn code(self) -> u8 {
        match self {
            Self::Backpressure => 1,
            Self::TooLarge => 2,
            Self::Overflow => 3,
            Self::HostStopped => 4,
            Self::Other => 255,
        }
    }
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Backpressure,
            2 => Self::TooLarge,
            3 => Self::Overflow,
            4 => Self::HostStopped,
            _ => Self::Other,
        }
    }
}

/// イベントの Payload 参照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadRef {
    /// Payload 無し（長さ 0 の取得済み Payload も含む）。
    None,
    /// Blob として保存済み。実体は Blob Chunk / Blob ストア側にある。
    Blob(BlobId),
    /// 小さいためイベント列へ直接埋め込んだバイト列。
    Inline(Vec<u8>),
    /// 欠落した Payload。元長と理由だけを残す（A72：キーは生成しない）。
    Dropped {
        original_len: u64,
        reason: PayloadLossReason,
    },
}

/// 公開 Trace の 1 イベント。sequence と timestamp_qpc は Writer 内の
/// 絶対値（符号化時は Batch 内差分になる）。
#[derive(Debug, Clone, PartialEq)]
pub struct TraceEvent {
    /// 転送 Descriptor の kind と同じ番号（1 = CallEnter、2 = CallLeave、
    /// 7 = CallAborted、8 = CallCompleted）。
    pub kind: u16,
    pub sequence: u64,
    pub timestamp_qpc: u64,
    pub call_id: u64,
    pub parent_call_id: u64,
    pub api_id: u32,
    /// 引数値列の Schema。0 は「引数なし / 未割当」。
    pub schema_id: u32,
    pub capture: EventCapture,
    pub payload: PayloadRef,
    /// Compact Binary で符号化済みの引数値列（生バイト列のまま保持し、
    /// Schema で解釈するのは読み手）。None は引数なし。
    pub args: Option<Vec<u8>>,
    /// 全スレッド共通の観測順序番号（L11 `--order=global`）。
    /// None は「未割当」（同オプション無効時に記録されたイベント）。
    /// Some の値は 1 始まりで、同一 Batch 内では厳密に増加する。
    pub global_order: Option<u64>,
}

impl TraceEvent {
    /// L15: トップレベルの呼び出しか（親を持たない呼び出しか）。
    /// 詳細調査モードで記録された内部呼び出し（Nt* など）は
    /// `parent_call_id` に親の call_id を持つため false になる。
    /// 再実行・Probe 生成ではトップレベルの呼び出しだけを実行し、
    /// 下位呼び出しを重ねて実行しない（overview「記録境界と
    /// モジュール分類」節。`top_level_events` も参照）。
    pub fn is_top_level(&self) -> bool {
        self.parent_call_id == 0
    }

    /// L15: 下位呼び出しか（親を持つ呼び出しか）。
    pub fn is_nested(&self) -> bool {
        !self.is_top_level()
    }
}

/// L15: イベント列からトップレベルの呼び出しだけを抜き出す（順序は
/// 維持する）。再実行・Probe 生成の入力にするためのもの。下位呼び出し
/// （`parent_call_id != 0` のイベント）は、親の操作の一部として既に
/// 実行されるため、ここには含めない。親子関係の検証（子の親が列に
/// 存在するか等）は呼び出し側の責任。
pub fn top_level_events(events: &[TraceEvent]) -> Vec<&TraceEvent> {
    events.iter().filter(|e| e.is_top_level()).collect()
}

/// Event Batch：同一 Writer（スレッド）のイベント列と、その文脈。
/// 共通情報はバッチに一度だけ書く（overview の決定）。
#[derive(Debug, Clone, PartialEq)]
pub struct EventBatch {
    pub session_id: u64,
    pub process_id: u64,
    /// OS の PID 生値。
    pub raw_pid: u32,
    pub thread_id: u64,
    pub qpc_frequency: u64,
    pub events: Vec<TraceEvent>,
}

impl EventBatch {
    pub fn first_sequence(&self) -> u64 {
        self.events.first().map(|e| e.sequence).unwrap_or(0)
    }
    pub fn base_timestamp_qpc(&self) -> u64 {
        self.events.first().map(|e| e.timestamp_qpc).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(call_id: u64, parent_call_id: u64, api_id: u32) -> TraceEvent {
        TraceEvent {
            kind: 1,
            sequence: call_id,
            timestamp_qpc: 1000 + call_id,
            call_id,
            parent_call_id,
            api_id,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
            global_order: None,
        }
    }

    #[test]
    fn top_level_events_keeps_only_calls_without_a_parent() {
        // L15: CreateFileW (call 10) の内側の NtCreateFile (call 11) と
        // NtClose (call 13) は親を持つため除外され、トップレベルの
        // CreateFileW / CloseHandle だけが残る（順序は維持）。
        let events = vec![
            event(10, 0, 1),
            event(11, 10, 79),
            event(12, 0, 4),
            event(13, 12, 83),
        ];
        assert!(events[0].is_top_level());
        assert!(!events[0].is_nested());
        assert!(!events[1].is_top_level());
        assert!(events[1].is_nested());
        let top = top_level_events(&events);
        let ids: Vec<u64> = top.iter().map(|e| e.call_id).collect();
        assert_eq!(ids, vec![10, 12]);
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn top_level_events_of_empty_is_empty() {
        let events: Vec<TraceEvent> = Vec::new();
        assert!(top_level_events(&events).is_empty());
    }
}
