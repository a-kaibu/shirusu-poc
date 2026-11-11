//! EventDescriptor: spec v0.4 の 64 バイト固定レイアウト。
//! 固定幅整数と明示的アラインメントだけを使い、x86/x64 で同一レイアウトにする。

/// イベント種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EventKind {
    Unknown = 0,
    CallEnter = 1,
    CallLeave = 2,
    SnapshotFragment = 3,
    SnapshotComplete = 4,
    Loss = 5,
    SlotExpandRequest = 6,
    /// 元の API 呼び出しが例外で中断した（L08）。CallLeave の代わりに
    /// 記録され、引数値列は無い。例外自体は Detour が捕捉しない。
    CallAborted = 7,
    /// 非同期 I/O が完了した（F27）。OVERLAPPED 指定の呼び出しの
    /// leave は未完了のため Unsupported だが、完了を観測した時点
    /// （GetOverlappedResult / GetQueuedCompletionStatus）で、元の
    /// 呼び出しの leave Schema の値列を改めて記録する。`schema_id`
    /// には元の API の leave Schema の ID を入れる。
    CallCompleted = 8,
}

impl EventKind {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0 => Self::Unknown,
            1 => Self::CallEnter,
            2 => Self::CallLeave,
            3 => Self::SnapshotFragment,
            4 => Self::SnapshotComplete,
            5 => Self::Loss,
            6 => Self::SlotExpandRequest,
            7 => Self::CallAborted,
            8 => Self::CallCompleted,
            _ => return None,
        })
    }
}

/// Descriptor flags (u16 ビット)。
pub mod flags {
    /// Payload 本体は転送されておらず、payload_len は「落とした元の長さ」。
    pub const PAYLOAD_DROPPED: u16 = 1 << 0;
    /// 値が切り捨てられた。
    pub const TRUNCATED: u16 = 1 << 1;
    /// 対象メモリが読めなかった。
    pub const MEMORY_UNREADABLE: u16 = 1 << 2;
    /// 設定上限を超えた。
    pub const CAPTURE_LIMIT_EXCEEDED: u16 = 1 << 3;
    /// 背圧で落とした。
    pub const DROPPED_BY_BACKPRESSURE: u16 = 1 << 4;
    /// 未対応の取得。
    pub const UNSUPPORTED: u16 = 1 << 5;
    /// Snapshot の同時点性は保証されない（Fragment 取得中の書換えがあり得る）。
    pub const SNAPSHOT_NOT_COHERENT: u16 = 1 << 6;
}

/// 値ごとの取得結果。Payload を落とした呼出は L1 として扱わないことを型で表すため、
/// `CaptureState` を持つイベントは `is_l1_eligible()` で判定できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureState {
    Captured,
    MemoryUnreadable,
    CaptureLimitExceeded,
    DroppedByBackpressure,
    Truncated,
    Unsupported,
}

impl CaptureState {
    pub fn to_flags(self) -> u16 {
        match self {
            Self::Captured => 0,
            Self::MemoryUnreadable => flags::MEMORY_UNREADABLE,
            Self::CaptureLimitExceeded => flags::CAPTURE_LIMIT_EXCEEDED,
            Self::DroppedByBackpressure => flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE,
            Self::Truncated => flags::TRUNCATED,
            Self::Unsupported => flags::UNSUPPORTED,
        }
    }
    pub fn from_flags(f: u16) -> Self {
        if f & flags::DROPPED_BY_BACKPRESSURE != 0 {
            Self::DroppedByBackpressure
        } else if f & flags::MEMORY_UNREADABLE != 0 {
            Self::MemoryUnreadable
        } else if f & flags::CAPTURE_LIMIT_EXCEEDED != 0 {
            Self::CaptureLimitExceeded
        } else if f & flags::TRUNCATED != 0 {
            Self::Truncated
        } else if f & flags::UNSUPPORTED != 0 {
            Self::Unsupported
        } else {
            Self::Captured
        }
    }
    /// Payload を落とした呼出は L1 扱いしない（spec: 欠落の記録）。
    pub fn is_l1_eligible(self) -> bool {
        !matches!(self, Self::DroppedByBackpressure)
    }
}

/// 64 バイト固定のイベント記述子。spec のフィールドそのまま。
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDescriptor {
    pub kind: u16,
    pub flags: u16,
    /// Payload が格納されている場合は格納長、落とした場合は元の長さ。
    pub payload_len: u32,
    pub sequence: u64,
    pub timestamp_qpc: u64,
    pub call_id: u64,
    pub parent_call_id: u64,
    /// Payload Ring 内の単調増加する論理オフセット（生ポインタではない）。
    pub payload_position: u64,
    pub api_id: u32,
    pub schema_id: u32,
    /// 全スレッド共通の観測順序番号（L11 `--order=global`）。
    /// 0 は「未割当」（同オプション無効時）。有効時は Agent が観測点で
    /// アトミックカウンタから採番した値（1 始まり）が入る。Payload の
    /// 識別子ではない（A72 の「Payload ID を持たない」決定は不変）。
    /// 64B レイアウトは維持し、旧 `reserved` 欄の再利用である。
    pub global_order: u64,
}

impl EventDescriptor {
    pub const SIZE: usize = 64;
    pub fn new(kind: EventKind, sequence: u64) -> Self {
        Self {
            kind: kind as u16,
            flags: 0,
            payload_len: 0,
            sequence,
            timestamp_qpc: 0,
            call_id: 0,
            parent_call_id: 0,
            payload_position: 0,
            api_id: 0,
            schema_id: 0,
            global_order: 0,
        }
    }
    pub fn kind_enum(&self) -> Option<EventKind> {
        EventKind::from_u16(self.kind)
    }
    pub fn capture_state(&self) -> CaptureState {
        CaptureState::from_flags(self.flags)
    }
    pub fn payload_dropped(&self) -> bool {
        self.flags & flags::PAYLOAD_DROPPED != 0
    }
    /// リトルエンディアンで 64 バイトへ符号化する（Host 検証モジュールと共有）。
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[2..4].copy_from_slice(&self.flags.to_le_bytes());
        b[4..8].copy_from_slice(&self.payload_len.to_le_bytes());
        b[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        b[16..24].copy_from_slice(&self.timestamp_qpc.to_le_bytes());
        b[24..32].copy_from_slice(&self.call_id.to_le_bytes());
        b[32..40].copy_from_slice(&self.parent_call_id.to_le_bytes());
        b[40..48].copy_from_slice(&self.payload_position.to_le_bytes());
        b[48..52].copy_from_slice(&self.api_id.to_le_bytes());
        b[52..56].copy_from_slice(&self.schema_id.to_le_bytes());
        b[56..64].copy_from_slice(&self.global_order.to_le_bytes());
        b
    }
    /// バイト列からの復号（長さ 64 未満は None）。検証は validate 側の責務。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 64 {
            return None;
        }
        let g16 = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        let g32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let g64 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Some(Self {
            kind: g16(0),
            flags: g16(2),
            payload_len: g32(4),
            sequence: g64(8),
            timestamp_qpc: g64(16),
            call_id: g64(24),
            parent_call_id: g64(32),
            payload_position: g64(40),
            api_id: g32(48),
            schema_id: g32(52),
            global_order: g64(56),
        })
    }
}

// 静的レイアウト検査（x86/x64 共通。両ターゲットでコンパイル時に検証される）。
const _: () = {
    assert!(core::mem::size_of::<EventDescriptor>() == 64);
    assert!(core::mem::align_of::<EventDescriptor>() == 64);
    assert!(core::mem::offset_of!(EventDescriptor, kind) == 0);
    assert!(core::mem::offset_of!(EventDescriptor, flags) == 2);
    assert!(core::mem::offset_of!(EventDescriptor, payload_len) == 4);
    assert!(core::mem::offset_of!(EventDescriptor, sequence) == 8);
    assert!(core::mem::offset_of!(EventDescriptor, timestamp_qpc) == 16);
    assert!(core::mem::offset_of!(EventDescriptor, call_id) == 24);
    assert!(core::mem::offset_of!(EventDescriptor, parent_call_id) == 32);
    assert!(core::mem::offset_of!(EventDescriptor, payload_position) == 40);
    assert!(core::mem::offset_of!(EventDescriptor, api_id) == 48);
    assert!(core::mem::offset_of!(EventDescriptor, schema_id) == 52);
    assert!(core::mem::offset_of!(EventDescriptor, global_order) == 56);
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_is_64_bytes() {
        assert_eq!(core::mem::size_of::<EventDescriptor>(), 64);
        assert_eq!(core::mem::offset_of!(EventDescriptor, payload_position), 40);
    }
    #[test]
    fn bytes_roundtrip() {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 42);
        d.api_id = 7;
        d.payload_position = 123_456;
        d.payload_len = 99;
        let b = d.to_bytes();
        assert_eq!(EventDescriptor::from_bytes(&b), Some(d));
        assert_eq!(EventDescriptor::from_bytes(&b[..63]), None);
    }
    #[test]
    fn call_completed_kind_roundtrips() {
        // F27: 非同期 I/O の完了を表す CallCompleted = 8。元の呼び出しの
        // leave Schema の値列を、完了を観測した時点で記録する。
        assert_eq!(EventKind::CallCompleted as u16, 8);
        assert_eq!(EventKind::from_u16(8), Some(EventKind::CallCompleted));
        assert_eq!(EventKind::from_u16(9), None);
    }
    #[test]
    fn call_aborted_kind_roundtrips() {
        // L08: 中断した呼び出しを表す CallAborted = 7。
        assert_eq!(EventKind::CallAborted as u16, 7);
        assert_eq!(EventKind::from_u16(7), Some(EventKind::CallAborted));
        assert_eq!(EventKind::from_u16(8), Some(EventKind::CallCompleted));
    }
    #[test]
    fn global_order_roundtrips_and_defaults_to_unassigned() {
        // L11: 既定は未割当 (0)。有効時は観測点で採番した値が入る。
        let d = EventDescriptor::new(EventKind::CallEnter, 1);
        assert_eq!(d.global_order, 0);
        let mut stamped = d;
        stamped.global_order = 123;
        assert_eq!(
            EventDescriptor::from_bytes(&stamped.to_bytes()),
            Some(stamped)
        );
    }
    #[test]
    fn capture_state_flags_roundtrip_and_l1() {
        for s in [
            CaptureState::Captured,
            CaptureState::MemoryUnreadable,
            CaptureState::CaptureLimitExceeded,
            CaptureState::DroppedByBackpressure,
            CaptureState::Truncated,
            CaptureState::Unsupported,
        ] {
            assert_eq!(CaptureState::from_flags(s.to_flags()), s);
        }
        assert!(!CaptureState::DroppedByBackpressure.is_l1_eligible());
        assert!(CaptureState::Captured.is_l1_eligible());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// 全フィールドが任意値でもバイト往復は恒等 (レイアウト解釈の安全性)。
    #[kani::proof]
    fn bytes_roundtrip_is_identity() {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 0);
        d.kind = kani::any();
        d.flags = kani::any();
        d.payload_len = kani::any();
        d.sequence = kani::any();
        d.timestamp_qpc = kani::any();
        d.call_id = kani::any();
        d.parent_call_id = kani::any();
        d.payload_position = kani::any();
        d.api_id = kani::any();
        d.schema_id = kani::any();
        d.global_order = kani::any();
        assert!(EventDescriptor::from_bytes(&d.to_bytes()) == Some(d));
    }

    /// 64 バイト未満は常に None。
    #[kani::proof]
    fn from_bytes_rejects_short_inputs() {
        let len: usize = kani::any();
        kani::assume(len < 64);
        let buf = [0u8; 64];
        assert!(EventDescriptor::from_bytes(&buf[..len]).is_none());
    }

    /// CaptureState のフラグ往復と L1 可否は全状態で仕様どおり。
    #[kani::proof]
    fn capture_state_flags_roundtrip_all_states() {
        let sel: u8 = kani::any();
        let s = match sel % 6 {
            0 => CaptureState::Captured,
            1 => CaptureState::MemoryUnreadable,
            2 => CaptureState::CaptureLimitExceeded,
            3 => CaptureState::DroppedByBackpressure,
            4 => CaptureState::Truncated,
            _ => CaptureState::Unsupported,
        };
        assert!(CaptureState::from_flags(s.to_flags()) == s);
        assert!(s.is_l1_eligible() == (s != CaptureState::DroppedByBackpressure));
    }
}
