//! descriptor 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - EventKind: 全既知値の from_u16 往復と未知値の拒否。
//! - EventDescriptor: フィールドごとに代表値 (0 / 1 / 型最大 / 特徴値) を入れた
//!   encode/decode 往復と、他のフィールドが汚染されない独立性。
//! - to_bytes のバイト配置: 各フィールドが spec のオフセットに LE で現れること。
//! - from_bytes: 64 バイト未満の全代表長で None、64 以上は先頭 64 バイトだけ読む。
//! - CaptureState::from_flags: 優先順位に関わる 5 ビット + 無関係 2 ビットの
//!   全 128 通りについて、優先順位規則どおりの状態に解釈されること。

use shirusu_transport::descriptor::{flags, CaptureState, EventDescriptor, EventKind};

// ---- EventKind の往復と未知値 ----
macro_rules! kind_case {
    ($name:ident, $v:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!(EventKind::from_u16($v), $expect, "kind {}", $v);
        }
    };
}
kind_case!(kind_0_unknown, 0, Some(EventKind::Unknown));
kind_case!(kind_1_enter, 1, Some(EventKind::CallEnter));
kind_case!(kind_2_leave, 2, Some(EventKind::CallLeave));
kind_case!(kind_3_fragment, 3, Some(EventKind::SnapshotFragment));
kind_case!(kind_4_complete, 4, Some(EventKind::SnapshotComplete));
kind_case!(kind_5_loss, 5, Some(EventKind::Loss));
kind_case!(kind_6_expand, 6, Some(EventKind::SlotExpandRequest));
kind_case!(kind_7_aborted, 7, Some(EventKind::CallAborted));
kind_case!(kind_8_completed, 8, Some(EventKind::CallCompleted));
kind_case!(kind_9_rejected, 9, None);
kind_case!(kind_100_rejected, 100, None);
kind_case!(kind_1000_rejected, 1000, None);
kind_case!(kind_u16max_rejected, u16::MAX, None);

// ---- フィールド値域の往復 (to_bytes/from_bytes) ----
// 各フィールドに特徴的な値を 1 つだけ入れ、往復で保たれ、他は既定のままであること。
fn base() -> EventDescriptor {
    EventDescriptor::new(EventKind::CallEnter, 1)
}
macro_rules! field_case {
    ($name:ident, $set:expr, $check:expr) => {
        #[test]
        fn $name() {
            let mut d = base();
            $set(&mut d);
            let rt = EventDescriptor::from_bytes(&d.to_bytes()).expect("64 bytes decode");
            assert_eq!(rt, d, "roundtrip preserves the set field exactly");
            $check(&rt);
        }
    };
}
field_case!(
    field_kind_max_valid,
    |d: &mut EventDescriptor| d.kind = 6,
    |d: &EventDescriptor| assert_eq!(d.kind_enum(), Some(EventKind::SlotExpandRequest))
);
field_case!(
    field_kind_arbitrary_preserved,
    |d: &mut EventDescriptor| d.kind = 999,
    |d: &EventDescriptor| assert_eq!(d.kind_enum(), None)
);
field_case!(
    field_flags_all_bits,
    |d: &mut EventDescriptor| d.flags = u16::MAX,
    |d: &EventDescriptor| assert_eq!(d.flags, u16::MAX)
);
field_case!(
    field_flags_dropped_bit,
    |d: &mut EventDescriptor| d.flags = flags::PAYLOAD_DROPPED,
    |d: &EventDescriptor| assert!(d.payload_dropped())
);
field_case!(
    field_payload_len_max,
    |d: &mut EventDescriptor| d.payload_len = u32::MAX,
    |d: &EventDescriptor| assert_eq!(d.payload_len, u32::MAX)
);
field_case!(
    field_payload_len_one,
    |d: &mut EventDescriptor| d.payload_len = 1,
    |d: &EventDescriptor| assert_eq!(d.payload_len, 1)
);
field_case!(
    field_sequence_max,
    |d: &mut EventDescriptor| d.sequence = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.sequence, u64::MAX)
);
field_case!(
    field_timestamp_max,
    |d: &mut EventDescriptor| d.timestamp_qpc = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.timestamp_qpc, u64::MAX)
);
field_case!(
    field_call_id_max,
    |d: &mut EventDescriptor| d.call_id = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.call_id, u64::MAX)
);
field_case!(
    field_parent_call_id_max,
    |d: &mut EventDescriptor| d.parent_call_id = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.parent_call_id, u64::MAX)
);
field_case!(
    field_payload_position_max,
    |d: &mut EventDescriptor| d.payload_position = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.payload_position, u64::MAX)
);
field_case!(
    field_api_id_max,
    |d: &mut EventDescriptor| d.api_id = u32::MAX,
    |d: &EventDescriptor| assert_eq!(d.api_id, u32::MAX)
);
field_case!(
    field_schema_id_max,
    |d: &mut EventDescriptor| d.schema_id = u32::MAX,
    |d: &EventDescriptor| assert_eq!(d.schema_id, u32::MAX)
);
field_case!(
    field_reserved_max,
    |d: &mut EventDescriptor| d.global_order = u64::MAX,
    |d: &EventDescriptor| assert_eq!(d.global_order, u64::MAX)
);
// 全フィールド同時最大でも往復する
field_case!(
    field_all_max_together,
    |d: &mut EventDescriptor| {
        d.kind = 6;
        d.flags = u16::MAX;
        d.payload_len = u32::MAX;
        d.sequence = u64::MAX;
        d.timestamp_qpc = u64::MAX;
        d.call_id = u64::MAX;
        d.parent_call_id = u64::MAX;
        d.payload_position = u64::MAX;
        d.api_id = u32::MAX;
        d.schema_id = u32::MAX;
        d.global_order = u64::MAX;
    },
    |d: &EventDescriptor| assert_eq!(d.payload_position, u64::MAX)
);

// ---- to_bytes のバイト配置 (spec オフセット) ----
#[test]
fn byte_layout_matches_spec_offsets() {
    let mut d = base();
    d.kind = 0x0201;
    d.flags = 0x0403;
    d.payload_len = 0x08070605;
    d.sequence = 0x100F0E0D0C0B0A09;
    d.timestamp_qpc = 0x1817161514131211;
    d.call_id = 0x201F1E1D1C1B1A19;
    d.parent_call_id = 0x2827262524232221;
    d.payload_position = 0x302F2E2D2C2B2A29;
    d.api_id = 0x34333231;
    d.schema_id = 0x38373635;
    d.global_order = 0x403F3E3D3C3B3A39;
    let b = d.to_bytes();
    let g16 = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
    let g32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let g64 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    assert_eq!(g16(0), d.kind);
    assert_eq!(g16(2), d.flags);
    assert_eq!(g32(4), d.payload_len);
    assert_eq!(g64(8), d.sequence);
    assert_eq!(g64(16), d.timestamp_qpc);
    assert_eq!(g64(24), d.call_id);
    assert_eq!(g64(32), d.parent_call_id);
    assert_eq!(g64(40), d.payload_position);
    assert_eq!(g32(48), d.api_id);
    assert_eq!(g32(52), d.schema_id);
    assert_eq!(g64(56), d.global_order);
    assert_eq!(b.len(), EventDescriptor::SIZE);
}

// ---- from_bytes の長さ境界 ----
macro_rules! short_case {
    ($name:ident, $len:expr) => {
        #[test]
        fn $name() {
            let b = [0xABu8; 128];
            assert_eq!(
                EventDescriptor::from_bytes(&b[..$len]),
                None,
                "len {}",
                $len
            );
        }
    };
}
short_case!(short_0, 0);
short_case!(short_1, 1);
short_case!(short_2, 2);
short_case!(short_31, 31);
short_case!(short_32, 32);
short_case!(short_62, 62);
short_case!(short_63, 63);
#[test]
fn from_bytes_reads_only_first_64_of_longer_input() {
    let d = base();
    let mut buf = d.to_bytes().to_vec();
    buf.extend_from_slice(&[0xFF; 64]); // 後続のゴミは読まない
    assert_eq!(EventDescriptor::from_bytes(&buf), Some(d));
}

// ---- CaptureState::from_flags の全組合せ (2^7) ----
// 優先順位: DROPPED_BY_BACKPRESSURE > MEMORY_UNREADABLE > CAPTURE_LIMIT_EXCEEDED
//           > TRUNCATED > UNSUPPORTED > (なし) Captured。
// PAYLOAD_DROPPED と SNAPSHOT_NOT_COHERENT は状態判定に影響しない。
fn expected_state(f: u16) -> CaptureState {
    if f & flags::DROPPED_BY_BACKPRESSURE != 0 {
        CaptureState::DroppedByBackpressure
    } else if f & flags::MEMORY_UNREADABLE != 0 {
        CaptureState::MemoryUnreadable
    } else if f & flags::CAPTURE_LIMIT_EXCEEDED != 0 {
        CaptureState::CaptureLimitExceeded
    } else if f & flags::TRUNCATED != 0 {
        CaptureState::Truncated
    } else if f & flags::UNSUPPORTED != 0 {
        CaptureState::Unsupported
    } else {
        CaptureState::Captured
    }
}
macro_rules! flags_case {
    ($name:ident, $bits:expr) => {
        #[test]
        fn $name() {
            let f: u16 = $bits;
            assert_eq!(
                CaptureState::from_flags(f),
                expected_state(f),
                "flags {f:#06x}"
            );
            // L1 可否は DroppedByBackpressure のときだけ false
            assert_eq!(
                CaptureState::from_flags(f).is_l1_eligible(),
                expected_state(f) != CaptureState::DroppedByBackpressure
            );
        }
    };
}
flags_case!(flags_none, 0);
flags_case!(flags_pd, flags::PAYLOAD_DROPPED);
flags_case!(flags_tr, flags::TRUNCATED);
flags_case!(flags_pd_tr, flags::PAYLOAD_DROPPED | flags::TRUNCATED);
flags_case!(flags_mu, flags::MEMORY_UNREADABLE);
flags_case!(
    flags_pd_mu,
    flags::PAYLOAD_DROPPED | flags::MEMORY_UNREADABLE
);
flags_case!(flags_tr_mu, flags::TRUNCATED | flags::MEMORY_UNREADABLE);
flags_case!(
    flags_pd_tr_mu,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::MEMORY_UNREADABLE
);
flags_case!(flags_cle, flags::CAPTURE_LIMIT_EXCEEDED);
flags_case!(
    flags_pd_cle,
    flags::PAYLOAD_DROPPED | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_tr_cle,
    flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_pd_tr_cle,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_mu_cle,
    flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_pd_mu_cle,
    flags::PAYLOAD_DROPPED | flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_tr_mu_cle,
    flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(
    flags_pd_tr_mu_cle,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
);
flags_case!(flags_bp, flags::DROPPED_BY_BACKPRESSURE);
flags_case!(
    flags_pd_bp,
    flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_tr_bp,
    flags::TRUNCATED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_tr_bp,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_mu_bp,
    flags::MEMORY_UNREADABLE | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_mu_bp,
    flags::PAYLOAD_DROPPED | flags::MEMORY_UNREADABLE | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_tr_mu_bp,
    flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_tr_mu_bp,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_cle_bp,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_cle_bp,
    flags::PAYLOAD_DROPPED | flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_tr_cle_bp,
    flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_tr_cle_bp,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_mu_cle_bp,
    flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_mu_cle_bp,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_tr_mu_cle_bp,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(
    flags_pd_tr_mu_cle_bp,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
);
flags_case!(flags_uns, flags::UNSUPPORTED);
flags_case!(flags_pd_uns, flags::PAYLOAD_DROPPED | flags::UNSUPPORTED);
flags_case!(flags_tr_uns, flags::TRUNCATED | flags::UNSUPPORTED);
flags_case!(
    flags_pd_tr_uns,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::UNSUPPORTED
);
flags_case!(flags_mu_uns, flags::MEMORY_UNREADABLE | flags::UNSUPPORTED);
flags_case!(
    flags_pd_mu_uns,
    flags::PAYLOAD_DROPPED | flags::MEMORY_UNREADABLE | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_mu_uns,
    flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_mu_uns,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::UNSUPPORTED
);
flags_case!(
    flags_cle_uns,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_cle_uns,
    flags::PAYLOAD_DROPPED | flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_cle_uns,
    flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_cle_uns,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED
);
flags_case!(
    flags_mu_cle_uns,
    flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_mu_cle_uns,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_mu_cle_uns,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_mu_cle_uns,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
);
flags_case!(
    flags_bp_uns,
    flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_bp_uns,
    flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_bp_uns,
    flags::TRUNCATED | flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_bp_uns,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_mu_bp_uns,
    flags::MEMORY_UNREADABLE | flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_mu_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_mu_bp_uns,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_mu_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_cle_bp_uns,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_cle_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_cle_bp_uns,
    flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_cle_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_mu_cle_bp_uns,
    flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_mu_cle_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_tr_mu_cle_bp_uns,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(
    flags_pd_tr_mu_cle_bp_uns,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
);
flags_case!(flags_snc, flags::SNAPSHOT_NOT_COHERENT);
flags_case!(
    flags_pd_snc,
    flags::PAYLOAD_DROPPED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_snc,
    flags::TRUNCATED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_snc,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_snc,
    flags::MEMORY_UNREADABLE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_snc,
    flags::PAYLOAD_DROPPED | flags::MEMORY_UNREADABLE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_snc,
    flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_cle_snc,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_cle_snc,
    flags::PAYLOAD_DROPPED | flags::CAPTURE_LIMIT_EXCEEDED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_cle_snc,
    flags::TRUNCATED | flags::CAPTURE_LIMIT_EXCEEDED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_cle_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_cle_snc,
    flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_cle_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_cle_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_cle_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_bp_snc,
    flags::DROPPED_BY_BACKPRESSURE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_bp_snc,
    flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_bp_snc,
    flags::TRUNCATED | flags::DROPPED_BY_BACKPRESSURE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_bp_snc,
    flags::MEMORY_UNREADABLE | flags::DROPPED_BY_BACKPRESSURE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_bp_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_cle_bp_snc,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::DROPPED_BY_BACKPRESSURE | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_cle_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_cle_bp_snc,
    flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_cle_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_cle_bp_snc,
    flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_cle_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_cle_bp_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_cle_bp_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_uns_snc,
    flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_uns_snc,
    flags::PAYLOAD_DROPPED | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_uns_snc,
    flags::TRUNCATED | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_uns_snc,
    flags::PAYLOAD_DROPPED | flags::TRUNCATED | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_uns_snc,
    flags::MEMORY_UNREADABLE | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_uns_snc,
    flags::TRUNCATED | flags::MEMORY_UNREADABLE | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_cle_uns_snc,
    flags::CAPTURE_LIMIT_EXCEEDED | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_cle_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_cle_uns_snc,
    flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_cle_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_cle_uns_snc,
    flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_cle_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_cle_uns_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_cle_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_bp_uns_snc,
    flags::DROPPED_BY_BACKPRESSURE | flags::UNSUPPORTED | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_bp_uns_snc,
    flags::TRUNCATED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_bp_uns_snc,
    flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_bp_uns_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_cle_bp_uns_snc,
    flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_cle_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_cle_bp_uns_snc,
    flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_cle_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_mu_cle_bp_uns_snc,
    flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_mu_cle_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_tr_mu_cle_bp_uns_snc,
    flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
flags_case!(
    flags_pd_tr_mu_cle_bp_uns_snc,
    flags::PAYLOAD_DROPPED
        | flags::TRUNCATED
        | flags::MEMORY_UNREADABLE
        | flags::CAPTURE_LIMIT_EXCEEDED
        | flags::DROPPED_BY_BACKPRESSURE
        | flags::UNSUPPORTED
        | flags::SNAPSHOT_NOT_COHERENT
);
