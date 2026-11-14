//! snapshot 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - fragment_count / fragment_len: (全体サイズ x 分割サイズ) で、天井除算・
//!   各 Fragment 長・合計・範囲外 index=0 を参照定義と照合。
//! - write_snapshot + reassemble: (全体サイズ x 分割サイズ) の往復が
//!   バイト列・状態・Complete マーカーまで一致する。
//! - FailAfterSource: 故障位置が Fragment 境界の前後で、公開済み件数と
//!   状態 (MemoryUnreadable) が境界どおりに変わる。
//! - 容量不足: Payload 容量ごとに「入る Fragment 数」だけ公開して Truncated。
//! - reassemble 単体: 他 call_id の混入、落とした Fragment、Complete の有無。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::{flags, CaptureState, EventKind};
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{ReceivedEvent, SharedRegion, WriterPolicy};
use shirusu_transport::snapshot::{
    fragment_count, fragment_len, reassemble, write_snapshot, FailAfterSource, SliceSource,
};
use shirusu_transport::{Clock, EventDescriptor};
use std::sync::Arc;
use std::time::Duration;

// ---------- fragment_count / fragment_len の純粋行列 ----------
macro_rules! frag_case {
    ($name:ident, $total:expr, $frag:expr) => {
        #[test]
        fn $name() {
            let total: usize = $total;
            let frag: usize = $frag;
            let expect_count = if total == 0 || frag == 0 {
                0
            } else {
                total.div_ceil(frag)
            };
            assert_eq!(
                fragment_count(total, frag),
                expect_count,
                "count({total},{frag})"
            );
            let mut sum = 0usize;
            for i in 0..expect_count {
                let expect_len = (total - i * frag).min(frag);
                assert_eq!(
                    fragment_len(total, frag, i),
                    expect_len,
                    "len({total},{frag},{i})"
                );
                sum += expect_len;
            }
            if frag > 0 {
                assert_eq!(sum, total, "fragments tile the whole input");
            }
            assert_eq!(
                fragment_len(total, frag, expect_count),
                0,
                "first out-of-range index"
            );
            assert_eq!(
                fragment_len(total, frag, expect_count + 5),
                0,
                "far out-of-range index"
            );
        }
    };
}
frag_case!(frag_t0_f1, 0, 1);
frag_case!(frag_t0_f256, 0, 256);
frag_case!(frag_t1_f1, 1, 1);
frag_case!(frag_t1_f256, 1, 256);
frag_case!(frag_t2_f1, 2, 1);
frag_case!(frag_t255_f256, 255, 256);
frag_case!(frag_t256_f256, 256, 256);
frag_case!(frag_t257_f256, 257, 256);
frag_case!(frag_t511_f256, 511, 256);
frag_case!(frag_t512_f256, 512, 256);
frag_case!(frag_t513_f256, 513, 256);
frag_case!(frag_t1000_f256, 1000, 256);
frag_case!(frag_t1000_f1, 1000, 1);
frag_case!(frag_t1000_f3, 1000, 3);
frag_case!(frag_t1000_f7, 1000, 7);
frag_case!(frag_t1000_f1000, 1000, 1000);
frag_case!(frag_t1000_f1001, 1000, 1001);
frag_case!(frag_t7_f2, 7, 2);
frag_case!(frag_t7_f7, 7, 7);
frag_case!(frag_t1024_f512, 1024, 512);
frag_case!(frag_zero_frag, 500, 0);
frag_case!(frag_zero_both, 0, 0);

// ---------- write + reassemble の往復行列 ----------
fn setup(
    pcap: usize,
) -> (
    SharedRegion,
    shirusu_transport::RingWriter,
    shirusu_transport::RingReader,
) {
    let cfg = RingConfig::new(64, pcap);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let policy = WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    };
    let w = unsafe { region.writer(policy, clock) };
    let r = unsafe { region.reader() };
    (region, w, r)
}
macro_rules! roundtrip_case {
    ($name:ident, $total:expr, $frag:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd) = setup(8192);
            let data: Vec<u8> = (0..$total as u32).map(|i| (i * 3 % 256) as u8).collect();
            let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), $frag, 1, 1, 77);
            assert_eq!(
                out.state,
                CaptureState::Captured,
                "total {} frag {}",
                $total,
                $frag
            );
            assert!(out.complete_marker_published);
            assert_eq!(out.fragments_published, fragment_count($total, $frag));
            assert_eq!(out.bytes_captured, $total);
            assert!(
                !out.simultaneity_guaranteed,
                "simultaneity is never guaranteed"
            );
            let batch = rd.drain_all();
            let (joined, state) = reassemble(&batch.events, 77);
            assert_eq!(state, CaptureState::Captured);
            assert_eq!(joined, data);
        }
    };
}
roundtrip_case!(rt_t0_f64, 0, 64);
roundtrip_case!(rt_t0_f256, 0, 256);
roundtrip_case!(rt_t1_f64, 1, 64);
roundtrip_case!(rt_t1_f256, 1, 256);
roundtrip_case!(rt_t255_f256, 255, 256);
roundtrip_case!(rt_t256_f256, 256, 256);
roundtrip_case!(rt_t257_f256, 257, 256);
roundtrip_case!(rt_t768_f64, 768, 64);
roundtrip_case!(rt_t768_f256, 768, 256);
roundtrip_case!(rt_t1000_f1000, 1000, 1000);
roundtrip_case!(rt_t1000_f128, 1000, 128);

// ---------- FailAfter: 故障位置 x Fragment 境界 ----------
// 全体 768 = 256 x 3 Fragment。fail_at までに収まる Fragment だけが公開され、
// 状態は MemoryUnreadable、Complete は書かれない。
macro_rules! fail_case {
    ($name:ident, $fail_at:expr, $expect_frags:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd) = setup(4096);
            let data = vec![7u8; 768];
            let src = FailAfterSource {
                inner: &data,
                fail_at: $fail_at,
            };
            let out = write_snapshot(&mut w, &src, data.len(), 256, 1, 1, 5);
            assert_eq!(
                out.state,
                CaptureState::MemoryUnreadable,
                "fail_at {}",
                $fail_at
            );
            assert_eq!(out.fragments_published, $expect_frags);
            assert_eq!(out.bytes_captured, $expect_frags * 256);
            assert!(!out.complete_marker_published);
            let batch = rd.drain_all();
            let (joined, state) = reassemble(&batch.events, 5);
            assert_eq!(state, CaptureState::Truncated);
            assert_eq!(joined.len(), $expect_frags * 256);
            assert!(joined.iter().all(|&b| b == 7));
        }
    };
}
fail_case!(fail_at_0, 0, 0);
fail_case!(fail_at_1, 1, 0);
fail_case!(fail_at_255, 255, 0);
fail_case!(fail_at_256, 256, 1);
fail_case!(fail_at_257, 257, 1);
fail_case!(fail_at_511, 511, 1);
fail_case!(fail_at_512, 512, 2);
fail_case!(fail_at_767, 767, 2);
#[test]
fn fail_at_exact_total_is_fully_readable() {
    let (_rg, mut w, _rd) = setup(4096);
    let data = vec![7u8; 768];
    let src = FailAfterSource {
        inner: &data,
        fail_at: 768,
    };
    let out = write_snapshot(&mut w, &src, data.len(), 256, 1, 1, 5);
    assert_eq!(out.state, CaptureState::Captured);
    assert_eq!(out.fragments_published, 3);
    assert!(out.complete_marker_published);
}

// ---------- 容量不足: 入る Fragment 数だけ公開して Truncated ----------
macro_rules! shortage_case {
    ($name:ident, $pcap:expr, $expect_frags:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, _rd) = setup($pcap);
            let data = vec![1u8; 5000];
            let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), 256, 1, 1, 5);
            assert_eq!(out.state, CaptureState::Truncated, "pcap {}", $pcap);
            assert_eq!(out.fragments_published, $expect_frags);
            assert!(!out.complete_marker_published);
        }
    };
}
shortage_case!(shortage_pcap300, 300, 1);
shortage_case!(shortage_pcap511, 511, 1);
shortage_case!(shortage_pcap512, 512, 2);
shortage_case!(shortage_pcap513, 513, 2);
shortage_case!(shortage_pcap768, 768, 3);

// ---------- fragment_payload = 0 は Unsupported ----------
#[test]
fn zero_fragment_payload_is_unsupported() {
    let (_rg, mut w, _rd) = setup(4096);
    let data = vec![1u8; 100];
    let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), 0, 1, 1, 5);
    assert_eq!(out.state, CaptureState::Unsupported);
    assert_eq!(out.fragments_published, 0);
    assert!(!out.complete_marker_published);
}

// ---------- reassemble 単体の行列 ----------
fn ev(kind: EventKind, call: u64, payload: &[u8], dropped: bool) -> ReceivedEvent {
    let mut d = EventDescriptor::new(kind, 1);
    d.call_id = call;
    d.payload_len = payload.len() as u32;
    if dropped {
        d.flags |= flags::PAYLOAD_DROPPED;
    }
    ReceivedEvent {
        descriptor: d,
        payload: payload.into(),
    }
}
#[test]
fn reasm_fragments_without_complete_is_truncated() {
    let evs = vec![
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
        ev(EventKind::SnapshotFragment, 9, b"cd", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"abcd");
    assert_eq!(state, CaptureState::Truncated);
}
#[test]
fn reasm_with_complete_is_captured() {
    let evs = vec![
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
        ev(EventKind::SnapshotComplete, 9, b"", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"ab");
    assert_eq!(state, CaptureState::Captured);
}
#[test]
fn reasm_ignores_other_call_ids() {
    let evs = vec![
        ev(EventKind::SnapshotFragment, 8, b"XX", false),
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
        ev(EventKind::SnapshotComplete, 8, b"", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"ab");
    assert_eq!(
        state,
        CaptureState::Truncated,
        "other call's complete does not count"
    );
}
#[test]
fn reasm_dropped_fragment_contributes_nothing() {
    let evs = vec![
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
        ev(EventKind::SnapshotFragment, 9, b"", true),
        ev(EventKind::SnapshotFragment, 9, b"ef", false),
        ev(EventKind::SnapshotComplete, 9, b"", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"abef", "dropped fragment leaves a hole, not a shift");
    assert_eq!(state, CaptureState::Captured);
}
#[test]
fn reasm_empty_events_is_truncated_empty() {
    let (data, state) = reassemble(&[], 9);
    assert!(data.is_empty());
    assert_eq!(state, CaptureState::Truncated);
}
#[test]
fn reasm_ignores_non_snapshot_kinds() {
    let evs = vec![
        ev(EventKind::CallEnter, 9, b"zz", false),
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
        ev(EventKind::CallLeave, 9, b"zz", false),
        ev(EventKind::SnapshotComplete, 9, b"", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"ab");
    assert_eq!(state, CaptureState::Captured);
}
#[test]
fn reasm_complete_before_fragments_still_counts() {
    // reassemble は走査順に依存せず Complete の存在だけを見る
    let evs = vec![
        ev(EventKind::SnapshotComplete, 9, b"", false),
        ev(EventKind::SnapshotFragment, 9, b"ab", false),
    ];
    let (data, state) = reassemble(&evs, 9);
    assert_eq!(data, b"ab");
    assert_eq!(state, CaptureState::Captured);
}
