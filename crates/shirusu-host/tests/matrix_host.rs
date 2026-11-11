//! host 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - TemporaryPayloadKey: 5 要素の直積 (2x2x2x2x2=32 通り) が全て異なるキーに
//!   なること、各要素を個別に変えた場合の分離、Ord の辞書順、世代の折り返し。
//! - Enter/Leave 対応付け: 入れ子・再入・二重 Leave・孤児 Leave・finalize の
//!   冪等性とソート順。
//! - Loss 会計: 段階的な回収で Counters 差分が正確に 1 回だけ報告され、
//!   SequenceGap と共存すること。Degraded のカウンタ内訳。
//! - ValidatingHost: 世代不一致で停止し続けること、identity 付きキーの累積。

use shirusu_host::{
    host_release_slot, DrainWorker, IntegrityLevel, LossEvent, ProcessInstanceId, RingId,
    RingIdentity, TemporaryPayloadKey, ValidatingHost,
};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{EventInput, ReceivedEvent, SharedRegion, WriterPolicy};
use shirusu_transport::slot::SlotPool;
use shirusu_transport::validate::KnownConfig;
use shirusu_transport::{Clock, EventDescriptor};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

// ---------- TemporaryPayloadKey の分離行列 ----------
fn key(p: u64, r: u64, g: u64, s: u64, pos: u64) -> TemporaryPayloadKey {
    TemporaryPayloadKey {
        process_id: ProcessInstanceId(p),
        ring_id: RingId(r),
        generation: g,
        sequence: s,
        payload_position: pos,
    }
}
#[test]
fn key_full_grid_all_distinct() {
    // 5 要素それぞれ 2 値の直積 32 通りが 1 つも衝突しない
    let mut set = HashSet::new();
    for p in [1u64, 2] {
        for r in [1u64, 2] {
            for g in [1u64, 2] {
                for s in [1u64, 2] {
                    for pos in [0u64, 8] {
                        assert!(
                            set.insert(key(p, r, g, s, pos)),
                            "collision at {p}/{r}/{g}/{s}/{pos}"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(set.len(), 32);
}
macro_rules! key_vary_case {
    ($name:ident, $other:expr) => {
        #[test]
        fn $name() {
            let base = key(10, 20, 30, 40, 50);
            assert_ne!(base, $other);
            // base 自身とは決定的に等しい
            assert_eq!(base, key(10, 20, 30, 40, 50));
        }
    };
}
key_vary_case!(key_vary_process_near, key(11, 20, 30, 40, 50));
key_vary_case!(key_vary_process_max, key(u64::MAX, 20, 30, 40, 50));
key_vary_case!(key_vary_ring_near, key(10, 21, 30, 40, 50));
key_vary_case!(key_vary_ring_max, key(10, u64::MAX, 30, 40, 50));
key_vary_case!(key_vary_generation_near, key(10, 20, 31, 40, 50));
key_vary_case!(key_vary_generation_max, key(10, 20, u64::MAX, 40, 50));
key_vary_case!(key_vary_sequence_near, key(10, 20, 30, 41, 50));
key_vary_case!(key_vary_sequence_max, key(10, 20, 30, u64::MAX, 50));
key_vary_case!(key_vary_position_near, key(10, 20, 30, 40, 51));
key_vary_case!(key_vary_position_max, key(10, 20, 30, 40, u64::MAX));
#[test]
fn key_ordering_is_lexicographic_by_components() {
    let mut keys = vec![
        key(2, 1, 1, 1, 1),
        key(1, 9, 9, 9, 9),
        key(1, 2, 1, 1, 1),
        key(1, 2, 3, 1, 1),
        key(1, 2, 3, 4, 1),
        key(1, 2, 3, 4, 5),
    ];
    keys.sort();
    assert_eq!(
        keys,
        vec![
            key(1, 2, 1, 1, 1),
            key(1, 2, 3, 1, 1),
            key(1, 2, 3, 4, 1),
            key(1, 2, 3, 4, 5),
            key(1, 9, 9, 9, 9),
            key(2, 1, 1, 1, 1),
        ]
    );
}
#[test]
fn ring_identity_next_generation_wraps_at_max() {
    // 世代は wrapping_add: u64::MAX の次は 0 に折り返る (現行仕様の固定)。
    // 実運用で世代が 2^64 回進むことは無いが、折り返し方を明示しておく。
    let id = RingIdentity::new(ProcessInstanceId(1), RingId(1), u64::MAX);
    assert_eq!(id.next_generation().generation, 0);
    let id2 = RingIdentity::new(ProcessInstanceId(1), RingId(1), 41);
    assert_eq!(id2.next_generation().generation, 42);
    // 他の要素は保たれる
    let next = id2.next_generation();
    assert_eq!(next.process_id, ProcessInstanceId(1));
    assert_eq!(next.ring_id, RingId(1));
}

// ---------- Enter/Leave 対応付けパターン ----------
fn setup(desc: usize, pay: usize) -> (SharedRegion, shirusu_transport::RingWriter, DrainWorker) {
    let cfg = RingConfig::new(desc, pay);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    (region, w, worker)
}
fn ev(kind: EventKind, call: u64) -> EventInput<'static> {
    EventInput {
        kind,
        api_id: 3,
        schema_id: 4,
        call_id: call,
        parent_call_id: 0,
        payload: b"x",
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}
#[test]
fn pairing_interleaved_calls_all_close() {
    let (_rg, mut w, mut host) = setup(16, 512);
    w.write(ev(EventKind::CallEnter, 1));
    w.write(ev(EventKind::CallEnter, 2));
    w.write(ev(EventKind::CallLeave, 2));
    w.write(ev(EventKind::CallLeave, 1));
    host.drain_all();
    assert_eq!(host.open_call_count(), 0);
    assert!(host.finalize_thread().is_empty());
    assert!(host.loss_events.is_empty());
}
#[test]
fn pairing_reenter_same_id_overwrites_open_entry() {
    let (_rg, mut w, mut host) = setup(16, 512);
    w.write(ev(EventKind::CallEnter, 5));
    w.write(ev(EventKind::CallEnter, 5)); // 同じ call_id の再入は上書き
    w.write(ev(EventKind::CallLeave, 5));
    host.drain_all();
    assert_eq!(host.open_call_count(), 0);
    assert!(host.finalize_thread().is_empty());
}
#[test]
fn pairing_double_leave_is_harmless() {
    let (_rg, mut w, mut host) = setup(16, 512);
    w.write(ev(EventKind::CallEnter, 5));
    w.write(ev(EventKind::CallLeave, 5));
    w.write(ev(EventKind::CallLeave, 5));
    host.drain_all();
    assert_eq!(host.open_call_count(), 0);
    assert!(host.finalize_thread().is_empty());
    assert!(host.loss_events.is_empty());
}
#[test]
fn pairing_leave_before_enter_does_not_close_future_enter() {
    let (_rg, mut w, mut host) = setup(16, 512);
    w.write(ev(EventKind::CallLeave, 7)); // 孤児 Leave は無視される
    w.write(ev(EventKind::CallEnter, 7));
    host.drain_all();
    assert_eq!(host.open_call_count(), 1);
    assert_eq!(host.finalize_thread(), vec![7]);
}
#[test]
fn pairing_finalize_is_sorted_and_idempotent() {
    let (_rg, mut w, mut host) = setup(16, 512);
    for call in [9u64, 3, 5] {
        w.write(ev(EventKind::CallEnter, call));
    }
    host.drain_all();
    assert_eq!(host.finalize_thread(), vec![3, 5, 9], "sorted by call_id");
    let events_after_first = host.loss_events.len();
    assert_eq!(events_after_first, 3);
    // 2 回目の finalize は何も追加しない
    assert!(host.finalize_thread().is_empty());
    assert_eq!(host.loss_events.len(), events_after_first);
}

// ---------- Loss 会計の段階差分 ----------
#[test]
fn loss_counters_reported_once_then_gap_separately() {
    let (_rg, mut w, mut host) = setup(4, 256);
    for i in 0..4u64 {
        w.write(ev(EventKind::CallEnter, i));
    }
    // 満杯のまま (回収する前に) 3 件落とす (dropped_events=3, bytes=3)
    for j in 0..3u64 {
        let _ = w.write(ev(EventKind::CallEnter, 90 + j));
    }
    // 回収: 4 件のイベントと一緒にカウンタ差分が 1 回だけ報告される
    host.drain_all();
    assert_eq!(
        host.loss_events,
        vec![LossEvent::Counters {
            dropped_events: 3,
            dropped_payload_bytes: 3,
            degraded_events: 0,
        }]
    );
    // 次の 1 件 (seq 8) が欠番 3 を露わにする。カウンタは増えていないので
    // Counters は再報告されない
    w.write(ev(EventKind::CallEnter, 200));
    host.drain_all();
    assert_eq!(
        host.loss_events,
        vec![
            LossEvent::Counters {
                dropped_events: 3,
                dropped_payload_bytes: 3,
                degraded_events: 0,
            },
            LossEvent::SequenceGap { count: 3 },
        ]
    );
}
#[test]
fn degraded_counters_breakdown() {
    let (_rg, mut w, mut host) = setup(8, 16);
    let big = |call: u64| EventInput {
        kind: EventKind::CallEnter,
        api_id: 3,
        schema_id: 4,
        call_id: call,
        parent_call_id: 0,
        payload: b"12345678",
        capture_state: CaptureState::Captured,
        global_order: 0,
    };
    w.write(big(1));
    w.write(big(2));
    // Payload 満杯 (16/16) で 2 件 Degraded: degraded=2, 落としたバイト=16
    let _ = w.write(big(3));
    let _ = w.write(big(4));
    host.drain_all();
    assert_eq!(
        host.loss_events,
        vec![LossEvent::Counters {
            dropped_events: 0,
            dropped_payload_bytes: 16,
            degraded_events: 2,
        }]
    );
    let report = host.integrity_report(0, false);
    assert_eq!(report.semantic_completeness, IntegrityLevel::Degraded);
    assert_eq!(
        report.event_integrity,
        IntegrityLevel::Degraded,
        "loss events exist"
    );
}
#[test]
fn report_gap_only_degrades_event_not_semantic() {
    let (_rg, mut w, mut host) = setup(4, 256);
    for i in 0..4u64 {
        w.write(ev(EventKind::CallEnter, i));
    }
    let _ = w.write(ev(EventKind::CallEnter, 90)); // dropped (event itself lost)
    host.drain_all();
    w.write(ev(EventKind::CallEnter, 200));
    host.drain_all();
    let report = host.integrity_report(0, false);
    assert_eq!(report.event_integrity, IntegrityLevel::Degraded);
    assert_eq!(report.semantic_completeness, IntegrityLevel::Complete);
    assert_eq!(report.capture_coverage, IntegrityLevel::Complete);
}
#[test]
fn report_missing_and_lost_combine_independently() {
    let (_rg, _w, host) = setup(4, 256);
    let report = host.integrity_report(5, true);
    assert_eq!(report.capture_coverage, IntegrityLevel::Degraded);
    assert_eq!(report.event_integrity, IntegrityLevel::Lost);
    assert_eq!(report.semantic_completeness, IntegrityLevel::Complete);
    assert_eq!(report.notes.len(), 2);
}

// ---------- ValidatingHost の停止とキー累積 ----------
#[test]
fn validating_host_generation_mismatch_stops_permanently() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 5, 1);
    let known = KnownConfig::new(cfg, cfg.required_len());
    let mut host = ValidatingHost::new(known, 6); // 世代 5 の像に 6 を期待する
    assert!(host.drain_image(region.as_slice()).is_err());
    assert!(host.integrity_lost);
    assert!(host.is_stopped());
    assert!(matches!(
        host.loss_events.first(),
        Some(LossEvent::IntegrityLost { .. })
    ));
    // 停止後は正しい像を持ってきても RingStopped のまま
    assert!(matches!(
        host.drain_image(region.as_slice()),
        Err(shirusu_transport::validate::IntegrityError::RingStopped)
    ));
}
#[test]
fn validating_host_keys_accumulate_across_drains() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 3, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let mut host = ValidatingHost::new(KnownConfig::new(cfg, cfg.required_len()), 3);
    host.set_identity(RingIdentity::new(ProcessInstanceId(2), RingId(7), 3));
    let mut inp = ev(EventKind::CallEnter, 1);
    inp.payload = b"aaa";
    w.write(inp);
    let _ = host.drain_image(region.as_slice()).unwrap();
    let mut inp2 = ev(EventKind::CallEnter, 2);
    inp2.payload = b"bb";
    w.write(inp2);
    let _ = host.drain_image(region.as_slice()).unwrap();
    assert_eq!(
        host.payload_keys,
        vec![
            TemporaryPayloadKey {
                process_id: ProcessInstanceId(2),
                ring_id: RingId(7),
                generation: 3,
                sequence: 1,
                payload_position: 0,
            },
            TemporaryPayloadKey {
                process_id: ProcessInstanceId(2),
                ring_id: RingId(7),
                generation: 3,
                sequence: 2,
                payload_position: 3,
            },
        ]
    );
}
#[test]
fn host_release_with_wrong_handle_fails() {
    let pool = SlotPool::new(2);
    let a = pool.claim(1).unwrap();
    let b = pool.claim(2).unwrap();
    // b は Active のまま (DETACH していない) なので a の解放手順を流用できない
    assert!(!host_release_slot(&pool, &b, true, true));
    assert!(pool.begin_detach(&a));
    assert!(host_release_slot(&pool, &a, true, true));
    assert_eq!(
        pool.slot(a.index).state(),
        shirusu_transport::SlotState::Free
    );
    assert_eq!(
        pool.slot(b.index).state(),
        shirusu_transport::SlotState::Active
    );
}

// ReceivedEvent を使う場面のための参照 (型が公開 API にあることの確認)
#[allow(dead_code)]
fn _received_shape(e: &ReceivedEvent) -> (u64, usize) {
    (e.descriptor.sequence, e.payload.len())
}
#[allow(dead_code)]
fn _desc_shape(d: &EventDescriptor) -> u64 {
    d.sequence
}
