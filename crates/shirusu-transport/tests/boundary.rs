//! 境界スイート: Cursor の u64 極値、Payload サイズ境界、Descriptor フィールド極値、
//! Generation 境界、BOUNDED_WAIT の時刻境界（Manual Clock）、容量設定の境界を体系化する。
//! 仕様に 2 冪要件は無い（位置は剰余で計算する）ため、非 2 冪容量は「正しく動くこと」
//! を、容量下限未満は「拒否されること」を確認する。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::{flags, CaptureState, EventDescriptor, EventKind};
use shirusu_transport::layout::*;
use shirusu_transport::notify::{NotifySignal, PublishNotifyTracker, ReCheckPolicy};
use shirusu_transport::ring::*;
use shirusu_transport::slot::{SlotPool, SlotState, SLOT_MEMORY_BYTES};
use shirusu_transport::snapshot::{reassemble, write_snapshot, FailAfterSource, SliceSource};
use shirusu_transport::validate::{
    decode_descriptor, decode_payload, validate_control, validate_cursor_pair, IntegrityError,
    KnownConfig, ValidatingReader,
};
use shirusu_transport::{Clock, RingConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------- 共通ヘルパ ----------

fn setup(
    desc: usize,
    pay: usize,
    policy: WriterPolicy,
) -> (SharedRegion, RingWriter, RingReader, Arc<ManualClock>) {
    let cfg = RingConfig::new(desc, pay);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock = Arc::new(ManualClock::new());
    let w = unsafe { region.writer(policy, clock.clone() as Arc<dyn Clock>) };
    let r = unsafe { region.reader() };
    (region, w, r, clock)
}
fn no_wait() -> WriterPolicy {
    WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    }
}
fn input(kind: EventKind, call: u64, payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind,
        api_id: 10,
        schema_id: 20,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}
fn ctrl(base: *const u8, off: usize) -> u64 {
    load(base, off, Ordering::Relaxed)
}

// ---------- layout 純粋関数の極値 ----------

#[test]
fn occupancy_at_u64_extremes() {
    assert_eq!(occupancy(0, 0), Some(0));
    assert_eq!(occupancy(u64::MAX, 0), Some(u64::MAX));
    assert_eq!(occupancy(u64::MAX, u64::MAX), Some(0));
    assert_eq!(occupancy(u64::MAX, u64::MAX - 1), Some(1));
    assert_eq!(occupancy(0, 1), None, "read ahead of write is regression");
    assert_eq!(occupancy(5, u64::MAX), None);
    // u64::MAX の次 (0 への折り返し) は後退として扱われる = 安全側
    assert_eq!(occupancy(0, u64::MAX), None);
}

#[test]
fn descriptor_free_at_extremes() {
    assert_eq!(descriptor_free(0, 0, 0), Some(0));
    assert_eq!(descriptor_free(0, 0, u64::MAX), Some(u64::MAX));
    assert_eq!(descriptor_free(10, 10, 16), Some(16));
    assert_eq!(descriptor_free(u64::MAX, 0, 16), None, "occupancy overflow");
    assert_eq!(descriptor_free(3, 10, 16), None, "regression");
    assert_eq!(descriptor_free(20, 4, 16), Some(0), "exactly full");
    assert_eq!(descriptor_free(21, 4, 16), None, "over capacity");
}

#[test]
fn slot_and_payload_index_at_extremes() {
    for cap in [1u64, 2, 3, 7, 64, 4096, u64::MAX] {
        for cur in [0u64, 1, 63, 64, 65, u64::MAX - 1, u64::MAX] {
            assert_eq!(slot_index(cur, cap), cur % cap, "cap={cap} cur={cur}");
            assert_eq!(payload_index(cur, cap), cur % cap);
            assert!(slot_index(cur, cap) < cap);
        }
    }
    assert_eq!(slot_index(123, 0), 0, "capacity 0 is guarded");
    assert_eq!(slot_index(u64::MAX, 2), 1);
}

#[test]
fn usage_percent_boundaries_and_saturation_quirk() {
    assert_eq!(usage_percent(0, 100), 0);
    assert_eq!(usage_percent(1, 3), 33);
    assert_eq!(usage_percent(3, 2), 150, "over-100% is reported as-is");
    assert_eq!(usage_percent(100, 100), 100);
    assert_eq!(usage_percent(0, 0), 100, "zero capacity reads as full");
    assert_eq!(usage_percent(50, 0), 100);
    // 既知の癖: saturating_mul(100) が飽和するため、極値同士では 100 にならない。
    // 呼び手 (占有量 <= 容量の範囲) では発生しない。挙動を固定しておく。
    assert_eq!(usage_percent(u64::MAX, u64::MAX), 1);
}

#[test]
fn loss_counters_diff_each_field_regression() {
    let base = LossCounters {
        dropped_events: 10,
        dropped_payload_bytes: 100,
        degraded_events: 5,
    };
    assert_eq!(
        base.diff_since(&base),
        Some(LossCounters {
            dropped_events: 0,
            dropped_payload_bytes: 0,
            degraded_events: 0
        })
    );
    let maxed = LossCounters {
        dropped_events: u64::MAX,
        dropped_payload_bytes: u64::MAX,
        degraded_events: u64::MAX,
    };
    assert_eq!(
        maxed.diff_since(&maxed),
        Some(LossCounters::default()),
        "MAX vs MAX diffs to zero, no overflow"
    );
    for regressed in [
        LossCounters {
            dropped_events: 9,
            ..base
        },
        LossCounters {
            dropped_payload_bytes: 99,
            ..base
        },
        LossCounters {
            degraded_events: 4,
            ..base
        },
    ] {
        assert_eq!(
            regressed.diff_since(&base),
            None,
            "any single field regression invalidates the diff"
        );
    }
}

// ---------- RingConfig 境界 ----------

#[test]
#[should_panic(expected = "descriptor capacity must be >= 2")]
fn config_rejects_descriptor_capacity_zero() {
    let _ = RingConfig::new(0, 1024);
}
#[test]
#[should_panic(expected = "descriptor capacity must be >= 2")]
fn config_rejects_descriptor_capacity_one() {
    let _ = RingConfig::new(1, 1024);
}
#[test]
#[should_panic(expected = "payload capacity must be >= 16")]
fn config_rejects_payload_capacity_below_16() {
    let _ = RingConfig::new(2, 15);
}
#[test]
#[should_panic(expected = "payload capacity must be >= 16")]
fn config_rejects_payload_capacity_zero() {
    let _ = RingConfig::new(2, 0);
}

#[test]
fn config_minimum_sizes_are_accepted() {
    let c = RingConfig::new(2, 16);
    assert_eq!(c.descriptors_offset(), CONTROL_SIZE);
    assert_eq!(c.payload_offset(), CONTROL_SIZE + 128);
    assert_eq!(c.required_len(), CONTROL_SIZE + 128 + 16);
}

#[test]
fn config_offsets_for_various_capacities() {
    for (d, p) in [(2usize, 16usize), (3, 17), (4096, 1024 * 1024), (100, 999)] {
        let c = RingConfig::new(d, p);
        assert_eq!(c.descriptors_offset(), 256);
        assert_eq!(c.payload_offset(), 256 + d * 64);
        assert_eq!(c.required_len(), 256 + d * 64 + p);
    }
}

#[test]
fn non_power_of_two_capacities_roundtrip_with_wraparound() {
    // 仕様に 2 冪要件は無い。小さい非 2 冪容量でも書込/回収と折り返しが正しいこと。
    for (desc, pay) in [(3usize, 100usize), (5, 17), (7, 1000), (100, 999), (2, 16)] {
        let (_rg, mut w, mut rd, _ck) = setup(desc, pay, no_wait());
        for i in 0..200u64 {
            let len = (i % 13) as usize;
            let payload: Vec<u8> = (0..len).map(|k| (i as u8) ^ (k as u8)).collect();
            let out = w.write(input(EventKind::CallEnter, i, &payload));
            assert!(
                matches!(out, WriteOutcome::Published { .. }),
                "cfg ({desc},{pay}) write {i} not published: {out:?}"
            );
            let b = rd.drain_all();
            assert_eq!(b.events.len(), 1);
            assert_eq!(b.events[0].payload, payload, "cfg ({desc},{pay}) event {i}");
            assert_eq!(b.events[0].descriptor.sequence, i + 1);
        }
    }
}

// ---------- Cursor / Payload 位置の u64::MAX 付近 ----------

#[test]
fn cursors_near_u64_max_publish_and_drain() {
    let cfg = RingConfig::new(4, 64);
    let region = SharedRegion::new(cfg, 1, 1);
    // Cursor を u64::MAX-2 に置いてから writer/reader を作る。
    store(
        region.base(),
        OFF_WRITE_CURSOR,
        u64::MAX - 2,
        Ordering::Relaxed,
    );
    store(
        region.base(),
        OFF_READ_CURSOR,
        u64::MAX - 2,
        Ordering::Relaxed,
    );
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe { region.writer(no_wait(), clock) };
    let mut rd = unsafe { region.reader() };
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 1, b"aa")),
        WriteOutcome::Published { .. }
    ));
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 2, b"bb")),
        WriteOutcome::Published { .. }
    ));
    assert_eq!(rd.write_cursor(), u64::MAX, "cursor reaches MAX exactly");
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 2);
    assert_eq!(b.events[0].payload, b"aa");
    assert_eq!(b.events[1].payload, b"bb");
    assert_eq!(b.sequence_gaps, 0);
    assert_eq!(rd.read_cursor(), u64::MAX);
    // 注: 次の公開は write_cursor + 1 が u64 を溢れる。2^64 件の公開は現実の
    // 運用では到達不能 (10億件/秒でも 584 年) であり、純粋関数側は折り返しを
    // 後退として検出する (occupancy_at_u64_extremes を参照)。
}

#[test]
fn payload_position_near_u64_max() {
    let cfg = RingConfig::new(4, 64);
    let region = SharedRegion::new(cfg, 1, 1);
    store(
        region.base(),
        OFF_PAYLOAD_WRITE_POSITION,
        u64::MAX - 3,
        Ordering::Relaxed,
    );
    store(
        region.base(),
        OFF_PAYLOAD_READ_POSITION,
        u64::MAX - 3,
        Ordering::Relaxed,
    );
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe { region.writer(no_wait(), clock) };
    let mut rd = unsafe { region.reader() };
    let out = w.write(input(EventKind::CallEnter, 1, b"xyz"));
    assert!(matches!(out, WriteOutcome::Published { .. }));
    assert_eq!(
        ctrl(region.base(), OFF_PAYLOAD_WRITE_POSITION),
        u64::MAX,
        "position advances to MAX exactly"
    );
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1);
    assert_eq!(b.events[0].descriptor.payload_position, u64::MAX - 3);
    assert_eq!(b.events[0].payload, b"xyz", "position % capacity で読める");
    assert_eq!(
        ctrl(region.base(), OFF_PAYLOAD_READ_POSITION),
        u64::MAX,
        "read position tracks the logical (unwrapped) position"
    );
}

// ---------- Payload サイズ境界 ----------

#[test]
fn payload_size_zero_one_cap_minus_one_cap() {
    for len in [0usize, 1, 31, 32] {
        let (_rg, mut w, mut rd, _ck) = setup(8, 32, no_wait());
        let payload = vec![0xABu8; len];
        let out = w.write(input(EventKind::CallEnter, 1, &payload));
        assert!(
            matches!(out, WriteOutcome::Published { .. }),
            "len {len} must publish into an empty 32B payload ring"
        );
        let b = rd.drain_all();
        assert_eq!(b.events.len(), 1);
        assert_eq!(b.events[0].payload, payload);
        assert_eq!(b.events[0].descriptor.payload_len as usize, len);
    }
}

#[test]
fn payload_size_cap_plus_one_degrades_and_accounts_bytes() {
    let (_rg, mut w, mut rd, _ck) = setup(8, 32, no_wait());
    let payload = vec![7u8; 33]; // capacity + 1: 永遠に入らない
    let out = w.write(input(EventKind::CallEnter, 1, &payload));
    assert!(
        matches!(out, WriteOutcome::PublishedDegraded { .. }),
        "oversized payload degrades, got {out:?}"
    );
    let c = w.loss_counters();
    assert_eq!(c.dropped_payload_bytes, 33);
    assert_eq!(c.degraded_events, 1);
    assert_eq!(c.dropped_events, 0);
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1, "descriptor survives");
    assert!(b.events[0].payload.is_empty());
    assert_eq!(b.events[0].descriptor.payload_len, 33, "original len kept");
    assert_eq!(
        b.events[0].capture_state(),
        CaptureState::DroppedByBackpressure
    );
}

#[test]
fn payload_exact_remaining_fit_then_one_byte_over() {
    let (_rg, mut w, mut rd, _ck) = setup(8, 32, no_wait());
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 1, &[1u8; 20])),
        WriteOutcome::Published { .. }
    ));
    // 残り 12 バイトちょうど
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 2, &[2u8; 12])),
        WriteOutcome::Published { .. }
    ));
    // 残り 0 バイトに 1 バイトは劣化する
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 3, &[3u8; 1])),
        WriteOutcome::PublishedDegraded { .. }
    ));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 3);
    assert_eq!(b.events[0].payload, vec![1u8; 20]);
    assert_eq!(b.events[1].payload, vec![2u8; 12]);
    assert!(b.events[2].payload.is_empty());
}

#[test]
fn oversized_payload_with_full_descriptors_drops_event() {
    let (_rg, mut w, _rd, _ck) = setup(2, 32, no_wait());
    // Descriptor 2 件を Payload 満杯の劣化で埋める
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 1, &[1u8; 32])),
        WriteOutcome::Published { .. }
    ));
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 2, &[2u8; 32])),
        WriteOutcome::PublishedDegraded { .. }
    ));
    // 3 件目: Descriptor も Payload も無いのでイベントごと落ちる
    let out = w.write(input(EventKind::CallEnter, 3, &[3u8; 32]));
    assert!(matches!(
        out,
        WriteOutcome::Dropped {
            sequence: 3,
            reason: CaptureState::DroppedByBackpressure
        }
    ));
    let c = w.loss_counters();
    assert_eq!(c.dropped_events, 1);
    assert_eq!(c.degraded_events, 1);
    assert_eq!(c.dropped_payload_bytes, 64, "degraded 32 + dropped 32");
}

#[test]
fn zero_length_payload_needs_no_payload_space() {
    // Payload が満杯でも、長さ 0 のイベントは Descriptor だけで公開できる。
    let (_rg, mut w, mut rd, _ck) = setup(4, 16, no_wait());
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 1, &[9u8; 16])),
        WriteOutcome::Published { .. }
    ));
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 2, &[])),
        WriteOutcome::Published { .. }
    ));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 2);
    assert!(b.events[1].payload.is_empty());
}

// ---------- Descriptor フィールド極値 ----------

#[test]
fn descriptor_all_fields_at_extremes_roundtrip() {
    let mut d = EventDescriptor::new(EventKind::SlotExpandRequest, u64::MAX);
    d.flags = u16::MAX;
    d.payload_len = u32::MAX;
    d.timestamp_qpc = u64::MAX;
    d.call_id = u64::MAX;
    d.parent_call_id = u64::MAX - 1;
    d.payload_position = u64::MAX;
    d.api_id = u32::MAX;
    d.schema_id = u32::MAX;
    d.global_order = 0;
    let bytes = d.to_bytes();
    assert_eq!(EventDescriptor::from_bytes(&bytes), Some(d));
}

#[test]
fn descriptor_kind_enum_boundaries() {
    for v in 0u16..=8 {
        assert!(EventKind::from_u16(v).is_some(), "kind {v} valid");
    }
    for v in [9u16, 100, 1000, u16::MAX] {
        assert_eq!(EventKind::from_u16(v), None, "kind {v} unknown");
    }
    let mut d = EventDescriptor::new(EventKind::Unknown, 1);
    d.kind = u16::MAX;
    assert_eq!(d.kind_enum(), None);
}

#[test]
fn descriptor_from_bytes_length_boundaries() {
    let d = EventDescriptor::new(EventKind::CallEnter, 9);
    let bytes = d.to_bytes();
    for len in 0..64usize {
        assert_eq!(
            EventDescriptor::from_bytes(&bytes[..len]),
            None,
            "len {len} too short"
        );
    }
    assert_eq!(EventDescriptor::from_bytes(&bytes), Some(d));
    let mut longer = bytes.to_vec();
    longer.extend_from_slice(&[0xEE; 64]);
    assert_eq!(
        EventDescriptor::from_bytes(&longer),
        Some(d),
        "trailing bytes beyond 64 are ignored"
    );
}

#[test]
fn capture_state_flag_priority_matrix() {
    use CaptureState::*;
    // 優先順位: DroppedByBackpressure > MemoryUnreadable > CaptureLimitExceeded
    //           > Truncated > Unsupported > Captured
    let cases: &[(u16, CaptureState)] = &[
        (0, Captured),
        (flags::PAYLOAD_DROPPED, Captured), // 落とした印だけでは状態は Captured
        (flags::SNAPSHOT_NOT_COHERENT, Captured),
        (flags::TRUNCATED | flags::UNSUPPORTED, Truncated),
        (
            flags::TRUNCATED | flags::MEMORY_UNREADABLE,
            MemoryUnreadable,
        ),
        (
            flags::CAPTURE_LIMIT_EXCEEDED | flags::TRUNCATED,
            CaptureLimitExceeded,
        ),
        (
            flags::MEMORY_UNREADABLE | flags::CAPTURE_LIMIT_EXCEEDED,
            MemoryUnreadable,
        ),
        (
            flags::DROPPED_BY_BACKPRESSURE | flags::MEMORY_UNREADABLE,
            DroppedByBackpressure,
        ),
        (u16::MAX, DroppedByBackpressure),
    ];
    for (f, want) in cases {
        assert_eq!(CaptureState::from_flags(*f), *want, "flags {f:#06x}");
    }
    // 全状態の L1 可否
    assert!(Captured.is_l1_eligible());
    assert!(MemoryUnreadable.is_l1_eligible());
    assert!(CaptureLimitExceeded.is_l1_eligible());
    assert!(!DroppedByBackpressure.is_l1_eligible());
    assert!(Truncated.is_l1_eligible());
    assert!(Unsupported.is_l1_eligible());
    // payload_dropped は PAYLOAD_DROPPED ビットそのものを見る
    let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
    d.flags = flags::PAYLOAD_DROPPED;
    assert!(d.payload_dropped());
    assert_eq!(d.capture_state(), Captured);
}

// ---------- BOUNDED_WAIT 時刻境界 (Manual Clock) ----------

#[test]
fn bounded_wait_zero_and_dangerous_path_never_wait() {
    // max_wait = 0
    let (_rg, mut w, _rd, _ck) = setup(2, 64, no_wait());
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    let out = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert!(matches!(out, WriteOutcome::Dropped { .. }));
    assert_eq!(
        w.wait_count, 0,
        "zero max_wait must not enter the wait loop"
    );
    assert_eq!(w.state(), OverflowState::Overflow);

    // 危険経路フラグ: max_wait が大きくても待たない
    let policy = WriterPolicy {
        max_wait: Duration::from_secs(5),
        no_wait_dangerous_path: true,
        ..Default::default()
    };
    let (_rg2, mut w2, _rd2, _ck2) = setup(2, 64, policy);
    w2.write(input(EventKind::CallEnter, 1, b"a"));
    w2.write(input(EventKind::CallEnter, 2, b"b"));
    let out = w2.write(input(EventKind::CallEnter, 3, b"c"));
    assert!(matches!(out, WriteOutcome::Dropped { .. }));
    assert_eq!(w2.wait_count, 0);
    assert_eq!(w2.last_wait_ns, 0);
}

#[test]
fn bounded_wait_timeout_exact_boundary_values() {
    // Manual Clock は sleep した分だけ正確に進むので、待機時間は deadline と
    // ちょうど一致するはず。1ns 未満/ちょうど/超過の境界を並べる。
    for deadline_ns in [
        1u64, 49_999, 50_000, 50_001, 999_999, 1_000_000, 1_000_001, 3_700_000,
    ] {
        let policy = WriterPolicy {
            max_wait: Duration::from_nanos(deadline_ns),
            ..Default::default()
        };
        let (region, mut w, _rd, _ck) = setup(2, 64, policy);
        w.write(input(EventKind::CallEnter, 1, b"a"));
        w.write(input(EventKind::CallEnter, 2, b"b"));
        let out = w.write(input(EventKind::CallEnter, 3, b"c"));
        assert!(
            matches!(out, WriteOutcome::Dropped { .. }),
            "deadline {deadline_ns}: full ring must drop after timeout"
        );
        assert_eq!(w.wait_count, 1, "deadline {deadline_ns}");
        assert_eq!(
            w.last_wait_ns, deadline_ns,
            "deadline {deadline_ns}: waited exactly the deadline on a virtual clock"
        );
        assert_eq!(w.total_wait_ns, deadline_ns);
        assert_eq!(w.state(), OverflowState::Overflow);
        assert_eq!(ctrl(region.base(), OFF_OVERFLOW_STATE), 2, "OVERFLOW=2");
        assert_eq!(
            ctrl(region.base(), OFF_LAST_WAIT_NS),
            deadline_ns,
            "wait time is recorded in Control"
        );
        assert!(
            !shirusu_transport::layout::writer_waiting(region.base()),
            "waiting flag must be cleared after timeout"
        );
    }
}

/// sleep の中で回収する Clock。空きができるタイミングを sleep 回数で制御する。
struct DrainClock {
    ticks: AtomicU64,
    reader: Mutex<RingReader>,
    drain_on_sleep: u64,
    sleeps: AtomicU64,
    states_seen: Mutex<Vec<u64>>,
    base: usize,
}
impl Clock for DrainClock {
    fn now_ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }
    fn ticks_per_second(&self) -> u64 {
        1_000_000_000
    }
    fn sleep(&self, dur: Duration) {
        self.ticks
            .fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
        let n = self.sleeps.fetch_add(1, Ordering::Relaxed) + 1;
        let st = load(
            self.base as *const u8,
            OFF_OVERFLOW_STATE,
            Ordering::Relaxed,
        );
        self.states_seen.lock().unwrap().push(st);
        if n == self.drain_on_sleep {
            self.reader.lock().unwrap().drain_all();
        }
    }
}

fn drain_clock_setup(drain_on_sleep: u64) -> (SharedRegion, RingWriter, Arc<DrainClock>) {
    let cfg = RingConfig::new(2, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let reader = unsafe { region.reader() };
    let clock = Arc::new(DrainClock {
        ticks: AtomicU64::new(0),
        reader: Mutex::new(reader),
        drain_on_sleep,
        sleeps: AtomicU64::new(0),
        states_seen: Mutex::new(Vec::new()),
        base: region.base() as usize,
    });
    let policy = WriterPolicy {
        max_wait: Duration::from_nanos(100_000), // 50µs スライス 2 回分
        ..Default::default()
    };
    let mut w = unsafe { region.writer(policy, clock.clone() as Arc<dyn Clock>) };
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    (region, w, clock)
}

#[test]
fn bounded_wait_space_freed_exactly_at_deadline_succeeds() {
    // 2 回目の sleep で空く = 経過がちょうど deadline に達した時点で空きがある。
    // ループは空き確認を deadline 判定より先に行うので成功する。
    let (_rg, mut w, clock) = drain_clock_setup(2);
    let out = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert!(
        matches!(out, WriteOutcome::Published { .. }),
        "space at exactly the deadline must still publish, got {out:?}"
    );
    assert_eq!(w.last_wait_ns, 100_000);
    assert_eq!(w.state(), OverflowState::Normal);
    assert_eq!(
        *clock.states_seen.lock().unwrap(),
        vec![1, 1],
        "state during wait is BOUNDED_WAIT=1"
    );
}

#[test]
fn bounded_wait_space_freed_after_deadline_fails() {
    // 3 回目の sleep で空く = deadline を過ぎてから。待機は失敗する。
    let (_rg, mut w, clock) = drain_clock_setup(3);
    let out = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert!(matches!(out, WriteOutcome::Dropped { .. }));
    assert_eq!(w.last_wait_ns, 100_000);
    assert_eq!(w.state(), OverflowState::Overflow);
    assert_eq!(
        clock.sleeps.load(Ordering::Relaxed),
        2,
        "gave up at deadline"
    );
}

#[test]
fn bounded_wait_total_accumulates_across_waits() {
    let policy = WriterPolicy {
        max_wait: Duration::from_nanos(30_000),
        resume_threshold_percent: 50,
        ..Default::default()
    };
    let (_rg, mut w, mut rd, _ck) = setup(2, 64, policy);
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    let _ = w.write(input(EventKind::CallEnter, 3, b"c")); // wait 1
    assert_eq!(w.total_wait_ns, 30_000);
    rd.drain_all(); // usage 0% < 50% -> 次の書込で Normal に復帰する
    w.write(input(EventKind::CallEnter, 4, b"d"));
    w.write(input(EventKind::CallEnter, 5, b"e"));
    let _ = w.write(input(EventKind::CallEnter, 6, b"f")); // wait 2
    assert_eq!(w.wait_count, 2);
    assert_eq!(w.total_wait_ns, 60_000);
    assert_eq!(w.last_wait_ns, 30_000);
}

// ---------- OVERFLOW 復帰閾値の境界 ----------

#[test]
fn overflow_resume_threshold_is_strictly_below() {
    let mut policy = no_wait();
    policy.resume_threshold_percent = 50;
    let (region, mut w, mut rd, _ck) = setup(4, 1024, policy);
    for i in 1..=4u64 {
        w.write(input(EventKind::CallEnter, i, b"x"));
    }
    let out = w.write(input(EventKind::CallEnter, 5, b"x"));
    assert!(matches!(out, WriteOutcome::Dropped { .. }));
    assert_eq!(w.state(), OverflowState::Overflow);
    rd.drain(2); // 使用率 50% ちょうど: まだ復帰しない (< 50 が条件)
    let out = w.write(input(EventKind::CallEnter, 6, b"x"));
    assert!(
        matches!(out, WriteOutcome::PublishedDegraded { .. }),
        "at exactly the threshold the writer stays in OVERFLOW, got {out:?}"
    );
    assert_eq!(w.state(), OverflowState::Overflow);
    assert_eq!(ctrl(region.base(), OFF_OVERFLOW_STATE), 2);
    rd.drain(2); // 劣化分も含め回収し使用率 0%: 復帰する (劣化書込でも Cursor は進む)
    let out = w.write(input(EventKind::CallEnter, 7, b"x"));
    assert!(matches!(out, WriteOutcome::Published { .. }));
    assert_eq!(w.state(), OverflowState::Normal);
    assert_eq!(ctrl(region.base(), OFF_OVERFLOW_STATE), 0);
}

#[test]
fn overflow_resume_threshold_zero_never_resumes() {
    let mut policy = no_wait();
    policy.resume_threshold_percent = 0;
    let (_rg, mut w, mut rd, _ck) = setup(2, 64, policy);
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert_eq!(w.state(), OverflowState::Overflow);
    rd.drain_all(); // 使用率 0% でも 0 < 0 は偽なので復帰しない
    let out = w.write(input(EventKind::CallEnter, 4, b"d"));
    assert!(
        matches!(out, WriteOutcome::PublishedDegraded { .. }),
        "threshold 0 pins the writer in OVERFLOW, got {out:?}"
    );
    assert_eq!(w.state(), OverflowState::Overflow);
}

#[test]
fn overflow_resume_threshold_hundred_resumes_below_full() {
    let mut policy = no_wait();
    policy.resume_threshold_percent = 100;
    let (_rg, mut w, mut rd, _ck) = setup(2, 64, policy);
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert_eq!(w.state(), OverflowState::Overflow);
    rd.drain(1); // 使用率 50% < 100%: 復帰
    let out = w.write(input(EventKind::CallEnter, 4, b"d"));
    assert!(matches!(out, WriteOutcome::Published { .. }));
    assert_eq!(w.state(), OverflowState::Normal);
}

// ---------- 書込結果と CaptureState の経路 ----------

#[test]
fn publish_notify_signal_crossing_and_host_waiting() {
    // cargo-mutants で検出: publish の used_after の + を * に変える mutant と
    // host_waiting の != を == に変える mutant が、WriteOutcome.notify を
    // 誰も検証していなかったため生き残っていた。
    use shirusu_transport::notify::NotifySignal;
    let cfg = RingConfig::new(4, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock = Arc::new(ManualClock::new());
    let mut w = unsafe { region.writer(no_wait(), clock as Arc<dyn Clock>) };
    let notify_of = |o: WriteOutcome| match o {
        WriteOutcome::Published { notify, .. } => notify,
        other => panic!("must publish, got {other:?}"),
    };
    // Host が待っていない: 閾値 (50% = 2 件) を下から越えたときだけ通知
    assert_eq!(
        notify_of(w.write(input(EventKind::CallEnter, 1, b"a"))),
        NotifySignal::None
    );
    assert_eq!(
        notify_of(w.write(input(EventKind::CallEnter, 2, b"b"))),
        NotifySignal::ThresholdCrossing
    );
    // Host 待機中フラグが立っていれば、crossing でなくても HostWaiting
    let region2 = SharedRegion::new(cfg, 1, 1);
    store(region2.base(), OFF_HOST_WAITING, 1, Ordering::Relaxed);
    let clock2 = Arc::new(ManualClock::new());
    let mut w2 = unsafe { region2.writer(no_wait(), clock2 as Arc<dyn Clock>) };
    assert_eq!(
        notify_of(w2.write(input(EventKind::CallEnter, 1, b"a"))),
        NotifySignal::HostWaiting
    );
}

#[test]
fn leave_after_published_enter_is_published() {
    // cargo-mutants で検出: dropped-enter 判定の && を || に変える mutant。
    // 公開に成功した Enter への Leave が落ちてしまう形で検出する。
    let (_r, mut w, mut rd, _c) = setup(8, 256, no_wait());
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 5, b"v")),
        WriteOutcome::Published { .. }
    ));
    assert!(matches!(
        w.write(input(EventKind::CallLeave, 5, b"v")),
        WriteOutcome::Published { .. }
    ));
    assert_eq!(w.loss_counters().dropped_events, 0);
    assert_eq!(rd.drain_all().events.len(), 2);
}

/// bounded_wait の最終判定と fits 再評価の間に Host の回収が割り込む競合を、
/// elapsed_ns の呼び出しにフックを持つ時計で決定的に再現する。
struct RacingClock {
    inner: ManualClock,
    base: usize,
    trigger_call: u64,
    calls: AtomicU64,
}
impl Clock for RacingClock {
    fn now_ticks(&self) -> u64 {
        self.inner.now_ticks()
    }
    fn ticks_per_second(&self) -> u64 {
        1_000_000_000
    }
    fn sleep(&self, dur: Duration) {
        self.inner.sleep(dur)
    }
    fn elapsed_ns(&self, start: u64, end: u64) -> u64 {
        let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.trigger_call {
            // 競合する Host の回収: Descriptor を 1 つ空ける
            store(self.base as *mut u8, OFF_READ_CURSOR, 1, Ordering::Relaxed);
        }
        end.saturating_sub(start)
    }
}

#[test]
fn bounded_wait_timeout_wins_over_racing_drain() {
    // cargo-mutants で検出: `bounded_wait(...) && fits(...)` の && を || に
    // 変える mutant。待機がタイムアウトした後に空きができても、その試行は
    // OVERFLOW 経路に落ちるのが仕様 (次の書込で再評価される)。
    let cfg = RingConfig::new(2, 4096);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock = Arc::new(RacingClock {
        inner: ManualClock::new(),
        base: region.base() as usize,
        trigger_call: 2,
        calls: AtomicU64::new(0),
    });
    let mut policy = no_wait();
    policy.max_wait = Duration::from_nanos(1);
    let mut w = unsafe { region.writer(policy, clock as Arc<dyn Clock>) };
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    // Descriptor 満杯。待機ループ 2 回目の elapsed 計測で回収が割り込み、
    // その直後に期限切れとなる → 待機は失敗として扱われる。
    let out = w.write(input(EventKind::CallEnter, 3, b"c"));
    assert!(
        !matches!(out, WriteOutcome::Published { .. }),
        "timed-out wait must not publish normally even if space raced in, got {out:?}"
    );
    let counters = w.loss_counters();
    assert_eq!(counters.dropped_events + counters.degraded_events, 1);
}

#[test]
fn drain_payload_read_position_ignores_degraded_descriptors() {
    // cargo-mutants で検出: drain の last_payload_end 更新条件
    // `!dropped && len > 0` の && を || に変える mutant。劣化イベントは
    // Payload を格納していないので、回収位置はその長さ分進んではいけない。
    let (region, mut w, mut rd, _c) = setup(8, 64, no_wait());
    w.write(input(EventKind::CallEnter, 1, b"aaaa"));
    w.write(input(EventKind::CallEnter, 2, b"bbbb"));
    rd.drain_all();
    assert_eq!(ctrl(region.base(), OFF_PAYLOAD_READ_POSITION), 8);
    let mut degraded = input(EventKind::CallEnter, 3, b"012345678901234567890123456789");
    degraded.capture_state = CaptureState::DroppedByBackpressure;
    assert!(matches!(w.write(degraded), WriteOutcome::Published { .. }));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1);
    assert!(b.events[0].descriptor.payload_dropped());
    assert_eq!(
        ctrl(region.base(), OFF_PAYLOAD_READ_POSITION),
        8,
        "degraded descriptors must not advance the payload read position"
    );
}

#[test]
fn reader_level_accessors_reflect_shared_state() {
    // cargo-mutants で検出: RingReader::writer_waiting / loss_counters の
    // 戻り値を固定化する mutant が transport 範囲で生き残っていた
    // (Host 側テストでのみ間接検証されていた)。
    let (region, mut w, rd, _clock) = setup(2, 64, no_wait());
    assert!(!rd.writer_waiting());
    store(region.base(), OFF_WRITER_WAITING, 1, Ordering::Relaxed);
    assert!(rd.writer_waiting());
    store(region.base(), OFF_WRITER_WAITING, 0, Ordering::Relaxed);
    assert!(!rd.writer_waiting());
    // 欠落を起こしてから Reader 側カウンタが Writer 側と一致すること
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    let _ = w.write(input(EventKind::CallEnter, 3, b"c")); // 落ちる
    let from_reader = rd.loss_counters();
    let from_writer = w.loss_counters();
    assert_eq!(from_reader, from_writer);
    assert_eq!(from_reader.dropped_events, 1);
}

#[test]
fn slot_pool_capacity_and_free_count_lifecycle() {
    // cargo-mutants で検出: capacity/free_count の固定化・比較反転 mutant。
    let pool = SlotPool::new(3);
    assert_eq!(pool.capacity(), 3);
    assert_eq!(pool.free_count(), 3);
    let h1 = pool.claim(1).unwrap();
    assert_eq!(pool.free_count(), 2);
    let _h2 = pool.claim(2).unwrap();
    assert_eq!(pool.free_count(), 1);
    pool.begin_detach(&h1);
    assert_eq!(pool.free_count(), 1, "detach alone does not free");
    assert!(pool.host_confirm_ended_and_drained(&h1, true, true));
    assert_eq!(pool.free_count(), 1, "reclaimable is not free yet");
    assert!(pool.host_reclaim(&h1));
    assert_eq!(pool.free_count(), 2);
    assert_eq!(pool.capacity(), 3);
}

#[test]
fn fragment_count_and_len_value_matrix() {
    use shirusu_transport::snapshot::{fragment_count, fragment_len};
    // cargo-mutants で検出: 0 ガードの || を && に変える mutant。
    // frag=0 では割り算に落ちてパニックする形で検出する。
    assert_eq!(fragment_count(0, 8), 0);
    assert_eq!(fragment_count(100, 0), 0);
    assert_eq!(fragment_count(0, 0), 0);
    assert_eq!(fragment_count(1, 8), 1);
    assert_eq!(fragment_count(8, 8), 1);
    assert_eq!(fragment_count(9, 8), 2);
    assert_eq!(fragment_count(16, 8), 2);
    assert_eq!(fragment_count(17, 8), 3);
    assert_eq!(fragment_len(100, 0, 0), 0);
    assert_eq!(fragment_len(100, 8, 0), 8);
    assert_eq!(fragment_len(100, 8, 12), 4);
    assert_eq!(
        fragment_len(100, 8, 13),
        0,
        "index == count is out of range"
    );
    assert_eq!(fragment_len(10, 4, 3), 0, "offset beyond total is 0");
    assert_eq!(fragment_len(17, 8, 2), 1);
}

#[test]
fn validating_reader_accepts_oversized_mapping() {
    // cargo-mutants で検出: mapping_len の < を > に変える mutant は
    // 「マッピングがちょうど必要サイズ」のテストでは区別できない。
    // マッピングの方が大きい正当なケースで倒す。
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 7, 1);
    let mut w2 =
        unsafe { region.writer(no_wait(), Arc::new(ManualClock::new()) as Arc<dyn Clock>) };
    w2.write(input(EventKind::CallEnter, 1, b"m"));
    let known = KnownConfig::new(cfg, cfg.required_len() + 8192);
    let mut vr = ValidatingReader::new(known, 7);
    let evs = vr.drain_image(region.as_slice()).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].payload, b"m");
}

#[test]
fn next_sequence_peek_tracks_writes_and_drops() {
    // cargo-mutants で検出: next_sequence_peek の戻り値を固定値に変える
    // mutant が生き残っていた (誰も覗き値を検証していなかった)。
    let (_region, mut w, _rd, _clock) = setup(2, 64, no_wait());
    assert_eq!(w.next_sequence_peek(), 1, "first sequence is 1");
    w.write(input(EventKind::CallEnter, 1, b"a"));
    assert_eq!(w.next_sequence_peek(), 2);
    w.write(input(EventKind::CallEnter, 2, b"b"));
    assert_eq!(w.next_sequence_peek(), 3);
    // 落ちた書込も Sequence を消費する (欠落として観測されるため)
    let _ = w.write(input(EventKind::CallEnter, 3, b"cdefghij"));
    assert_eq!(w.next_sequence_peek(), 4);
}

#[test]
fn descriptor_flag_constants_match_spec_bit_positions() {
    // flags は共有メモリ ABI の一部。各ビット位置を仕様どおりに固定する
    // (cargo-mutants で検出: SNAPSHOT_NOT_COHERENT の << を >> に変える
    // mutant が、行列テストの入力として縮退して生き残っていた)。
    assert_eq!(flags::PAYLOAD_DROPPED, 1 << 0);
    assert_eq!(flags::TRUNCATED, 1 << 1);
    assert_eq!(flags::MEMORY_UNREADABLE, 1 << 2);
    assert_eq!(flags::CAPTURE_LIMIT_EXCEEDED, 1 << 3);
    assert_eq!(flags::DROPPED_BY_BACKPRESSURE, 1 << 4);
    assert_eq!(flags::UNSUPPORTED, 1 << 5);
    assert_eq!(flags::SNAPSHOT_NOT_COHERENT, 1 << 6);
    // 全ビットが相異なる (重なっていない) ことも ABI 上の要件
    let all = [
        flags::PAYLOAD_DROPPED,
        flags::TRUNCATED,
        flags::MEMORY_UNREADABLE,
        flags::CAPTURE_LIMIT_EXCEEDED,
        flags::DROPPED_BY_BACKPRESSURE,
        flags::UNSUPPORTED,
        flags::SNAPSHOT_NOT_COHERENT,
    ];
    let union: u16 = all.iter().fold(0, |a, b| a | b);
    assert_eq!(union.count_ones() as usize, all.len());
}

#[test]
fn slot_state_encoding_matrix() {
    use shirusu_transport::slot::SlotState;
    let all = [
        SlotState::Free,
        SlotState::Claimed,
        SlotState::Active,
        SlotState::Draining,
        SlotState::Reclaimable,
        // R3: 回収中だけ現れる過渡状態 (番号 5)
        SlotState::Reclaiming,
        // レビュー #4 の #10: 追加直後・公開前だけ現れる状態 (番号 6)
        SlotState::Preparing,
    ];
    for (i, s) in all.iter().enumerate() {
        assert_eq!(s.to_u8(), i as u8);
        assert_eq!(SlotState::from_u8(i as u8), Some(*s));
    }
    assert_eq!(SlotState::from_u8(7), None);
    assert_eq!(SlotState::from_u8(255), None);
    // Pool 経由の Slot アクセサ: claim 前後で generation / owner が読める
    let pool = SlotPool::new(1);
    let slot = pool.slot(0);
    assert_eq!(slot.state(), SlotState::Free);
    assert_eq!(slot.generation(), 1);
    assert_eq!(slot.owner_thread_id(), 0);
    let _h = pool.claim(4242).unwrap();
    let slot = pool.slot(0);
    // claim は CLAIMED を経由して ACTIVE まで進めてから返る
    assert_eq!(slot.state(), SlotState::Active);
    assert_eq!(slot.owner_thread_id(), 4242);
}

#[test]
fn non_captured_state_in_normal_path_keeps_original_length() {
    // 通常経路 (満杯でない) で DroppedByBackpressure を書くと、Payload は
    // 格納されないが Descriptor には元の長さが残る (publish_normal の分岐)。
    let (_region, mut w, mut rd, _clock) = setup(8, 256, no_wait());
    let mut inp = input(EventKind::CallEnter, 5, b"not-stored-value");
    inp.capture_state = CaptureState::DroppedByBackpressure;
    assert!(matches!(w.write(inp), WriteOutcome::Published { .. }));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1);
    assert_eq!(b.events[0].descriptor.payload_len, 16);
    assert!(b.events[0].descriptor.payload_dropped());
    assert!(b.events[0].payload.is_empty());
}

#[test]
fn non_captured_states_store_no_payload_but_keep_length() {
    for state in [
        CaptureState::MemoryUnreadable,
        CaptureState::CaptureLimitExceeded,
        CaptureState::DroppedByBackpressure,
        CaptureState::Truncated,
        CaptureState::Unsupported,
    ] {
        let (_rg, mut w, mut rd, _ck) = setup(4, 64, no_wait());
        let mut inp = input(EventKind::CallEnter, 1, b"xyz");
        inp.capture_state = state;
        let out = w.write(inp);
        assert!(
            matches!(out, WriteOutcome::Published { .. }),
            "state {state:?} still publishes the descriptor"
        );
        // Payload 位置は進んでいない: 次の Captured は位置 0 に書く
        w.write(input(EventKind::CallEnter, 2, b"ab"));
        let b = rd.drain_all();
        assert_eq!(b.events.len(), 2);
        let first = &b.events[0];
        assert!(
            first.payload.is_empty(),
            "state {state:?}: no payload stored"
        );
        assert_eq!(first.descriptor.payload_len, 3, "original length kept");
        assert_eq!(first.capture_state(), state);
        assert!(first.descriptor.payload_dropped());
        assert_eq!(b.events[1].descriptor.payload_position, 0);
        assert_eq!(b.events[1].payload, b"ab");
    }
}

#[test]
fn dropped_events_consume_sequence_and_gap_is_exact() {
    let (_rg, mut w, mut rd, _ck) = setup(2, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, b""));
    w.write(input(EventKind::CallEnter, 2, b""));
    for want_seq in 3..=5u64 {
        let out = w.write(input(EventKind::CallEnter, want_seq, b""));
        assert!(matches!(
            out,
            WriteOutcome::Dropped { sequence, .. } if sequence == want_seq
        ));
    }
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 2);
    assert_eq!(b.sequence_gaps, 0, "drops are after the drained prefix");
    w.write(input(EventKind::CallEnter, 6, b""));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1);
    assert_eq!(b.events[0].descriptor.sequence, 6);
    assert_eq!(b.sequence_gaps, 3, "sequences 3,4,5 were dropped");
}

#[test]
fn reader_drain_zero_and_partial_advance() {
    let (region, mut w, mut rd, _ck) = setup(8, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, b"aaaa")); // payload 0..4
    w.write(input(EventKind::CallEnter, 2, b"bb")); // payload 4..6
    w.write(input(EventKind::CallEnter, 3, b"c")); // payload 6..7
    let b = rd.drain(0);
    assert!(b.events.is_empty());
    assert_eq!(rd.read_cursor(), 0, "drain(0) advances nothing");
    let b = rd.drain(2);
    assert_eq!(b.events.len(), 2);
    assert_eq!(rd.read_cursor(), 2);
    assert_eq!(
        ctrl(region.base(), OFF_PAYLOAD_READ_POSITION),
        6,
        "payload read position = end of last drained event"
    );
    let b = rd.drain(99);
    assert_eq!(b.events.len(), 1, "drain clamps to available");
    assert_eq!(ctrl(region.base(), OFF_PAYLOAD_READ_POSITION), 7);
    assert!(rd.drain_all().events.is_empty());
    assert_eq!(
        ctrl(region.base(), OFF_HOST_DRAIN_COUNT),
        2,
        "two non-empty drains"
    );
}

#[test]
fn writer_with_regressed_reader_cursor_drops_safely() {
    // 読み手 Cursor が書き手より先行する破損状態でも、書込は落として前に進む。
    let (region, mut w, _rd, _ck) = setup(4, 64, no_wait());
    store(region.base(), OFF_READ_CURSOR, 10, Ordering::Relaxed);
    let out = w.write(input(EventKind::CallEnter, 1, b"data"));
    assert!(matches!(out, WriteOutcome::Dropped { .. }));
    assert_eq!(w.loss_counters().dropped_events, 1);
}

#[test]
fn detached_flag_alone_does_not_block_ring_writes() {
    // Ring 層では DETACH は印だけ。書込を止めるのは Agent 層の責務。
    let (_rg, mut w, mut rd, _ck) = setup(4, 64, no_wait());
    assert!(!w.is_detached());
    w.mark_detached();
    assert!(w.is_detached());
    assert!(matches!(
        w.write(input(EventKind::CallEnter, 1, b"x")),
        WriteOutcome::Published { .. }
    ));
    assert_eq!(rd.drain_all().events.len(), 1);
}

// ---------- 通知閾値の境界 ----------

#[test]
fn notify_threshold_edge_values() {
    // 閾値 0: 最初の公開で「越えた」ことになる (使用率 0% -> 正の使用率)
    let mut t = PublishNotifyTracker::new();
    assert_eq!(
        t.after_publish(0, 1, 100, 0, false),
        NotifySignal::ThresholdCrossing
    );
    // 閾値 100: 満杯になった瞬間だけ
    let mut t = PublishNotifyTracker::new();
    assert_eq!(t.after_publish(0, 1, 4, 100, false), NotifySignal::None);
    assert_eq!(t.after_publish(1, 2, 4, 100, false), NotifySignal::None);
    assert_eq!(t.after_publish(2, 3, 4, 100, false), NotifySignal::None);
    assert_eq!(
        t.after_publish(3, 4, 4, 100, false),
        NotifySignal::ThresholdCrossing
    );
    assert_eq!(t.after_publish(4, 5, 4, 100, false), NotifySignal::None);
    // 閾値 >100: 永遠に越えない
    let mut t = PublishNotifyTracker::new();
    assert_eq!(t.after_publish(0, 100, 100, 150, false), NotifySignal::None);
    // 容量 0: usage_percent は 100 を返すため閾値 50 では越えた扱い
    let mut t = PublishNotifyTracker::new();
    assert_eq!(
        t.after_publish(0, 1, 0, 50, false),
        NotifySignal::ThresholdCrossing
    );
    // 越えと HostWaiting が同時なら ThresholdCrossing が優先される
    let mut t = PublishNotifyTracker::new();
    assert_eq!(
        t.after_publish(49, 50, 100, 50, true),
        NotifySignal::ThresholdCrossing
    );
    // 使用率が閾値ちょうどから始まる公開は「下から上へ」ではない
    let mut t = PublishNotifyTracker::new();
    assert_eq!(t.after_publish(50, 51, 100, 50, false), NotifySignal::None);
}

#[test]
fn recheck_policy_edge_values() {
    let zero = ReCheckPolicy {
        interval: Duration::ZERO,
    };
    assert!(zero.should_recheck(Duration::ZERO));
    assert_eq!(zero.wait_timeout(Duration::ZERO), Duration::ZERO);
    let p = ReCheckPolicy::default();
    assert_eq!(p.interval, Duration::from_millis(2));
    assert_eq!(
        p.wait_timeout(Duration::from_millis(1)),
        Duration::from_millis(1)
    );
    assert_eq!(p.wait_timeout(Duration::from_millis(2)), Duration::ZERO);
    assert_eq!(p.wait_timeout(Duration::from_secs(1)), Duration::ZERO);
}

// ---------- Clock 境界 ----------

#[test]
fn clock_elapsed_and_advance_edges() {
    let mut c = ManualClock::new();
    c.ticks_per_second = 1_000; // 1 tick = 1ms 相当の粗い時計
    assert_eq!(c.elapsed_ns(0, 1_000), 1_000_000_000);
    assert_eq!(c.elapsed_ns(500, 400), 0, "end < start saturates to 0");
    assert_eq!(c.elapsed_ns(7, 7), 0);
    c.set(1_000_000);
    assert_eq!(c.now_ticks(), 1_000_000);
    c.advance(Duration::from_millis(3));
    assert_eq!(c.now_ticks(), 1_000_000 + 3_000_000);

    let z = ManualClock::new();
    let s = z.now_ticks();
    z.sleep(Duration::ZERO);
    assert_eq!(z.now_ticks(), s + 1, "zero sleep still advances 1 tick");
    // ticks_per_second = 0 は 1 として扱われる (ゼロ除算しない)
    let mut weird = ManualClock::new();
    weird.ticks_per_second = 0;
    assert_eq!(weird.elapsed_ns(0, 5), 5_000_000_000);

    let sys = shirusu_transport::clock::SystemClock::default();
    assert_eq!(sys.ticks_per_second(), 1_000_000_000);
    let a = sys.now_ticks();
    sys.sleep(Duration::ZERO);
    assert!(sys.now_ticks() >= a);
}

// ---------- CRC32C 境界 ----------

#[test]
fn crc32c_single_byte_inputs_are_all_distinct() {
    let mut seen = std::collections::HashSet::new();
    for b in 0u16..=255 {
        seen.insert(shirusu_transport::crc32c::crc32c(&[b as u8]));
    }
    assert_eq!(seen.len(), 256, "CRC32C separates all 1-byte inputs");
}

#[test]
fn crc32c_every_single_bit_flip_is_detected() {
    let msg = b"shirusu";
    let want = shirusu_transport::crc32c::crc32c(msg);
    for byte in 0..msg.len() {
        for bit in 0..8 {
            let mut m = msg.to_vec();
            m[byte] ^= 1 << bit;
            assert_ne!(shirusu_transport::crc32c::crc32c(&m), want);
        }
    }
    // 末尾に 0 バイトを足すと CRC は変わる (長さも効く)
    let mut extended = msg.to_vec();
    extended.push(0);
    assert_ne!(shirusu_transport::crc32c::crc32c(&extended), want);
    // 空入力の update は seed をそのまま返す (!(!seed) == seed)
    assert_eq!(
        shirusu_transport::crc32c::crc32c_update(0xDEAD_BEEF, &[]),
        0xDEAD_BEEF
    );
    assert_eq!(shirusu_transport::crc32c::crc32c_update(0, &[]), 0);
}

// ---------- Slot 境界 ----------

#[test]
fn slot_pool_zero_capacity() {
    let pool = SlotPool::new(0);
    assert_eq!(pool.capacity(), 0);
    assert_eq!(pool.free_count(), 0);
    assert!(pool.claim(1).is_none());
    assert_eq!(pool.missing_calls(), 1);
    assert_eq!(pool.total_memory_bytes(), 0);
    assert!(pool.can_add_slot(), "no limit configured");
}

#[test]
fn slot_low_watermark_zero_and_above_capacity() {
    // 低水位 0: 残りが何件でも拡張要求は立たない
    let pool = SlotPool::with_low_watermark(2, 0);
    pool.claim(1).unwrap();
    pool.claim(2).unwrap();
    assert_eq!(
        pool.expansion_request_count.load(Ordering::Relaxed),
        0,
        "free_count < 0 never holds"
    );
    assert!(!pool.take_expansion_request());
    // 低水位が容量以上: 最初の claim で要求が立つが、フラグが立っている間は増えない
    let pool = SlotPool::with_low_watermark(3, 99);
    pool.claim(1).unwrap();
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 1);
    pool.claim(2).unwrap();
    assert_eq!(
        pool.expansion_request_count.load(Ordering::Relaxed),
        1,
        "request flag latches until taken"
    );
    assert!(pool.take_expansion_request());
    pool.claim(3).unwrap(); // free 0 < 99 なので再び立つ
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 2);
}

#[test]
fn slot_stale_handle_rejected_in_every_transition() {
    let pool = SlotPool::new(1);
    let h1 = pool.claim(1).unwrap();
    // Active のままでは confirm/reclaim できない
    assert!(!pool.host_confirm_ended_and_drained(&h1, true, true));
    assert!(!pool.host_reclaim(&h1));
    assert!(pool.begin_detach(&h1));
    // 二度目の DETACH は失敗する (既に DRAINING)
    assert!(!pool.begin_detach(&h1));
    assert!(pool.host_confirm_ended_and_drained(&h1, true, true));
    assert_eq!(pool.slot(h1.index).state(), SlotState::Reclaimable);
    // Reclaimable でも DETACH 後呼出は数える
    assert!(pool.note_call_after_detach(&h1));
    assert!(pool.host_reclaim(&h1));
    // 再利用後に古い handle は全ての遷移で効かない
    let h2 = pool.claim(2).unwrap();
    assert_eq!(h2.index, h1.index);
    assert!(!pool.begin_detach(&h1));
    assert!(!pool.host_confirm_ended_and_drained(&h1, true, true));
    assert!(!pool.host_reclaim(&h1));
    assert!(!pool.note_call_after_detach(&h1), "new owner is Active");
    assert_eq!(pool.slot(h2.index).state(), SlotState::Active);
}

#[test]
fn slot_generation_increments_each_reuse_cycle() {
    let pool = SlotPool::new(1);
    let mut prev = 0u64;
    for cycle in 1..=5u64 {
        let h = pool.claim(cycle).unwrap();
        assert_eq!(h.generation, prev + 1, "cycle {cycle}");
        prev = h.generation;
        assert!(pool.begin_detach(&h));
        assert!(pool.host_confirm_ended_and_drained(&h, true, true));
        assert!(pool.host_reclaim(&h));
    }
}

#[test]
fn slot_memory_limit_exact_boundary() {
    // (現在 + 1) Slot ちょうどで収まる上限は許可、それ未満は不許可
    let exact = (32 + 1) * SLOT_MEMORY_BYTES;
    assert!(SlotPool::production()
        .with_memory_limit(exact)
        .can_add_slot());
    assert!(!SlotPool::production()
        .with_memory_limit(exact - 1)
        .can_add_slot());
    assert!(
        !SlotPool::production()
            .with_memory_limit(32 * SLOT_MEMORY_BYTES)
            .can_add_slot(),
        "current usage alone is not room for one more"
    );
    assert!(
        !SlotPool::new(1).with_memory_limit(0).can_add_slot(),
        "zero limit admits nothing"
    );
    assert_eq!(SlotPool::new(3).total_memory_bytes(), 3 * SLOT_MEMORY_BYTES);
}

// ---------- Snapshot 境界 ----------

#[test]
fn snapshot_zero_length_completes_with_no_fragments() {
    let (_rg, mut w, mut rd, _ck) = setup(16, 1024, no_wait());
    let out = write_snapshot(&mut w, &SliceSource(&[]), 0, 128, 1, 1, 42);
    assert_eq!(out.state, CaptureState::Captured);
    assert_eq!(out.fragments_published, 0);
    assert_eq!(out.bytes_captured, 0);
    assert!(out.complete_marker_published);
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1, "only the Complete marker");
    let (joined, state) = reassemble(&b.events, 42);
    assert_eq!(state, CaptureState::Captured);
    assert!(joined.is_empty());
}

#[test]
fn snapshot_fragment_size_boundaries() {
    // fragment == total, fragment > total, total % fragment == 0 (余分な空 Fragment なし)
    for (len, frag, want_frags) in [
        (100usize, 100usize, 1usize),
        (100, 1000, 1),
        (256, 128, 2),
        (255, 128, 2),
        (128, 128, 1),
    ] {
        let data: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
        let (_rg, mut w, mut rd, _ck) = setup(64, 8192, no_wait());
        let out = write_snapshot(&mut w, &SliceSource(&data), len, frag, 1, 1, 3);
        assert_eq!(out.state, CaptureState::Captured, "len {len} frag {frag}");
        assert_eq!(out.fragments_published, want_frags, "len {len} frag {frag}");
        let b = rd.drain_all();
        let (joined, state) = reassemble(&b.events, 3);
        assert_eq!(state, CaptureState::Captured);
        assert_eq!(joined, data);
    }
    // fragment_payload = 0 は Unsupported で何も書かない
    let (_rg, mut w, mut rd, _ck) = setup(16, 1024, no_wait());
    let out = write_snapshot(&mut w, &SliceSource(b"abc"), 3, 0, 1, 1, 3);
    assert_eq!(out.state, CaptureState::Unsupported);
    assert_eq!(out.fragments_published, 0);
    assert!(!out.complete_marker_published);
    assert!(rd.drain_all().events.is_empty());
}

#[test]
fn snapshot_fail_at_zero_and_source_read_boundaries() {
    let data = vec![5u8; 300];
    let (_rg, mut w, _rd, _ck) = setup(64, 8192, no_wait());
    let src = FailAfterSource {
        inner: &data,
        fail_at: 0,
    };
    let out = write_snapshot(&mut w, &src, data.len(), 128, 1, 1, 3);
    assert_eq!(out.state, CaptureState::MemoryUnreadable);
    assert_eq!(out.fragments_published, 0);
    assert_eq!(out.bytes_captured, 0);
    // Source の読み取り境界そのもの: fail_at ちょうどまでは読める
    let src = FailAfterSource {
        inner: &data,
        fail_at: 10,
    };
    let mut buf = [0u8; 10];
    use shirusu_transport::snapshot::MemorySource;
    assert!(src.read_mem(0, &mut buf).is_ok());
    assert!(src.read_mem(1, &mut buf).is_err(), "1+10 > fail_at");
    let slice = SliceSource(&data);
    assert!(
        slice.read_mem(300, &mut []).is_ok(),
        "empty read at exact end"
    );
    assert!(slice.read_mem(299, &mut [0u8; 1]).is_ok());
    assert!(slice.read_mem(300, &mut [0u8; 1]).is_err());
}

#[test]
fn reassemble_mixed_calls_dropped_fragment_and_missing_complete() {
    use shirusu_transport::ring::ReceivedEvent;
    let mk = |kind: EventKind, call: u64, flags_v: u16, payload: &[u8]| ReceivedEvent {
        descriptor: {
            let mut d = EventDescriptor::new(kind, 1);
            d.call_id = call;
            d.flags = flags_v;
            d
        },
        payload: payload.into(),
    };
    let events = vec![
        mk(EventKind::SnapshotFragment, 9, 0, b"aa"),
        mk(EventKind::SnapshotFragment, 8, 0, b"XX"), // 別 call は混ざらない
        mk(
            EventKind::SnapshotFragment,
            9,
            flags::PAYLOAD_DROPPED,
            b"zz",
        ), // 落とした分は連結しない
        mk(EventKind::SnapshotFragment, 9, 0, b"bb"),
        mk(EventKind::SnapshotComplete, 8, 0, b""), // 別 call の Complete は効かない
    ];
    let (joined, state) = reassemble(&events, 9);
    assert_eq!(joined, b"aabb");
    assert_eq!(state, CaptureState::Truncated, "no Complete for call 9");
    let (joined8, state8) = reassemble(&events, 8);
    assert_eq!(joined8, b"XX");
    assert_eq!(state8, CaptureState::Captured);
    let (empty, st) = reassemble(&[], 9);
    assert!(empty.is_empty());
    assert_eq!(st, CaptureState::Truncated);
    // Complete があれば、途中の穴があっても状態は Captured (欠落は Descriptor 側の記録を見る)
    let mut ev2 = events.clone();
    ev2.push(mk(EventKind::SnapshotComplete, 9, 0, b""));
    let (j2, s2) = reassemble(&ev2, 9);
    assert_eq!(j2, b"aabb");
    assert_eq!(s2, CaptureState::Captured);
}

// ---------- validate 境界 ----------

#[test]
fn validate_cursor_pair_extremes() {
    assert_eq!(validate_cursor_pair(u64::MAX, u64::MAX, 8), Ok(0));
    assert_eq!(validate_cursor_pair(u64::MAX, 0, u64::MAX), Ok(u64::MAX));
    assert_eq!(validate_cursor_pair(5, 5, 0), Ok(0));
    assert!(matches!(
        validate_cursor_pair(6, 5, 0),
        Err(IntegrityError::OccupancyExceedsCapacity {
            occupancy: 1,
            capacity: 0
        })
    ));
    assert!(matches!(
        validate_cursor_pair(0, 1, 100),
        Err(IntegrityError::CursorRegressed { .. })
    ));
    assert!(matches!(
        validate_cursor_pair(u64::MAX, 0, 100),
        Err(IntegrityError::OccupancyExceedsCapacity { .. })
    ));
}

fn known_small() -> KnownConfig {
    KnownConfig::new(
        RingConfig::new(16, 256),
        RingConfig::new(16, 256).required_len(),
    )
}
/// Vec<u8> はポインタの 8 バイト整列を保証しないため、layout の原子操作
/// (AtomicU64 参照を作る) を適用する画像は u64 バッファで保持する。
/// 整列していないポインタへの原子操作は UB (Miri 検出)。
struct AlignedImage {
    words: Vec<u64>,
    len: usize,
}
impl AlignedImage {
    fn zeroed(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(8)],
            len,
        }
    }
    fn copy_of(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.as_mut_slice().copy_from_slice(src);
        s
    }
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }
}
impl std::ops::Deref for AlignedImage {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl std::ops::DerefMut for AlignedImage {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

fn control_image(mutate: impl FnOnce(&mut [u8])) -> AlignedImage {
    let cfg = RingConfig::new(16, 256);
    let mut img = AlignedImage::zeroed(cfg.required_len());
    init_control(img.as_mut_ptr(), cfg, 3, 9);
    mutate(img.as_mut_slice());
    img
}
fn set(img: &mut [u8], off: usize, v: u64) {
    store(img.as_mut_ptr(), off, v, Ordering::Relaxed);
}

#[test]
fn validate_control_length_magic_and_mapping_boundaries() {
    let known = known_small();
    let img = control_image(|_| {});
    assert!(matches!(
        validate_control(&img[..255], &known, None),
        Err(IntegrityError::ImageTooSmall)
    ));
    assert!(validate_control(&img[..256], &known, None).is_ok());
    assert!(
        validate_control(&img, &known, None).is_ok(),
        "longer copies are fine"
    );
    let bad_magic = control_image(|i| set(i, OFF_MAGIC, 0));
    assert!(matches!(
        validate_control(&bad_magic[..256], &known, None),
        Err(IntegrityError::BadMagic)
    ));
    // Host 既知の mapping が小さい場合は Control が正しくても弾く
    let tiny = KnownConfig {
        mapping_len: 10,
        ..known_small()
    };
    assert!(matches!(
        validate_control(&img[..256], &tiny, None),
        Err(IntegrityError::ImageTooSmall)
    ));
    // Payload 側 Cursor 対の後退も検出する
    let bad_payload = control_image(|i| {
        set(i, OFF_PAYLOAD_WRITE_POSITION, 3);
        set(i, OFF_PAYLOAD_READ_POSITION, 9);
    });
    assert!(matches!(
        validate_control(&bad_payload[..256], &known, None),
        Err(IntegrityError::CursorRegressed { .. })
    ));
}

#[test]
fn validate_control_prev_snapshot_priority_and_counter_regression() {
    let known = known_small();
    let img = control_image(|i| {
        set(i, OFF_WRITE_CURSOR, 5);
        set(i, OFF_DROPPED_EVENTS, 2);
    });
    let prev = validate_control(&img[..256], &known, None).unwrap();
    // 世代が違えば Cursor 後退より先に世代不一致で弾く
    let other = control_image(|i| {
        set(i, OFF_WRITE_CURSOR, 1);
    });
    let other_snap_img = {
        let cfg = RingConfig::new(16, 256);
        let mut v = AlignedImage::zeroed(cfg.required_len());
        init_control(v.as_mut_ptr(), cfg, 4, 9);
        v
    };
    let _ = other;
    assert!(matches!(
        validate_control(&other_snap_img[..256], &known, Some(&prev)),
        Err(IntegrityError::GenerationMismatch {
            expected: 3,
            found: 4
        })
    ));
    // カウンタ後退は CounterRegressed
    let regressed = control_image(|i| {
        set(i, OFF_WRITE_CURSOR, 6);
        set(i, OFF_DROPPED_EVENTS, 1);
    });
    assert!(matches!(
        validate_control(&regressed[..256], &known, Some(&prev)),
        Err(IntegrityError::CounterRegressed)
    ));
    // read_cursor だけの後退も CursorRegressed
    let read_back = control_image(|i| {
        set(i, OFF_WRITE_CURSOR, 5);
        set(i, OFF_READ_CURSOR, 0);
        set(i, OFF_DROPPED_EVENTS, 2);
    });
    let prev2_img = control_image(|i| {
        set(i, OFF_WRITE_CURSOR, 5);
        set(i, OFF_READ_CURSOR, 2);
        set(i, OFF_DROPPED_EVENTS, 2);
    });
    let prev2 = validate_control(&prev2_img[..256], &known, None).unwrap();
    assert!(matches!(
        validate_control(&read_back[..256], &known, Some(&prev2)),
        Err(IntegrityError::CursorRegressed { .. })
    ));
}

#[test]
fn decode_descriptor_boundaries() {
    let known = known_small(); // payload capacity 256
    let good = EventDescriptor::new(EventKind::CallEnter, 1);
    assert!(matches!(
        decode_descriptor(&good.to_bytes()[..63], &known, false),
        Err(IntegrityError::ImageTooSmall)
    ));
    for kind in 1u16..=8 {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
        d.kind = kind;
        assert!(
            decode_descriptor(&d.to_bytes(), &known, false).is_ok(),
            "kind {kind}"
        );
    }
    let mut d = EventDescriptor::new(EventKind::Unknown, 1);
    assert!(matches!(
        decode_descriptor(&d.to_bytes(), &known, false),
        Err(IntegrityError::UnknownKind(0))
    ));
    d.kind = 9;
    assert!(matches!(
        decode_descriptor(&d.to_bytes(), &known, false),
        Err(IntegrityError::UnknownKind(9))
    ));
    // payload_len は容量ちょうどまで可、+1 は不可
    let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
    d.payload_len = 256;
    assert!(decode_descriptor(&d.to_bytes(), &known, false).is_ok());
    d.payload_len = 257;
    assert!(matches!(
        decode_descriptor(&d.to_bytes(), &known, false),
        Err(IntegrityError::PayloadTooLarge {
            len: 257,
            capacity: 256
        })
    ));
    // L11: global_order は無効なセッションでは 1 でも MAX でも不可。
    // 有効なセッションでは受理する。
    for r in [1u64, u64::MAX] {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
        d.global_order = r;
        assert!(matches!(
            decode_descriptor(&d.to_bytes(), &known, false),
            Err(IntegrityError::GlobalOrderNotAllowed)
        ));
        assert!(decode_descriptor(&d.to_bytes(), &known, true).is_ok());
    }
}

#[test]
fn decode_payload_range_boundaries() {
    let known = known_small(); // cap 256
    let region: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
    let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
    // 領域が容量より小さい
    d.payload_len = 4;
    assert!(matches!(
        decode_payload(&d, &region[..100], &known),
        Err(IntegrityError::PayloadRangeInvalid)
    ));
    // payload_len > capacity は Descriptor が直接来た場合も弾く
    d.payload_len = 257;
    assert!(matches!(
        decode_payload(&d, &region, &known),
        Err(IntegrityError::PayloadRangeInvalid)
    ));
    // 位置 u64::MAX: start = MAX % 256 = 255、末尾から折り返す
    d.payload_len = 3;
    d.payload_position = u64::MAX;
    let p = decode_payload(&d, &region, &known).unwrap();
    assert_eq!(p, vec![255, 0, 1]);
    // 容量ちょうど 1 周: start から回転した全体が返る
    d.payload_len = 256;
    d.payload_position = 100;
    let p = decode_payload(&d, &region, &known).unwrap();
    assert_eq!(p.len(), 256);
    assert_eq!(p[0], 100);
    assert_eq!(p[155], 255);
    assert_eq!(p[156], 0);
    assert_eq!(p[255], 99);
    // 位置が容量の倍数なら回転しない
    d.payload_position = 512;
    d.payload_len = 4;
    assert_eq!(
        decode_payload(&d, &region, &known).unwrap(),
        vec![0, 1, 2, 3]
    );
}

#[test]
fn validating_reader_boundaries() {
    let cfg = RingConfig::new(8, 256);
    let known = KnownConfig::new(cfg, cfg.required_len());
    // 像が小さい → ImageTooSmall で停止する
    let mut vr = ValidatingReader::new(known, 1);
    assert!(matches!(
        vr.drain_image(&[0u8; 10]),
        Err(IntegrityError::ImageTooSmall)
    ));
    assert!(vr.is_stopped());
    assert!(
        matches!(vr.drain_image(&[0u8; 10]), Err(IntegrityError::RingStopped)),
        "once stopped, always RingStopped"
    );

    // 正常な像を 2 回読んでも 2 回目は空
    let region = SharedRegion::new(cfg, 7, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe { region.writer(no_wait(), clock) };
    w.write(input(EventKind::CallEnter, 1, b"one"));
    let mut vr = ValidatingReader::new(known, 7);
    let evs = vr.drain_image(region.as_slice()).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].payload, b"one");
    assert!(vr.drain_image(region.as_slice()).unwrap().is_empty());
    assert!(!vr.is_stopped());
    assert_eq!(vr.control_snapshot().unwrap().write_cursor, 1);

    // Sequence 0 の Descriptor は確定済みスロットでは矛盾（書き手は 1 から振る）。
    // write_cursor だけが進んだ壊れた像として SequenceRegressed で止まる。
    let mut image = AlignedImage::copy_of(region.as_slice());
    let mut zero_seq = EventDescriptor::new(EventKind::CallEnter, 0);
    zero_seq.payload_len = 0;
    let off = cfg.descriptors_offset() + 64; // slot 1
    image[off..off + 64].copy_from_slice(&zero_seq.to_bytes());
    set(image.as_mut_slice(), OFF_WRITE_CURSOR, 2);
    assert!(matches!(
        vr.drain_image(image.as_slice()),
        Err(IntegrityError::SequenceRegressed {
            expected_at_least: 2,
            found: 0
        })
    ));
    assert!(vr.is_stopped());

    // Sequence が後退した Descriptor を置くと SequenceRegressed で止まる
    // （止まった Reader は再利用できないため、新しい Reader で確認する）
    let mut vr = ValidatingReader::new(known, 7);
    let evs = vr.drain_image(region.as_slice()).unwrap();
    assert_eq!(evs.len(), 1);
    let mut image2 = AlignedImage::copy_of(region.as_slice());
    // slot 1 は正常な後続イベントにする（seq 2、Payload 位置は "one" の終端 3）。
    // そうしないと Reader は slot 1 のゼロ埋め像で UnknownKind になってしまう。
    let mut next = EventDescriptor::new(EventKind::CallEnter, 2);
    next.payload_len = 0;
    next.payload_position = 3;
    let off1 = cfg.descriptors_offset() + 64; // slot 1
    image2[off1..off1 + 64].copy_from_slice(&next.to_bytes());
    let mut back = EventDescriptor::new(EventKind::CallEnter, 1);
    back.payload_len = 0;
    back.payload_position = 3;
    let off2 = cfg.descriptors_offset() + 2 * 64; // slot 2
    image2[off2..off2 + 64].copy_from_slice(&back.to_bytes());
    set(image2.as_mut_slice(), OFF_WRITE_CURSOR, 3);
    assert!(matches!(
        vr.drain_image(image2.as_slice()),
        Err(IntegrityError::SequenceRegressed {
            expected_at_least: 3,
            found: 1
        })
    ));
    assert!(vr.is_stopped());
}

#[test]
fn init_control_writes_meta_and_zeroes_cursors() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 42, 777);
    let base = region.base();
    assert_eq!(ctrl(base, OFF_MAGIC), MAGIC);
    assert_eq!(ctrl(base, OFF_LAYOUT_VERSION), LAYOUT_VERSION);
    assert_eq!(ctrl(base, OFF_DESCRIPTOR_CAPACITY), 8);
    assert_eq!(ctrl(base, OFF_PAYLOAD_CAPACITY), 256);
    assert_eq!(ctrl(base, OFF_GENERATION), 42);
    assert_eq!(ctrl(base, OFF_OWNER_THREAD_ID), 777);
    for off in [
        OFF_WRITE_CURSOR,
        OFF_READ_CURSOR,
        OFF_PAYLOAD_WRITE_POSITION,
        OFF_PAYLOAD_READ_POSITION,
        OFF_DROPPED_EVENTS,
        OFF_DROPPED_PAYLOAD_BYTES,
        OFF_DEGRADED_EVENTS,
        OFF_OVERFLOW_STATE,
        OFF_HOST_WAITING,
        OFF_RING_STOPPED,
        OFF_WRITER_WAITING,
    ] {
        assert_eq!(ctrl(base, off), 0, "offset {off} starts at zero");
    }
}

proptest::proptest! {
    /// The captured fast path must behave exactly like `write` for captured
    /// events: same outcomes (including notification), the same descriptors
    /// apart from timestamps, and the same loss accounting, across full Rings,
    /// wraps, degradation and dropped Enters.
    #[test]
    fn write_captured_matches_write(
        ops in proptest::collection::vec((0u8..4, 0usize..40), 1..120),
        desc in 4usize..10,
        pay in 64usize..160,
    ) {
        let (_ra, mut wa, mut rda, _) = setup(desc, pay, no_wait());
        let (_rb, mut wb, mut rdb, _) = setup(desc, pay, no_wait());
        let bytes = [0xA5u8; 40];
        for (i, (op, len)) in ops.into_iter().enumerate() {
            let call = i as u64 / 2 + 1;
            let kind = match op {
                0 => EventKind::CallEnter,
                1 => EventKind::CallLeave,
                2 => EventKind::CallAborted,
                _ => {
                    let (a, b) = (rda.drain(len % 5), rdb.drain(len % 5));
                    let strip = |e: Vec<ReceivedEvent>| {
                        e.into_iter()
                            .map(|mut e| {
                                e.descriptor.timestamp_qpc = 0;
                                e
                            })
                            .collect::<Vec<_>>()
                    };
                    proptest::prop_assert_eq!(strip(a.events), strip(b.events));
                    continue;
                }
            };
            let payload = &bytes[..len];
            let a = wa.write(input(kind, call, payload));
            let b = wb.write_captured(kind, 10, 20, call, 0, 0, payload);
            proptest::prop_assert_eq!(a, b);
            proptest::prop_assert_eq!(wa.state(), wb.state());
        }
        proptest::prop_assert_eq!(wa.loss_counters(), wb.loss_counters());
    }
}
