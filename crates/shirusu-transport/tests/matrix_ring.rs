//! ring 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - 満杯時の落下会計: Descriptor 容量 x 書き込み超過数で Published/Degraded/Dropped と
//!   Loss カウンタ (dropped_events / dropped_payload_bytes / degraded_events) が一致する。
//! - Payload 容量側の満杯: Descriptor に空きがあれば Payload だけ落とす (Degraded)。
//! - OVERFLOW 復帰: 使用率が resume_threshold 未満になったときだけ Normal に戻る
//!   (ちょうど閾値は戻らない) ことを閾値ごとに確認。
//! - 落とした CallEnter の CallLeave も落とす対応付け。
//! - Sequence 欠番の会計: 落とした件数 k だけ Reader の sequence_gaps に現れる。
//! - Payload 折り返し: 開始位置 x 長さで分割コピーが回転と一致する。
//! - Payload サイズ境界: 容量ちょうど/超過では空でも入らない。
//! - CaptureState ごとの公開形 (格納されない状態は PAYLOAD_DROPPED で公開される)。
//! - 通知シグナル: HostWaiting / 閾値越えの発火点。
//! - drain(max) の件数と Cursor 前進、Timestamp の Clock 由来。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::layout::*;
use shirusu_transport::notify::NotifySignal;
use shirusu_transport::ring::*;
use shirusu_transport::Clock;
use shirusu_transport::RingConfig;
use std::sync::Arc;
use std::time::Duration;

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
fn kind_of(o: &WriteOutcome) -> &'static str {
    match o {
        WriteOutcome::Published { .. } => "published",
        WriteOutcome::PublishedDegraded { .. } => "degraded",
        WriteOutcome::Dropped { .. } => "dropped",
    }
}

// ---------- 満杯時の落下会計 (Descriptor 容量 x 超過数) ----------
macro_rules! fill_case {
    ($name:ident, $cap:expr, $writes:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, rd, _clk) = setup($cap, 4096, no_wait());
            let payload = [7u8; 8];
            let mut outcomes = Vec::new();
            for i in 0..$writes {
                outcomes.push(kind_of(&w.write(input(EventKind::CallEnter, i, &payload))));
            }
            let expect_published = ($writes).min($cap);
            let expect_dropped = $writes - expect_published;
            assert_eq!(
                outcomes.iter().filter(|o| **o == "published").count(),
                expect_published
            );
            // Descriptor が埋まれば Degraded の余地もなく即 Dropped
            assert_eq!(
                outcomes.iter().filter(|o| **o == "dropped").count(),
                expect_dropped
            );
            let loss = rd.loss_counters();
            assert_eq!(loss.dropped_events, expect_dropped as u64);
            assert_eq!(loss.dropped_payload_bytes, expect_dropped as u64 * 8);
            assert_eq!(loss.degraded_events, 0);
            // Sequence は落とした分も払い済み
            assert_eq!(w.next_sequence_peek(), $writes + 1);
        }
    };
}
fill_case!(fill_cap2_w2, 2, 2);
fill_case!(fill_cap2_w3, 2, 3);
fill_case!(fill_cap2_w5, 2, 5);
fill_case!(fill_cap4_w4, 4, 4);
fill_case!(fill_cap4_w6, 4, 6);
fill_case!(fill_cap8_w8, 8, 8);
fill_case!(fill_cap8_w11, 8, 11);

// ---------- Payload 側満杯は Degraded (Descriptor を残す) ----------
#[test]
fn payload_full_degrades_instead_of_dropping() {
    let (_rg, mut w, mut rd, _clk) = setup(8, 16, no_wait());
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 1, &[1u8; 8]))),
        "published"
    );
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 2, &[2u8; 8]))),
        "published"
    );
    // Payload は満杯 (16/16) だが Descriptor には空きがある
    let o = w.write(input(EventKind::CallEnter, 3, &[3u8; 8]));
    assert!(matches!(
        o,
        WriteOutcome::PublishedDegraded {
            reason: CaptureState::DroppedByBackpressure,
            ..
        }
    ));
    let loss = rd.loss_counters();
    assert_eq!(loss.degraded_events, 1);
    assert_eq!(loss.dropped_payload_bytes, 8);
    assert_eq!(loss.dropped_events, 0);
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 3);
    assert_eq!(b.events[2].payload.len(), 0);
    assert!(b.events[2].descriptor.payload_dropped());
    assert_eq!(b.events[2].descriptor.payload_len, 8, "元の長さが残る");
}
#[test]
fn payload_exact_fit_then_one_byte_over_degrades() {
    let (_rg, mut w, _rd, _clk) = setup(8, 16, no_wait());
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 1, &[1u8; 16]))),
        "published"
    );
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 2, &[2u8; 1]))),
        "degraded"
    );
}

// ---------- OVERFLOW 復帰閾値の境界 ----------
fn overflowed_writer(resume: u64) -> (SharedRegion, RingWriter, RingReader, Arc<ManualClock>) {
    let mut policy = no_wait();
    policy.resume_threshold_percent = resume;
    let (rg, mut w, rd, clock) = setup(8, 4096, policy);
    for i in 0..8u64 {
        w.write(input(EventKind::CallEnter, i, b"x"));
    }
    let o = w.write(input(EventKind::CallEnter, 99, b"x"));
    assert_eq!(kind_of(&o), "dropped", "9th write overflows");
    assert_eq!(w.state(), OverflowState::Overflow);
    (rg, w, rd, clock)
}
#[test]
fn resume_at_exact_threshold_stays_overflow() {
    // 使用率 50% (4/8) は「未満」ではないので復帰しない
    let (_rg, mut w, mut rd, _c) = overflowed_writer(50);
    rd.drain(4);
    let o = w.write(input(EventKind::CallEnter, 100, b"y"));
    assert_eq!(kind_of(&o), "degraded", "still overflow: payload dropped");
    assert_eq!(w.state(), OverflowState::Overflow);
    // Degraded 自体も 1 スロット消費する (使用率 62.5%)。2 件回収して
    // 37.5% になれば復帰する
    rd.drain(2);
    let o = w.write(input(EventKind::CallEnter, 101, b"y"));
    assert_eq!(kind_of(&o), "published");
    assert_eq!(w.state(), OverflowState::Normal);
}
#[test]
fn resume_threshold_100_recovers_after_one_drain() {
    let (_rg, mut w, mut rd, _c) = overflowed_writer(100);
    rd.drain(1); // 使用率 87.5% < 100%
    let o = w.write(input(EventKind::CallEnter, 100, b"y"));
    assert_eq!(kind_of(&o), "published");
}
#[test]
fn resume_threshold_25_needs_deep_drain() {
    let (_rg, mut w, mut rd, _c) = overflowed_writer(25);
    rd.drain(6); // 使用率 25% (2/8) は未満でない
    let o = w.write(input(EventKind::CallEnter, 100, b"y"));
    assert_eq!(kind_of(&o), "degraded");
    rd.drain(2); // Degraded の消費分も戻して 12.5%
    let o = w.write(input(EventKind::CallEnter, 101, b"y"));
    assert_eq!(kind_of(&o), "published");
}
#[test]
fn resume_threshold_0_never_recovers() {
    let (_rg, mut w, mut rd, _c) = overflowed_writer(0);
    rd.drain_all(); // 使用率 0% でも 0 未満にはならない
    let o = w.write(input(EventKind::CallEnter, 100, b"y"));
    assert_eq!(kind_of(&o), "degraded", "latched overflow with threshold 0");
    assert_eq!(w.state(), OverflowState::Overflow);
}

// ---------- 落とした Enter の Leave も落とす ----------
#[test]
fn leave_of_dropped_enter_is_dropped_even_with_space() {
    let (_rg, mut w, mut rd, _clk) = setup(2, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    // 満杯で Enter(3) が落ちる
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 3, b"c"))),
        "dropped"
    );
    rd.drain_all(); // 空きを作る
                    // 空きがあっても、落ちた Enter の Leave は落とす
    let o = w.write(input(EventKind::CallLeave, 3, b"c"));
    assert!(matches!(
        o,
        WriteOutcome::Dropped {
            reason: CaptureState::DroppedByBackpressure,
            ..
        }
    ));
    // 落ちていない Enter の Leave は普通に書ける
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallLeave, 1, b"a"))),
        "published"
    );
    // Leave の落下は 1 回だけ (追跡は消費される)。2 回目の Leave(3) は対象が無いので通常処理
    let before = rd.loss_counters().dropped_events;
    let _ = w.write(input(EventKind::CallLeave, 3, b"c"));
    assert_eq!(
        rd.loss_counters().dropped_events,
        before,
        "second leave is not force-dropped"
    );
}
#[test]
fn leave_with_unrelated_call_id_unaffected() {
    let (_rg, mut w, _rd, _clk) = setup(2, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, b"a"));
    w.write(input(EventKind::CallEnter, 2, b"b"));
    assert_eq!(
        kind_of(&w.write(input(EventKind::CallEnter, 3, b"c"))),
        "dropped"
    );
    // Enter が落ちていない call_id の Leave まで巻き込まない (Ring は満杯なので
    // 通常経路でも Degraded/Dropped にはなるが、理由は追跡ベースではない。
    // ここでは空きのある別 Ring で「無関係の Leave が書ける」ことを確認する)
    let (_rg2, mut w2, _rd2, _clk2) = setup(4, 256, no_wait());
    assert_eq!(
        kind_of(&w2.write(input(EventKind::CallLeave, 3, b"c"))),
        "published"
    );
}

// ---------- Sequence 欠番の会計 ----------
macro_rules! gap_case {
    ($name:ident, $drops:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clk) = setup(4, 256, no_wait());
            for i in 0..4u64 {
                w.write(input(EventKind::CallEnter, i, b"x"));
            }
            for j in 0..$drops {
                let o = w.write(input(EventKind::CallEnter, 90 + j, b"x"));
                assert_eq!(kind_of(&o), "dropped");
            }
            let b1 = rd.drain_all();
            assert_eq!(b1.events.len(), 4);
            assert_eq!(b1.sequence_gaps, 0);
            // 回収後は復帰し、次の 1 件が欠番を露わにする
            assert_eq!(
                kind_of(&w.write(input(EventKind::CallEnter, 200, b"x"))),
                "published"
            );
            let b2 = rd.drain_all();
            assert_eq!(b2.events.len(), 1);
            assert_eq!(b2.sequence_gaps, $drops, "gap equals dropped count");
        }
    };
}
gap_case!(gap_of_1, 1);
gap_case!(gap_of_2, 2);
gap_case!(gap_of_3, 3);
gap_case!(gap_of_5, 5);

// ---------- Payload 折り返し: 開始位置 x 長さ ----------
fn patterned(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}
macro_rules! wrap_case {
    ($name:ident, $advance:expr, $len:expr) => {
        // advance=0 は行列の正規の点 (前進なし) なので空 range を許す
        #[allow(clippy::reversed_empty_ranges)]
        #[test]
        fn $name() {
            // Payload 容量 16 の Ring で、まず $advance バイト書いて回収し、
            // 論理位置 $advance から $len バイト書く (容量をまたぐ場合は分割コピー)。
            let (_rg, mut w, mut rd, _clk) = setup(8, 16, no_wait());
            // 位置の前進は 1B ずつの書込み+回収で積む (各回は必ず空になる)
            for _ in 0..$advance {
                let filler = patterned(1, 0xF0);
                assert_eq!(
                    kind_of(&w.write(input(EventKind::CallEnter, 1, &filler))),
                    "published"
                );
                let b = rd.drain_all();
                assert_eq!(b.events[0].payload, filler);
            }
            let data = patterned($len, 0x10);
            let o = w.write(input(EventKind::CallEnter, 2, &data));
            assert_eq!(
                kind_of(&o),
                "published",
                "len {} must fit in empty payload ring",
                $len
            );
            let b = rd.drain_all();
            assert_eq!(b.events.len(), 1);
            assert_eq!(b.events[0].descriptor.payload_position, $advance as u64);
            assert_eq!(b.events[0].payload, data, "wrapped copy must be byte-exact");
        }
    };
}
wrap_case!(wrap_start0_len1, 0, 1);
wrap_case!(wrap_start0_len16, 0, 16);
wrap_case!(wrap_start1_len15, 1, 15);
wrap_case!(wrap_start1_len16, 1, 16);
wrap_case!(wrap_start6_len10, 6, 10);
wrap_case!(wrap_start6_len16, 6, 16);
wrap_case!(wrap_start10_len5, 10, 5);
wrap_case!(wrap_start10_len6, 10, 6);
wrap_case!(wrap_start10_len7, 10, 7);
wrap_case!(wrap_start15_len1, 15, 1);
wrap_case!(wrap_start15_len2, 15, 2);
wrap_case!(wrap_start15_len16, 15, 16);
wrap_case!(wrap_start16_len16, 16, 16);
wrap_case!(wrap_start31_len9, 31, 9);
wrap_case!(wrap_start32_len16, 32, 16);

// ---------- Payload サイズ境界 (容量 64) ----------
macro_rules! size_case {
    ($name:ident, $len:expr, $expect:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clk) = setup(8, 64, no_wait());
            let data = patterned($len, 0x20);
            let o = w.write(input(EventKind::CallEnter, 1, &data));
            assert_eq!(kind_of(&o), $expect, "payload len {}", $len);
            let b = rd.drain_all();
            assert_eq!(b.events.len(), 1);
            if $expect == "published" {
                assert_eq!(b.events[0].payload, data);
            } else {
                assert_eq!(b.events[0].payload.len(), 0);
                assert_eq!(b.events[0].descriptor.payload_len, $len as u32);
                assert!(b.events[0].descriptor.payload_dropped());
            }
        }
    };
}
size_case!(size_0_published, 0, "published");
size_case!(size_1_published, 1, "published");
size_case!(size_63_published, 63, "published");
size_case!(size_64_exact_published, 64, "published");
size_case!(size_65_over_empty_ring_degrades, 65, "degraded");
size_case!(size_128_over_empty_ring_degrades, 128, "degraded");

// ---------- CaptureState ごとの公開形 ----------
macro_rules! state_case {
    ($name:ident, $state:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clk) = setup(8, 256, no_wait());
            let mut inp = input(EventKind::CallEnter, 1, b"value-bytes");
            inp.capture_state = $state;
            let o = w.write(inp);
            // 空きがあるので公開自体はされる (劣化は Descriptor の状態として残る)
            assert_eq!(kind_of(&o), "published");
            let b = rd.drain_all();
            let e = &b.events[0];
            assert_eq!(e.capture_state(), $state);
            assert!(
                e.descriptor.payload_dropped(),
                "non-captured states are not stored"
            );
            assert_eq!(e.payload.len(), 0);
            assert_eq!(e.descriptor.payload_len, 11, "original length retained");
        }
    };
}
state_case!(
    state_memory_unreadable_shape,
    CaptureState::MemoryUnreadable
);
state_case!(
    state_capture_limit_shape,
    CaptureState::CaptureLimitExceeded
);
state_case!(state_truncated_shape, CaptureState::Truncated);
state_case!(state_unsupported_shape, CaptureState::Unsupported);
state_case!(
    state_dropped_by_backpressure_shape,
    CaptureState::DroppedByBackpressure
);

// ---------- 通知シグナル ----------
#[test]
fn notify_host_waiting_flag_produces_signal() {
    let (region, mut w, _rd, _clk) = setup(4, 256, no_wait());
    store(
        region.base(),
        OFF_HOST_WAITING,
        1,
        std::sync::atomic::Ordering::Relaxed,
    );
    match w.write(input(EventKind::CallEnter, 1, b"a")) {
        WriteOutcome::Published { notify, .. } => assert_eq!(notify, NotifySignal::HostWaiting),
        o => panic!("expected published, got {o:?}"),
    }
}
#[test]
fn notify_threshold_crossing_at_half_capacity() {
    let (_rg, mut w, _rd, _clk) = setup(4, 256, no_wait());
    let signals: Vec<NotifySignal> = (0..4)
        .map(|i| match w.write(input(EventKind::CallEnter, i, b"a")) {
            WriteOutcome::Published { notify, .. } => notify,
            o => panic!("expected published, got {o:?}"),
        })
        .collect();
    // 使用率 25% -> 50% (越える) -> 75% -> 100%: 発火は 50% 到達時の一度だけ
    assert_eq!(
        signals,
        vec![
            NotifySignal::None,
            NotifySignal::ThresholdCrossing,
            NotifySignal::None,
            NotifySignal::None
        ]
    );
}
#[test]
fn notify_threshold_100_fires_on_last_slot() {
    let mut policy = no_wait();
    policy.notify_threshold_percent = 100;
    let (_rg, mut w, _rd, _clk) = setup(4, 256, policy);
    let mut last = NotifySignal::None;
    for i in 0..4 {
        if let WriteOutcome::Published { notify, .. } =
            w.write(input(EventKind::CallEnter, i, b"a"))
        {
            last = notify;
        }
    }
    assert_eq!(last, NotifySignal::ThresholdCrossing);
}
#[test]
fn notify_threshold_25_fires_on_first_publish() {
    let mut policy = no_wait();
    policy.notify_threshold_percent = 25;
    let (_rg, mut w, _rd, _clk) = setup(4, 256, policy);
    match w.write(input(EventKind::CallEnter, 1, b"a")) {
        WriteOutcome::Published { notify, .. } => {
            assert_eq!(notify, NotifySignal::ThresholdCrossing)
        }
        o => panic!("expected published, got {o:?}"),
    }
}
#[test]
fn notify_threshold_rearms_after_partial_drain_without_an_intermediate_publish() {
    let (_region, mut writer, mut reader, _clock) = setup(4, 256, no_wait());
    writer.write(input(EventKind::CallEnter, 1, b"a"));
    assert!(matches!(
        writer.write(input(EventKind::CallEnter, 2, b"b")),
        WriteOutcome::Published {
            notify: NotifySignal::ThresholdCrossing,
            ..
        }
    ));
    assert_eq!(reader.drain(1).events.len(), 1);
    // Occupancy moved from 50% down to 25% in the consumer. The producer
    // did not publish an event below the threshold before this next crossing.
    assert!(matches!(
        writer.write(input(EventKind::CallEnter, 3, b"c")),
        WriteOutcome::Published {
            notify: NotifySignal::ThresholdCrossing,
            ..
        }
    ));
    assert!(matches!(
        writer.write(input(EventKind::CallEnter, 4, b"d")),
        WriteOutcome::Published {
            notify: NotifySignal::None,
            ..
        }
    ));
}

#[test]
fn notify_crossing_takes_precedence_over_host_waiting() {
    let (region, mut w, _rd, _clk) = setup(4, 256, no_wait());
    store(
        region.base(),
        OFF_HOST_WAITING,
        1,
        std::sync::atomic::Ordering::Relaxed,
    );
    w.write(input(EventKind::CallEnter, 1, b"a")); // 25%: HostWaiting 側
    match w.write(input(EventKind::CallEnter, 2, b"b")) {
        WriteOutcome::Published { notify, .. } => {
            assert_eq!(notify, NotifySignal::ThresholdCrossing, "crossing wins")
        }
        o => panic!("expected published, got {o:?}"),
    }
}

// ---------- drain(max) の件数と前進 ----------
macro_rules! drain_case {
    ($name:ident, $max:expr, $expect:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clk) = setup(8, 256, no_wait());
            for i in 0..5u64 {
                w.write(input(EventKind::CallEnter, i, &[i as u8; 2]));
            }
            let b = rd.drain($max);
            assert_eq!(b.events.len(), $expect);
            assert_eq!(rd.read_cursor(), $expect as u64);
            let rest = rd.drain_all();
            assert_eq!(rest.events.len(), 5 - $expect);
            // 通しで読んでも Sequence は 1..=5 の順
            let seqs: Vec<u64> = b
                .events
                .iter()
                .chain(rest.events.iter())
                .map(|e| e.descriptor.sequence)
                .collect();
            assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        }
    };
}
drain_case!(drain_max0, 0, 0);
drain_case!(drain_max1, 1, 1);
drain_case!(drain_max3, 3, 3);
drain_case!(drain_max5, 5, 5);
drain_case!(drain_max6_over, 6, 5);

// ---------- Timestamp は時刻源 (TimestampSource) 由来 ----------
// レビュー第2回・項目8 で責務分離する前は待機用 Clock 由来だった。
// 現在は刻印専用の TimestampSource から取るため、このケース群は
// ManualTimestampSource を差し替えて値を固定する形に追随させた。
macro_rules! ts_case {
    ($name:ident, $ticks:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clock) = setup(8, 256, no_wait());
            w.set_timestamp_source(Arc::new(shirusu_transport::ManualTimestampSource::new(
                $ticks,
                1_000_000_000,
            )));
            w.write(input(EventKind::CallEnter, 1, b"a"));
            let b = rd.drain_all();
            assert_eq!(b.events[0].descriptor.timestamp_qpc, $ticks);
        }
    };
}
ts_case!(ts_zero, 0);
ts_case!(ts_one, 1);
ts_case!(ts_large, 123_456_789);

// ---------- 複数サイクルの折り返し再利用 ----------
macro_rules! cycle_case {
    ($name:ident, $cap:expr) => {
        #[test]
        fn $name() {
            let (_rg, mut w, mut rd, _clk) = setup($cap, 256, no_wait());
            let mut expect_seq = 1u64;
            for cycle in 0..3u8 {
                for i in 0..$cap {
                    let o = w.write(input(EventKind::CallEnter, i as u64, &[cycle; 3]));
                    assert_eq!(kind_of(&o), "published", "cycle {cycle} slot {i}");
                }
                let b = rd.drain_all();
                assert_eq!(b.events.len(), $cap);
                for e in &b.events {
                    assert_eq!(e.descriptor.sequence, expect_seq);
                    assert_eq!(e.payload, vec![cycle; 3]);
                    expect_seq += 1;
                }
            }
        }
    };
}
cycle_case!(cycles_cap2, 2);
cycle_case!(cycles_cap3, 3);
cycle_case!(cycles_cap5, 5);

// ---------- 格納位置の累積 (落とした件は位置を共有) ----------
#[test]
fn positions_accumulate_over_stored_lengths_only() {
    let (_rg, mut w, mut rd, _clk) = setup(8, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, &[0u8; 3]));
    let mut dropped = input(EventKind::CallEnter, 2, &[0u8; 100]);
    dropped.capture_state = CaptureState::MemoryUnreadable;
    w.write(dropped);
    w.write(input(EventKind::CallEnter, 3, &[0u8; 5]));
    w.write(input(EventKind::CallEnter, 4, &[0u8; 1]));
    let b = rd.drain_all();
    let positions: Vec<u64> = b
        .events
        .iter()
        .map(|e| e.descriptor.payload_position)
        .collect();
    assert_eq!(positions, vec![0, 3, 3, 8]);
}

// ---------- Ring 使用量の観測 (L10: バッファ使用率) ----------
#[test]
fn reader_reports_descriptor_and_payload_usage() {
    let (_rg, mut w, r, _clk) = setup(8, 256, no_wait());
    assert_eq!(r.descriptor_used(), 0);
    assert_eq!(r.payload_used(), 0);
    w.write(input(EventKind::CallEnter, 1, &[0u8; 3]));
    w.write(input(EventKind::CallEnter, 2, &[0u8; 5]));
    assert_eq!(r.descriptor_used(), 2);
    assert_eq!(r.payload_used(), 8);
}

#[test]
fn reader_usage_drops_after_drain() {
    let (_rg, mut w, mut r, _clk) = setup(8, 256, no_wait());
    w.write(input(EventKind::CallEnter, 1, &[0u8; 3]));
    w.write(input(EventKind::CallEnter, 2, &[0u8; 5]));
    assert_eq!(r.descriptor_used(), 2);
    let b = r.drain_all();
    assert_eq!(b.events.len(), 2);
    assert_eq!(r.descriptor_used(), 0);
    assert_eq!(r.payload_used(), 0);
}
