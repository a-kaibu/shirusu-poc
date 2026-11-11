//! レビュー第2回・項目8 の回帰: Clock の責務分離。
//!
//! 待機時間の実測に使う `Clock` (差し替え可能・原点はインスタンス相対) と、
//! Descriptor の `timestamp_qpc` を刻むイベント時刻源 `TimestampSource`
//! (プロセス間で比較可能な時刻系) を分ける。Clock を差し替えても、
//! また時刻源のインスタンスを作り直しても、刻印の原点は動かない。

use std::sync::Arc;
use std::time::Duration;

use shirusu_transport::clock::{
    ManualClock, ManualTimestampSource, SystemTimestampSource, TimestampSource,
};
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventKind};

fn input(call: u64, payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 10,
        schema_id: 20,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}

#[test]
fn default_source_origin_is_shared_across_instances() {
    // 原点はプロセス全体で 1 つ。後から作ったインスタンスでも時刻は
    // 遡らない (インスタンスごとの原点だった SystemClock の欠陥の回帰)。
    let a = SystemTimestampSource::new();
    let t1 = a.now_qpc();
    std::thread::sleep(Duration::from_millis(2));
    let b = SystemTimestampSource::new();
    let t2 = b.now_qpc();
    assert!(
        t2 >= t1 + 1_000_000,
        "origin must be process-global: t1={t1} t2={t2}"
    );
}

#[test]
fn default_source_is_monotonic_and_frequency_consistent() {
    let a = SystemTimestampSource::new();
    let b = SystemTimestampSource::new();
    assert_eq!(a.frequency(), 1_000_000_000);
    assert_eq!(a.frequency(), b.frequency(), "周波数はインスタンス不変");
    let mut prev = a.now_qpc();
    for _ in 0..100 {
        let now = a.now_qpc();
        assert!(now >= prev, "単調性: {now} < {prev}");
        prev = now;
    }
}

#[test]
fn stamps_do_not_come_from_wait_clock() {
    // 旧 API のみで書ける行動回帰: 待機用 Clock を ManualClock に差し替えて
    // 大きな値を設定しても、刻印はその値にならない (旧実装では刻印が
    // Clock 由来で、この表明が失敗した)。
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 100);
    let clock = Arc::new(ManualClock::new());
    clock.set(777_000_000);
    let mut w = unsafe { region.writer(WriterPolicy::default(), clock as Arc<dyn Clock>) };
    let mut rd = unsafe { region.reader() };
    w.write(input(1, b"x"));
    w.write(input(2, b"y"));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 2);
    for e in &b.events {
        assert_ne!(e.descriptor.timestamp_qpc, 777_000_000);
    }
    assert!(b.events[1].descriptor.timestamp_qpc >= b.events[0].descriptor.timestamp_qpc);
}

#[test]
fn writer_stamps_track_timestamp_source_not_clock_swaps() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 100);
    let ts = Arc::new(ManualTimestampSource::new(424_242, 10_000_000));
    let clock = Arc::new(ManualClock::new());
    clock.set(111);
    let mut w = unsafe {
        region.writer_with_timestamps(
            WriterPolicy::default(),
            clock as Arc<dyn Clock>,
            ts.clone() as Arc<dyn TimestampSource>,
        )
    };
    let mut rd = unsafe { region.reader() };
    w.write(input(1, b"a"));
    // 待機用 Clock を差し替えても (R7 の EventClock 化に相当) 刻印は不変。
    let other = Arc::new(ManualClock::new());
    other.set(999_999_999);
    w.set_clock(other as Arc<dyn Clock>);
    w.write(input(2, b"b"));
    // 時刻源を進めれば刻印だけが追随する。
    ts.advance(10);
    w.write(input(3, b"c"));
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 3);
    assert_eq!(b.events[0].descriptor.timestamp_qpc, 424_242);
    assert_eq!(b.events[1].descriptor.timestamp_qpc, 424_242);
    assert_eq!(b.events[2].descriptor.timestamp_qpc, 424_252);
    assert_eq!(w.timestamp_frequency(), 10_000_000);
}
