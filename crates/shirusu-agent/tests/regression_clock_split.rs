//! レビュー第2回・項目8 の回帰 (Agent 経路): イベント時刻の刻印は
//! 待機用 Clock ではなく、専用の `TimestampSource` から取る。
//! Agent の待機用 Clock を ManualClock に差し替えて大きな値を設定しても、
//! Descriptor の `timestamp_qpc` は時刻源の値を刻む。

use std::sync::Arc;

use shirusu_agent::Agent;
use shirusu_transport::clock::{Clock, ManualClock, ManualTimestampSource, TimestampSource};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::RingReader;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;

#[test]
fn agent_stamps_come_from_timestamp_source_not_wait_clock() {
    let cfg = RingConfig::new(8, 256);
    let manual_clock = Arc::new(ManualClock::new());
    manual_clock.set(777_000_000);
    let ts = Arc::new(ManualTimestampSource::new(424_242, 10_000_000));
    let a = Agent::new(
        Arc::new(SlotPool::new(2)),
        cfg,
        Arc::new(HostMonitor::always_alive()),
    )
    .with_clock(manual_clock as Arc<dyn Clock>)
    .with_timestamp_source(ts.clone() as Arc<dyn TimestampSource>);

    a.record_enter(1, 1, 1, 1, 0, b"x");
    ts.advance(5);
    a.record_enter(1, 1, 1, 2, 0, b"y");

    let base = unsafe { a.thread_region_base(1) }.expect("region base");
    let mut rd = unsafe { RingReader::new(base, cfg) };
    let b = rd.drain_all();
    assert_eq!(b.integrity_error, None);
    assert_eq!(b.events.len(), 2);
    assert_eq!(b.events[0].descriptor.timestamp_qpc, 424_242);
    assert_eq!(b.events[1].descriptor.timestamp_qpc, 424_247);
}
