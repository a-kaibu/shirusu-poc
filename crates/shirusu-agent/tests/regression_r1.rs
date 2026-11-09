//! R1 回帰 (レビュー指摘): Agent::record が threads の全体 Mutex を
//! RingWriter::write の間保持していたため、満杯 Ring の BOUNDED_WAIT
//! (最大で policy.max_wait) が他スレッドの記録まで直列化していた。
//! thread_detach も同じ Mutex を共有していた。
//!
//! このテストは、スレッド 1 の Ring を満杯にして別スレッドに BOUNDED_WAIT
//! へ入らせ、その間に空の Ring を持つスレッド 2 の記録が即座に返ることを
//! 確認する。修正前は全体 Mutex のためスレッド 2 の記録が待機の終わり
//! (800ms) までブロックされ、このテストは失敗した。

use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn full_ring_wait_does_not_block_other_threads() {
    let pool = Arc::new(SlotPool::new(4));
    let agent = Arc::new(
        Agent::new(
            pool,
            RingConfig::new(2, 64),
            Arc::new(HostMonitor::always_alive()),
        )
        .with_policy(WriterPolicy {
            max_wait: Duration::from_millis(800),
            ..Default::default()
        }),
    );
    // スレッド 1 の Ring (Descriptor 容量 2) を埋める。
    assert!(matches!(
        agent.record_enter(1, 1, 1, 1, 0, b"a"),
        RecordResult::Written(_)
    ));
    assert!(matches!(
        agent.record_enter(1, 1, 1, 2, 0, b"b"),
        RecordResult::Written(_)
    ));
    let base = unsafe { agent.thread_region_base(1) }.expect("region base");
    // 別スレッドが満杯 Ring へ記録し、BOUNDED_WAIT (最大 800ms) に入る。
    let a2 = Arc::clone(&agent);
    let waiter = std::thread::spawn(move || {
        a2.record_enter(1, 1, 1, 3, 0, b"c");
    });
    // writer_waiting フラグが立つまで待つ (待機区間に入ったことの同期)。
    let deadline = Instant::now() + Duration::from_secs(5);
    while !shirusu_transport::layout::writer_waiting(base as *const u8) {
        assert!(
            Instant::now() < deadline,
            "writer never entered bounded wait"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // その間に、空の Ring を持つスレッド 2 の記録は即座に返らなければならない。
    let start = Instant::now();
    let r = agent.record_enter(2, 1, 1, 1, 0, b"x");
    let elapsed = start.elapsed();
    assert!(matches!(r, RecordResult::Written(_)));
    assert!(
        elapsed < Duration::from_millis(200),
        "record for another thread blocked {elapsed:?} behind a full ring's bounded wait"
    );
    waiter.join().unwrap();
}
