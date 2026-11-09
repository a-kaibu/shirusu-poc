//! R7 回帰 (レビュー指摘): space_available は仕様上 Ring 単位だが、Agent は
//! Clock と通知を全体で 1 つ共有しており、全 Ring の書き手が単一の
//! EventClock (単一の auto-reset Event) で待っていた。複数書き手が同じ
//! auto-reset Event を待つと、ある Ring への通知を別の Ring の書き手が
//! 消費して起床対象がずれる。
//!
//! 修正後は Ring ごとに RingNotify と EventClock を結びつける。旧 API は
//! 「Ring ごとの結線」自体を表現できなかったため、このテストは新 API の
//! 結線そのものを検証する: 各 Ring の書き手が自分の Clock でだけ待ち、
//! 他 Ring の Clock は一切使われないこと。

use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use shirusu_transport_win::RingNotify;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn agent() -> Arc<Agent> {
    Arc::new(
        Agent::new(
            Arc::new(SlotPool::new(4)),
            RingConfig::new(2, 64),
            Arc::new(HostMonitor::always_alive()),
        )
        .with_policy(WriterPolicy {
            max_wait: Duration::from_millis(400),
            ..Default::default()
        }),
    )
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn each_ring_waits_on_its_own_event_clock() {
    let a = agent();
    let n1 = Arc::new(RingNotify::new().unwrap());
    let n2 = Arc::new(RingNotify::new().unwrap());
    let c1 = a.attach_space_available_notify(1, n1).unwrap();
    let c2 = a.attach_space_available_notify(2, n2).unwrap();
    assert!(!Arc::ptr_eq(&c1, &c2), "each ring gets its own EventClock");
    // スレッド 1 の Ring (Descriptor 容量 2) を埋める。
    a.record_enter(1, 1, 1, 1, 0, b"a");
    a.record_enter(1, 1, 1, 2, 0, b"b");
    let base = unsafe { a.thread_region_base(1) }.expect("region base");
    // 別 OS スレッドから満杯 Ring へ書くと、その Ring の EventClock で待つ。
    let aw = Arc::clone(&a);
    let waiter = std::thread::spawn(move || aw.record_enter(1, 1, 1, 3, 0, b"c"));
    wait_until("writer_waiting flag", || {
        shirusu_transport::layout::writer_waiting(base as *const u8)
    });
    wait_until("ring 1 clock sleeping", || c1.sleep_calls() > 0);
    assert_eq!(
        c2.sleep_calls(),
        0,
        "ring 2's clock must not be used by ring 1's writer"
    );
    // スレッド 2 は影響なく即座に書ける。
    assert!(matches!(
        a.record_enter(2, 1, 1, 1, 0, b"x"),
        RecordResult::Written(_)
    ));
    waiter.join().unwrap();
}

#[test]
fn attach_after_begin_binds_that_ring_only() {
    let a = agent();
    assert!(a.thread_begin(1).is_some());
    assert!(a.thread_begin(2).is_some());
    // 書き始めた後でも、その Ring の書き手の Clock だけを差し替えられる。
    let n1 = Arc::new(RingNotify::new().unwrap());
    let c1 = a.attach_space_available_notify(1, n1).unwrap();
    assert!(a.space_available_attached(1));
    assert!(!a.space_available_attached(2));
    a.record_enter(1, 1, 1, 1, 0, b"a");
    a.record_enter(1, 1, 1, 2, 0, b"b");
    let aw = Arc::clone(&a);
    let waiter = std::thread::spawn(move || aw.record_enter(1, 1, 1, 3, 0, b"c"));
    wait_until("ring 1 clock sleeping after swap", || c1.sleep_calls() > 0);
    waiter.join().unwrap();
}
