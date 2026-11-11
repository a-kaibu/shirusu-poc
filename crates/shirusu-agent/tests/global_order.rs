//! L11 `--order=global`: 観測点で全スレッド共通の番号を振る。
//!
//! - 無効な間は Descriptor の `global_order` は 0 のまま。
//! - 有効にすると `Agent::record` が書き込み確定の直前にアトミック
//!   カウンタから採番し、1 始まりで単調に増える。
//! - スキップされた呼出（Agent 内部・Host 停止・Slot 無し）は番号を消費しない。

use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::context::{CallOrigin, HostMonitor};
use shirusu_transport::descriptor::CaptureState;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{EventInput, RingReader, WriteOutcome};
use shirusu_transport::slot::SlotPool;
use shirusu_transport::EventKind;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

fn agent(order_global: bool) -> Agent {
    let mut a = Agent::new(
        Arc::new(SlotPool::new(8)),
        RingConfig::new(64, 4096),
        Arc::new(HostMonitor::always_alive()),
    )
    .with_policy(shirusu_transport::WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    });
    if order_global {
        a = a.with_order_global(true);
    }
    a
}

fn enter(a: &Agent, thread_id: u64, call_id: u64) {
    assert!(matches!(
        a.record_enter(thread_id, 1, 2, call_id, 0, b"x"),
        RecordResult::Written(WriteOutcome::Published { .. })
    ));
}

fn drain_orders(a: &Agent, thread_id: u64, allow: bool) -> Vec<u64> {
    let base = unsafe { a.thread_region_base(thread_id) }.expect("region base");
    let mut reader =
        unsafe { RingReader::new(base, RingConfig::new(64, 4096)) }.with_global_order(allow);
    reader
        .drain_all()
        .events
        .iter()
        .map(|e| e.descriptor.global_order)
        .collect()
}

#[test]
fn global_order_disabled_by_default() {
    let a = agent(false);
    enter(&a, 1, 1);
    enter(&a, 1, 2);
    enter(&a, 2, 3);
    assert_eq!(drain_orders(&a, 1, false), vec![0, 0]);
    assert_eq!(drain_orders(&a, 2, false), vec![0]);
}

#[test]
fn global_order_stamped_in_observation_order() {
    let a = agent(true);
    enter(&a, 1, 1);
    enter(&a, 1, 2);
    enter(&a, 1, 3);
    enter(&a, 2, 4);
    enter(&a, 2, 5);
    // スレッド内では記録順に 1 ずつ増え、スレッド間では採番順に続く。
    assert_eq!(drain_orders(&a, 1, true), vec![1, 2, 3]);
    assert_eq!(drain_orders(&a, 2, true), vec![4, 5]);
}

#[test]
fn global_order_unique_across_threads() {
    let a = Arc::new(agent(true));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let a = Arc::clone(&a);
        handles.push(std::thread::spawn(move || {
            for i in 0..25u64 {
                enter(&a, 100 + t, 1000 + t * 100 + i);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let mut all = HashSet::new();
    for t in 0..4u64 {
        for g in drain_orders(&a, 100 + t, true) {
            assert!((1..=100).contains(&g), "global_order {g} out of range");
            assert!(all.insert(g), "duplicate global_order {g}");
        }
    }
    assert_eq!(all.len(), 100);
}

#[test]
fn skipped_events_do_not_consume_numbers() {
    let a = agent(true);
    // Agent 内部の呼出は記録せず、番号も消費しない。
    assert_eq!(
        a.record(
            1,
            CallOrigin::AgentInternal,
            EventInput {
                kind: EventKind::CallEnter,
                api_id: 1,
                schema_id: 2,
                call_id: 9,
                parent_call_id: 0,
                payload: b"x",
                capture_state: CaptureState::Captured,
                global_order: 0,
            },
        ),
        RecordResult::SkippedAgentInternal
    );
    enter(&a, 1, 1);
    assert_eq!(drain_orders(&a, 1, true), vec![1]);
}

#[test]
fn reader_rejects_stamped_descriptors_when_disabled() {
    // Host 側の検証がセッション設定と一致すること: 採番済み像を
    // 無効な設定で読むと GlobalOrderNotAllowed で Ring が止まる。
    let a = agent(true);
    enter(&a, 1, 1);
    let base = unsafe { a.thread_region_base(1) }.expect("region base");
    let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
    let batch = reader.drain_all();
    assert!(batch.integrity_error.is_some());
    assert_eq!(batch.events.len(), 0);
}
