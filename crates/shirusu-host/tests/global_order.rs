//! L11 `--order=global` の Host 側 E2E:
//! Agent（採番あり）→ CaptureSession（設定あり）→ Trace まで通し、
//! 全体順序番号が TraceEvent に残ることと、設定の不一致が
//! 検証で弾かれることを確かめる。

use shirusu_agent::{Agent, RecordResult};
use shirusu_host::recorder::{CaptureSession, CaptureSessionConfig, RingSpec};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const SESSION: u64 = 4242;
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_trace(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "shirusu-global-order-{tag}-{}-{n}.trace",
        std::process::id()
    ))
}

fn config(order_global: bool) -> CaptureSessionConfig {
    CaptureSessionConfig {
        session_id: SESSION,
        ring_config: RingConfig::new(64, 4096),
        environment: CaptureEnvironment {
            session: SessionMetadata {
                session_id: SESSION,
                created_by: "shirusu-host test (global-order)".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        },
        qpc_frequency: 10_000_000,
        durability: shirusu_trace::writer::Durability::Buffered,
        order_global,
        // L07: Runtime 独自の API は既定で記録しない。
        record_runtime_apis: false,
        diagnostic_query_interface: false,
        // L09: 既定は `full`（間引きなし）。
        record_mode: shirusu_host::trace_convert::RecordMode::Full,
    }
}

fn agent_and_region(tid: u64, order_global: bool) -> (Arc<Agent>, u64, *mut u8) {
    let cfg = RingConfig::new(64, 4096);
    let pool = Arc::new(SlotPool::new(4));
    let agent = Arc::new(
        Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive()))
            .with_policy(WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            })
            .with_order_global(order_global),
    );
    let handle = agent.thread_begin(tid).expect("slot");
    let base = unsafe { agent.thread_region_base(tid) }.expect("region");
    (agent, handle.generation, base)
}

fn spec(generation: u64, thread_id: u64) -> RingSpec {
    RingSpec {
        process_id: 1,
        raw_pid: 1234,
        thread_id,
        expected_generation: generation,
    }
}

fn record(agent: &Agent, tid: u64, call_id: u64) {
    assert!(matches!(
        agent.record_enter(tid, 1, 2, call_id, 0, b"x"),
        RecordResult::Written(_)
    ));
}

#[test]
fn global_order_flows_agent_to_trace() {
    let path = temp_trace("flow");
    let (agent, gen1, base1) = agent_and_region(11, true);
    let handle2 = agent.thread_begin(12).expect("slot 12");
    let base2 = unsafe { agent.thread_region_base(12) }.expect("region 12");

    let mut session = CaptureSession::create_file(&path, config(true)).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base1,
                RingConfig::new(64, 4096).required_len(),
                spec(gen1, 11),
            )
            .unwrap();
        session
            .add_borrowed_ring(
                base2,
                RingConfig::new(64, 4096).required_len(),
                spec(handle2.generation, 12),
            )
            .unwrap();
    }
    session.start().unwrap();
    record(&agent, 11, 1);
    record(&agent, 11, 2);
    record(&agent, 12, 3);
    record(&agent, 11, 4);
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 4);
    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 4);

    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.batches.len(), 2);
    let mut all: Vec<u64> = Vec::new();
    for b in &trace.batches {
        let orders: Vec<u64> = b
            .events
            .iter()
            .map(|e| e.global_order.expect("global order present"))
            .collect();
        // Batch 内では厳密に増加する。
        assert!(orders.windows(2).all(|w| w[0] < w[1]));
        all.extend(orders);
    }
    // 2 スレッド合わせて 1..=4 が重複なく揃う。
    all.sort_unstable();
    assert_eq!(all, vec![1, 2, 3, 4]);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn global_order_disabled_session_rejects_stamped_descriptors() {
    let path = temp_trace("mismatch");
    let (agent, gen1, base1) = agent_and_region(11, true);
    let mut session = CaptureSession::create_file(&path, config(false)).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base1,
                RingConfig::new(64, 4096).required_len(),
                spec(gen1, 11),
            )
            .unwrap();
    }
    session.start().unwrap();
    record(&agent, 11, 1);
    // Collection only copies; validation on the Trace worker rejects the
    // stamped descriptors, stops the Ring and accepts no event.
    let _ = session.poll_once().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 0);
    assert_eq!(summary.rings_stopped, 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn global_order_absent_when_disabled_everywhere() {
    let path = temp_trace("off");
    let (agent, gen1, base1) = agent_and_region(11, false);
    let mut session = CaptureSession::create_file(&path, config(false)).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base1,
                RingConfig::new(64, 4096).required_len(),
                spec(gen1, 11),
            )
            .unwrap();
    }
    session.start().unwrap();
    record(&agent, 11, 1);
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 1);
    let _ = session.stop().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.batches[0]
        .events
        .iter()
        .all(|e| e.global_order.is_none()));
    let _ = std::fs::remove_file(&path);
}
