//! A70 E2E: Agent → Host → Agent の往復で実際に Slot が増え、新規スレッドが
//! Host の Mapping の Ring で記録でき、検証付き Host が回収できること。
//! 追加中に Host が止まっても、既存 Ring での記録が続くこと (C11)。
//!
//! 既存の c11 テスト (spec_table.rs) は「Host が止まっても既存 Ring で記録
//! 継続」だけを確認しており、実際の非同期拡張フローは扱わない。ここでは
//! 実際の管理スレッドと ExpansionService を回して往復させる。

use shirusu_agent::{Agent, RecordResult};
use shirusu_host::expansion::ExpansionService;
use shirusu_host::{DrainWorker, ProcessInstanceId, RingId, RingIdentity};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn make_agent(pool: Arc<SlotPool>, cfg: RingConfig) -> Arc<Agent> {
    Arc::new(
        Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive())).with_policy(WriterPolicy {
            max_wait: Duration::ZERO,
            ..Default::default()
        }),
    )
}

fn wait_capacity(pool: &SlotPool, want: usize, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while pool.capacity() < want {
        assert!(
            Instant::now() < deadline,
            "{label}: capacity stayed {} (want {want})",
            pool.capacity()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn agent_to_host_round_trip_expands_slot_and_new_thread_records() {
    let cfg = RingConfig::new(16, 512);
    let pool = Arc::new(SlotPool::with_low_watermark(3, 2));
    let agent = make_agent(Arc::clone(&pool), cfg);
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, del_rx) = mpsc::channel();
    let manager = Agent::spawn_expansion_manager(Arc::clone(&agent), req_tx, del_rx);
    let service = ExpansionService::new(req_rx, Box::new(del_tx), cfg);
    let service_stop = Arc::new(AtomicBool::new(false));
    let service_handle = service.spawn(Arc::clone(&service_stop));

    // 初期 Slot を使い切ると低水位を踏み、往復で Slot が増える。
    assert!(agent.thread_begin(1).is_some());
    assert!(agent.thread_begin(2).is_some());
    assert!(agent.thread_begin(3).is_some());
    wait_capacity(&pool, 4, "expansion round trip");
    // 新規スレッドは追加 Slot (generation 0) を取り、Host の Mapping の Ring で記録する。
    let h4 = agent.thread_begin(4).unwrap();
    assert_eq!(h4.index, 3);
    assert_eq!(h4.generation, 0);
    for i in 0..3u64 {
        assert!(matches!(
            agent.record_enter(4, 10, 20, i, 0, b"payload"),
            RecordResult::Written(_)
        ));
    }
    // 既存スレッドの記録も続く。
    assert!(matches!(
        agent.record_enter(1, 10, 20, 100, 0, b"old-ring"),
        RecordResult::Written(_)
    ));
    assert!(matches!(
        agent.record_enter(2, 10, 20, 101, 0, b"old-ring"),
        RecordResult::Written(_)
    ));
    assert!(matches!(
        agent.record_enter(3, 10, 20, 102, 0, b"old-ring"),
        RecordResult::Written(_)
    ));

    // 検証付き Host が追加 Ring を回収する (generation 0 を期待値とする)。
    // A72 の一時キーも generation 0 で生成される。
    let base4 = unsafe { agent.thread_region_base(4) }.expect("expanded region base");
    let mut worker4 = unsafe { DrainWorker::new(base4, cfg, 0) };
    worker4.set_identity(RingIdentity::new(ProcessInstanceId(1), RingId(4), 0));
    let batch = worker4.drain_all();
    assert_eq!(batch.events.len(), 3);
    assert_eq!(batch.sequence_gaps, 0);
    assert!(!worker4.integrity_lost);
    assert_eq!(worker4.total_events, 3);
    assert_eq!(worker4.payload_keys.len(), 3);
    assert!(worker4
        .payload_keys
        .iter()
        .all(|k| k.generation == 0 && k.ring_id == RingId(4)));
    assert_eq!(worker4.payload_keys[0].sequence, 1);
    // 既存 Ring も検証付きで回収できる。
    for (tid, call) in [(1u64, 100u64), (2, 101), (3, 102)] {
        let base = unsafe { agent.thread_region_base(tid) }.expect("region base");
        let handle_gen = agent.thread_begin(tid).unwrap().generation;
        let mut worker = unsafe { DrainWorker::new(base, cfg, handle_gen) };
        let batch = worker.drain_all();
        assert_eq!(batch.events.len(), 1, "ring {tid}");
        assert_eq!(batch.events[0].descriptor.call_id, call);
        assert!(!worker.integrity_lost);
    }

    let manager_stats = manager.stop();
    let service = service_handle.stop();
    assert!(manager_stats.requested >= 1, "{manager_stats:?}");
    assert!(manager_stats.registered >= 1, "{manager_stats:?}");
    assert!(service.created >= 1);
    assert!(pool.capacity() >= 4);
    let _ = service_stop.load(Ordering::Relaxed);
}

#[test]
fn host_stop_during_expansion_existing_rings_continue() {
    // 追加中に Host が止まる (サービスを起動せず、配送口を落とす):
    // 管理スレッドは要求を破棄し、既存 Ring での記録は続く。
    let cfg = RingConfig::new(16, 512);
    let pool = Arc::new(SlotPool::with_low_watermark(3, 2));
    let agent = make_agent(Arc::clone(&pool), cfg);
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, del_rx) = mpsc::channel();
    let manager = Agent::spawn_expansion_manager(Arc::clone(&agent), req_tx, del_rx);
    // サービスは起動しない (Host 役はいない)。要求が届いたら配送口を落とす。
    assert!(agent.thread_begin(1).is_some());
    assert!(agent.thread_begin(2).is_some());
    assert!(agent.thread_begin(3).is_some());
    let req = req_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("manager must send a request");
    assert_eq!(req.slots, 1);
    drop(del_tx); // Host が追加中に止まる。
                  // 管理スレッドが切断に気づくまで少し待つ (ポーリング 5ms)。
    std::thread::sleep(Duration::from_millis(100));
    // 既存 Ring での記録は一切止めない。
    for i in 0..5u64 {
        assert!(matches!(
            agent.record_enter(1, 10, 20, i, 0, b"still-going"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            agent.record_enter(2, 10, 20, i, 0, b"still-going"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            agent.record_enter(3, 10, 20, i, 0, b"still-going"),
            RecordResult::Written(_)
        ));
    }
    // 既存 Ring は検証付きで回収できる。
    for tid in [1u64, 2, 3] {
        let base = unsafe { agent.thread_region_base(tid) }.expect("region base");
        let handle_gen = agent.thread_begin(tid).unwrap().generation;
        let mut worker = unsafe { DrainWorker::new(base, cfg, handle_gen) };
        let batch = worker.drain_all();
        assert_eq!(batch.events.len(), 5, "ring {tid}");
        assert!(!worker.integrity_lost);
    }
    let stats = manager.stop();
    assert_eq!(stats.requested, 1, "{stats:?}");
    assert_eq!(stats.discarded_host_stopped, 1, "{stats:?}");
    assert_eq!(stats.registered, 0, "{stats:?}");
    assert_eq!(pool.capacity(), 3, "no slot was registered");
}
