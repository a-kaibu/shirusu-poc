//! E2E 統合 (レビュー指摘の E2E 追加分): 実 `Agent::record` → 複数 Ring →
//! 独立した検証付き Host (DrainWorker) の通し経路。
//!
//! 従来の検証は RingWriter + 無検証 RingReader の直接経路か、単一 Ring の
//! Host 経路に限られ、「複数スレッドが実 Agent 経由で書き、独立した Host
//! が検証しながら複数 Ring を回収する」形が無かった。ここでは OS スレッド
//! 複数が 1 つの Agent へ記録し、Host 側はスレッドとは独立に全 Ring を
//! 検証付きで回収して、件数・対応付け・A72 の一時キーが全 Ring で閉じる
//! ことを確認する。Windows の別プロセス E2E は e2e クレートと CI が担い、
//! これは同一プロセスで Linux でも回る統合テストである。

use shirusu_agent::{Agent, RecordResult};
use shirusu_host::{DrainWorker, ProcessInstanceId, RingId, RingIdentity};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_agent(pool_size: usize, cfg: RingConfig) -> Arc<Agent> {
    Arc::new(
        Agent::new(
            Arc::new(SlotPool::new(pool_size)),
            cfg,
            Arc::new(HostMonitor::always_alive()),
        )
        .with_policy(WriterPolicy {
            max_wait: Duration::ZERO,
            ..Default::default()
        }),
    )
}

#[test]
fn agent_multi_thread_to_validating_host_all_events_accounted() {
    // 8 スレッド x (Enter/Leave 500 組) = 8000 イベント。全 Ring を検証付き
    // Host が回収し、対応付けと一時キーが Ring ごとに閉じること。
    let cfg = RingConfig::new(1024, 65536);
    let agent = make_agent(8, cfg);
    let threads = 8u64;
    let pairs = 500u64;
    // 先に全 Ring を作り、Host 側の Worker を用意する (Host は記録側と独立)。
    let mut workers = Vec::new();
    for tid in 1..=threads {
        let handle = agent.thread_begin(tid).expect("slot for thread");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region base");
        let mut worker = unsafe { DrainWorker::new(base, cfg, handle.generation) };
        worker.set_identity(RingIdentity::new(
            ProcessInstanceId(1),
            RingId(tid),
            handle.generation,
        ));
        workers.push(worker);
    }
    let mut hs = Vec::new();
    for tid in 1..=threads {
        let a = Arc::clone(&agent);
        hs.push(std::thread::spawn(move || {
            for i in 0..pairs {
                assert!(matches!(
                    a.record_enter(tid, 10, 20, i, 0, b"payload"),
                    RecordResult::Written(_)
                ));
                assert!(matches!(
                    a.record_leave(tid, 10, 20, i, 0, b"payload"),
                    RecordResult::Written(_)
                ));
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    let mut total = 0u64;
    for (i, w) in workers.iter_mut().enumerate() {
        let batch = w.drain_all();
        assert_eq!(batch.events.len() as u64, pairs * 2, "ring {}", i + 1);
        assert_eq!(batch.sequence_gaps, 0);
        assert!(!w.integrity_lost);
        assert_eq!(w.total_events, pairs * 2);
        assert_eq!(w.open_call_count(), 0, "all enter/leave pairs closed");
        assert!(w.finalize_thread().is_empty());
        // 格納済み Payload は全件に一時キーが付く (A72)。
        assert_eq!(w.payload_keys.len() as u64, pairs * 2);
        total += w.total_events;
    }
    assert_eq!(total, threads * pairs * 2);
}

#[test]
fn independent_host_drains_32_rings_while_producers_write() {
    // レビューの E2E 指摘: 32 スレッドストームは各スレッドが自 Ring を
    // 読み書きしており、独立 Host の同時回収になっていなかった。
    // ここでは 32 の Producer が書き続ける間に、独立した Host スレッドが
    // 32 Ring 全てを検証付きで回し続ける。
    let cfg = RingConfig::new(256, 8192);
    let agent = make_agent(32, cfg);
    let threads = 32u64;
    let events_per = 200u64;
    let mut workers = Vec::new();
    for tid in 1..=threads {
        let handle = agent.thread_begin(tid).expect("slot for thread");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region base");
        let worker = unsafe { DrainWorker::new(base, cfg, handle.generation) };
        workers.push(worker);
    }
    let mut producers = Vec::new();
    for tid in 1..=threads {
        let a = Arc::clone(&agent);
        producers.push(std::thread::spawn(move || {
            for i in 0..events_per {
                a.record_enter(tid, 1, 1, i, 0, b"data");
            }
        }));
    }
    // Host は Producer と独立に回収し続ける。
    let target = (threads * events_per) as usize;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut drained = 0usize;
    while drained < target && Instant::now() < deadline {
        let mut progressed = false;
        for w in workers.iter_mut() {
            let n = w.drain_all().events.len();
            if n > 0 {
                progressed = true;
            }
            drained += n;
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    for p in producers {
        p.join().unwrap();
    }
    for w in workers.iter_mut() {
        drained += w.drain_all().events.len();
        assert!(!w.integrity_lost);
        assert!(
            w.loss_events.is_empty(),
            "no loss expected: {:?}",
            w.loss_events
        );
    }
    assert_eq!(drained, target, "independent host recovered every event");
}
