//! A70: 低水位時の非同期 Mapping 追加フロー (Agent 側)。
//!
//! 管理スレッド (`ExpansionManager`) が SlotPool の拡張要求フラグを消費して
//! Host へ要求し、配送された Mapping を登録する。記録経路は登録しない。
//! Host 役はテストが手動で行う (実際の `ExpansionService` との往復は
//! host クレートの expansion_e2e が担う)。

use shirusu_agent::{Agent, ExpansionManager, RecordResult};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::expansion::{ExpansionDelivery, ExpansionRequest, EXPANDED_SLOT_GENERATION};
use shirusu_transport::ring::WriterPolicy;
use shirusu_transport::slot::{SlotPool, SLOT_MEMORY_BYTES};
use shirusu_transport::RingConfig;
use shirusu_transport_win::SharedMapping;
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// 管理スレッドと「手動 Host」の配線。Host 役はテストが `deliver_mapping` で行う。
struct Rig {
    agent: Arc<Agent>,
    pool: Arc<SlotPool>,
    manager: ExpansionManager,
    requests: mpsc::Receiver<ExpansionRequest>,
    deliveries: Option<mpsc::Sender<ExpansionDelivery>>,
    /// 手動 Host が作った Mapping の保持。Agent は base を借りるため、
    /// テストが生存期間中有効に保つ。
    mappings: Vec<SharedMapping>,
    cfg: RingConfig,
}
impl Rig {
    fn new(pool: Arc<SlotPool>, monitor: Arc<HostMonitor>) -> Self {
        let cfg = RingConfig::new(16, 512);
        let agent = Arc::new(Agent::new(Arc::clone(&pool), cfg, monitor).with_policy(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
        ));
        let (req_tx, req_rx) = mpsc::channel();
        let (del_tx, del_rx) = mpsc::channel();
        let manager = ExpansionManager::new(Arc::clone(&agent), Box::new(req_tx), del_rx);
        Self {
            agent,
            pool,
            manager,
            requests: req_rx,
            deliveries: Some(del_tx),
            mappings: Vec::new(),
            cfg,
        }
    }
    fn with_pool_size(size: usize, low_watermark: usize) -> Self {
        Self::new(
            Arc::new(SlotPool::with_low_watermark(size, low_watermark)),
            Arc::new(HostMonitor::always_alive()),
        )
    }
    /// 保留中の要求を 1 件取り出す (無ければ None)。
    fn take_request(&self) -> Option<ExpansionRequest> {
        self.requests.try_recv().ok()
    }
    /// Host 役: 新しい Mapping を作って配送する。作った Mapping は保持する。
    fn deliver_mapping(&mut self) -> *mut u8 {
        let mapping = SharedMapping::create(self.cfg.required_len()).unwrap();
        let base = mapping.as_ptr();
        self.mappings.push(mapping);
        self.deliveries
            .as_ref()
            .unwrap()
            .send(ExpansionDelivery {
                len: self.cfg.required_len(),
                base: Some(base),
                handle_value: None,
                generation: EXPANDED_SLOT_GENERATION,
            })
            .unwrap();
        base
    }
    /// Host 役の配送口を落とす (追加中の Host 停止の再現)。
    fn drop_deliveries(&mut self) {
        self.deliveries = None;
    }
    fn record(&self, tid: u64, call: u64) -> RecordResult {
        self.agent.record_enter(tid, 1, 1, call, 0, b"x")
    }
}

#[test]
fn manager_registers_expansion_and_new_thread_uses_mapping() {
    // A70 の基本形: 低水位 → 要求 → 配送 → 登録 → 新規スレッドが
    // Host の Mapping の Ring で記録できる。
    let mut rig = Rig::with_pool_size(3, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    assert_eq!(rig.pool.free_count(), 0);
    // 管理スレッドが要求を送る。
    rig.manager.step();
    assert!(rig.manager.is_in_flight());
    assert_eq!(rig.manager.stats().requested, 1);
    assert!(rig.take_request().is_some(), "request must be sent");
    // Host 役が Mapping を配送し、管理スレッドが登録する。
    let base = rig.deliver_mapping();
    rig.manager.step();
    assert!(!rig.manager.is_in_flight());
    assert_eq!(rig.manager.stats().registered, 1);
    assert_eq!(rig.pool.capacity(), 4);
    assert_eq!(rig.pool.slot(3).generation(), 0);
    // 新規スレッドは追加 Slot を取り、Host の Mapping の Ring で記録する。
    let h = rig.agent.thread_begin(4).unwrap();
    assert_eq!(h.index, 3);
    assert_eq!(h.generation, 0);
    assert_eq!(unsafe { rig.agent.thread_region_base(4) }, Some(base));
    assert!(matches!(rig.record(4, 1), RecordResult::Written(_)));
    // 既存スレッドの記録も続く。
    assert!(matches!(rig.record(1, 2), RecordResult::Written(_)));
    assert!(matches!(rig.record(2, 3), RecordResult::Written(_)));
    assert!(matches!(rig.record(3, 4), RecordResult::Written(_)));
}

#[test]
fn record_path_never_registers() {
    // Hook / 記録経路では登録しない。管理スレッドが step するまで
    // Slot は増えず、要求も送られない。
    let mut rig = Rig::with_pool_size(3, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    for i in 0..20u64 {
        assert!(matches!(rig.record(1, i), RecordResult::Written(_)));
        assert!(matches!(rig.record(2, i), RecordResult::Written(_)));
        assert!(matches!(rig.record(3, i), RecordResult::Written(_)));
    }
    assert_eq!(rig.pool.capacity(), 3, "record must not register slots");
    assert!(rig.take_request().is_none(), "record must not request");
    // 管理スレッドが動いて初めて拡張される。
    rig.manager.step();
    assert_eq!(rig.manager.stats().requested, 1);
    rig.deliver_mapping();
    rig.manager.step();
    assert_eq!(rig.pool.capacity(), 4);
}

#[test]
fn duplicate_requests_suppressed_while_in_flight() {
    // 進行中の拡張が 1 件ある間は新規要求を出さない (二重作成しない)。
    // 進行中に立った要求は、完了後の step で改めて処理される。
    let mut rig = Rig::with_pool_size(4, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some()); // free 1 < 2 → フラグ
    rig.manager.step();
    assert_eq!(rig.manager.stats().requested, 1);
    assert!(rig.take_request().is_some());
    // 進行中にさらに低水位を踏んでも、要求は増えない。
    assert!(rig.agent.thread_begin(4).is_some()); // free 0 < 2 → 再ラッチ
    for _ in 0..5 {
        rig.manager.step();
        assert!(rig.take_request().is_none(), "no duplicate while in flight");
    }
    assert_eq!(rig.manager.stats().requested, 1);
    assert_eq!(rig.pool.capacity(), 4);
    // 配送が届いて登録が完了した後、次の step で溜まった要求が出る。
    rig.deliver_mapping();
    rig.manager.step();
    assert_eq!(rig.manager.stats().registered, 1);
    assert_eq!(rig.pool.capacity(), 5);
    rig.manager.step();
    assert_eq!(rig.manager.stats().requested, 2);
    assert!(rig.take_request().is_some());
    rig.deliver_mapping();
    rig.manager.step();
    assert_eq!(rig.manager.stats().registered, 2);
    assert_eq!(rig.pool.capacity(), 6);
}

#[test]
fn host_stop_discards_in_flight_request_via_monitor() {
    // Host 停止を HostMonitor で検知したら、進行中の要求を破棄する。
    // (記録の素通し自体は C10 の設計どおりで、ここでは管理スレッドの
    // 状態だけを見る。)
    let monitor = Arc::new(HostMonitor::new(|| true));
    let mut rig = Rig::new(
        Arc::new(SlotPool::with_low_watermark(3, 2)),
        Arc::clone(&monitor),
    );
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    rig.manager.step();
    assert!(rig.manager.is_in_flight());
    assert_eq!(rig.manager.stats().requested, 1);
    // Host 停止を検知する。
    monitor.force_dead();
    rig.manager.step();
    assert!(!rig.manager.is_in_flight());
    assert_eq!(rig.manager.stats().discarded_host_stopped, 1);
    assert_eq!(rig.manager.stats().registered, 0);
    assert_eq!(rig.pool.capacity(), 3, "no slot was registered");
    // フラグは消費済みで、新しい claim が無ければ再要求は起きない。
    rig.manager.step();
    assert_eq!(rig.manager.stats().requested, 1);
}

#[test]
fn host_stop_skips_new_requests() {
    // Host 停止が分かっている間は、フラグが立っても要求を送らない。
    let monitor = Arc::new(HostMonitor::new(|| true));
    let mut rig = Rig::new(
        Arc::new(SlotPool::with_low_watermark(4, 2)),
        Arc::clone(&monitor),
    );
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some()); // free 1 < 2 → フラグ
    monitor.force_dead();
    rig.manager.step();
    assert_eq!(rig.manager.stats().skipped_host_stopped, 1);
    assert_eq!(rig.manager.stats().requested, 0);
    assert_eq!(rig.pool.capacity(), 4);
    // 新しい claim でフラグが再び立っても、送らない。
    assert!(rig.agent.thread_begin(4).is_some()); // free 0 < 2 → 再ラッチ
    rig.manager.step();
    assert_eq!(rig.manager.stats().skipped_host_stopped, 2);
    assert_eq!(rig.manager.stats().requested, 0);
    assert_eq!(rig.pool.capacity(), 4);
}

#[test]
fn host_disconnect_discards_request_and_existing_rings_continue() {
    // C11 をフロー全体で維持する: 追加中に Host (配送口) が止まっても、
    // 管理スレッドは要求を破棄し、既存 Ring での記録は続く。
    let mut rig = Rig::with_pool_size(3, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    rig.manager.step();
    assert!(rig.manager.is_in_flight());
    assert!(rig.take_request().is_some());
    // Host が配送口ごと止まる。
    rig.drop_deliveries();
    rig.manager.step();
    assert!(!rig.manager.is_in_flight());
    assert_eq!(rig.manager.stats().discarded_host_stopped, 1);
    assert_eq!(rig.manager.stats().registered, 0);
    assert_eq!(rig.pool.capacity(), 3);
    // 既存 Ring での記録は一切止めない。
    for i in 0..5u64 {
        assert!(matches!(rig.record(1, i), RecordResult::Written(_)));
        assert!(matches!(rig.record(2, i), RecordResult::Written(_)));
        assert!(matches!(rig.record(3, i), RecordResult::Written(_)));
    }
}

#[test]
fn memory_limit_declines_expansion() {
    // 総メモリ上限を超える場合は拡張を断念し、フラグを落とす。
    // (SLOT_MEMORY_BYTES は本番既定 1 Slot 分の共有メモリ量。)
    let mut rig = Rig::new(
        Arc::new(SlotPool::with_low_watermark(2, 1).with_memory_limit(2 * SLOT_MEMORY_BYTES)),
        Arc::new(HostMonitor::always_alive()),
    );
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some()); // free 0 < 1 → フラグ
    rig.manager.step();
    assert_eq!(rig.manager.stats().declined_limit, 1);
    assert_eq!(rig.manager.stats().requested, 0);
    assert!(rig.take_request().is_none());
    assert_eq!(rig.pool.capacity(), 2);
    // 1 本分の余裕があれば 1 回だけ拡張し、次は断念する。
    let mut rig2 = Rig::new(
        Arc::new(SlotPool::with_low_watermark(2, 1).with_memory_limit(3 * SLOT_MEMORY_BYTES)),
        Arc::new(HostMonitor::always_alive()),
    );
    assert!(rig2.agent.thread_begin(1).is_some());
    assert!(rig2.agent.thread_begin(2).is_some());
    rig2.manager.step();
    assert_eq!(rig2.manager.stats().requested, 1);
    rig2.deliver_mapping();
    rig2.manager.step();
    assert_eq!(rig2.manager.stats().registered, 1);
    assert_eq!(rig2.pool.capacity(), 3);
    assert!(rig2.agent.thread_begin(3).is_some()); // free 0 < 1 → 再ラッチ
    rig2.manager.step();
    assert_eq!(rig2.manager.stats().declined_limit, 1);
    assert_eq!(rig2.manager.stats().requested, 1);
    assert_eq!(rig2.pool.capacity(), 3);
}

#[test]
fn delivery_with_handle_value_unsupported_on_stub() {
    // base が無くハンドル値だけの配送は、写像を作れなければ登録しない。
    // Linux スタブでは from_handle_value が Unsupported で失敗する。
    // Windows でもハンドル値 0 は無効なため同じく失敗する。
    let mut rig = Rig::with_pool_size(3, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    rig.manager.step();
    assert!(rig.take_request().is_some());
    rig.deliveries
        .as_ref()
        .unwrap()
        .send(ExpansionDelivery {
            len: rig.cfg.required_len(),
            base: None,
            handle_value: Some(0),
            generation: EXPANDED_SLOT_GENERATION,
        })
        .unwrap();
    rig.manager.step();
    assert_eq!(rig.manager.stats().failed_delivery, 1);
    assert_eq!(rig.manager.stats().registered, 0);
    assert_eq!(rig.pool.capacity(), 3, "failed delivery adds no slot");
}

#[test]
fn generation_mismatch_delivery_rejected() {
    // 世代が追加 Slot の世代 (0) と一致しない配送は登録しない。
    let mut rig = Rig::with_pool_size(3, 2);
    assert!(rig.agent.thread_begin(1).is_some());
    assert!(rig.agent.thread_begin(2).is_some());
    assert!(rig.agent.thread_begin(3).is_some());
    rig.manager.step();
    assert!(rig.take_request().is_some());
    let mapping = SharedMapping::create(rig.cfg.required_len()).unwrap();
    let base = mapping.as_ptr();
    rig.mappings.push(mapping);
    rig.deliveries
        .as_ref()
        .unwrap()
        .send(ExpansionDelivery {
            len: rig.cfg.required_len(),
            base: Some(base),
            handle_value: None,
            generation: 1,
        })
        .unwrap();
    rig.manager.step();
    assert_eq!(rig.manager.stats().failed_delivery, 1);
    assert_eq!(rig.manager.stats().registered, 0);
    assert_eq!(rig.pool.capacity(), 3);
}
