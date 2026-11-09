//! Bootstrap 経由の Mapping 登録（Phase 3）: 初期 Slot 0 の Agent が、
//! Host から配送された Mapping だけで記録できることの確認。
//! Agent DLL の初期化はこの経路で Ring を得る。

use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::expansion::ExpansionDelivery;
use shirusu_transport::ring::{RingReader, SharedRegion, WriterPolicy};
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::Arc;

#[test]
fn agent_with_zero_initial_slots_records_into_registered_mapping() {
    let cfg = RingConfig::new(64, 4096);
    // Host 側が作った共有領域（プロセス内では SharedRegion で代用）
    let host_region = SharedRegion::new(cfg, 0, 0);
    let base = host_region.base();

    let pool = Arc::new(SlotPool::new(0));
    let agent =
        Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive())).with_policy(WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        });
    // Slot が無い状態では記録できない
    assert_eq!(
        agent.record_enter(7, 1, 1, 1, 0, b"x"),
        RecordResult::NoSlot
    );
    // Bootstrap 相当: Mapping を 1 本登録する
    let delivery = ExpansionDelivery {
        len: cfg.required_len(),
        base: Some(base),
        handle_value: None,
        generation: shirusu_transport::EXPANDED_SLOT_GENERATION,
    };
    assert_eq!(agent.register_slot_mapping(delivery), Some(0));
    // 登録後はその Mapping へ記録でき、Host 側から読み戻せる
    assert!(matches!(
        agent.record_enter(7, 1, 1, 1, 0, b"args-bytes"),
        RecordResult::Written(_)
    ));
    let mut reader = unsafe { RingReader::new(base, cfg) };
    let batch = reader.drain_all();
    assert!(batch.integrity_error.is_none());
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].payload, b"args-bytes");
    assert_eq!(batch.events[0].descriptor.call_id, 1);
}

#[test]
fn register_slot_mapping_rejects_bad_deliveries() {
    let cfg = RingConfig::new(16, 512);
    let pool = Arc::new(SlotPool::new(0));
    let agent = Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive()));
    // base もハンドルも無い配送
    let empty = ExpansionDelivery {
        len: cfg.required_len(),
        base: None,
        handle_value: None,
        generation: shirusu_transport::EXPANDED_SLOT_GENERATION,
    };
    assert_eq!(agent.register_slot_mapping(empty), None);
    // 世代が違う配送
    let region = SharedRegion::new(cfg, 0, 0);
    let bad_gen = ExpansionDelivery {
        len: cfg.required_len(),
        base: Some(region.base()),
        handle_value: None,
        generation: 9,
    };
    assert_eq!(agent.register_slot_mapping(bad_gen), None);
    // 長さ不足の配送
    let short = ExpansionDelivery {
        len: 16,
        base: Some(region.base()),
        handle_value: None,
        generation: shirusu_transport::EXPANDED_SLOT_GENERATION,
    };
    assert_eq!(agent.register_slot_mapping(short), None);
}
