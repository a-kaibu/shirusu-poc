//! agent 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - record の結果分岐: (呼出元 x Host 生存) の優先順位、Slot 枯渇、DETACH。
//! - thread_begin の冪等性・thread_id の極値・forget 後の再確保 (Slot は
//!   Host が解放するまで残ること)。
//! - Payload サイズ境界 (容量 512 に対して 0/1/511/512/513)。

use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::context::{CallOrigin, HostMonitor};
use shirusu_transport::descriptor::flags;
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{EventInput, WriteOutcome};
use shirusu_transport::slot::SlotPool;
use std::sync::Arc;
use std::time::Duration;

fn agent(pool_size: usize) -> Agent {
    Agent::new(
        Arc::new(SlotPool::new(pool_size)),
        RingConfig::new(16, 512),
        Arc::new(HostMonitor::always_alive()),
    )
    .with_policy(shirusu_transport::WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    })
}
fn dead_host_agent(pool_size: usize) -> Agent {
    let monitor = Arc::new(HostMonitor::new(|| true));
    monitor.force_dead();
    Agent::new(
        Arc::new(SlotPool::new(pool_size)),
        RingConfig::new(16, 512),
        monitor,
    )
    .with_policy(shirusu_transport::WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    })
}
fn inp(payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 1,
        schema_id: 2,
        call_id: 7,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}

// ---------- record の分岐優先順位 ----------
#[test]
fn record_application_alive_writes() {
    let a = agent(2);
    assert!(matches!(
        a.record(1, CallOrigin::Application, inp(b"x")),
        RecordResult::Written(WriteOutcome::Published { sequence: 1, .. })
    ));
}
#[test]
fn record_internal_skipped_even_when_alive() {
    let a = agent(2);
    assert_eq!(
        a.record(1, CallOrigin::AgentInternal, inp(b"x")),
        RecordResult::SkippedAgentInternal
    );
    // スキップは Slot を消費しない
    assert_eq!(a.pool().free_count(), 2);
}
#[test]
fn record_internal_check_precedes_host_check() {
    // 呼出元の判定が Host 停止判定より先: 内部呼出は Host 停止時でも Skipped
    let a = dead_host_agent(2);
    assert_eq!(
        a.record(1, CallOrigin::AgentInternal, inp(b"x")),
        RecordResult::SkippedAgentInternal
    );
}
#[test]
fn record_application_dead_host_passthrough() {
    let a = dead_host_agent(2);
    assert_eq!(
        a.record(1, CallOrigin::Application, inp(b"x")),
        RecordResult::PassthroughHostStopped
    );
    assert_eq!(a.pool().free_count(), 2, "passthrough claims no slot");
}
#[test]
fn record_auto_begins_unknown_thread() {
    let a = agent(2);
    assert!(matches!(
        a.record(55, CallOrigin::Application, inp(b"x")),
        RecordResult::Written(_)
    ));
    // 自動で Slot が確保されている
    assert!(unsafe { a.thread_region_base(55) }.is_some());
    assert_eq!(a.pool().free_count(), 1);
}
#[test]
fn record_no_slot_when_pool_exhausted() {
    let a = agent(1);
    a.thread_begin(1).unwrap();
    assert_eq!(
        a.record(2, CallOrigin::Application, inp(b"x")),
        RecordResult::NoSlot
    );
    // 既存スレッドの記録は影響を受けない
    assert!(matches!(
        a.record(1, CallOrigin::Application, inp(b"x")),
        RecordResult::Written(_)
    ));
}

// ---------- thread_begin / detach / forget ----------
#[test]
fn thread_begin_is_idempotent() {
    let a = agent(3);
    let h1 = a.thread_begin(9).unwrap();
    let h2 = a.thread_begin(9).unwrap();
    assert_eq!(h1, h2, "same thread gets the same handle");
    assert_eq!(a.pool().free_count(), 2, "only one slot consumed");
}
#[test]
fn thread_begin_extreme_ids() {
    let a = agent(3);
    let h0 = a.thread_begin(0).unwrap();
    let hm = a.thread_begin(u64::MAX).unwrap();
    assert_ne!(h0.index, hm.index);
    assert_eq!(h0.thread_id, 0);
    assert_eq!(hm.thread_id, u64::MAX);
}
#[test]
fn detach_then_record_counts_missing() {
    let a = agent(2);
    a.thread_begin(7).unwrap();
    assert!(a.thread_detach(7));
    assert_eq!(
        a.record(7, CallOrigin::Application, inp(b"x")),
        RecordResult::AfterDetach
    );
    assert_eq!(
        a.record(7, CallOrigin::Application, inp(b"x")),
        RecordResult::AfterDetach
    );
    assert_eq!(
        a.pool().missing_calls(),
        2,
        "each post-detach record counts"
    );
}
#[test]
fn detach_unknown_thread_is_false() {
    let a = agent(2);
    assert!(!a.thread_detach(12345));
}
#[test]
fn detach_twice_second_is_false() {
    let a = agent(2);
    a.thread_begin(7).unwrap();
    assert!(a.thread_detach(7));
    assert!(
        !a.thread_detach(7),
        "already draining: begin_detach fails again"
    );
}
#[test]
fn forget_releases_agent_side_but_pool_slot_stays() {
    // forget は Agent の対応表を消すだけ。Slot の解放は Host 主導なので、
    // プール 1 枠では再記録が NoSlot になる (現行仕様の固定)
    let a = agent(1);
    a.thread_begin(1).unwrap();
    a.thread_forget(1);
    assert!(unsafe { a.thread_region_base(1) }.is_none());
    assert_eq!(
        a.record(1, CallOrigin::Application, inp(b"x")),
        RecordResult::NoSlot
    );
}
#[test]
fn forget_then_record_with_spare_slot_gets_fresh_slot() {
    let a = agent(2);
    let h1 = a.thread_begin(1).unwrap();
    a.thread_forget(1);
    let r = a.record(1, CallOrigin::Application, inp(b"x"));
    assert!(matches!(r, RecordResult::Written(_)));
    let h2 = a.thread_begin(1).unwrap();
    assert_ne!(h2.index, h1.index, "a different slot backs the new region");
}

// ---------- Payload サイズ境界 (容量 512) ----------
macro_rules! payload_size_case {
    ($name:ident, $len:expr, $published:expr) => {
        #[test]
        fn $name() {
            let a = agent(2);
            let buf = vec![7u8; $len];
            match a.record(1, CallOrigin::Application, inp(&buf)) {
                RecordResult::Written(WriteOutcome::Published { .. }) => {
                    assert!($published, "len {} should not publish fully", $len)
                }
                // 容量を超える Payload は Descriptor を残して Payload だけ落とす
                RecordResult::Written(WriteOutcome::PublishedDegraded { reason, .. }) => {
                    assert!(!$published, "len {} should publish fully", $len);
                    assert_ne!(
                        reason.to_flags() & flags::PAYLOAD_DROPPED,
                        0,
                        "dropped flag is set"
                    );
                }
                other => panic!("unexpected result for len {}: {:?}", $len, other),
            }
        }
    };
}
payload_size_case!(size_0_published, 0, true);
payload_size_case!(size_1_published, 1, true);
payload_size_case!(size_511_published, 511, true);
payload_size_case!(size_512_exact_published, 512, true);
payload_size_case!(size_513_degraded, 513, false);
payload_size_case!(size_4096_degraded, 4096, false);

// ---------- with_clock 後の記録 ----------
#[test]
fn record_with_manual_clock_still_writes() {
    let a = agent(2).with_clock(Arc::new(ManualClock::new()));
    assert!(matches!(
        a.record_enter(3, 1, 2, 9, 0, b"args"),
        RecordResult::Written(WriteOutcome::Published { sequence: 1, .. })
    ));
    assert!(matches!(
        a.record_leave(3, 1, 2, 9, 0, b"ret"),
        RecordResult::Written(WriteOutcome::Published { sequence: 2, .. })
    ));
}
