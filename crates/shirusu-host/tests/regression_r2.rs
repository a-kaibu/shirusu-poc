//! R2 回帰 (レビュー指摘): Host の通常回収経路が無検証の RingReader を
//! 使っており、共有メモリ上の Descriptor の payload_len / payload_position
//! を検証せずコピーしていた。破損 (または攻撃側が細工) した Descriptor を
//! 注入しても、通常経路はイベントとして取り込まず、Ring を止めて完全性
//! 喪失として扱わなければならない。
//!
//! 修正前の DrainWorker ではどちらのテストも失敗した (破損イベントが
//! そのまま取り込まれた)。修正後は DrainWorker 自身が検証付き経路
//! (copy→検証→前進) を通る。

use shirusu_host::{DrainWorker, ProcessInstanceId, RingId, RingIdentity};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::EventKind;
use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventDescriptor, RingConfig};
use std::sync::Arc;

fn setup() -> (SharedRegion, shirusu_transport::RingWriter, DrainWorker) {
    let cfg = RingConfig::new(16, 512);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: std::time::Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    (region, w, worker)
}

fn ev(call: u64, payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 3,
        schema_id: 4,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}

/// Descriptor スロット `slot` のバイト列を書き換える (共有メモリ破損の注入)。
fn rewrite_descriptor(region: &SharedRegion, slot: usize, f: impl Fn(&mut EventDescriptor)) {
    let cfg = region.config;
    let off = cfg.descriptors_offset() + slot * 64;
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&region.as_slice()[off..off + 64]);
    let mut d = EventDescriptor::from_bytes(&bytes).unwrap();
    f(&mut d);
    unsafe {
        std::ptr::copy_nonoverlapping(d.to_bytes().as_ptr(), region.base().add(off), 64);
    }
}

#[test]
fn drain_worker_rejects_corrupt_payload_position() {
    let (region, mut w, mut host) = setup();
    host.set_identity(RingIdentity::new(ProcessInstanceId(1), RingId(1), 1));
    w.write(ev(1, b"one"));
    w.write(ev(2, b"two"));
    w.write(ev(3, b"three"));
    // 2 件目の Descriptor の payload_position を +1 ずらす。
    rewrite_descriptor(&region, 1, |d| d.payload_position += 1);
    let batch = host.drain_all();
    assert!(
        batch.events.is_empty(),
        "corrupt descriptor must not be drained, got {} events",
        batch.events.len()
    );
    assert_eq!(host.total_events, 0);
    assert!(
        host.payload_keys.is_empty(),
        "no key may be minted from an unvalidated descriptor"
    );
    // Ring は止まり、完全性喪失として記録され、以後も取り込まない。
    assert!(host.integrity_lost);
    assert!(host.is_stopped());
    assert!(host
        .loss_events
        .iter()
        .any(|l| matches!(l, shirusu_host::LossEvent::IntegrityLost { .. })));
    assert!(host.drain_all().events.is_empty());
}

#[test]
fn drain_worker_rejects_oversized_payload_len() {
    let (region, mut w, mut host) = setup();
    w.write(ev(1, b"one"));
    // 容量 512 の Ring に対し payload_len = 600 を名乗る Descriptor。
    // 無検証経路は折り返し読みで 600 バイトのゴミを Payload として返す。
    rewrite_descriptor(&region, 0, |d| d.payload_len = 600);
    let batch = host.drain_all();
    assert!(
        batch.events.is_empty(),
        "oversized payload_len must be rejected, got {} events",
        batch.events.len()
    );
    assert_eq!(host.total_events, 0);
    assert!(host.integrity_lost);
}
