//! Host 側の配線（`NotifyingDrainWorker`、`ValidatingHost`）と
//! `DrainWorker` の集計値。空き通知は書き手が待っているときだけ数え、
//! 集計と完全性の判定は内側の `DrainWorker` と一致すること。

use shirusu_host::{DrainWorker, IntegrityLevel, NotifyingDrainWorker, ValidatingHost};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::layout;
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::validate::KnownConfig;
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use shirusu_transport_win::RingNotify;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn writer(region: &SharedRegion) -> RingWriter {
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    }
}

fn write(w: &mut RingWriter, kind: EventKind, call: u64, order: u64) {
    w.write(EventInput {
        kind,
        api_id: 1,
        schema_id: 1,
        call_id: call,
        parent_call_id: 0,
        payload: &[1, 2, 3],
        capture_state: CaptureState::Captured,
        global_order: order,
    });
}

fn set_writer_waiting(region: &SharedRegion, on: bool) {
    layout::store(
        region.base(),
        layout::OFF_WRITER_WAITING,
        on as u64,
        Ordering::Release,
    );
}

#[test]
fn space_is_notified_only_while_the_writer_waits() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer(&region);
    let inner = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    let mut nw = NotifyingDrainWorker::new(inner, Arc::new(RingNotify::new().unwrap()), &region);

    write(&mut w, EventKind::CallEnter, 1, 0);
    assert_eq!(nw.drain_once(8).events.len(), 1);
    assert_eq!(nw.space_notifications, 0, "writer not waiting");

    write(&mut w, EventKind::CallEnter, 2, 0);
    set_writer_waiting(&region, true);
    assert_eq!(nw.drain_once(8).events.len(), 1);
    assert_eq!(nw.space_notifications, 1);
    // 何も回収しなければ空きはできず、通知しない。
    assert!(nw.drain_once(8).events.is_empty());
    assert_eq!(nw.space_notifications, 1);

    write(&mut w, EventKind::CallEnter, 3, 0);
    assert_eq!(nw.drain_all().events.len(), 1);
    assert_eq!(nw.space_notifications, 2);
    write(&mut w, EventKind::CallEnter, 4, 0);
    assert_eq!(nw.drain_all().events.len(), 1);
    assert_eq!(nw.space_notifications, 3);
    assert_eq!(nw.space_notify_errors, 0);

    set_writer_waiting(&region, false);
    write(&mut w, EventKind::CallEnter, 5, 0);
    assert_eq!(nw.drain_all().events.len(), 1);
    assert_eq!(nw.space_notifications, 3);
}

#[test]
fn wrapper_reports_the_inner_worker_counts() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer(&region);
    let inner = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    let mut nw = NotifyingDrainWorker::new(inner, Arc::new(RingNotify::new().unwrap()), &region);
    write(&mut w, EventKind::CallEnter, 1, 0);
    write(&mut w, EventKind::CallEnter, 2, 0);
    write(&mut w, EventKind::CallEnter, 3, 0);
    write(&mut w, EventKind::CallAborted, 2, 0);
    nw.drain_all();
    assert_eq!(nw.open_call_count(), 2);
    assert_eq!(nw.worker.open_call_count(), 2);
    assert_eq!(nw.worker.aborted_call_count(), 1);
    let clean = nw.integrity_report(0, false);
    assert_eq!(clean, nw.worker.integrity_report(0, false));
    let lost = nw.integrity_report(2, true);
    assert_eq!(lost.event_integrity, IntegrityLevel::Lost);
    assert_eq!(lost.capture_coverage, IntegrityLevel::Degraded);
    assert_eq!(lost, nw.worker.integrity_report(2, true));
}

#[test]
fn aborted_calls_are_counted_each() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer(&region);
    let mut worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    assert_eq!(worker.aborted_call_count(), 0);
    for call in 1..=3 {
        write(&mut w, EventKind::CallEnter, call, 0);
        write(&mut w, EventKind::CallAborted, call, 0);
    }
    worker.drain_all();
    assert_eq!(worker.aborted_call_count(), 3);
    assert_eq!(worker.open_call_count(), 0);
}

#[test]
fn validating_host_accepts_global_order_only_when_enabled() {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer(&region);
    write(&mut w, EventKind::CallEnter, 1, 5);
    let known = KnownConfig::new(cfg, cfg.required_len());

    let mut strict = ValidatingHost::new(known, 1);
    assert!(strict.drain_image(region.as_slice()).is_err());
    assert!(strict.is_stopped());

    let mut host = ValidatingHost::new(known, 1);
    host.set_global_order(true);
    let events = host.drain_image(region.as_slice()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].descriptor.global_order, 5);
}
