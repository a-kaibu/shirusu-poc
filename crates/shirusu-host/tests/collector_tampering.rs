//! `CommittedRangeCollector::collect` は対象プロセスが書き換え得る共有メモリを
//! 読む。矛盾した Cursor や Descriptor を見たら、写さず・解放せずに回収を止め、
//! 証拠の Control だけを検証側へ渡すこと（検証側がその理由で Ring を止める）。

use shirusu_host::{CommittedRangeCollector, DrainWorker};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::EventDescriptor;
use shirusu_transport::layout;
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

struct Rig {
    cfg: RingConfig,
    region: SharedRegion,
    writer: RingWriter,
    collector: CommittedRangeCollector,
    worker: DrainWorker,
}

fn rig() -> Rig {
    let cfg = RingConfig::new(4, 64);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let writer = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let collector = unsafe { CommittedRangeCollector::new(region.base(), cfg) };
    let worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    Rig {
        cfg,
        region,
        writer,
        collector,
        worker,
    }
}

impl Rig {
    fn write(&mut self, len: usize) {
        let body = vec![0x5a; len];
        self.writer.write(EventInput {
            kind: EventKind::CallEnter,
            api_id: 1,
            schema_id: 1,
            call_id: 1,
            parent_call_id: 0,
            payload: &body,
            capture_state: CaptureState::Captured,
            global_order: 0,
        });
    }
    fn load(&self, off: usize) -> u64 {
        layout::load(self.region.base(), off, Ordering::Acquire)
    }
    fn tamper(&self, cursor: u64, f: impl FnOnce(&mut EventDescriptor)) {
        let off = self.cfg.descriptors_offset()
            + ((cursor % self.cfg.descriptor_capacity as u64) as usize) * 64;
        let mut d = EventDescriptor::from_bytes(&self.region.as_slice()[off..off + 64]).unwrap();
        f(&mut d);
        let bytes = d.to_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.region.base().add(off), 64) };
    }
    /// 回収が止まり、何も写さず・解放せず、検証側も Ring を止めること。
    fn expect_stop(&mut self, read_cursor: u64, payload_read: u64) {
        let chunk = self.collector.collect(|| {}).expect("evidence chunk");
        assert!(self.collector.is_stopped());
        assert!(
            chunk.payload.is_empty(),
            "nothing beyond the bad descriptor is copied"
        );
        assert_eq!(self.load(layout::OFF_READ_CURSOR), read_cursor);
        assert_eq!(self.load(layout::OFF_PAYLOAD_READ_POSITION), payload_read);
        let batch = self.worker.ingest_chunk(&chunk);
        assert!(batch.events.is_empty(), "{batch:?}");
        assert!(
            self.worker.is_stopped(),
            "the validator stops on the evidence"
        );
        assert!(
            self.collector.collect(|| {}).is_none(),
            "a stopped collector stays stopped"
        );
    }
}

#[test]
fn untouched_ring_is_collected_and_released() {
    let mut r = rig();
    r.write(10);
    r.write(20);
    let chunk = r.collector.collect(|| {}).unwrap();
    assert_eq!(chunk.descriptor_count(), 2);
    assert_eq!(chunk.payload.len(), 30);
    assert_eq!(r.load(layout::OFF_READ_CURSOR), 2);
    assert_eq!(r.load(layout::OFF_PAYLOAD_READ_POSITION), 30);
    let batch = r.worker.ingest_chunk(&chunk);
    assert_eq!(batch.integrity_error, None);
    assert_eq!(batch.events.len(), 2);
    assert!(!r.worker.is_stopped());
    assert!(r.collector.collect(|| {}).is_none(), "nothing new");
}

#[test]
fn last_descriptor_past_the_payload_write_position_stops_collection() {
    let mut r = rig();
    r.write(10);
    r.write(20);
    r.tamper(1, |d| d.payload_len += 8);
    r.expect_stop(0, 0);
}

#[test]
fn last_descriptor_before_the_payload_read_position_stops_collection() {
    let mut r = rig();
    r.write(10);
    let first = r.collector.collect(|| {}).unwrap();
    assert!(r.worker.ingest_chunk(&first).integrity_error.is_none());
    r.write(20);
    // 2 件目が Payload の先頭 (既に解放した位置) を指す。
    r.tamper(1, |d| {
        d.payload_position = 0;
        d.payload_len = 4;
    });
    r.expect_stop(1, 10);
}

#[test]
fn last_descriptor_spanning_more_than_the_payload_capacity_stops_collection() {
    let mut r = rig();
    r.write(10);
    r.write(20);
    // 書込み済み位置を超えない範囲で、容量 (64) を超える長さの区間を作る。
    layout::store(
        r.region.base(),
        layout::OFF_PAYLOAD_WRITE_POSITION,
        200,
        Ordering::Release,
    );
    r.tamper(1, |d| d.payload_len = 100);
    r.expect_stop(0, 0);
}

#[test]
fn write_cursor_beyond_the_capacity_stops_collection() {
    let mut r = rig();
    r.write(10);
    layout::store(
        r.region.base(),
        layout::OFF_WRITE_CURSOR,
        5,
        Ordering::Release,
    );
    let chunk = r.collector.collect(|| {}).unwrap();
    assert!(r.collector.is_stopped());
    assert!(chunk.descriptors.is_empty());
    assert_eq!(r.load(layout::OFF_READ_CURSOR), 0);
    assert!(r.worker.ingest_chunk(&chunk).events.is_empty());
    assert!(r.worker.is_stopped());
}

// DrainWorker の直接回収（像を写す経路）と観測用の値。

#[test]
fn drain_once_takes_at_most_the_limit_in_order() {
    let mut r = rig();
    for len in [3, 5, 7] {
        r.write(len);
    }
    assert_eq!(r.worker.total_bytes_copied(), 0);
    let first = r.worker.drain_once(2);
    assert_eq!(
        first
            .events
            .iter()
            .map(|e| e.payload.len())
            .collect::<Vec<_>>(),
        [3, 5]
    );
    let after_first = r.worker.total_bytes_copied();
    assert!(after_first > 0);
    let rest = r.worker.drain_once(2);
    assert_eq!(rest.events.len(), 1);
    assert_eq!(rest.events[0].payload.len(), 7);
    assert!(r.worker.total_bytes_copied() > after_first);
    assert!(r.worker.drain_once(2).events.is_empty());
    assert_eq!(r.load(layout::OFF_READ_CURSOR), 3);
    assert_eq!(r.load(layout::OFF_PAYLOAD_READ_POSITION), 15);
}

#[test]
fn chunk_ingest_counts_owned_bytes() {
    let mut r = rig();
    r.write(10);
    let a = r.collector.collect(|| {}).unwrap();
    r.worker.ingest_chunk(&a);
    assert_eq!(r.worker.total_bytes_copied(), a.owned_bytes() as u64);
    r.write(20);
    let b = r.collector.collect(|| {}).unwrap();
    r.worker.ingest_chunk(&b);
    assert_eq!(
        r.worker.total_bytes_copied(),
        (a.owned_bytes() + b.owned_bytes()) as u64
    );
}

#[test]
fn resume_counts_the_copied_range_and_continues() {
    let mut r = rig();
    r.write(10);
    r.write(4);
    assert_eq!(r.worker.drain_once(1).events.len(), 1);
    let mut resumed = unsafe { DrainWorker::new(r.region.base(), r.cfg, 1) };
    resumed.resume_from_shared();
    assert!(!resumed.is_stopped());
    assert!(resumed.total_bytes_copied() > 0);
    let rest = resumed.drain_all();
    assert_eq!(rest.events.len(), 1);
    assert_eq!(rest.events[0].payload.len(), 4);
}

#[test]
fn identity_is_reported_once_set() {
    use shirusu_host::{ProcessInstanceId, RingId, RingIdentity};
    let mut r = rig();
    assert_eq!(r.worker.identity(), None);
    let id = RingIdentity::new(ProcessInstanceId(7), RingId(3), 1);
    r.worker.set_identity(id);
    assert_eq!(r.worker.identity(), Some(id));
}

#[test]
fn each_loss_counter_alone_produces_a_counters_event() {
    use shirusu_host::LossEvent;
    // Descriptor 満杯で落とした Payload なしの Event だけ（落とした Payload
    // バイトと劣化は 0）。
    let mut r = rig();
    for _ in 0..5 {
        r.write(0);
    }
    r.worker.drain_all();
    let counters: Vec<_> = r
        .worker
        .loss_events
        .iter()
        .filter(|e| matches!(e, LossEvent::Counters { .. }))
        .cloned()
        .collect();
    assert_eq!(
        counters,
        vec![LossEvent::Counters {
            dropped_events: 1,
            dropped_payload_bytes: 0,
            degraded_events: 0,
        }]
    );
}
