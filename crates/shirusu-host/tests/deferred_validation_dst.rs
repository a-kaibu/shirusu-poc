//! DST-in-PBT (review P1, transport spec v0.5): the Host releases Ring space
//! as soon as it has copied it ([`CommittedRangeCollector`]) and validates
//! the copy later on the Trace worker. While validation lags, the Agent keeps
//! writing into the released space. Operation sequences mix writes, copies,
//! delayed validation and corruption of a committed descriptor that the Host
//! has not copied yet.
//!
//! Invariants:
//! - Accepted events are a prefix of the published ones, in order (nothing
//!   corrupted, reordered, duplicated or invented is accepted).
//! - Without corruption every published event is accepted once.
//! - After a corruption is detected the Ring is stopped: no later chunk is
//!   accepted and no more space is released to the writer.
//! - A Trace with a corruption is Lost; one with dropped events (including
//!   drops after the last published event) is never Complete.

use proptest::prelude::*;
use shirusu_host::{CommittedRangeCollector, DrainWorker, IntegrityLevel};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::layout;
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriteOutcome, WriterPolicy};
use shirusu_transport::validate::CommittedChunk;
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn pbt_cases(default: u32) -> u32 {
    std::env::var("SHIRUSU_PBT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
enum Op {
    /// Writer publishes an event with this payload length.
    Write(u8),
    /// Host collection thread: copy and release (unless the Ring stopped).
    Collect,
    /// Trace worker validates the oldest copied chunk (validation lag).
    Validate,
    /// The target corrupts the oldest committed descriptor the Host has not
    /// copied yet.
    Corrupt(Corruption),
}

#[derive(Debug, Clone, Copy)]
enum Corruption {
    Kind,
    PayloadLength,
    SequenceBackwards,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..40).prop_map(Op::Write),
        2 => Just(Op::Collect),
        2 => Just(Op::Validate),
        1 => prop_oneof![
            Just(Corruption::Kind),
            Just(Corruption::PayloadLength),
            Just(Corruption::SequenceBackwards),
        ]
        .prop_map(Op::Corrupt),
    ]
}

struct Sim {
    cfg: RingConfig,
    // Drop order: worker, collector, writer, region.
    worker: DrainWorker,
    collector: CommittedRangeCollector,
    writer: RingWriter,
    region: SharedRegion,
    queue: VecDeque<CommittedChunk>,
    published: Vec<u64>,
    accepted: Vec<u64>,
    next_call: u64,
    dropped: u64,
    degraded: u64,
    /// Published index of the first corrupted descriptor.
    corrupted_at: Option<usize>,
    /// Shared read cursor when the validator stopped the Ring.
    read_cursor_at_stop: Option<u64>,
}

impl Sim {
    fn new() -> Self {
        let cfg = RingConfig::new(8, 128);
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
        Self {
            cfg,
            worker: DrainWorker::for_chunks(cfg, 1),
            collector,
            writer,
            region,
            queue: VecDeque::new(),
            published: Vec::new(),
            accepted: Vec::new(),
            next_call: 1,
            dropped: 0,
            degraded: 0,
            corrupted_at: None,
            read_cursor_at_stop: None,
        }
    }

    fn shared_read_cursor(&self) -> u64 {
        layout::load(
            self.region.base(),
            layout::OFF_READ_CURSOR,
            Ordering::Acquire,
        )
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Write(len) => {
                let call = self.next_call;
                self.next_call += 1;
                let body = vec![(call & 0xff) as u8; *len as usize];
                let outcome = self.writer.write(EventInput {
                    kind: EventKind::CallEnter,
                    api_id: 1,
                    schema_id: 1,
                    call_id: call,
                    parent_call_id: 0,
                    payload: &body,
                    capture_state: CaptureState::Captured,
                    global_order: 0,
                });
                match outcome {
                    WriteOutcome::Published { .. } => self.published.push(call),
                    WriteOutcome::PublishedDegraded { .. } => {
                        self.published.push(call);
                        self.degraded += 1;
                    }
                    WriteOutcome::Dropped { .. } => self.dropped += 1,
                }
            }
            Op::Collect => {
                // As CaptureSession::poll_once: a stopped validator stops
                // collection before anything more is released.
                if self.worker.is_stopped() {
                    self.collector.stop();
                }
                if let Some(chunk) = self.collector.collect(|| {}) {
                    self.queue.push_back(chunk);
                }
            }
            Op::Validate => {
                if let Some(chunk) = self.queue.pop_front() {
                    let batch = self.worker.ingest_chunk(&chunk);
                    self.accepted
                        .extend(batch.events.iter().map(|e| e.descriptor.call_id));
                    if self.worker.is_stopped() && self.read_cursor_at_stop.is_none() {
                        self.read_cursor_at_stop = Some(self.shared_read_cursor());
                    }
                }
            }
            Op::Corrupt(kind) => {
                if self.corrupted_at.is_some() {
                    return;
                }
                let base = self.region.base();
                let read = self.shared_read_cursor();
                let write = layout::load(base, layout::OFF_WRITE_CURSOR, Ordering::Acquire);
                if read == write {
                    return; // nothing committed and uncopied
                }
                let slot = (read % self.cfg.descriptor_capacity as u64) as usize;
                // SAFETY: inside the descriptor region of this Ring.
                let desc = unsafe { base.add(self.cfg.descriptors_offset() + slot * 64) };
                unsafe {
                    match kind {
                        Corruption::Kind => desc.cast::<u16>().write_unaligned(0xffff),
                        Corruption::PayloadLength => {
                            desc.add(4).cast::<u32>().write_unaligned(u32::MAX)
                        }
                        Corruption::SequenceBackwards => {
                            desc.add(8).cast::<u64>().write_unaligned(0)
                        }
                    }
                }
                // Every published event got the next descriptor, so the
                // cursor is also its index in `published`.
                self.corrupted_at = Some(read as usize);
            }
        }
        if let Some(at) = self.read_cursor_at_stop {
            assert_eq!(
                self.shared_read_cursor(),
                at,
                "space was released after the Ring stopped"
            );
        }
    }

    fn finish(&mut self) {
        for _ in 0..64 {
            self.apply(&Op::Collect);
            while !self.queue.is_empty() {
                self.apply(&Op::Validate);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pbt_cases(512)))]

    #[test]
    fn deferred_validation_never_accepts_corrupt_or_lost_data(
        ops in proptest::collection::vec(op(), 1..160)
    ) {
        let mut sim = Sim::new();
        for op in &ops {
            sim.apply(op);
        }
        sim.finish();
        // Prefix of the published order.
        prop_assert!(sim.accepted.len() <= sim.published.len());
        prop_assert_eq!(&sim.accepted[..], &sim.published[..sim.accepted.len()]);
        let lost = sim.worker.is_stopped();
        let report = sim.worker.integrity_report(0, lost);
        match sim.corrupted_at {
            Some(at) => {
                // SequenceBackwards on a descriptor whose sequence is already
                // 0 is no corruption; every other case must be caught.
                if lost {
                    prop_assert!(sim.accepted.len() <= at, "accepted beyond the corruption");
                    prop_assert_eq!(report.event_integrity, IntegrityLevel::Lost);
                } else {
                    prop_assert_eq!(&sim.accepted, &sim.published);
                }
            }
            None => {
                prop_assert!(!lost, "valid Ring stopped");
                prop_assert_eq!(&sim.accepted, &sim.published);
                if sim.dropped + sim.degraded > 0 {
                    prop_assert_ne!(
                        report.event_integrity,
                        IntegrityLevel::Complete,
                        "dropped events finalized as complete"
                    );
                } else {
                    prop_assert_eq!(report.event_integrity, IntegrityLevel::Complete);
                }
            }
        }
    }
}

/// Drops after the last published event change only the loss counters. The
/// collector must still hand them to the validator (Control-only chunk);
/// before, a Ring that never published again hid them.
#[test]
fn trailing_drops_without_new_events_are_reported() {
    let mut sim = Sim::new();
    for _ in 0..20 {
        sim.apply(&Op::Write(30));
    }
    assert!(sim.dropped > 0, "the Ring must overflow");
    sim.finish();
    assert_eq!(sim.accepted, sim.published);
    let before = sim.worker.loss_events.len();
    assert!(before > 0, "drops are reported");
    // Only a counter moves now, as for an event cut off by a writer that was
    // terminated mid-record (review P0).
    layout::fetch_add(sim.region.base(), layout::OFF_DROPPED_EVENTS, 1);
    sim.finish();
    assert_eq!(sim.worker.loss_events.len(), before + 1);
    let report = sim.worker.integrity_report(0, false);
    assert_ne!(report.event_integrity, IntegrityLevel::Complete);
    assert!(!sim.worker.is_stopped());
}
