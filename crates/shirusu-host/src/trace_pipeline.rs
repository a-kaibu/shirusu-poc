//! Ownership transfer from Ring collection to validation and Trace conversion.
//! The collection thread copies committed Ring contents and releases them at
//! once; validation (per-Ring [`DrainWorker`]), conversion and compression run
//! on this worker. The worker never sees a shared Ring pointer. FIFO order
//! includes environment updates, loss records and barriers.
use crate::trace_convert::{ArgsConversionStats, TraceBatchContext, TraceRecorder};
use crate::{DrainWorker, LossEvent};
use shirusu_trace::{proto::CaptureEnvironment, DurableWrite, TraceError};
use shirusu_transport::ring::ReceivedEvent;
use shirusu_transport::validate::CommittedChunk;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Events one output chunk collects before it is written.
const STAGE_MAX_EVENTS: usize = 4096;
/// Payload bytes one output chunk collects before it is written.
const STAGE_MAX_PAYLOAD: usize = 1024 * 1024;
/// Longest a sparse stream's events wait to fill a chunk. Barriers (Ring
/// retirement, stop) flush at once, so this only delays the bytes on disk.
const STAGE_MAX_AGE: Duration = Duration::from_millis(100);

/// One context's events waiting to be written as one Event Chunk.
struct Staged {
    context: TraceBatchContext,
    events: Vec<ReceivedEvent>,
    payload: usize,
    /// Queue accounting of each merged command, released once written.
    bytes: Vec<usize>,
    since: Instant,
}

impl Staged {
    fn new(context: TraceBatchContext) -> Self {
        Self {
            context,
            events: Vec::new(),
            payload: 0,
            bytes: Vec::new(),
            since: Instant::now(),
        }
    }
}

/// Whether `events` more events with `payload` bytes still fit `staged`.
fn fits(staged: &Staged, events: usize, payload: usize) -> bool {
    staged.events.len().saturating_add(events) <= STAGE_MAX_EVENTS
        && staged.payload.saturating_add(payload) <= STAGE_MAX_PAYLOAD
}

/// Write one staged group. Compression is skipped while conversion is behind:
/// judged by the bytes waiting in the queue, not by whether another command
/// is ready (review 2026-11-14 P2-1: several Rings collected in one poll
/// always looked like a backlog and disabled compression for every
/// multithreaded target).
fn write_staged<W: DurableWrite>(
    recorder: &mut TraceRecorder<W>,
    totals: &mut PipelineReport,
    state: &WorkerState,
    staged: Staged,
) -> Result<(), TraceError> {
    if !staged.events.is_empty() {
        let backlogged =
            state.queued_bytes.load(Ordering::Acquire) > state.byte_budget / BACKLOG_FRACTION;
        let stats = if backlogged {
            totals.metrics.compression_bypass_requests =
                totals.metrics.compression_bypass_requests.saturating_add(1);
            recorder.record_owned_batch_uncompressed(&staged.context, staged.events)?
        } else {
            recorder.record_owned_batch_with_args(&staged.context, staged.events)?
        };
        totals.args.args_attached += stats.args_attached;
        totals.args.args_incomplete += stats.args_incomplete;
        totals.args.args_fallback_blob += stats.args_fallback_blob;
    }
    for bytes in staged.bytes {
        state.release(bytes);
    }
    Ok(())
}

/// Write staged groups: all of them, or with `aged_only` those past
/// [`STAGE_MAX_AGE`]. Groups are written in the order they were started.
fn flush_staged<W: DurableWrite>(
    recorder: &mut TraceRecorder<W>,
    totals: &mut PipelineReport,
    state: &WorkerState,
    staged: &mut Vec<Staged>,
    aged_only: bool,
) -> Result<(), TraceError> {
    let mut i = 0;
    while i < staged.len() {
        if aged_only && staged[i].since.elapsed() < STAGE_MAX_AGE {
            i += 1;
            continue;
        }
        let group = staged.remove(i);
        write_staged(recorder, totals, state, group)?;
    }
    Ok(())
}

/// Conversion counts as behind once this fraction of the queue budget waits.
const BACKLOG_FRACTION: usize = 8;

/// Owned bytes the queue may hold before the collector waits. The Ring is
/// released as soon as a chunk is copied, so this budget, not the Ring, absorbs
/// a burst that conversion cannot keep up with. Waiting here back-pressures
/// the Ring (and so the writer) exactly as a full bounded queue did.
pub(crate) const QUEUE_BYTE_BUDGET: usize = if usize::BITS >= 64 {
    256 * 1024 * 1024
} else {
    64 * 1024 * 1024
};

/// A Ring's validation state, shared by the collection thread (stop checks,
/// final accounting after a barrier) and the worker (validation).
pub(crate) type SharedDrainWorker = Arc<RingValidation>;

/// The worker validates under `worker`'s lock, which a large chunk holds for
/// a while. The collection thread must never wait for it while the writer is
/// producing: it polls `stopped` instead, and locks only after a barrier.
pub(crate) struct RingValidation {
    worker: Mutex<DrainWorker>,
    stopped: std::sync::atomic::AtomicBool,
}

impl RingValidation {
    pub(crate) fn new(worker: DrainWorker) -> Arc<Self> {
        Arc::new(Self {
            stopped: std::sync::atomic::AtomicBool::new(worker.is_stopped()),
            worker: Mutex::new(worker),
        })
    }
    /// Whether validation stopped this Ring (no lock).
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    /// Validation state. Call only after a pipeline barrier.
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, DrainWorker> {
        // A panic while validating leaves no half-applied state that matters
        // here: the pipeline worker failure itself forbids Finalization.
        self.worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum Command {
    Events(TraceBatchContext, Vec<ReceivedEvent>),
    Chunk(TraceBatchContext, SharedDrainWorker, CommittedChunk),
    Losses(Vec<LossEvent>, u64, u64),
    Environment(CaptureEnvironment),
    Barrier(Sender<()>),
}

impl Command {
    fn queued_bytes(&self) -> usize {
        match self {
            Self::Events(_, events) => events
                .iter()
                .fold(0usize, |n, e| n.saturating_add(e.payload.len() + 96)),
            Self::Chunk(_, _, chunk) => chunk.owned_bytes(),
            Self::Losses(losses, ..) => losses.len().saturating_mul(64),
            Self::Environment(_) | Self::Barrier(_) => 0,
        }
    }
}

struct Queued {
    command: Command,
    bytes: usize,
}

/// Wall-clock diagnostics, not additive CPU attribution or completeness proof.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostPipelineStats {
    pub commands_processed: u64,
    pub events_received: u64,
    pub merged_event_commands: u64,
    /// Processing groups requesting raw Event Chunks; Profile/Filtered groups
    /// can produce no Event Chunk, so this is not a physical chunk count.
    pub compression_bypass_requests: u64,
    pub conversion_wall_ns: u64,
    pub queue_full_count: u64,
    pub drain_wait_ns: u64,
    /// Largest number of bytes queued for conversion at once (sustained-load
    /// measurement: a Host that keeps up keeps it bounded).
    pub peak_queued_bytes: u64,
}

#[derive(Default)]
pub(crate) struct PipelineReport {
    pub args: ArgsConversionStats,
    pub metrics: HostPipelineStats,
}
type Finished<W> = Result<(TraceRecorder<W>, PipelineReport), TraceError>;

pub(crate) struct TracePipeline<W: DurableWrite + Send + 'static> {
    sender: Option<Sender<Queued>>,
    worker: Option<JoinHandle<Finished<W>>>,
    queued_bytes: Arc<AtomicUsize>,
    /// Commands sent and not yet completed by the worker.
    queued_commands: Arc<AtomicUsize>,
    byte_budget: usize,
    queue_full_count: u64,
    drain_wait_ns: u64,
    peak_queued_bytes: usize,
    /// Set while the worker runs at Normal priority because collection
    /// waited on it (see `boost_worker`).
    boosted: Arc<AtomicBool>,
}

struct WorkerState {
    receiver: Receiver<Queued>,
    queued_bytes: Arc<AtomicUsize>,
    queued_commands: Arc<AtomicUsize>,
    boosted: Arc<AtomicBool>,
    byte_budget: usize,
}

impl WorkerState {
    /// Complete a command's accounting (after its work is done).
    fn release(&self, bytes: usize) {
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
        self.queued_commands.fetch_sub(1, Ordering::AcqRel);
    }

    /// Return to below-normal priority once a boost has drained the queue
    /// to half the budget (the worker only runs boosted while it is behind).
    fn settle_priority(&self) {
        if self.boosted.load(Ordering::Acquire)
            && self.queued_bytes.load(Ordering::Acquire) <= self.byte_budget / 2
            && self.boosted.swap(false, Ordering::AcqRel)
        {
            shirusu_transport_win::set_current_thread_priority(
                shirusu_transport_win::ThreadPriority::BelowNormal,
            );
        }
    }
}

/// Validate a collected chunk into owned events. A rejected chunk stops its
/// Ring inside the DrainWorker (recorded at finalization) and yields nothing.
///
/// Loss records accumulated by the validator are handed back once there are
/// [`LOSS_FLUSH_RECORDS`] of them (review 2026-11-14 P2-3): an overloaded
/// session would otherwise hold every record until stop, and a Host crash
/// would leave a Trace with no sign that anything was lost.
fn materialize(command: Command) -> (Command, Option<Command>) {
    match command {
        Command::Chunk(context, worker, chunk) => {
            let (events, losses) = match worker.worker.lock() {
                Ok(mut validator) => {
                    let events = validator.ingest_chunk(&chunk).events;
                    if validator.is_stopped() {
                        worker.stopped.store(true, Ordering::Release);
                    }
                    let losses = (validator.loss_events.len() >= LOSS_FLUSH_RECORDS)
                        .then(|| validator.take_loss_events());
                    (events, losses)
                }
                // A poisoned validator cannot vouch for anything.
                Err(_) => {
                    worker.stopped.store(true, Ordering::Release);
                    (Vec::new(), None)
                }
            };
            let losses = losses.map(|l| Command::Losses(l, context.process_id, context.thread_id));
            (Command::Events(context, events), losses)
        }
        other => (other, None),
    }
}

/// Validator loss records written as soon as this many have accumulated.
const LOSS_FLUSH_RECORDS: usize = 256;

impl<W: DurableWrite + Send + 'static> TracePipeline<W> {
    pub(crate) fn new(recorder: TraceRecorder<W>) -> Result<Self, TraceError> {
        Self::with_budget(recorder, QUEUE_BYTE_BUDGET)
    }

    pub(crate) fn with_budget(
        mut recorder: TraceRecorder<W>,
        byte_budget: usize,
    ) -> Result<Self, TraceError> {
        let (sender, receiver) = channel::<Queued>();
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queued_commands = Arc::new(AtomicUsize::new(0));
        let boosted = Arc::new(AtomicBool::new(false));
        let state = WorkerState {
            receiver,
            queued_bytes: queued_bytes.clone(),
            queued_commands: queued_commands.clone(),
            boosted: boosted.clone(),
            byte_budget,
        };
        let worker = std::thread::Builder::new()
            .name("shirusu-trace-writer".into())
            .spawn(move || {
                // Conversion uses spare CPU; Ring collection and the target come
                // first. When collection has to wait on a full queue it raises this
                // thread to Normal (a CPU-bound target would otherwise starve it
                // and the Ring would overflow), and it settles back here.
                shirusu_transport_win::set_current_thread_priority(
                    shirusu_transport_win::ThreadPriority::BelowNormal,
                );
                let mut totals = PipelineReport::default();
                // Events staged per context until a full output chunk, an
                // age limit, or an ordering barrier (review 2026-11-14 P1-2:
                // one Block per collection made millions of tiny Blocks and
                // an Index that eventually could not be written).
                let mut staged: Vec<Staged> = Vec::new();
                loop {
                    let received = if staged.is_empty() {
                        state.receiver.recv().ok()
                    } else {
                        let oldest = staged
                            .iter()
                            .map(|s| s.since)
                            .min()
                            .unwrap_or_else(Instant::now);
                        match state
                            .receiver
                            .recv_timeout(STAGE_MAX_AGE.saturating_sub(oldest.elapsed()))
                        {
                            Ok(q) => Some(q),
                            Err(RecvTimeoutError::Timeout) => {
                                flush_staged(
                                    &mut recorder,
                                    &mut totals,
                                    &state,
                                    &mut staged,
                                    true,
                                )?;
                                continue;
                            }
                            Err(RecvTimeoutError::Disconnected) => None,
                        }
                    };
                    let Some(queued) = received else { break };
                    let started = Instant::now();
                    let bytes = queued.bytes;
                    totals.metrics.commands_processed =
                        totals.metrics.commands_processed.saturating_add(1);
                    let mut barrier_reached: Option<Sender<()>> = None;
                    let (command, early_losses) = materialize(queued.command);
                    match command {
                        Command::Events(context, events) => {
                            totals.metrics.events_received = totals
                                .metrics
                                .events_received
                                .saturating_add(events.len() as u64);
                            let payload = events
                                .iter()
                                .fold(0usize, |n, e| n.saturating_add(e.payload.len()));
                            let slot = match staged.iter().position(|s| s.context == context) {
                                Some(i) if fits(&staged[i], events.len(), payload) => {
                                    totals.metrics.merged_event_commands =
                                        totals.metrics.merged_event_commands.saturating_add(1);
                                    i
                                }
                                Some(i) => {
                                    // Full: write what is staged, start anew.
                                    let full = staged.remove(i);
                                    write_staged(&mut recorder, &mut totals, &state, full)?;
                                    staged.push(Staged::new(context));
                                    staged.len() - 1
                                }
                                None => {
                                    staged.push(Staged::new(context));
                                    staged.len() - 1
                                }
                            };
                            let entry = &mut staged[slot];
                            entry.events.extend(events);
                            entry.payload = entry.payload.saturating_add(payload);
                            entry.bytes.push(bytes);
                            if entry.events.len() >= STAGE_MAX_EVENTS
                                || entry.payload >= STAGE_MAX_PAYLOAD
                            {
                                let full = staged.remove(slot);
                                write_staged(&mut recorder, &mut totals, &state, full)?;
                            }
                            // Staged events still count against the queue
                            // budget: never let them keep collection waiting.
                            let pressed = state.boosted.load(Ordering::Acquire)
                                || state.queued_bytes.load(Ordering::Acquire)
                                    > state.byte_budget / 2;
                            flush_staged(
                                &mut recorder,
                                &mut totals,
                                &state,
                                &mut staged,
                                !pressed,
                            )?;
                        }
                        Command::Chunk(..) => unreachable!("chunks are materialized on receipt"),
                        other => {
                            // Loss, environment and barrier commands keep their
                            // place relative to every event received before them.
                            flush_staged(&mut recorder, &mut totals, &state, &mut staged, false)?;
                            match other {
                                Command::Losses(losses, process, thread) => {
                                    recorder.record_losses(&losses, process, thread)?;
                                }
                                Command::Environment(environment) => {
                                    recorder.update_environment(&environment)?;
                                }
                                Command::Barrier(reached) => barrier_reached = Some(reached),
                                Command::Events(..) | Command::Chunk(..) => unreachable!(),
                            }
                            state.release(bytes);
                        }
                    }
                    if let Some(Command::Losses(losses, process, thread)) = early_losses {
                        // After the events they describe, like a Loss command.
                        flush_staged(&mut recorder, &mut totals, &state, &mut staged, false)?;
                        recorder.record_losses(&losses, process, thread)?;
                    }
                    // Acknowledge only after the barrier's own accounting is
                    // released: a caller reading the queue after the barrier
                    // must see it empty.
                    state.settle_priority();
                    if let Some(reached) = barrier_reached.take() {
                        let _ = reached.send(());
                    }
                    totals.metrics.conversion_wall_ns = totals
                        .metrics
                        .conversion_wall_ns
                        .saturating_add(elapsed_ns(started));
                }
                flush_staged(&mut recorder, &mut totals, &state, &mut staged, false)?;
                Ok((recorder, totals))
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            queued_bytes,
            queued_commands,
            byte_budget,
            queue_full_count: 0,
            peak_queued_bytes: 0,
            drain_wait_ns: 0,
            boosted,
        })
    }

    /// Collection is about to wait for the worker: make sure it is not left
    /// below the target's threads (review N3). Flag first, so a worker that
    /// settles concurrently can at worst leave itself at Normal.
    fn boost_worker(&self) {
        if !self.boosted.swap(true, Ordering::AcqRel) {
            if let Some(worker) = &self.worker {
                shirusu_transport_win::set_thread_priority(
                    worker,
                    shirusu_transport_win::ThreadPriority::Normal,
                );
            }
        }
    }

    fn join(&mut self) -> Finished<W> {
        drop(self.sender.take());
        let (recorder, mut report) = self
            .worker
            .take()
            .ok_or_else(|| failure("trace worker already joined"))?
            .join()
            .map_err(|_| failure("trace worker panicked"))??;
        report.metrics.queue_full_count = self.queue_full_count;
        report.metrics.drain_wait_ns = self.drain_wait_ns;
        report.metrics.peak_queued_bytes = self.peak_queued_bytes as u64;
        Ok((recorder, report))
    }

    fn failed_worker(&mut self) -> TraceError {
        match self.join() {
            Err(error) => error,
            Ok(_) => failure("trace worker stopped before finalization"),
        }
    }

    pub(crate) fn check_health(&mut self) -> Result<(), TraceError> {
        if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(self.failed_worker());
        }
        Ok(())
    }

    fn over_budget(&self, bytes: usize) -> bool {
        let queued = self.queued_bytes.load(Ordering::Acquire);
        // A single oversized command is accepted once the queue is empty.
        queued > 0 && queued.saturating_add(bytes) > self.byte_budget
    }

    fn send(&mut self, command: Command) -> Result<(), TraceError> {
        self.check_health()?;
        let bytes = command.queued_bytes();
        if self.over_budget(bytes) {
            self.queue_full_count = self.queue_full_count.saturating_add(1);
            self.boost_worker();
            let started = Instant::now();
            while self.over_budget(bytes) {
                self.check_health()?;
                std::thread::sleep(Duration::from_micros(200));
            }
            self.drain_wait_ns = self.drain_wait_ns.saturating_add(elapsed_ns(started));
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| failure("trace worker closed"))?;
        let queued = self.queued_bytes.fetch_add(bytes, Ordering::AcqRel) + bytes;
        self.peak_queued_bytes = self.peak_queued_bytes.max(queued);
        self.queued_commands.fetch_add(1, Ordering::AcqRel);
        if sender.send(Queued { command, bytes }).is_err() {
            return Err(self.failed_worker());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_owned_batch_with_args(
        &mut self,
        context: &TraceBatchContext,
        events: Vec<ReceivedEvent>,
    ) -> Result<(), TraceError> {
        self.send(Command::Events(*context, events))
    }

    /// Queue a collected chunk for validation by `worker`, then conversion.
    pub(crate) fn record_chunk(
        &mut self,
        context: &TraceBatchContext,
        worker: &SharedDrainWorker,
        chunk: CommittedChunk,
    ) -> Result<(), TraceError> {
        self.send(Command::Chunk(*context, Arc::clone(worker), chunk))
    }

    pub(crate) fn record_losses(
        &mut self,
        losses: Vec<LossEvent>,
        process: u64,
        thread: u64,
    ) -> Result<(), TraceError> {
        self.send(Command::Losses(losses, process, thread))
    }

    pub(crate) fn update_environment(
        &mut self,
        environment: &CaptureEnvironment,
    ) -> Result<(), TraceError> {
        self.send(Command::Environment(environment.clone()))
    }

    /// Wait until every command sent before this call has been processed, so
    /// that validation state (DrainWorker) reflects every collected chunk.
    pub(crate) fn barrier(&mut self) -> Result<(), TraceError> {
        let (reached, wait) = channel();
        self.send(Command::Barrier(reached))?;
        if wait.recv().is_err() {
            return Err(self.failed_worker());
        }
        Ok(())
    }

    // Closing the queue drains every accepted command before the caller can
    // inspect totals or write Finalization. A worker error forbids finalization.
    pub(crate) fn finish(mut self) -> Finished<W> {
        self.join()
    }
}

impl<W: DurableWrite + Send + 'static> Drop for TracePipeline<W> {
    fn drop(&mut self) {
        // Abandoning a session must not leave a writer mutating the file after
        // its owner returns. No Finalization is synthesized on this path.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn failure(message: &str) -> TraceError {
    std::io::Error::other(message).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_convert::RecordMode;
    use crate::IntegrityReport;
    use shirusu_hook::{
        api::{api_by_id, API_CLOSE_HANDLE},
        capture,
    };
    use shirusu_trace::proto::SessionMetadata;
    use shirusu_trace::schema::ValueCapture;
    use shirusu_transport::descriptor::{CaptureState, EventDescriptor, EventKind};
    use std::io::{self, Write};
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        mpsc, Arc, Mutex,
    };

    fn environment() -> CaptureEnvironment {
        CaptureEnvironment {
            session: SessionMetadata {
                session_id: 1,
                created_by: "pipeline test".into(),
                qpc_frequency: 1000,
            },
            ..Default::default()
        }
    }
    fn context() -> TraceBatchContext {
        TraceBatchContext {
            session_id: 1,
            process_id: 1,
            raw_pid: 10,
            thread_id: 1,
            qpc_frequency: 1000,
        }
    }
    fn recorder<W: DurableWrite>(writer: W, mode: RecordMode) -> TraceRecorder<W> {
        let mut recorder = TraceRecorder::from_environment(writer, environment()).unwrap();
        let api = api_by_id(API_CLOSE_HANDLE).unwrap();
        recorder.register_schema(api.enter_schema()).unwrap();
        recorder.register_schema(api.leave_schema()).unwrap();
        recorder.set_record_mode(mode);
        recorder
    }
    fn events(call: u64) -> Vec<ReceivedEvent> {
        let api = api_by_id(API_CLOSE_HANDLE).unwrap();
        let mut enter = capture::close_handle_enter(42);
        // Field incompleteness must survive asynchronous accumulation too.
        if call == 2 {
            enter[0].capture = ValueCapture::Unsupported;
        }
        let payloads = [
            capture::encode_enter(api, &enter).unwrap(),
            capture::encode_leave(api, &capture::close_handle_leave(1, 0)).unwrap(),
        ];
        payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let mut descriptor = EventDescriptor::new(
                    if i == 0 {
                        EventKind::CallEnter
                    } else {
                        EventKind::CallLeave
                    },
                    call * 2 - 1 + i as u64,
                );
                descriptor.flags = CaptureState::Captured.to_flags();
                descriptor.api_id = API_CLOSE_HANDLE;
                descriptor.schema_id = if i == 0 {
                    api.enter_schema_id()
                } else {
                    api.leave_schema_id()
                };
                descriptor.call_id = call;
                descriptor.timestamp_qpc = call * 10 + i as u64;
                descriptor.payload_len = payload.len() as u32;
                ReceivedEvent {
                    descriptor,
                    payload,
                }
            })
            .collect()
    }

    #[test]
    fn asynchronous_output_matches_synchronous_in_every_mode() {
        for mode in [
            RecordMode::Full,
            RecordMode::Detailed,
            RecordMode::Profile,
            RecordMode::Filtered {
                apis: [API_CLOSE_HANDLE].into_iter().collect(),
            },
            RecordMode::Filtered {
                apis: Default::default(),
            },
        ] {
            let mut direct = recorder(Vec::new(), mode.clone());
            let mut pipeline = TracePipeline::new(recorder(Vec::new(), mode)).unwrap();
            let mut expected = ArgsConversionStats::default();
            for call in 1..=2 {
                let stats = direct
                    .record_owned_batch_with_args(&context(), events(call))
                    .unwrap();
                expected.args_attached += stats.args_attached;
                expected.args_incomplete += stats.args_incomplete;
                expected.args_fallback_blob += stats.args_fallback_blob;
                pipeline
                    .record_owned_batch_with_args(&context(), events(call))
                    .unwrap();
                let mut env = environment();
                env.capture_config = format!("update={call}");
                direct.update_environment(&env).unwrap();
                pipeline.update_environment(&env).unwrap();
                let losses = vec![LossEvent::SequenceGap { count: call }];
                direct.record_losses(&losses, 1, 1).unwrap();
                pipeline.record_losses(losses, 1, 1).unwrap();
            }
            let (queued, actual) = pipeline.finish().unwrap();
            assert_eq!(expected, actual.args);
            assert_eq!(actual.metrics.events_received, 4);
            assert_eq!(actual.metrics.commands_processed, 6);
            assert_eq!(direct.profile_summary(), queued.profile_summary());
            assert_eq!(
                direct.finish(&IntegrityReport::default()).unwrap(),
                queued.finish(&IntegrityReport::default()).unwrap()
            );
        }
    }

    struct ControlledWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        mode: Arc<AtomicU8>,
        blocked: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    impl Write for ControlledWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.mode.swap(0, Ordering::SeqCst) {
                1 => return Err(io::Error::other("injected disk failure")),
                2 => panic!("injected worker panic"),
                3 => {
                    self.blocked.send(()).unwrap();
                    self.resume.recv().unwrap();
                }
                _ => {}
            }
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl DurableWrite for ControlledWriter {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn controlled() -> (ControlledWriter, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (blocked, ready) = mpsc::channel();
        let (resume, wait) = mpsc::channel();
        (
            ControlledWriter {
                bytes: Default::default(),
                mode: Arc::new(AtomicU8::new(0)),
                blocked,
                resume: wait,
            },
            ready,
            resume,
        )
    }

    #[test]
    fn validator_losses_are_written_before_stop() {
        // P2-3: 溜まった欠落記録は停止を待たずに Trace へ書く。
        use shirusu_transport::clock::{Clock, ManualClock};
        use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
        use shirusu_transport::RingConfig;
        let cfg = RingConfig::new(16, 512);
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut ring = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: Duration::ZERO,
                    ..Default::default()
                },
                clock,
            )
        };
        let mut collector = unsafe { crate::CommittedRangeCollector::new(region.base(), cfg) };
        let mut validator = DrainWorker::for_chunks(cfg, 1);
        validator.loss_events.extend(
            (0..LOSS_FLUSH_RECORDS as u64).map(|count| LossEvent::SequenceGap { count: count + 1 }),
        );
        let shared = RingValidation::new(validator);
        ring.write(EventInput {
            kind: EventKind::CallEnter,
            api_id: API_CLOSE_HANDLE,
            schema_id: 1,
            call_id: 1,
            parent_call_id: 0,
            payload: b"",
            capture_state: CaptureState::Captured,
            global_order: 0,
        });
        let chunk = collector.collect(|| {}).expect("one event committed");
        let (writer, _, _) = controlled();
        let bytes = writer.bytes.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        pipeline.record_chunk(&context(), &shared, chunk).unwrap();
        pipeline.barrier().unwrap();
        {
            let validator = shared.lock();
            assert!(validator.loss_events.is_empty());
            assert_eq!(validator.loss_event_count(), LOSS_FLUSH_RECORDS as u64);
        }
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert!(trace.finalization.is_none(), "still recording");
        assert_eq!(trace.loss_records.len(), LOSS_FLUSH_RECORDS);
        assert_eq!(
            trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
            1
        );
        drop(pipeline);
    }

    #[test]
    fn conversion_failure_or_panic_cannot_reach_finalization() {
        for mode in [1, 2] {
            let (writer, _, _) = controlled();
            let flag = writer.mode.clone();
            let bytes = writer.bytes.clone();
            let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
            flag.store(mode, Ordering::SeqCst);
            let _ = pipeline.update_environment(&environment());
            let error = match pipeline.finish() {
                Err(e) => e,
                Ok(_) => panic!("worker failure accepted"),
            };
            assert!(error.to_string().contains(if mode == 1 {
                "injected disk failure"
            } else {
                "worker panicked"
            }));
            let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
            assert!(trace.finalization.is_none());
        }
    }

    #[test]
    fn idle_poll_observes_original_worker_error() {
        let (writer, _, _) = controlled();
        let flag = writer.mode.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        flag.store(1, Ordering::SeqCst);
        let _ = pipeline.update_environment(&environment());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !pipeline.worker.as_ref().unwrap().is_finished() {
            assert!(std::time::Instant::now() < deadline, "worker did not stop");
            std::thread::yield_now();
        }
        assert!(pipeline
            .check_health()
            .unwrap_err()
            .to_string()
            .contains("injected disk failure"));
        assert!(pipeline.finish().is_err());
    }

    #[test]
    fn waiting_on_a_full_queue_boosts_the_worker_until_it_drains() {
        let (writer, blocked, resume) = controlled();
        let flag = writer.mode.clone();
        let one = Command::Events(context(), events(1)).queued_bytes();
        let mut pipeline =
            TracePipeline::with_budget(recorder(writer, RecordMode::Full), one * 2).unwrap();
        flag.store(3, Ordering::SeqCst);
        pipeline.update_environment(&environment()).unwrap();
        blocked
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for call in 1..=2 {
            pipeline
                .record_owned_batch_with_args(&context(), events(call))
                .unwrap();
        }
        assert!(!pipeline.boosted.load(Ordering::Acquire), "no wait yet");
        let resumer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            resume.send(()).unwrap();
        });
        // Over budget: the collector boosts the worker before it waits.
        pipeline
            .record_owned_batch_with_args(&context(), events(3))
            .unwrap();
        assert!(pipeline.queue_full_count >= 1);
        resumer.join().unwrap();
        pipeline.barrier().unwrap();
        assert!(!pipeline.boosted.load(Ordering::Acquire));
        pipeline.finish().unwrap();
    }

    #[test]
    fn slow_writer_bounds_queue_and_preserves_every_accepted_batch() {
        const BATCHES: u64 = 16;
        let (writer, blocked, resume) = controlled();
        let flag = writer.mode.clone();
        let one = Command::Events(context(), events(1)).queued_bytes();
        // Room for four batches while the writer is blocked.
        let mut pipeline =
            TracePipeline::with_budget(recorder(writer, RecordMode::Full), one * 4).unwrap();
        flag.store(3, Ordering::SeqCst);
        pipeline.update_environment(&environment()).unwrap();
        blocked
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for call in 1..=4 {
            pipeline
                .record_owned_batch_with_args(&context(), events(call))
                .unwrap();
        }
        assert!(pipeline.over_budget(one), "budget must bound the queue");
        let resumer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            resume.send(()).unwrap();
        });
        for call in 5..=BATCHES {
            pipeline
                .record_owned_batch_with_args(&context(), events(call))
                .unwrap();
        }
        resumer.join().unwrap();
        // Waiting on a full queue boosted the worker (N3); once it drained
        // the queue it settled back.
        let boosted = pipeline.boosted.clone();
        let (recorder, stats) = pipeline.finish().unwrap();
        assert!(
            !boosted.load(Ordering::Acquire),
            "drained worker returns to below-normal"
        );
        assert!(stats.metrics.queue_full_count >= 1);
        assert_eq!(stats.args.args_attached, BATCHES as usize * 2);
        assert_eq!(stats.metrics.events_received, BATCHES * 2);
        assert_eq!(stats.metrics.commands_processed, BATCHES + 1);
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(trace.finalization.unwrap().total_events, BATCHES * 2);
        assert_eq!(
            trace
                .batches
                .iter()
                .flat_map(|b| b.events.iter().map(|e| e.call_id))
                .collect::<Vec<_>>(),
            (1..=BATCHES).flat_map(|c| [c, c]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn barrier_waits_for_every_queued_command() {
        let (writer, blocked, resume) = controlled();
        let flag = writer.mode.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        flag.store(3, Ordering::SeqCst);
        pipeline.update_environment(&environment()).unwrap();
        blocked
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        pipeline
            .record_owned_batch_with_args(&context(), events(1))
            .unwrap();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resumer = {
            let done = done.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                assert!(
                    !done.load(Ordering::SeqCst),
                    "barrier passed a blocked writer"
                );
                resume.send(()).unwrap();
            })
        };
        pipeline.barrier().unwrap();
        done.store(true, Ordering::SeqCst);
        resumer.join().unwrap();
        assert_eq!(pipeline.queued_commands.load(Ordering::SeqCst), 0);
        assert_eq!(pipeline.queued_bytes.load(Ordering::SeqCst), 0);
        let (_, stats) = pipeline.finish().unwrap();
        assert_eq!(stats.metrics.events_received, 2);
    }

    #[test]
    fn coalescing_preserves_context_boundaries_and_event_order() {
        let (writer, blocked, resume) = controlled();
        let flag = writer.mode.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        flag.store(3, Ordering::SeqCst);
        pipeline.update_environment(&environment()).unwrap();
        blocked
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for (call, thread_id) in [(1, 1), (2, 1), (3, 2), (4, 1)] {
            let mut ctx = context();
            ctx.thread_id = thread_id;
            pipeline
                .record_owned_batch_with_args(&ctx, events(call))
                .unwrap();
        }
        resume.send(()).unwrap();
        let (recorder, stats) = pipeline.finish().unwrap();
        // Each context collects its own events (P1-2); 2 and 4 join 1.
        assert_eq!(stats.metrics.merged_event_commands, 2);
        // A tiny queue is not a backlog (P2-1): every group is compressed.
        assert_eq!(stats.metrics.compression_bypass_requests, 0);
        assert_eq!(stats.metrics.commands_processed, 5);
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(
            trace
                .batches
                .iter()
                .map(|b| b.events.len())
                .collect::<Vec<_>>(),
            [6, 2]
        );
        assert_eq!(
            trace
                .batches
                .iter()
                .map(|b| b.thread_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(
            trace
                .batches
                .iter()
                .flat_map(|b| b.events.iter().map(|e| e.call_id))
                .collect::<Vec<_>>(),
            [1, 1, 2, 2, 4, 4, 3, 3]
        );
    }

    /// P1-2: a sparse stream is not written one Block per collection; the
    /// age limit writes it without waiting for a barrier.
    #[test]
    fn sparse_events_share_a_block_and_age_out() {
        let (writer, _blocked, _resume) = controlled();
        let bytes = writer.bytes.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        for call in 1..=20 {
            pipeline
                .record_owned_batch_with_args(&context(), events(call))
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let len_before = bytes.lock().unwrap().len();
        while bytes.lock().unwrap().len() == len_before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            bytes.lock().unwrap().len() > len_before,
            "aged group written"
        );
        let (recorder, stats) = pipeline.finish().unwrap();
        assert_eq!(stats.metrics.merged_event_commands, 19);
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(trace.batches.len(), 1);
        assert_eq!(trace.batches[0].events.len(), 40);
    }

    #[test]
    fn coalescing_respects_event_and_payload_limits() {
        for oversized_payload in [false, true] {
            let (writer, blocked, resume) = controlled();
            let flag = writer.mode.clone();
            let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
            flag.store(3, Ordering::SeqCst);
            pipeline.update_environment(&environment()).unwrap();
            blocked
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            let mut first = if oversized_payload {
                events(1)
            } else {
                (1..=2048).flat_map(events).collect::<Vec<_>>()
            };
            if oversized_payload {
                // Valid transport payload may be opaque to the schema converter.
                first[0].payload = vec![0; 1024 * 1024];
                first[0].descriptor.payload_len = first[0].payload.len() as u32;
            }
            let first_len = first.len();
            pipeline
                .record_owned_batch_with_args(&context(), first)
                .unwrap();
            for call in 2049..=2051 {
                pipeline
                    .record_owned_batch_with_args(&context(), events(call))
                    .unwrap();
            }
            resume.send(()).unwrap();
            let (recorder, stats) = pipeline.finish().unwrap();
            assert_eq!(stats.metrics.merged_event_commands, 2);
            assert_eq!(stats.metrics.events_received, (first_len + 6) as u64);
            let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
            let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
            assert_eq!(
                trace
                    .batches
                    .iter()
                    .map(|b| b.events.len())
                    .collect::<Vec<_>>(),
                [first_len, 6]
            );
        }
    }

    #[test]
    #[ignore = "manual release measurement, not a timing assertion"]
    fn measure_queued_conversion() {
        for round in 0..5 {
            let mut pipeline = TracePipeline::new(recorder(Vec::new(), RecordMode::Full)).unwrap();
            let batches: Vec<_> = (0..2000)
                .map(|batch| {
                    (1..=64)
                        .flat_map(|i| events(batch * 64 + i))
                        .collect::<Vec<_>>()
                })
                .collect();
            let start = Instant::now();
            for batch in batches {
                pipeline
                    .record_owned_batch_with_args(&context(), batch)
                    .unwrap();
            }
            let (recorder, stats) = pipeline.finish().unwrap();
            let bytes = recorder.finish(&IntegrityReport::default()).unwrap();
            println!(
                "queued_conversion round={round} elapsed_ms={} bytes={} merged={} compression_bypasses={}",
                start.elapsed().as_secs_f64() * 1000.0,
                bytes.len(),
                stats.metrics.merged_event_commands,
                stats.metrics.compression_bypass_requests
            );
        }
    }

    #[test]
    fn dropping_session_joins_writer_without_inventing_finalization() {
        let (writer, _, _) = controlled();
        let bytes = writer.bytes.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        pipeline
            .record_owned_batch_with_args(&context(), events(1))
            .unwrap();
        drop(pipeline);
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert!(trace.finalization.is_none());
        assert_eq!(
            trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
            2
        );
    }
}
