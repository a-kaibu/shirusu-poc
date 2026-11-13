//! Bounded ownership transfer from Ring drain to Trace conversion/compression.
//! Only validated, owned events cross this boundary. The worker never sees a
//! shared Ring pointer. FIFO order includes environment updates and loss records.
use crate::trace_convert::{ArgsConversionStats, TraceBatchContext, TraceRecorder};
use crate::LossEvent;
use shirusu_trace::{proto::CaptureEnvironment, DurableWrite, TraceError};
use shirusu_transport::ring::ReceivedEvent;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::Instant;

// A producer holds at most one drained batch while waiting; the worker owns
// a bounded group and at most one lookahead command. Individual batches retain
// their Ring descriptor/payload bounds; coalescing never waits for more input.
pub(crate) const QUEUED_BATCHES: usize = 4;

enum Command {
    Events(TraceBatchContext, Vec<ReceivedEvent>),
    Losses(Vec<LossEvent>, u64, u64),
    Environment(CaptureEnvironment),
}
/// Wall-clock diagnostics, not additive CPU attribution or completeness proof.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostPipelineStats {
    pub commands_processed: u64,
    pub events_received: u64,
    pub merged_event_commands: u64,
    pub conversion_wall_ns: u64,
    pub queue_full_count: u64,
    pub drain_wait_ns: u64,
}

#[derive(Default)]
pub(crate) struct PipelineReport {
    pub args: ArgsConversionStats,
    pub metrics: HostPipelineStats,
}
type Finished<W> = Result<(TraceRecorder<W>, PipelineReport), TraceError>;

pub(crate) struct TracePipeline<W: DurableWrite + Send + 'static> {
    sender: Option<SyncSender<Command>>,
    worker: Option<JoinHandle<Finished<W>>>,
    queue_full_count: u64,
    drain_wait_ns: u64,
}

impl<W: DurableWrite + Send + 'static> TracePipeline<W> {
    pub(crate) fn new(mut recorder: TraceRecorder<W>) -> Result<Self, TraceError> {
        let (sender, receiver) = sync_channel(QUEUED_BATCHES);
        let worker = std::thread::Builder::new()
            .name("shirusu-trace-writer".into())
            .spawn(move || {
                let mut totals = PipelineReport::default();
                let mut pending = None;
                while let Some(command) = pending.take().or_else(|| receiver.recv().ok()) {
                    let started = Instant::now();
                    match command {
                        Command::Events(context, mut events) => {
                            let mut payload_bytes = events
                                .iter()
                                .fold(0usize, |n, e| n.saturating_add(e.payload.len()));
                            for _ in 0..QUEUED_BATCHES {
                                // Preserve context, loss and environment boundaries. Do not
                                // delay a sparse stream to fill a larger output chunk.
                                let Ok(next) = receiver.try_recv() else { break };
                                match next {
                                    Command::Events(next_context, next_events)
                                        if next_context == context
                                            && events.len().saturating_add(next_events.len())
                                                <= 4096
                                            && payload_bytes.saturating_add(
                                                next_events.iter().fold(0usize, |n, e| {
                                                    n.saturating_add(e.payload.len())
                                                }),
                                            ) <= 1024 * 1024 =>
                                    {
                                        payload_bytes += next_events
                                            .iter()
                                            .map(|e| e.payload.len())
                                            .sum::<usize>();
                                        events.extend(next_events);
                                        totals.metrics.commands_processed =
                                            totals.metrics.commands_processed.saturating_add(1);
                                        totals.metrics.merged_event_commands =
                                            totals.metrics.merged_event_commands.saturating_add(1);
                                    }
                                    other => {
                                        pending = Some(other);
                                        break;
                                    }
                                }
                            }
                            totals.metrics.events_received = totals
                                .metrics
                                .events_received
                                .saturating_add(events.len() as u64);
                            let stats = recorder.record_owned_batch_with_args(&context, events)?;
                            totals.args.args_attached += stats.args_attached;
                            totals.args.args_incomplete += stats.args_incomplete;
                            totals.args.args_fallback_blob += stats.args_fallback_blob;
                        }
                        Command::Losses(losses, process, thread) => {
                            recorder.record_losses(&losses, process, thread)?;
                        }
                        Command::Environment(environment) => {
                            recorder.update_environment(&environment)?;
                        }
                    }
                    totals.metrics.commands_processed =
                        totals.metrics.commands_processed.saturating_add(1);
                    totals.metrics.conversion_wall_ns = totals
                        .metrics
                        .conversion_wall_ns
                        .saturating_add(elapsed_ns(started));
                }
                Ok((recorder, totals))
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            queue_full_count: 0,
            drain_wait_ns: 0,
        })
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

    fn send(&mut self, command: Command) -> Result<(), TraceError> {
        self.check_health()?;
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| failure("trace worker closed"))?;
        let command = match sender.try_send(command) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(command)) => command,
            Err(TrySendError::Disconnected(_)) => return Err(self.failed_worker()),
        };
        self.queue_full_count = self.queue_full_count.saturating_add(1);
        let started = Instant::now();
        let result = sender.send(command);
        self.drain_wait_ns = self.drain_wait_ns.saturating_add(elapsed_ns(started));
        if result.is_err() {
            return Err(self.failed_worker());
        }
        Ok(())
    }

    pub(crate) fn record_owned_batch_with_args(
        &mut self,
        context: &TraceBatchContext,
        events: Vec<ReceivedEvent>,
    ) -> Result<(), TraceError> {
        self.send(Command::Events(*context, events))
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
    fn slow_writer_bounds_queue_and_preserves_every_accepted_batch() {
        let (writer, blocked, resume) = controlled();
        let flag = writer.mode.clone();
        let mut pipeline = TracePipeline::new(recorder(writer, RecordMode::Full)).unwrap();
        flag.store(3, Ordering::SeqCst);
        pipeline.update_environment(&environment()).unwrap();
        blocked
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for call in 1..=QUEUED_BATCHES as u64 {
            pipeline
                .record_owned_batch_with_args(&context(), events(call))
                .unwrap();
        }
        assert!(matches!(
            pipeline
                .sender
                .as_ref()
                .unwrap()
                .try_send(Command::Events(context(), events(5))),
            Err(mpsc::TrySendError::Full(_))
        ));
        resume.send(()).unwrap();
        let (recorder, stats) = pipeline.finish().unwrap();
        assert_eq!(
            stats.metrics.merged_event_commands,
            (QUEUED_BATCHES - 1) as u64
        );
        assert_eq!(stats.args.args_attached, QUEUED_BATCHES * 2);
        assert_eq!(stats.metrics.events_received, (QUEUED_BATCHES * 2) as u64);
        assert_eq!(
            stats.metrics.commands_processed,
            (QUEUED_BATCHES + 1) as u64
        );
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(trace.batches.len(), 1);
        assert_eq!(
            trace.finalization.unwrap().total_events,
            (QUEUED_BATCHES * 2) as u64
        );
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
        assert_eq!(stats.metrics.merged_event_commands, 1);
        assert_eq!(stats.metrics.commands_processed, 5);
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(
            trace
                .batches
                .iter()
                .map(|b| b.events.len())
                .collect::<Vec<_>>(),
            [4, 2, 2]
        );
        assert_eq!(
            trace
                .batches
                .iter()
                .map(|b| b.thread_id)
                .collect::<Vec<_>>(),
            [1, 2, 1]
        );
        assert_eq!(
            trace
                .batches
                .iter()
                .flat_map(|b| b.events.iter().map(|e| e.call_id))
                .collect::<Vec<_>>(),
            [1, 1, 2, 2, 3, 3, 4, 4]
        );
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
                "queued_conversion round={round} elapsed_ms={} bytes={} merged={}",
                start.elapsed().as_secs_f64() * 1000.0,
                bytes.len(),
                stats.metrics.merged_event_commands
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
