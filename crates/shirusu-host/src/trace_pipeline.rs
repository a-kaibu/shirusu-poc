//! Bounded ownership transfer from Ring drain to Trace conversion/compression.
//! Only validated, owned events cross this boundary. The worker never sees a
//! shared Ring pointer. FIFO order includes environment updates and loss records.
use crate::trace_convert::{ArgsConversionStats, TraceBatchContext, TraceRecorder};
use crate::LossEvent;
use shirusu_trace::{proto::CaptureEnvironment, DurableWrite, TraceError};
use shirusu_transport::ring::ReceivedEvent;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread::JoinHandle;

// A producer holds at most one drained batch while waiting; the worker owns
// one more. Each event batch is bounded by its Ring's descriptor/payload limits.
pub(crate) const QUEUED_BATCHES: usize = 4;

enum Command {
    Events(TraceBatchContext, Vec<ReceivedEvent>),
    Losses(Vec<LossEvent>, u64, u64),
    Environment(CaptureEnvironment),
}
type Finished<W> = Result<(TraceRecorder<W>, ArgsConversionStats), TraceError>;

pub(crate) struct TracePipeline<W: DurableWrite + Send + 'static> {
    sender: Option<SyncSender<Command>>,
    worker: Option<JoinHandle<Finished<W>>>,
}

impl<W: DurableWrite + Send + 'static> TracePipeline<W> {
    pub(crate) fn new(mut recorder: TraceRecorder<W>) -> Result<Self, TraceError> {
        let (sender, receiver) = sync_channel(QUEUED_BATCHES);
        let worker = std::thread::Builder::new()
            .name("shirusu-trace-writer".into())
            .spawn(move || {
                let mut totals = ArgsConversionStats::default();
                for command in receiver {
                    match command {
                        Command::Events(context, events) => {
                            let stats = recorder.record_owned_batch_with_args(&context, events)?;
                            totals.args_attached += stats.args_attached;
                            totals.args_incomplete += stats.args_incomplete;
                            totals.args_fallback_blob += stats.args_fallback_blob;
                        }
                        Command::Losses(losses, process, thread) => {
                            recorder.record_losses(&losses, process, thread)?;
                        }
                        Command::Environment(environment) => {
                            recorder.update_environment(&environment)?;
                        }
                    }
                }
                Ok((recorder, totals))
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    fn join(&mut self) -> Finished<W> {
        drop(self.sender.take());
        self.worker
            .take()
            .ok_or_else(|| failure("trace worker already joined"))?
            .join()
            .map_err(|_| failure("trace worker panicked"))?
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
        if self
            .sender
            .as_ref()
            .ok_or_else(|| failure("trace worker closed"))?
            .send(command)
            .is_err()
        {
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
            assert_eq!(expected, actual);
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
        assert_eq!(stats.args_attached, QUEUED_BATCHES * 2);
        let bytes = recorder.finish(&IntegrityReport::default()).unwrap().bytes;
        let trace = shirusu_trace::read_trace(&bytes.lock().unwrap()).unwrap();
        assert_eq!(
            trace.finalization.unwrap().total_events,
            (QUEUED_BATCHES * 2) as u64
        );
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
