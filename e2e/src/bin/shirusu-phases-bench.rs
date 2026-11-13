//! Component measurements, not additive attribution of an injected application.
//! Runs production functions without patching an application or notifying a Host.
use shirusu_agent::{Agent, RecordResult};
use shirusu_hook::{
    api::api_by_import,
    capture,
    runtime::{DetourFlight, HookRuntime, ReentrancyGuard, RuntimeSlot},
};
use shirusu_host::{
    trace_convert::{TraceBatchContext, TraceRecorder},
    CommittedRangeCollector, DrainWorker,
};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_transport::{
    clock::TimestampSource, context::HostMonitor, layout::RingConfig, ring::WriteOutcome,
    slot::SlotPool,
};
use std::{hint::black_box, sync::Arc, time::Instant};

const OPS: usize = 100_000;

#[cfg(not(windows))]
struct PortableInterpolated(shirusu_transport::SystemTimestampSource);
#[cfg(not(windows))]
impl TimestampSource for PortableInterpolated {
    fn now_qpc(&self) -> u64 {
        self.0.now_qpc()
    }
    fn frequency(&self) -> u64 {
        self.0.frequency()
    }
    fn tsc_interpolation(&self) -> bool {
        shirusu_transport::tsc::invariant_tsc_available()
    }
}
const ROUNDS: usize = 5;

fn measure(name: &str, mut operation: impl FnMut()) {
    for _ in 0..1000 {
        operation();
    }
    let mut samples = Vec::new();
    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..OPS {
            operation();
        }
        samples.push(start.elapsed().as_nanos() as f64 / OPS as f64);
    }
    report(name, &mut samples, "operation");
}
fn report(name: &str, samples: &mut [f64], unit: &str) {
    samples.sort_by(f64::total_cmp);
    println!(
        "phase={name} median_ns_per_{unit}={:.2} min={:.2} max={:.2}",
        samples[samples.len() / 2],
        samples[0],
        samples[samples.len() - 1]
    );
}
fn published(result: RecordResult) {
    assert!(
        matches!(
            result,
            RecordResult::Written(WriteOutcome::Published { .. })
        ),
        "measurement must not lose events: {result:?}"
    );
}
fn main() {
    println!(
        "shirusu-phases-bench os={} arch={} rounds={ROUNDS} ops={OPS}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("scope=isolated-components; no detour patch, SEH boundary, cross-process notification, disk durability or competing producer; measurements overlap and must not be added");
    let cfg = RingConfig::new(4096, 1024 * 1024);
    #[cfg(windows)]
    let timestamps: Arc<dyn TimestampSource> =
        Arc::new(shirusu_transport_win::QpcTimestampSource::new());
    // Off Windows, mirror the Windows source's choice: interpolate the portable
    // clock with the TSC when the CPU reports an invariant TSC.
    #[cfg(not(windows))]
    let timestamps: Arc<dyn TimestampSource> = Arc::new(PortableInterpolated(
        shirusu_transport::SystemTimestampSource::new(),
    ));
    let agent = Arc::new(
        Agent::new(
            Arc::new(SlotPool::new(2)),
            cfg,
            Arc::new(HostMonitor::always_alive()),
        )
        .with_timestamp_source(timestamps.clone()),
    );
    let rt = Arc::new(HookRuntime::new(agent.clone(), Vec::new(), None));
    let slot = RuntimeSlot::new();
    assert!(slot.register(rt.clone()).is_ok());
    rt.ensure_thread(1);
    let api = api_by_import("kernel32.dll", "HeapAlloc").unwrap();
    let args = [0x1234, 0, 64];
    for id in [api.api_id, shirusu_hook::api::API_COUNT as u32] {
        measure(&format!("api_lookup_id_{id}"), || {
            black_box(shirusu_hook::api::api_by_id(black_box(id)));
        });
    }
    measure("runtime_target_policy_by_name", || {
        black_box(black_box(&rt).should_suppress_api(black_box(api.module)));
    });
    measure("runtime_target_policy_by_id", || {
        black_box(black_box(&rt).should_suppress_api_id(black_box(api.api_id)));
    });
    measure("runtime_passthrough_rwlock_arc", || {
        drop(black_box(slot.for_detour()));
    });
    {
        let _guard = ReentrancyGuard::try_enter().unwrap();
        measure("runtime_tls_weak_upgrade", || {
            drop(black_box(slot.for_detour()));
        });
    }
    measure("reentrancy_guard", || {
        drop(black_box(ReentrancyGuard::try_enter().unwrap()));
    });
    measure("in_flight_arc", || {
        drop(black_box(DetourFlight::begin(&rt).unwrap()));
    });
    measure("registered_thread_cache", || rt.ensure_thread(black_box(1)));
    measure("call_id_atomic", || {
        black_box(rt.alloc_call_id());
    });
    let mut notify = shirusu_transport::notify::PublishNotifyTracker::new();
    measure("notification_watermark", || {
        black_box(notify.after_publish(
            black_box(49),
            black_box(50),
            black_box(100),
            black_box(50),
            false,
        ));
    });
    measure("timestamp", || {
        black_box(timestamps.now_qpc());
    });
    // The Ring writer's event clock: TSC interpolation of the same source when
    // the source enables it (Windows with an invariant TSC), else direct reads.
    println!(
        "event_clock tsc_interpolation={} invariant_tsc={}",
        timestamps.tsc_interpolation(),
        shirusu_transport::tsc::invariant_tsc_available()
    );
    let mut event_clock = shirusu_transport::tsc::EventTimestamper::new(timestamps.clone());
    measure("event_timestamp", || {
        black_box(event_clock.now());
    });
    println!("event_clock interpolating={}", event_clock.interpolating());
    measure("scalar_enter_encode", || {
        black_box(capture::encode_generic_enter::<3>(api, black_box(&args)));
    });
    measure("scalar_leave_encode", || {
        black_box(capture::encode_generic_leave(
            api,
            black_box(0x5678),
            black_box(0),
        ));
    });
    let enter_schema = api.enter_schema();
    let leave_schema = api.leave_schema();
    let enter_types = shirusu_trace::schema::schema_types(&enter_schema).unwrap();
    let leave_types = shirusu_trace::schema::schema_types(&leave_schema).unwrap();
    let enter_payload = capture::encode_generic_enter::<3>(api, &args);
    let leave_payload = capture::encode_generic_leave(api, 0x5678, 0);
    measure("scalar_enter_validate", || {
        assert!(
            black_box(shirusu_trace::compact::validate_values_completeness(
                black_box(&enter_types),
                black_box(enter_payload.as_bytes())
            ))
            .unwrap()
        );
    });
    measure("scalar_leave_validate", || {
        assert!(
            black_box(shirusu_trace::compact::validate_values_completeness(
                black_box(&leave_types),
                black_box(leave_payload.as_bytes())
            ))
            .unwrap()
        );
    });
    #[cfg(windows)]
    measure("last_error_read_restore", || {
        let value = shirusu_hook::last_error::get();
        shirusu_hook::last_error::set(black_box(value));
    });

    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        measure("thread_id_windows_api_unhooked", || {
            black_box(unsafe { GetCurrentThreadId() });
        });
        measure("thread_id_direct_teb", || {
            black_box(shirusu_hook::thread_id::current());
        });
    }

    // Batch sizes stay below capacity. Production sizes are unchanged; no wait
    // for a consumer is measured here. Compare with native-performance losses.
    // SAFETY: Agent owns this registered ring until after worker is dropped;
    // only this thread produces and this worker consumes it.
    let base = unsafe { agent.thread_region_base(1) }.unwrap();
    // Production path: the collection thread copies and releases committed
    // contents; the Trace worker validates them before conversion.
    let mut collector = unsafe { CommittedRangeCollector::new(base, cfg) };
    let mut worker = DrainWorker::for_chunks(cfg, 1);
    for (owned, calls) in [false, true]
        .into_iter()
        .flat_map(|owned| [64usize, 512, 1536].map(|calls| (owned, calls)))
    {
        println!(
            "payload_ownership={} batch_events={}",
            if owned { "transferred" } else { "borrowed" },
            2 * calls
        );
        let mut produce = Vec::new();
        let mut collect = Vec::new();
        let mut drain = Vec::new();
        let mut convert = Vec::new();
        let mut release = Vec::new();
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 1,
                created_by: "phases-bench".into(),
                qpc_frequency: timestamps.frequency(),
            },
            os_version: std::env::consts::OS.into(),
            cpu_arch: std::env::consts::ARCH.into(),
            pointer_width: usize::BITS,
            ..Default::default()
        };
        let mut recorder = TraceRecorder::from_environment(Vec::new(), env).unwrap();
        recorder.register_schema(api.enter_schema()).unwrap();
        recorder.register_schema(api.leave_schema()).unwrap();
        let ctx = TraceBatchContext {
            session_id: 1,
            process_id: 1,
            raw_pid: 1,
            thread_id: 1,
            qpc_frequency: timestamps.frequency(),
        };
        let enter = capture::encode_generic_enter::<3>(api, &args);
        let leave = capture::encode_generic_leave(api, 0x5678, 0);
        for _ in 0..ROUNDS {
            let start = Instant::now();
            for _ in 0..calls {
                let id = rt.alloc_call_id();
                published(rt.record_enter(1, api, id, enter.as_bytes()));
                published(rt.record_leave(1, api, id, leave.as_bytes()));
            }
            produce.push(start.elapsed().as_nanos() as f64 / (2 * calls) as f64);
            let start = Instant::now();
            let chunk = collector.collect(|| {}).expect("committed events");
            collect.push(start.elapsed().as_nanos() as f64 / (2 * calls) as f64);
            let start = Instant::now();
            let mut batch = worker.ingest_chunk(&chunk);
            drop(chunk);
            drain.push(start.elapsed().as_nanos() as f64 / (2 * calls) as f64);
            assert_eq!(batch.events.len(), 2 * calls);
            assert!(!worker.integrity_lost);
            assert!(worker.loss_events.is_empty());
            let start = Instant::now();
            let stats = if owned {
                recorder.record_owned_batch_with_args(&ctx, std::mem::take(&mut batch.events))
            } else {
                recorder.record_batch_with_args(&ctx, &batch.events)
            }
            .unwrap();
            convert.push(start.elapsed().as_nanos() as f64 / (2 * calls) as f64);
            assert_eq!(stats.args_attached, 2 * calls);
            assert_eq!(stats.args_fallback_blob, 0);
            let start = Instant::now();
            drop(batch);
            release.push(start.elapsed().as_nanos() as f64 / (2 * calls) as f64);
        }
        report(
            &format!("ring_publish_batch_{}", 2 * calls),
            &mut produce,
            "event",
        );
        report(
            &format!("host_collect_release_batch_{}", 2 * calls),
            &mut collect,
            "event",
        );
        report(
            &format!("host_validate_batch_{}", 2 * calls),
            &mut drain,
            "event",
        );
        report(
            &format!("host_convert_compress_memory_batch_{}", 2 * calls),
            &mut convert,
            "event",
        );
        report(
            &format!("host_release_batch_{}", 2 * calls),
            &mut release,
            "event",
        );
    }
}
