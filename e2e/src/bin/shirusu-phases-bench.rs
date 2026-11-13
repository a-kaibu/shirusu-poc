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
    DrainWorker,
};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_transport::{
    clock::TimestampSource, context::HostMonitor, layout::RingConfig, ring::WriteOutcome,
    slot::SlotPool,
};
use std::{hint::black_box, sync::Arc, time::Instant};

const OPS: usize = 100_000;
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
    #[cfg(not(windows))]
    let timestamps: Arc<dyn TimestampSource> = shirusu_transport::clock::system_timestamp_source();
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
    measure("timestamp", || {
        black_box(timestamps.now_qpc());
    });
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
    let mut worker = unsafe { DrainWorker::new(base, cfg, 1) };
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
            let mut batch = worker.drain_all();
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
            &format!("host_drain_batch_{}", 2 * calls),
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
