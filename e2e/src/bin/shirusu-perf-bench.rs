//! 性能目標の測定ベンチ (L10)。
//!
//! 測るもの (overview「記録モードと性能目標」節):
//! - L1 API 一件あたりの追加遅延: `Agent::record_enter` + `record_leave` の
//!   1 呼び出しあたり時間。Payload サイズ別 (0B / 100B / 512B / 4KiB)。
//!   Windows の Detour 自体のコストは含まない (F26 の M1 と同じ範囲)。
//! - L2 記録スループット: 記録あり走行での回収＋変換＋書き込みのイベント/秒。
//! - L3 バッファ使用率: 本番サイズ Ring でのバースト時の Descriptor /
//!   Payload Ring のピーク使用率と欠落数。
//! - L4 実行時間の倍率: 代表的な GUI ワークロード (gui-mix、上限 3 倍) と
//!   高負荷のケース (high-load、上限 5 倍) で、記録なし走行に対する記録あり
//!   走行の時間比。基準は開発中の評価基準であり保証値ではない。
//!
//! すべての OS で API 本体のコストは校正済み
//! スピンでモデル化する (`spin_loop` の 1 回あたり時間をベンチ開始時に測り、
//! 目標時間から反復回数を決める。校正値は出力する)。記録経路そのもの
//! (Agent・Ring・DrainWorker・TraceRecorder・TraceWriter) は本物を使う。
//! Windows CI でも同じモデルを使う。実アプリへの DLL 注入・Detour を
//! 含む実行時間の倍率は、このベンチでは測定していない。
//!
//! 使い方: `cargo run -p shirusu-e2e --bin shirusu-perf-bench --release [-- --rounds 3]`
//! 終了コードは常に 0。基準は開発中の評価目標でありゲートではないため、
//! 判定が FAIL でも失敗にしない（数値を読むための測定器である）。

use shirusu_agent::{Agent, RecordResult};
use shirusu_e2e::perf::{
    break_even_api_cost_ns, evaluate, execution_ratio, gui_mix_spec, high_load_spec, BufferUsage,
    CallClass, WorkloadKind, WorkloadSpec,
};
use shirusu_host::trace_convert::{TraceBatchContext, TraceRecorder};
use shirusu_host::{DrainWorker, IntegrityReport};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{RingReader, WriteOutcome};
use shirusu_transport::slot::SlotPool;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const N_LATENCY_CALLS_SMALL: u64 = 20_000;
const N_LATENCY_CALLS_4K: u64 = 2_000;
const N_RATIO_CALLS: u64 = 10_000;
const N_BURST_CALLS: u64 = 20_000;
/// 遅延測定用の Ring: 回収しないため、測定件数が収まる大きさにする。
const LATENCY_DESC_CAP: usize = 65_536;
const LATENCY_PAYLOAD_CAP: usize = 64 * 1024 * 1024;
/// 比率測定用の Ring: 本番既定 (4096 件 / 1MiB)。Host がコピーするのは
/// 公開済みの範囲だけだが、容量変更はバースト耐性や待機頻度を変えるため、
/// 比較には本番と同じサイズを使う。
const RATIO_DESC_CAP: usize = 4096;
const RATIO_PAYLOAD_CAP: usize = 1024 * 1024;
/// バースト測定用の Ring: 本番既定 (4096 件 / 1MiB)。
const BURST_DESC_CAP: usize = 4096;
const BURST_PAYLOAD_CAP: usize = 1024 * 1024;
/// Host の再確認周期にならった回収ポーリング間隔。実 Host は data_ready
/// 通知＋2ms 再確認で回収する。ベンチのプロセス内では通知が結線されない
/// ため 2ms ポーリングで代用する。実 Host は空のときだけ通知を待つため、
/// このモデルの固定待機とはスケジューリングが異なる。
const DRAIN_POLL: Duration = Duration::from_millis(2);
const BURST_DRAIN_POLL: Duration = Duration::from_millis(2);
/// TraceRecorder へ渡す 1 回の Batch の目標イベント数。drain のたびに
/// record_batch を呼ぶと EventChunk が細切れになり、Trace バイト数が
/// バッチング依存になる（F25/F26 は 10,000 件ずつ）。実運用の drain も
/// 通知駆動で数千件単位のため、ここで溜めてから渡す。
const RECORDER_BATCH_EVENTS: usize = 5_000;

fn median(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

fn env(session_id: u64) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by: "shirusu-perf-bench".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: std::env::consts::OS.into(),
        os_build: 0,
        cpu_arch: std::env::consts::ARCH.into(),
        pointer_width: usize::BITS,
        capture_config: "L10".into(),
        feature_flags: 3,
        target_description: "bench.exe".into(),
        modules: Vec::new(),
        // L13: ベンチは静的依存も記録しない（空）。
        static_dependencies: Vec::new(),
    }
}

/// 校正済みスピン。`spin_loop` の 1 回あたり時間を測り、目標 ns から反復回数を決める。
struct SpinModel {
    ns_per_iter: f64,
}

impl SpinModel {
    fn calibrate() -> Self {
        // 2,000,000 回で校正する。測定自体が数 ms で終わる。
        let n: u64 = 2_000_000;
        let t0 = Instant::now();
        spin_iters(n);
        let ns = t0.elapsed().as_nanos() as f64;
        Self {
            ns_per_iter: ns / n as f64,
        }
    }

    fn iters_for(&self, target_ns: u64) -> u64 {
        ((target_ns as f64 / self.ns_per_iter).round() as u64).max(1)
    }
}

fn spin_iters(n: u64) {
    for _ in 0..n {
        std::hint::spin_loop();
    }
}

/// ワークロード仕様のクラスを、呼び出し番号から決定的に選ぶ。
/// `i % 20` (gui-mix) または `i % 10` (high-load) の剰余で割り振る。
fn class_for(spec: &WorkloadSpec, i: u64) -> (usize, &'static str, u32, u32) {
    // クラス境界は share から決める。gui-mix: 0-15 short / 16-18 medium / 19 long。
    // high-load: 0-4 short / 5-7 medium / 8-9 long。
    let (api_id, schema_id, name) = match spec.kind {
        WorkloadKind::GuiMix => match i % 20 {
            0..=15 => (4u32, 4u32, "short"),
            16..=18 => (2u32, 2u32, "medium"),
            _ => (3u32, 3u32, "long"),
        },
        WorkloadKind::HighLoad => match i % 10 {
            0..=4 => (4u32, 4u32, "short"),
            5..=7 => (2u32, 2u32, "medium"),
            _ => (3u32, 3u32, "long"),
        },
    };
    let idx = match name {
        "short" => 0,
        "medium" => 1,
        _ => 2,
    };
    (idx, name, api_id, schema_id)
}

fn class_payloads(spec: &WorkloadSpec) -> Vec<Vec<u8>> {
    spec.classes
        .iter()
        .map(|c| vec![0xABu8; c.payload_bytes])
        .collect()
}

/// 1 呼び出し分の enter/leave を記録する。enter にだけ Payload を載せる。
/// 遅延測定は Ring に収まる件数に留めるため、欠落・劣化があれば前提崩壊で
/// パニックする。
fn record_call(agent: &Agent, api_id: u32, schema_id: u32, call_id: u64, payload: &[u8]) {
    let mut dropped = 0u64;
    let mut degraded = 0u64;
    count_record(
        agent.record_enter(1, api_id, schema_id, call_id, 0, payload),
        &mut dropped,
        &mut degraded,
    );
    count_record(
        agent.record_leave(1, api_id, schema_id, call_id, 0, &[]),
        &mut dropped,
        &mut degraded,
    );
    assert_eq!((dropped, degraded), (0, 0), "latency run must be lossless");
}

/// 記録結果を数える。Published 以外は呼び出し側のカウンタに足す。
/// 想定外の結果（Slot 無し・DETACH 後・Host 停止）はベンチの前提が崩れて
/// いるためパニックする。
fn count_record(r: RecordResult, dropped: &mut u64, degraded: &mut u64) {
    match r {
        RecordResult::Written(WriteOutcome::Published { .. }) => {}
        RecordResult::Written(WriteOutcome::PublishedDegraded { .. }) => *degraded += 1,
        RecordResult::Written(WriteOutcome::Dropped { .. }) => *dropped += 1,
        other => panic!("unexpected record result: {other:?}"),
    }
}

/// L1: API 一件あたりの追加遅延。Payload サイズ別に enter+leave の
/// 1 呼び出しあたり時間を測る。回収はしないため Ring に収まる件数に留める。
fn measure_latency(rounds: usize) -> Vec<(String, usize, u64, f64)> {
    // (表示名, Payload バイト数, 呼び出し数, ns/呼び出しの中央値)
    let shapes: [(String, usize, u64); 4] = [
        (
            "no-payload (CloseHandle-like)".into(),
            0,
            N_LATENCY_CALLS_SMALL,
        ),
        (
            "path 100B (CreateFileW-like)".into(),
            100,
            N_LATENCY_CALLS_SMALL,
        ),
        (
            "data 512B (ReadFile-like)".into(),
            512,
            N_LATENCY_CALLS_SMALL,
        ),
        (
            "data 4KiB (WriteFile-like)".into(),
            4096,
            N_LATENCY_CALLS_4K,
        ),
    ];
    let mut out = Vec::new();
    for (name, payload_len, n_calls) in shapes {
        let payload = vec![0xCDu8; payload_len];
        let mut per_call_ns = Vec::new();
        for _ in 0..rounds {
            let cfg = RingConfig::new(LATENCY_DESC_CAP, LATENCY_PAYLOAD_CAP);
            let pool = Arc::new(SlotPool::new(2));
            let monitor = Arc::new(HostMonitor::always_alive());
            let agent = Agent::new(pool, cfg, monitor);
            agent.thread_begin(1);
            let t0 = Instant::now();
            for i in 0..n_calls {
                record_call(&agent, 4, 4, i + 1, &payload);
            }
            let elapsed = t0.elapsed();
            per_call_ns.push(elapsed.as_nanos() as u64 / n_calls);
        }
        let med = median(per_call_ns);
        out.push((name, payload_len, n_calls, med as f64));
    }
    out
}

/// L4: ワークロード 1 件の比率測定。baseline（スピンのみ）と recorded
/// （スピン＋記録経路＋並行回収・変換・書き込み）を同じ呼び出し列で測る。
/// 戻り値は (baseline ns, recorded ns, 記録スループット ev/s, Trace バイト数,
/// Trace バイト/イベント, 欠落イベント数)。
fn measure_ratio(
    spec: &WorkloadSpec,
    spin: &SpinModel,
    rounds: usize,
    session: u64,
) -> (u64, u64, f64, usize, f64, u64) {
    let payloads = class_payloads(spec);
    let iters: Vec<u64> = spec
        .classes
        .iter()
        .map(|c: &CallClass| spin.iters_for(c.api_cost_ns))
        .collect();
    let mut baseline_ns = Vec::new();
    let mut recorded_ns = Vec::new();
    let mut throughput = 0f64;
    let mut trace_bytes = 0usize;
    let mut dropped_total = 0u64;
    for _ in 0..rounds {
        // baseline: API 本体のモデル化スピンだけ。
        let t0 = Instant::now();
        for i in 0..N_RATIO_CALLS {
            let (idx, _, _, _) = class_for(spec, i);
            spin_iters(iters[idx]);
        }
        baseline_ns.push(t0.elapsed().as_nanos() as u64);

        // recorded: 同じスピン＋記録経路。回収スレッドが並行して回す。
        let cfg = RingConfig::new(RATIO_DESC_CAP, RATIO_PAYLOAD_CAP);
        let pool = Arc::new(SlotPool::new(2));
        let monitor = Arc::new(HostMonitor::always_alive());
        let agent = Arc::new(Agent::new(pool, cfg, monitor));
        agent.thread_begin(1);
        let base = unsafe { agent.thread_region_base(1) }.expect("agent region");
        // 生ポインタは Send ではないためアドレスを usize で渡す。Agent は
        // join まで生きており、領域はその間有効（thread_region_base の契約）。
        let base_addr = base as usize;
        let done = Arc::new(AtomicBool::new(false));
        let consumer_done = Arc::new(AtomicBool::new(false));
        let consumer = {
            let done = done.clone();
            let consumer_done = consumer_done.clone();
            std::thread::spawn(move || {
                let mut worker = unsafe { DrainWorker::new(base_addr as *mut u8, cfg, 1) };
                let mut recorder =
                    TraceRecorder::from_environment(Vec::new(), env(session)).expect("recorder");
                let ctx = TraceBatchContext {
                    session_id: session,
                    process_id: 7,
                    raw_pid: 1234,
                    thread_id: 1,
                    qpc_frequency: 10_000_000,
                };
                let mut total = 0u64;
                // drain のたびに record_batch すると EventChunk が細切れに
                // なり Trace バイト数がバッチング依存になる。溜めてから渡す。
                let mut pending: Vec<shirusu_transport::ring::ReceivedEvent> = Vec::new();
                loop {
                    // 終了確認を先に行う。done が立った後の最終 drain は、
                    // producer の全公開を Acquire で見る（done の Release
                    // と同期する）ため取りこぼさない。drain→done 確認の順
                    // だと、drain の直後に公開された最後の 1 件を落とす
                    // レースがある。
                    if done.load(Ordering::Acquire) {
                        let batch = worker.drain_all();
                        total += batch.events.len() as u64;
                        pending.extend(batch.events);
                        break;
                    }
                    let batch = worker.drain_all();
                    if !batch.events.is_empty() {
                        total += batch.events.len() as u64;
                        pending.extend(batch.events);
                        if pending.len() >= RECORDER_BATCH_EVENTS {
                            recorder.record_batch(&ctx, &pending).expect("record_batch");
                            pending.clear();
                        }
                    }
                    std::thread::sleep(DRAIN_POLL);
                }
                if !pending.is_empty() {
                    recorder.record_batch(&ctx, &pending).expect("record_batch");
                }
                assert!(
                    worker.loss_events.is_empty() && !worker.integrity_lost,
                    "recorded run must be lossless: {:?}, integrity_lost={}",
                    worker.loss_events,
                    worker.integrity_lost
                );
                let finished = recorder
                    .finish(&IntegrityReport::default())
                    .expect("finish recorder");
                consumer_done.store(true, Ordering::Release);
                (total, finished.len())
            })
        };
        let t0 = Instant::now();
        let mut dropped = 0u64;
        let mut degraded = 0u64;
        for i in 0..N_RATIO_CALLS {
            let (idx, _, api_id, schema_id) = class_for(spec, i);
            // enter 記録 → API 本体（スピン）→ leave 記録。Detour と同じ順序。
            count_record(
                agent.record_enter(1, api_id, schema_id, i + 1, 0, &payloads[idx]),
                &mut dropped,
                &mut degraded,
            );
            spin_iters(iters[idx]);
            count_record(
                agent.record_leave(1, api_id, schema_id, i + 1, 0, &[]),
                &mut dropped,
                &mut degraded,
            );
        }
        done.store(true, Ordering::Release);
        let (total_events, bytes) = consumer.join().expect("consumer thread");
        let elapsed = t0.elapsed();
        // 壁時間は producer 開始から consumer の最終回収＋finish 完了まで。
        // スループットはこの端から端までの時間で割る（Host の並行処理込み）。
        assert_eq!(
            total_events,
            N_RATIO_CALLS * 2,
            "all enter+leave must be drained"
        );
        assert_eq!(
            (dropped, degraded),
            (0, 0),
            "ratio run must be lossless (big ring)"
        );
        recorded_ns.push(elapsed.as_nanos() as u64);
        throughput = (N_RATIO_CALLS * 2) as f64 / elapsed.as_secs_f64();
        trace_bytes = bytes;
        dropped_total = dropped;
    }
    let b_med = median(baseline_ns);
    let r_med = median(recorded_ns);
    (
        b_med,
        r_med,
        throughput,
        trace_bytes,
        trace_bytes as f64 / (N_RATIO_CALLS * 2) as f64,
        dropped_total,
    )
}

/// L3: 本番サイズ Ring でのバースト時のバッファ使用率。API スピン無しで
/// 記録だけを連打し、2ms 周期で回収する Host 相当の消費者と組み合わせる。
/// 戻り値は (BufferUsage, 欠落呼び出し数, 劣化呼び出し数, 回収イベント数)。
fn measure_burst(spec: &WorkloadSpec, rounds: usize) -> (BufferUsage, u64, u64, u64) {
    let payloads = class_payloads(spec);
    let mut best = BufferUsage {
        descriptor_used_peak: 0,
        descriptor_capacity: BURST_DESC_CAP as u64,
        payload_used_peak: 0,
        payload_capacity: BURST_PAYLOAD_CAP as u64,
    };
    let mut dropped = 0u64;
    let mut degraded = 0u64;
    let mut drained = 0u64;
    for _ in 0..rounds {
        let cfg = RingConfig::new(BURST_DESC_CAP, BURST_PAYLOAD_CAP);
        let pool = Arc::new(SlotPool::new(2));
        let monitor = Arc::new(HostMonitor::always_alive());
        let agent = Arc::new(Agent::new(pool, cfg, monitor));
        agent.thread_begin(1);
        let base = unsafe { agent.thread_region_base(1) }.expect("agent region");
        // 生ポインタは Send ではないためアドレスを usize で渡す。Agent は
        // join まで生きており、領域はその間有効（thread_region_base の契約）。
        let base_addr = base as usize;
        // Cursor だけを読む観測用 Reader。回収は DrainWorker が行う。
        let observer = unsafe { RingReader::new(base, cfg) };
        let done = Arc::new(AtomicBool::new(false));
        let peak_desc = Arc::new(AtomicU64::new(0));
        let peak_pay = Arc::new(AtomicU64::new(0));
        let consumer = {
            let done = done.clone();
            std::thread::spawn(move || {
                let mut worker = unsafe { DrainWorker::new(base_addr as *mut u8, cfg, 1) };
                let mut total = 0u64;
                loop {
                    // 終了確認を先に行う（比率測定と同じ理由。done 後の最終
                    // drain は全公開を見るため取りこぼさない）。
                    if done.load(Ordering::Acquire) {
                        let batch = worker.drain_all();
                        total += batch.events.len() as u64;
                        break;
                    }
                    let batch = worker.drain_all();
                    total += batch.events.len() as u64;
                    std::thread::sleep(BURST_DRAIN_POLL);
                }
                (total, worker.integrity_lost)
            })
        };
        // producer: 記録だけを連打し、公開のたびに使用率のピークを観測する。
        // 欠落・劣化は RecordResult（WriteOutcome）で数える。
        let mut round_dropped = 0u64;
        let mut round_degraded = 0u64;
        for i in 0..N_BURST_CALLS {
            let (idx, _, api_id, schema_id) = class_for(spec, i);
            for (is_enter, payload) in [(true, &payloads[idx][..]), (false, &[][..])] {
                let r = if is_enter {
                    agent.record_enter(1, api_id, schema_id, i + 1, 0, payload)
                } else {
                    agent.record_leave(1, api_id, schema_id, i + 1, 0, payload)
                };
                count_record(r, &mut round_dropped, &mut round_degraded);
                let d = observer.descriptor_used();
                let p = observer.payload_used();
                peak_desc.fetch_max(d, Ordering::Relaxed);
                peak_pay.fetch_max(p, Ordering::Relaxed);
            }
        }
        done.store(true, Ordering::Release);
        let (total, integrity_lost) = consumer.join().expect("consumer thread");
        assert!(!integrity_lost, "burst run must not lose ring integrity");
        let usage = BufferUsage {
            descriptor_used_peak: peak_desc.load(Ordering::Relaxed),
            descriptor_capacity: BURST_DESC_CAP as u64,
            payload_used_peak: peak_pay.load(Ordering::Relaxed),
            payload_capacity: BURST_PAYLOAD_CAP as u64,
        };
        if usage.descriptor_used_peak > best.descriptor_used_peak {
            best.descriptor_used_peak = usage.descriptor_used_peak;
        }
        if usage.payload_used_peak > best.payload_used_peak {
            best.payload_used_peak = usage.payload_used_peak;
        }
        dropped = round_dropped;
        degraded = round_degraded;
        drained = total;
    }
    (best, dropped, degraded, drained)
}

fn main() {
    let rounds = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--rounds")
        .and_then(|w| w[1].parse::<usize>().ok())
        .unwrap_or(3)
        .max(1);
    println!("shirusu-perf-bench: L10 performance targets (overview: gui-mix <= 3x, high-load <= 5x; development targets, not guarantees)");
    println!(
        "rounds: {rounds} (median) | ratio calls: {N_RATIO_CALLS} | burst calls: {N_BURST_CALLS}"
    );

    // ---- スピン校正 ----
    let spin = SpinModel::calibrate();
    println!(
        "\nspin calibration: {:.2} ns/iter (spin_loop; API-body model, Linux only)",
        spin.ns_per_iter
    );

    // ---- L1: API 一件あたりの追加遅延 ----
    println!(
        "\n== L1 per-API additional latency (Agent record enter+leave, Detour itself excluded) =="
    );
    println!("shape | payload | calls | ns/call (median)");
    let latencies = measure_latency(rounds);
    for (name, payload_len, n_calls, ns_per_call) in &latencies {
        println!("{name} | {payload_len} B | {n_calls} | {ns_per_call:.1}");
    }
    println!("\nbreak-even API cost (API body cost at which the ratio equals the limit):");
    println!("shape | 3x break-even | 5x break-even");
    for (name, _, _, ns_per_call) in &latencies {
        println!(
            "{name} | {:.0} ns | {:.0} ns",
            break_even_api_cost_ns(*ns_per_call as u64, 3.0),
            break_even_api_cost_ns(*ns_per_call as u64, 5.0),
        );
    }
    println!("reading: an API whose body is shorter than the 3x break-even exceeds 3x when called on its own; the ratio criterion applies to representative workloads, not to isolated short APIs (overview).");

    // ---- L4/L2: 倍率とスループット ----
    for (spec, session) in [(gui_mix_spec(), 100u64), (high_load_spec(), 101u64)] {
        let kind = spec.kind;
        println!(
            "\n== L4+L2 {} (limit {}x) ==",
            kind.name(),
            kind.ratio_limit()
        );
        println!(
            "workload: expected API cost {:.0} ns/call, {} calls",
            spec.expected_api_cost_ns_per_call(),
            N_RATIO_CALLS
        );
        let (baseline_ns, recorded_ns, throughput, trace_bytes, bytes_per_event, dropped) =
            measure_ratio(&spec, &spin, rounds, session);
        let ratio = execution_ratio(recorded_ns, baseline_ns);
        let verdict = evaluate(kind, ratio);
        println!(
            "baseline {:.1} ms | recorded {:.1} ms | ratio {:.3}x | limit {}x | verdict {}",
            baseline_ns as f64 / 1e6,
            recorded_ns as f64 / 1e6,
            ratio,
            verdict.limit,
            if verdict.meets { "PASS" } else { "FAIL" },
        );
        println!(
            "throughput (recorded leg): {:.0} ev/s | trace {} bytes ({:.1} B/event) | dropped events: {dropped}",
            throughput, trace_bytes, bytes_per_event,
        );
    }

    // ---- L3: バッファ使用率 ----
    println!("\n== L3 buffer usage (production ring {BURST_DESC_CAP} desc / {} KiB payload, 2ms drain poll) ==", BURST_PAYLOAD_CAP / 1024);
    let (usage, dropped, degraded, drained) = measure_burst(&gui_mix_spec(), rounds);
    println!(
        "peak descriptor usage: {} / {} ({}%) | peak payload usage: {} / {} ({}%)",
        usage.descriptor_used_peak,
        usage.descriptor_capacity,
        usage.descriptor_percent(),
        usage.payload_used_peak,
        usage.payload_capacity,
        usage.payload_percent(),
    );
    println!(
        "drained events: {drained} / attempted {} | dropped events: {dropped} | degraded events: {degraded} | hit full: {}",
        N_BURST_CALLS * 2,
        usage.hit_full(),
    );
    if dropped > 0 {
        println!("note: the burst exceeded the production ring; the trace would be incomplete (full mode does not guarantee recording under any load).");
    }

    println!("\nnote: these numbers measure Agent/Ring/Host/Writer with simulated API costs on every OS. They do not measure DLL injection, Detour overhead, or real GUI/API execution.");
    println!("note: medians of {rounds} rounds on {} / {}; absolute numbers vary by machine. These modeled criteria do not establish the real-application performance targets.", std::env::consts::OS, std::env::consts::ARCH);
}
