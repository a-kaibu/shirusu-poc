//! 転送・ディスク形式のベンチマーク (F25 + F26)。
//!
//! 測定するもの:
//! - F25 チャンクサイズ: `WriterOptions::chunk_raw_target` を 128 KiB /
//!   256 KiB / 512 KiB / 1 MiB で掃引し、Trace の総バイト数・書き込み時間・
//!   デコード時間・Event Chunk 数を比べる。128 KiB は仕様範囲外の対照用で、
//!   決定は仕様の目安範囲 256 KiB〜1 MiB の中から行う。決定規則は「1 MiB
//!   に対する総バイト数が +1% 以内で、デコード時間が最速の +5% 以内を満たす
//!   最小の目標値」とし、満たすものが無ければ 1 MiB。既定値の維持/変更は
//!   測定値で決める。
//! - F26 4 指標の分離測定（同じワークロード、決定したチャンクサイズ）:
//!   - M1 Agent の観測コスト: `Agent::record` 1 件あたりの時間
//!     （Windows の Detour 自体のコストは含まない。Detour の実測は
//!     Windows 実機＝L06 の範囲。ここでは記録経路＝Ring 書き込みまで）。
//!   - M2 Host の処理量: `DrainWorker::drain_all`＋`TraceRecorder` 変換の
//!     イベント/秒と書き出した Trace バイト/秒。
//!   - M3 ファイルサイズ: F25 の結果からバイト/イベント。
//!   - M4 デコード速度: `read_trace` のイベント/秒と MiB/秒。
//!
//! ワークロード（決定的・シード固定）: 20,000 イベントを 10,000 件ずつの
//! Batch に分ける（1 Batch の符号化サイズが約 400 KiB あり、128 KiB〜
//! 1 MiB の全目標値で分割の有無が変わる。Batch が目標値より小さいと分割が
//! 起きず掃引が無意味になるため）。API 混合は CreateFileW 20% / ReadFile 30% /
//! WriteFile 30% / CloseHandle 20%。CreateFileW は 64 種のパス Blob
//! （UTF-16）、ReadFile/WriteFile は 256 種のデータ Blob（512 B〜4 KiB、
//! 繰り返し句＋ノイズで中程度に圧縮可能）を参照する。引数値列は Schema
//! に沿って事前に符号化しておき、計測区間には含めない。
//!
//! 使い方: `cargo run -p shirusu-e2e --bin shirusu-trace-bench --release [-- --rounds 3]`
//! 環境: Linux VM での測定。Windows 実機分は CI 待ち。

use shirusu_agent::{Agent, RecordResult};
use shirusu_e2e::ev;
use shirusu_host::trace_convert::{TraceBatchContext, TraceRecorder};
use shirusu_host::{DrainWorker, IntegrityReport};
use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::container::BlockType;
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::read_trace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::{FinalizationInfo, WriterOptions};
use shirusu_trace::TraceWriter;
use shirusu_transport::context::{CallOrigin, HostMonitor};
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::SharedRegion;
use shirusu_transport::slot::SlotPool;
use std::sync::Arc;
use std::time::{Duration, Instant};

const N_EVENTS: usize = 20_000;
const BATCH_EVENTS: usize = 10_000;
const N_AGENT_EVENTS: u64 = 50_000;
const TARGETS: [usize; 4] = [128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024];

/// 測定用の簡易乱数 (xorshift64)。ワークロード生成だけに使う。
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

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
            created_by: "shirusu-trace-bench".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        os_build: 26100,
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        capture_config: "L2".into(),
        feature_flags: 3,
        target_description: "bench.exe".into(),
        // L07: ベンチはモジュール分類を記録しない（空）。
        modules: Vec::new(),
    }
}

/// 決定的な合成ワークロード。Schema・Payload プール・Batch を作る。
struct Workload {
    schemas: Vec<shirusu_trace::proto::SchemaDef>,
    payloads: Vec<Vec<u8>>,
    payload_ids: Vec<BlobId>,
    batches: Vec<EventBatch>,
}

fn build_workload() -> Workload {
    let schemas = vec![
        make_schema(
            1,
            "kernel32!CreateFileW",
            vec![
                ("handle".into(), Ty::Ptr64, 0),
                ("flags".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            2,
            "kernel32!ReadFile",
            vec![
                ("handle".into(), Ty::Ptr64, 0),
                ("bytes".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            3,
            "kernel32!WriteFile",
            vec![
                ("handle".into(), Ty::Ptr64, 0),
                ("bytes".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            4,
            "kernel32!CloseHandle",
            vec![("handle".into(), Ty::Ptr64, 0)],
        ),
    ];

    // Payload プール: 64 種のパス (UTF-16) と 256 種のデータ。
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for i in 0..64 {
        let path = format!("C:\\game\\data\\chapter{:02}\\file{:02}.dat", i / 8, i % 8);
        let utf16: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        payloads.push(utf16);
    }
    let phrase = b"shirusu-bench-payload:the-quick-brown-fox-jumps-over-the-lazy-dog;";
    for k in 0..256 {
        let size = [512, 1024, 2048, 4096][k % 4];
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            data.extend_from_slice(phrase);
        }
        data.truncate(size);
        // 8 バイトに 1 バイトだけ乱数を混ぜる（中程度に圧縮可能な実データ風）。
        for (j, b) in data.iter_mut().enumerate() {
            if j % 8 == 0 {
                *b = (rng.next() & 0xff) as u8;
            }
        }
        payloads.push(data);
    }
    let payload_ids: Vec<BlobId> = payloads.iter().map(|d| BlobId::of_content(d)).collect();

    // イベント列。args は事前に符号化しておく（計測区間外）。
    let mut batches = Vec::new();
    let mut events = Vec::with_capacity(BATCH_EVENTS);
    for i in 0..N_EVENTS {
        let seq = i as u64 + 1;
        let mix = i % 10;
        let (api_id, schema_id, payload) = match mix {
            0 | 1 => (1u32, 1u32, PayloadRef::Blob(payload_ids[i % 64])),
            2..=4 => (2u32, 2u32, PayloadRef::Blob(payload_ids[64 + (i % 256)])),
            5..=7 => (3u32, 3u32, PayloadRef::Blob(payload_ids[64 + (i % 256)])),
            _ => (4u32, 4u32, PayloadRef::None),
        };
        let (types, values): (&[Ty], Vec<CapturedValue>) = if api_id == 4 {
            (
                &[Ty::Ptr64][..],
                vec![CapturedValue::captured(TypedValue::Ptr64(
                    0x1000 + i as u64,
                ))],
            )
        } else {
            (
                &[Ty::Ptr64, Ty::U32][..],
                vec![
                    CapturedValue::captured(TypedValue::Ptr64(0x1000 + i as u64)),
                    CapturedValue::captured(TypedValue::U32((i % 4096) as u32)),
                ],
            )
        };
        let args = encode_values(types, &values).unwrap();
        events.push(TraceEvent {
            kind: 1,
            sequence: seq,
            timestamp_qpc: 1_000_000 + (i as u64) * 100,
            call_id: seq,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload,
            args: Some(args),
            global_order: None,
        });
        if events.len() == BATCH_EVENTS {
            let batch_no = batches.len() as u64;
            batches.push(EventBatch {
                session_id: 42,
                process_id: 7,
                raw_pid: 1234,
                thread_id: 1 + (batch_no % 4),
                qpc_frequency: 10_000_000,
                events: std::mem::take(&mut events),
            });
        }
    }
    Workload {
        schemas,
        payloads,
        payload_ids,
        batches,
    }
}

/// ワークロードを 1 回書き、(バイト列, 書き込み時間, Event Chunk 数) を返す。
fn write_trace(w: &Workload, target: usize) -> (Vec<u8>, Duration, usize) {
    let t0 = Instant::now();
    let mut writer = TraceWriter::with_options(
        Vec::new(),
        env(42),
        WriterOptions {
            chunk_raw_target: target,
            ..Default::default()
        },
    )
    .unwrap();
    for s in &w.schemas {
        writer.register_schema(s.clone()).unwrap();
    }
    for (data, want) in w.payloads.iter().zip(w.payload_ids.iter()) {
        let got = writer.add_payload(data).unwrap();
        assert_eq!(&got, want, "BlobId は内容の BLAKE3 と一致するはず");
    }
    for b in &w.batches {
        writer.write_batch(b).unwrap();
    }
    let bytes = writer.finish(FinalizationInfo::default()).unwrap();
    let elapsed = t0.elapsed();
    let trace = read_trace(&bytes).unwrap();
    let chunks = trace
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::EventChunk)
        .count();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.total_events(), N_EVENTS as u64);
    (bytes, elapsed, chunks)
}

/// バイト列を 1 回デコードし、(イベント数, デコード時間) を返す。
fn decode_trace(bytes: &[u8]) -> (usize, Duration) {
    let t0 = Instant::now();
    let trace = read_trace(bytes).unwrap();
    let n = trace.total_events() as usize;
    let elapsed = t0.elapsed();
    assert_eq!(n, N_EVENTS);
    (n, elapsed)
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
    println!("shirusu-trace-bench: {N_EVENTS} events, {rounds} rounds each");
    println!("workload: CreateFileW 20% / ReadFile 30% / WriteFile 30% / CloseHandle 20%");
    println!("payload pool: 64 paths (UTF-16) + 256 data buffers (512B-4KiB)");

    let workload = build_workload();
    let raw_bytes: usize = workload
        .batches
        .iter()
        .flat_map(|b| &b.events)
        .map(|e| {
            let payload_len = match &e.payload {
                PayloadRef::Blob(id) => workload
                    .payload_ids
                    .iter()
                    .position(|p| p == id)
                    .map(|i| workload.payloads[i].len())
                    .unwrap_or(0),
                PayloadRef::Inline(v) => v.len(),
                _ => 0,
            };
            payload_len + e.args.as_ref().map(|a| a.len()).unwrap_or(0) + 32
        })
        .sum();
    println!("estimated raw event bytes (incl. deduped payload refs): {raw_bytes}");

    // ---- F25: チャンクサイズの掃引 ----
    println!("\n== F25 chunk-size sweep ==");
    println!("target | file bytes | bytes/event | chunks | write ms | decode ms | write ev/s | decode ev/s");
    let mut rows: Vec<(usize, usize, usize, u64, u64)> = Vec::new(); // target, bytes, chunks, write_ns, decode_ns
    for &target in &TARGETS {
        let mut write_ns = Vec::new();
        let mut decode_ns = Vec::new();
        let mut file_bytes = 0usize;
        let mut chunks = 0usize;
        for _ in 0..rounds {
            let (bytes, w_elapsed, n_chunks) = write_trace(&workload, target);
            let (_, d_elapsed) = decode_trace(&bytes);
            file_bytes = bytes.len();
            chunks = n_chunks;
            write_ns.push(w_elapsed.as_nanos() as u64);
            decode_ns.push(d_elapsed.as_nanos() as u64);
        }
        let w_med = median(write_ns);
        let d_med = median(decode_ns);
        rows.push((target, file_bytes, chunks, w_med, d_med));
        println!(
            "{:>6} KiB | {:>10} | {:>11.1} | {:>6} | {:>8.1} | {:>9.1} | {:>10} | {:>11}",
            target / 1024,
            file_bytes,
            file_bytes as f64 / N_EVENTS as f64,
            chunks,
            w_med as f64 / 1e6,
            d_med as f64 / 1e6,
            (N_EVENTS as f64 / (w_med as f64 / 1e9)) as u64,
            (N_EVENTS as f64 / (d_med as f64 / 1e9)) as u64,
        );
    }
    // 決定規則: 仕様の目安範囲 256 KiB〜1 MiB の中で、1 MiB に対する
    // 総バイト数 +1% 以内、かつデコード時間は最速の +5% 以内を満たす最小の
    // 目標値。128 KiB は範囲外の対照用で決定対象外。
    let best_bytes = rows.iter().map(|r| r.1).min().unwrap() as f64;
    let best_decode = rows.iter().map(|r| r.4).min().unwrap() as f64;
    let mut decision = TARGETS[TARGETS.len() - 1];
    for r in rows.iter().filter(|r| r.0 >= 256 * 1024) {
        if (r.1 as f64) <= best_bytes * 1.01 && (r.4 as f64) <= best_decode * 1.05 {
            decision = r.0;
            break;
        }
    }
    println!(
        "F25 decision: chunk_raw_target = {} KiB (smallest in-spec target within +1% bytes of best and +5% decode of fastest)",
        decision / 1024
    );

    // ---- F26: 4 指標の分離測定（決定したチャンクサイズ） ----
    println!(
        "\n== F26 four metrics (chunk target {} KiB) ==",
        decision / 1024
    );
    // M1: Agent の観測コスト (record 経路のみ。Windows Detour 自体は含まない)。
    let cfg = RingConfig::new(65536, 4 * 1024 * 1024);
    let pool = Arc::new(SlotPool::new(2));
    let monitor = Arc::new(HostMonitor::always_alive());
    let agent = Agent::new(pool, cfg, monitor);
    let payload8 = [0xAB; 8];
    let mut written = 0u64;
    let t0 = Instant::now();
    for i in 0..N_AGENT_EVENTS {
        match agent.record(1, CallOrigin::Application, ev(i, &payload8)) {
            RecordResult::Written(_) => written += 1,
            other => panic!("unexpected record result: {other:?}"),
        }
    }
    let m1_ns = t0.elapsed();
    println!(
        "M1 agent record: {written} events in {:.1} ms = {:.1} ns/event ({:.0} ev/s)",
        m1_ns.as_secs_f64() * 1e3,
        m1_ns.as_nanos() as f64 / written as f64,
        written as f64 / m1_ns.as_secs_f64(),
    );

    // M2: Host の処理量 (DrainWorker の検証付き回収＋TraceRecorder 変換)。
    let cfg2 = RingConfig::new(65536, 4 * 1024 * 1024);
    let region = Arc::new(SharedRegion::new(cfg2, 1, 1));
    {
        let r2 = region.clone();
        let mut w = shirusu_e2e::writer_over(&r2, true);
        for i in 0..N_AGENT_EVENTS {
            let p = i.to_le_bytes();
            match w.write(ev(i, &p)) {
                shirusu_transport::ring::WriteOutcome::Published { .. } => {}
                other => panic!("unexpected ring write: {other:?}"),
            }
        }
    }
    let t0 = Instant::now();
    let mut worker = unsafe { DrainWorker::new(region.base(), cfg2, 1) };
    let drained = worker.drain_all();
    assert!(
        worker.loss_events.is_empty() && !worker.integrity_lost,
        "drain must be lossless: {:?}, integrity_lost={}",
        worker.loss_events,
        worker.integrity_lost
    );
    assert_eq!(drained.events.len() as u64, N_AGENT_EVENTS);
    let mut recorder = TraceRecorder::from_environment(Vec::new(), env(43)).expect("recorder");
    let ctx = TraceBatchContext {
        session_id: 43,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 1,
        qpc_frequency: 10_000_000,
    };
    recorder
        .record_batch(&ctx, &drained.events)
        .expect("record_batch");
    let m2_elapsed = t0.elapsed();
    let m2_bytes = {
        let finished = recorder
            .finish(&IntegrityReport::default())
            .expect("finish recorder for measurement");
        finished.len()
    };
    println!(
        "M2 host drain+convert: {N_AGENT_EVENTS} events in {:.1} ms = {:.0} ev/s, wrote {m2_bytes} trace bytes ({:.1} B/event)",
        m2_elapsed.as_secs_f64() * 1e3,
        N_AGENT_EVENTS as f64 / m2_elapsed.as_secs_f64(),
        m2_bytes as f64 / N_AGENT_EVENTS as f64,
    );

    // M3/M4: F25 の決定サイズの行から。
    let row = rows.iter().find(|r| r.0 == decision).unwrap();
    println!(
        "M3 file size: {} bytes / {} events = {:.1} B/event (chunk target {} KiB)",
        row.1,
        N_EVENTS,
        row.1 as f64 / N_EVENTS as f64,
        decision / 1024,
    );
    println!(
        "M4 decode speed: {} events in {:.1} ms = {:.0} ev/s ({:.1} MiB/s of trace bytes)",
        N_EVENTS,
        row.4 as f64 / 1e6,
        N_EVENTS as f64 / (row.4 as f64 / 1e9),
        (row.1 as f64 / 1_048_576.0) / (row.4 as f64 / 1e9),
    );
    println!("\nnote: M1 excludes the Windows Detour itself (hook cost on real Windows is L06/CI scope).");
    println!("note: medians of 5 rounds on this shared Linux VM; absolute numbers vary by machine, the decision rule (not the raw numbers) is what the default rests on.");
}
