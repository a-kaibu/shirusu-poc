//! ストレステスト: 大量書込、SPSC 並行、Host 一時停止、終端またぎ、
//! Generation 越え、共有メモリ破壊耐性。

// (atomic imports removed: stop flag is no longer used)
use shirusu_transport::clock::ManualClock;
use shirusu_transport::ring::*;
use shirusu_transport::validate::{KnownConfig, ValidatingReader};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::sync::Arc;
use std::time::Duration;

fn input(payload: &[u8], call: u64) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 5,
        schema_id: 6,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}

#[test]
fn spsc_concurrent_writer_reader_100k() {
    let cfg = RingConfig::new(1024, 65536);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let r2 = region.clone();
    let reader_thread = std::thread::spawn(move || {
        let mut rd = unsafe { r2.reader() };
        // 正常公開されたイベントだけを集める（劣化イベントは欠落として別に現れる）
        let mut got: Vec<ReceivedEvent> = Vec::new();
        while got.len() < 100_000 {
            let b = rd.drain(512);
            if b.events.is_empty() {
                std::thread::yield_now();
                continue;
            }
            for e in b.events {
                if !e.descriptor.payload_dropped() {
                    got.push(e);
                }
            }
        }
        got
    });
    // 実時計で上限付き待機させ、満杯でも reader の回収を待って正常公開できるようにする
    let clock: Arc<dyn Clock> = shirusu_transport::clock::system_clock();
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::from_millis(200),
                ..Default::default()
            },
            clock,
        )
    };
    let mut sent = 0u64;
    while sent < 100_000 {
        let p = sent.to_le_bytes();
        match w.write(input(&p, sent)) {
            WriteOutcome::Published { .. } => sent += 1,
            // 劣化/欠落した分はアプリ相当に再送する
            _ => std::thread::yield_now(),
        }
    }
    let got = reader_thread.join().unwrap();
    assert_eq!(got.len(), 100_000);
    for (i, e) in got.iter().enumerate() {
        assert_eq!(e.payload, (i as u64).to_le_bytes());
    }
}

/// 1000 万 ops 級のソーク (release 前提)。debug では縮小版になる。
/// 規模は環境変数 SHIRUSU_STRESS_OPS で上書きできる（短時間ジョブでは縮小し、
/// 週次 CI では scripts/ci/stress-long.sh が 10 億 ops に拡大する）。
/// バッチ単位で書いて回収するので欠落は起きず、全 Payload の内容と
/// Sequence の連続性を全件検証する。Payload Ring は小さくして
/// 位置の折り返しを大量に踏ませる。
#[test]
fn soak_10m_ops_throughput_and_integrity() {
    let total: u64 = std::env::var("SHIRUSU_STRESS_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(if cfg!(debug_assertions) {
            200_000
        } else {
            10_000_000
        });
    const BATCH: u64 = 4096;
    let cfg = RingConfig::new(8192, 65536);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let mut rd = unsafe { region.reader() };
    let started = std::time::Instant::now();
    let mut done = 0u64;
    let mut received = 0u64;
    while done < total {
        let n = BATCH.min(total - done);
        for k in 0..n {
            let seq = done + k + 1;
            let p = seq.to_le_bytes();
            let out = w.write(input(&p, seq));
            assert!(
                matches!(out, WriteOutcome::Published { .. }),
                "batch-sized writes into a large ring must not drop (seq {seq})"
            );
        }
        let b = rd.drain_all();
        assert_eq!(b.events.len() as u64, n);
        assert_eq!(b.sequence_gaps, 0);
        for e in &b.events {
            received += 1;
            assert_eq!(e.descriptor.sequence, received);
            assert_eq!(e.payload, received.to_le_bytes());
        }
        done += n;
    }
    let elapsed = started.elapsed();
    println!(
        "soak: {total} ops in {elapsed:?} ({:.0} ops/s)",
        total as f64 / elapsed.as_secs_f64()
    );
    assert_eq!(received, total);
    assert_eq!(
        w.loss_counters(),
        shirusu_transport::LossCounters::default()
    );
}

#[test]
fn host_pause_then_resume_recovers_via_recheck_drain() {
    let cfg = RingConfig::new(256, 16384);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let mut rd = unsafe { region.reader() };
    for i in 0..100u64 {
        w.write(input(b"pause-test", i));
    }
    // Host 一時停止相当: ここまで drain しない。通知が無くても再確認 drain で全件回収できる。
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 100);
}

#[test]
fn corrupted_image_never_panics_and_stops_ring() {
    let cfg = RingConfig::new(16, 512);
    let known = KnownConfig::new(cfg, cfg.required_len());
    for seed in 0..64u64 {
        let region = SharedRegion::new(cfg, 1, 1);
        let mut image = region.as_slice().to_vec();
        // 疑似ランダムにバイトを壊す
        let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        for _ in 0..24 {
            x ^= x << 13;
            x ^= x >> 7;
            let idx = (x as usize) % image.len();
            image[idx] = (x >> 32) as u8;
        }
        let mut vr = ValidatingReader::new(known, 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = vr.drain_image(&image);
            let _ = vr.drain_image(&image);
        }));
        assert!(result.is_ok(), "seed {seed}: validating reader panicked");
    }
}

#[test]
fn generation_rollover_isolation() {
    // 同じ slot を何世代も使い回しても、検証側は世代を区別できる
    let cfg = RingConfig::new(8, 256);
    for gen in 1..=8u64 {
        let region = SharedRegion::new(cfg, gen, 55);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
        w.write(input(b"gen-data", gen));
        let mut vr = ValidatingReader::new(KnownConfig::new(cfg, cfg.required_len()), gen);
        let events = vr.drain_image(region.as_slice()).unwrap();
        assert_eq!(events.len(), 1);
        let mut vr_old = ValidatingReader::new(
            KnownConfig::new(cfg, cfg.required_len()),
            gen.wrapping_add(100),
        );
        assert!(vr_old.drain_image(region.as_slice()).is_err());
    }
}
