//! 調整値のベンチマーク (A73): 転送の調整値（Ring 容量・待機上限・再確認周期・
//! 復帰閾値・Slot 数）を掃引して測定し、既定値の維持/変更の根拠を出す。
//!
//! 測定するもの:
//! - S1 Ring 容量: descriptor 256/1024/4096/16384 × payload 256KiB/1MiB/4MiB。
//!   固定した producer/consumer 速度（consumer は 200µs 周期で回収）での
//!   スループット・欠落率と、共有メモリ量 (required_len)。
//!   遅い Host (5ms 周期) での欠落率も別途測る。
//!   consumer は検証なし RingReader を使う。検証付き DrainWorker は回収のたびに
//!   像全体をコピーするため、容量が大きいほど回収コストが増える——それは
//!   容量そのものの効果ではなく検証経路のコストなので、容量の掃引からは分離する
//!   （D65 の経路。コスト自体は別途 README に明記）。
//! - S2 BOUNDED_WAIT 上限: 0 / 0.25 / 1 / 5ms。Host が 500µs 後に回収する場合の
//!   書き手の再開可否・再開遅延と、Host が止まったままの場合の 1 回の書込の停滞時間。
//! - S3 再確認周期: 1 / 2 / 5 / 10ms。通知を取りこぼした Host が再確認で
//!   気づくまでの遅延と、無通知のアイドル時の再確認 (wakeup) 回数。
//! - S4 復帰閾値: 25 / 50 / 75%。OVERFLOW から復帰するのに必要なまとまった
//!   回収件数と、復帰後に再 OVERFLOW するまでの余裕 (headroom)。
//! - S5 Slot 数・低水位: 初期 32・低水位 8 のメモリ使用量と拡張要求の発火点。
//!
//! 使い方: `cargo run -p shirusu-e2e --bin shirusu-tuning-bench [-- --rounds 3]`
//! 環境: Linux VM での測定。Windows 実機分は CI 待ち。

use shirusu_e2e::ev;
use shirusu_host::DrainWorker;
use shirusu_transport::clock::{system_clock, Clock, ManualClock};
use shirusu_transport::layout::{writer_waiting, RingConfig};
use shirusu_transport::notify::ReCheckPolicy;
use shirusu_transport::ring::{OverflowState, SharedRegion, WriteOutcome, WriterPolicy};
use shirusu_transport::slot::{SlotPool, SLOT_MEMORY_BYTES};
use shirusu_transport_win::ProcessNotify;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PAYLOAD_256: [u8; 256] = [0xAB; 256];

/// 測定用の簡易乱数 (xorshift64)。到着時刻のランダム化だけに使う。
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
fn p95(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let idx = ((v.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    v[idx.min(v.len() - 1)]
}

// ---------------------------------------------------------------- S1: Ring 容量

struct CapThroughput {
    mem_kib: u64,
    throughput_eps: u64,
    published: u64,
    degraded: u64,
    dropped: u64,
    drained: u64,
    wait_ms: u64,
    balanced: bool,
}

fn run_capacity_throughput(desc: usize, payload: usize, attempts: u64) -> CapThroughput {
    let cfg = RingConfig::new(desc, payload);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    let r2 = region.clone();
    let consumer = std::thread::spawn(move || {
        let mut reader = unsafe { r2.reader() };
        let mut drained = 0u64;
        while !d2.load(Ordering::Relaxed) {
            drained += reader.drain_all().events.len() as u64;
            std::thread::sleep(Duration::from_micros(200));
        }
        drained += reader.drain_all().events.len() as u64;
        drained
    });
    let r3 = region.clone();
    let start = Instant::now();
    let producer = std::thread::spawn(move || {
        let mut w = unsafe { r3.writer(WriterPolicy::default(), system_clock() as Arc<dyn Clock>) };
        let mut published = 0u64;
        let mut degraded = 0u64;
        let mut dropped = 0u64;
        for i in 0..attempts {
            match w.write(ev(i, &PAYLOAD_256)) {
                WriteOutcome::Published { .. } => published += 1,
                WriteOutcome::PublishedDegraded { .. } => degraded += 1,
                WriteOutcome::Dropped { .. } => dropped += 1,
            }
        }
        let wait_ms = w.total_wait_ns / 1_000_000;
        done.store(true, Ordering::Relaxed);
        (published, degraded, dropped, wait_ms)
    });
    let (published, degraded, dropped, wait_ms) = producer.join().unwrap();
    let drained = consumer.join().unwrap();
    let elapsed = start.elapsed();
    CapThroughput {
        mem_kib: cfg.required_len() as u64 / 1024,
        throughput_eps: attempts * 1_000_000_000 / elapsed.as_nanos().max(1) as u64,
        published,
        degraded,
        dropped,
        drained,
        wait_ms,
        balanced: published + degraded + dropped == attempts && drained == published + degraded,
    }
}

struct CapSlowHost {
    attempted: u64,
    published: u64,
    degraded: u64,
    dropped: u64,
    drained: u64,
    balanced: bool,
}

fn run_capacity_slow_host(desc: usize, payload: usize, secs: u64) -> CapSlowHost {
    let cfg = RingConfig::new(desc, payload);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    let r2 = region.clone();
    let consumer = std::thread::spawn(move || {
        let mut reader = unsafe { r2.reader() };
        let mut drained = 0u64;
        while !d2.load(Ordering::Relaxed) {
            drained += reader.drain_all().events.len() as u64;
            std::thread::sleep(Duration::from_millis(5));
        }
        drained += reader.drain_all().events.len() as u64;
        drained
    });
    let r3 = region.clone();
    let producer = std::thread::spawn(move || {
        let mut w = unsafe { r3.writer(WriterPolicy::default(), system_clock() as Arc<dyn Clock>) };
        let start = Instant::now();
        let mut attempted = 0u64;
        let mut published = 0u64;
        let mut degraded = 0u64;
        let mut dropped = 0u64;
        let mut i = 0u64;
        while start.elapsed() < Duration::from_secs(secs) {
            match w.write(ev(i, &PAYLOAD_256)) {
                WriteOutcome::Published { .. } => published += 1,
                WriteOutcome::PublishedDegraded { .. } => degraded += 1,
                WriteOutcome::Dropped { .. } => dropped += 1,
            }
            attempted += 1;
            i += 1;
        }
        done.store(true, Ordering::Relaxed);
        (attempted, published, degraded, dropped)
    });
    let (attempted, published, degraded, dropped) = producer.join().unwrap();
    let drained = consumer.join().unwrap();
    CapSlowHost {
        attempted,
        published,
        degraded,
        dropped,
        drained,
        balanced: published + degraded + dropped == attempted && drained <= published + degraded,
    }
}

// ------------------------------------------------------- S2: BOUNDED_WAIT 上限

struct MaxWaitResume {
    published: usize,
    rounds: usize,
    median_delay_us: u64,
    p95_delay_us: u64,
    median_wait_ns: u64,
}

/// Host が書き手の待機を確認してから 500µs 後に回収する。書き手が再開できたかと再開遅延を測る。
fn run_max_wait_resume(max_wait: Duration, rounds: usize) -> MaxWaitResume {
    let mut delays = Vec::new();
    let mut waits = Vec::new();
    let mut published = 0usize;
    for _ in 0..rounds {
        let cfg = RingConfig::new(4, 256);
        let region = Arc::new(SharedRegion::new(cfg, 1, 1));
        let outcome: Arc<Mutex<Option<(bool, Instant, u64)>>> = Arc::new(Mutex::new(None));
        let o2 = outcome.clone();
        let r2 = region.clone();
        let producer = std::thread::spawn(move || {
            let mut w = unsafe {
                r2.writer(
                    WriterPolicy {
                        max_wait,
                        ..Default::default()
                    },
                    system_clock() as Arc<dyn Clock>,
                )
            };
            for i in 0..4 {
                let _ = w.write(ev(i, b"fill"));
            }
            let out = w.write(ev(4, b"blocked"));
            let t = Instant::now();
            let ok = matches!(out, WriteOutcome::Published { .. });
            *o2.lock().unwrap() = Some((ok, t, w.last_wait_ns));
        });
        let r3 = region.clone();
        let drain_done: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let d2 = drain_done.clone();
        let host = std::thread::spawn(move || {
            // 書き手が待機に入るまで待つ（最大 50ms。max_wait=0 では立たないのでそのまま進む）。
            let deadline = Instant::now() + Duration::from_millis(50);
            while !writer_waiting(r3.base()) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_micros(200));
            }
            std::thread::sleep(Duration::from_micros(500));
            let mut worker = unsafe { DrainWorker::new(r3.base(), cfg, 1) };
            let _ = worker.drain_all();
            *d2.lock().unwrap() = Some(Instant::now());
        });
        producer.join().unwrap();
        host.join().unwrap();
        let (ok, publish_at, last_wait) = outcome.lock().unwrap().take().unwrap();
        if ok {
            published += 1;
            if let Some(dd) = *drain_done.lock().unwrap() {
                delays.push(publish_at.saturating_duration_since(dd).as_nanos() as u64);
            }
            waits.push(last_wait);
        }
    }
    MaxWaitResume {
        published,
        rounds,
        median_delay_us: median(delays.clone()) / 1_000,
        p95_delay_us: p95(delays) / 1_000,
        median_wait_ns: median(waits),
    }
}

struct MaxWaitStuck {
    median_wall_us: u64,
    published: usize,
    rounds: usize,
}

/// Host が 30ms 回収しない。満杯への 1 回の書込がどれだけ停滞するかを測る。
fn run_max_wait_stuck(max_wait: Duration, rounds: usize) -> MaxWaitStuck {
    let mut walls = Vec::new();
    let mut published = 0usize;
    for _ in 0..rounds {
        let cfg = RingConfig::new(4, 256);
        let region = Arc::new(SharedRegion::new(cfg, 1, 1));
        let r2 = region.clone();
        let producer = std::thread::spawn(move || {
            let mut w = unsafe {
                r2.writer(
                    WriterPolicy {
                        max_wait,
                        ..Default::default()
                    },
                    system_clock() as Arc<dyn Clock>,
                )
            };
            for i in 0..4 {
                let _ = w.write(ev(i, b"fill"));
            }
            let t0 = Instant::now();
            let out = w.write(ev(4, b"blocked"));
            let wall = t0.elapsed();
            let ok = matches!(out, WriteOutcome::Published { .. });
            (wall, ok)
        });
        // Host は 30ms 後に回収する（producer の計測には影響しない）。
        let r3 = region.clone();
        let host = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let mut worker = unsafe { DrainWorker::new(r3.base(), cfg, 1) };
            let _ = worker.drain_all();
        });
        let (wall, ok) = producer.join().unwrap();
        host.join().unwrap();
        walls.push(wall.as_nanos() as u64);
        if ok {
            published += 1;
        }
    }
    MaxWaitStuck {
        median_wall_us: median(walls) / 1_000,
        published,
        rounds,
    }
}

// ------------------------------------------------------------ S3: 再確認周期

struct RecheckResult {
    median_detect_us: u64,
    p95_detect_us: u64,
    found: usize,
    rounds: usize,
    idle_wakeups_per_100ms: u64,
}

/// 通知を取りこぼした（data_ready を Set しない）Host が、再確認で
/// データ有りに気づくまでの遅延を測る。データの到着時刻はラウンドごとに
/// 1〜21ms の範囲でランダム化する（固定時刻だと到着位相が区間と同期し、
/// 区間の効果が測れないため）。乱数は xorshift（測定用の簡易生成器）。
fn run_recheck_detect(interval: Duration, rounds: usize) -> RecheckResult {
    let mut rng = XorShift(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1,
    );
    let mut lats = Vec::new();
    let mut found = 0usize;
    for _ in 0..rounds {
        let arrival = Duration::from_micros(1_000 + rng.next() % 20_000);
        let notify = ProcessNotify::new().expect("ProcessNotify");
        let data = Arc::new(AtomicBool::new(false));
        let d2 = data.clone();
        let start = Instant::now();
        let setter = std::thread::spawn(move || {
            std::thread::sleep(arrival);
            d2.store(true, Ordering::Release);
        });
        let set_at = start + arrival;
        let ok = notify.wait_with_recheck(
            ReCheckPolicy { interval },
            || data.load(Ordering::Acquire),
            Duration::from_millis(200),
        );
        let returned = Instant::now();
        setter.join().unwrap();
        if ok {
            found += 1;
            lats.push(returned.saturating_duration_since(set_at).as_nanos() as u64);
        }
    }
    // アイドル 100ms での再確認 (wakeup) 回数。recheck 呼び出し回数を数える。
    let mut wakeups = Vec::new();
    for _ in 0..5 {
        let notify = ProcessNotify::new().expect("ProcessNotify");
        let calls = Arc::new(AtomicU64::new(0));
        let c2 = calls.clone();
        let ok = notify.wait_with_recheck(
            ReCheckPolicy { interval },
            || {
                c2.fetch_add(1, Ordering::Relaxed);
                false
            },
            Duration::from_millis(100),
        );
        assert!(!ok, "idle recheck must time out");
        wakeups.push(calls.load(Ordering::Relaxed));
    }
    RecheckResult {
        median_detect_us: median(lats.clone()) / 1_000,
        p95_detect_us: p95(lats) / 1_000,
        found,
        rounds,
        idle_wakeups_per_100ms: median(wakeups),
    }
}

// ------------------------------------------------------------ S4: 復帰閾値

/// 新しい Ring で OVERFLOW まで書き、`drain_n` 件まとめて回収してから
/// 1 件書く。復帰（Normal）すれば true。
fn resume_after_batch_drain(pct: u64, drain_n: usize) -> bool {
    let cfg = RingConfig::new(16, 4096);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                resume_threshold_percent: pct,
                ..Default::default()
            },
            Arc::new(ManualClock::new()) as Arc<dyn Clock>,
        )
    };
    let mut reader = unsafe { region.reader() };
    let mut i = 0u64;
    loop {
        let _ = w.write(ev(i, &PAYLOAD_256));
        i += 1;
        if w.state() == OverflowState::Overflow {
            break;
        }
        assert!(i <= 64, "never reached OVERFLOW");
    }
    let batch = reader.drain(drain_n);
    assert_eq!(
        batch.events.len(),
        drain_n,
        "drain({drain_n}) must return all"
    );
    let _ = w.write(ev(i, &PAYLOAD_256));
    w.state() == OverflowState::Normal
}

struct ResumeResult {
    pct: u64,
    min_drain_to_resume: usize,
    headroom: u64,
    /// drain 1 件ずつの小刻みな回収を 32 回繰り返しても復帰しなかったか。
    no_resume_on_trickle: bool,
}

fn run_resume_threshold(pct: u64) -> ResumeResult {
    let min_drain = (1..=16)
        .find(|&k| resume_after_batch_drain(pct, k))
        .expect("must resume after draining everything");
    // headroom: 復帰させてから回収なしで書き続け、再 OVERFLOW までの Published 数。
    let cfg = RingConfig::new(16, 4096);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                resume_threshold_percent: pct,
                ..Default::default()
            },
            Arc::new(ManualClock::new()) as Arc<dyn Clock>,
        )
    };
    let mut reader = unsafe { region.reader() };
    let mut i = 0u64;
    loop {
        let _ = w.write(ev(i, &PAYLOAD_256));
        i += 1;
        if w.state() == OverflowState::Overflow {
            break;
        }
    }
    let batch = reader.drain(min_drain);
    assert_eq!(batch.events.len(), min_drain);
    let out = w.write(ev(i, &PAYLOAD_256));
    i += 1;
    assert!(matches!(out, WriteOutcome::Published { .. }));
    assert_eq!(w.state(), OverflowState::Normal);
    let mut headroom = 0u64;
    while let WriteOutcome::Published { .. } = w.write(ev(i, &PAYLOAD_256)) {
        headroom += 1;
        i += 1;
        assert!(headroom <= 64, "never re-overflowed");
    }
    // 小刻み回収の確認: drain 1 件→書込 1 件を 32 回繰り返す。
    let cfg2 = RingConfig::new(16, 4096);
    let region2 = SharedRegion::new(cfg2, 1, 1);
    let mut w2 = unsafe {
        region2.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                resume_threshold_percent: pct,
                ..Default::default()
            },
            Arc::new(ManualClock::new()) as Arc<dyn Clock>,
        )
    };
    let mut reader2 = unsafe { region2.reader() };
    let mut j = 0u64;
    loop {
        let _ = w2.write(ev(j, &PAYLOAD_256));
        j += 1;
        if w2.state() == OverflowState::Overflow {
            break;
        }
    }
    let mut resumed = false;
    for _ in 0..32 {
        let b = reader2.drain(1);
        assert_eq!(b.events.len(), 1);
        let _ = w2.write(ev(j, &PAYLOAD_256));
        j += 1;
        if w2.state() == OverflowState::Normal {
            resumed = true;
            break;
        }
    }
    ResumeResult {
        pct,
        min_drain_to_resume: min_drain,
        headroom,
        no_resume_on_trickle: !resumed,
    }
}

// ------------------------------------------------------- S5: Slot 数・低水位

struct SlotResult {
    bytes_per_slot: u64,
    pool_bytes: u64,
    pool_mib: f64,
    claim_32_us: u64,
    expansion_after_24: u64,
    expansion_after_25: u64,
}

fn run_slot_pool() -> SlotResult {
    let pool = SlotPool::production();
    assert_eq!(pool.capacity(), 32);
    assert_eq!(pool.low_watermark, 8);
    let start = Instant::now();
    let mut handles = Vec::new();
    for t in 0..32u64 {
        handles.push(pool.claim(t + 1).expect("slot must be claimable"));
        if t + 1 == 24 {
            // 空き 8 件（低水位ちょうど）ではまだ要求は立たないはず。
            assert_eq!(pool.free_count(), 8);
        }
    }
    let claim_32_us = start.elapsed().as_nanos() as u64 / 1_000;
    // 低水位の発火点は claim 中に観測済みのはずだが、ここで再確認する。
    // expansion_request_count は「要求が立った回数」で、初回のみ加算される。
    let expansion_after_25 = pool.expansion_request_count.load(Ordering::Relaxed);
    assert_eq!(pool.free_count(), 0);
    // 24 件目までの時点の値は、別プールで再現して測る。
    let pool2 = SlotPool::production();
    for t in 0..24u64 {
        let _ = pool2.claim(t + 1).expect("slot must be claimable");
    }
    let expansion_after_24 = pool2.expansion_request_count.load(Ordering::Relaxed);
    SlotResult {
        bytes_per_slot: SLOT_MEMORY_BYTES,
        pool_bytes: pool.total_memory_bytes(),
        pool_mib: pool.total_memory_bytes() as f64 / (1024.0 * 1024.0),
        claim_32_us,
        expansion_after_24,
        expansion_after_25,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args
        .windows(2)
        .find(|w| w[0] == "--rounds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(3);
    let slow_secs: u64 = args
        .windows(2)
        .find(|w| w[0] == "--slow-secs")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(2);
    let attempts: u64 = 50_000;
    println!(
        "tuning bench (A73): Linux, parallelism={:?}, rounds={rounds}, slow-host {slow_secs}s",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    let mut all_ok = true;

    // ---- S1a: 容量 × スループット（consumer 200µs 周期）
    println!("\n[S1a] capacity sweep: producer 50k x 256B events, consumer drains every 200us");
    println!(
        "{:>6} {:>10} {:>9} {:>12} {:>10} {:>10} {:>8} {:>8} {:>9}",
        "desc",
        "payload",
        "mem_KiB",
        "events/s",
        "published",
        "degraded",
        "dropped",
        "drained",
        "wait_ms"
    );
    let configs = [
        (256, 256 * 1024),
        (1024, 256 * 1024),
        (4096, 256 * 1024),
        (16384, 256 * 1024),
        (256, 1024 * 1024),
        (1024, 1024 * 1024),
        (4096, 1024 * 1024),
        (16384, 1024 * 1024),
        (256, 4 * 1024 * 1024),
        (1024, 4 * 1024 * 1024),
        (4096, 4 * 1024 * 1024),
        (16384, 4 * 1024 * 1024),
    ];
    for (d, p) in configs {
        let mut tps = Vec::new();
        let mut last: Option<CapThroughput> = None;
        for _ in 0..rounds {
            let r = run_capacity_throughput(d, p, attempts);
            tps.push(r.throughput_eps);
            all_ok &= r.balanced;
            last = Some(r);
        }
        let r = last.unwrap();
        println!(
            "{:>6} {:>10} {:>9} {:>12} {:>10} {:>10} {:>8} {:>8} {:>9}  (median {}/s)",
            d,
            p,
            r.mem_kib,
            r.throughput_eps,
            r.published,
            r.degraded,
            r.dropped,
            r.drained,
            r.wait_ms,
            median(tps)
        );
        if !r.balanced {
            println!("  MISMATCH: accounting does not balance for desc={d} payload={p}");
        }
    }

    // ---- S1b: 遅い Host (5ms 周期) での欠落率
    println!("\n[S1b] slow host: consumer drains every 5ms, producer runs {slow_secs}s");
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8}",
        "desc", "payload", "attempted", "published", "degraded", "dropped", "drained"
    );
    for (d, p) in configs {
        let r = run_capacity_slow_host(d, p, slow_secs);
        all_ok &= r.balanced;
        let drop_pct = r.dropped as f64 * 100.0 / r.attempted.max(1) as f64;
        let degr_pct = r.degraded as f64 * 100.0 / r.attempted.max(1) as f64;
        println!(
            "{:>6} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8}  (dropped {drop_pct:.2}%, degraded {degr_pct:.2}%)",
            d, p, r.attempted, r.published, r.degraded, r.dropped, r.drained
        );
        if !r.balanced {
            println!("  MISMATCH: accounting does not balance for desc={d} payload={p}");
        }
    }

    // ---- S2: BOUNDED_WAIT 上限
    println!("\n[S2a] max_wait sweep: host drains 500us after writer starts waiting (25 rounds)");
    println!(
        "{:>10} {:>9} {:>12} {:>12} {:>14}",
        "max_wait", "published", "delay_med_us", "delay_p95_us", "wait_med_ns"
    );
    for mw in [
        Duration::ZERO,
        Duration::from_micros(250),
        Duration::from_millis(1),
        Duration::from_millis(5),
    ] {
        let r = run_max_wait_resume(mw, 25);
        // 500µs 後に回収されるなら、1ms/5ms は再開できるはず。0/0.25ms は間に合わないはず。
        let expect_published = mw >= Duration::from_millis(1);
        let ok = if expect_published {
            r.published * 5 >= r.rounds * 4 // 80% 以上が再開
        } else {
            r.published == 0
        };
        all_ok &= ok;
        println!(
            "{:>10} {:>8}/{} {:>12} {:>12} {:>14}  {}",
            format!("{}us", mw.as_micros()),
            r.published,
            r.rounds,
            r.median_delay_us,
            r.p95_delay_us,
            r.median_wait_ns,
            if ok { "ok" } else { "MISMATCH" }
        );
    }
    println!("\n[S2b] max_wait sweep: host stuck 30ms, wall time of one blocked write (10 rounds)");
    println!(
        "{:>10} {:>14} {:>9}",
        "max_wait", "wall_med_us", "published"
    );
    for mw in [
        Duration::ZERO,
        Duration::from_micros(250),
        Duration::from_millis(1),
        Duration::from_millis(5),
    ] {
        let r = run_max_wait_stuck(mw, 10);
        // 停滞は max_wait 程度（+スライス誤差 5ms まで許容）。0 は即復帰。
        let wall_ok = if mw.is_zero() {
            r.median_wall_us < 5_000
        } else {
            let lo = mw.as_micros() as u64 * 8 / 10;
            let hi = mw.as_micros() as u64 + 5_000;
            r.median_wall_us >= lo && r.median_wall_us <= hi
        };
        all_ok &= wall_ok && r.published == 0;
        println!(
            "{:>10} {:>14} {:>8}/{}  {}",
            format!("{}us", mw.as_micros()),
            r.median_wall_us,
            r.published,
            r.rounds,
            if wall_ok && r.published == 0 {
                "ok"
            } else {
                "MISMATCH"
            }
        );
    }

    // ---- S3: 再確認周期
    println!("\n[S3] recheck interval sweep: lost notification, data arrival randomized 1-21ms (25 rounds)");
    println!(
        "{:>10} {:>13} {:>12} {:>8} {:>18}",
        "interval", "detect_med_us", "detect_p95_us", "found", "idle_wakeups/100ms"
    );
    for iv in [
        Duration::from_millis(1),
        Duration::from_millis(2),
        Duration::from_millis(5),
        Duration::from_millis(10),
    ] {
        let r = run_recheck_detect(iv, 25);
        let ok = r.found == r.rounds;
        all_ok &= ok;
        println!(
            "{:>10} {:>13} {:>12} {:>7}/{} {:>18}  {}",
            format!("{}ms", iv.as_millis()),
            r.median_detect_us,
            r.p95_detect_us,
            r.found,
            r.rounds,
            r.idle_wakeups_per_100ms,
            if ok { "ok" } else { "MISMATCH" }
        );
    }

    // ---- S4: 復帰閾値
    println!("\n[S4] resume threshold sweep: 16-desc ring, payload 256B/event");
    println!(
        "{:>10} {:>18} {:>10} {:>22}",
        "threshold", "min_drain_to_resume", "headroom", "no_resume_on_trickle"
    );
    for pct in [25u64, 50, 75] {
        let r = run_resume_threshold(pct);
        println!(
            "{:>9}% {:>18} {:>10} {:>22}",
            r.pct, r.min_drain_to_resume, r.headroom, r.no_resume_on_trickle
        );
        all_ok &= r.no_resume_on_trickle;
    }

    // ---- S5: Slot 数・低水位
    println!("\n[S5] slot pool: production() = 32 slots, low watermark 8");
    let s = run_slot_pool();
    println!(
        "bytes per slot: {} ({} KiB)",
        s.bytes_per_slot,
        s.bytes_per_slot / 1024
    );
    println!(
        "pool total: {} bytes ({:.1} MiB) for 32 slots",
        s.pool_bytes, s.pool_mib
    );
    println!("claim 32 slots: {} us", s.claim_32_us);
    println!(
        "expansion_request_count after 24 claims (8 free): {}",
        s.expansion_after_24
    );
    println!(
        "expansion_request_count after 25 claims (7 free): {}",
        s.expansion_after_25
    );
    let slot_ok = s.expansion_after_24 == 0 && s.expansion_after_25 == 1;
    all_ok &= slot_ok;
    if !slot_ok {
        println!("  MISMATCH: low-watermark trigger point is not at the 25th claim");
    }

    println!(
        "\nnote: consumer in S1 uses the unvalidated RingReader (test/internal path) to isolate\ncapacity effects; the validating DrainWorker copies the whole image per drain (D65),\nso its per-drain cost grows with ring size and is a separate factor."
    );
    println!("note: Windows real-machine numbers are CI-only (this run is Linux).");
    std::process::exit(if all_ok { 0 } else { 1 });
}
