//! 待機方式のベンチマーク (A65): 書き手が bounded_wait で空きを待つとき、
//! `Clock::sleep` の実装（待機方式）を変えると、Host が回収してから書き手が
//! 書き込みを再開するまでの遅延と、待機ループの回数がどう変わるかを測る。
//!
//! 方式:
//! - sleep: 現行（50µs スライスの実 sleep）。SystemClock と同じ挙動。
//! - yield: sleep 時間いっぱい `yield_now` を繰り返す。
//! - spin: sleep 時間いっぱいビジーループする。
//! - event: `EventClock`。書き手が Ring の `space_available` イベントを待つ。
//!   回収側は `NotifyingDrainWorker` を通り、同じイベントへ SetEvent する。
//!   Windows ではカーネルイベント、Linux スタブでは condvar ベースの待機。
//!
//! 使い方: `cargo run -p shirusu-e2e --bin shirusu-wait-bench [-- --rounds 25]`

use shirusu_e2e::ev;
use shirusu_host::{DrainWorker, NotifyingDrainWorker};
use shirusu_transport::clock::Clock;
use shirusu_transport::layout::writer_waiting;
use shirusu_transport::ring::{SharedRegion, WriterPolicy};
use shirusu_transport::RingConfig;
use shirusu_transport_win::{EventClock, RingNotify};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strategy {
    Sleep,
    Yield,
    Spin,
    Event,
}
impl Strategy {
    fn name(self) -> &'static str {
        match self {
            Strategy::Sleep => "sleep",
            Strategy::Yield => "yield",
            Strategy::Spin => "spin",
            Strategy::Event => "event",
        }
    }
}

/// sleep / yield / spin 用の Clock。event は `EventClock` が担う。
struct BenchClock {
    strategy: Strategy,
    calls: AtomicU64,
    origin: Instant,
}
impl BenchClock {
    fn new(strategy: Strategy) -> Self {
        Self {
            strategy,
            calls: AtomicU64::new(0),
            origin: Instant::now(),
        }
    }
    fn sleep_calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}
impl Clock for BenchClock {
    fn now_ticks(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64
    }
    fn ticks_per_second(&self) -> u64 {
        1_000_000_000
    }
    fn sleep(&self, dur: Duration) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.strategy {
            Strategy::Sleep => std::thread::sleep(dur),
            Strategy::Yield => {
                let end = Instant::now() + dur;
                while Instant::now() < end {
                    std::thread::yield_now();
                }
            }
            Strategy::Spin => {
                let end = Instant::now() + dur;
                while Instant::now() < end {
                    std::hint::spin_loop();
                }
            }
            // event は EventClock が担うためここには来ない。念のため実 sleep。
            Strategy::Event => std::thread::sleep(dur),
        }
    }
}

struct RoundResult {
    /// Host の回収完了から、待っていた書き込みの公開までの遅延。
    wake_latency: Option<Duration>,
    sleep_calls: u64,
    published: u64,
    dropped: u64,
    drained: usize,
}

fn run_round(strategy: Strategy) -> RoundResult {
    let cfg = RingConfig::new(4, 256);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    // 書き手と Host で同じ space_available イベントを共有する。
    let notify = Arc::new(RingNotify::new().expect("RingNotify"));
    let bench_clock = Arc::new(BenchClock::new(strategy));
    let event_clock = Arc::new(EventClock::new(Arc::clone(&notify)));
    let clock: Arc<dyn Clock> = if strategy == Strategy::Event {
        event_clock.clone()
    } else {
        bench_clock.clone()
    };
    let total = 8u64;
    let blocked_done: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let bd2 = blocked_done.clone();
    let r2 = region.clone();
    let c2 = clock.clone();
    let producer = std::thread::spawn(move || {
        let mut w = unsafe {
            r2.writer(
                WriterPolicy {
                    max_wait: Duration::from_secs(10),
                    ..Default::default()
                },
                c2,
            )
        };
        let mut published = 0u64;
        let mut dropped = 0u64;
        for i in 0..total {
            let out = w.write(ev(i, b"wait-bench"));
            if i == 4 {
                // 5 件目が Ring 満杯で待機に入るはずの書き込み。
                *bd2.lock().unwrap() = Some(Instant::now());
            }
            match out {
                shirusu_transport::ring::WriteOutcome::Published { .. } => published += 1,
                _ => dropped += 1,
            }
        }
        (published, dropped)
    });
    // 書き手が空き待ちに入るまで待つ。
    let deadline = Instant::now() + Duration::from_secs(5);
    let sleep_calls = || {
        if strategy == Strategy::Event {
            event_clock.sleep_calls()
        } else {
            bench_clock.sleep_calls()
        }
    };
    loop {
        if writer_waiting(region.base()) {
            break;
        }
        if Instant::now() > deadline {
            let _ = producer.join();
            return RoundResult {
                wake_latency: None,
                sleep_calls: sleep_calls(),
                published: 0,
                dropped: total,
                drained: 0,
            };
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // 書き手が待機の最中であることを確定させてから回収する。
    std::thread::sleep(Duration::from_millis(10));
    let worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
    let mut host = NotifyingDrainWorker::new(worker, Arc::clone(&notify), &region);
    let mut drained = host.drain_all().events.len();
    let drain_done = Instant::now();
    let (published, dropped) = producer.join().unwrap_or((0, total));
    drained += host.drain_all().events.len();
    let wake_latency = blocked_done
        .lock()
        .unwrap()
        .map(|t| t.saturating_duration_since(drain_done));
    RoundResult {
        wake_latency,
        sleep_calls: sleep_calls(),
        published,
        dropped,
        drained,
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args
        .windows(2)
        .find(|w| w[0] == "--rounds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(25);
    let strategies = [
        Strategy::Sleep,
        Strategy::Yield,
        Strategy::Spin,
        Strategy::Event,
    ];
    println!("wait strategy bench: {rounds} rounds each, ring 4 desc / 256B payload");
    println!(
        "{:<8} {:>12} {:>12} {:>12} {:>10}",
        "method", "median_us", "p95_us", "sleep_calls", "ok"
    );
    let mut medians: Vec<(Strategy, u64)> = Vec::new();
    let mut all_ok = true;
    for s in strategies {
        let mut lat = Vec::new();
        let mut calls = Vec::new();
        let mut ok = 0;
        for _ in 0..rounds {
            let r = run_round(s);
            if let Some(l) = r.wake_latency {
                lat.push(l.as_nanos() as u64);
            }
            calls.push(r.sleep_calls);
            if r.published == 8 && r.dropped == 0 && r.drained == 8 {
                ok += 1;
            }
        }
        let med = median(lat.clone());
        medians.push((s, med));
        all_ok &= ok == rounds;
        println!(
            "{:<8} {:>12} {:>12} {:>12} {:>9}/{rounds}",
            s.name(),
            med / 1_000,
            p95(lat) / 1_000,
            median(calls),
            ok
        );
    }
    // 選定: ビジーにしない方式（sleep / event）の中で中央値遅延が最小のもの。
    // spin / yield は遅延は小さいが、各 sleep 呼び出しの中で CPU を焼き続ける
    // （sleep_calls はループ回数で、1 回あたりの CPU 消費は表に出ない）ため、
    // 待機方式としては選ばない。
    let non_busy = medians
        .iter()
        .filter(|(s, _)| matches!(s, Strategy::Sleep | Strategy::Event));
    if let Some((best, _)) = non_busy.min_by_key(|(_, m)| *m) {
        println!(
            "selection: {} (lowest median wake latency among non-busy methods)",
            best.name()
        );
    }
    println!("note: spin/yield burn a full core inside each sleep call; sleep/event block.");
    std::process::exit(if all_ok { 0 } else { 1 });
}
