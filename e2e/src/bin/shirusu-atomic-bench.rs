//! A74: 64bit アトミック操作のコスト測定ベンチ。
//!
//! spec (Cursor 節): 「i686 での 64bit アトミック操作 (cmpxchg8b 等で
//! 実現される) のコストが問題になれば、32bit の折り返しカウンタに
//! 切り替える」。現行実装は 64bit Cursor (AtomicU64) で、この bench が
//! その判断材料を測る。
//!
//! 測定するもの:
//! - L64/L32: 単スレッドの fetch_add / load / store / CAS の ns/op
//!   (AtomicU64 と AtomicU32 を同条件で比較する)
//! - SPSC64/SPSC32: Cursor の実利用に近い形。書き手が fetch_add で
//!   Cursor を進め、読み手が load で追う 2 スレッドのスループット
//! - CONT64/CONT32: 4 スレッドが同じカウンタへ fetch_add する競合時
//!
//! 切替判断の基準 (この bench の出力に対する読み方):
//! - 64bit fetch_add のレイテンシが 32bit の 2 倍を超える、または
//!   SPSC スループットが 32bit 版の 70% 未満に落ちる場合、
//!   「32bit 折り返しカウンタへの切替検討を開始する」。
//! - 判断は対象環境 (Windows i686 / WoW64) の実測で行う。x86_64 や
//!   Linux i686 の数値は参考値であり、判断そのものには使わない。
//!
//! 使い方:
//!   cargo run -p shirusu-e2e --release --bin shirusu-atomic-bench [-- --ops 10000000 --rounds 3]
//!   (i686) cargo run -p shirusu-e2e --release --target i686-pc-windows-msvc --bin shirusu-atomic-bench
//! CI では windows.ps1 (x64) と windows-x86.ps1 (i686, WoW64) が実行する。

use std::hint::black_box;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn bench_latency<T, F: Fn(&T)>(make: impl Fn() -> T, op: F, ops: u64, rounds: usize) -> f64 {
    let mut samples = Vec::new();
    for _ in 0..rounds {
        let v = make();
        let start = Instant::now();
        for _ in 0..ops {
            op(&v);
        }
        black_box(&v);
        samples.push(start.elapsed().as_nanos() as f64 / ops as f64);
    }
    median(samples)
}

/// SPSC の Cursor パターン: 書き手が Release store で Cursor を進め、
/// 読み手が Acquire load で追う。書き手側の ns/op を返す (読み手の
/// 追走によるキャッシュ競合込みの、実利用に近い条件で測る)。
fn bench_spsc64(total: u64) -> f64 {
    let cursor = Arc::new(AtomicU64::new(0));
    let c2 = cursor.clone();
    let reader = std::thread::spawn(move || {
        let mut last = 0u64;
        while last < total {
            last = c2.load(Ordering::Acquire);
        }
        black_box(last);
    });
    let start = Instant::now();
    for i in 1..=total {
        cursor.store(i, Ordering::Release);
    }
    let elapsed = start.elapsed();
    let _ = reader.join();
    elapsed.as_nanos() as f64 / total as f64
}

fn bench_spsc32(total: u64) -> f64 {
    let cursor = Arc::new(AtomicU32::new(0));
    let c2 = cursor.clone();
    let reader = std::thread::spawn(move || {
        let mut last = 0u32;
        while last < total as u32 {
            last = c2.load(Ordering::Acquire);
        }
        black_box(last);
    });
    let start = Instant::now();
    for i in 1..=total {
        cursor.store(i as u32, Ordering::Release);
    }
    let elapsed = start.elapsed();
    let _ = reader.join();
    elapsed.as_nanos() as f64 / total as f64
}

fn bench_contended64(threads: u64, per_thread: u64) -> f64 {
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let c = counter.clone();
            std::thread::spawn(move || {
                for _ in 0..per_thread {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    start.elapsed().as_nanos() as f64 / (threads * per_thread) as f64
}

fn bench_contended32(threads: u64, per_thread: u64) -> f64 {
    let counter = Arc::new(AtomicU32::new(0));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let c = counter.clone();
            std::thread::spawn(move || {
                for _ in 0..per_thread {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    start.elapsed().as_nanos() as f64 / (threads * per_thread) as f64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ops: u64 = 10_000_000;
    let mut rounds: usize = 3;
    let mut i = 1;
    while i + 1 < args.len() + 1 && i < args.len() {
        match args[i].as_str() {
            "--ops" if i + 1 < args.len() => {
                ops = args[i + 1].parse().unwrap_or(ops);
                i += 2;
            }
            "--rounds" if i + 1 < args.len() => {
                rounds = args[i + 1].parse().unwrap_or(rounds);
                i += 2;
            }
            _ => i += 1,
        }
    }
    println!(
        "shirusu-atomic-bench: arch={} ops={} rounds={} (median ns/op)",
        std::env::consts::ARCH,
        ops,
        rounds
    );

    let fa64 = bench_latency(
        || AtomicU64::new(0),
        |v: &AtomicU64| {
            black_box(v.fetch_add(1, Ordering::Relaxed));
        },
        ops,
        rounds,
    );
    let fa32 = bench_latency(
        || AtomicU32::new(0),
        |v: &AtomicU32| {
            black_box(v.fetch_add(1, Ordering::Relaxed));
        },
        ops,
        rounds,
    );
    let load64 = bench_latency(
        || AtomicU64::new(0),
        |v: &AtomicU64| {
            black_box(v.load(Ordering::Acquire));
        },
        ops,
        rounds,
    );
    let load32 = bench_latency(
        || AtomicU32::new(0),
        |v: &AtomicU32| {
            black_box(v.load(Ordering::Acquire));
        },
        ops,
        rounds,
    );
    let store64 = bench_latency(
        || AtomicU64::new(0),
        |v: &AtomicU64| {
            v.store(1, Ordering::Release);
        },
        ops,
        rounds,
    );
    let store32 = bench_latency(
        || AtomicU32::new(0),
        |v: &AtomicU32| {
            v.store(1, Ordering::Release);
        },
        ops,
        rounds,
    );
    let cas64 = bench_latency(
        || AtomicU64::new(0),
        |v: &AtomicU64| {
            let cur = v.load(Ordering::Relaxed);
            black_box(
                v.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok(),
            );
        },
        ops,
        rounds,
    );
    let cas32 = bench_latency(
        || AtomicU32::new(0),
        |v: &AtomicU32| {
            let cur = v.load(Ordering::Relaxed);
            black_box(
                v.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok(),
            );
        },
        ops,
        rounds,
    );

    let spsc64 = median((0..rounds).map(|_| bench_spsc64(ops)).collect());
    let spsc32 = median((0..rounds).map(|_| bench_spsc32(ops)).collect());
    let cont64 = bench_contended64(4, ops / 4);
    let cont32 = bench_contended32(4, ops / 4);

    println!(
        "fetch_add:  u64 {fa64:8.2} ns/op | u32 {fa32:8.2} ns/op | ratio {:.2}",
        fa64 / fa32
    );
    println!(
        "load:       u64 {load64:8.2} ns/op | u32 {load32:8.2} ns/op | ratio {:.2}",
        load64 / load32
    );
    println!(
        "store:      u64 {store64:8.2} ns/op | u32 {store32:8.2} ns/op | ratio {:.2}",
        store64 / store32
    );
    println!(
        "cas:        u64 {cas64:8.2} ns/op | u32 {cas32:8.2} ns/op | ratio {:.2}",
        cas64 / cas32
    );
    println!(
        "spsc cursor: u64 {spsc64:8.2} ns/op | u32 {spsc32:8.2} ns/op | ratio {:.2}",
        spsc64 / spsc32
    );
    println!(
        "contended fetch_add (4t): u64 {cont64:8.2} ns/op | u32 {cont32:8.2} ns/op | ratio {:.2}",
        cont64 / cont32
    );

    let needs_review = fa64 / fa32 > 2.0 || spsc64 / spsc32 > 1.0 / 0.70;
    println!(
        "verdict (arch={}): {}",
        std::env::consts::ARCH,
        if needs_review {
            "REVIEW: 64bit コストが基準を超えた。32bit 折り返しカウンタへの切替検討を開始すること"
        } else {
            "OK: 基準内。64bit Cursor を継続してよい (対象環境の実測で最終判断)"
        }
    );
}
