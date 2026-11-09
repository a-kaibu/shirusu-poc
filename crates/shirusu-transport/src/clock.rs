//! QPC 相当の単調時計の抽象。待機時間の実測と、DST/PBT での仮想時計差替えに使う。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub trait Clock: Send + Sync {
    /// QPC tick 相当の単調増加値。
    fn now_ticks(&self) -> u64;
    /// 1 秒あたりの tick 数。
    fn ticks_per_second(&self) -> u64;
    /// 待機する。仮想時計では実時間を眠らず仮想時刻だけ進める。
    fn sleep(&self, dur: Duration);
    fn elapsed_ns(&self, start: u64, end: u64) -> u64 {
        let ticks = end.saturating_sub(start);
        let per = self.ticks_per_second().max(1);
        ticks.saturating_mul(1_000_000_000) / per
    }
}

/// 実時計。std::time::Instant を QPC の代替とする（Windows 実装では QPC 周波数へ読み替え可能）。
pub struct SystemClock {
    origin: Instant,
}
impl Default for SystemClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}
impl Clock for SystemClock {
    fn now_ticks(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64
    }
    fn ticks_per_second(&self) -> u64 {
        1_000_000_000
    }
    fn sleep(&self, dur: Duration) {
        if dur.is_zero() {
            std::thread::yield_now();
        } else {
            std::thread::sleep(dur);
        }
    }
}

/// 仮想時計（テスト/DST 用）。sleep で仮想時刻が進み、決定論的に再現できる。
pub struct ManualClock {
    ticks: AtomicU64,
    pub ticks_per_second: u64,
}
impl ManualClock {
    pub fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            ticks_per_second: 1_000_000_000,
        }
    }
    pub fn advance(&self, dur: Duration) {
        self.ticks
            .fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
    }
    pub fn set(&self, ticks: u64) {
        self.ticks.store(ticks, Ordering::Relaxed);
    }
}
impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock for ManualClock {
    fn now_ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }
    fn ticks_per_second(&self) -> u64 {
        self.ticks_per_second
    }
    fn sleep(&self, dur: Duration) {
        // 実時間は眠らず、仮想時刻だけを進める。最小 1 tick 進めることで待機ループが必ず前進する。
        let ns = (dur.as_nanos() as u64).max(1);
        self.ticks.fetch_add(ns, Ordering::Relaxed);
    }
}

pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manual_clock_default_starts_at_zero() {
        let c = ManualClock::default();
        assert_eq!(c.now_ticks(), 0);
        assert_eq!(c.ticks_per_second(), 1_000_000_000);
    }
    #[test]
    fn manual_clock_advances_on_sleep() {
        let c = ManualClock::new();
        let s = c.now_ticks();
        c.sleep(Duration::from_millis(1));
        assert!(c.now_ticks() > s);
        assert_eq!(c.elapsed_ns(s, c.now_ticks()), 1_000_000);
    }
    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemClock::default();
        let a = c.now_ticks();
        let b = c.now_ticks();
        assert!(b >= a);
    }
    #[test]
    fn system_clock_sleep_actually_sleeps() {
        // cargo-mutants で検出: sleep 本体を消す mutant が生き残っていた。
        // 実時間が実際に進むことを測って倒す。
        let c = SystemClock::default();
        let start = c.now_ticks();
        c.sleep(Duration::from_millis(3));
        let elapsed = c.elapsed_ns(start, c.now_ticks());
        assert!(
            elapsed >= 1_000_000,
            "3ms sleep must advance real time (>=1ms), got {elapsed}ns"
        );
        assert!(elapsed < 5_000_000_000, "sleep must not overshoot wildly");
        c.sleep(Duration::ZERO); // yield 経路も通す
    }
}
