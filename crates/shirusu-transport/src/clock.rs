//! 時計の抽象は責務で 2 つに分ける (レビュー第2回・項目8)。
//!
//! - `Clock`: 待機時間の実測・再確認・ベンチマーク用。差し替え可能で、
//!   DST/PBT では仮想時計 (ManualClock) に替える。原点はインスタンス
//!   ごとの相対値でよく、イベント時刻には使わない。
//! - `TimestampSource`: イベント時刻専用。Descriptor の `timestamp_qpc`
//!   に刻む値と、その周波数を返す。仕様 (overview / spec) はイベント時刻を
//!   QPC 値と周波数で記録し、プロセス間で比較可能にすることを定めるため、
//!   待機用 Clock を差し替えても原点が動いてはならない。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub trait Clock: Send + Sync {
    /// 待機実測用の単調増加値。原点はインスタンス相対でよい
    /// (イベント時刻の刻印には使わない。そちらは [`TimestampSource`])。
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

/// イベント時刻の供給源。`now_qpc` の値は同じプロセス内では単調で、
/// 周波数 (`frequency`) と組にして解釈する。Windows では
/// `shirusu-transport-win` の QPC 実装が本物の QueryPerformanceCounter
/// 値を返し、プロセス間でそのまま比較できる。待機制御には使わない
/// (そちらは [`Clock`])。
pub trait TimestampSource: Send + Sync {
    /// QPC 相当の単調増加値 (イベント時刻の刻印用)。
    fn now_qpc(&self) -> u64;
    /// 1 秒あたりの tick 数 (`now_qpc` の周波数)。
    fn frequency(&self) -> u64;
    /// Ring の書き手がこの時刻源を TSC で補間してよいか
    /// ([`crate::tsc::EventTimestamper`])。値は常にこの時刻源の単位に保つ。
    /// 既定は false (毎回 `now_qpc` を読む)。
    fn tsc_interpolation(&self) -> bool {
        false
    }
}

/// 既定のイベント時刻源 (std のみ・ポータブル)。
///
/// 原点はプロセス全体で 1 つだけ (初回利用時に確定する `OnceLock`)。
/// `SystemClock` と違いインスタンス生成タイミングに原点が依存しない
/// ため、Writer ごとに作っても同じ時刻系になる。単調性は `Instant`
/// 由来。真の QPC ではないのでプロセス間比較は Windows の QPC 実装が
/// 担い、こちらはフォールバックと位置づける (README 所感参照)。
pub struct SystemTimestampSource {
    _private: (),
}
impl SystemTimestampSource {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
impl Default for SystemTimestampSource {
    fn default() -> Self {
        Self::new()
    }
}
static TIMESTAMP_ORIGIN: OnceLock<Instant> = OnceLock::new();
impl TimestampSource for SystemTimestampSource {
    fn now_qpc(&self) -> u64 {
        TIMESTAMP_ORIGIN
            .get_or_init(Instant::now)
            .elapsed()
            .as_nanos() as u64
    }
    fn frequency(&self) -> u64 {
        1_000_000_000
    }
}

/// テスト用のイベント時刻源。値を明示的に設定・前進させる。
pub struct ManualTimestampSource {
    ticks: AtomicU64,
    frequency: u64,
}
impl ManualTimestampSource {
    pub fn new(ticks: u64, frequency: u64) -> Self {
        Self {
            ticks: AtomicU64::new(ticks),
            frequency,
        }
    }
    pub fn set(&self, ticks: u64) {
        self.ticks.store(ticks, Ordering::Relaxed);
    }
    pub fn advance(&self, ticks: u64) {
        self.ticks.fetch_add(ticks, Ordering::Relaxed);
    }
}
impl TimestampSource for ManualTimestampSource {
    fn now_qpc(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }
    fn frequency(&self) -> u64 {
        self.frequency
    }
}

pub fn system_timestamp_source() -> Arc<dyn TimestampSource> {
    Arc::new(SystemTimestampSource::new())
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
