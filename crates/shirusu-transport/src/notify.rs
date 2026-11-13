//! 通知ロジック（OS 非依存の純粋ロジック）。
//! - `data_ready` は auto-reset 前提。Host は既定 2ms 周期で再確認する。
//! - 書き手は公開後にフラグをフェンスなしで読み、立っていれば通知する。
//! - 使用率が閾値を下から上へ越えたときだけ一度通知する。
//!
//! 通常経路に全順序フェンスは入れない（このモジュールは原子操作の順序付けを行わない）。

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifySignal {
    None,
    /// Host が待機中フラグを立てていたので通知する。
    HostWaiting,
    /// 使用率が閾値を下から上へ越えたので通知する。
    ThresholdCrossing,
}

// Preserve usage_percent's saturation and zero-capacity semantics without
// division on each publication. floor(n / d) >= t iff n >= t*d; an
// overflowing product cannot be reached by the saturated u64 numerator.
#[inline]
fn usage_at_least(used: u64, capacity: u64, threshold: u64) -> bool {
    if capacity == 0 {
        return threshold <= 100;
    }
    threshold
        .checked_mul(capacity)
        .is_some_and(|minimum| used.saturating_mul(100) >= minimum)
}

#[derive(Debug, Default, Clone)]
pub struct PublishNotifyTracker {
    above_threshold: bool,
}
impl PublishNotifyTracker {
    pub fn new() -> Self {
        Self::default()
    }
    /// 公開直後に呼ぶ。使用量と容量は同じ単位（件数またはバイト数）。
    pub fn after_publish(
        &mut self,
        used_before: u64,
        used_after: u64,
        capacity: u64,
        threshold_percent: u64,
        host_waiting: bool,
    ) -> NotifySignal {
        let was_above = used_before > 0 && usage_at_least(used_before, capacity, threshold_percent);
        let is_above = usage_at_least(used_after, capacity, threshold_percent);
        // The consumer can drain below the threshold between publications.
        // Its current read cursor (used_before) rearms the edge even when no
        // producer event was published while occupancy was below threshold.
        self.above_threshold &= was_above;
        let crossed = is_above && !self.above_threshold && !was_above;
        self.above_threshold = is_above;
        if crossed {
            NotifySignal::ThresholdCrossing
        } else if host_waiting {
            NotifySignal::HostWaiting
        } else {
            NotifySignal::None
        }
    }
    /// 読み手が回収して使用率が下がったことを反映する。
    pub fn observe_used(&mut self, used: u64, capacity: u64, threshold_percent: u64) {
        self.above_threshold = usage_at_least(used, capacity, threshold_percent);
    }
}

/// Host 側の再確認ポリシー。通知を取りこぼしても無期限に待たない。
/// ただし待機が終わった後にすぐ実行されるとは限らないため、2ms 以内の回収は
/// 保証しない。2ms は再確認の周期であり、回収遅延の上限ではない。
#[derive(Debug, Clone, Copy)]
pub struct ReCheckPolicy {
    pub interval: Duration,
}
impl Default for ReCheckPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(2),
        }
    }
}
impl ReCheckPolicy {
    /// 待機開始からの経過で再確認すべきか。
    pub fn should_recheck(&self, waited: Duration) -> bool {
        waited >= self.interval
    }
    /// 次の再確認までの待機時間（Event 待機のタイムアウトに使う）。
    /// `waited` は「待機開始からの経過」であり、返る値はその経過時点から
    /// 次の再確認時刻までの残り。ループの各反復のスライス計算には使わない
    /// こと (反復ごとに interval から数え直す。R4)。
    pub fn wait_timeout(&self, waited: Duration) -> Duration {
        self.interval.saturating_sub(waited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    proptest::proptest! {
        #[test]
        fn division_free_watermark_matches_saturated_percentage(
            used in proptest::prelude::any::<u64>(),
            capacity in proptest::prelude::any::<u64>(),
            threshold in proptest::prelude::any::<u64>(),
        ) {
            proptest::prop_assert_eq!(usage_at_least(used, capacity, threshold),
                crate::layout::usage_percent(used, capacity) >= threshold);
        }
    }

    #[test]
    fn watermark_extremes_preserve_zero_capacity_and_saturation() {
        let edges = [0, 1, 49, 50, 99, 100, u64::MAX / 100, u64::MAX];
        for used in edges {
            for capacity in edges {
                for threshold in edges {
                    assert_eq!(
                        usage_at_least(used, capacity, threshold),
                        crate::layout::usage_percent(used, capacity) >= threshold
                    );
                }
            }
        }
    }

    #[test]
    fn notifies_when_host_waiting() {
        let mut t = PublishNotifyTracker::new();
        assert_eq!(
            t.after_publish(0, 1, 100, 50, true),
            NotifySignal::HostWaiting
        );
        assert_eq!(t.after_publish(0, 1, 100, 50, false), NotifySignal::None);
    }
    #[test]
    fn threshold_crossing_fires_once() {
        let mut t = PublishNotifyTracker::new();
        assert_eq!(
            t.after_publish(49, 50, 100, 50, false),
            NotifySignal::ThresholdCrossing
        );
        // 閾値を超えている間は繰り返さない
        assert_eq!(t.after_publish(50, 51, 100, 50, false), NotifySignal::None);
        assert_eq!(t.after_publish(60, 61, 100, 50, false), NotifySignal::None);
        // 下がってから再び越えたら再度通知する
        t.observe_used(10, 100, 50);
        assert_eq!(
            t.after_publish(49, 50, 100, 50, false),
            NotifySignal::ThresholdCrossing
        );
    }
    #[test]
    fn recheck_policy_is_bounded() {
        let p = ReCheckPolicy::default();
        assert!(!p.should_recheck(Duration::from_millis(1)));
        assert!(p.should_recheck(Duration::from_millis(2)));
        assert_eq!(p.wait_timeout(Duration::from_millis(5)), Duration::ZERO);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// 除算を使わない閾値判定は、128bit の乗算で書いた定義式と全域で一致する。
    /// 定義式: floor(min(used*100, u64::MAX) / capacity) >= threshold
    ///   ⇔ min(used*100, u64::MAX) >= threshold*capacity (capacity > 0)。
    /// 容量 0 は usage_percent の「100% に潰す」意味と一致する。
    /// (usage_percent との直接比較は記号除算になり CBMC で解けないため、
    /// 除算の等価性は PBT と境界行列が担い、ここでは乗算側を全域で証明する)
    #[kani::proof]
    fn usage_at_least_matches_wide_multiplication() {
        let used: u64 = kani::any();
        let capacity: u64 = kani::any();
        let threshold: u64 = kani::any();
        let expected = if capacity == 0 {
            threshold <= 100
        } else {
            let numerator = (used as u128 * 100).min(u64::MAX as u128);
            numerator >= threshold as u128 * capacity as u128
        };
        assert!(usage_at_least(used, capacity, threshold) == expected);
    }

    /// ThresholdCrossing は「公開後に閾値以上」かつ「公開前は閾値未満 (または空)」
    /// のときだけ返る。任意の内部状態から 1 回の公開について成り立つ。
    #[kani::proof]
    fn threshold_crossing_requires_upward_edge() {
        let mut t = PublishNotifyTracker {
            above_threshold: kani::any(),
        };
        let before: u64 = kani::any();
        let after: u64 = kani::any();
        let cap: u64 = kani::any();
        let th: u64 = kani::any();
        kani::assume(cap <= 1 << 20 && th <= 200);
        let waiting: bool = kani::any();
        let signal = t.after_publish(before, after, cap, th, waiting);
        if signal == NotifySignal::ThresholdCrossing {
            assert!(usage_at_least(after, cap, th));
            assert!(before == 0 || !usage_at_least(before, cap, th));
        }
        // Host が待機中なら、必ず何らかの通知が出る (取りこぼしの元にならない)。
        if waiting {
            assert!(signal != NotifySignal::None);
        }
        // 追跡状態は直近の公開後の判定そのもの。
        assert!(t.above_threshold == usage_at_least(after, cap, th));
    }

    /// 回収を挟まずに閾値以上のまま公開が続く間、ThresholdCrossing は二度出ない。
    #[kani::proof]
    fn threshold_crossing_does_not_repeat_without_drain() {
        let mut t = PublishNotifyTracker::new();
        let u0: u64 = kani::any();
        let u1: u64 = kani::any();
        let u2: u64 = kani::any();
        let cap: u64 = kani::any();
        let th: u64 = kani::any();
        kani::assume(cap >= 1 && cap <= 1 << 16 && th >= 1 && th <= 100);
        kani::assume(u0 <= u1 && u1 <= u2 && u2 <= cap);
        let first = t.after_publish(u0, u1, cap, th, false);
        let second = t.after_publish(u1, u2, cap, th, false);
        assert!(
            !(first == NotifySignal::ThresholdCrossing
                && second == NotifySignal::ThresholdCrossing)
        );
        // 単調に増える列では、閾値を越えた公開でちょうど一度だけ通知する。
        // (閾値 >= 1 かつ容量 >= 1 なので、空の Ring は閾値未満)
        if usage_at_least(u2, cap, th) && !usage_at_least(u0, cap, th) {
            assert!(
                first == NotifySignal::ThresholdCrossing
                    || second == NotifySignal::ThresholdCrossing
            );
        }
    }

    /// 再確認の待機時間は interval を超えず、経過が interval 以上なら 0 (再確認する)。
    #[kani::proof]
    fn recheck_timeout_is_bounded_by_interval() {
        let interval = Duration::from_nanos(kani::any::<u32>() as u64);
        let waited = Duration::from_nanos(kani::any::<u32>() as u64);
        let p = ReCheckPolicy { interval };
        let timeout = p.wait_timeout(waited);
        assert!(timeout <= interval);
        assert!(p.should_recheck(waited) == (timeout == Duration::ZERO && waited >= interval));
        if !p.should_recheck(waited) {
            assert!(waited + timeout == interval);
        }
    }
}
