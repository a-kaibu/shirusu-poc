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
