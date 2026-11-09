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

#[derive(Debug, Default, Clone)]
pub struct PublishNotifyTracker {
    above_threshold: bool,
}
impl PublishNotifyTracker {
    pub fn new() -> Self {
        Self::default()
    }
    /// 公開直後に呼ぶ。使用量は件数ベース。
    pub fn after_publish(
        &mut self,
        used_before: u64,
        used_after: u64,
        capacity: u64,
        threshold_percent: u64,
        host_waiting: bool,
    ) -> NotifySignal {
        let pct = |u: u64| crate::layout::usage_percent(u, capacity);
        let was_above = pct(used_before) >= threshold_percent && used_before > 0;
        let is_above = pct(used_after) >= threshold_percent;
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
        self.above_threshold = crate::layout::usage_percent(used, capacity) >= threshold_percent;
    }
}

/// Host 側の再確認ポリシー。通知を取りこぼしても無期限に待たない。
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
    pub fn wait_timeout(&self, waited: Duration) -> Duration {
        self.interval.saturating_sub(waited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
