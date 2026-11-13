//! 再入ガードと Host 停止確認。
//! - 再入ガードは「イベントを公開している間だけ」の短いガード。元の API 呼出前には外す。
//! - Agent 自身の呼出は記録しない。アプリ由来の入れ子は記録する。
//! - Host 生存確認は異常経路でのみ行い、停止確認後は記録を無効化して素通しにする。

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOrigin {
    /// アプリケーション由来（入れ子含む）。
    Application,
    /// Agent 自身が引き起こした呼出。
    AgentInternal,
}

thread_local! {
    static PUBLISH_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// 公開区間だけ張る再入ガード。Drop で必ず外れる。
pub struct PublishGuard;
impl PublishGuard {
    pub fn enter() -> Self {
        PUBLISH_DEPTH.with(|d| d.set(d.get() + 1));
        Self
    }
    pub fn is_active() -> bool {
        PUBLISH_DEPTH.with(|d| d.get() > 0)
    }
}
impl Drop for PublishGuard {
    fn drop(&mut self) {
        PUBLISH_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// 記録すべき呼出か。公開区間の中での Agent 由来呼出は記録しないが、
/// ガードを外した後（= 元の API 実行中）のアプリ由来入れ子は記録する。
pub fn should_record(origin: CallOrigin) -> bool {
    match origin {
        CallOrigin::AgentInternal => false,
        CallOrigin::Application => !PublishGuard::is_active(),
    }
}

/// Host 生存確認。異常経路でのみ `check_on_abnormal_path` を呼ぶ設計。
pub struct HostMonitor {
    alive_probe: Box<dyn Fn() -> bool + Send + Sync>,
    recording_disabled: AtomicBool,
    pub probe_count: std::sync::atomic::AtomicU64,
    abnormal_count: std::sync::atomic::AtomicU64,
}

/// Abnormal-path events between Host liveness probes. A probe is a system
/// call (about a microsecond); probing on every dropped event during a burst
/// made overflow itself the dominant cost. The first abnormal event always
/// probes, so a stopped Host is still detected at the start of an overflow.
pub const ABNORMAL_EVENTS_PER_PROBE: u64 = 256;
impl HostMonitor {
    pub fn new(probe: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            alive_probe: Box::new(probe),
            recording_disabled: AtomicBool::new(false),
            probe_count: std::sync::atomic::AtomicU64::new(0),
            abnormal_count: std::sync::atomic::AtomicU64::new(0),
        }
    }
    pub fn always_alive() -> Self {
        Self::new(|| true)
    }
    pub fn recording_enabled(&self) -> bool {
        !self.recording_disabled.load(Ordering::Relaxed)
    }
    /// 容量不足などの異常経路でのみ呼ぶ。通常経路では呼ばない。
    /// Host 停止を確認したら記録を無効化し、以後は素通しにする。再接続は初版対象外。
    pub fn check_on_abnormal_path(&self) -> bool {
        let n = self.abnormal_count.fetch_add(1, Ordering::Relaxed);
        if !n.is_multiple_of(ABNORMAL_EVENTS_PER_PROBE) {
            // Between probes the last verdict stands.
            return self.recording_enabled();
        }
        self.probe_count.fetch_add(1, Ordering::Relaxed);
        if (self.alive_probe)() {
            true
        } else {
            self.recording_disabled.store(true, Ordering::Relaxed);
            false
        }
    }
    /// テスト用に停止状態を直接設定する。
    pub fn force_dead(&self) {
        self.recording_disabled.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guard_only_during_publish() {
        assert!(should_record(CallOrigin::Application));
        {
            let _g = PublishGuard::enter();
            assert!(PublishGuard::is_active());
            // 公開区間内ではアプリ由来でも記録しない（公開処理自体が呼ぶ API を避ける）
            assert!(!should_record(CallOrigin::Application));
            assert!(!should_record(CallOrigin::AgentInternal));
        }
        // 元の API 呼出前には外れているので、入れ子は記録できる
        assert!(should_record(CallOrigin::Application));
        assert!(!should_record(CallOrigin::AgentInternal));
    }
    #[test]
    fn host_stop_disables_recording_permanently() {
        let m = HostMonitor::new(|| false);
        assert!(m.recording_enabled());
        assert!(!m.check_on_abnormal_path());
        assert!(!m.recording_enabled());
    }
    #[test]
    fn force_dead_disables_recording() {
        // cargo-mutants で検出: force_dead を消す mutant が transport 単体の
        // テスト範囲では生き残っていた (agent 側テストでのみ検証されていた)。
        let m = HostMonitor::always_alive();
        assert!(m.recording_enabled());
        m.force_dead();
        assert!(!m.recording_enabled());
    }
    #[test]
    fn abnormal_path_probes_are_rate_limited() {
        let m = HostMonitor::always_alive();
        for _ in 0..ABNORMAL_EVENTS_PER_PROBE * 3 {
            assert!(m.check_on_abnormal_path());
        }
        assert_eq!(m.probe_count.load(Ordering::Relaxed), 3);
        let dead = HostMonitor::new(|| false);
        assert!(!dead.check_on_abnormal_path());
        assert!(
            !dead.check_on_abnormal_path(),
            "stays stopped between probes"
        );
        assert_eq!(dead.probe_count.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn host_alive_keeps_recording() {
        let m = HostMonitor::always_alive();
        assert!(m.check_on_abnormal_path());
        assert!(m.recording_enabled());
        assert_eq!(m.probe_count.load(Ordering::Relaxed), 1);
    }
}
