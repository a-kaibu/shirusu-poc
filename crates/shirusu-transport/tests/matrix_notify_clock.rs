//! notify / clock / context 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - PublishNotifyTracker: (容量, 閾値, 公開前使用量, 公開後使用量, Host 待機) の
//!   組合せで、閾値越えが「下から上へ越えた瞬間」だけ発火し、HostWaiting より
//!   優先すること。使用率の切り捨てで境界がずれるケースも含む。
//! - ReCheckPolicy: (周期, 経過) で再確認要否と残り時間がちょうど境界で切り替わる。
//! - Clock::elapsed_ns: tick 周波数 x tick 差の換算（切り捨て・飽和・逆転）。
//! - PublishGuard / HostMonitor: 入れ子深さと probe 結果による記録可否。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::context::{
    should_record, CallOrigin, HostMonitor, PublishGuard, ABNORMAL_EVENTS_PER_PROBE,
};
use shirusu_transport::notify::{NotifySignal, PublishNotifyTracker, ReCheckPolicy};
use shirusu_transport::Clock;
use std::sync::atomic::Ordering;
use std::time::Duration;

// ---------- PublishNotifyTracker: 新規 tracker での 1 公開 ----------
macro_rules! notify_case {
    ($name:ident, $cap:expr, $thr:expr, $before:expr, $after:expr, $waiting:expr, $expect:expr) => {
        #[test]
        fn $name() {
            let mut t = PublishNotifyTracker::new();
            assert_eq!(
                t.after_publish($before, $after, $cap, $thr, $waiting),
                $expect,
                "cap {} thr {} {}->{} waiting {}",
                $cap,
                $thr,
                $before,
                $after,
                $waiting
            );
        }
    };
}
notify_case!(nt_below_none, 100, 50, 0, 1, false, NotifySignal::None);
notify_case!(
    nt_below_waiting,
    100,
    50,
    0,
    1,
    true,
    NotifySignal::HostWaiting
);
notify_case!(
    nt_cross_exact,
    100,
    50,
    49,
    50,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_cross_beats_waiting,
    100,
    50,
    49,
    50,
    true,
    NotifySignal::ThresholdCrossing
);
notify_case!(nt_already_above, 100, 50, 50, 51, false, NotifySignal::None);
notify_case!(nt_approach_only, 100, 50, 48, 49, false, NotifySignal::None);
notify_case!(
    nt_jump_from_empty,
    100,
    50,
    0,
    50,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_jump_to_full,
    100,
    50,
    0,
    100,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_at_full_already,
    100,
    50,
    99,
    100,
    false,
    NotifySignal::None
);
notify_case!(
    nt_no_movement_at_threshold,
    100,
    50,
    50,
    50,
    false,
    NotifySignal::None
);
notify_case!(
    nt_cap4_cross,
    4,
    50,
    1,
    2,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(nt_cap4_below, 4, 50, 0, 1, false, NotifySignal::None);
notify_case!(nt_cap4_above_stays, 4, 50, 2, 3, false, NotifySignal::None);
notify_case!(
    nt_cap4_thr25_first,
    4,
    25,
    0,
    1,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(nt_cap4_thr25_second, 4, 25, 1, 2, false, NotifySignal::None);
notify_case!(
    nt_cap4_thr100_last,
    4,
    100,
    3,
    4,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_cap4_thr100_full_stays,
    4,
    100,
    4,
    4,
    false,
    NotifySignal::None
);
notify_case!(
    nt_truncation_delays_crossing,
    200,
    1,
    0,
    1,
    false,
    NotifySignal::None
);
notify_case!(
    nt_truncation_reaches_one_percent,
    200,
    1,
    1,
    2,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_cap3_thr34_step_over,
    3,
    34,
    1,
    2,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(nt_cap3_thr34_below, 3, 34, 0, 1, false, NotifySignal::None);
notify_case!(
    nt_thr0_first_crosses,
    100,
    0,
    0,
    1,
    false,
    NotifySignal::ThresholdCrossing
);
notify_case!(
    nt_thr0_second_does_not,
    100,
    0,
    1,
    2,
    false,
    NotifySignal::None
);
notify_case!(
    nt_cap0_degenerate_crosses,
    0,
    50,
    0,
    1,
    false,
    NotifySignal::ThresholdCrossing
);

// ---------- tracker の状態遷移 (observe_used との組合せ) ----------
#[test]
fn tracker_refires_only_after_dropping_below() {
    let mut t = PublishNotifyTracker::new();
    assert_eq!(
        t.after_publish(49, 50, 100, 50, false),
        NotifySignal::ThresholdCrossing
    );
    // 閾値ちょうどまで下がっても「上」のまま (50 >= 50)
    t.observe_used(50, 100, 50);
    assert_eq!(t.after_publish(50, 51, 100, 50, false), NotifySignal::None);
    // 閾値未満まで下がれば再び越えたときに発火する
    t.observe_used(49, 100, 50);
    assert_eq!(
        t.after_publish(49, 50, 100, 50, false),
        NotifySignal::ThresholdCrossing
    );
}
#[test]
fn tracker_host_waiting_still_fires_while_above() {
    let mut t = PublishNotifyTracker::new();
    assert_eq!(
        t.after_publish(49, 50, 100, 50, false),
        NotifySignal::ThresholdCrossing
    );
    // 越えた後は越え直しはしないが、Host 待機への通知は別途返る
    assert_eq!(
        t.after_publish(50, 51, 100, 50, true),
        NotifySignal::HostWaiting
    );
    assert_eq!(t.after_publish(50, 51, 100, 50, false), NotifySignal::None);
}

// ---------- ReCheckPolicy: 周期 x 経過 ----------
macro_rules! recheck_case {
    ($name:ident, $interval_ms:expr, $waited_ms:expr, $expect_recheck:expr, $expect_timeout_ms:expr) => {
        #[test]
        fn $name() {
            let p = ReCheckPolicy {
                interval: Duration::from_millis($interval_ms),
            };
            let waited = Duration::from_millis($waited_ms);
            assert_eq!(p.should_recheck(waited), $expect_recheck);
            assert_eq!(
                p.wait_timeout(waited),
                Duration::from_millis($expect_timeout_ms)
            );
        }
    };
}
recheck_case!(rc_2ms_at0, 2, 0, false, 2);
recheck_case!(rc_2ms_at1, 2, 1, false, 1);
recheck_case!(rc_2ms_at2, 2, 2, true, 0);
recheck_case!(rc_2ms_at3, 2, 3, true, 0);
recheck_case!(rc_0ms_at0, 0, 0, true, 0);
recheck_case!(rc_1ms_at0, 1, 0, false, 1);
recheck_case!(rc_1ms_at1, 1, 1, true, 0);
recheck_case!(rc_10ms_at9, 10, 9, false, 1);
recheck_case!(rc_10ms_at10, 10, 10, true, 0);
recheck_case!(rc_1s_at999ms, 1000, 999, false, 1);

// ---------- Clock::elapsed_ns: 周波数 x tick 差 ----------
macro_rules! elapsed_case {
    ($name:ident, $tps:expr, $start:expr, $end:expr, $expect:expr) => {
        #[test]
        fn $name() {
            let mut c = ManualClock::new();
            c.ticks_per_second = $tps;
            assert_eq!(
                c.elapsed_ns($start, $end),
                $expect,
                "tps {} {}..{}",
                $tps,
                $start,
                $end
            );
        }
    };
}
elapsed_case!(el_1ghz_1tick, 1_000_000_000, 0, 1, 1);
elapsed_case!(el_1ghz_1ms, 1_000_000_000, 0, 1_000_000, 1_000_000);
elapsed_case!(el_1mhz_1tick, 1_000_000, 0, 1, 1_000);
elapsed_case!(el_1mhz_half_sec, 1_000_000, 0, 500_000, 500_000_000);
elapsed_case!(el_qpc_10mhz_1sec, 10_000_000, 0, 10_000_000, 1_000_000_000);
elapsed_case!(el_qpc_10mhz_1tick, 10_000_000, 0, 1, 100);
elapsed_case!(el_tps3_third, 3, 0, 1, 333_333_333);
elapsed_case!(el_tps3_full, 3, 0, 3, 1_000_000_000);
elapsed_case!(el_tps7_floor, 7, 0, 2, 285_714_285);
elapsed_case!(el_reversed_is_zero, 1_000_000_000, 100, 50, 0);
elapsed_case!(el_zero_tps_treated_as_one, 0, 0, 5, 5_000_000_000);
elapsed_case!(el_saturating_product, 1, 0, u64::MAX, u64::MAX);
elapsed_case!(
    el_offset_window,
    1_000_000_000,
    1_000_000,
    2_500_000,
    1_500_000
);

// ---------- ManualClock の前進規則 ----------
#[test]
fn manual_sleep_zero_still_advances_one_tick() {
    let c = ManualClock::new();
    c.sleep(Duration::ZERO);
    assert_eq!(c.now_ticks(), 1, "sleep always advances at least 1 tick");
}
#[test]
fn manual_advance_adds_duration_as_ticks() {
    let c = ManualClock::new();
    c.advance(Duration::from_nanos(1500));
    assert_eq!(c.now_ticks(), 1500);
    c.advance(Duration::from_millis(1));
    assert_eq!(c.now_ticks(), 1500 + 1_000_000);
}
#[test]
fn manual_set_overrides() {
    let c = ManualClock::new();
    c.advance(Duration::from_millis(5));
    c.set(42);
    assert_eq!(c.now_ticks(), 42);
}
#[test]
fn manual_sleep_accumulates() {
    let c = ManualClock::new();
    for _ in 0..3 {
        c.sleep(Duration::from_millis(2));
    }
    assert_eq!(c.now_ticks(), 6_000_000);
}

// ---------- PublishGuard の入れ子 ----------
#[test]
fn guard_depth_zero_records_application() {
    assert!(should_record(CallOrigin::Application));
    assert!(!should_record(CallOrigin::AgentInternal));
    assert!(!PublishGuard::is_active());
}
#[test]
fn guard_depth_one_blocks_application() {
    let _g = PublishGuard::enter();
    assert!(PublishGuard::is_active());
    assert!(!should_record(CallOrigin::Application));
    assert!(!should_record(CallOrigin::AgentInternal));
}
#[test]
fn guard_nested_drop_keeps_outer_active() {
    let _outer = PublishGuard::enter();
    {
        let _inner = PublishGuard::enter();
        assert!(PublishGuard::is_active());
    }
    // 内側を抜けても外側が残っている間は記録しない
    assert!(PublishGuard::is_active());
    assert!(!should_record(CallOrigin::Application));
}
#[test]
fn guard_fully_released_records_again() {
    {
        let _a = PublishGuard::enter();
        let _b = PublishGuard::enter();
    }
    assert!(!PublishGuard::is_active());
    assert!(should_record(CallOrigin::Application));
}

// ---------- HostMonitor の probe と無効化 ----------
#[test]
fn monitor_counts_each_probe() {
    let m = HostMonitor::always_alive();
    // One probe per ABNORMAL_EVENTS_PER_PROBE abnormal events, the first included.
    for i in 1..=3 {
        for _ in 0..ABNORMAL_EVENTS_PER_PROBE {
            assert!(m.check_on_abnormal_path());
        }
        assert_eq!(m.probe_count.load(Ordering::Relaxed), i);
    }
    assert!(m.recording_enabled());
}
#[test]
fn monitor_dead_probe_disables_and_stays_disabled() {
    let m = HostMonitor::new(|| false);
    assert!(!m.check_on_abnormal_path());
    assert!(!m.recording_enabled());
    // 再確認しても有効には戻らない (再接続は初版対象外)
    for _ in 0..ABNORMAL_EVENTS_PER_PROBE {
        assert!(!m.check_on_abnormal_path());
    }
    assert!(!m.recording_enabled());
    assert_eq!(m.probe_count.load(Ordering::Relaxed), 2);
}
#[test]
fn monitor_force_dead_is_not_revived_by_alive_probe() {
    let m = HostMonitor::always_alive();
    m.force_dead();
    assert!(!m.recording_enabled());
    // probe 自体は true を返すが、無効化は恒久的
    assert!(m.check_on_abnormal_path());
    assert!(!m.recording_enabled());
}

/// `depth_cell` はこのスレッドの公開深さカウンタそのものを指す（Agent は
/// これを自分のスレッドローカルに控えて読む）。ガードの出入りが同じ
/// ポインタ越しに見え、別スレッドのカウンタとは別物。
#[test]
fn depth_cell_points_at_this_threads_publish_depth() {
    let cell = PublishGuard::depth_cell();
    assert!(!cell.is_null());
    assert_eq!(cell, PublishGuard::depth_cell(), "stable for the thread");
    // SAFETY: このスレッドのカウンタで、スレッドの寿命の間有効。
    let depth = unsafe { &*cell };
    let base = depth.get();
    {
        let _outer = PublishGuard::enter();
        assert_eq!(depth.get(), base + 1);
        let _inner = PublishGuard::enter();
        assert_eq!(depth.get(), base + 2);
    }
    assert_eq!(depth.get(), base);
    let other = std::thread::spawn(|| PublishGuard::depth_cell() as usize)
        .join()
        .unwrap();
    assert_ne!(other, cell as usize);
}
