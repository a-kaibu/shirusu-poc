//! Windows の supervisor だけが実行していた同一プロセス内シナリオ群を、
//! Linux の `cargo test` でも 1 件ずつ実行する。シナリオ本体は
//! プラットフォーム非依存の共有メモリ（他 OS ではプロセス内確保）の上で動く。

use shirusu_e2e::*;

fn assert_passed(r: ScenarioReport) {
    assert!(r.passed, "{}: {}", r.name, r.detail);
}

#[test]
fn basic() {
    assert_passed(scenario_basic(5000));
}
#[test]
fn basic_zero_events() {
    assert_passed(scenario_basic(0));
}
#[test]
fn host_pause() {
    assert_passed(scenario_host_pause(&SyncPoints::test_enabled()));
}
#[test]
fn notification_loss() {
    assert_passed(scenario_notification_loss(&SyncPoints::test_enabled()));
}
#[test]
fn space_available_notify() {
    assert_passed(scenario_space_available_notify());
}
#[test]
fn agent_space_available_handoff() {
    assert_passed(scenario_agent_space_available_handoff());
}
#[test]
fn host_killed() {
    assert_passed(scenario_host_killed());
}
#[test]
fn writer_stops_midway() {
    assert_passed(scenario_writer_stops_midway());
}
#[test]
fn slot_reuse() {
    assert_passed(scenario_slot_reuse());
}
#[test]
fn corruption() {
    assert_passed(scenario_corruption());
}
#[test]
fn host_restart_resume() {
    assert_passed(scenario_host_restart_resume());
}
#[test]
fn producer_killed_mid_publish() {
    assert_passed(scenario_producer_killed_mid_publish());
}
#[test]
fn producer_storm_32_threads() {
    assert_passed(scenario_producer_storm_32_threads());
}
#[test]
fn soak_loss_accounting() {
    assert_passed(scenario_soak_loss_accounting());
}
#[test]
fn corruption_injection_stops_ring() {
    assert_passed(scenario_corruption_injection_stops_ring());
}
#[test]
fn detach_publish_storm() {
    assert_passed(scenario_detach_publish_storm());
}
#[test]
fn run_all_reports_every_scenario_once() {
    let reports = run_all_in_process();
    assert_eq!(reports.len(), 15);
    let mut names: Vec<_> = reports.iter().map(|r| r.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 15, "scenario names must be unique");
    for r in reports {
        assert_passed(r);
    }
}

#[test]
fn production_sync_points_never_fire() {
    let s = SyncPoints::production();
    s.pause_host.store(true, std::sync::atomic::Ordering::Relaxed);
    s.drop_notifications.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(!s.host_paused());
    assert!(!s.notifications_dropped());
    let t = SyncPoints::test_enabled();
    assert!(!t.host_paused());
    t.pause_host.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(t.host_paused());
}
