//! Capture Session（recorder.rs）のカバレッジ gap テスト。
//!
//! 15:29 回の全ワークスペース計測（行 85.86%）で `recorder.rs` に残った
//! 未実行行（真の未実行は 53 行。76 行という数は `has_count=false` の
//! セグメント＝実行行でない閉じ括弧等を含んだ数え間違いだった）を埋める。
//! 対象：`SessionError` の Display／`From`、 `SessionState::name` の
//! Stopped／Finished 腕、`shutdown_integrity_impact` の全バリアントと
//! `level_severity` の Unknown 腕、各種 setter／getter、
//! `add_ring` の小さすぎる Mapping 拒否、`create_file` の Writer 構築
//! 失敗（`/dev/full`）、世代交代時の旧 Worker 確定（`retire_ring_worker`
//! の Loss 記録）。
//!
//! Linux では到達不能として残すもの（別途テスト不能な理由つき）：
//! - `retire_ring_worker` の worker なし早期 return（367 行目相当）：
//!   `poll_once` は `worker.is_some()` のときだけ呼ぶ。
//! - `poll_once` の retire 失敗 `?`（662 行目相当）：TraceWriter の
//!   失敗をセッション途中で注入する手段がない（`CaptureSession` は
//!   `W = File` に固定）。`/dev/full` は構築時にしか失敗させられない。
//! - `space_notify` の `Some` 腕（699〜703 行目相当）：`Some` を渡せる
//!   のは cfg(windows) の `add_shared_mapping` だけ。
//! - `stop` の `InvalidTransition` 腕（742〜746 行目相当）：`stop` は
//!   `self` を消費するため、入口の状態は常に Created／Recording。
//! - `SessionError::Win` の Display／`From`：cfg(windows) のみ。

use shirusu_agent::Agent;
use shirusu_hook::api::{api_by_id, API_CREATE_FILE_W};
use shirusu_hook::capture::{self, MapMemory};
use shirusu_host::recorder::{
    shutdown_integrity_impact, CaptureSession, CaptureSessionConfig, RingSpec, SessionError,
    SessionState, ShutdownOutcome,
};
use shirusu_host::IntegrityLevel;
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::TraceError;
use shirusu_transport::context::HostMonitor;
use shirusu_transport::layout;
use shirusu_transport::ring::{SharedRegion, WriterPolicy};
use shirusu_transport::slot::SlotPool;
use shirusu_transport::RingConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SESSION: u64 = 99;
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_trace(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "shirusu-recorder-gap-{tag}-{}-{n}.trace",
        std::process::id()
    ))
}

fn config() -> CaptureSessionConfig {
    CaptureSessionConfig {
        session_id: SESSION,
        ring_config: RingConfig::new(64, 4096),
        environment: CaptureEnvironment {
            session: SessionMetadata {
                session_id: SESSION,
                created_by: "shirusu-host test (recorder coverage gaps)".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        },
        qpc_frequency: 10_000_000,
        durability: shirusu_trace::writer::Durability::Buffered,
        order_global: false,
        record_runtime_apis: false,
        diagnostic_query_interface: false,
        record_mode: shirusu_host::trace_convert::RecordMode::Full,
    }
}

fn spec(generation: u64) -> RingSpec {
    RingSpec {
        process_id: 1,
        raw_pid: 1234,
        thread_id: 1,
        expected_generation: generation,
    }
}

fn agent_and_region(tid: u64) -> (Arc<Agent>, u64, *mut u8) {
    let cfg = RingConfig::new(64, 4096);
    let pool = Arc::new(SlotPool::new(2));
    let agent = Arc::new(
        Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive())).with_policy(WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        }),
    );
    let handle = agent.thread_begin(tid).expect("slot");
    let base = unsafe { agent.thread_region_base(tid) }.expect("region");
    (agent, handle.generation, base)
}

/// `SessionError` の Display：Linux で構築できる全バリアント。
#[test]
fn session_error_display_covers_all_linux_variants() {
    let invalid = SessionError::InvalidTransition {
        from: "Created",
        op: "start",
    };
    assert_eq!(
        format!("{invalid}"),
        "invalid session operation start in state Created"
    );
    assert!(std::error::Error::source(&invalid).is_none());

    assert_eq!(
        format!("{}", SessionError::Config("boom".to_string())),
        "session config error: boom"
    );
    let io = SessionError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "missing file",
    ));
    assert_eq!(format!("{io}"), "io error: missing file");
    let trace = SessionError::Trace(TraceError::NotATrace);
    assert!(format!("{trace}").starts_with("trace error: "));
    assert_eq!(
        format!("{}", SessionError::Injection("no dll".to_string())),
        "injection failed: no dll"
    );
}

/// `SessionError` の `From` 変換 2 件。
#[test]
fn session_error_from_conversions() {
    let from_io = SessionError::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    ));
    assert!(matches!(from_io, SessionError::Io(_)));
    assert!(format!("{from_io}").contains("denied"));

    let from_trace = SessionError::from(TraceError::InvalidInput("bad input".to_string()));
    assert!(matches!(from_trace, SessionError::Trace(_)));
    assert!(format!("{from_trace}").contains("bad input"));
}

/// `SessionState::name`：全 4 バリアント。
#[test]
fn session_state_name_covers_all_variants() {
    assert_eq!(SessionState::Created.name(), "Created");
    assert_eq!(SessionState::Recording.name(), "Recording");
    assert_eq!(SessionState::Stopped.name(), "Stopped");
    assert_eq!(SessionState::Finished.name(), "Finished");
}

/// `shutdown_integrity_impact`：全 7 バリアント。
#[test]
fn shutdown_integrity_impact_covers_all_outcomes() {
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::NotRequired),
        None
    );
    assert_eq!(shutdown_integrity_impact(&ShutdownOutcome::Confirmed), None);
    let (level, note) =
        shutdown_integrity_impact(&ShutdownOutcome::CallFailed("boom".to_string())).unwrap();
    assert_eq!(level, IntegrityLevel::Degraded);
    assert!(note.contains("remote call failed"));
    assert!(note.contains("boom"));
    let (level, note) = shutdown_integrity_impact(&ShutdownOutcome::AgentIncomplete).unwrap();
    assert_eq!(level, IntegrityLevel::Degraded);
    assert!(note.contains("did not drain"));
    let (level, note) = shutdown_integrity_impact(&ShutdownOutcome::ExportUnavailable).unwrap();
    assert_eq!(level, IntegrityLevel::Unknown);
    assert!(note.contains("unavailable"));
    let (level, note) = shutdown_integrity_impact(&ShutdownOutcome::AgentNotInitialized).unwrap();
    assert_eq!(level, IntegrityLevel::Unknown);
    assert!(note.contains("no active session"));
    let (level, note) = shutdown_integrity_impact(&ShutdownOutcome::UnexpectedStatus(7)).unwrap();
    assert_eq!(level, IntegrityLevel::Unknown);
    assert!(note.contains("unexpected status 7"));
}

/// `stop` で `shutdown_outcome` が Event Integrity へ写る。
/// ExportUnavailable（Unknown）は `worst` の `level_severity` で
/// Unknown 腕（331 行目相当）を踏む。
#[test]
fn stop_with_export_unavailable_shutdown_marks_event_integrity_unknown() {
    let path = temp_trace("shutdown-unknown");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_shutdown_outcome(ShutdownOutcome::ExportUnavailable);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Unknown);
    assert!(summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("shutdown entry point unavailable")));
}

#[test]
fn stop_with_call_failed_shutdown_marks_event_integrity_degraded() {
    let path = temp_trace("shutdown-degraded");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_shutdown_outcome(ShutdownOutcome::CallFailed("timeout".to_string()));
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Degraded);
    assert!(summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("remote call failed (timeout)")));
}

#[test]
fn stop_with_confirmed_shutdown_keeps_event_integrity_complete() {
    let path = temp_trace("shutdown-confirmed");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_shutdown_outcome(ShutdownOutcome::Confirmed);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Complete);
}

/// 各種 setter／getter が要約へ流れ込むこと。
/// `set_coverage_missing_calls(5)` は `coverage_missing_calls == 0`
/// の偽腕（793 行目相当＝slot 不足の注記を出さない側）を踏む。
#[test]
fn setters_and_getters_flow_into_summary() {
    let path = temp_trace("setters");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    assert_eq!(session.state(), SessionState::Created);
    assert_eq!(session.trace_path(), path.as_path());
    assert_eq!(session.ring_count(), 0);
    assert_eq!(session.state().name(), "Created");

    session.set_coverage_missing_calls(5);
    session.set_hook_coverage(3, 2);
    session.set_com_factory_count(2);
    session.set_winrt_activation_count(1);
    session.set_internal_hook_count(7);
    session.set_callback_hook_count(4);
    session.note_uninjectable_child(1234, "protected");
    // 同じ pid の 2 回目は最初の理由のまま 1 件にまとまる。
    session.note_uninjectable_child(1234, "other reason");

    session.start().unwrap();
    assert_eq!(session.state(), SessionState::Recording);
    let summary = session.stop().unwrap();

    assert_eq!(summary.trace_path, path);
    assert_eq!(summary.hook_coverage, Some((3, 2)));
    assert_eq!(summary.com_factory_count, Some(2));
    assert_eq!(summary.winrt_activation_count, Some(1));
    assert_eq!(summary.internal_hook_count, Some(7));
    assert_eq!(summary.callback_hook_count, Some(4));
    assert_eq!(
        summary.uninjectable_children,
        vec![(1234, "protected".to_string())]
    );
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Degraded);
    assert!(summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("hook coverage: 3/5")));
    assert!(summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("child process 1234 could not be injected (protected)")));
    // coverage_missing_calls != 0 のため slot 不足の注記は出ない。
    assert!(!summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("cross-process slot exhaustion")));
    // SharedRegion を使った add_local_ring が ring_count を増やす。
    let path2 = temp_trace("setters-ring");
    let mut session2 = CaptureSession::create_file(&path2, config()).unwrap();
    let region = SharedRegion::new(RingConfig::new(64, 4096), 1, 1);
    let idx = session2.add_local_ring(region, spec(1)).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(session2.ring_count(), 1);
}

/// `add_borrowed_ring` で小さすぎる Mapping は Config エラー。
#[test]
fn add_borrowed_ring_too_small_is_config_error() {
    let path = temp_trace("too-small");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    let mut buf = vec![0u8; 64];
    let base = buf.as_mut_ptr();
    let err = unsafe { session.add_borrowed_ring(base, 64, spec(1)) }.unwrap_err();
    assert!(matches!(err, SessionError::Config(_)));
    assert!(format!("{err}").contains("ring mapping too small"));
}

/// `/dev/full` へ Trace を作ると Writer 構築（Header 書き込み）で
/// 失敗し、`create_file` の `?` 伝播（451 行目相当）が走る。
#[cfg(target_os = "linux")]
#[test]
fn create_file_on_dev_full_fails_at_writer_construction() {
    let err = match CaptureSession::create_file("/dev/full", config()) {
        Ok(_) => panic!("create_file on /dev/full should fail at writer construction"),
        Err(e) => e,
    };
    assert!(matches!(err, SessionError::Trace(_)));
}

/// 世代交代：Enter のみ（Leave なし）の呼び出しを残したまま Control
/// を新しい世代で再初期化すると、次の `poll_once` で旧 Worker が確定
/// され、未終了呼び出しが Loss として記録される（374〜375 行目相当）。
#[test]
fn generation_change_retires_worker_and_records_loss() {
    let path = temp_trace("generation-change");
    let (agent, generation, base) = agent_and_region(11);
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    let len = RingConfig::new(64, 4096).required_len();
    unsafe {
        session
            .add_borrowed_ring(base, len, spec(generation))
            .unwrap();
    }
    session.start().unwrap();

    // Leave なしの Enter を 1 件だけ記録する。
    let cf = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut mem = MapMemory::new();
    let units: Vec<u16> = "C:\\game\\save.dat".encode_utf16().chain([0]).collect();
    mem.write_u16s(0x1000, &units);
    let enter = capture::create_file_w_enter(&mem, 0x1000, 0xC000_0000, 0, 0, 2, 0x80, 0);
    let payload = capture::encode_enter(cf, &enter).unwrap();
    assert!(matches!(
        agent.record_enter(11, cf.api_id, cf.enter_schema_id(), 1, 0, &payload),
        shirusu_agent::RecordResult::Written(_)
    ));

    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 1);
    assert_eq!(stats.active_rings, 1);

    // 同じ Mapping を新しい世代で再初期化する（別スレッドが Slot を
    // 回収して使い直したのと同じ状態）。
    layout::init_control(base, RingConfig::new(64, 4096), generation + 1, 11);

    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 0);
    assert_eq!(stats.active_rings, 1);

    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 1);
    assert_eq!(summary.total_loss_records, 1);
    assert_eq!(summary.rings_active, 1);
    assert_eq!(summary.rings_stopped, 0);
}

#[test]
fn com_methods_missing_for_safety_degrade_coverage_with_reason() {
    let path = temp_trace("com-safe-skip");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_com_factory_count(2);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Degraded);
    assert!(summary
        .integrity
        .notes
        .iter()
        .any(|n| n.contains("shared-object-safety-unproven")));
    let trace = shirusu_trace::reader::read_trace(&std::fs::read(&path).unwrap()).unwrap();
    assert!(trace
        .finalization
        .unwrap()
        .notes
        .iter()
        .any(|n| n.contains("shared-object-safety-unproven")));
}

#[test]
fn create_file_in_missing_directory_reports_io_error() {
    let missing = temp_trace("missing-parent").join("capture.trace");
    assert!(!missing.parent().unwrap().exists());
    let error = match CaptureSession::create_file(&missing, config()) {
        Ok(_) => panic!("missing parent must fail before writer construction"),
        Err(error) => error,
    };
    assert!(matches!(error, SessionError::Io(_)), "{error}");
}
