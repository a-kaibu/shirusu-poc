//! Capture Session（recorder）の中核テスト。
//!
//! 実 Agent（同一プロセス）→ セッション回収 → Trace 読み戻しまでを通し、
//! 状態機械・異常系（共有メモリ破損、終了不明）・未初期化 Ring の扱いを固める。
//! Windows のプロセス間経路は recorder_launch と CI が担う。

use shirusu_agent::{Agent, RecordResult};
use shirusu_hook::api::{api_by_id, API_CLOSE_HANDLE, API_CREATE_FILE_W, API_WRITE_FILE};
use shirusu_hook::capture::{self, MapMemory};
use shirusu_host::recorder::{
    shutdown_integrity_impact, CaptureSession, CaptureSessionConfig, RingSpec, SessionError,
    SessionState, ShutdownOutcome,
};
use shirusu_host::IntegrityLevel;
use shirusu_trace::compact::decode_values;
use shirusu_trace::proto::{loss_kind, CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::TypedValue;
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
        "shirusu-recorder-{tag}-{}-{n}.trace",
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
                created_by: "shirusu-host test (recorder)".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        },
        qpc_frequency: 10_000_000,
        durability: shirusu_trace::writer::Durability::Buffered,
        order_global: false,
        // L07: Runtime 独自の API は既定で記録しない。
        record_runtime_apis: false,
        diagnostic_query_interface: false,
        // L09: 既定は `full`（間引きなし）。
        record_mode: shirusu_host::trace_convert::RecordMode::Full,
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

fn spec(generation: u64) -> RingSpec {
    RingSpec {
        process_id: 1,
        raw_pid: 1234,
        thread_id: 1,
        expected_generation: generation,
    }
}

/// フック Detour が作るのと同じ形の Payload で 3 API 分を記録する。
fn record_file_io(agent: &Agent, tid: u64) {
    let cf = api_by_id(API_CREATE_FILE_W).unwrap();
    let wf = api_by_id(API_WRITE_FILE).unwrap();
    let ch = api_by_id(API_CLOSE_HANDLE).unwrap();
    let mut mem = MapMemory::new();
    let units: Vec<u16> = "C:\\game\\save.dat".encode_utf16().chain([0]).collect();
    mem.write_u16s(0x1000, &units);
    mem.write(0x2000, b"hello-save");
    let enter = capture::create_file_w_enter(&mem, 0x1000, 0xC000_0000, 0, 0, 2, 0x80, 0);
    let payload = capture::encode_enter(cf, &enter).unwrap();
    assert!(matches!(
        agent.record_enter(tid, cf.api_id, cf.enter_schema_id(), 1, 0, &payload),
        RecordResult::Written(_)
    ));
    let leave = capture::create_file_w_leave(0x2A4, 0, 3);
    let payload = capture::encode_leave(cf, &leave).unwrap();
    agent.record_leave(tid, cf.api_id, cf.leave_schema_id(), 1, 0, &payload);
    let enter = capture::write_file_enter(&mem, 0x2A4, 0x2000, 10, 0);
    let payload = capture::encode_enter(wf, &enter).unwrap();
    agent.record_enter(tid, wf.api_id, wf.enter_schema_id(), 2, 0, &payload);
    let leave = capture::write_file_leave(&mem, 1, 0, false, 0);
    let payload = capture::encode_leave(wf, &leave).unwrap();
    agent.record_leave(tid, wf.api_id, wf.leave_schema_id(), 2, 0, &payload);
    let enter = capture::close_handle_enter(0x2A4);
    let payload = capture::encode_enter(ch, &enter).unwrap();
    agent.record_enter(tid, ch.api_id, ch.enter_schema_id(), 3, 0, &payload);
    let leave = capture::close_handle_leave(1, 0);
    let payload = capture::encode_leave(ch, &leave).unwrap();
    agent.record_leave(tid, ch.api_id, ch.leave_schema_id(), 3, 0, &payload);
}

#[test]
fn full_capture_in_process_produces_decodable_trace() {
    let path = temp_trace("full");
    let (agent, generation, base) = agent_and_region(11);
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base,
                RingConfig::new(64, 4096).required_len(),
                spec(generation),
            )
            .unwrap();
    }
    session.start().unwrap();
    record_file_io(&agent, 11);
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 6);
    assert_eq!(stats.active_rings, 1);
    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 6);
    assert_eq!(summary.rings_active, 1);
    assert_eq!(summary.rings_stopped, 0);
    assert_eq!(summary.args_attached, 6);
    assert_eq!(summary.host_pipeline.events_received, summary.total_events);
    // One Events command plus the final validation barrier.
    assert_eq!(summary.host_pipeline.commands_processed, 2);
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Complete);

    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.finalization.is_some());
    let capture_config = &trace.environment.as_ref().unwrap().capture_config;
    assert!(capture_config.contains("host_events_received=6"));
    assert!(capture_config.contains(&format!(
        "host_conversion_wall_ns={}",
        summary.host_pipeline.conversion_wall_ns
    )));
    let events: Vec<_> = trace.batches.iter().flat_map(|b| &b.events).collect();
    assert_eq!(events.len(), 6);
    // CreateFileW のパスが L2 で復元できる
    let types = trace.registry.types(events[0].schema_id).unwrap();
    let values = decode_values(&types, events[0].args.as_ref().unwrap()).unwrap();
    match &values[0].value {
        TypedValue::Str16(u) => assert_eq!(String::from_utf16_lossy(u), "C:\\game\\save.dat"),
        other => panic!("path: {other:?}"),
    }
    // WriteFile の入力バッファ内容が復元できる
    let types = trace.registry.types(events[2].schema_id).unwrap();
    let values = decode_values(&types, events[2].args.as_ref().unwrap()).unwrap();
    assert_eq!(values[1].value, TypedValue::Bytes(b"hello-save".to_vec()));
    // CloseHandle の対象が CreateFileW の戻りハンドルと一致する（相関）
    let types = trace.registry.types(events[4].schema_id).unwrap();
    let values = decode_values(&types, events[4].args.as_ref().unwrap()).unwrap();
    assert_eq!(values[0].value, TypedValue::U64(0x2A4));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn uninitialized_ring_is_pending_not_an_error() {
    let path = temp_trace("pending");
    let cfg = RingConfig::new(64, 4096);
    // Agent が初期化していない（Magic が無い）領域
    let region = SharedRegion::new(cfg, 0, 0);
    // SharedRegion::new は Control を初期化してしまうので、Magic を消して
    // 「まだ Agent が claim していない」状態を作る。
    unsafe {
        let p = region.base().add(layout::OFF_MAGIC) as *mut u64;
        p.write_unaligned(0);
    }
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    unsafe {
        session
            .add_borrowed_ring(region.base(), cfg.required_len(), spec(0))
            .unwrap();
    }
    session.start().unwrap();
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 0);
    assert_eq!(stats.pending_rings, 1);
    let summary = session.stop().unwrap();
    assert_eq!(summary.rings_never_initialized, 1);
    assert_eq!(summary.total_events, 0);
    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.finalization.is_some(), "empty trace still finalizes");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn corrupted_ring_stops_and_marks_integrity_lost() {
    let path = temp_trace("corrupt");
    let (agent, generation, base) = agent_and_region(11);
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base,
                RingConfig::new(64, 4096).required_len(),
                spec(generation),
            )
            .unwrap();
    }
    session.start().unwrap();
    record_file_io(&agent, 11);
    assert_eq!(session.poll_once().unwrap().events, 6);
    // 共有メモリの破損を注入： write cursor をあり得ない値にする
    unsafe {
        let p = base.add(layout::OFF_WRITE_CURSOR) as *mut u64;
        p.write_unaligned(u64::MAX - 3);
    }
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.stopped_rings, 1);
    let summary = session.stop().unwrap();
    assert_eq!(summary.rings_stopped, 1);
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Lost);
    // 破損前に回収した 6 件は Trace に残る
    assert_eq!(summary.total_events, 6);
    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let n: usize = trace.batches.iter().map(|b| b.events.len()).sum();
    assert_eq!(n, 6);
    assert!(trace
        .loss_records
        .iter()
        .any(|l| l.kind == loss_kind::INTEGRITY_LOST));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn unterminated_call_becomes_loss_record() {
    let path = temp_trace("unterminated");
    let (agent, generation, base) = agent_and_region(11);
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    unsafe {
        session
            .add_borrowed_ring(
                base,
                RingConfig::new(64, 4096).required_len(),
                spec(generation),
            )
            .unwrap();
    }
    session.start().unwrap();
    // Enter だけ記録して対象が死んだ状況（Leave が来ない）
    let cf = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut mem = MapMemory::new();
    let units: Vec<u16> = "X:\\a.bin".encode_utf16().chain([0]).collect();
    mem.write_u16s(0x1000, &units);
    let enter = capture::create_file_w_enter(&mem, 0x1000, 0, 0, 0, 1, 0, 0);
    let payload = capture::encode_enter(cf, &enter).unwrap();
    agent.record_enter(11, cf.api_id, cf.enter_schema_id(), 77, 0, &payload);
    session.poll_once().unwrap();
    let summary = session.stop().unwrap();
    assert!(summary.total_loss_records >= 1);
    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace
        .loss_records
        .iter()
        .any(|l| { l.kind == loss_kind::UNKNOWN_TERMINATION && l.call_id == 77 }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn state_machine_rejects_illegal_operations() {
    let path = temp_trace("sm");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    // 開始前の poll は不可
    assert!(matches!(
        session.poll_once(),
        Err(SessionError::InvalidTransition { .. })
    ));
    session.start().unwrap();
    // 二重 start は不可
    assert!(matches!(
        session.start(),
        Err(SessionError::InvalidTransition { .. })
    ));
    // 開始後の Ring 追加は不可
    let region = SharedRegion::new(RingConfig::new(64, 4096), 1, 0);
    assert!(matches!(
        session.add_local_ring(region, spec(1)),
        Err(SessionError::InvalidTransition { .. })
    ));
    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 0);
    let _ = std::fs::remove_file(&path);

    // 未開始のまま stop しても空の Trace が確定する
    let path2 = temp_trace("sm2");
    let session2 = CaptureSession::create_file(&path2, config()).unwrap();
    assert_eq!(session2.state(), SessionState::Created);
    let summary = session2.stop().unwrap();
    assert_eq!(summary.total_events, 0);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn session_id_mismatch_is_config_error() {
    let path = temp_trace("cfg");
    let mut cfg = config();
    cfg.session_id = SESSION + 1;
    assert!(matches!(
        CaptureSession::create_file(&path, cfg),
        Err(SessionError::Config(_))
    ));
    let _ = std::fs::remove_file(&path);
}

// ---- 状態機械の PBT： ランダムな操作列で不変条件が壊れないこと ----

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Start,
    Poll,
    AddRing,
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn random_ops_respect_state_machine(
        ops in prop::collection::vec(
            prop_oneof![Just(Op::Start), Just(Op::Poll), Just(Op::AddRing)],
            0..24,
        )
    ) {
        let path = temp_trace("pbt");
        let cfg = RingConfig::new(64, 4096); // セッション設定と一致させる
        let mut session = CaptureSession::create_file(&path, config()).unwrap();
        let mut started = false;
        for op in ops {
            match op {
                Op::Start => {
                    let r = session.start();
                    prop_assert_eq!(r.is_ok(), !started);
                    started = true;
                }
                Op::Poll => {
                    let r = session.poll_once();
                    prop_assert_eq!(r.is_ok(), started);
                }
                Op::AddRing => {
                    let region = SharedRegion::new(cfg, 1, 0);
                    let r = session.add_local_ring(region, spec(1));
                    prop_assert_eq!(r.is_ok(), !started);
                }
            }
        }
        let summary = session.stop().unwrap();
        prop_assert_eq!(summary.total_events, 0);
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn zero_hook_target_is_coverage_loss_not_session_failure() {
    // レビュー #4 の #8: 対象 API を 1 つもインポートしていない
    // アプリは「0 件設置・全件欠落」であり、セッションの失敗では
    // ない。Coverage の劣化として閉じられる。
    let path = temp_trace("zero-hook");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_hook_coverage(0, 4);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.hook_coverage, Some((0, 4)));
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Degraded);
    assert!(
        summary
            .integrity
            .notes
            .iter()
            .any(|n| n.contains("ran unrecorded")),
        "notes: {:?}",
        summary.integrity.notes
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn shutdown_outcome_maps_to_event_integrity() {
    // レビュー第5回 #6: 完全停止を確認できなかったセッションは
    // 正常終了として確定しない。純粋関数の全分岐を固定する。
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::NotRequired),
        None
    );
    assert_eq!(shutdown_integrity_impact(&ShutdownOutcome::Confirmed), None);
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::CallFailed("boom".into())).map(|(l, _)| l),
        Some(IntegrityLevel::Degraded)
    );
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::AgentIncomplete).map(|(l, _)| l),
        Some(IntegrityLevel::Degraded)
    );
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::ExportUnavailable).map(|(l, _)| l),
        Some(IntegrityLevel::Unknown)
    );
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::AgentNotInitialized).map(|(l, _)| l),
        Some(IntegrityLevel::Unknown)
    );
    assert_eq!(
        shutdown_integrity_impact(&ShutdownOutcome::UnexpectedStatus(77)).map(|(l, _)| l),
        Some(IntegrityLevel::Unknown)
    );
}

#[test]
fn unconfirmed_shutdown_degrades_finalized_integrity() {
    // セッション経由: 終了結果が Finalization の Event Integrity と
    // 注記へ写ること。
    let path = temp_trace("shutdown-degraded");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_shutdown_outcome(ShutdownOutcome::AgentIncomplete);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Degraded);
    assert!(
        summary
            .integrity
            .notes
            .iter()
            .any(|n| n.contains("agent shutdown")),
        "notes: {:?}",
        summary.integrity.notes
    );
    let _ = std::fs::remove_file(&path);

    // 完全停止が確認できれば劣化しない。
    let path = temp_trace("shutdown-confirmed");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_shutdown_outcome(ShutdownOutcome::Confirmed);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Complete);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn partial_and_full_hook_coverage_levels() {
    // 一部欠落も劣化。全件設置なら Coverage は落ちない。
    let path = temp_trace("partial-hook");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_hook_coverage(3, 1);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.hook_coverage, Some((3, 1)));
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Degraded);
    let _ = std::fs::remove_file(&path);

    let path = temp_trace("full-hook");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.set_hook_coverage(4, 0);
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.hook_coverage, Some((4, 0)));
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Complete);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn uninjectable_child_degrades_capture_coverage() {
    // L05: 注入できなかった子プロセスは Capture Coverage の劣化として
    // Finalization の注記に残る。同じ pid の二重記録は 1 件にまとめる。
    let path = temp_trace("uninjectable-child");
    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    session.note_uninjectable_child(4321, "access denied (protected process)");
    session.note_uninjectable_child(4321, "access denied (protected process)");
    session.note_uninjectable_child(9876, "exited before injection");
    session.start().unwrap();
    let summary = session.stop().unwrap();
    assert_eq!(summary.uninjectable_children.len(), 2);
    assert_eq!(summary.uninjectable_children[0].0, 4321);
    assert_eq!(summary.integrity.capture_coverage, IntegrityLevel::Degraded);
    assert!(
        summary.integrity.notes.iter().any(|n| n.contains("4321")),
        "notes: {:?}",
        summary.integrity.notes
    );
    assert!(
        summary.integrity.notes.iter().any(|n| n.contains("9876")),
        "notes: {:?}",
        summary.integrity.notes
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_follows_ring_reincarnation_after_slot_reuse() {
    // レビュー #6 P1-4: Agent がスレッド終了で Slot を回収し、別の
    // スレッドが同じ Mapping を新しい Generation で再利用しても、
    // セッションは Worker を張り替えて記録を続ける。旧来は世代
    // 不一致で Ring が止まっていた (Host 側は固定の期待世代)。
    let path = temp_trace("reincarnation");
    let cfg = RingConfig::new(64, 4096);
    // Host が所有する領域を Agent の追加 Slot へ配送する (実経路の
    // Bootstrap Mapping と同じ形)。base は incarnation をまたいで不変。
    let region = SharedRegion::new(cfg, 0, 0);
    let base = region.base();
    let pool = Arc::new(SlotPool::new(0));
    let agent = Arc::new(
        Agent::new(pool, cfg, Arc::new(HostMonitor::always_alive())).with_policy(WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        }),
    );
    let delivery = shirusu_transport::expansion::ExpansionDelivery {
        len: cfg.required_len(),
        base: Some(base),
        handle_value: None,
        generation: shirusu_transport::EXPANDED_SLOT_GENERATION,
    };
    assert_eq!(agent.register_slot_mapping(delivery), Some(0));

    let mut session = CaptureSession::create_file(&path, config()).unwrap();
    unsafe {
        session
            .add_borrowed_ring(base, cfg.required_len(), spec(0))
            .unwrap();
    }
    session.start().unwrap();
    // incarnation 1: TID 11 が世代 0 で記録する
    let h1 = agent.thread_begin(11).expect("slot");
    assert_eq!(h1.generation, 0);
    record_file_io(&agent, 11);
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 6);
    // スレッド終了 → セッションが最終回収 → Agent が Slot を回収する
    assert!(agent.thread_exit(11));
    let _ = session.poll_once().unwrap();
    assert_eq!(agent.poll_reclaims(), 1);
    // incarnation 2: 別の TID が同じ Slot を世代 1 で使う
    let h2 = agent.thread_begin(222).expect("recycled slot");
    assert_eq!(h2.index, h1.index);
    assert_eq!(h2.generation, 1);
    record_file_io(&agent, 222);
    let stats = session.poll_once().unwrap();
    assert_eq!(stats.events, 6, "new incarnation must be drained");
    assert_eq!(stats.stopped_rings, 0);
    let summary = session.stop().unwrap();
    assert_eq!(summary.total_events, 12);
    assert_eq!(summary.rings_stopped, 0);
    assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Complete);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn late_module_scan_preserves_initial_metadata_when_unavailable() {
    let path = temp_trace("late-modules");
    let mut cfg = config();
    cfg.environment.target_description = "short-lived.exe".into();
    let evidence = shirusu_trace::proto::HookEvidence {
        api_id: 1,
        module: "kernel32.dll".into(),
        function: "CreateFileW".into(),
        method: "inline".into(),
        outcome: "installed".into(),
        ..Default::default()
    };
    cfg.environment.hook_evidence.push(evidence.clone());
    let mut session = CaptureSession::create_file(&path, cfg).unwrap();
    assert!(session.update_modules(Vec::new()).is_err());
    session.start().unwrap();
    session.update_modules(Vec::new()).unwrap();
    session.stop().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let environment = trace.environment.unwrap();
    assert_eq!(environment.target_description, "short-lived.exe");
    assert_eq!(environment.hook_evidence, vec![evidence]);
    assert!(environment
        .capture_config
        .contains("module_scan=unavailable"));
    assert!(trace.finalization.is_some());
    assert!(trace.issues.is_empty(), "{:?}", trace.issues);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn field_capture_quality_reaches_finalization_without_event_loss() {
    use shirusu_trace::schema::ValueCapture;
    for state in [
        ValueCapture::Captured,
        ValueCapture::Stale,
        ValueCapture::Unreadable,
        ValueCapture::Unsupported,
        ValueCapture::Truncated,
        ValueCapture::LimitExceeded,
    ] {
        let path = temp_trace("field-quality");
        let (agent, generation, base) = agent_and_region(11);
        let mut session = CaptureSession::create_file(&path, config()).unwrap();
        unsafe {
            session
                .add_borrowed_ring(
                    base,
                    RingConfig::new(64, 4096).required_len(),
                    spec(generation),
                )
                .unwrap();
        }
        session.start().unwrap();
        let api = api_by_id(API_CLOSE_HANDLE).unwrap();
        let enter = capture::encode_enter(api, &capture::close_handle_enter(42)).unwrap();
        agent.record_enter(11, api.api_id, api.enter_schema_id(), 1, 0, &enter);
        let mut values = capture::close_handle_leave(1, 0);
        values[1].capture = state;
        let leave = capture::encode_leave(api, &values).unwrap();
        agent.record_leave(11, api.api_id, api.leave_schema_id(), 1, 0, &leave);
        session.poll_once().unwrap();
        let summary = session.stop().unwrap();
        let expected = if matches!(state, ValueCapture::Captured | ValueCapture::Stale) {
            IntegrityLevel::Complete
        } else {
            IntegrityLevel::Degraded
        };
        assert_eq!(
            summary.integrity.semantic_completeness, expected,
            "{state:?}"
        );
        assert_eq!(summary.integrity.event_integrity, IntegrityLevel::Complete);
        let trace = shirusu_trace::read_trace(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            trace.finalization.unwrap().semantic_completeness,
            shirusu_host::trace_convert::integrity_level_code(expected)
        );
        std::fs::remove_file(path).unwrap();
    }
}
