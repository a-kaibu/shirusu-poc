//! 適合検査の各検査を 1 つずつ破った Trace（読み込み後の `ReadTrace` を
//! 直接書き換える）で、該当する検査だけが期待どおりに判定すること。
//! 境界値（Unknown は有効な水準、閉じた Enter への二重 Leave は違反）も見る。

use shirusu_conformance::{check_trace, CheckStatus};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{integrity_level, CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};

fn ev(kind: u16, sequence: u64, call_id: u64, schema_id: u32) -> TraceEvent {
    TraceEvent {
        kind,
        sequence,
        timestamp_qpc: sequence * 10,
        call_id,
        parent_call_id: 0,
        api_id: 1,
        schema_id,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: None,
        global_order: None,
    }
}

/// Enter/Leave 1 組と、BlobRef 引数を持つ Enter/Leave 1 組の Trace。
fn base() -> ReadTrace {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 3,
            created_by: "check-edges".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    w.register_schema(make_schema(1, "x!Y/enter", vec![("h".into(), Ty::U64, 0)]))
        .unwrap();
    w.register_schema(make_schema(2, "x!Y/leave", vec![("r".into(), Ty::U64, 0)]))
        .unwrap();
    w.register_schema(make_schema(
        3,
        "x!Z/enter",
        vec![("data".into(), Ty::BlobRef, 0)],
    ))
    .unwrap();
    let blob = w.add_payload(b"referenced").unwrap();
    let args = shirusu_trace::compact::encode_values(
        &[Ty::BlobRef],
        &[CapturedValue::captured(TypedValue::BlobRef(blob))],
    )
    .unwrap();
    let mut with_ref = ev(1, 3, 2, 3);
    with_ref.args = Some(args);
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![ev(1, 1, 1, 1), ev(2, 2, 1, 2), with_ref, ev(2, 4, 2, 2)],
    })
    .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    shirusu_trace::read_trace(&bytes).unwrap()
}

fn status(trace: &ReadTrace, id: &str) -> CheckStatus {
    check_trace(trace)
        .finding(id)
        .unwrap_or_else(|| panic!("no finding {id}"))
        .status
}

#[test]
fn base_trace_conforms() {
    let t = base();
    let report = check_trace(&t);
    assert!(report.conformant(), "{}", report.render_human("base"));
}

#[test]
fn human_report_lists_each_finding_and_the_result() {
    let t = base();
    let report = check_trace(&t);
    let text = report.render_human("sample.trace");
    assert!(
        text.starts_with("shirusu-conformance: sample.trace\n"),
        "{text}"
    );
    for f in &report.findings {
        let line = format!(
            "{} {} — {}\n",
            f.status.name().to_uppercase(),
            f.id,
            f.detail
        );
        assert!(text.contains(&line), "{text}");
    }
    assert!(text.contains("PASS clean-scan — "), "{text}");
    assert!(text.ends_with("result: conformant\n"), "{text}");

    let mut broken = base();
    broken.finalized_cleanly = false;
    let report = check_trace(&broken);
    let text = report.render_human("broken");
    assert!(text.contains("FAIL finalization — "), "{text}");
    assert_ne!(text, check_trace(&t).render_human("broken"));
    assert_eq!(CheckStatus::Pass.name(), "pass");
    assert_eq!(CheckStatus::Warn.name(), "warn");
    assert_eq!(CheckStatus::Fail.name(), "fail");
}

#[test]
fn finalization_without_a_clean_end_fails() {
    let mut t = base();
    assert_eq!(status(&t, "finalization"), CheckStatus::Pass);
    t.finalized_cleanly = false;
    assert_eq!(status(&t, "finalization"), CheckStatus::Fail);
}

#[test]
fn second_leave_or_abort_for_a_closed_call_fails() {
    for kind in [2u16, 7] {
        let mut t = base();
        let events = &mut t.batches[0].events;
        events.insert(2, ev(kind, 2, 1, 2));
        assert_eq!(
            status(&t, "enter-leave-pairing"),
            CheckStatus::Fail,
            "kind {kind}"
        );
    }
}

#[test]
fn abort_closes_its_enter() {
    let mut t = base();
    t.batches[0].events[1].kind = 7;
    t.batches[0].events[1].schema_id = 0;
    assert_eq!(status(&t, "enter-leave-pairing"), CheckStatus::Pass);
}

#[test]
fn missing_blob_referenced_by_a_field_fails() {
    let mut t = base();
    assert_eq!(status(&t, "blob-refs-resolvable"), CheckStatus::Pass);
    t.blobs.clear();
    let f = check_trace(&t);
    let f = f.finding("blob-refs-resolvable").unwrap();
    assert_eq!(f.status, CheckStatus::Fail);
    assert!(f.detail.contains("field data"), "{}", f.detail);
}

#[test]
fn integrity_levels_up_to_unknown_are_valid() {
    for level in [
        integrity_level::COMPLETE,
        integrity_level::DEGRADED,
        integrity_level::LOST,
        integrity_level::UNKNOWN,
    ] {
        let mut t = base();
        t.finalization.as_mut().unwrap().capture_coverage = level;
        assert_eq!(
            status(&t, "integrity-consistent"),
            CheckStatus::Pass,
            "level {level}"
        );
    }
    let mut t = base();
    t.finalization.as_mut().unwrap().semantic_completeness = integrity_level::UNKNOWN + 1;
    assert_eq!(status(&t, "integrity-consistent"), CheckStatus::Fail);
}

#[test]
fn complete_semantics_with_a_degraded_event_fails() {
    let mut t = base();
    t.batches[0].events[0].capture = EventCapture::Truncated;
    assert_eq!(status(&t, "integrity-consistent"), CheckStatus::Fail);
    t.finalization.as_mut().unwrap().semantic_completeness = integrity_level::DEGRADED;
    assert_eq!(status(&t, "integrity-consistent"), CheckStatus::Pass);
}
