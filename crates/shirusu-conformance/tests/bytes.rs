//! バイト列レベルの統合テスト：TraceWriter で実際に書いた Trace が
//! 適合し、途中で切断した Trace が finalization 検査で落ちること。

use shirusu_conformance::{check_trace, CheckStatus};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, EventCapture, Ty};
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};

fn env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 3,
            created_by: "bytes-test writer".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    }
}

fn build_trace(unregistered_schema_event: bool) -> Vec<u8> {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    w.register_schema(make_schema(1, "x!Y/enter", vec![("h".into(), Ty::U64, 0)]))
        .unwrap();
    w.register_schema(make_schema(
        2,
        "x!Y/leave",
        vec![
            ("return".into(), Ty::U64, 0),
            ("last_error".into(), Ty::U32, 0),
        ],
    ))
    .unwrap();
    let ev = |kind, sequence, call_id, schema_id| TraceEvent {
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
    };
    let mut events = vec![ev(1, 1, 1, 1), ev(2, 2, 1, 2)];
    if unregistered_schema_event {
        events.push(ev(1, 3, 2, 77));
        events.push(ev(2, 4, 2, 77));
    }
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events,
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn writer_built_trace_conforms() {
    let bytes = build_trace(false);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let report = check_trace(&trace);
    assert!(report.conformant(), "{}", report.render_human("t"));
}

#[test]
fn writer_built_trace_with_unregistered_schema_fails_schema_check() {
    let bytes = build_trace(true);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let report = check_trace(&trace);
    assert!(!report.conformant());
    let f = report.finding("schemas-registered").unwrap();
    assert_eq!(f.status, CheckStatus::Fail);
    assert!(f.detail.contains("77"), "detail: {}", f.detail);
}

#[test]
fn truncated_trace_fails_finalization() {
    let bytes = build_trace(false);
    // Index + Finalization は末尾にある。末尾を切り落とすと
    // Finalization が消え、Reader は「途中で終わった Trace」として読む。
    let cut = &bytes[..bytes.len() - 40];
    let trace = shirusu_trace::read_trace(cut).unwrap();
    assert!(trace.finalization.is_none());
    let report = check_trace(&trace);
    assert_eq!(
        report.finding("finalization").unwrap().status,
        CheckStatus::Fail
    );
}
