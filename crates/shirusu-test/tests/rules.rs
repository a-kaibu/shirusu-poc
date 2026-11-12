//! ルール評価の検証。合成 Trace に対して各ルールの pass/fail と、
//! CLI の終了コードを確認する。

use shirusu_test::{evaluate, TestSpec};
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

struct B {
    events: Vec<TraceEvent>,
    seq: u64,
}

impl B {
    fn new() -> Self {
        B {
            events: Vec::new(),
            seq: 0,
        }
    }
    fn push(
        &mut self,
        kind: u16,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
        payload: PayloadRef,
    ) {
        self.seq += 1;
        self.events.push(TraceEvent {
            kind,
            sequence: self.seq,
            timestamp_qpc: 100 + self.seq * 10,
            call_id: if kind == 2 { self.seq - 1 } else { self.seq },
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
    }
    fn create(&mut self, handle: u64, path: &str) {
        self.push(
            1,
            1,
            1,
            &[Ty::Str16, Ty::U32],
            vec![
                cv(TypedValue::Str16(path.encode_utf16().collect())),
                cv(TypedValue::U32(0x8000_0000)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }
    fn read(&mut self, handle: u64, want: u32, payload: PayloadRef) {
        self.push(
            1,
            2,
            3,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(want))],
            payload,
        );
        self.push(
            2,
            2,
            4,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(want))],
            PayloadRef::None,
        );
    }
    fn close(&mut self, handle: u64) {
        self.push(
            1,
            4,
            7,
            &[Ty::U64],
            vec![cv(TypedValue::U64(handle))],
            PayloadRef::None,
        );
        self.push(
            2,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }
    fn finish(self, fin: FinalizationInfo) -> ReadTrace {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 1,
                created_by: "test-crate".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        for def in [
            make_schema(
                1,
                "kernel32!CreateFileW/enter",
                vec![
                    ("lpFileName".into(), Ty::Str16, 0),
                    ("dwDesiredAccess".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                2,
                "kernel32!CreateFileW/leave",
                vec![
                    ("return".into(), Ty::U64, 0),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                3,
                "kernel32!ReadFile/enter",
                vec![
                    ("hFile".into(), Ty::U64, 0),
                    ("nNumberOfBytesToRead".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                4,
                "kernel32!ReadFile/leave",
                vec![
                    ("return".into(), Ty::I32, 0),
                    ("lpNumberOfBytesRead".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                7,
                "kernel32!CloseHandle/enter",
                vec![("hObject".into(), Ty::U64, 0)],
            ),
            make_schema(
                8,
                "kernel32!CloseHandle/leave",
                vec![
                    ("return".into(), Ty::I32, 0),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ),
        ] {
            w.register_schema(def).unwrap();
        }
        if !self.events.is_empty() {
            w.write_batch(&EventBatch {
                session_id: 1,
                process_id: 1,
                raw_pid: 10,
                thread_id: 1,
                qpc_frequency: 10_000_000,
                events: self.events,
            })
            .unwrap();
        }
        let bytes = w.finish(fin).unwrap();
        shirusu_trace::read_trace(&bytes).unwrap()
    }
}

fn clean_trace() -> ReadTrace {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(0x100, 4, PayloadRef::None);
    b.close(0x100);
    b.finish(FinalizationInfo::default())
}

#[test]
fn recovered_trace_cannot_pass_no_integrity_loss() {
    let mut trace = clean_trace();
    trace
        .issues
        .push(shirusu_trace::reader::RecoveryIssue::CorruptBlock {
            offset: 100,
            reason: "crc mismatch".into(),
        });
    let s = spec(r#"{"rules":[{"type":"no-integrity-loss"}]}"#);
    assert!(!evaluate(&s, &trace).all_passed());
    trace.issues.clear();
    trace.finalized_cleanly = false;
    assert!(!evaluate(&s, &trace).all_passed());
}

#[test]
fn failed_close_is_not_a_closed_object() {
    let mut trace = clean_trace();
    for batch in &mut trace.batches {
        for e in &mut batch.events {
            if e.schema_id == 8 {
                e.args = Some(
                    encode_values(
                        &[Ty::I32, Ty::U32],
                        &[cv(TypedValue::I32(0)), cv(TypedValue::U32(6))],
                    )
                    .unwrap(),
                );
            }
        }
    }
    let s = spec(r#"{"rules":[{"type":"object-closed","created_by":"kernel32!CreateFileW"}]}"#);
    assert!(!evaluate(&s, &trace).all_passed());
}

fn spec(json: &str) -> TestSpec {
    TestSpec::parse(json).unwrap()
}

#[test]
fn api_called_variants() {
    let trace = clean_trace();
    let s = spec(
        r#"{"name":"t","rules":[
            {"type":"api-called","api":"kernel32!CreateFileW"},
            {"type":"api-called","api":"kernel32!ReadFile","field":"nNumberOfBytesToRead","equals":4},
            {"type":"api-called","api":"kernel32!CreateFileW","field":"lpFileName","contains":"save.dat"},
            {"type":"api-called","api":"kernel32!WriteFile"}
        ]}"#,
    );
    let report = evaluate(&s, &trace);
    assert!(report.results[0].passed, "{:?}", report.results[0]);
    assert!(report.results[1].passed, "{:?}", report.results[1]);
    assert!(report.results[2].passed, "{:?}", report.results[2]);
    assert!(!report.results[3].passed, "{:?}", report.results[3]);
    assert!(!report.all_passed());
}

#[test]
fn api_called_field_mismatch_reports_observed() {
    let trace = clean_trace();
    let s = spec(
        r#"{"rules":[{"type":"api-called","api":"kernel32!ReadFile","field":"nNumberOfBytesToRead","equals":99}]}"#,
    );
    let report = evaluate(&s, &trace);
    assert!(!report.results[0].passed);
    assert!(
        report.results[0].detail.contains("observed: 4"),
        "{}",
        report.results[0].detail
    );
}

#[test]
fn no_integrity_loss_pass_and_fail() {
    let s = spec(r#"{"rules":[{"type":"no-integrity-loss"}]}"#);
    assert!(evaluate(&s, &clean_trace()).all_passed());

    // Payload が落ちた Trace は失敗する。
    let mut b = B::new();
    b.create(0x100, "x");
    b.read(
        0x100,
        4,
        PayloadRef::Dropped {
            original_len: 4096,
            reason: PayloadLossReason::Overflow,
        },
    );
    b.close(0x100);
    let dropped = b.finish(FinalizationInfo::default());
    let report = evaluate(&s, &dropped);
    assert!(!report.all_passed());
    assert!(
        report.results[0].detail.contains("dropped payload"),
        "{}",
        report.results[0].detail
    );

    // Finalization が Degraded を宣言する Trace も失敗する。
    let degraded = clean_trace_degraded();
    let report = evaluate(&s, &degraded);
    assert!(!report.all_passed());
}

fn clean_trace_degraded() -> ReadTrace {
    let mut b = B::new();
    b.create(0x100, "x");
    b.close(0x100);
    b.finish(FinalizationInfo {
        event_integrity: 1,
        ..Default::default()
    })
}

#[test]
fn object_closed_variants() {
    let s = spec(r#"{"rules":[{"type":"object-closed","created_by":"kernel32!CreateFileW"}]}"#);
    assert!(evaluate(&s, &clean_trace()).all_passed());

    let mut b = B::new();
    b.create(0x100, "x");
    b.read(0x100, 4, PayloadRef::None);
    let unclosed = b.finish(FinalizationInfo::default());
    let report = evaluate(&s, &unclosed);
    assert!(!report.all_passed());
    assert!(
        report.results[0].detail.contains("unclosed"),
        "{}",
        report.results[0].detail
    );

    // 生成自体が無い場合は空虚な真にせず失敗とする。
    let empty = B::new().finish(FinalizationInfo::default());
    let report = evaluate(&s, &empty);
    assert!(!report.all_passed());
    assert!(
        report.results[0].detail.contains("no object"),
        "{}",
        report.results[0].detail
    );
}

#[test]
fn event_count_bounds() {
    let trace = clean_trace();
    let s = spec(r#"{"rules":[{"type":"event-count","min":6,"max":6}]}"#);
    assert!(evaluate(&s, &trace).all_passed());
    let s = spec(r#"{"rules":[{"type":"event-count","min":7}]}"#);
    assert!(!evaluate(&s, &trace).all_passed());
}

#[test]
fn uncaptured_dummy_and_stale_values_are_not_evidence() {
    use shirusu_trace::{compact::decode_values, schema::ValueCapture};
    for capture in [
        ValueCapture::Unreadable,
        ValueCapture::Unsupported,
        ValueCapture::Truncated,
        ValueCapture::LimitExceeded,
        ValueCapture::Stale,
    ] {
        let mut trace = clean_trace();
        let event = &mut trace.batches[0].events[0];
        let types = [Ty::Str16, Ty::U32];
        let mut values = decode_values(&types, event.args.as_ref().unwrap()).unwrap();
        values[0].capture = capture;
        values[0].value = TypedValue::Str16("dummy".encode_utf16().collect());
        event.args = Some(encode_values(&types, &values).unwrap());
        for condition in [r#""equals":"dummy""#, r#""contains":"dum""#] {
            let rule = spec(&format!(
                r#"{{"rules":[{{"type":"api-called","api":"kernel32!CreateFileW","field":"lpFileName",{condition}}}]}}"#
            ));
            assert!(!evaluate(&rule, &trace).all_passed(), "{capture:?}");
        }
    }
}

#[test]
fn integrity_rule_rejects_reader_recovery_even_with_complete_finalization() {
    let mut trace = clean_trace();
    trace
        .issues
        .push(shirusu_trace::reader::RecoveryIssue::IndexMismatch);
    let rule = spec(r#"{"rules":[{"type":"no-integrity-loss"}]}"#);
    assert!(!evaluate(&rule, &trace).all_passed());
}
