//! レビュー第5回 #5 の回帰テスト: INVALID_HANDLE_VALUE はポインタ幅
//! 依存の番兵であり、無効ハンドル判定は Trace の
//! `CaptureEnvironment.pointer_width` に基づかなければならない。
//!
//! - x86 (32bit): INVALID_HANDLE_VALUE は 0x0000_0000_FFFF_FFFF
//!   (HANDLE は 32bit で、記録時は u64 へゼロ拡張される)。
//! - x64 (64bit): INVALID_HANDLE_VALUE は 0xFFFF_FFFF_FFFF_FFFF。
//!
//! 旧実装は u64::MAX だけを無効とみなしたため、x86 の CreateFileW
//! 失敗が「オブジェクト生成」として登録され、x86/x64 の Trace 比較で
//! 偽の差分になった。逆に x64 では 0x0000_0000_FFFF_FFFF は正当な
//! ハンドル値であり、生成として扱われなければならない。

use shirusu_compare::{compare_traces, NormTrace, NormValue};
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue, ValueKind};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

const X86_INVALID: u64 = 0x0000_0000_FFFF_FFFF;
const X64_INVALID: u64 = u64::MAX;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn schemas() -> Vec<shirusu_trace::proto::SchemaDef> {
    vec![
        make_schema(201, "test!CreateFileW/enter", vec![]),
        make_schema(
            202,
            "test!CreateFileW/leave",
            vec![
                ("return".into(), Ty::U64, ValueKind::CreatedObject.flags()),
                ("last_error".into(), Ty::U32, ValueKind::Scalar.flags()),
            ],
        ),
        make_schema(
            203,
            "test!UseHandle/enter",
            vec![("h".into(), Ty::U64, ValueKind::Handle.flags())],
        ),
        make_schema(
            204,
            "test!UseHandle/leave",
            vec![
                ("return".into(), Ty::I32, ValueKind::Scalar.flags()),
                ("last_error".into(), Ty::U32, ValueKind::Scalar.flags()),
            ],
        ),
    ]
}

struct B {
    events: Vec<TraceEvent>,
    seq: u64,
    pointer_width: u32,
}

impl B {
    fn new(pointer_width: u32) -> Self {
        B {
            events: Vec::new(),
            seq: 0,
            pointer_width,
        }
    }
    fn push(
        &mut self,
        kind: u16,
        call: u64,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
    ) {
        self.seq += 1;
        self.events.push(TraceEvent {
            kind,
            sequence: self.seq,
            timestamp_qpc: 1000 + self.seq * 10,
            call_id: call,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
    }
    /// CreateFileW の呼び出し。err は last_error (失敗時 5 など)。
    fn create_file(&mut self, call: u64, ret: u64, err: u32) {
        self.push(1, call, 60, 201, &[], vec![]);
        self.push(
            2,
            call,
            60,
            202,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(ret)), cv(TypedValue::U32(err))],
        );
    }
    fn use_handle(&mut self, call: u64, h: u64) {
        self.push(1, call, 61, 203, &[Ty::U64], vec![cv(TypedValue::U64(h))]);
        self.push(
            2,
            call,
            61,
            204,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        );
    }
    fn finish(self) -> ReadTrace {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 42,
                created_by: "invalid-handle-width-test".into(),
                qpc_frequency: 10_000_000,
            },
            pointer_width: self.pointer_width,
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        for def in schemas() {
            w.register_schema(def).unwrap();
        }
        w.write_batch(&EventBatch {
            session_id: 42,
            process_id: 7,
            raw_pid: 100,
            thread_id: 55,
            qpc_frequency: 10_000_000,
            events: self.events,
        })
        .unwrap();
        let bytes = w.finish(FinalizationInfo::default()).unwrap();
        shirusu_trace::read_trace(&bytes).unwrap()
    }
}

#[test]
fn x86_invalid_handle_value_is_not_a_creation() {
    let mut b = B::new(32);
    b.create_file(1, X86_INVALID, 5);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    assert!(
        norm.objects.is_empty(),
        "x86 INVALID_HANDLE_VALUE must not register as a creation: {:?}",
        norm.objects
    );
    assert!(norm.calls[0].created.is_none());
}

#[test]
fn x64_invalid_handle_value_is_not_a_creation() {
    let mut b = B::new(64);
    b.create_file(1, X64_INVALID, 5);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    assert!(norm.objects.is_empty());
    assert!(norm.calls[0].created.is_none());
}

#[test]
fn failed_create_compares_equal_across_architectures() {
    // レビューのシナリオ: 同じ「ファイルを開けなかった」記録が、
    // x86 と x64 で差分になってはいけない。
    let mut l = B::new(32);
    l.create_file(1, X86_INVALID, 5);
    let left = l.finish();
    let mut r = B::new(64);
    r.create_file(1, X64_INVALID, 5);
    let right = r.finish();
    let report = compare_traces(&left, &right);
    assert!(
        report.candidates.is_empty(),
        "cross-arch failed CreateFileW must not diff: {:?}",
        report.candidates
    );
}

#[test]
fn x64_low32_all_ones_is_a_valid_creation() {
    // x64 では 0x0000_0000_FFFF_FFFF は番兵ではない。正当な生成。
    let mut b = B::new(64);
    b.create_file(1, X86_INVALID, 0);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    assert_eq!(norm.objects.len(), 1);
    assert!(norm.calls[0].created.is_some());
}

#[test]
fn x86_valid_handle_is_a_creation() {
    let mut b = B::new(32);
    b.create_file(1, 0x0000_0000_0000_0800, 0);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    assert_eq!(norm.objects.len(), 1);
}

#[test]
fn x86_invalid_handle_argument_normalizes_to_invalid() {
    // 引数として渡された無効ハンドルも幅依存で Invalid になる。
    let mut b = B::new(32);
    b.use_handle(1, X86_INVALID);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    let enter = norm.calls[0].enter.as_ref().expect("enter");
    assert_eq!(enter.fields[0].value, NormValue::Invalid);
}

#[test]
fn x64_invalid_handle_argument_normalizes_to_invalid() {
    let mut b = B::new(64);
    b.use_handle(1, X64_INVALID);
    let trace = b.finish();
    let norm = NormTrace::build(&trace);
    let enter = norm.calls[0].enter.as_ref().expect("enter");
    assert_eq!(enter.fields[0].value, NormValue::Invalid);
}

#[test]
fn failed_creation_does_not_shift_later_object_correspondence() {
    use shirusu_compare::CandidateKind;
    for width in [32, 64] {
        let invalid = if width == 32 {
            X86_INVALID
        } else {
            X64_INVALID
        };
        let mut left = B::new(width);
        left.create_file(1, 100, 0);
        left.create_file(2, 200, 0);
        left.use_handle(3, 200);
        let left = left.finish();
        let mut right = B::new(width);
        right.create_file(1, invalid, 5);
        right.create_file(2, 300, 0);
        right.use_handle(3, 300);
        let right = right.finish();
        let normalized = NormTrace::build(&right);
        assert_eq!(normalized.objects.len(), 1);
        assert_eq!(normalized.objects[0].key.ordinal, 1);
        for (a, b) in [(&left, &right), (&right, &left)] {
            let report = compare_traces(a, b);
            assert_eq!(report.paired_objects, 1);
            let returns: Vec<_> = report
                .candidates
                .iter()
                .filter(|c| {
                    c.kind == CandidateKind::ReturnDifference
                        && c.field.as_deref() == Some("return")
                })
                .collect();
            assert_eq!(returns.len(), 1, "{:?}", report.candidates);
            assert_eq!(returns[0].left_event.as_ref().unwrap().sequence, 1);
            assert_eq!(returns[0].right_event.as_ref().unwrap().sequence, 1);
            assert!(
                !report.candidates.iter().any(|c| matches!(
                    c.kind,
                    CandidateKind::ExtraCall | CandidateKind::MissingCall
                )),
                "{:?}",
                report.candidates
            );
        }
    }
}
