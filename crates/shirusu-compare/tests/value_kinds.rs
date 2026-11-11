//! レビュー #4 の #7 の回帰テスト: 正規化は型 (Ty) ではなく Schema
//! の意味種別 (ValueKind) で判断する。
//!
//! 旧来の実装は U64 を一律にポインタ級として扱い、Leave の U64
//! `return` を常にオブジェクト生成とみなしていた。そのため:
//! - U64 スカラー (カウンタ等) の戻り値が 100 → 200 に変わっても、
//!   両側とも「生成オブジェクト」として正規化され差分が消えた。
//! - スカラー値がハンドル値と偶然一致すると、無関係なオブジェクト
//!   への参照として相関されてしまった。
//!
//! 意味種別を持つ Schema ではどちらも起きないことを固定する。

use shirusu_compare::{compare_traces, CandidateKind, NormTrace};
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{
    make_schema, CapturedValue, EventCapture, LastErrorMeaning, Ty, TypedValue, ValueCapture,
    ValueKind,
};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

/// 古い残留値としての last_error（F20）。値本体は生値を保持する。
fn stale(v: u32) -> CapturedValue {
    CapturedValue {
        capture: ValueCapture::Stale,
        value: TypedValue::U32(v),
    }
}

fn schemas() -> Vec<shirusu_trace::proto::SchemaDef> {
    vec![
        make_schema(101, "test!GetCounter/enter", vec![]),
        make_schema(
            102,
            "test!GetCounter/leave",
            vec![
                ("return".into(), Ty::U64, ValueKind::Scalar.flags()),
                ("last_error".into(), Ty::U32, ValueKind::Scalar.flags()),
            ],
        ),
        make_schema(103, "test!MakeThing/enter", vec![]),
        make_schema(
            104,
            "test!MakeThing/leave",
            vec![
                ("return".into(), Ty::U64, ValueKind::CreatedObject.flags()),
                ("last_error".into(), Ty::U32, ValueKind::Scalar.flags()),
            ],
        ),
        make_schema(
            105,
            "test!UseThing/enter",
            vec![
                ("h".into(), Ty::U64, ValueKind::Handle.flags()),
                ("flags".into(), Ty::U64, ValueKind::Scalar.flags()),
            ],
        ),
        make_schema(
            106,
            "test!UseThing/leave",
            vec![
                ("return".into(), Ty::I32, ValueKind::Scalar.flags()),
                // F20: BOOL 戻り値の API なので、last_error は FALSE の
                // 場合にだけ意味を持つ。
                (
                    "last_error".into(),
                    Ty::U32,
                    ValueKind::Scalar.flags() | LastErrorMeaning::WhenReturnIsFalse.flags(),
                ),
            ],
        ),
    ]
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
    fn get_counter(&mut self, call: u64, value: u64) {
        self.push(1, call, 50, 101, &[], vec![]);
        self.push(
            2,
            call,
            50,
            102,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(value)), cv(TypedValue::U32(0))],
        );
    }
    fn make_thing(&mut self, call: u64, handle: u64) {
        self.push(1, call, 51, 103, &[], vec![]);
        self.push(
            2,
            call,
            51,
            104,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
        );
    }
    fn use_thing(&mut self, call: u64, handle: u64, flags: u64) {
        self.push(
            1,
            call,
            52,
            105,
            &[Ty::U64, Ty::U64],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U64(flags))],
        );
        self.push(
            2,
            call,
            52,
            106,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        );
    }
    fn use_thing_with_last_error(
        &mut self,
        call: u64,
        handle: u64,
        flags: u64,
        ret: i32,
        last: CapturedValue,
    ) {
        self.push(
            1,
            call,
            52,
            105,
            &[Ty::U64, Ty::U64],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U64(flags))],
        );
        self.push(
            2,
            call,
            52,
            106,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(ret)), last],
        );
    }
    fn finish(self) -> ReadTrace {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 42,
                created_by: "value-kinds-test".into(),
                qpc_frequency: 10_000_000,
            },
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

fn kinds(report: &shirusu_compare::DiffReport) -> Vec<CandidateKind> {
    report.candidates.iter().map(|c| c.kind).collect()
}

#[test]
fn scalar_u64_return_difference_is_detected() {
    // レビューの例そのもの: U64 スカラーの戻り値 100 → 200 は差分。
    // 旧実装では両側が「生成オブジェクト」に正規化され消えていた。
    let mut l = B::new();
    l.get_counter(1, 100);
    let left = l.finish();
    let mut r = B::new();
    r.get_counter(1, 200);
    let right = r.finish();
    assert!(
        NormTrace::build(&right).objects.is_empty(),
        "a scalar return must not be treated as object creation"
    );
    let report = compare_traces(&left, &right);
    assert_eq!(
        kinds(&report),
        vec![CandidateKind::ReturnDifference],
        "candidates: {:?}",
        report.candidates
    );
    // 同じ値なら差分なし。
    let mut r2 = B::new();
    r2.get_counter(1, 100);
    let report = compare_traces(&left, &r2.finish());
    assert!(report.is_identical(), "candidates: {:?}", report.candidates);
}

#[test]
fn kinded_handle_renumbering_has_no_candidates() {
    // CreatedObject / Handle の意味種別があれば、ハンドルの再番号
    // 付けは従来どおり差分にならない。
    let mut l = B::new();
    l.make_thing(1, 0x1000);
    l.use_thing(2, 0x1000, 7);
    let left = l.finish();
    let mut r = B::new();
    r.make_thing(1, 0x8ABC);
    r.use_thing(2, 0x8ABC, 7);
    let right = r.finish();
    let report = compare_traces(&left, &right);
    assert!(
        report.is_identical(),
        "renumbering must be normalized away: {:?}",
        report.candidates
    );
    assert_eq!(report.paired_objects, 1);
}

#[test]
fn scalar_value_equal_to_a_handle_is_not_conflated() {
    // スカラーのカウンタ値が生成ハンドルの生値と一致しても、オブ
    // ジェクトへの参照として相関しない。カウンタの変化だけが差分。
    let mut l = B::new();
    l.make_thing(1, 100); // ハンドルの生値がたまたま 100
    l.get_counter(2, 100);
    let left = l.finish();
    assert_eq!(
        NormTrace::build(&left).objects.len(),
        1,
        "only MakeThing creates an object"
    );
    let mut r = B::new();
    r.make_thing(1, 100);
    r.get_counter(2, 200);
    let right = r.finish();
    let report = compare_traces(&left, &right);
    assert_eq!(
        kinds(&report),
        vec![CandidateKind::ReturnDifference],
        "candidates: {:?}",
        report.candidates
    );
}

#[test]
fn scalar_u64_argument_difference_is_detected() {
    // 引数側の U64 スカラーも同様: ポインタとして消去されない。
    let mut l = B::new();
    l.make_thing(1, 0x1000);
    l.use_thing(2, 0x1000, 7);
    let left = l.finish();
    let mut r = B::new();
    r.make_thing(1, 0x1000);
    r.use_thing(2, 0x1000, 9);
    let right = r.finish();
    let report = compare_traces(&left, &right);
    assert_eq!(
        kinds(&report),
        vec![CandidateKind::ArgumentDifference],
        "candidates: {:?}",
        report.candidates
    );
}

#[test]
fn stale_last_error_difference_is_ignored_but_meaningful_is_detected() {
    // F20: 呼び出しが成功したときの last_error 生値は古い残留値
    // (Stale) であり、値が違っても差分にしない。一方、呼び出しが
    // 失敗したときの意味のある last_error の違いは ReturnDifference
    // として検出する。
    // 成功時: 残留値 5 と 7 の違いは差分にならない。
    let mut l = B::new();
    l.use_thing_with_last_error(1, 0x1000, 7, 1, stale(5));
    let left = l.finish();
    let mut r = B::new();
    r.use_thing_with_last_error(1, 0x1000, 7, 1, stale(7));
    let report = compare_traces(&left, &r.finish());
    assert!(
        report.is_identical(),
        "stale last_error must not diff: {:?}",
        report.candidates
    );
    // 失敗時: 意味のある last_error 5 と 2 の違いは差分になる。
    let mut l = B::new();
    l.use_thing_with_last_error(1, 0x1000, 7, 0, cv(TypedValue::U32(5)));
    let left = l.finish();
    let mut r = B::new();
    r.use_thing_with_last_error(1, 0x1000, 7, 0, cv(TypedValue::U32(2)));
    let report = compare_traces(&left, &r.finish());
    assert_eq!(
        kinds(&report),
        vec![CandidateKind::ReturnDifference],
        "candidates: {:?}",
        report.candidates
    );
    // 失敗時でも同じ値なら差分なし。
    let mut r2 = B::new();
    r2.use_thing_with_last_error(1, 0x1000, 7, 0, cv(TypedValue::U32(5)));
    let report = compare_traces(&left, &r2.finish());
    assert!(report.is_identical(), "candidates: {:?}", report.candidates);
}
