//! カバレッジ gap のテスト：normalize / diff の未実行分岐を
//! 直接・合成 Trace で駆動する（2026-11-12 計測分）。
//!
//! 既存の scenarios / value_kinds では到達しない経路が対象：
//! - `NormValue` / `NormPayload` の `describe()` 全バリアント
//! - `norm_value` の Ptr32 / Ptr64 / I64 / Bool / F32 / F64 / Str /
//!   BlobRef / U64 Pointer 各アーム
//! - `NormTrace::build` の Other 相・Completed の代替経路・二重 Enter・
//!   未登録スキーマ・Inline / Blob / Dropped の Payload 各アーム
//! - `compare_traces` の左のみ生成オブジェクト・対向オブジェクトへの
//!   追加操作・Capture 相違・フィールド欠落（両方向）・Payload 相違・
//!   完全性メタデータの相違（未 Finalization・Medium 重要度・落ちた
//!   Payload・欠落 Blob）

mod common;

use common::{Builder, Env};
use shirusu_compare::{
    compare_traces, CandidateKind, NormCall, NormPayload, NormTrace, NormValue, ObjectKey, Severity,
};
use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, SchemaDef, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue, ValueKind};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

/// 任意のイベントを直接積める合成 Trace ビルダ。スキーマは呼び出し側
/// が渡す（左右でスキーマを変えるテストのため）。
struct X {
    events: Vec<TraceEvent>,
    seq: u64,
}

impl X {
    fn new() -> Self {
        X {
            events: Vec::new(),
            seq: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: u16,
        call: u64,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
        payload: PayloadRef,
        capture: EventCapture,
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
            capture,
            payload,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
    }

    fn finish(
        self,
        schemas: Vec<SchemaDef>,
        fin: FinalizationInfo,
        losses: &[LossRecord],
        blobs: &[&[u8]],
    ) -> ReadTrace {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 42,
                created_by: "coverage-gaps".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        for def in schemas {
            w.register_schema(def).unwrap();
        }
        for b in blobs {
            w.add_payload(b).unwrap();
        }
        if !losses.is_empty() {
            w.write_loss_records(losses).unwrap();
        }
        if !self.events.is_empty() {
            w.write_batch(&EventBatch {
                session_id: 42,
                process_id: 7,
                raw_pid: 100,
                thread_id: 55,
                qpc_frequency: 10_000_000,
                events: self.events,
            })
            .unwrap();
        }
        let bytes = w.finish(fin).unwrap();
        shirusu_trace::read_trace(&bytes).unwrap()
    }
}

/// Misc API（api_id 60）のスキーマ。norm_value の各型アームを
/// 1 回の enter で駆動する。
fn misc_schemas() -> Vec<SchemaDef> {
    vec![
        make_schema(
            201,
            "test!Misc/enter",
            vec![
                ("p32_scalar".into(), Ty::Ptr32, ValueKind::Scalar.flags()),
                ("p32".into(), Ty::Ptr32, 0),
                ("p32_zero".into(), Ty::Ptr32, 0),
                ("p64_scalar".into(), Ty::Ptr64, ValueKind::Scalar.flags()),
                ("p64".into(), Ty::Ptr64, 0),
                ("p64_zero".into(), Ty::Ptr64, 0),
                ("i64v".into(), Ty::I64, ValueKind::Scalar.flags()),
                ("flag".into(), Ty::Bool, ValueKind::Scalar.flags()),
                ("f32v".into(), Ty::F32, ValueKind::Scalar.flags()),
                ("f64v".into(), Ty::F64, ValueKind::Scalar.flags()),
                ("text".into(), Ty::Str, ValueKind::Scalar.flags()),
                ("blob_known".into(), Ty::BlobRef, 0),
                ("blob_unknown".into(), Ty::BlobRef, 0),
                ("ptr_u64".into(), Ty::U64, ValueKind::Pointer.flags()),
                ("ptr_u64_zero".into(), Ty::U64, ValueKind::Pointer.flags()),
                ("h_unresolved".into(), Ty::U64, ValueKind::Handle.flags()),
                ("h_invalid".into(), Ty::U64, ValueKind::Handle.flags()),
            ],
        ),
        make_schema(
            202,
            "test!Misc/leave",
            vec![
                ("return".into(), Ty::I32, ValueKind::Scalar.flags()),
                // U64 でない生成フィールドは生成とみなさない（272 行）。
                (
                    "u32_created".into(),
                    Ty::U32,
                    ValueKind::CreatedObject.flags(),
                ),
            ],
        ),
        make_schema(203, "test!Ping/enter", vec![]),
        make_schema(
            204,
            "test!Ping/leave",
            vec![("return".into(), Ty::U32, ValueKind::Scalar.flags())],
        ),
    ]
}

fn ping_schemas() -> Vec<SchemaDef> {
    vec![
        make_schema(301, "test!Ping/enter", vec![]),
        make_schema(
            302,
            "test!Ping/leave",
            vec![("return".into(), Ty::U32, ValueKind::Scalar.flags())],
        ),
    ]
}

fn ping_extra_schemas() -> Vec<SchemaDef> {
    vec![
        make_schema(301, "test!Ping/enter", vec![]),
        make_schema(
            302,
            "test!Ping/leave",
            vec![
                ("return".into(), Ty::U32, ValueKind::Scalar.flags()),
                ("extra".into(), Ty::U32, ValueKind::Scalar.flags()),
            ],
        ),
    ]
}

fn standard_left() -> ReadTrace {
    let mut b = Builder::new(Env::default());
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.read_file(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0);
    b.close_handle(3, 0);
    b.ping(4, 7, 7);
    b.finish(FinalizationInfo::default(), &[])
}

fn kinds(report: &shirusu_compare::DiffReport) -> Vec<CandidateKind> {
    report.candidates.iter().map(|c| c.kind).collect()
}

#[test]
fn norm_value_describe_covers_all_variants() {
    assert_eq!(NormValue::Null.describe(), "null");
    assert_eq!(NormValue::Invalid.describe(), "invalid");
    let key = ObjectKey {
        creator_api: "test!Make".into(),
        ordinal: 3,
    };
    assert_eq!(key.describe(), "test!Make#3");
    assert_eq!(NormValue::Object(key).describe(), "object:test!Make#3");
    assert_eq!(NormValue::Pointer.describe(), "pointer");
    assert_eq!(NormValue::Int(-42).describe(), "-42");
    assert_eq!(NormValue::Bool(true).describe(), "true");
    assert_eq!(
        NormValue::FloatBits {
            bits: 0x3FF0_0000_0000_0000,
            is64: true
        }
        .describe(),
        "f64(0x3ff0000000000000)"
    );
    assert_eq!(
        NormValue::FloatBits {
            bits: 0x3F80_0000,
            is64: false
        }
        .describe(),
        "f32(0x3f800000)"
    );
    assert_eq!(NormValue::Text("hi".into()).describe(), "\"hi\"");
    assert_eq!(NormValue::Bytes(vec![1, 2, 3]).describe(), "bytes[3]");
    assert_eq!(
        NormValue::BlobContent(vec![9; 5].into()).describe(),
        "blob-content[5]"
    );
    assert_eq!(
        NormValue::BlobUnknown("ab12".into()).describe(),
        "blob:ab12"
    );
    assert_eq!(NormValue::NotCaptured("stale").describe(), "<stale>");
}

#[test]
fn norm_payload_describe_covers_all_variants() {
    assert_eq!(NormPayload::None.describe(), "none");
    assert_eq!(
        NormPayload::Content(vec![1, 2].into()).describe(),
        "content[2]"
    );
    assert_eq!(
        NormPayload::Dropped {
            original_len: 100,
            reason_code: 2
        }
        .describe(),
        "dropped(len=100, reason=2)"
    );
    assert_eq!(NormPayload::UnknownBlob("ff".into()).describe(), "blob:ff");
}

#[test]
fn norm_call_objects_dedups_referenced() {
    let key = ObjectKey {
        creator_api: "test!Make".into(),
        ordinal: 0,
    };
    let base = NormCall {
        thread: 0,
        position: 0,
        api: "test!Use".into(),
        raw_call_id: 1,
        enter: None,
        leave: None,
        aborted: None,
        completed: None,
        solo: None,
        created: None,
        referenced: Vec::new(),
        first_sequence: 1,
    };
    // 生成と参照が同じキーの場合、objects() は重複を出さない。
    let mut call = base.clone();
    call.created = Some(key.clone());
    call.referenced = vec![key.clone()];
    assert!(call.involves_object());
    assert_eq!(call.objects(), vec![key.clone()]);
    // 参照だけの場合、重複した参照は 1 件にまとまる（208 行の push）。
    let mut call2 = base;
    call2.referenced = vec![key.clone(), key.clone()];
    assert_eq!(call2.objects(), vec![key]);
}

#[test]
fn norm_value_covers_pointer_and_misc_types() {
    let known = BlobId::of_content(b"known-blob");
    let unknown = BlobId::from_bytes([0xAB; 32]);
    let mut x = X::new();
    x.push(
        1,
        1,
        60,
        201,
        &[
            Ty::Ptr32,
            Ty::Ptr32,
            Ty::Ptr32,
            Ty::Ptr64,
            Ty::Ptr64,
            Ty::Ptr64,
            Ty::I64,
            Ty::Bool,
            Ty::F32,
            Ty::F64,
            Ty::Str,
            Ty::BlobRef,
            Ty::BlobRef,
            Ty::U64,
            Ty::U64,
            Ty::U64,
            Ty::U64,
        ],
        vec![
            cv(TypedValue::Ptr32(0x1234)),
            cv(TypedValue::Ptr32(0x5678)),
            cv(TypedValue::Ptr32(0)),
            cv(TypedValue::Ptr64(0x1234_5678)),
            cv(TypedValue::Ptr64(0x9abc)),
            cv(TypedValue::Ptr64(0)),
            cv(TypedValue::I64(-7)),
            cv(TypedValue::Bool(true)),
            cv(TypedValue::F32Bits(0x3F80_0000)),
            cv(TypedValue::F64Bits(0x3FF0_0000_0000_0000)),
            cv(TypedValue::Str("hello".into())),
            cv(TypedValue::BlobRef(known)),
            cv(TypedValue::BlobRef(unknown)),
            cv(TypedValue::U64(0x7ff0_0000)),
            cv(TypedValue::U64(0)),
            cv(TypedValue::U64(0x1234_5678)),
            cv(TypedValue::U64(u64::MAX)),
        ],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        2,
        1,
        60,
        202,
        &[Ty::I32, Ty::U32],
        vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0x2a4))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(
        misc_schemas(),
        FinalizationInfo::default(),
        &[],
        &[b"known-blob"],
    );
    let nt = NormTrace::build(&trace);
    // U32 の CreatedObject フィールドは生成とみなさない（272 行）。
    assert!(nt.objects.is_empty(), "objects: {:?}", nt.objects);
    let call = &nt.calls[0];
    let enter = call.enter.as_ref().unwrap();
    let v = |name: &str| {
        enter
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(v("p32_scalar"), NormValue::Int(0x1234));
    assert_eq!(v("p32"), NormValue::Pointer);
    assert_eq!(v("p32_zero"), NormValue::Null);
    assert_eq!(v("p64_scalar"), NormValue::Int(0x1234_5678));
    assert_eq!(v("p64"), NormValue::Pointer);
    assert_eq!(v("p64_zero"), NormValue::Null);
    assert_eq!(v("i64v"), NormValue::Int(-7));
    assert_eq!(v("flag"), NormValue::Bool(true));
    assert_eq!(
        v("f32v"),
        NormValue::FloatBits {
            bits: 0x3F80_0000,
            is64: false
        }
    );
    assert_eq!(
        v("f64v"),
        NormValue::FloatBits {
            bits: 0x3FF0_0000_0000_0000,
            is64: true
        }
    );
    assert_eq!(v("text"), NormValue::Text("hello".into()));
    assert_eq!(
        v("blob_known"),
        NormValue::BlobContent(b"known-blob".to_vec().into())
    );
    assert_eq!(v("blob_unknown"), NormValue::BlobUnknown(unknown.to_hex()));
    assert_eq!(v("ptr_u64"), NormValue::Pointer);
    assert_eq!(v("ptr_u64_zero"), NormValue::Null);
    assert_eq!(v("h_unresolved"), NormValue::Pointer);
    assert_eq!(v("h_invalid"), NormValue::Invalid);
}

#[test]
fn norm_event_covers_payload_variants() {
    let known = BlobId::of_content(b"payload-blob");
    let unknown = BlobId::from_bytes([0xCD; 32]);
    let mut x = X::new();
    // call 1: enter に Inline Payload。
    x.push(
        1,
        1,
        70,
        203,
        &[],
        vec![],
        PayloadRef::Inline(vec![1, 2, 3]),
        EventCapture::Captured,
    );
    x.push(
        2,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    // call 2: leave に既知 Blob Payload。
    x.push(
        1,
        2,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        2,
        2,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::Blob(known),
        EventCapture::Captured,
    );
    // call 3: leave に未知 Blob Payload（Writer は add_payload 済み
    // の参照しか書けないため、読取後に差し替える）。
    x.push(
        1,
        3,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        2,
        3,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::Blob(known),
        EventCapture::Captured,
    );
    // call 4: enter に Dropped Payload。
    x.push(
        1,
        4,
        70,
        203,
        &[],
        vec![],
        PayloadRef::Dropped {
            original_len: 4096,
            reason: PayloadLossReason::TooLarge,
        },
        EventCapture::Captured,
    );
    x.push(
        2,
        4,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let mut trace = x.finish(
        misc_schemas(),
        FinalizationInfo::default(),
        &[],
        &[b"payload-blob"],
    );
    trace.batches[0].events[5].payload = PayloadRef::Blob(unknown);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 4);
    assert_eq!(
        nt.calls[0].enter.as_ref().unwrap().payload,
        NormPayload::Content(vec![1, 2, 3].into())
    );
    assert_eq!(
        nt.calls[1].leave.as_ref().unwrap().payload,
        NormPayload::Content(b"payload-blob".to_vec().into())
    );
    assert_eq!(
        nt.calls[2].leave.as_ref().unwrap().payload,
        NormPayload::UnknownBlob(unknown.to_hex())
    );
    assert_eq!(
        nt.calls[3].enter.as_ref().unwrap().payload,
        NormPayload::Dropped {
            original_len: 4096,
            reason_code: 2
        }
    );
}

#[test]
fn other_phase_event_becomes_a_solo_call() {
    let mut x = X::new();
    // kind 5 は Enter/Leave/Aborted/Completed のいずれでもない。
    x.push(
        5,
        9,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 1);
    assert!(nt.calls[0].solo.is_some());
    assert!(nt.calls[0].enter.is_none() && nt.calls[0].leave.is_none());
    assert_eq!(nt.calls[0].api, "test!Ping");
}

#[test]
fn unregistered_schema_event_uses_api_id_fallback() {
    let mut x = X::new();
    // schema 999 は未登録：api_name が None になる。
    x.push(
        2,
        1,
        60,
        999,
        &[Ty::U32],
        vec![cv(TypedValue::U32(7))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 1);
    assert_eq!(nt.calls[0].api, "api#60");
    assert!(nt.objects.is_empty());
}

#[test]
fn completed_without_leave_attaches_to_latest_call() {
    let mut x = X::new();
    x.push(
        1,
        1,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    // leave が無いまま kind 8 が来る：rposition の代替経路で
    // enter だけの呼び出しに付く。
    x.push(
        8,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(3))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 1);
    assert!(nt.calls[0].enter.is_some());
    assert!(nt.calls[0].completed.is_some());
    assert!(nt.calls[0].leave.is_none());
}

#[test]
fn completed_without_any_call_becomes_solo() {
    let mut x = X::new();
    x.push(
        8,
        7,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(3))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 1);
    assert!(nt.calls[0].solo.is_some());
    assert!(nt.calls[0].completed.is_none());
}

#[test]
fn completion_does_not_guess_between_reused_call_ids() {
    for other_api in [70, 71] {
        let mut x = X::new();
        for api in [70, other_api] {
            x.push(
                1,
                1,
                api,
                203,
                &[],
                vec![],
                PayloadRef::None,
                EventCapture::Captured,
            );
            x.push(
                2,
                1,
                api,
                203,
                &[],
                vec![],
                PayloadRef::None,
                EventCapture::Captured,
            );
        }
        x.push(
            8,
            1,
            70,
            204,
            &[Ty::U32],
            vec![cv(TypedValue::U32(3))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
        let nt = NormTrace::build(&trace);
        if other_api == 70 {
            assert_eq!(nt.calls.len(), 3);
            assert!(nt.calls[0].completed.is_none());
            assert!(nt.calls[1].completed.is_none());
            assert!(nt.calls[2].solo.is_some());
        } else {
            assert_eq!(nt.calls.len(), 2);
            assert!(nt.calls[0].completed.is_some());
            assert!(nt.calls[1].completed.is_none());
        }
    }
}

#[test]
fn double_enter_starts_a_new_call() {
    let mut x = X::new();
    x.push(
        1,
        1,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        1,
        1,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        2,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    // 先行する enter は未終了のまま確定し、2 回目の enter が新しい
    // 呼び出しを始め、leave はそちらを閉じる。
    assert_eq!(nt.calls.len(), 2);
    assert!(nt.calls[0].enter.is_some() && nt.calls[0].leave.is_none());
    assert!(nt.calls[1].enter.is_some() && nt.calls[1].leave.is_some());
}

#[test]
fn second_completion_is_ignored() {
    let mut x = X::new();
    x.push(
        1,
        1,
        70,
        203,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        2,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        8,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(2))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    x.push(
        8,
        1,
        70,
        204,
        &[Ty::U32],
        vec![cv(TypedValue::U32(3))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = x.finish(misc_schemas(), FinalizationInfo::default(), &[], &[]);
    let nt = NormTrace::build(&trace);
    assert_eq!(nt.calls.len(), 1);
    let completed = nt.calls[0].completed.as_ref().unwrap();
    assert_eq!(completed.fields[0].value, NormValue::Int(2));
}

#[test]
fn object_created_only_in_left_is_a_state_candidate() {
    let left = {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "C:\\game\\save.dat");
        b.close_handle(2, 0);
        b.finish(FinalizationInfo::default(), &[])
    };
    let right = {
        let mut b = Builder::new(Env::default());
        b.ping(1, 7, 7);
        b.finish(FinalizationInfo::default(), &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::ObjectStateDifference
                && c.message
                    .contains("created in left but never created in right")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn extra_op_on_paired_object_is_reported() {
    let left = {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        b.read_file(2, 0, 4, 4, &[1, 2, 3, 4], true, 0);
        b.close_handle(3, 0);
        b.finish(FinalizationInfo::default(), &[])
    };
    let right = {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        b.read_file(2, 0, 4, 4, &[1, 2, 3, 4], true, 0);
        b.write_file(3, 0, &[9, 9]);
        b.close_handle(4, 0);
        b.finish(FinalizationInfo::default(), &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::ExtraCall
                && c.api.as_deref() == Some("kernel32!WriteFile")
                && c.object.is_some()),
        "{:?}",
        report.candidates
    );
}

#[test]
fn capture_difference_is_reported() {
    let left = {
        let mut b = Builder::new(Env::default());
        b.ping(1, 7, 7);
        b.finish(FinalizationInfo::default(), &[])
    };
    let right = {
        let mut b = Builder::new(Env::default());
        b.ping(1, 7, 7);
        // leave イベントだけ部分取得だったことにする。
        b.events.last_mut().unwrap().capture = EventCapture::Truncated;
        b.finish(FinalizationInfo::default(), &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::CaptureDifference),
        "{:?}",
        report.candidates
    );
}

#[test]
fn field_absent_in_right_is_reported() {
    let left = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32, Ty::U32],
            vec![cv(TypedValue::U32(7)), cv(TypedValue::U32(99))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_extra_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let right = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::ArgumentDifference
                && c.field.as_deref() == Some("extra")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn field_present_only_in_right_is_reported() {
    let left = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let right = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32, Ty::U32],
            vec![cv(TypedValue::U32(7)), cv(TypedValue::U32(99))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_extra_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::ArgumentDifference
                && c.field.as_deref() == Some("extra")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn payload_difference_is_reported() {
    let build = |data: Vec<u8>| {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::Inline(data),
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let left = build(vec![1, 2, 3]);
    let right = build(vec![4, 5, 6]);
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::PayloadDifference),
        "{:?}",
        report.candidates
    );
}

#[test]
fn integrity_unknown_finalization_is_reported() {
    let left = standard_left();
    let mut right = standard_left();
    right.finalization = None;
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::IntegrityDifference
                && c.right_value.as_deref() == Some("Unknown (no finalization)")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn integrity_medium_severity_when_neither_side_is_complete() {
    let left = {
        let mut b = Builder::new(Env::default());
        b.ping(1, 7, 7);
        b.finish(
            FinalizationInfo {
                event_integrity: 1,
                ..Default::default()
            },
            &[],
        )
    };
    let right = {
        let mut b = Builder::new(Env::default());
        b.ping(1, 7, 7);
        b.finish(
            FinalizationInfo {
                event_integrity: 2,
                ..Default::default()
            },
            &[],
        )
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::IntegrityDifference
                && c.field.as_deref() == Some("event_integrity")
                && c.severity == Severity::Medium),
        "{:?}",
        report.candidates
    );
}

#[test]
fn integrity_dropped_payload_events_differ() {
    let left = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::Dropped {
                original_len: 100,
                reason: PayloadLossReason::Backpressure,
            },
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let right = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::IntegrityDifference
                && c.field.as_deref() == Some("dropped_payload_events")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn integrity_missing_blob_refs_differ() {
    let unknown = BlobId::from_bytes([0xEE; 32]);
    let left = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        let mut t = x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[]);
        // Writer は未追加 Blob への参照を書けないため、読取後に差し替える。
        t.batches[0].events[0].payload = PayloadRef::Blob(unknown);
        t
    };
    let right = {
        let mut x = X::new();
        x.push(
            1,
            1,
            70,
            301,
            &[],
            vec![],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.push(
            2,
            1,
            70,
            302,
            &[Ty::U32],
            vec![cv(TypedValue::U32(7))],
            PayloadRef::None,
            EventCapture::Captured,
        );
        x.finish(ping_schemas(), FinalizationInfo::default(), &[], &[])
    };
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::IntegrityDifference
                && c.field.as_deref() == Some("missing_blob_refs")),
        "{:?}",
        report.candidates
    );
    // ついでに kinds() の未使用警告を避けるための参照（本ファイルの
    // ヘルパが scenarios と同じ形であることを示す）。
    assert!(kinds(&report).contains(&CandidateKind::IntegrityDifference));
}
