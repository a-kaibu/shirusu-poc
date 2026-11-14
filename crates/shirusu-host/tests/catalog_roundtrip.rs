//! 生成 API（標準層 L1 と広域層 5,693 件）すべてについて、Hook の
//! スタック符号化（`encode_generic_enter` / `encode_generic_leave_with_inputs`）
//! の Payload を Host の変換（遅延 Schema 登録を含む）に通し、公開 Trace から
//! Schema で復号した値が参照実装（`generic_enter` / `generic_leave`）の値と
//! 一致することを検査する。Hook 単体の既存テストは標準層の符号化だけを
//! 照合しており、広域層の符号化と、Host・Trace を通した往復は対象外だった。

use proptest::prelude::*;
use shirusu_hook::api::{self, ApiDef, BROAD_API_TABLE, GENERATED_API_TABLE};
use shirusu_hook::capture;
use shirusu_host::trace_convert::{TraceBatchContext, TraceRecorder};
use shirusu_host::IntegrityReport;
use shirusu_trace::compact::decode_values;
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_transport::descriptor::{EventDescriptor, EventKind};
use shirusu_transport::ring::ReceivedEvent;

fn ctx() -> TraceBatchContext {
    TraceBatchContext {
        session_id: 5,
        process_id: 1,
        raw_pid: 10,
        thread_id: 2,
        qpc_frequency: 1000,
    }
}

fn recorder() -> TraceRecorder<Vec<u8>> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 5,
            created_by: "catalog roundtrip".into(),
            qpc_frequency: 1000,
        },
        ..Default::default()
    };
    let mut rec = TraceRecorder::from_environment(Vec::new(), env).unwrap();
    for def in api::eager_schemas() {
        rec.register_schema(def).unwrap();
    }
    rec.set_lazy_schemas(api::broad_schema);
    rec
}

fn event(
    api: &ApiDef,
    seq: u64,
    kind: EventKind,
    schema_id: u32,
    payload: Vec<u8>,
) -> ReceivedEvent {
    let mut d = EventDescriptor::new(kind, seq);
    d.payload_len = payload.len() as u32;
    d.schema_id = schema_id;
    d.api_id = api.api_id;
    d.call_id = seq.div_ceil(2);
    d.timestamp_qpc = seq;
    ReceivedEvent {
        descriptor: d,
        payload,
    }
}

fn generated() -> impl Iterator<Item = &'static ApiDef> {
    GENERATED_API_TABLE.iter().chain(BROAD_API_TABLE.iter())
}

/// 1 つの Trace に `calls` の enter/leave を記録し、復号値を参照実装と照合する。
fn roundtrip(calls: &[(&'static ApiDef, Vec<u64>, u64, u32)]) {
    let mut rec = recorder();
    let mut events = Vec::new();
    let mut expected = Vec::new();
    for (i, (api, args, ret, err)) in calls.iter().enumerate() {
        let seq = 2 * i as u64 + 1;
        let enter = capture::encode_generic_enter::<32>(api, args)
            .as_bytes()
            .to_vec();
        let leave = capture::encode_generic_leave_with_inputs(api, *ret, *err, args)
            .as_bytes()
            .to_vec();
        events.push(event(
            api,
            seq,
            EventKind::CallEnter,
            api.enter_schema_id(),
            enter,
        ));
        events.push(event(
            api,
            seq + 1,
            EventKind::CallLeave,
            api.leave_schema_id(),
            leave,
        ));
        expected.push(capture::generic_enter(api, args));
        // generic_leave は入力に依存する意味を解決しない（DependsOnInputs）。
        // 入力付きの符号化と比べるため、値と取得状態は個別に確かめる。
        expected.push(capture::generic_leave(api, *ret, *err));
    }
    let stats = rec.record_batch_with_args(&ctx(), &events).unwrap();
    // 空の値列（引数なしの enter）は Payload を持たず、args も付かない。
    let non_empty = events.iter().filter(|e| !e.payload.is_empty()).count();
    assert_eq!(
        stats.args_attached, non_empty,
        "every payload decodes as args"
    );
    assert_eq!(stats.args_fallback_blob, 0);
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "{:?}", trace.issues);
    assert!(trace.blobs.is_empty());
    let got: Vec<_> = trace.batches.iter().flat_map(|b| b.events.iter()).collect();
    assert_eq!(got.len(), events.len());
    for (k, (e, want)) in got.iter().zip(&expected).enumerate() {
        let (api, ..) = &calls[k / 2];
        let types = trace
            .registry
            .types(e.schema_id)
            .unwrap_or_else(|| panic!("{}: schema {} not registered", api.function, e.schema_id));
        let values = match e.args.as_deref() {
            Some(args) => decode_values(&types, args).unwrap(),
            None => {
                assert!(types.is_empty(), "{}: args missing", api.function);
                Vec::new()
            }
        };
        assert_eq!(values.len(), want.len(), "{}", api.function);
        for (v, w) in values.iter().zip(want) {
            assert_eq!(v.value, w.value, "{} value", api.function);
            if k % 2 == 0 {
                assert_eq!(v.capture, w.capture, "{} enter capture", api.function);
            }
        }
    }
}

#[test]
fn every_generated_api_roundtrips_through_host_and_trace() {
    let all: Vec<&'static ApiDef> = generated().collect();
    assert!(all.len() > 5_000, "{} generated APIs", all.len());
    for raw in [
        0u64,
        1,
        u32::MAX as u64,
        u64::MAX,
        i64::MIN as u64,
        0x8000_0000,
    ] {
        // 1 Trace に数百件ずつ（遅延登録が多数の Schema に跨っても成り立つ）。
        for chunk in all.chunks(512) {
            let calls: Vec<_> = chunk
                .iter()
                .map(|api| (*api, vec![raw; api.enter_fields.len()], raw, raw as u32))
                .collect();
            roundtrip(&calls);
        }
    }
}

#[test]
fn broad_stack_encoding_matches_reference_for_every_api() {
    for api in BROAD_API_TABLE {
        for raw in [
            0,
            1,
            u32::MAX as u64,
            u64::MAX,
            i64::MIN as u64,
            0x7ff8_0000_0000_1234,
        ] {
            let args = vec![raw; api.enter_fields.len()];
            assert_eq!(
                capture::encode_generic_enter::<32>(api, &args).as_bytes(),
                capture::encode_enter(api, &capture::generic_enter(api, &args)).unwrap(),
                "{} enter",
                api.function
            );
            assert_eq!(
                capture::encode_generic_leave(api, raw, u32::MAX).as_bytes(),
                capture::encode_leave(api, &capture::generic_leave(api, raw, u32::MAX)).unwrap(),
                "{} leave",
                api.function
            );
        }
    }
}

fn call() -> impl Strategy<Value = (&'static ApiDef, Vec<u64>, u64, u32)> {
    let n = GENERATED_API_TABLE.len() + BROAD_API_TABLE.len();
    (
        0..n,
        proptest::collection::vec(any::<u64>(), 32),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(|(i, raw, ret, err)| {
            let api = generated().nth(i).unwrap();
            let args = raw[..api.enter_fields.len()].to_vec();
            (api, args, ret, err)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn arbitrary_generated_calls_roundtrip(calls in proptest::collection::vec(call(), 1..24)) {
        roundtrip(&calls);
    }
}
