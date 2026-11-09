//! PBT：値列・イベント列・Writer→Reader の往復と、破壊入力での
//! 非 panic 性。参照モデルは「符号化して復号したら元と一致する」こと。

use proptest::prelude::*;
use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::{decode_values, encode_values};
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{CapturedValue, EventCapture, Ty, TypedValue, ValueCapture};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::TraceWriter;
use std::collections::HashMap;

fn arb_value() -> impl Strategy<Value = (Ty, TypedValue)> {
    prop_oneof![
        any::<i32>().prop_map(|v| (Ty::I32, TypedValue::I32(v))),
        any::<i64>().prop_map(|v| (Ty::I64, TypedValue::I64(v))),
        any::<u32>().prop_map(|v| (Ty::U32, TypedValue::U32(v))),
        any::<u64>().prop_map(|v| (Ty::U64, TypedValue::U64(v))),
        any::<u32>().prop_map(|v| (Ty::F32, TypedValue::F32Bits(v))),
        any::<u64>().prop_map(|v| (Ty::F64, TypedValue::F64Bits(v))),
        any::<bool>().prop_map(|v| (Ty::Bool, TypedValue::Bool(v))),
        "[a-zA-Z0-9 ]{0,12}".prop_map(|v| (Ty::Str, TypedValue::Str(v))),
        prop::collection::vec(any::<u16>(), 0..8).prop_map(|v| (Ty::Str16, TypedValue::Str16(v))),
        prop::collection::vec(any::<u8>(), 0..16).prop_map(|v| (Ty::Bytes, TypedValue::Bytes(v))),
        any::<[u8; 32]>().prop_map(|v| (Ty::BlobRef, TypedValue::BlobRef(BlobId::from_bytes(v)))),
        any::<u32>().prop_map(|v| (Ty::Ptr32, TypedValue::Ptr32(v))),
        any::<u64>().prop_map(|v| (Ty::Ptr64, TypedValue::Ptr64(v))),
    ]
}

fn arb_capture() -> impl Strategy<Value = ValueCapture> {
    (0u8..5).prop_map(|c| ValueCapture::from_code(c).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn values_roundtrip(
        pairs in prop::collection::vec((arb_value(), arb_capture()), 0..24)
    ) {
        let types: Vec<Ty> = pairs.iter().map(|((t, _), _)| *t).collect();
        let values: Vec<CapturedValue> = pairs
            .iter()
            .map(|((_, v), c)| CapturedValue { capture: *c, value: v.clone() })
            .collect();
        let encoded = encode_values(&types, &values).unwrap();
        let decoded = decode_values(&types, &encoded).unwrap();
        prop_assert_eq!(decoded, values);
    }

    #[test]
    fn values_decode_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..64),
        ty_count in 0usize..8,
    ) {
        let types: Vec<Ty> = (0..ty_count).map(|i| match i % 13 {
            0 => Ty::I32, 1 => Ty::I64, 2 => Ty::U32, 3 => Ty::U64,
            4 => Ty::F32, 5 => Ty::F64, 6 => Ty::Bool, 7 => Ty::Str,
            8 => Ty::Str16, 9 => Ty::Bytes, 10 => Ty::BlobRef,
            11 => Ty::Ptr32, _ => Ty::Ptr64,
        }).collect();
        // 戻り値は問わない。panic しないことだけが不変条件。
        let _ = decode_values(&types, &data);
    }
}

// ---------------------------------------------------------------------------
// Writer → Reader の往復
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum ArbPayload {
    None,
    Inline(Vec<u8>),
    Blob(Vec<u8>),
    Dropped(u64, u8),
}

fn arb_payload() -> impl Strategy<Value = ArbPayload> {
    prop_oneof![
        Just(ArbPayload::None),
        prop::collection::vec(any::<u8>(), 0..48).prop_map(ArbPayload::Inline),
        prop::collection::vec(any::<u8>(), 0..48).prop_map(ArbPayload::Blob),
        (
            0u64..1_000_000,
            prop_oneof![Just(1u8), Just(2), Just(3), Just(4), Just(255)]
        )
            .prop_map(|(len, reason)| ArbPayload::Dropped(len, reason)),
    ]
}

fn run_writer_reader_case(
    specs: Vec<(u64, u64, ArbPayload, Option<Vec<u8>>)>,
) -> Result<(), TestCaseError> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "pbt".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    let mut expected_events = Vec::new();
    let mut expected_blobs: HashMap<BlobId, Vec<u8>> = HashMap::new();
    for (seq, ts, payload, args) in specs {
        let payload_ref = match &payload {
            ArbPayload::None => PayloadRef::None,
            ArbPayload::Inline(b) => PayloadRef::Inline(b.clone()),
            ArbPayload::Blob(b) => {
                let id = w.add_payload(b).unwrap();
                expected_blobs.insert(id, b.clone());
                PayloadRef::Blob(id)
            }
            ArbPayload::Dropped(len, code) => PayloadRef::Dropped {
                original_len: *len,
                reason: PayloadLossReason::from_code(*code),
            },
        };
        expected_events.push(TraceEvent {
            kind: 1,
            sequence: seq,
            timestamp_qpc: ts,
            call_id: seq,
            parent_call_id: 0,
            api_id: 5,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: payload_ref,
            args,
        });
    }
    let batch = EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 100,
        thread_id: 3,
        qpc_frequency: 10_000_000,
        events: expected_events.clone(),
    };
    if !batch.events.is_empty() {
        w.write_batch(&batch).unwrap();
    }
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    prop_assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    let flat: Vec<TraceEvent> = trace
        .batches
        .iter()
        .flat_map(|b| b.events.iter().cloned())
        .collect();
    prop_assert_eq!(flat, expected_events);
    prop_assert_eq!(trace.blobs.len(), expected_blobs.len());
    for (id, content) in &expected_blobs {
        prop_assert_eq!(trace.blobs.get(id), Some(content));
    }
    prop_assert!(trace.index_matches_scan);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn writer_reader_roundtrip(
        raw in prop::collection::vec(
            (any::<u64>(), arb_payload(), prop::option::of(prop::collection::vec(any::<u8>(), 0..24))),
            1..40,
        )
    ) {
        // sequence は単調非減少に整える（Writer の不変条件）。
        let mut specs: Vec<(u64, u64, ArbPayload, Option<Vec<u8>>)> = raw
            .into_iter()
            .enumerate()
            .map(|(i, (ts, p, a))| (i as u64, ts % 1_000_000, p, a))
            .collect();
        specs.sort_by_key(|(seq, _, _, _)| *seq);
        run_writer_reader_case(specs)?;
    }

    #[test]
    fn mutated_trace_never_panics(
        flips in prop::collection::vec((0usize..400, 1u8..=255), 1..8)
    ) {
        // 有効な Trace を 1 つ作り、任意の位置を書き換えても
        // recover_trace が panic しないこと。先頭 Block 内の破壊は
        // NotATrace、それ以外は回復結果が返る。
        let env = CaptureEnvironment {
            session: SessionMetadata { session_id: 42, created_by: "pbt".into(), qpc_frequency: 10_000_000 },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        let id = w.add_payload(b"mutation target payload").unwrap();
        let batch = EventBatch {
            session_id: 42, process_id: 7, raw_pid: 100, thread_id: 3, qpc_frequency: 10_000_000,
            events: vec![TraceEvent {
                kind: 1, sequence: 1, timestamp_qpc: 5, call_id: 1, parent_call_id: 0,
                api_id: 1, schema_id: 0, capture: EventCapture::Captured,
                payload: PayloadRef::Blob(id), args: None,
            }],
        };
        w.write_batch(&batch).unwrap();
        let base = w.finish(FinalizationInfo::default()).unwrap();
        let mut broken = base.clone();
        // 同じ位置への複数 flip は合算し、打ち消し合う場合は「触っていない」
        // として扱う（バイトが元に戻るケースを不変条件から除くため）。
        let mut net: std::collections::HashMap<usize, u8> = std::collections::HashMap::new();
        for (pos, delta) in &flips {
            let pos = pos % broken.len();
            let e = net.entry(pos).or_insert(0);
            *e = e.wrapping_add(*delta);
        }
        let mut touched_header = false;
        for (pos, delta) in net {
            if delta == 0 {
                continue;
            }
            if pos < 56 {
                touched_header = true;
            }
            broken[pos] = broken[pos].wrapping_add(delta);
        }
        let result = shirusu_trace::recover_trace(&broken);
        if touched_header {
            prop_assert!(
                matches!(result, Err(shirusu_trace::TraceError::NotATrace)),
                "header corruption must be NotATrace, got Ok or other error"
            );
        } else {
            prop_assert!(result.is_ok(), "body corruption must recover: {:?}", result.err());
        }
    }
}
