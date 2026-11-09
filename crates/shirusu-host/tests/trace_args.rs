//! Phase 3: フック由来イベントの引数変換テスト。
//!
//! - 登録済みフック Schema の Payload は引数値列として args へ写り、
//!   Blob にはならない。読み戻して Schema で復号できる。
//! - 復号できない Payload は Blob として保持され（データを失わない）、
//!   統計で数えられる。
//! - 未登録 Schema の Payload は従来どおり Blob。
//! - 欠落 Payload は引数モードでも Dropped のまま。

use shirusu_hook::api::{api_by_id, API_CREATE_FILE_W};
use shirusu_hook::capture::{self, MapMemory};
use shirusu_host::trace_convert::{TraceBatchContext, TraceRecorder};
use shirusu_host::IntegrityReport;
use shirusu_trace::model::PayloadRef;
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::TypedValue;
use shirusu_transport::descriptor::{CaptureState, EventDescriptor, EventKind};
use shirusu_transport::ring::ReceivedEvent;

const SESSION: u64 = 7;

fn environment() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: SESSION,
            created_by: "shirusu-host test (args)".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    }
}

fn ctx() -> TraceBatchContext {
    TraceBatchContext {
        session_id: SESSION,
        process_id: 3,
        raw_pid: 100,
        thread_id: 9,
        qpc_frequency: 10_000_000,
    }
}

fn recorder() -> TraceRecorder<Vec<u8>> {
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    for def in shirusu_hook::api::all_schemas() {
        rec.register_schema(def).unwrap();
    }
    rec
}

fn event(sequence: u64, kind: EventKind, schema_id: u32, payload: Vec<u8>) -> ReceivedEvent {
    let mut d = EventDescriptor::new(kind, sequence);
    d.payload_len = payload.len() as u32;
    d.schema_id = schema_id;
    d.api_id = API_CREATE_FILE_W;
    d.call_id = 55;
    d.timestamp_qpc = 9000 + sequence;
    ReceivedEvent {
        descriptor: d,
        payload,
    }
}

fn create_file_enter_payload() -> Vec<u8> {
    let api = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut mem = MapMemory::new();
    let units: Vec<u16> = "C:\\work\\a.txt".encode_utf16().chain([0]).collect();
    mem.write_u16s(0x1000, &units);
    let values = capture::create_file_w_enter(&mem, 0x1000, 0xC000_0000, 0, 0, 2, 0x80, 0);
    capture::encode_enter(api, &values).unwrap()
}

#[test]
fn hook_payload_becomes_args_not_blob() {
    let api = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut rec = recorder();
    let payload = create_file_enter_payload();
    let ev = event(
        1,
        EventKind::CallEnter,
        api.enter_schema_id(),
        payload.clone(),
    );
    let stats = rec.record_batch_with_args(&ctx(), &[ev]).unwrap();
    assert_eq!(stats.args_attached, 1);
    assert_eq!(stats.args_fallback_blob, 0);
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.blobs.is_empty(), "args must not be blobbed");
    let e = &trace.batches[0].events[0];
    assert_eq!(e.payload, PayloadRef::None);
    assert_eq!(e.args.as_deref(), Some(payload.as_slice()));
    // Schema で復号してパスが復元できる (L2)
    let types = trace.registry.types(e.schema_id).unwrap();
    let values = shirusu_trace::compact::decode_values(&types, e.args.as_ref().unwrap()).unwrap();
    match &values[0].value {
        TypedValue::Str16(u) => {
            assert_eq!(String::from_utf16_lossy(u), "C:\\work\\a.txt");
        }
        other => panic!("expected Str16 path, got {other:?}"),
    }
}

#[test]
fn undecodable_payload_falls_back_to_blob() {
    let api = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut rec = recorder();
    // フック Schema ID を名乗るが値列として壊れている Payload
    let ev = event(
        1,
        EventKind::CallEnter,
        api.enter_schema_id(),
        vec![0xFF, 0xFF, 0xFF, 0xFF],
    );
    let stats = rec.record_batch_with_args(&ctx(), &[ev]).unwrap();
    assert_eq!(stats.args_attached, 0);
    assert_eq!(stats.args_fallback_blob, 1);
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let e = &trace.batches[0].events[0];
    assert!(
        matches!(e.payload, PayloadRef::Blob(_)),
        "data is preserved as blob"
    );
    assert!(e.args.is_none());
}

#[test]
fn unregistered_schema_payload_stays_blob() {
    let mut rec = recorder();
    let ev = event(1, EventKind::CallEnter, 200, b"raw-bytes".to_vec());
    let stats = rec.record_batch_with_args(&ctx(), &[ev]).unwrap();
    assert_eq!(stats.args_attached, 0);
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let e = &trace.batches[0].events[0];
    assert!(matches!(e.payload, PayloadRef::Blob(_)));
    assert!(e.args.is_none());
}

#[test]
fn dropped_payload_stays_dropped_in_args_mode() {
    let api = api_by_id(API_CREATE_FILE_W).unwrap();
    let mut rec = recorder();
    let mut ev = event(1, EventKind::CallEnter, api.enter_schema_id(), Vec::new());
    ev.descriptor.flags = CaptureState::DroppedByBackpressure.to_flags()
        | shirusu_transport::descriptor::flags::PAYLOAD_DROPPED;
    ev.descriptor.payload_len = 1234;
    let stats = rec.record_batch_with_args(&ctx(), &[ev]).unwrap();
    assert_eq!(stats.args_attached, 0);
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let e = &trace.batches[0].events[0];
    assert!(matches!(
        e.payload,
        PayloadRef::Dropped {
            original_len: 1234,
            ..
        }
    ));
    assert!(e.args.is_none());
}
