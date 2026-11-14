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

#[test]
fn owned_and_borrowed_batches_preserve_args_fallbacks_and_modes() {
    use shirusu_host::trace_convert::RecordMode;
    let schema = api_by_id(API_CREATE_FILE_W).unwrap().enter_schema_id();
    let mut dropped = event(5, EventKind::CallEnter, schema, Vec::new());
    dropped.descriptor.flags = CaptureState::DroppedByBackpressure.to_flags()
        | shirusu_transport::descriptor::flags::PAYLOAD_DROPPED;
    dropped.descriptor.payload_len = 1234;
    let events = vec![
        event(1, EventKind::CallEnter, schema, create_file_enter_payload()),
        event(2, EventKind::CallEnter, schema, vec![0xff]),
        event(3, EventKind::CallEnter, 0, b"raw".to_vec()),
        event(4, EventKind::CallEnter, schema, Vec::new()),
        dropped,
    ];
    for mode in [
        RecordMode::Full,
        RecordMode::Detailed,
        RecordMode::Profile,
        RecordMode::Filtered {
            apis: [API_CREATE_FILE_W].into_iter().collect(),
        },
        RecordMode::Filtered {
            apis: Default::default(),
        },
    ] {
        let mut borrowed = recorder();
        let mut owned = recorder();
        borrowed.set_record_mode(mode.clone());
        owned.set_record_mode(mode);
        let a = borrowed.record_batch_with_args(&ctx(), &events).unwrap();
        let b = owned
            .record_owned_batch_with_args(&ctx(), events.clone())
            .unwrap();
        assert_eq!(a.args_attached, b.args_attached);
        assert_eq!(a.args_fallback_blob, b.args_fallback_blob);
        let a = borrowed.finish(&IntegrityReport::default()).unwrap();
        let b = owned.finish(&IntegrityReport::default()).unwrap();
        assert_eq!(a, b, "ownership must not change the Trace bytes");
        shirusu_trace::read_trace(&b).unwrap();
    }
}

#[test]
fn broad_tier_schemas_are_registered_on_first_use() {
    // Registering every broad-tier Schema up front costs megabytes per Trace;
    // the Host registers eager Schemas and adds broad ones when used.
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    for def in shirusu_hook::api::eager_schemas() {
        rec.register_schema(def).unwrap();
    }
    rec.set_lazy_schemas(shirusu_hook::api::broad_schema);
    let broad = &shirusu_hook::api::BROAD_API_TABLE[0];
    let payload = shirusu_hook::capture::encode_generic_enter::<12>(
        broad,
        &vec![0u64; broad.enter_fields.len()],
    )
    .as_bytes()
    .to_vec();
    let mut ev = event(1, EventKind::CallEnter, broad.enter_schema_id(), payload);
    ev.descriptor.api_id = broad.api_id;
    let stats = rec.record_batch_with_args(&ctx(), &[ev]).unwrap();
    assert_eq!(
        stats.args_attached, 1,
        "lazily registered Schema decodes args"
    );
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    eprintln!("eager + 1 broad schema trace: {} bytes", bytes.len());
    assert!(bytes.len() < 512 * 1024, "{} bytes", bytes.len());
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.registry.types(broad.enter_schema_id()).is_some());
    let unused = &shirusu_hook::api::BROAD_API_TABLE[1];
    assert!(trace.registry.types(unused.enter_schema_id()).is_none());
    assert!(
        shirusu_hook::api::broad_schema(1).is_none(),
        "curated stays eager"
    );
    assert_eq!(
        shirusu_hook::api::broad_schema(broad.leave_schema_id())
            .unwrap()
            .schema_id,
        broad.leave_schema_id()
    );
}

#[test]
fn plain_record_batch_blobs_even_decodable_payloads() {
    // record_batch（引数モードでない経路）は、登録済み Schema で復号できる
    // Payload でも args にせず Blob として残す。
    let schema = api_by_id(API_CREATE_FILE_W).unwrap().enter_schema_id();
    let payload = create_file_enter_payload();
    let mut rec = recorder();
    rec.record_batch(
        &ctx(),
        &[event(1, EventKind::CallEnter, schema, payload.clone())],
    )
    .unwrap();
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let e = &trace.batches[0].events[0];
    assert!(e.args.is_none());
    match e.payload {
        PayloadRef::Blob(id) => assert_eq!(trace.blobs[&id], payload),
        ref other => panic!("expected a blob, got {other:?}"),
    }
}

#[test]
fn profile_summary_is_readable_before_finish_only_in_profile_mode() {
    use shirusu_host::trace_convert::RecordMode;
    let mut full = recorder();
    assert!(full.profile_summary().is_none());
    full.record_batch(&ctx(), &[event(1, EventKind::CallEnter, 0, vec![])])
        .unwrap();
    assert!(full.profile_summary().is_none());

    let mut rec = recorder();
    rec.set_record_mode(RecordMode::Profile);
    let empty = rec.profile_summary().unwrap();
    assert_eq!(empty.total_events_seen, 0);
    assert!(empty.apis.is_empty());
    let mut leave = event(2, EventKind::CallLeave, 0, vec![]);
    leave.descriptor.timestamp_qpc = 9001 + 40;
    rec.record_batch(&ctx(), &[event(1, EventKind::CallEnter, 0, vec![]), leave])
        .unwrap();
    let summary = rec.profile_summary().unwrap();
    assert_eq!(summary.qpc_frequency, 10_000_000);
    assert_eq!(summary.total_events_seen, 2);
    assert_eq!(summary.apis.len(), 1);
    let row = &summary.apis[0];
    assert_eq!(row.api_id, API_CREATE_FILE_W);
    assert_eq!((row.calls, row.enters, row.leaves), (1, 1, 1));
    assert_eq!(row.total_duration_qpc, 40);
    // 読んでも集計は続く。
    rec.record_batch(&ctx(), &[event(3, EventKind::CallEnter, 0, vec![])])
        .unwrap();
    assert_eq!(rec.profile_summary().unwrap().total_events_seen, 3);
}
