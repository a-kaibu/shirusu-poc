//! ビューの単体テスト。合成 Trace を Writer で作り、復号・整形・
//! 完全性サマリが期待どおりになることを確認する。

use shirusu_analysis::{EventFilter, TraceView};
use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::container::{
    parse_raw_header, serialize_header, BlockHeader, BlockType, Compression,
};
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::{PayloadResolution, RecoveryIssue};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::TraceWriter;

pub fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

pub fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

/// フック表と同じ名前・形のスキーマで、CreateFileW→ReadFile→
/// CloseHandle の 1 往復を記録した合成 Trace のバイト列。
pub fn sample_trace_bytes() -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "analysis-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    let schemas = [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
                ("hTemplateFile".into(), Ty::U64, 0),
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
                ("data".into(), Ty::Bytes, 0),
                ("last_error".into(), Ty::U32, 0),
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
    ];
    for def in &schemas {
        w.register_schema(def.clone()).unwrap();
    }
    let handle = 0x2a4u64;
    let ev = |kind: u16,
              sequence: u64,
              call_id: u64,
              api_id: u32,
              schema_id: u32,
              types: &[Ty],
              values: Vec<CapturedValue>| {
        TraceEvent {
            kind,
            sequence,
            timestamp_qpc: 1_000 + sequence * 10,
            call_id,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload: shirusu_trace::PayloadRef::None,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        }
    };
    let events = vec![
        ev(
            1,
            1,
            1,
            1,
            1,
            &[Ty::Str16, Ty::U32, Ty::U64],
            vec![
                cv(str16("C:\\game\\save.dat")),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U64(0)),
            ],
        ),
        ev(
            2,
            2,
            1,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
        ),
        ev(
            1,
            3,
            2,
            2,
            3,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(4))],
        ),
        ev(
            2,
            4,
            2,
            2,
            4,
            &[Ty::I32, Ty::U32, Ty::Bytes, Ty::U32],
            vec![
                cv(TypedValue::I32(1)),
                cv(TypedValue::U32(4)),
                cv(TypedValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
                cv(TypedValue::U32(0)),
            ],
        ),
        ev(1, 5, 3, 4, 7, &[Ty::U64], vec![cv(TypedValue::U64(handle))]),
        ev(
            2,
            6,
            3,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        ),
    ];
    let batch = EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events,
    };
    w.write_batch(&batch).unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn view_decodes_args_and_formats_lines() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    assert_eq!(view.events.len(), 6);
    let first = &view.events[0];
    assert_eq!(first.api_name.as_deref(), Some("kernel32!CreateFileW"));
    assert_eq!(
        first.line(),
        "#0 seq=1 thread=55 kernel32!CreateFileW enter call=1 \
         lpFileName=\"C:\\\\game\\\\save.dat\" dwDesiredAccess=2147483648 hTemplateFile=0x0 \
         payload=none capture=captured"
    );
    let read_leave = &view.events[3];
    assert!(
        read_leave.line().contains("data=bytes[4]=deadbeef"),
        "{}",
        read_leave.line()
    );
}

#[test]
fn api_stats_and_thread_count() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let stats = view.api_stats();
    assert_eq!(
        stats,
        vec![
            ("kernel32!CloseHandle".to_string(), 1, 1),
            ("kernel32!CreateFileW".to_string(), 1, 1),
            ("kernel32!ReadFile".to_string(), 1, 1),
        ]
    );
    assert_eq!(view.thread_count(), 1);
}

#[test]
fn integrity_summary_of_clean_trace() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let s = &view.integrity;
    assert!(s.has_finalization);
    assert!(s.finalized_cleanly);
    assert_eq!(s.capture_coverage, Some(0));
    assert_eq!(s.event_integrity, Some(0));
    assert!(!s.has_event_loss());
    assert_eq!(s.dropped_payload_events, 0);
    assert_eq!(s.missing_blob_refs, 0);
}

#[test]
fn filters_match_api_kind_seq_and_text() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let by_api = EventFilter {
        api: Some("ReadFile".into()),
        ..Default::default()
    };
    let hits: Vec<usize> = view
        .events
        .iter()
        .filter(|e| by_api.matches(e))
        .map(|e| e.index)
        .collect();
    assert_eq!(hits, vec![2, 3]);

    let by_seq = EventFilter {
        seq_min: Some(2),
        seq_max: Some(3),
        kind: Some(2),
        ..Default::default()
    };
    let hits: Vec<usize> = view
        .events
        .iter()
        .filter(|e| by_seq.matches(e))
        .map(|e| e.index)
        .collect();
    assert_eq!(hits, vec![1]);

    let by_text = EventFilter {
        text: Some("save.dat".into()),
        ..Default::default()
    };
    let hits: Vec<usize> = view
        .events
        .iter()
        .filter(|e| by_text.matches(e))
        .map(|e| e.index)
        .collect();
    assert_eq!(hits, vec![0]);
}

#[test]
fn event_json_shape() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let rendered = view.events[1].to_json().render();
    assert!(
        rendered.contains("\"api\":\"kernel32!CreateFileW\""),
        "{rendered}"
    );
    assert!(rendered.contains("\"phase\":\"leave\""), "{rendered}");
    assert!(
        rendered.contains("\"return\":{\"ty\":\"U64\""),
        "{rendered}"
    );
    assert!(rendered.contains("\"value\":\"0x2a4\""), "{rendered}");
}

#[test]
fn stale_last_error_renders_as_stale_not_value() {
    // F20: 成功時の last_error 残留値は `<stale>` と表示し、生値を
    // 意味のあるエラー値のように見せない。
    use shirusu_analysis::{format_field, value_capture_name, FieldView};
    use shirusu_trace::schema::{ValueCapture, ValueKind};
    let f = FieldView {
        name: "last_error".into(),
        ty: Ty::U32,
        kind: ValueKind::Scalar,
        capture: ValueCapture::Stale,
        value: TypedValue::U32(5),
    };
    assert_eq!(format_field(&f), "last_error=<stale>");
    assert_eq!(value_capture_name(ValueCapture::Stale), "stale");
}

/// F22 用の Trace: Blob を参照する CreateFileW leave イベント 1 件。
/// 戻り値は (Trace バイト列, BlobId)。
fn blob_trace_bytes() -> (Vec<u8>, BlobId) {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "analysis-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    w.register_schema(make_schema(
        2,
        "kernel32!CreateFileW/leave",
        vec![
            ("return".into(), Ty::U64, 0),
            ("last_error".into(), Ty::U32, 0),
        ],
    ))
    .unwrap();
    let id = w.add_payload(b"file contents").unwrap();
    let args = encode_values(
        &[Ty::U64, Ty::U32],
        &[cv(TypedValue::U64(0x2a4)), cv(TypedValue::U32(0))],
    )
    .unwrap();
    let event = TraceEvent {
        kind: 2,
        sequence: 1,
        timestamp_qpc: 1010,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 2,
        capture: EventCapture::Captured,
        payload: shirusu_trace::PayloadRef::Blob(id),
        args: Some(args),
        global_order: None,
    };
    let batch = EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events: vec![event],
    };
    w.write_batch(&batch).unwrap();
    (w.finish(FinalizationInfo::default()).unwrap(), id)
}

/// Blob Chunk の本体 1 バイトを壊し、Block の CRC32C を再計算して
/// 整合させる。Blob ID と内容の BLAKE3 が一致しなくなるため、
/// Reader はその Blob を取り込まず MissingBlob として扱う。
fn corrupt_blob_body(bytes: &[u8]) -> Vec<u8> {
    let mut pos = 0usize;
    while pos + 32 <= bytes.len() {
        let raw = parse_raw_header(&bytes[pos..]).expect("valid header");
        if raw.block_type_code == BlockType::BlobChunk.code() {
            let header = BlockHeader {
                block_type: BlockType::BlobChunk,
                compression: Compression::from_code(raw.compression_code).unwrap(),
                sequence: raw.sequence,
                stored_len: raw.stored_len,
                raw_len: raw.raw_len,
            };
            let stored = &bytes[pos + 32..pos + 32 + raw.stored_len as usize];
            let mut payload = shirusu_trace::container::decode_payload(&header, stored).unwrap();
            payload[36] ^= 0xFF;
            let new_header = BlockHeader {
                block_type: BlockType::BlobChunk,
                compression: Compression::None,
                sequence: raw.sequence,
                stored_len: payload.len() as u32,
                raw_len: payload.len() as u32,
            };
            let mut out = bytes[..pos].to_vec();
            out.extend_from_slice(&serialize_header(&new_header, &payload));
            out.extend_from_slice(&payload);
            out.extend_from_slice(&bytes[pos + 32 + raw.stored_len as usize..]);
            return out;
        }
        pos += 32 + raw.stored_len as usize;
    }
    panic!("no blob chunk found");
}

#[test]
fn corrupt_blob_keeps_api_call_searchable() {
    // F22: Blob が壊れても、API 呼び出し自体は残り、名前・api_id の
    // どちらでも検索できる。Blob 内容の復元（リソース復元可能）とは別。
    let (bytes, id) = blob_trace_bytes();
    let corrupted = corrupt_blob_body(&bytes);
    let trace = shirusu_trace::read_trace(&corrupted).unwrap();
    assert!(
        trace.issues.iter().any(|i| matches!(
            i,
            RecoveryIssue::BlobHashMismatch { id: found, .. } if *found == id
        )),
        "issues: {:?}",
        trace.issues
    );
    let view = TraceView::build(&trace);
    assert_eq!(view.events.len(), 1);
    let ev = &view.events[0];
    assert_eq!(ev.api_name.as_deref(), Some("kernel32!CreateFileW"));
    // API 名での検索ができる。
    let by_name = EventFilter {
        api: Some("CreateFileW".into()),
        ..Default::default()
    };
    assert!(by_name.matches(ev));
    // api_id（数値）での検索もできる。
    let by_id = EventFilter {
        api: Some(ev.api_id.to_string()),
        ..Default::default()
    };
    assert!(by_id.matches(ev));
    // 欠落した Blob は解決時に明示され、イベント自体は残る。
    assert_eq!(
        trace.resolve_payload(&trace.batches[0].events[0]),
        PayloadResolution::MissingBlob(id)
    );
    assert!(ev.line().contains("kernel32!CreateFileW"), "{}", ev.line());
}
