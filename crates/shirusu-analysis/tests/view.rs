//! ビューの単体テスト。合成 Trace を Writer で作り、復号・整形・
//! 完全性サマリが期待どおりになることを確認する。

use shirusu_analysis::{EventFilter, TraceView};
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
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
