//! ビューの単体テスト。合成 Trace を Writer で作り、復号・整形・
//! 完全性サマリが期待どおりになることを確認する。

use shirusu_analysis::{EventFilter, IntegritySummary, TraceView};
use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::container::{
    parse_raw_header, serialize_header, BlockHeader, BlockType, Compression,
};
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, FieldDef, LossRecord, SchemaDef, SessionMetadata};
use shirusu_trace::reader::{PayloadResolution, ReadTrace, RecoveryIssue};
use shirusu_trace::schema::{
    make_schema, schema_content_hash, CapturedValue, EventCapture, Ty, TypedValue, ValueKind,
};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

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

/// 任意の kind / Payload / 取得状態 / 全体順序でイベントを積める
/// 合成 Trace ビルダ（sample_trace_bytes() では作れない形用）。
struct Flex {
    events: Vec<TraceEvent>,
    seq: u64,
    global_order: bool,
}

impl Flex {
    fn new(global_order: bool) -> Self {
        Flex {
            events: Vec::new(),
            seq: 0,
            global_order,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: u16,
        call: u64,
        api_id: u32,
        schema_id: u32,
        args: Option<Vec<u8>>,
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
            args,
            global_order: if self.global_order {
                Some(self.seq)
            } else {
                None
            },
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn push_typed(
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
        self.push(
            kind,
            call,
            api_id,
            schema_id,
            Some(encode_values(types, &values).unwrap()),
            payload,
            capture,
        );
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
                created_by: "view-coverage".into(),
                qpc_frequency: 10_000_000,
            },
            os_version: "Windows 11".into(),
            cpu_arch: "x86_64".into(),
            pointer_width: 64,
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
                raw_pid: 1234,
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

fn flex_schemas() -> Vec<SchemaDef> {
    vec![
        make_schema(301, "test!Ping/enter", vec![]),
        make_schema(
            302,
            "test!Ping/leave",
            vec![("return".into(), Ty::U32, ValueKind::Scalar.flags())],
        ),
        make_schema(
            303,
            "test!OneField/enter",
            vec![("only".into(), Ty::U32, 0)],
        ),
    ]
}

#[test]
fn line_and_json_cover_payload_global_order_and_unknown_schema() {
    let known = BlobId::of_content(b"flex-blob");
    let mut f = Flex::new(true);
    // enter: Inline Payload + 全体順序。
    f.push_typed(
        1,
        1,
        70,
        301,
        &[],
        vec![],
        PayloadRef::Inline(vec![1, 2]),
        EventCapture::Captured,
    );
    // leave: Blob Payload。
    f.push_typed(
        2,
        1,
        70,
        302,
        &[Ty::U32],
        vec![cv(TypedValue::U32(7))],
        PayloadRef::Blob(known),
        EventCapture::Captured,
    );
    // enter: Dropped Payload。
    f.push_typed(
        1,
        2,
        70,
        301,
        &[],
        vec![],
        PayloadRef::Dropped {
            original_len: 55,
            reason: PayloadLossReason::Overflow,
        },
        EventCapture::Captured,
    );
    f.push_typed(
        2,
        2,
        70,
        302,
        &[Ty::U32],
        vec![cv(TypedValue::U32(7))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    // 未登録スキーマの leave（api_name なし・args_error あり）。
    f.push_typed(
        2,
        3,
        70,
        999,
        &[Ty::U32],
        vec![cv(TypedValue::U32(7))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = f.finish(
        flex_schemas(),
        FinalizationInfo::default(),
        &[],
        &[b"flex-blob"],
    );
    let view = TraceView::build(&trace);
    assert_eq!(view.events.len(), 5);
    // 全体順序が line() に出る。
    assert!(
        view.events[0].line().contains("g=1"),
        "{}",
        view.events[0].line()
    );
    // Inline / Blob / Dropped の payload 要約。
    assert!(
        view.events[0].line().contains("payload=inline[2]"),
        "{}",
        view.events[0].line()
    );
    assert!(
        view.events[1]
            .line()
            .contains(&format!("payload=blob:{}", known.to_hex())),
        "{}",
        view.events[1].line()
    );
    assert!(
        view.events[2]
            .line()
            .contains("payload=dropped(len=55, reason=overflow)"),
        "{}",
        view.events[2].line()
    );
    // 未登録スキーマは api# 表示と args_error。
    let ev = &view.events[4];
    assert!(ev.api_name.is_none());
    assert!(
        ev.args_error.as_deref().unwrap().contains("not registered"),
        "{:?}",
        ev.args_error
    );
    assert!(ev.line().contains("api#70 kind=2"), "{}", ev.line());
    assert!(ev.line().contains("args_error="), "{}", ev.line());
    // to_json の payload 各種と全体順序。
    let j0 = view.events[0].to_json().render();
    assert!(j0.contains("\"kind\":\"inline\""), "{j0}");
    assert!(j0.contains("\"global_order\":1"), "{j0}");
    let j1 = view.events[1].to_json().render();
    assert!(j1.contains("\"kind\":\"blob\""), "{j1}");
    let j2 = view.events[2].to_json().render();
    assert!(j2.contains("\"kind\":\"dropped\""), "{j2}");
    assert!(j2.contains("\"reason\":\"overflow\""), "{j2}");
    // api_name が無い場合の to_json は null。
    let j4 = view.events[4].to_json().render();
    assert!(j4.contains("\"api\":null"), "{j4}");
    assert!(
        j4.contains("\"args_error\":\"schema 999 not registered\""),
        "{j4}"
    );
}

#[test]
fn filter_mismatches_return_false_on_each_field() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let ev = &view.events[0]; // api_id 1, kind 1, seq 1, thread 55
                              // 数値 api_id の不一致。
    assert!(!EventFilter {
        api: Some("9999".into()),
        ..Default::default()
    }
    .matches(ev));
    // 名前の不一致。
    assert!(!EventFilter {
        api: Some("NoSuchApi".into()),
        ..Default::default()
    }
    .matches(ev));
    // kind の不一致。
    assert!(!EventFilter {
        kind: Some(2),
        ..Default::default()
    }
    .matches(ev));
    // seq 範囲外。
    assert!(!EventFilter {
        seq_min: Some(2),
        ..Default::default()
    }
    .matches(ev));
    assert!(!EventFilter {
        seq_max: Some(0),
        ..Default::default()
    }
    .matches(ev));
    // thread の不一致。
    assert!(!EventFilter {
        thread_id: Some(56),
        ..Default::default()
    }
    .matches(ev));
    // text の不一致。
    assert!(!EventFilter {
        text: Some("no-such-text".into()),
        ..Default::default()
    }
    .matches(ev));
}

#[test]
fn decode_fields_reports_undecodable_args() {
    // 復号できない args バイト列（空バイト列に U32 1 件を要求）：
    // decode failed として args_error に残る。
    let mut f = Flex::new(false);
    f.push(
        1,
        1,
        70,
        303,
        Some(Vec::new()),
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = f.finish(flex_schemas(), FinalizationInfo::default(), &[], &[]);
    let view = TraceView::build(&trace);
    assert!(view.events[0].fields.is_empty());
    let err = view.events[0].args_error.as_deref().unwrap();
    assert!(err.contains("decode failed"), "{err}");
}

#[test]
fn api_stats_counts_only_enter_and_leave() {
    // Aborted / Completed / Other は Enter にも Leave にも数えない。
    let mut f = Flex::new(false);
    f.push_typed(
        1,
        1,
        70,
        301,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    f.push_typed(
        2,
        1,
        70,
        302,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    f.push(
        7,
        2,
        70,
        302,
        None,
        PayloadRef::None,
        EventCapture::Captured,
    );
    f.push_typed(
        8,
        3,
        70,
        302,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    f.push_typed(
        5,
        4,
        70,
        301,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = f.finish(flex_schemas(), FinalizationInfo::default(), &[], &[]);
    let view = TraceView::build(&trace);
    assert_eq!(view.api_stats(), vec![("test!Ping".to_string(), 1, 1)]);
    assert_eq!(view.thread_count(), 1);
    // 未登録スキーマのイベントは api#<id> で集計される。
    let mut f2 = Flex::new(false);
    f2.push_typed(
        1,
        1,
        70,
        999,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace2 = f2.finish(flex_schemas(), FinalizationInfo::default(), &[], &[]);
    let view2 = TraceView::build(&trace2);
    assert_eq!(view2.api_stats(), vec![("api#70".to_string(), 1, 0)]);
}

#[test]
fn integrity_summary_counts_losses_degraded_and_missing_blobs() {
    let unknown = BlobId::from_bytes([0xEE; 32]);
    let mut f = Flex::new(false);
    // Dropped Payload の enter。
    f.push_typed(
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
    // 取得状態が Captured でない leave（degraded）。
    f.push_typed(
        2,
        1,
        70,
        302,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Truncated,
    );
    // 欠落 Blob の参照先にするための平凡な enter。
    f.push_typed(
        1,
        2,
        70,
        301,
        &[],
        vec![],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let mut trace = f.finish(
        flex_schemas(),
        FinalizationInfo {
            event_integrity: 2,
            ..Default::default()
        },
        &[LossRecord {
            kind: 1,
            count: 3,
            ..Default::default()
        }],
        &[],
    );
    // Writer は未追加 Blob への参照を書けないため、読取後に差し替える。
    trace.batches[0].events[2].payload = PayloadRef::Blob(unknown);
    // 回復 issue は全バリアントを直接積む（Reader が出す形の再現）。
    let id = BlobId::of_content(b"issue-blob");
    trace.issues = vec![
        RecoveryIssue::TruncatedTail { offset: 10 },
        RecoveryIssue::CorruptBlock {
            offset: 20,
            reason: "crc".into(),
        },
        RecoveryIssue::Resync { from: 30, to: 40 },
        RecoveryIssue::DuplicateBlob { id },
        RecoveryIssue::BlobHashMismatch {
            id,
            computed: BlobId::of_content(b"other"),
        },
        RecoveryIssue::MissingBlob { id },
        RecoveryIssue::ForwardBlobReference { id },
        RecoveryIssue::IndexMismatch,
        RecoveryIssue::LimitExceeded { what: "blocks" },
        RecoveryIssue::SessionMismatch {
            what: "environment",
            expected: 42,
            found: 43,
        },
        RecoveryIssue::BlobUpdateMissingBase { resource_id: id },
        RecoveryIssue::BlobUpdateOutOfRange {
            resource_id: id,
            offset: 1,
            size: 2,
            base_len: 3,
        },
        RecoveryIssue::BlobUpdateHashMismatch {
            resource_id: id,
            expected: BlobId::of_content(b"expected"),
            computed: BlobId::of_content(b"computed"),
        },
    ];
    let s = IntegritySummary::of(&trace);
    assert_eq!(s.loss_records_by_kind.get(&1), Some(&1));
    assert_eq!(s.total_loss_count, 3);
    assert_eq!(s.dropped_payload_events, 1);
    assert_eq!(s.dropped_payload_bytes, 100);
    assert_eq!(s.degraded_events, 1);
    assert_eq!(s.missing_blob_refs, 1);
    assert!(s.has_event_loss());
    let issues = s.recovery_issues.join("\n");
    for expect in [
        "truncated_tail(offset=10)",
        "corrupt_block(offset=20, reason=crc)",
        "resync(30..40)",
        "index_mismatch",
        "limit_exceeded(blocks)",
        "session_mismatch(what=environment, expected=42, found=43)",
    ] {
        assert!(issues.contains(expect), "{issues}");
    }
    let hex = id.to_hex();
    for expect in [
        format!("duplicate_blob({hex})"),
        format!("blob_hash_mismatch(id={hex}, computed="),
        format!("missing_blob({hex})"),
        format!("forward_blob_reference({hex})"),
        format!("blob_update_missing_base(resource={hex})"),
        format!("blob_update_out_of_range(resource={hex}, offset=1, size=2, base_len=3)"),
        format!("blob_update_hash_mismatch(resource={hex}, expected="),
    ] {
        assert!(issues.contains(&expect), "{issues}");
    }
}

#[test]
fn has_event_loss_uses_each_disjunct() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let mut s = view.integrity.clone();
    // クリーンな Trace は損失なし。
    assert!(!s.has_event_loss());
    // event_integrity だけが非 Complete でも損失あり（596 行）。
    s.event_integrity = Some(1);
    assert!(s.has_event_loss());
    s.event_integrity = Some(0);
    assert!(!s.has_event_loss());
    s.event_integrity = None;
    assert!(!s.has_event_loss());
    // 他の内訳だけでも損失あり。
    s.dropped_payload_events = 1;
    assert!(s.has_event_loss());
    s.dropped_payload_events = 0;
    s.missing_blob_refs = 1;
    assert!(s.has_event_loss());
    s.missing_blob_refs = 0;
    s.loss_records_by_kind.insert(2, 1);
    assert!(s.has_event_loss());
}

#[test]
fn event_field_lookup_finds_by_name() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let first = &view.events[0];
    assert_eq!(first.field("lpFileName").unwrap().name, "lpFileName");
    assert!(first.field("no_such_field").is_none());
}

#[test]
fn decode_fields_reports_schema_with_unknown_types() {
    // 未知の型タグ（99）を持つスキーマ定義：正規化ハッシュは公開関数
    // で計算するため Writer の検証を通り、Reader 側で型一覧が引けない。
    let fields = vec![FieldDef {
        name: "x".into(),
        ty: 99,
        flags: 0,
    }];
    let def = SchemaDef {
        schema_id: 404,
        name: "test!Weird/enter".into(),
        content_hash: schema_content_hash("test!Weird/enter", &fields),
        fields,
        annotation: String::new(),
    };
    let mut f = Flex::new(false);
    f.push_typed(
        1,
        1,
        70,
        404,
        &[Ty::U32],
        vec![cv(TypedValue::U32(1))],
        PayloadRef::None,
        EventCapture::Captured,
    );
    let trace = f.finish(vec![def], FinalizationInfo::default(), &[], &[]);
    let view = TraceView::build(&trace);
    assert!(view.events[0].fields.is_empty());
    let err = view.events[0].args_error.as_deref().unwrap();
    assert!(err.contains("has unknown types"), "{err}");
}

#[test]
fn iid_identification_requires_captured_com_context_and_is_exported() {
    use shirusu_analysis::{EventView, FieldView, PayloadView};
    use shirusu_trace::schema::ValueCapture;
    let mut event = EventView {
        index: 0,
        session_id: 1,
        process_id: 1,
        raw_pid: 1,
        thread_id: 1,
        qpc_frequency: 1,
        kind: 1,
        sequence: 1,
        global_order: None,
        timestamp_qpc: 1,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1000,
        schema_id: 10001,
        api_name: Some("com!method".into()),
        schema_name: None,
        capture: EventCapture::Captured,
        args_error: None,
        payload: PayloadView::None,
        fields: vec![FieldView {
            name: "iid".into(),
            ty: Ty::Bytes,
            kind: ValueKind::Scalar,
            capture: ValueCapture::Captured,
            value: TypedValue::Bytes(vec![12, 0, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70]),
        }],
    };
    assert!(event
        .to_json()
        .render()
        .contains("Windows.Win32.System.Com.IStream"));
    assert!(event.line().contains("IStream"));
    event.fields[0].capture = ValueCapture::Unreadable;
    assert!(event.com_interface_names().is_none());
    event.fields[0].capture = ValueCapture::Captured;
    event.api_name = Some("application!not-com".into());
    assert!(event.com_interface_names().is_none());
}

/// P1-4: ストリーミング集計は全体読み込みと同じ完全性の要約と件数を出す。
#[test]
fn streamed_summary_matches_full_read() {
    let (blob_bytes, _) = blob_trace_bytes();
    let corrupt = corrupt_blob_body(&blob_bytes);
    let mut cut = sample_trace_bytes();
    cut.truncate(cut.len() - 7);
    for bytes in [sample_trace_bytes(), blob_bytes.clone(), corrupt, cut] {
        let full = shirusu_trace::read_trace(&bytes).unwrap();
        let view = TraceView::build(&full);
        let mut seen = 0u64;
        let streamed =
            shirusu_analysis::stream_trace(std::io::Cursor::new(&bytes), |_, _, _| seen += 1)
                .unwrap();
        assert_eq!(streamed.integrity, view.integrity);
        assert_eq!(streamed.total_events, full.total_events());
        assert_eq!(seen, full.total_events());
        assert_eq!(streamed.batch_count, full.batches.len() as u64);
        assert_eq!(streamed.blob_count, full.blobs.len() as u64);
        assert_eq!(
            streamed.blob_bytes,
            full.blobs.values().map(|b| b.len() as u64).sum::<u64>()
        );
        assert_eq!(streamed.meta.schemas.len(), full.schemas.len());
        assert_eq!(streamed.meta.finalization, full.finalization);
        assert!(streamed.meta.batches.is_empty());
    }
}

#[test]
fn seq_bounds_are_inclusive_and_index_mismatch_alone_is_not_loss() {
    let bytes = sample_trace_bytes();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let view = TraceView::build(&trace);
    let target = &view.events[2];
    let exact = EventFilter {
        seq_min: Some(target.sequence),
        seq_max: Some(target.sequence),
        ..Default::default()
    };
    let hits: Vec<usize> = view
        .events
        .iter()
        .filter(|e| exact.matches(e))
        .map(|e| e.index)
        .collect();
    assert_eq!(hits, vec![2]);

    let mut s = view.integrity.clone();
    s.recovery_issues = vec!["index_mismatch".into()];
    assert!(!s.has_event_loss(), "a stale index loses no events");
    s.recovery_issues.push("truncated_tail".into());
    assert!(s.has_event_loss());
}

#[test]
fn thread_count_counts_distinct_threads() {
    let bytes = sample_trace_bytes();
    let mut trace = shirusu_trace::read_trace(&bytes).unwrap();
    let mut other = trace.batches[0].clone();
    other.thread_id += 1;
    trace.batches.push(other.clone());
    trace.batches.push(other);
    let view = TraceView::build(&trace);
    assert_eq!(view.thread_count(), 2);
}

#[test]
fn hex_prefix_marks_only_real_truncation() {
    use shirusu_analysis::view::hex_prefix;
    assert_eq!(hex_prefix(&[1, 2, 3], 3), "010203");
    assert_eq!(hex_prefix(&[1, 2, 3], 2), "0102..");
    assert_eq!(hex_prefix(&[], 0), "");
}

#[test]
fn json_compact_and_pretty_layouts_are_fixed() {
    use shirusu_analysis::JsonValue as J;
    let v = J::obj(vec![
        ("a", J::Array(vec![J::U64(1), J::I64(-2), J::Null])),
        ("b", J::Array(vec![])),
        ("c", J::Object(vec![])),
        (
            "d",
            J::obj(vec![("x", J::Bool(true)), ("y", J::Str("q\"".into()))]),
        ),
    ]);
    assert_eq!(
        v.render(),
        r#"{"a":[1,-2,null],"b":[],"c":{},"d":{"x":true,"y":"q\""}}"#
    );
    assert_eq!(
        v.render_pretty(),
        "{\n  \"a\": [\n    1,\n    -2,\n    null\n  ],\n  \"b\": [],\n  \"c\": {},\n  \"d\": {\n    \"x\": true,\n    \"y\": \"q\\\"\"\n  }\n}"
    );
    assert_eq!(
        J::Array(vec![J::Array(vec![J::U64(7)])]).render_pretty(),
        "[\n  [\n    7\n  ]\n]"
    );
}
