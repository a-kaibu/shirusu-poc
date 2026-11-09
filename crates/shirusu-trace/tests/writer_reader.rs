//! Trace Writer → Reader の往復と Writer の不変条件テスト。

use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::container::BlockType;
use shirusu_trace::error::TraceError;
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, SessionMetadata};
use shirusu_trace::reader::read_trace as read_trace_via;
use shirusu_trace::reader::PayloadResolution;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::TraceWriter;
use std::sync::{Arc, Mutex};

fn env(session_id: u64) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by: "shirusu-host test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        os_build: 26100,
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        capture_config: "L2".into(),
        feature_flags: 3,
        target_description: "game.exe".into(),
    }
}

fn event(seq: u64, payload: PayloadRef) -> TraceEvent {
    TraceEvent {
        kind: 1,
        sequence: seq,
        timestamp_qpc: 1000 + seq * 10,
        call_id: seq,
        parent_call_id: 0,
        api_id: 77,
        schema_id: 0,
        capture: EventCapture::Captured,
        payload,
        args: None,
    }
}

fn batch(thread_id: u64, events: Vec<TraceEvent>) -> EventBatch {
    EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id,
        qpc_frequency: 10_000_000,
        events,
    }
}

/// 終了せずに中身を取り出すための共有バッファ Writer。
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl SharedBuf {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

#[test]
fn full_roundtrip() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let schema = make_schema(
        1,
        "kernel32!CreateFileW",
        vec![
            ("handle".into(), Ty::Ptr64, 0),
            ("flags".into(), Ty::U32, 0),
        ],
    );
    w.register_schema(schema).unwrap();
    let args = encode_values(
        &[Ty::Ptr64, Ty::U32],
        &[
            CapturedValue::captured(TypedValue::Ptr64(0x1234)),
            CapturedValue::captured(TypedValue::U32(7)),
        ],
    )
    .unwrap();
    let blob_a = w.add_payload(b"shared payload").unwrap();
    let blob_b = w.add_payload(b"unique payload").unwrap();
    let blob_a2 = w.add_payload(b"shared payload").unwrap();
    assert_eq!(blob_a, blob_a2, "重複排除で同じ ID");

    let mut e1 = event(1, PayloadRef::Blob(blob_a));
    e1.schema_id = 1;
    e1.args = Some(args.clone());
    let e2 = event(2, PayloadRef::Inline(vec![1, 2, 3]));
    let e3 = TraceEvent {
        capture: EventCapture::DroppedByBackpressure,
        payload: PayloadRef::Dropped {
            original_len: 8192,
            reason: PayloadLossReason::Backpressure,
        },
        ..event(3, PayloadRef::None)
    };
    w.write_batch(&batch(3, vec![e1, e2, e3])).unwrap();
    let e4 = event(1, PayloadRef::Blob(blob_b));
    w.write_batch(&batch(4, vec![e4])).unwrap();
    w.write_schema_checkpoint().unwrap();
    w.write_loss_records(&[LossRecord {
        kind: 1,
        count: 2,
        process_id: 7,
        thread_id: 3,
        ..Default::default()
    }])
    .unwrap();
    let bytes = w
        .finish(FinalizationInfo {
            capture_coverage: 1,
            event_integrity: 0,
            semantic_completeness: 3,
            notes: vec!["done".into()],
        })
        .unwrap();

    let trace = read_trace_via(&bytes).unwrap();
    assert_eq!(trace.header.session_id, 42);
    assert_eq!(trace.environment.as_ref().unwrap(), &env(42));
    assert_eq!(trace.schemas.len(), 1);
    assert_eq!(trace.registry.len(), 1);
    assert_eq!(trace.batches.len(), 2);
    assert_eq!(trace.batches[0].events.len(), 3);
    assert_eq!(trace.batches[0].events[0].payload, PayloadRef::Blob(blob_a));
    assert_eq!(
        trace.resolve_payload(&trace.batches[0].events[0]),
        PayloadResolution::Blob(b"shared payload")
    );
    assert_eq!(
        trace.resolve_payload(&trace.batches[0].events[1]),
        PayloadResolution::Inline(&[1, 2, 3])
    );
    assert_eq!(
        trace.resolve_payload(&trace.batches[0].events[2]),
        PayloadResolution::Dropped {
            original_len: 8192,
            reason: PayloadLossReason::Backpressure
        }
    );
    // 引数値列も Schema で復号できる
    let types = trace.registry.types(1).unwrap();
    let decoded_args = shirusu_trace::compact::decode_values(
        &types,
        trace.batches[0].events[0].args.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded_args[0].value, TypedValue::Ptr64(0x1234));
    assert_eq!(trace.loss_records.len(), 1);
    assert_eq!(trace.blobs.len(), 2);
    let fin = trace.finalization.as_ref().expect("finalization exists");
    assert_eq!(fin.total_events, 4);
    assert_eq!(fin.total_blobs, 2);
    assert_eq!(fin.total_loss_records, 1);
    assert_eq!(fin.capture_coverage, 1);
    assert_eq!(fin.semantic_completeness, 3);
    assert!(trace.finalized_cleanly);
    assert!(trace.stored_index.is_some());
    assert!(trace.index_matches_scan);
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn unfinalized_trace_is_readable() {
    let buf = SharedBuf::default();
    let mut w = TraceWriter::new(buf.clone(), env(42)).unwrap();
    let id = w.add_payload(b"data").unwrap();
    w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(id))]))
        .unwrap();
    let bytes = buf.bytes();
    drop(w); // finish せずに終わる（Host が落ちた状況）
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.finalization.is_none());
    assert!(!trace.finalized_cleanly);
    assert_eq!(trace.total_events(), 1);
    assert_eq!(trace.blobs.len(), 1);
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn unregistered_schema_reference_is_kept_not_rejected() {
    // schema_id は Agent が番号として渡すもので、定義の登録は別経路。
    // 定義が無い参照は欠落 Blob と同様、Reader 側で「引けない」ことが
    // 分かる形で保持する（Writer は拒否しない）。
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let mut e = event(1, PayloadRef::None);
    e.schema_id = 9;
    w.write_batch(&batch(3, vec![e])).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert_eq!(trace.batches[0].events[0].schema_id, 9);
    assert!(trace.registry.get(9).is_none());
    assert!(trace.issues.is_empty());
}

#[test]
fn writer_invariants_are_enforced() {
    // 未追加 Blob への参照
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let unknown = BlobId::from_bytes([9u8; 32]);
    assert!(matches!(
        w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(unknown))])),
        Err(TraceError::WriterInvariant(_))
    ));
    // 空バッチ
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    assert!(matches!(
        w.write_batch(&batch(3, vec![])),
        Err(TraceError::WriterInvariant(_))
    ));
    // セッション不一致
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let mut b = batch(3, vec![event(1, PayloadRef::None)]);
    b.session_id = 43;
    assert!(matches!(
        w.write_batch(&b),
        Err(TraceError::WriterInvariant(_))
    ));
    // バッチ内の sequence 後退
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    assert!(matches!(
        w.write_batch(&batch(
            3,
            vec![event(5, PayloadRef::None), event(4, PayloadRef::None)]
        )),
        Err(TraceError::WriterInvariant(_))
    ));
    // バッチをまたいだ sequence 後退（同一スレッド）
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    w.write_batch(&batch(3, vec![event(5, PayloadRef::None)]))
        .unwrap();
    assert!(matches!(
        w.write_batch(&batch(3, vec![event(4, PayloadRef::None)])),
        Err(TraceError::WriterInvariant(_))
    ));
    // 別スレッドなら同じ sequence でもよい
    w.write_batch(&batch(4, vec![event(4, PayloadRef::None)]))
        .unwrap();
}

#[test]
fn large_batch_is_split_into_multiple_chunks() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let events: Vec<TraceEvent> = (1..=3000u64)
        .map(|i| event(i, PayloadRef::Inline(vec![0xcd; 200])))
        .collect();
    w.write_batch(&batch(3, events)).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    let chunk_count = trace
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::EventChunk)
        .count();
    assert!(
        chunk_count >= 2,
        "3000 events x ~210B should split, got {chunk_count} chunk(s)"
    );
    assert_eq!(trace.total_events(), 3000);
    let flat: Vec<&TraceEvent> = trace.batches.iter().flat_map(|b| &b.events).collect();
    for (i, e) in flat.iter().enumerate() {
        assert_eq!(e.sequence, i as u64 + 1);
    }
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn blobs_are_written_before_referencing_chunk() {
    let buf = SharedBuf::default();
    let mut w = TraceWriter::new(buf.clone(), env(42)).unwrap();
    // 1 つ目のバッチは Payload 無し
    w.write_batch(&batch(3, vec![event(1, PayloadRef::None)]))
        .unwrap();
    // その後に Payload を追加し、2 つ目のバッチが参照する
    let id = w.add_payload(b"late payload").unwrap();
    w.write_batch(&batch(3, vec![event(2, PayloadRef::Blob(id))]))
        .unwrap();
    let bytes = buf.bytes();
    let trace = read_trace_via(&bytes).unwrap();
    let offsets: Vec<(u64, BlockType)> = trace
        .blocks
        .iter()
        .map(|b| (b.offset, b.block_type))
        .collect();
    let blob_pos = offsets
        .iter()
        .position(|(_, t)| *t == BlockType::BlobChunk)
        .expect("blob chunk exists");
    let event_positions: Vec<usize> = offsets
        .iter()
        .enumerate()
        .filter(|(_, (_, t))| *t == BlockType::EventChunk)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(event_positions.len(), 2);
    assert!(
        blob_pos > event_positions[0] && blob_pos < event_positions[1],
        "blob chunk must sit between the two event chunks: {offsets:?}"
    );
}

#[test]
fn repetitive_chunk_is_stored_compressed() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let events: Vec<TraceEvent> = (1..=500u64)
        .map(|i| event(i, PayloadRef::Inline(vec![0xee; 512])))
        .collect();
    w.write_batch(&batch(3, events)).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    // Event Chunk の Block ヘッダーを直接見て、圧縮格納を確認する
    let mut pos = 0usize;
    let mut found = false;
    while pos + 32 <= bytes.len() {
        let raw = shirusu_trace::container::parse_raw_header(&bytes[pos..]).unwrap();
        if raw.block_type_code == BlockType::EventChunk.code() {
            assert_eq!(raw.compression_code, 1, "repetitive chunk should be zstd");
            assert!(raw.stored_len < raw.raw_len);
            found = true;
        }
        pos += 32 + raw.stored_len as usize;
    }
    assert!(found);
    // 圧縮されていても全件読める
    let trace = read_trace_via(&bytes).unwrap();
    assert_eq!(trace.total_events(), 500);
}
