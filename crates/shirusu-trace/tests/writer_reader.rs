//! Trace Writer → Reader の往復と Writer の不変条件テスト。

use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::{decode_values, encode_values};
use shirusu_trace::container::{parse_raw_header, BlockType};
use shirusu_trace::error::TraceError;
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, SessionMetadata};
use shirusu_trace::reader::read_trace as read_trace_via;
use shirusu_trace::reader::{PayloadResolution, RecoveryIssue};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::{DurableWrite, FinalizationInfo, WriterOptions};
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
        modules: Vec::new(),
        static_dependencies: Vec::new(),
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
        global_order: None,
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
impl DurableWrite for SharedBuf {
    fn sync_all(&mut self) -> std::io::Result<()> {
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
fn writer_rejects_single_payload_above_raw_limit() {
    // レビュー #4 の #6: 1 Blob のエントリ (ID 32 + 長さ 4 + 本体) が
    // Reader の上限 MAX_RAW_LEN を超える Payload は、Writer が明示的
    // に拒否する。黙って書くと Reader が読めない Trace ができる。
    let limit = shirusu_trace::container::MAX_RAW_LEN as usize;
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let too_big = vec![0u8; limit - 36 + 1];
    let err = w.add_payload(&too_big).unwrap_err();
    assert!(
        format!("{err}").contains("raw limit"),
        "error must name the raw limit: {err}"
    );
}

#[test]
fn writer_reader_roundtrip_at_raw_limit_boundary() {
    // 境界値: エントリ全体がちょうど MAX_RAW_LEN に収まる Blob は
    // 書けて、同じバージョンの Reader が読み戻せる (Writer/Reader 契約)。
    let limit = shirusu_trace::container::MAX_RAW_LEN as usize;
    let data = vec![0u8; limit - 36];
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let id = w.add_payload(&data).unwrap();
    w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(id))]))
        .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert_eq!(trace.blobs.get(&id).map(|b| b.len()), Some(limit - 36));
    assert!(
        trace.issues.is_empty(),
        "boundary trace must read cleanly: {:?}",
        trace.issues
    );
    let ev = &trace.batches[0].events[0];
    assert!(matches!(
        trace.resolve_payload(ev),
        PayloadResolution::Blob(b) if b.len() == limit - 36
    ));
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

/// F22 用の最小 Trace: Schema 1 件（kernel32!CreateFileW）と
/// その Schema を使う args 付きイベント 1 件。戻り値は
/// (Trace バイト列, イベントの args バイト列)。
fn schema_trace_bytes() -> (Vec<u8>, Vec<u8>) {
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
    let mut e = event(1, PayloadRef::None);
    e.schema_id = 1;
    e.args = Some(args.clone());
    w.write_batch(&batch(3, vec![e])).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    (bytes, args)
}

/// Trace の Block 位置一覧 (offset, type, stored_len)。
fn block_layout(data: &[u8]) -> Vec<(usize, BlockType, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 32 <= data.len() {
        let raw = parse_raw_header(&data[pos..]).expect("valid header");
        out.push((
            pos,
            BlockType::from_code(raw.block_type_code),
            raw.stored_len as usize,
        ));
        pos += 32 + raw.stored_len as usize;
    }
    out
}

/// 指定 Block の payload 先頭 1 バイトを壊す。CRC は直さないため
/// その Block は CRC 不一致で隔離される。
fn corrupt_block_payload(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset + 32] ^= 0xFF;
    out
}

#[test]
fn schema_checkpoint_twins_schema_block() {
    // F22: Writer は Schema Block を書くたびに、直後に同じ定義集合の
    // 複製を Schema Checkpoint Block として書く。手動の
    // write_schema_checkpoint() は呼ばない。
    let (bytes, _) = schema_trace_bytes();
    let trace = read_trace_via(&bytes).unwrap();
    let types: Vec<BlockType> = trace.blocks.iter().map(|b| b.block_type).collect();
    let schema_pos = types
        .iter()
        .position(|t| *t == BlockType::Schema)
        .expect("schema block exists");
    assert_eq!(
        types[schema_pos + 1],
        BlockType::SchemaCheckpoint,
        "checkpoint must directly follow the schema block: {types:?}"
    );
    // 複製はレジストリの重複登録にならない。
    assert_eq!(trace.schemas.len(), 1);
    assert_eq!(trace.registry.len(), 1);
    assert!(trace.registry.get(1).is_some());
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn corrupt_schema_block_is_covered_by_checkpoint() {
    // F22: Schema Block が 1 個壊れても、直後の Checkpoint の複製から
    // Schema が復旧し、型付き解釈ができる。
    let (bytes, args) = schema_trace_bytes();
    let layout = block_layout(&bytes);
    let (schema_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Schema)
        .copied()
        .unwrap();
    let corrupted = corrupt_block_payload(&bytes, schema_off);
    let trace = read_trace_via(&corrupted).unwrap();
    assert!(
        trace.issues.iter().any(|i| matches!(
            i,
            RecoveryIssue::CorruptBlock { offset, .. } if *offset == schema_off as u64
        )),
        "issues: {:?}",
        trace.issues
    );
    assert!(
        trace.registry.get(1).is_some(),
        "schema must survive via the checkpoint"
    );
    let types = trace.registry.types(1).unwrap();
    let decoded = decode_values(&types, &args).unwrap();
    assert_eq!(decoded[0].value, TypedValue::Ptr64(0x1234));
    assert_eq!(decoded[1].value, TypedValue::U32(7));
    assert_eq!(trace.total_events(), 1);
}

#[test]
fn corrupt_schema_and_checkpoint_loses_typed_args_but_keeps_events() {
    // F22 の境界: Schema Block とその Checkpoint の両方が壊れると
    // 型付き解釈はできないが、イベント列の構造復号は残る。
    // args の生バイト列もイベントに残る（再取得の余地を残す）。
    let (bytes, args) = schema_trace_bytes();
    let layout = block_layout(&bytes);
    let mut corrupted = bytes.clone();
    for (off, t, _) in &layout {
        if *t == BlockType::Schema || *t == BlockType::SchemaCheckpoint {
            corrupted = corrupt_block_payload(&corrupted, *off);
        }
    }
    let trace = read_trace_via(&corrupted).unwrap();
    assert!(trace.registry.get(1).is_none(), "no schema copy survives");
    assert_eq!(trace.total_events(), 1);
    let ev = &trace.batches[0].events[0];
    assert_eq!(ev.schema_id, 1);
    assert_eq!(ev.args.as_deref(), Some(args.as_slice()));
}

// ---- F18: Blob の部分的な更新 ----

/// 基底 Blob＋更新 1 件＋更新版を参照するイベントの往復。
/// Reader は更新を畳み込んで新版の内容を復元し、Payload 解決できる。
#[test]
fn blob_update_roundtrip_resolves_derived_version() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let base = b"0123456789abcdef";
    let base_id = w.add_payload(base).unwrap();
    let folded = b"01234XXXXXabcdef".to_vec();
    let new_version = BlobId::of_content(&folded);
    w.write_blob_update(base_id, new_version, 5, b"XXXXX")
        .unwrap();
    // 更新版を参照するイベント（Writer は更新の書出し時に新版 ID を
    // 既知として登録するため validate_batch が通る）
    w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(new_version))]))
        .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.blob_updates.len(), 1);
    assert_eq!(trace.blob_updates[0].resource_id, base_id);
    assert_eq!(trace.blob_updates[0].new_version_id, new_version);
    assert_eq!(trace.blob_updates[0].offset, 5);
    assert_eq!(trace.blob_updates[0].data, b"XXXXX");
    assert_eq!(trace.resource_versions.get(&base_id), Some(&new_version));
    // 派生版は blobs へ具体化され、Payload 解決と総数照合が通る
    assert_eq!(
        trace.blobs.get(&new_version).map(Vec::as_slice),
        Some(folded.as_slice())
    );
    let ev = &trace.batches[0].events[0];
    assert!(matches!(
        trace.resolve_payload(ev),
        PayloadResolution::Blob(b) if b == folded.as_slice()
    ));
    let fin = trace.finalization.as_ref().unwrap();
    assert_eq!(
        fin.total_blobs as usize,
        trace.blobs.len(),
        "stored + derived versions are all counted"
    );
    // （更新記録と全体保存の同一性は new_version の定義そのもの:
    // 呼び出し側が更新後の全体内容から BlobId::of_content で求めた
    // ID と、Reader の畳み込み結果のハッシュが一致すること）
    assert_eq!(BlobId::of_content(&folded), new_version);
}

#[test]
fn blob_update_chained_later_wins_on_overlap() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let base = b"aaaaaaaaaaaaaaaa";
    let base_id = w.add_payload(base).unwrap();
    // 1 件目: 先頭 8 バイトを 'b' に置き換え（残り 8 バイトは 'a' のまま）
    let v1 = b"bbbbbbbbaaaaaaaa".to_vec();
    let v1_id = BlobId::of_content(&v1);
    w.write_blob_update(base_id, v1_id, 0, b"bbbbbbbb").unwrap();
    // 2 件目: 8 バイト目からの 4 バイトを 'C' に置き換える
    // （1 件目の版に重なる範囲をさらに書き換える）
    let v2 = b"bbbbbbbbCCCCaaaa".to_vec();
    let v2_id = BlobId::of_content(&v2);
    w.write_blob_update(base_id, v2_id, 8, b"CCCC").unwrap();
    w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(v2_id))]))
        .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.blob_updates.len(), 2);
    assert_eq!(trace.resource_versions.get(&base_id), Some(&v2_id));
    assert_eq!(
        trace.blobs.get(&v2_id).map(Vec::as_slice),
        Some(v2.as_slice())
    );
    // 中間版も具体化されている（参照可能）
    assert_eq!(
        trace.blobs.get(&v1_id).map(Vec::as_slice),
        Some(v1.as_slice())
    );
}

#[test]
fn blob_update_writer_rejects_unknown_resource_and_out_of_range() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let base_id = w.add_payload(b"0123456789abcdef").unwrap();
    let unknown = BlobId::of_content(b"no such resource");
    let any_version = BlobId::of_content(b"whatever version");
    assert!(
        w.write_blob_update(unknown, any_version, 0, b"X").is_err(),
        "unknown resource must be rejected"
    );
    // 範囲外（offset + size > base_len）
    assert!(
        w.write_blob_update(base_id, any_version, 15, b"XY")
            .is_err(),
        "out-of-range update must be rejected"
    );
    // offset == base_len の空更新は許容（無変更）
    let same_version = base_id;
    w.write_blob_update(base_id, same_version, 16, b"").unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.resource_versions.get(&base_id), Some(&base_id));
}

/// F25: `chunk_raw_target` が Event Chunk の分割に反映される。
/// 同じ 3000 イベント（約 630 KiB）を 64 KiB / 256 KiB / 1 MiB で書くと
/// チャンク数が単調に減る。
fn write_with_chunk_target(target: usize) -> usize {
    let mut w = TraceWriter::with_options(
        Vec::new(),
        env(42),
        WriterOptions {
            chunk_raw_target: target,
            ..Default::default()
        },
    )
    .unwrap();
    let events: Vec<TraceEvent> = (1..=3000u64)
        .map(|i| event(i, PayloadRef::Inline(vec![0xcd; 200])))
        .collect();
    w.write_batch(&batch(3, events)).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.total_events(), 3000);
    trace
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::EventChunk)
        .count()
}

#[test]
fn chunk_raw_target_is_honored() {
    let small = write_with_chunk_target(64 * 1024);
    let def = write_with_chunk_target(256 * 1024);
    let large = write_with_chunk_target(1024 * 1024);
    assert!(
        small > def,
        "64 KiB should split more than 256 KiB: {small} vs {def}"
    );
    assert!(
        def > large,
        "256 KiB should split more than 1 MiB: {def} vs {large}"
    );
}

/// F25: `chunk_raw_target = 0` は既定値（512 KiB）と等価。
#[test]
fn chunk_raw_target_zero_means_default() {
    assert_eq!(
        write_with_chunk_target(0),
        write_with_chunk_target(512 * 1024),
        "0 must behave as the default chunk target"
    );
}

/// F25: 既定の `chunk_raw_target` は 512 KiB（ベンチ測定で決定）。
#[test]
fn chunk_raw_target_default_is_512kib() {
    let w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    assert_eq!(w.chunk_raw_target(), 512 * 1024);
    let w = TraceWriter::with_options(
        Vec::new(),
        env(42),
        WriterOptions {
            chunk_raw_target: 512 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(w.chunk_raw_target(), 512 * 1024);
    let _ = w.finish(FinalizationInfo::default()).unwrap();
}

/// L09: ProfileSummary Block の書き込みと読み戻し。Finalization の
/// 前に書かれ、Reader が `profile_summary` として保持する。
#[test]
fn profile_summary_block_roundtrip() {
    use shirusu_trace::proto::{ApiProfile, ProfileSummary};
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let summary = ProfileSummary {
        qpc_frequency: 10_000_000,
        total_events_seen: 6,
        apis: vec![ApiProfile {
            api_id: 1,
            calls: 2,
            enters: 3,
            leaves: 2,
            total_duration_qpc: 500,
            min_duration_qpc: 100,
            max_duration_qpc: 400,
        }],
    };
    w.write_profile_summary(&summary).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.profile_summary, Some(summary));
    // イベントが無い Trace でも Finalization は書かれる。
    assert_eq!(trace.finalization.as_ref().unwrap().total_events, 0);
}

/// L09: ProfileSummary が無い旧来の Trace では `profile_summary` は
/// None のまま（後方互換）。
#[test]
fn profile_summary_absent_without_block() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    w.write_batch(&batch(3, vec![event(1, PayloadRef::None)]))
        .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace_via(&bytes).unwrap();
    assert!(trace.profile_summary.is_none());
}
