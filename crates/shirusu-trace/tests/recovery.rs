//! 回復意味論（recover_trace）のケーステスト。
//! docs/trace-format.md「回復意味論」の表の各行に対応する。

use shirusu_trace::blob::BlobId;
use shirusu_trace::container::{
    parse_raw_header, serialize_header, BlockHeader, BlockType, Compression,
};
use shirusu_trace::error::TraceError;
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::{
    read_trace_with_limits, PayloadResolution, ReaderLimits, RecoveryIssue,
};
use shirusu_trace::schema::EventCapture;
use shirusu_trace::{read_trace, TraceWriter};

fn env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "recovery-test".into(),
            qpc_frequency: 10_000_000,
        },
        cpu_arch: "x86_64".into(),
        ..Default::default()
    }
}

fn event(seq: u64, payload: PayloadRef) -> TraceEvent {
    TraceEvent {
        kind: 1,
        sequence: seq,
        timestamp_qpc: 1000 + seq,
        call_id: seq,
        parent_call_id: 0,
        api_id: 1,
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
        raw_pid: 100,
        thread_id,
        qpc_frequency: 10_000_000,
        events,
    }
}

/// Blob 1 件＋バッチ 2 件＋Finalization の標準 Trace。
/// 戻り値: (バイト列, BlobId)
fn base_trace() -> (Vec<u8>, BlobId) {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let id = w.add_payload(b"important payload").unwrap();
    w.write_batch(&batch(
        3,
        vec![event(1, PayloadRef::Blob(id)), event(2, PayloadRef::None)],
    ))
    .unwrap();
    w.write_batch(&batch(4, vec![event(1, PayloadRef::Inline(vec![5]))]))
        .unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    (bytes, id)
}

/// 有効な Trace の Block 位置一覧 (offset, type, stored_len)。
fn block_layout(data: &[u8]) -> Vec<(usize, BlockType, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 32 <= data.len() {
        let raw = parse_raw_header(&data[pos..]).expect("valid header in base trace");
        out.push((
            pos,
            BlockType::from_code(raw.block_type_code),
            raw.stored_len as usize,
        ));
        pos += 32 + raw.stored_len as usize;
    }
    out
}

fn has_corrupt_at(trace: &shirusu_trace::ReadTrace, offset: u64) -> bool {
    trace
        .issues
        .iter()
        .any(|i| matches!(i, RecoveryIssue::CorruptBlock { offset: o, .. } if *o == offset))
}

#[test]
fn not_a_trace_inputs() {
    assert!(matches!(read_trace(&[]), Err(TraceError::NotATrace)));
    assert!(matches!(
        read_trace(b"hello world, not a trace"),
        Err(TraceError::NotATrace)
    ));
    assert!(matches!(
        read_trace(&vec![0u8; 4096]),
        Err(TraceError::NotATrace)
    ));
    // SBLK で始まるが File Magic が違う
    let payload = [0u8; 24];
    let header = BlockHeader {
        block_type: BlockType::Header,
        compression: Compression::None,
        sequence: 0,
        stored_len: 24,
        raw_len: 24,
    };
    let mut fake = serialize_header(&header, &payload).to_vec();
    fake.extend_from_slice(&payload);
    assert!(matches!(read_trace(&fake), Err(TraceError::NotATrace)));
    // 先頭が Header Block でない（Environment から始まる）
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let env_start = layout[1].0;
    assert!(matches!(
        read_trace(&bytes[env_start..]),
        Err(TraceError::NotATrace)
    ));
}

#[test]
fn truncated_tail_mid_payload_and_mid_header() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (fin_off, _, fin_len) = *layout.last().unwrap();
    // Finalization の payload 途中で切断
    let cut = &bytes[..fin_off + 32 + fin_len / 2];
    let trace = read_trace(cut).unwrap();
    assert!(trace.finalization.is_none());
    assert_eq!(trace.total_events(), 3);
    assert!(trace.issues.contains(&RecoveryIssue::TruncatedTail {
        offset: fin_off as u64
    }));
    // Finalization のヘッダー途中で切断
    let cut = &bytes[..fin_off + 10];
    let trace = read_trace(cut).unwrap();
    assert!(trace.finalization.is_none());
    assert!(trace.issues.contains(&RecoveryIssue::TruncatedTail {
        offset: fin_off as u64
    }));
    // Block 境界ちょうどで切断した場合は issue 無し（単に未完）
    let cut = &bytes[..fin_off];
    let trace = read_trace(cut).unwrap();
    assert!(trace.finalization.is_none());
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn crc_corruption_isolates_one_block_and_resyncs() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (chunk_off, _, chunk_len) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::EventChunk)
        .copied()
        .unwrap();
    let mut broken = bytes.clone();
    broken[chunk_off + 32 + chunk_len / 2] ^= 0xff; // payload を壊す（CRC 不一致）
    let trace = read_trace(&broken).unwrap();
    assert!(
        has_corrupt_at(&trace, chunk_off as u64),
        "issues: {:?}",
        trace.issues
    );
    assert!(trace
        .issues
        .iter()
        .any(|i| matches!(i, RecoveryIssue::Resync { from, .. } if *from == chunk_off as u64)));
    // 壊れたバッチは落ち、もう一方のバッチと Finalization は残る
    assert_eq!(trace.batches.len(), 1);
    assert_eq!(trace.batches[0].thread_id, 4);
    assert!(trace.finalization.is_some());
    // Blob Chunk は無事なので Blob は残るが、参照イベントが消えたため
    // MissingBlob にはならない
    assert_eq!(trace.blobs.len(), 1);
}

#[test]
fn garbage_between_blocks_is_resynced() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (chunk2_off, _, _) = layout
        .iter()
        .filter(|(_, t, _)| *t == BlockType::EventChunk)
        .nth(1)
        .copied()
        .unwrap();
    let mut spliced = bytes[..chunk2_off].to_vec();
    spliced.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03]);
    spliced.extend_from_slice(&bytes[chunk2_off..]);
    let trace = read_trace(&spliced).unwrap();
    assert!(trace.issues.iter().any(|i| matches!(
        i,
        RecoveryIssue::Resync { from, to } if *from == chunk2_off as u64 && *to == chunk2_off as u64 + 7
    )));
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn absurd_stored_len_is_corruption_not_panic() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (chunk_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::EventChunk)
        .copied()
        .unwrap();
    let mut broken = bytes.clone();
    // stored_len を上限超過の値に書き換える
    broken[chunk_off + 16..chunk_off + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    let trace = read_trace(&broken).unwrap();
    assert!(has_corrupt_at(&trace, chunk_off as u64));
    // 後続バッチは再同期で回収される
    assert!(trace.batches.iter().any(|b| b.thread_id == 4));
}

#[test]
fn zstd_garbage_with_valid_crc_is_isolated() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (index_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Index)
        .copied()
        .unwrap();
    let garbage = b"this is not a zstd frame at all";
    let header = BlockHeader {
        block_type: BlockType::EventChunk,
        compression: Compression::Zstd,
        sequence: 999,
        stored_len: garbage.len() as u32,
        raw_len: garbage.len() as u32,
    };
    let mut forged = bytes[..index_off].to_vec();
    forged.extend_from_slice(&serialize_header(&header, garbage));
    forged.extend_from_slice(garbage);
    forged.extend_from_slice(&bytes[index_off..]);
    let trace = read_trace(&forged).unwrap();
    assert!(
        has_corrupt_at(&trace, index_off as u64),
        "issues: {:?}",
        trace.issues
    );
    assert_eq!(trace.total_events(), 3);
    assert!(trace.finalization.is_some());
}

#[test]
fn unknown_block_type_is_skipped() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (index_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Index)
        .copied()
        .unwrap();
    let payload = b"future block content";
    let header = BlockHeader {
        block_type: BlockType::Unknown(200),
        compression: Compression::None,
        sequence: 998,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut extended = bytes[..index_off].to_vec();
    extended.extend_from_slice(&serialize_header(&header, payload));
    extended.extend_from_slice(payload);
    extended.extend_from_slice(&bytes[index_off..]);
    let trace = read_trace(&extended).unwrap();
    assert!(
        !has_corrupt_at(&trace, index_off as u64),
        "unknown block must not be corruption: {:?}",
        trace.issues
    );
    assert_eq!(trace.total_events(), 3);
    assert!(trace
        .blocks
        .iter()
        .any(|b| b.block_type == BlockType::Unknown(200)));
}

#[test]
fn duplicate_blob_id_is_reported_first_wins() {
    let (bytes, id) = base_trace();
    let layout = block_layout(&bytes);
    let (index_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Index)
        .copied()
        .unwrap();
    // 同じ Blob ID で異なる内容の Blob Chunk を捏造して挿入
    let forged_body = b"forged content";
    let mut payload = Vec::new();
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(&(forged_body.len() as u32).to_le_bytes());
    payload.extend_from_slice(forged_body);
    let header = BlockHeader {
        block_type: BlockType::BlobChunk,
        compression: Compression::None,
        sequence: 997,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut extended = bytes[..index_off].to_vec();
    extended.extend_from_slice(&serialize_header(&header, &payload));
    extended.extend_from_slice(&payload);
    extended.extend_from_slice(&bytes[index_off..]);
    let trace = read_trace(&extended).unwrap();
    assert!(trace.issues.contains(&RecoveryIssue::DuplicateBlob { id }));
    // 先に現れた内容が正
    assert_eq!(trace.blobs[&id], b"important payload");
}

#[test]
fn blob_with_mismatched_hash_is_rejected_even_with_valid_crc() {
    // レビュー #4 の #5: Blob の内容だけを書き換え、Block の CRC32C を
    // 再計算して整合させた入力。CRC は通るが、内容の BLAKE3 が ID と
    // 一致しないため、Reader はその Blob を取り込んではいけない。
    let (bytes, id) = base_trace();
    let layout = block_layout(&bytes);
    let (blob_off, _, blob_len) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::BlobChunk)
        .copied()
        .unwrap();
    let raw_header = parse_raw_header(&bytes[blob_off..]).unwrap();
    let header = BlockHeader {
        block_type: BlockType::BlobChunk,
        compression: Compression::from_code(raw_header.compression_code).unwrap(),
        sequence: raw_header.sequence,
        stored_len: raw_header.stored_len,
        raw_len: raw_header.raw_len,
    };
    let stored = &bytes[blob_off + 32..blob_off + 32 + blob_len];
    let mut payload = shirusu_trace::container::decode_payload(&header, stored).unwrap();
    // Blob エントリ: [ID 32][len 4][body]。body の 1 バイトだけ変える。
    assert_eq!(&payload[..32], id.as_bytes());
    payload[36] ^= 0xFF;
    let tampered_body: Vec<u8> = payload[36..].to_vec();
    let computed = BlobId::of_content(&tampered_body);
    assert_ne!(computed, id);
    // CRC は serialize_header が新しい payload で再計算する (整合する)。
    let new_header = BlockHeader {
        block_type: BlockType::BlobChunk,
        compression: Compression::None,
        sequence: raw_header.sequence,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut replaced = bytes[..blob_off].to_vec();
    replaced.extend_from_slice(&serialize_header(&new_header, &payload));
    replaced.extend_from_slice(&payload);
    replaced.extend_from_slice(&bytes[blob_off + 32 + blob_len..]);
    let trace = read_trace(&replaced).unwrap();
    assert!(
        trace
            .issues
            .contains(&RecoveryIssue::BlobHashMismatch { id, computed }),
        "issues: {:?}",
        trace.issues
    );
    // 取り込まれず、参照は欠落として明示される。他の内容は無事。
    assert!(!trace.blobs.contains_key(&id));
    let ev = &trace.batches[0].events[0];
    assert_eq!(
        trace.resolve_payload(ev),
        PayloadResolution::MissingBlob(id)
    );
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn missing_blob_is_explicit() {
    let (bytes, id) = base_trace();
    let layout = block_layout(&bytes);
    let (blob_off, _, blob_len) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::BlobChunk)
        .copied()
        .unwrap();
    // Blob Chunk を丸ごと取り除く
    let mut stripped = bytes[..blob_off].to_vec();
    stripped.extend_from_slice(&bytes[blob_off + 32 + blob_len..]);
    let trace = read_trace(&stripped).unwrap();
    // イベント自体は残り、欠落が明示される
    assert_eq!(trace.total_events(), 3);
    assert!(trace.issues.contains(&RecoveryIssue::MissingBlob { id }));
    let ev = &trace.batches[0].events[0];
    assert_eq!(
        trace.resolve_payload(ev),
        PayloadResolution::MissingBlob(id)
    );
}

#[test]
fn corrupt_environment_proto_is_isolated() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (env_off, _, _) = layout[1];
    // Environment Block を「CRC は正しいが Protobuf として壊れた」内容で置換
    let garbage = [0xff, 0xff, 0xff, 0xff];
    let header = BlockHeader {
        block_type: BlockType::Environment,
        compression: Compression::None,
        sequence: 1,
        stored_len: garbage.len() as u32,
        raw_len: garbage.len() as u32,
    };
    let mut replaced = bytes[..env_off].to_vec();
    replaced.extend_from_slice(&serialize_header(&header, &garbage));
    replaced.extend_from_slice(&garbage);
    let after_env = env_off + 32 + layout[1].2;
    replaced.extend_from_slice(&bytes[after_env..]);
    let trace = read_trace(&replaced).unwrap();
    assert!(trace.environment.is_none());
    assert!(has_corrupt_at(&trace, env_off as u64));
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn wrong_index_is_ignored() {
    let (bytes, _) = base_trace();
    // 末尾に「嘘の Index Block」を追加する（既存 Index が正でも、
    // 後から現れた Index が走査と一致しなければ無視される）
    let bogus = shirusu_trace::proto::BlockIndex {
        entries: vec![shirusu_trace::proto::IndexEntry {
            offset: 12345,
            block_type: 4,
            sequence: 0,
        }],
    };
    let payload = bogus.encode();
    let header = BlockHeader {
        block_type: BlockType::Index,
        compression: Compression::None,
        sequence: 1000,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut extended = bytes.clone();
    extended.extend_from_slice(&serialize_header(&header, &payload));
    extended.extend_from_slice(&payload);
    let trace = read_trace(&extended).unwrap();
    assert!(!trace.index_matches_scan);
    assert!(trace.issues.contains(&RecoveryIssue::IndexMismatch));
    // 走査結果そのものは使える
    assert_eq!(trace.total_events(), 3);
    assert!(trace.finalization.is_some());
}

#[test]
fn reader_limits_stop_scan() {
    let (bytes, _) = base_trace();
    let limits = ReaderLimits {
        max_blocks: 3,
        max_events: 100,
        max_blobs: 10,
    };
    let trace = read_trace_with_limits(&bytes, limits).unwrap();
    assert!(trace
        .issues
        .iter()
        .any(|i| matches!(i, RecoveryIssue::LimitExceeded { what: "blocks" })));
    // イベント上限：最初のバッチ（2 件）で上限 1 を超える
    let limits = ReaderLimits {
        max_blocks: 100,
        max_events: 1,
        max_blobs: 10,
    };
    let trace = read_trace_with_limits(&bytes, limits).unwrap();
    assert!(trace
        .issues
        .iter()
        .any(|i| matches!(i, RecoveryIssue::LimitExceeded { what: "events" })));
}

#[test]
fn duplicate_header_block_is_corruption() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (index_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Index)
        .copied()
        .unwrap();
    let mut extended = bytes[..index_off].to_vec();
    extended.extend_from_slice(&bytes[..56]); // Header Block の複製
    extended.extend_from_slice(&bytes[index_off..]);
    let trace = read_trace(&extended).unwrap();
    assert!(has_corrupt_at(&trace, index_off as u64));
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn totally_corrupt_tail_does_not_lose_prefix() {
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (fin_off, _, _) = *layout.last().unwrap();
    let mut broken = bytes.clone();
    // Finalization Block を丸ごとノイズで上書き（再同期先が無い）
    for b in &mut broken[fin_off..] {
        *b = 0x55;
    }
    let trace = read_trace(&broken).unwrap();
    assert!(trace.finalization.is_none());
    assert_eq!(trace.total_events(), 3);
    assert!(has_corrupt_at(&trace, fin_off as u64));
}
