//! 回復意味論（recover_trace）のケーステスト。
//! docs/trace-format.md「回復意味論」の表の各行に対応する。

use shirusu_trace::blob::BlobId;
use shirusu_trace::container::{
    parse_raw_header, serialize_header, BlockHeader, BlockType, Compression, FileHeader,
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
        global_order: None,
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
fn nonzero_header_flags_is_not_a_trace() {
    // F24: Header payload の header_flags（予約、0）が 0 でないファイルは
    // Trace ではない。CRC は serialize_header で付け直すため、失敗の原因
    // は header_flags の検証だけになる。
    let header = BlockHeader {
        block_type: BlockType::Header,
        compression: Compression::None,
        sequence: 0,
        stored_len: 24,
        raw_len: 24,
    };
    // 対照: flags=0 の Header だけのファイルは読める。
    let good_payload = FileHeader::new(42).encode();
    let mut good = serialize_header(&header, &good_payload).to_vec();
    good.extend_from_slice(&good_payload);
    let read = read_trace(&good).expect("header-only trace reads");
    assert_eq!(read.header.session_id, 42);

    for flags in [1u16, 0x8000, 0xffff] {
        let mut payload = FileHeader::new(42).encode();
        payload[14..16].copy_from_slice(&flags.to_le_bytes());
        let mut file = serialize_header(&header, &payload).to_vec();
        file.extend_from_slice(&payload);
        assert!(
            matches!(read_trace(&file), Err(TraceError::NotATrace)),
            "flags={flags:#06x} must be rejected"
        );
    }
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

#[test]
fn writer_session_ids_agree() {
    // F17: Writer が書いたファイルは Header.session_id ==
    // Environment.session.session_id == 各 Batch.session_id であり、
    // SessionMismatch の issue は出ない（Writer は単一源泉）。
    let (bytes, _) = base_trace();
    let trace = read_trace(&bytes).unwrap();
    assert_eq!(trace.header.session_id, 42);
    let env = trace.environment.as_ref().expect("environment present");
    assert_eq!(env.session.session_id, 42);
    assert!(trace.batches.iter().all(|b| b.session_id == 42));
    assert!(
        !trace
            .issues
            .iter()
            .any(|i| matches!(i, RecoveryIssue::SessionMismatch { .. })),
        "issues: {:?}",
        trace.issues
    );
}

#[test]
fn environment_session_mismatch_is_recorded() {
    // F17: Header.session_id (42) と Environment.session.session_id
    // が違う入力は、内容を読み捨てず issue として記録する。
    // session_id 43 は 42 と同じ varint 長（1 バイト）のため Block 長
    // が変わらず、保存 Index も有効なままになる。
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (env_off, _, env_len) = layout[1];
    let mut other = env();
    other.session.session_id = 43;
    let payload = other.encode();
    assert_eq!(payload.len(), env().encode().len());
    let header = BlockHeader {
        block_type: BlockType::Environment,
        compression: Compression::None,
        sequence: 1,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut replaced = bytes[..env_off].to_vec();
    replaced.extend_from_slice(&serialize_header(&header, &payload));
    replaced.extend_from_slice(&payload);
    replaced.extend_from_slice(&bytes[env_off + 32 + env_len..]);
    let trace = read_trace(&replaced).unwrap();
    assert_eq!(trace.environment.as_ref().unwrap().session.session_id, 43);
    assert!(
        trace.issues.contains(&RecoveryIssue::SessionMismatch {
            what: "environment",
            expected: 42,
            found: 43,
        }),
        "issues: {:?}",
        trace.issues
    );
    // 不一致でもイベントは読める
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn event_chunk_session_mismatch_is_recorded() {
    // F17: Event Chunk の BatchHeader.session_id が Header (42) と
    // 違う入力は issue として記録し、バッチ自体は読み捨てない。
    // Writer は不一致バッチを拒否するため、Chunk を直接捏造する。
    let (bytes, _) = base_trace();
    let layout = block_layout(&bytes);
    let (index_off, _, _) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::Index)
        .copied()
        .unwrap();
    let mut forged = batch(9, vec![event(1, PayloadRef::None)]);
    forged.session_id = 43;
    let payload = shirusu_trace::compact::encode_event_chunk(&forged);
    let header = BlockHeader {
        block_type: BlockType::EventChunk,
        compression: Compression::None,
        sequence: 998,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut extended = bytes[..index_off].to_vec();
    extended.extend_from_slice(&serialize_header(&header, &payload));
    extended.extend_from_slice(&payload);
    extended.extend_from_slice(&bytes[index_off..]);
    let trace = read_trace(&extended).unwrap();
    assert!(
        trace.issues.contains(&RecoveryIssue::SessionMismatch {
            what: "event chunk",
            expected: 42,
            found: 43,
        }),
        "issues: {:?}",
        trace.issues
    );
    // 不一致のバッチも読める（イベントは失われない）
    assert_eq!(trace.total_events(), 4);
    assert!(trace.batches.iter().any(|b| b.thread_id == 9));
}

/// Blob Chunk を、それを参照する Event Chunk より後ろへ移動した
/// ファイルを作る（前方参照の捏造）。Block の並びだけを変え、各
/// Block 自体（CRC を含む）は壊さない。保存 Index は付け直さない
/// ため IndexMismatch も出るが、それは本テストの関心外。
fn with_blob_moved_after_event(bytes: &[u8]) -> Vec<u8> {
    let layout = block_layout(bytes);
    let (blob_off, _, blob_len) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::BlobChunk)
        .copied()
        .expect("blob chunk present");
    let (ev_off, _, ev_len) = layout
        .iter()
        .find(|(_, t, _)| *t == BlockType::EventChunk)
        .copied()
        .expect("event chunk present");
    assert!(
        blob_off < ev_off,
        "base trace writes blob before event chunk"
    );
    let blob_end = blob_off + 32 + blob_len;
    let ev_end = ev_off + 32 + ev_len;
    let mut out = bytes[..blob_off].to_vec();
    out.extend_from_slice(&bytes[ev_off..ev_end]);
    out.extend_from_slice(&bytes[blob_off..blob_end]);
    out.extend_from_slice(&bytes[ev_end..]);
    out
}

#[test]
fn forward_blob_reference_is_recorded() {
    // F23: Blob Chunk が参照する Event Chunk より後に現れる前方参照は、
    // 内容を解決して保持したうえで issue として記録する。
    let (bytes, id) = base_trace();
    let reordered = with_blob_moved_after_event(&bytes);
    let trace = read_trace(&reordered).unwrap();
    assert!(
        trace
            .issues
            .contains(&RecoveryIssue::ForwardBlobReference { id }),
        "issues: {:?}",
        trace.issues
    );
    // 前方参照でも Payload は解決される（イベントは失われない）。
    let first = &trace.batches[0].events[0];
    assert_eq!(
        trace.resolve_payload(first),
        PayloadResolution::Blob(b"important payload")
    );
    assert_eq!(trace.total_events(), 3);
}

#[test]
fn writer_blob_before_event_chunk_has_no_forward_reference() {
    // F23: Writer が書いたファイルは Blob を参照 Event Chunk より先に
    // 書くため、前方参照の issue は出ない。
    let (bytes, _) = base_trace();
    let trace = read_trace(&bytes).unwrap();
    assert!(
        !trace
            .issues
            .iter()
            .any(|i| matches!(i, RecoveryIssue::ForwardBlobReference { .. })),
        "issues: {:?}",
        trace.issues
    );
}

#[test]
fn forward_blob_reference_is_recorded_once_per_blob() {
    // F23: 同じ Blob を参照するイベントが複数あっても、issue は Blob
    // ごとに 1 回だけ記録する（F17 の SessionMismatch と同じ方針）。
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let id = w.add_payload(b"shared payload").unwrap();
    w.write_batch(&batch(
        3,
        vec![
            event(1, PayloadRef::Blob(id)),
            event(2, PayloadRef::Blob(id)),
        ],
    ))
    .unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    let reordered = with_blob_moved_after_event(&bytes);
    let trace = read_trace(&reordered).unwrap();
    let count = trace
        .issues
        .iter()
        .filter(|i| matches!(i, RecoveryIssue::ForwardBlobReference { .. }))
        .count();
    assert_eq!(count, 1, "issues: {:?}", trace.issues);
    assert_eq!(trace.total_events(), 2);
}

// ---- F18: Blob の部分的な更新（回復意味論） ----

/// BlobUpdate 1 件を Block として符号化する（手組み用）。
/// sequence は Writer の連番と衝突しない大きな値を使う。
fn update_block(update: &shirusu_trace::blob::BlobUpdate) -> Vec<u8> {
    let payload = update.encode();
    let header = BlockHeader {
        block_type: BlockType::BlobUpdate,
        compression: Compression::None,
        sequence: 999,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut out = serialize_header(&header, &payload).to_vec();
    out.extend_from_slice(&payload);
    out
}

/// 基底 Blob（"0123456789abcdef"）＋イベント 1 件の Trace。
/// 戻り値: (バイト列, 基底 BlobId, 共有バッファ)
fn base_blob_trace() -> (Vec<u8>, BlobId) {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let id = w.add_payload(b"0123456789abcdef").unwrap();
    w.write_batch(&batch(3, vec![event(1, PayloadRef::Blob(id))]))
        .unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    (bytes, id)
}

#[test]
fn blob_update_missing_base_is_recorded() {
    // F18: 基底 Blob がファイル内に無い更新は適用できず、issue として
    // 記録する（内容は推測で作らない）。
    let mut bytes = base_blob_trace().0;
    let unknown = BlobId::of_content(b"this resource does not exist");
    let update = shirusu_trace::blob::BlobUpdate {
        resource_id: unknown,
        new_version_id: BlobId::of_content(b"some new version"),
        offset: 0,
        data: b"X".to_vec(),
    };
    bytes.extend_from_slice(&update_block(&update));
    let trace = read_trace(&bytes).unwrap();
    assert!(
        trace
            .issues
            .contains(&RecoveryIssue::BlobUpdateMissingBase {
                resource_id: unknown
            }),
        "issues: {:?}",
        trace.issues
    );
    assert!(!trace.resource_versions.contains_key(&unknown));
    assert_eq!(trace.blob_updates.len(), 1);
}

#[test]
fn blob_update_out_of_range_is_recorded_and_skipped() {
    // F18: offset + size が基底長を超える更新は適用せず、基底の内容は
    // そのまま残す。後続の正常な更新の畳み込みは続く。
    let (mut bytes, base_id) = base_blob_trace();
    let bad_version = BlobId::of_content(b"bad version bytes!");
    let bad = shirusu_trace::blob::BlobUpdate {
        resource_id: base_id,
        new_version_id: bad_version,
        offset: 15,
        data: b"XY".to_vec(),
    };
    bytes.extend_from_slice(&update_block(&bad));
    let good_version = BlobId::of_content(b"01234XXXXXabcdef");
    let good = shirusu_trace::blob::BlobUpdate {
        resource_id: base_id,
        new_version_id: good_version,
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    bytes.extend_from_slice(&update_block(&good));
    let trace = read_trace(&bytes).unwrap();
    assert!(
        trace.issues.contains(&RecoveryIssue::BlobUpdateOutOfRange {
            resource_id: base_id,
            offset: 15,
            size: 2,
            base_len: 16,
        }),
        "issues: {:?}",
        trace.issues
    );
    // 悪い更新は適用されず、良い更新だけが畳み込まれる
    assert_eq!(trace.resource_versions.get(&base_id), Some(&good_version));
    assert_eq!(
        trace.blobs.get(&good_version).map(Vec::as_slice),
        Some(b"01234XXXXXabcdef".as_slice())
    );
    assert!(!trace.blobs.contains_key(&bad_version));
    // 基底そのものは無傷
    assert_eq!(
        trace.blobs.get(&base_id).map(Vec::as_slice),
        Some(b"0123456789abcdef".as_slice())
    );
}

#[test]
fn blob_update_hash_mismatch_is_recorded_and_skipped() {
    // F18: 畳み込み結果のハッシュが宣言された新版 ID と違う更新は
    // 適用しない（BlobHashMismatch と同じく、ID は内容ハッシュそのもの
    // であるという設計を Reader 側でも守る）。参照側には MissingBlob
    // として現れる。
    let (mut bytes, base_id) = base_blob_trace();
    let wrong_version = BlobId::of_content(b"not the folded content");
    let update = shirusu_trace::blob::BlobUpdate {
        resource_id: base_id,
        new_version_id: wrong_version,
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    bytes.extend_from_slice(&update_block(&update));
    let trace = read_trace(&bytes).unwrap();
    let folded = b"01234XXXXXabcdef".to_vec();
    assert!(
        trace
            .issues
            .contains(&RecoveryIssue::BlobUpdateHashMismatch {
                resource_id: base_id,
                expected: wrong_version,
                computed: BlobId::of_content(&folded),
            }),
        "issues: {:?}",
        trace.issues
    );
    assert!(!trace.resource_versions.contains_key(&base_id));
    assert!(!trace.blobs.contains_key(&wrong_version));
    // この Trace のイベントは誤った新版を参照していないため、
    // MissingBlob は出ない（欠落の明示は参照がある場合のみ）。
    assert!(
        !trace
            .issues
            .iter()
            .any(|i| matches!(i, RecoveryIssue::MissingBlob { .. })),
        "issues: {:?}",
        trace.issues
    );
}

#[test]
fn blob_update_size_mismatch_is_corrupt_block() {
    // F18: 宣言サイズと実データ長が食い違う BlobUpdate は、その Block
    // だけを破損として隔離する（F05 の厳格さと同じ）。
    let (mut bytes, base_id) = base_blob_trace();
    let update = shirusu_trace::blob::BlobUpdate {
        resource_id: base_id,
        new_version_id: BlobId::of_content(b"01234XXXXXabcdef"),
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    let mut block = update_block(&update);
    // payload 内の size 欄（Block ヘッダー 32 + 72 バイト目）を +1 する
    let size_at = 32 + 72;
    block[size_at..size_at + 4].copy_from_slice(&6u32.to_le_bytes());
    // CRC を付け直さないと CRC 不一致になってしまうため、ヘッダーを
    // 作り直す（payload は size 欄を改変したもの）
    let payload = &block[32..];
    let header = BlockHeader {
        block_type: BlockType::BlobUpdate,
        compression: Compression::None,
        sequence: 999,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut fixed = serialize_header(&header, payload).to_vec();
    fixed.extend_from_slice(payload);
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(&fixed);
    let trace = read_trace(&bytes).unwrap();
    assert!(has_corrupt_at(&trace, offset), "issues: {:?}", trace.issues);
    assert!(trace.blob_updates.is_empty());
}
