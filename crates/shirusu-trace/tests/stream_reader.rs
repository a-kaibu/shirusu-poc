//! ストリーミング Reader（`shirusu_trace::stream`）が、全体読み込み
//! （`read_trace`）と同じ内容・同じ回復結果を返すことの検査。
//!
//! 正常な Trace に加え、全バイト位置の 1 バイト破損と全長での切断を
//! 総当たりで与え、両 Reader の結果（issue を含む）を突き合わせる。

use shirusu_trace::blob::BlobId;
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{
    CaptureEnvironment, LossRecord, ProfileSummary, SchemaDef, SessionMetadata,
};
use shirusu_trace::reader::{ReaderLimits, RecoveryIssue};
use shirusu_trace::schema::{make_schema, EventCapture, Ty};
use shirusu_trace::stream::{StreamItem, StreamOptions, TraceStream};
use shirusu_trace::{read_trace, read_trace_with_limits, TraceWriter};
use std::io::Cursor;

fn env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "stream-test".into(),
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
        schema_id: 1,
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

/// Schema・Blob 2 件・更新 1 件・Batch 3 件（圧縮あり・なし）・Loss・
/// Profile・Finalization を含む Trace。
fn rich_trace() -> (Vec<u8>, BlobId, BlobId) {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    w.register_schema(make_schema(
        1,
        "kernel32!Test/enter",
        vec![("x".into(), Ty::U32, 0)],
    ))
    .unwrap();
    let a = w.add_payload(b"0123456789abcdef").unwrap();
    let b = w.add_payload(b"second payload").unwrap();
    let updated = BlobId::of_content(b"01XY456789abcdef");
    w.write_blob_update(a, updated, 2, b"XY").unwrap();
    w.write_batch(&batch(
        3,
        vec![
            event(1, PayloadRef::Blob(a)),
            event(2, PayloadRef::Blob(updated)),
            event(3, PayloadRef::None),
        ],
    ))
    .unwrap();
    w.write_batch_uncompressed(&batch(4, vec![event(1, PayloadRef::Blob(b))]))
        .unwrap();
    w.write_batch(&batch(4, vec![event(2, PayloadRef::Inline(vec![5, 6]))]))
        .unwrap();
    w.write_loss_records(&[LossRecord {
        kind: 1,
        count: 3,
        process_id: 7,
        thread_id: 4,
        ..Default::default()
    }])
    .unwrap();
    w.write_profile_summary(&ProfileSummary {
        qpc_frequency: 10_000_000,
        total_events_seen: 5,
        apis: Vec::new(),
    })
    .unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    (bytes, a, updated)
}

#[derive(Default)]
struct Collected {
    environment: Option<CaptureEnvironment>,
    schemas: Vec<SchemaDef>,
    batches: Vec<EventBatch>,
    loss: Vec<LossRecord>,
    finalization: Option<(shirusu_trace::proto::Finalization, bool)>,
    profile: Option<ProfileSummary>,
}

fn issue_key(issue: &RecoveryIssue) -> Option<String> {
    Some(format!("{issue:?}"))
}

/// 両 Reader の結果を比べる。全体読み込みが拒否する入力はストリーミングも拒否する。
fn assert_equivalent(data: &[u8], limits: ReaderLimits) {
    let full = read_trace_with_limits(data, limits);
    let options = StreamOptions {
        limits,
        ..Default::default()
    };
    let stream = TraceStream::with_options(Cursor::new(data), options);
    let (full, mut stream) = match (full, stream) {
        (Err(_), Err(_)) => return,
        (Ok(f), Ok(s)) => (f, s),
        (f, s) => panic!(
            "acceptance differs: full={:?} stream={:?}",
            f.err(),
            s.err()
        ),
    };
    let mut got = Collected::default();
    while let Some(item) = stream.next_item().unwrap() {
        match item {
            StreamItem::Environment(e) => got.environment = Some(e),
            StreamItem::Schemas(s) => got.schemas.extend(s),
            StreamItem::Events(b) => got.batches.push(b),
            StreamItem::Loss(l) => got.loss.extend(l),
            StreamItem::Finalization {
                finalization,
                cleanly,
            } => got.finalization = Some((finalization, cleanly)),
            StreamItem::ProfileSummary(p) => got.profile = Some(p),
            StreamItem::SkippedEvents { .. }
            | StreamItem::Blobs(_)
            | StreamItem::BlobUpdate(_)
            | StreamItem::Index(_) => {}
        }
    }
    // Blob（更新で作った版を含む）は内容を保持せず、必要なときに読み直す。
    for (id, content) in &full.blobs {
        assert_eq!(
            stream.load_blob(id).unwrap().as_deref(),
            Some(content.as_slice()),
            "blob {id}"
        );
    }
    let summary = stream.finish().unwrap();
    assert_eq!(got.environment, full.environment);
    assert_eq!(got.schemas, full.schemas);
    assert_eq!(got.batches, full.batches);
    assert_eq!(got.loss, full.loss_records);
    assert_eq!(
        got.finalization,
        full.finalization
            .clone()
            .map(|f| (f, full.finalized_cleanly))
    );
    assert_eq!(got.profile, full.profile_summary);
    assert_eq!(summary.header, full.header);
    assert_eq!(summary.blocks, full.blocks);
    assert_eq!(summary.index_matches_scan, full.index_matches_scan);
    assert_eq!(summary.total_events, full.total_events());
    let mut a: Vec<_> = full.issues.iter().filter_map(issue_key).collect();
    let mut b: Vec<_> = summary.issues.iter().filter_map(issue_key).collect();
    a.sort();
    b.sort();
    assert_eq!(b, a, "issues differ");
}

#[test]
fn clean_trace_streams_the_same_content() {
    let (bytes, a, updated) = rich_trace();
    assert!(read_trace(&bytes).unwrap().issues.is_empty());
    assert_equivalent(&bytes, ReaderLimits::default());
    let mut stream = TraceStream::open(Cursor::new(&bytes)).unwrap();
    let mut events = 0;
    while let Some(item) = stream.next_item().unwrap() {
        if let StreamItem::Events(b) = item {
            events += b.events.len();
        }
    }
    assert_eq!(events, 5);
    assert_eq!(
        stream.load_blob(&updated).unwrap().as_deref(),
        Some(&b"01XY456789abcdef"[..])
    );
    assert_eq!(
        stream.load_blob(&a).unwrap().as_deref(),
        Some(&b"0123456789abcdef"[..])
    );
    assert_eq!(
        stream.load_blob(&BlobId::of_content(b"absent")).unwrap(),
        None
    );
    let summary = stream.finish().unwrap();
    assert!(summary.issues.is_empty());
    assert!(summary.index_matches_scan);
}

#[test]
fn every_single_byte_corruption_recovers_like_the_full_reader() {
    let (bytes, _, _) = rich_trace();
    for at in 0..bytes.len() {
        for flip in [0x01u8, 0xff] {
            let mut data = bytes.clone();
            data[at] ^= flip;
            assert_equivalent(&data, ReaderLimits::default());
        }
    }
}

#[test]
fn every_truncation_recovers_like_the_full_reader() {
    let (bytes, _, _) = rich_trace();
    for len in 0..=bytes.len() {
        assert_equivalent(&bytes[..len], ReaderLimits::default());
    }
}

#[test]
fn garbage_and_reordered_blocks_recover_like_the_full_reader() {
    let (bytes, _, _) = rich_trace();
    // 途中にゴミを挟む（Magic の一部を含めて再同期の窓境界も試す）。
    for gap in [1usize, 3, 4, 7, 100] {
        let mut data = bytes[..200.min(bytes.len())].to_vec();
        data.extend(std::iter::repeat_n(b'S', gap));
        data.extend_from_slice(b"SBL");
        data.extend_from_slice(&bytes[200.min(bytes.len())..]);
        assert_equivalent(&data, ReaderLimits::default());
    }
}

#[test]
fn limits_stop_both_readers_at_the_same_point() {
    let (bytes, _, _) = rich_trace();
    for limits in [
        ReaderLimits {
            max_blocks: 4,
            ..Default::default()
        },
        ReaderLimits {
            max_events: 3,
            ..Default::default()
        },
        ReaderLimits {
            max_decoded_bytes: 200,
            ..Default::default()
        },
        ReaderLimits {
            max_blobs: 1,
            ..Default::default()
        },
    ] {
        assert_equivalent(&bytes, limits);
    }
}

#[test]
fn metadata_only_streaming_skips_event_chunks() {
    let (bytes, _, _) = rich_trace();
    let mut stream = TraceStream::with_options(
        Cursor::new(&bytes),
        StreamOptions {
            decode_events: false,
            ..Default::default()
        },
    )
    .unwrap();
    let (mut skipped, mut decoded, mut finalized) = (0, 0, false);
    while let Some(item) = stream.next_item().unwrap() {
        match item {
            StreamItem::SkippedEvents { .. } => skipped += 1,
            StreamItem::Events(_) => decoded += 1,
            StreamItem::Finalization { cleanly, .. } => finalized = cleanly,
            _ => {}
        }
    }
    assert_eq!((skipped, decoded), (3, 0));
    assert!(finalized);
    assert_eq!(stream.finish().unwrap().total_events, 0);
}

#[test]
fn yielded_blobs_are_hash_checked_contents() {
    let (bytes, a, _) = rich_trace();
    let mut stream = TraceStream::with_options(
        Cursor::new(&bytes),
        StreamOptions {
            yield_blobs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut blobs = Vec::new();
    while let Some(item) = stream.next_item().unwrap() {
        if let StreamItem::Blobs(found) = item {
            blobs.extend(found);
        }
    }
    assert_eq!(blobs.len(), 2);
    assert!(blobs
        .iter()
        .any(|(id, data)| *id == a && data == b"0123456789abcdef"));
    assert!(blobs
        .iter()
        .all(|(id, data)| BlobId::of_content(data) == *id));
}

#[test]
fn blob_update_failures_are_reported_like_the_full_reader() {
    use shirusu_trace::blob::BlobUpdate;
    use shirusu_trace::container::{serialize_header, BlockHeader, BlockType, Compression};
    let (bytes, a, _) = rich_trace();
    let block = |update: &BlobUpdate| {
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
    };
    for update in [
        // 基底が無い。
        BlobUpdate {
            resource_id: BlobId::of_content(b"no such resource"),
            new_version_id: BlobId::of_content(b"x"),
            offset: 0,
            data: b"X".to_vec(),
        },
        // 範囲外。
        BlobUpdate {
            resource_id: a,
            new_version_id: BlobId::of_content(b"y"),
            offset: 100,
            data: b"X".to_vec(),
        },
        // 宣言した新版 ID と畳み込み結果が違う。
        BlobUpdate {
            resource_id: a,
            new_version_id: BlobId::of_content(b"wrong"),
            offset: 0,
            data: b"Z".to_vec(),
        },
    ] {
        let mut data = bytes.clone();
        data.extend_from_slice(&block(&update));
        assert_equivalent(&data, ReaderLimits::default());
    }
}

/// fuzz stream_trace が見つけた入力（crash-4f6331159bd50ee6d3d2640a93e5d3979aa559be）。
/// Environment Block が複数あり session が食い違うとき、不一致を最後の 1 つ
/// についてだけ記録する（全体読み込みと同じ）ことを確かめる。
#[test]
fn fuzz_stream_trace_crash_4f633115_recovers_like_the_full_reader() {
    let data: &[u8] = &[
        83, 66, 76, 75, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 24, 0, 0, 0, 255, 208,
        14, 141, 0, 0, 0, 0, 83, 72, 73, 82, 85, 83, 85, 0, 84, 82, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 83, 66, 76, 75, 2, 0, 32, 0, 1, 0, 0, 0, 0, 0, 83, 66, 76, 75, 1, 0, 32, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 24, 0, 0, 0, 24, 0, 0, 0, 84, 82, 206, 217, 0, 0, 0, 0, 83, 72, 73, 82, 85, 83,
        85, 0, 84, 82, 1, 0, 1, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 83, 66, 76, 75, 2, 0, 32, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 22, 0, 0, 0, 157, 175, 33, 188, 0, 0, 0, 0, 10, 12, 8,
        42, 18, 3, 118, 101, 99, 24, 128, 173, 226, 4, 34, 6, 120, 56, 54, 95, 54, 52, 83, 66, 76,
        75, 4, 0, 32, 0, 2, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0, 48, 171, 84, 3, 0, 0, 0,
        0, 21, 83, 66, 76, 75, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 83, 66, 76, 75, 2, 0, 32, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 22, 0, 0, 0, 22, 0, 0, 0, 157, 175, 33, 188, 0, 0, 0, 0, 10, 12, 8, 42, 18,
        3, 118, 101, 99, 24, 128, 173, 226, 4, 34, 6, 120, 56, 54, 95, 54, 52, 83, 66, 76, 75, 4,
        0, 32, 0, 2, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 24, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 83,
        66, 76, 75, 2, 0, 32, 0, 1, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 22, 0, 0, 0, 157, 157, 55,
        33, 95, 54, 52, 83, 66, 76, 75, 4, 0, 32, 83, 66, 76, 75, 0, 175, 33, 188, 0, 0, 0, 0, 10,
        12, 8, 42, 18, 3, 118, 101, 99, 24, 128, 173, 226, 4, 34, 6, 120, 56, 54, 95, 54, 52, 83,
        66, 76, 75, 4, 0, 32, 0, 2, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0, 0, 0, 24, 0, 0,
        0, 24, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 83, 66, 76, 75, 2, 0, 32, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 22, 0, 0, 0, 22, 0, 0, 0, 157, 175, 33, 188, 0, 0, 0, 0, 10, 12, 8, 42, 18, 3, 118, 101,
        99, 24, 128, 173, 226, 4, 34, 0, 0, 2, 0, 6, 120, 56, 54, 95, 54, 52, 83, 66, 76, 75, 4, 0,
        32, 0, 2, 0, 0, 0, 0, 83, 66, 76, 0, 75,
    ];
    assert_equivalent(data, ReaderLimits::default());
}

// ---------------------------------------------------------------------------
// モデルベース PBT: 任意の操作列で書いた Trace を、任意の小さな上限・破損・
// 切断・Block の並べ替えのもとで両 Reader に読ませ、結果の一致を検査する。
// 既存の総当たりは固定の rich_trace だけを使うため、Blob 更新の連鎖（更新で
// できた版をさらに更新する）、同じ基底への複数更新、上限到達の境界といった
// 経路をここで広く当てる。
// ---------------------------------------------------------------------------

mod model_based {
    use super::*;
    use proptest::prelude::*;
    use shirusu_trace::blob::apply_update_to;
    use shirusu_trace::container::HEADER_LEN;

    fn pbt_cases(default: u32) -> u32 {
        std::env::var("SHIRUSU_PBT_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default)
    }

    #[derive(Debug, Clone)]
    enum Op {
        Payload(Vec<u8>),
        /// 既知の Blob（index は既知集合の中の位置に丸める）への更新。
        Update {
            target: usize,
            offset: usize,
            data: Vec<u8>,
        },
        Batch {
            thread: u64,
            refs: Vec<usize>,
            inline: Option<Vec<u8>>,
        },
        Uncompressed {
            thread: u64,
            refs: Vec<usize>,
        },
        Loss(u64),
        Checkpoint,
        Profile,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => proptest::collection::vec(any::<u8>(), 0..48).prop_map(Op::Payload),
            3 => (any::<usize>(), any::<usize>(), proptest::collection::vec(any::<u8>(), 0..8))
                .prop_map(|(target, offset, data)| Op::Update { target, offset, data }),
            3 => (1u64..4, proptest::collection::vec(any::<usize>(), 0..4),
                  proptest::option::of(proptest::collection::vec(any::<u8>(), 0..6)))
                .prop_map(|(thread, refs, inline)| Op::Batch { thread, refs, inline }),
            1 => (1u64..4, proptest::collection::vec(any::<usize>(), 0..3))
                .prop_map(|(thread, refs)| Op::Uncompressed { thread, refs }),
            1 => (1u64..100).prop_map(Op::Loss),
            1 => Just(Op::Checkpoint),
            1 => Just(Op::Profile),
        ]
    }

    /// 操作列から Trace を書く。書き手の不変条件に反する操作（範囲外の
    /// 更新など）は書かずに飛ばす。`finish` するかどうかも選べる。
    fn write(ops: &[Op], finish: bool) -> Vec<u8> {
        let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
        w.register_schema(make_schema(
            1,
            "kernel32!Test/enter",
            vec![("x".into(), Ty::U32, 0)],
        ))
        .unwrap();
        // 既知の Blob（基底と更新でできた版）とその内容。
        let mut known: Vec<(BlobId, Vec<u8>)> = Vec::new();
        // リソース（更新の resource_id）ごとの作業中内容。Reader は同じ
        // リソースへの更新を基底でなく直前の版に重ねる（F18）。
        let mut current: std::collections::HashMap<BlobId, Vec<u8>> = Default::default();
        let mut seq: std::collections::HashMap<u64, u64> = Default::default();
        let mut next = |thread: u64| {
            let s = seq.entry(thread).or_insert(0);
            *s += 1;
            *s
        };
        for op in ops {
            match op {
                Op::Payload(data) => {
                    let id = w.add_payload(data).unwrap();
                    if !known.iter().any(|(k, _)| *k == id) {
                        known.push((id, data.clone()));
                    }
                }
                Op::Update {
                    target,
                    offset,
                    data,
                } => {
                    if known.is_empty() {
                        continue;
                    }
                    let (base, stored) = known[target % known.len()].clone();
                    let content = current.get(&base).cloned().unwrap_or(stored);
                    if content.is_empty() {
                        continue;
                    }
                    let offset = offset % content.len();
                    let data = &data[..data.len().min(content.len() - offset)];
                    let new = apply_update_to(&content, offset as u64, data).unwrap();
                    let new_id = BlobId::of_content(&new);
                    w.write_blob_update(base, new_id, offset as u64, data)
                        .unwrap();
                    current.insert(base, new.clone());
                    if !known.iter().any(|(k, _)| *k == new_id) {
                        known.push((new_id, new));
                    }
                }
                Op::Batch {
                    thread,
                    refs,
                    inline,
                } => {
                    let mut events = Vec::new();
                    for r in refs {
                        let payload = if known.is_empty() {
                            PayloadRef::None
                        } else {
                            PayloadRef::Blob(known[r % known.len()].0)
                        };
                        events.push(event(next(*thread), payload));
                    }
                    if let Some(bytes) = inline {
                        events.push(event(next(*thread), PayloadRef::Inline(bytes.clone())));
                    }
                    if !events.is_empty() {
                        w.write_batch(&batch(*thread, events)).unwrap();
                    }
                }
                Op::Uncompressed { thread, refs } => {
                    let events: Vec<_> = refs
                        .iter()
                        .map(|r| {
                            let payload = if known.is_empty() {
                                PayloadRef::None
                            } else {
                                PayloadRef::Blob(known[r % known.len()].0)
                            };
                            event(next(*thread), payload)
                        })
                        .collect();
                    if !events.is_empty() {
                        w.write_batch_uncompressed(&batch(*thread, events)).unwrap();
                    }
                }
                Op::Loss(count) => w
                    .write_loss_records(&[LossRecord {
                        kind: 1,
                        count: *count,
                        process_id: 7,
                        thread_id: 1,
                        ..Default::default()
                    }])
                    .unwrap(),
                Op::Checkpoint => w.write_schema_checkpoint().unwrap(),
                Op::Profile => w
                    .write_profile_summary(&ProfileSummary {
                        qpc_frequency: 10_000_000,
                        total_events_seen: 1,
                        apis: Vec::new(),
                    })
                    .unwrap(),
            }
        }
        if finish {
            w.finish(shirusu_trace::writer::FinalizationInfo::default())
                .unwrap()
        } else {
            // finish しないファイル: Writer を捨てる前の内容を取り出す手段が
            // 無いので、finish 後の Index/Finalization を切り落とす代わりに
            // 末尾を切断して扱う（切断は別の戦略でも与える）。
            let bytes = w
                .finish(shirusu_trace::writer::FinalizationInfo::default())
                .unwrap();
            let blocks = block_offsets(&bytes);
            let cut = blocks.len().saturating_sub(2).max(1);
            bytes[..blocks[cut]].to_vec()
        }
    }

    /// Block 境界の位置（最後の要素はファイル長）。
    fn block_offsets(bytes: &[u8]) -> Vec<usize> {
        let mut at = 0;
        let mut out = Vec::new();
        while at + HEADER_LEN <= bytes.len() {
            out.push(at);
            let stored = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
            at += HEADER_LEN + stored;
        }
        out.push(bytes.len());
        out
    }

    #[derive(Debug, Clone)]
    enum Damage {
        None,
        Flip {
            at: usize,
            mask: u8,
        },
        Truncate(usize),
        /// Block（Header 以外）を 1 つ複製して末尾に足す。
        DuplicateBlock(usize),
        /// 隣り合う Block（Header 以外）を入れ替える。
        SwapBlocks(usize),
        DropBlock(usize),
    }

    fn damage() -> impl Strategy<Value = Damage> {
        prop_oneof![
            2 => Just(Damage::None),
            2 => (any::<usize>(), 1u8..=255).prop_map(|(at, mask)| Damage::Flip { at, mask }),
            1 => any::<usize>().prop_map(Damage::Truncate),
            1 => any::<usize>().prop_map(Damage::DuplicateBlock),
            1 => any::<usize>().prop_map(Damage::SwapBlocks),
            1 => any::<usize>().prop_map(Damage::DropBlock),
        ]
    }

    fn apply(bytes: Vec<u8>, d: &Damage) -> Vec<u8> {
        let offs = block_offsets(&bytes);
        // offs: [0(header), b1, ..., len]
        let body: Vec<(usize, usize)> = offs.windows(2).skip(1).map(|w| (w[0], w[1])).collect();
        match *d {
            Damage::None => bytes,
            Damage::Flip { at, mask } => {
                let mut b = bytes;
                let i = at % b.len();
                b[i] ^= mask;
                b
            }
            Damage::Truncate(at) => bytes[..at % (bytes.len() + 1)].to_vec(),
            Damage::DuplicateBlock(i) if !body.is_empty() => {
                let (s, e) = body[i % body.len()];
                let mut b = bytes.clone();
                b.extend_from_slice(&bytes[s..e]);
                b
            }
            Damage::SwapBlocks(i) if body.len() >= 2 => {
                let k = i % (body.len() - 1);
                let (s1, e1) = body[k];
                let (s2, e2) = body[k + 1];
                let mut b = bytes[..s1].to_vec();
                b.extend_from_slice(&bytes[s2..e2]);
                b.extend_from_slice(&bytes[s1..e1]);
                b.extend_from_slice(&bytes[e2..]);
                b
            }
            Damage::DropBlock(i) if !body.is_empty() => {
                let (s, e) = body[i % body.len()];
                let mut b = bytes[..s].to_vec();
                b.extend_from_slice(&bytes[e..]);
                b
            }
            _ => bytes,
        }
    }

    fn limits() -> impl Strategy<Value = ReaderLimits> {
        prop_oneof![
            3 => Just(ReaderLimits::default()),
            2 => (1usize..24, 0u64..24, 0usize..8, 64u64..4096, 0u64..256).prop_map(
                |(max_blocks, max_events, max_blobs, max_decoded_bytes, max_blob_bytes)| {
                    ReaderLimits {
                        max_blocks,
                        max_events,
                        max_blobs,
                        max_decoded_bytes,
                        max_blob_bytes,
                    }
                }
            ),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(pbt_cases(384)))]

        #[test]
        fn random_traces_recover_identically(
            ops in proptest::collection::vec(op(), 0..24),
            finish in any::<bool>(),
            d in damage(),
            limits in limits(),
        ) {
            let bytes = apply(write(&ops, finish), &d);
            assert_equivalent(&bytes, limits);
        }

        /// 破損も上限も無い完了済み Trace では、書いた Blob（更新で
        /// できた版を含む）がすべて内容ハッシュどおりに読み戻せ、
        /// issue が出ない。
        #[test]
        fn clean_random_traces_have_no_issues(ops in proptest::collection::vec(op(), 0..24)) {
            let bytes = write(&ops, true);
            let full = read_trace(&bytes).unwrap();
            prop_assert!(full.issues.is_empty(), "{:?}", full.issues);
            prop_assert!(full.finalized_cleanly);
            prop_assert!(full.index_matches_scan);
            for (id, data) in &full.blobs {
                prop_assert_eq!(BlobId::of_content(data), *id);
            }
            assert_equivalent(&bytes, ReaderLimits::default());
        }
    }
}

/// 回帰: 更新でできた派生版をさらに更新した版（A → B → C）を
/// `load_blob` が読み戻せず None を返していた（全体読み込みは復元する）。
#[test]
fn chained_update_versions_load_like_the_full_reader() {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let a = w.add_payload(b"\x00\x00").unwrap();
    let b = BlobId::of_content(b"\x01\x00");
    w.write_blob_update(a, b, 0, b"\x01").unwrap();
    let c = BlobId::of_content(b"\x01\x02");
    w.write_blob_update(b, c, 1, b"\x02").unwrap();
    // 同じリソース A への 2 回目の更新は B に重なる（基底 A ではない）。
    let d = BlobId::of_content(b"\x01\x03");
    w.write_blob_update(a, d, 1, b"\x03").unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    let full = read_trace(&bytes).unwrap();
    assert!(full.issues.is_empty(), "{:?}", full.issues);
    let mut stream = TraceStream::open(Cursor::new(&bytes)).unwrap();
    while stream.next_item().unwrap().is_some() {}
    for (id, want) in [(b, &b"\x01\x00"[..]), (c, b"\x01\x02"), (d, b"\x01\x03")] {
        assert_eq!(full.blobs.get(&id).map(Vec::as_slice), Some(want));
        assert_eq!(stream.load_blob(&id).unwrap().as_deref(), Some(want));
    }
    assert_equivalent(&bytes, ReaderLimits::default());
}

/// 回帰: 同じ新版 ID を宣言する更新が 2 件あり、ファイル順で先の 1 件が
/// 失敗する（ハッシュ不一致）とき、`load_blob` は先の宣言だけを見て None を
/// 返していた。全体読み込みは後の成功した更新で版を具体化する。
#[test]
fn later_successful_declaration_of_a_version_is_loaded() {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let a = w.add_payload(b"\x00\x00").unwrap();
    let c = BlobId::of_content(b"\x06\x00");
    // Writer は新版 ID を検証しない（F18）。先の更新は内容が宣言と合わない。
    w.write_blob_update(a, c, 0, b"\x07").unwrap();
    w.write_blob_update(a, c, 0, b"\x06").unwrap();
    let bytes = w
        .finish(shirusu_trace::writer::FinalizationInfo::default())
        .unwrap();
    let full = read_trace(&bytes).unwrap();
    assert!(matches!(
        full.issues.as_slice(),
        [RecoveryIssue::BlobUpdateHashMismatch { .. }]
    ));
    assert_eq!(
        full.blobs.get(&c).map(Vec::as_slice),
        Some(&b"\x06\x00"[..])
    );
    let mut stream = TraceStream::open(Cursor::new(&bytes)).unwrap();
    while stream.next_item().unwrap().is_some() {}
    assert_eq!(
        stream.load_blob(&c).unwrap().as_deref(),
        Some(&b"\x06\x00"[..])
    );
    assert_equivalent(&bytes, ReaderLimits::default());
}

/// CRC は正しいが中身の壊れた Blob Chunk（正常なエントリの後ろに
/// 36 バイトに満たない端切れ、または本体の足りないエントリ）。その Block を
/// 破損として隔離し、先頭の正常なエントリは取り込む。両 Reader で同じ。
/// 走査途中の `registry()` / `issues()` も全体読み込みと同じものを返す。
#[test]
fn malformed_blob_chunk_entries_are_isolated_like_the_full_reader() {
    use shirusu_trace::container::{serialize_header, BlockHeader, BlockType, Compression};
    let (bytes, ..) = rich_trace();
    let good = b"kept blob";
    let good_id = BlobId::of_content(good);
    let entry = |id: BlobId, len: u32, body: &[u8]| {
        let mut e = id.as_bytes().to_vec();
        e.extend_from_slice(&len.to_le_bytes());
        e.extend_from_slice(body);
        e
    };
    for (tail, reason) in [
        (vec![0u8; 10], "blob entry header truncated"),
        (
            entry(BlobId::of_content(b"long"), 100, b"short"),
            "blob entry body truncated",
        ),
    ] {
        let mut payload = entry(good_id, good.len() as u32, good);
        payload.extend_from_slice(&tail);
        let header = BlockHeader {
            block_type: BlockType::BlobChunk,
            compression: Compression::None,
            sequence: 500,
            stored_len: payload.len() as u32,
            raw_len: payload.len() as u32,
        };
        let mut data = bytes.clone();
        let at = data.len() as u64;
        data.extend_from_slice(&serialize_header(&header, &payload));
        data.extend_from_slice(&payload);
        let full = read_trace(&data).unwrap();
        assert!(
            full.issues.iter().any(|i| matches!(
                i,
                RecoveryIssue::CorruptBlock { offset, reason: r } if *offset == at && r == reason
            )),
            "{reason}: {:?}",
            full.issues
        );
        assert_eq!(full.blobs.get(&good_id).map(Vec::as_slice), Some(&good[..]));
        assert_equivalent(&data, ReaderLimits::default());
        let mut stream = TraceStream::open(Cursor::new(&data)).unwrap();
        while stream.next_item().unwrap().is_some() {}
        assert!(!full.registry.ids().is_empty());
        assert_eq!(stream.registry().ids(), full.registry.ids());
        assert!(stream
            .issues()
            .iter()
            .any(|i| matches!(i, RecoveryIssue::CorruptBlock { .. })));
    }
}
