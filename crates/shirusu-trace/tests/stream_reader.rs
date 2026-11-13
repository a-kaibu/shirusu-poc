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
