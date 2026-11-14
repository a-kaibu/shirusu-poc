//! 壊れた入力・細工した入力でメモリと CPU が上限内に収まること
//! （2026-11-14 レビュー P2-11）。

use shirusu_trace::container::{
    resync_crc_budget, serialize_header, BlockHeader, BlockType, Compression, BLOCK_MAGIC,
    HEADER_LEN,
};
use shirusu_trace::proto::{
    decode_loss_block, BlockIndex, SchemaSet, MAX_INDEX_ENTRIES_PER_BLOCK,
    MAX_LOSS_RECORDS_PER_BLOCK, MAX_SCHEMAS_PER_BLOCK,
};
use shirusu_trace::ProtoError;

/// `count` empty messages in field 1 (2 bytes each).
fn empty_messages(count: usize) -> Vec<u8> {
    [0x0A, 0x00].repeat(count)
}

#[test]
fn repeated_fields_are_bounded_per_block() {
    let over = |limit: usize| empty_messages(limit + 1);
    assert_eq!(
        decode_loss_block(&over(MAX_LOSS_RECORDS_PER_BLOCK)).unwrap_err(),
        ProtoError::TooManyEntries {
            limit: MAX_LOSS_RECORDS_PER_BLOCK
        }
    );
    assert_eq!(
        decode_loss_block(&empty_messages(MAX_LOSS_RECORDS_PER_BLOCK))
            .unwrap()
            .len(),
        MAX_LOSS_RECORDS_PER_BLOCK
    );
    assert!(matches!(
        BlockIndex::decode(&over(MAX_INDEX_ENTRIES_PER_BLOCK)),
        Err(ProtoError::TooManyEntries { .. })
    ));
    assert!(matches!(
        SchemaSet::decode(&over(MAX_SCHEMAS_PER_BLOCK)),
        Err(ProtoError::TooManyEntries { .. })
    ));
}

#[test]
fn fake_headers_do_not_make_resync_quadratic() {
    // A file of fake `SBLK` headers, each claiming a long payload whose CRC
    // never matches. Without a budget every candidate CRCs to the end.
    let len = 8 * 1024 * 1024;
    let env = shirusu_trace::proto::CaptureEnvironment {
        session: shirusu_trace::proto::SessionMetadata {
            session_id: 1,
            created_by: "hostile input test".into(),
            qpc_frequency: 1000,
        },
        ..Default::default()
    };
    let prefix = shirusu_trace::TraceWriter::new(Vec::new(), env)
        .unwrap()
        .finish(shirusu_trace::FinalizationInfo::default())
        .unwrap();
    let mut data = vec![0u8; len];
    let fake = BlockHeader {
        block_type: BlockType::Loss,
        compression: Compression::None,
        sequence: 0,
        stored_len: (len / 2) as u32,
        raw_len: (len / 2) as u32,
    };
    let header = serialize_header(&fake, &[1]);
    data[..prefix.len()].copy_from_slice(&prefix);
    let mut at = prefix.len();
    while at + HEADER_LEN <= len / 2 {
        data[at..at + HEADER_LEN].copy_from_slice(&header);
        at += 64;
    }
    assert_eq!(&data[prefix.len()..prefix.len() + 4], &BLOCK_MAGIC);
    let started = std::time::Instant::now();
    let trace = shirusu_trace::read_trace(&data).unwrap();
    assert!(trace.issues.iter().any(|i| matches!(
        i,
        shirusu_trace::RecoveryIssue::LimitExceeded {
            what: "resync work"
        }
    )));
    // Bounded by the budget (4x input + 64MiB of CRC), not candidates x size.
    assert!(resync_crc_budget(len as u64) < 128 * 1024 * 1024);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );

    let started = std::time::Instant::now();
    let mut stream = shirusu_trace::stream::TraceStream::open(std::io::Cursor::new(data));
    if let Ok(stream) = stream.as_mut() {
        while let Ok(Some(_)) = stream.next_item() {}
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}
