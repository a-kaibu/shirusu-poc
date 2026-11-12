use shirusu_trace::{
    reader::{read_trace_with_limits, ReaderLimits, RecoveryIssue},
    writer::FinalizationInfo,
    BlobId, TraceWriter,
};
fn updates() -> Vec<u8> {
    let mut w = TraceWriter::new(Vec::new(), Default::default()).unwrap();
    let mut data = vec![0; 1024];
    let base = w.add_payload(&data).unwrap();
    for v in 1..=3u8 {
        data[0] = v;
        w.write_blob_update(base, BlobId::of_content(&data), 0, &[v])
            .unwrap();
    }
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn derived_blob_cannot_hide_a_forward_base_reference() {
    let mut w = TraceWriter::new(Vec::new(), Default::default()).unwrap();
    let base_data = vec![0; 1024];
    let base = w.add_payload(&base_data).unwrap();
    let mut updated = base_data.clone();
    updated[0] = 1;
    w.write_blob_update(base, BlobId::of_content(&updated), 0, &[1])
        .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let layout = read_trace_with_limits(&bytes, ReaderLimits::default())
        .unwrap()
        .blocks;
    let blob = layout
        .iter()
        .position(|b| b.block_type == shirusu_trace::container::BlockType::BlobChunk)
        .unwrap();
    let update = layout
        .iter()
        .position(|b| b.block_type == shirusu_trace::container::BlockType::BlobUpdate)
        .unwrap();
    assert_eq!(update, blob + 1);
    let start = layout[blob].offset as usize;
    let middle = layout[update].offset as usize;
    let end = layout[update + 1].offset as usize;
    // Deliberately corrupt ordering without corrupting either block's CRC.
    let reordered = [
        &bytes[..start],
        &bytes[middle..end],
        &bytes[start..middle],
        &bytes[end..],
    ]
    .concat();
    let trace = read_trace_with_limits(&reordered, ReaderLimits::default()).unwrap();
    assert!(trace
        .issues
        .iter()
        .any(|issue| matches!(issue, RecoveryIssue::ForwardBlobReference { .. })));
}
#[test]
fn derived_blobs_respect_count_and_byte_budgets() {
    for (limits, what, max) in [
        (
            ReaderLimits {
                max_blobs: 1,
                ..Default::default()
            },
            "blobs",
            1,
        ),
        (
            ReaderLimits {
                max_blob_bytes: 2048,
                ..Default::default()
            },
            "blob bytes",
            2,
        ),
    ] {
        let t = read_trace_with_limits(&updates(), limits).unwrap();
        assert_eq!(t.blobs.len(), max);
        assert!(t.issues.contains(&RecoveryIssue::LimitExceeded { what }));
    }
}
#[test]
fn decoded_budget_stops_before_expansion() {
    let t = read_trace_with_limits(
        &updates(),
        ReaderLimits {
            max_decoded_bytes: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(t.blobs.is_empty());
    assert!(t.issues.contains(&RecoveryIssue::LimitExceeded {
        what: "decoded bytes"
    }));
}
#[test]
fn non_ascii_hex_is_rejected_without_panicking() {
    for scalar in ['€', 'あ', '😀'] {
        for prefix in 0..4 {
            let s = format!(
                "{}{}{}",
                "a".repeat(prefix),
                scalar,
                "0".repeat(64 - prefix - scalar.len_utf8())
            );
            assert_eq!(BlobId::parse_hex(&s), None);
        }
    }
}
