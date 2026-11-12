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
