//! Block Container と Compact Binary の単体テスト。

use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::*;
use shirusu_trace::container::*;
use shirusu_trace::error::{CompactError, TraceError};
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::schema::{CapturedValue, EventCapture, Ty, TypedValue, ValueCapture};

// ---------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------

#[test]
fn block_header_roundtrip_and_crc() {
    let payload = b"hello container".to_vec();
    let header = BlockHeader {
        block_type: BlockType::EventChunk,
        compression: Compression::None,
        sequence: 7,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let bytes = serialize_header(&header, &payload);
    let (parsed, crc_ok) = parse_header(&bytes, &payload).expect("header parses");
    assert_eq!(parsed, header);
    assert!(crc_ok);
    // payload を 1 バイト変えると CRC が一致しない
    let mut tampered = payload.clone();
    tampered[0] ^= 0xff;
    let (_, crc_ok) = parse_header(&bytes, &tampered).unwrap();
    assert!(!crc_ok);
    // ヘッダー側（sequence）を変えても CRC が一致しない
    let mut bad_header = bytes;
    bad_header[8] ^= 1;
    let (_, crc_ok) = parse_header(&bad_header, &payload).unwrap();
    assert!(!crc_ok);
}

#[test]
fn parse_header_rejects_bad_magic_short_and_reserved() {
    let payload = b"x";
    let header = BlockHeader {
        block_type: BlockType::Loss,
        compression: Compression::None,
        sequence: 0,
        stored_len: 1,
        raw_len: 1,
    };
    let bytes = serialize_header(&header, payload);
    let mut bad_magic = bytes;
    bad_magic[0] = b'X';
    assert!(parse_header(&bad_magic, payload).is_none());
    assert!(parse_header(&bytes[..16], payload).is_none());
    let mut bad_reserved = bytes;
    bad_reserved[31] = 1;
    assert!(parse_header(&bad_reserved, payload).is_none());
    let mut bad_hlen = bytes;
    bad_hlen[6] = 33;
    assert!(parse_header(&bad_hlen, payload).is_none());
}

#[test]
fn raw_header_fields_and_crc() {
    let payload = vec![1u8, 2, 3, 4, 5];
    let header = BlockHeader {
        block_type: BlockType::BlobChunk,
        compression: Compression::Zstd,
        sequence: 99,
        stored_len: 5,
        raw_len: 500,
    };
    let bytes = serialize_header(&header, &payload);
    let raw = parse_raw_header(&bytes).expect("raw header");
    assert_eq!(raw.block_type_code, 5);
    assert_eq!(raw.compression_code, 1);
    assert_eq!(raw.sequence, 99);
    assert_eq!(raw.stored_len, 5);
    assert_eq!(raw.raw_len, 500);
    assert!(raw_header_crc_matches(&raw, &bytes, &payload));
    assert!(!raw_header_crc_matches(&raw, &bytes, &[9, 9, 9, 9, 9]));
    assert!(parse_raw_header(&bytes[..10]).is_none());
    assert!(parse_raw_header(b"NOPE............................").is_none());
}

#[test]
fn file_header_roundtrip() {
    let h = FileHeader::new(0x0123_4567_89ab_cdef);
    let bytes = h.encode();
    assert_eq!(&bytes[0..10], b"SHIRUSU\0TR");
    assert_eq!(FileHeader::decode(&bytes), Some(h));
    let mut bad = bytes;
    bad[0] = b'X';
    assert_eq!(FileHeader::decode(&bad), None);
    assert_eq!(FileHeader::decode(&bytes[..20]), None);
}

#[test]
fn file_header_rejects_nonzero_header_flags() {
    // F24: header_flags（bytes[14..16]、予約）は 0 でなければならない。
    let h = FileHeader::new(42);
    let bytes = h.encode();
    assert_eq!(bytes[14], 0);
    assert_eq!(bytes[15], 0);
    for flags in [1u16, 0x8000, 0xffff] {
        let mut bad = bytes;
        bad[14..16].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(FileHeader::decode(&bad), None, "flags={flags:#06x}");
    }
}

#[test]
fn zstd_roundtrip_repetitive_and_random() {
    let repetitive = vec![0xabu8; 100_000];
    let compressed = compress_chunk(&repetitive);
    assert!(compressed.len() < repetitive.len() / 10);
    let out = decompress_chunk(&compressed, repetitive.len() as u32).unwrap();
    assert_eq!(out, repetitive);

    // ランダムデータ（xorshift で決定的に生成）も往復する
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut random = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        random.push((state >> 32) as u8);
    }
    let compressed = compress_chunk(&random);
    let out = decompress_chunk(&compressed, random.len() as u32).unwrap();
    assert_eq!(out, random);

    // 空入力
    let compressed = compress_chunk(&[]);
    assert_eq!(decompress_chunk(&compressed, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn zstd_declared_length_mismatch_is_error() {
    let raw = vec![7u8; 1000];
    let compressed = compress_chunk(&raw);
    assert!(matches!(
        decompress_chunk(&compressed, 999),
        Err(TraceError::ZstdDecode(_))
    ));
    assert!(matches!(
        decompress_chunk(&compressed, 1001),
        Err(TraceError::ZstdDecode(_))
    ));
    // Zstd でない入力
    assert!(matches!(
        decompress_chunk(b"definitely not zstd", 19),
        Err(TraceError::ZstdDecode(_))
    ));
}

#[test]
fn decode_payload_variants() {
    let raw = b"payload bytes".to_vec();
    let uncompressed = BlockHeader {
        block_type: BlockType::Schema,
        compression: Compression::None,
        sequence: 0,
        stored_len: raw.len() as u32,
        raw_len: raw.len() as u32,
    };
    assert_eq!(decode_payload(&uncompressed, &raw).unwrap(), raw);
    // 無圧縮で stored != raw は破損
    let bad = BlockHeader {
        raw_len: 3,
        ..uncompressed
    };
    assert!(matches!(
        decode_payload(&bad, &raw),
        Err(TraceError::CorruptBlock { .. })
    ));
    // raw_len 上限超過
    let too_big = BlockHeader {
        compression: Compression::Zstd,
        raw_len: MAX_RAW_LEN + 1,
        stored_len: 0,
        ..uncompressed
    };
    assert!(matches!(
        decode_payload(&too_big, &[]),
        Err(TraceError::CorruptBlock { .. })
    ));
    // Zstd 経路
    let compressed = compress_chunk(&raw);
    let zh = BlockHeader {
        block_type: BlockType::EventChunk,
        compression: Compression::Zstd,
        sequence: 0,
        stored_len: compressed.len() as u32,
        raw_len: raw.len() as u32,
    };
    assert_eq!(decode_payload(&zh, &compressed).unwrap(), raw);
}

#[test]
fn block_type_and_compression_codes() {
    for (ty, code) in [
        (BlockType::Header, 1),
        (BlockType::Environment, 2),
        (BlockType::Schema, 3),
        (BlockType::EventChunk, 4),
        (BlockType::BlobChunk, 5),
        (BlockType::SchemaCheckpoint, 6),
        (BlockType::Index, 7),
        (BlockType::Finalization, 8),
        (BlockType::Loss, 9),
        (BlockType::BlobUpdate, 10),
        (BlockType::ProfileSummary, 11),
    ] {
        assert_eq!(ty.code(), code);
        assert_eq!(BlockType::from_code(code), ty);
        assert!(ty.is_known());
    }
    assert_eq!(BlockType::from_code(200), BlockType::Unknown(200));
    assert!(!BlockType::Unknown(200).is_known());
    assert_eq!(Compression::from_code(0), Some(Compression::None));
    assert_eq!(Compression::from_code(1), Some(Compression::Zstd));
    assert_eq!(Compression::from_code(2), None);
}

// ---------------------------------------------------------------------------
// Compact Binary: 値列
// ---------------------------------------------------------------------------

fn cv(value: TypedValue) -> CapturedValue {
    CapturedValue::captured(value)
}

#[test]
fn values_roundtrip_all_types() {
    let types = vec![
        Ty::I32,
        Ty::I64,
        Ty::U32,
        Ty::U64,
        Ty::F32,
        Ty::F64,
        Ty::Bool,
        Ty::Str,
        Ty::Str16,
        Ty::Bytes,
        Ty::BlobRef,
        Ty::Ptr32,
        Ty::Ptr64,
    ];
    let values = vec![
        cv(TypedValue::I32(i32::MIN)),
        cv(TypedValue::I64(i64::MAX)),
        cv(TypedValue::U32(u32::MAX)),
        cv(TypedValue::U64(u64::MAX)),
        cv(TypedValue::F32Bits(0x7fc0_0001)), // NaN ペイロード
        cv(TypedValue::F64Bits(0xfff8_0000_0000_0001)),
        cv(TypedValue::Bool(true)),
        cv(TypedValue::Str("パス".into())),
        cv(TypedValue::Str16(vec![0x30d1, 0x30b9, 0x0000, 0xd800])),
        cv(TypedValue::Bytes(vec![0, 1, 2, 255])),
        cv(TypedValue::BlobRef(BlobId::from_bytes([7u8; 32]))),
        cv(TypedValue::Ptr32(0xdead_beef)),
        cv(TypedValue::Ptr64(0x0000_7fff_1234_5678)),
    ];
    let encoded = encode_values(&types, &values).unwrap();
    assert_eq!(decode_values(&types, &encoded).unwrap(), values);
}

#[test]
fn values_capture_states_roundtrip() {
    let types = vec![Ty::U64; 6];
    let states = [
        ValueCapture::Captured,
        ValueCapture::Unreadable,
        ValueCapture::Truncated,
        ValueCapture::Unsupported,
        ValueCapture::LimitExceeded,
        ValueCapture::Stale, // F20: 符号化 5
    ];
    let values: Vec<CapturedValue> = states
        .iter()
        .map(|&capture| CapturedValue {
            capture,
            value: TypedValue::U64(0),
        })
        .collect();
    let encoded = encode_values(&types, &values).unwrap();
    assert_eq!(decode_values(&types, &encoded).unwrap(), values);
}

#[test]
fn values_errors() {
    let types = vec![Ty::Bool];
    // bool の値が 2
    assert_eq!(
        decode_values(&types, &[0, 2]),
        Err(CompactError::InvalidBool(2))
    );
    // 取得状態が未知
    assert_eq!(
        decode_values(&types, &[9, 1]),
        Err(CompactError::InvalidCapture(9))
    );
    // 切断
    assert_eq!(decode_values(&types, &[0]), Err(CompactError::Truncated));
    assert_eq!(decode_values(&types, &[]), Err(CompactError::Truncated));
    // 余分なバイト
    assert_eq!(
        decode_values(&types, &[0, 1, 0]),
        Err(CompactError::TrailingBytes(1))
    );
    // 符号化側：個数不一致と型不一致
    assert_eq!(
        encode_values(&types, &[]),
        Err(CompactError::FieldCountMismatch {
            expected: 1,
            actual: 0
        })
    );
    assert_eq!(
        encode_values(&types, &[cv(TypedValue::U64(1))]),
        Err(CompactError::TypeMismatch { field: 0 })
    );
}

#[test]
fn leb128_boundaries() {
    let mut buf = Vec::new();
    write_uleb(&mut buf, u64::MAX);
    assert_eq!(buf.len(), 10);
    let mut cur = Cursor::new(&buf);
    assert_eq!(cur.read_uleb().unwrap(), u64::MAX);
    // zigzag の極値
    for v in [i64::MIN, -1, 0, 1, i64::MAX] {
        let mut buf = Vec::new();
        write_sleb(&mut buf, v);
        let mut cur = Cursor::new(&buf);
        assert_eq!(cur.read_sleb().unwrap(), v);
    }
    // 11 バイトの LEB は不正
    let mut cur = Cursor::new(&[0x80; 11]);
    assert_eq!(cur.read_uleb(), Err(CompactError::Leb128TooLong));
    // 継続ビットが残ったまま終わる入力も不正
    let mut cur = Cursor::new(&[0x80, 0x80]);
    assert_eq!(cur.read_uleb(), Err(CompactError::Leb128TooLong));
}

#[test]
fn decode_compact_entry_point() {
    use shirusu_trace::proto::SchemaSet;
    use shirusu_trace::schema::make_schema;
    let def = make_schema(
        1,
        "api",
        vec![("a".into(), Ty::I32, 0), ("b".into(), Ty::Str, 0)],
    );
    let set = SchemaSet { schemas: vec![def] };
    let values = vec![cv(TypedValue::I32(-7)), cv(TypedValue::Str("x".into()))];
    let encoded = encode_values(&[Ty::I32, Ty::Str], &values).unwrap();
    let decoded = decode_compact(&set.encode(), &encoded).unwrap();
    assert_eq!(decoded, values);
    // 壊れた SchemaSet バイト列
    assert!(decode_compact(&[0xff, 0xff], &encoded).is_err());
    // 空の SchemaSet
    assert!(matches!(
        decode_compact(&SchemaSet::default().encode(), &encoded),
        Err(TraceError::InvalidInput(_))
    ));
    // 未知の型タグを持つ Schema
    let mut bad = make_schema(1, "api", vec![("a".into(), Ty::I32, 0)]);
    bad.fields[0].ty = 99;
    let bad_set = SchemaSet { schemas: vec![bad] };
    assert!(matches!(
        decode_compact(&bad_set.encode(), &encoded),
        Err(TraceError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------------------
// Compact Binary: イベント列
// ---------------------------------------------------------------------------

fn sample_batch() -> EventBatch {
    let blob = BlobId::from_bytes([3u8; 32]);
    EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 3,
        qpc_frequency: 10_000_000,
        events: vec![
            TraceEvent {
                kind: 1,
                sequence: 5,
                timestamp_qpc: 1000,
                call_id: 1,
                parent_call_id: 0,
                api_id: 77,
                schema_id: 0,
                capture: EventCapture::Captured,
                payload: PayloadRef::Blob(blob),
                args: Some(vec![1, 2, 3]),
                global_order: None,
            },
            TraceEvent {
                kind: 2,
                sequence: 5,        // 同一 sequence（欠番なしの再送相当）も許す
                timestamp_qpc: 900, // 時刻は後退し得る（zigzag）
                call_id: 1,
                parent_call_id: 0,
                api_id: 77,
                schema_id: 0,
                capture: EventCapture::Captured,
                payload: PayloadRef::Inline(vec![9, 8]),
                args: None,
                global_order: None,
            },
            TraceEvent {
                kind: 1,
                sequence: 12,
                timestamp_qpc: 2500,
                call_id: 2,
                parent_call_id: 1,
                api_id: 78,
                schema_id: 4,
                capture: EventCapture::DroppedByBackpressure,
                payload: PayloadRef::Dropped {
                    original_len: 1 << 20,
                    reason: PayloadLossReason::Backpressure,
                },
                args: None,
                global_order: None,
            },
            TraceEvent {
                kind: 6,
                sequence: 13,
                timestamp_qpc: 2600,
                call_id: 0,
                parent_call_id: 0,
                api_id: 0,
                schema_id: 0,
                capture: EventCapture::Other(200), // 未知の取得状態は往復で保持
                payload: PayloadRef::None,
                args: None,
                global_order: None,
            },
        ],
    }
}

#[test]
fn event_chunk_roundtrip() {
    let batch = sample_batch();
    let bytes = encode_event_chunk(&batch);
    let decoded = decode_event_chunk(&bytes).unwrap();
    assert_eq!(decoded, batch);
}

#[test]
fn event_chunk_empty_batch_roundtrip() {
    let batch = EventBatch {
        session_id: 1,
        process_id: 0,
        raw_pid: 0,
        thread_id: 0,
        qpc_frequency: 0,
        events: vec![],
    };
    let bytes = encode_event_chunk(&batch);
    assert_eq!(decode_event_chunk(&bytes).unwrap(), batch);
}

#[test]
fn event_chunk_corruption_cases() {
    let batch = sample_batch();
    let bytes = encode_event_chunk(&batch);
    // 末尾に余分なバイト
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode_event_chunk(&extra).is_err());
    // 途中切断
    assert!(decode_event_chunk(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_event_chunk(&[]).is_err());
    assert!(decode_event_chunk(&[0x80]).is_err());
    // payload_tag が未知（最後のイベントの payload_tag 位置を直接壊すのは
    // 脆いので、小さいバッチで組み立てる）
    let one = EventBatch {
        events: vec![TraceEvent {
            kind: 1,
            sequence: 0,
            timestamp_qpc: 0,
            call_id: 0,
            parent_call_id: 0,
            api_id: 0,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
            global_order: None,
        }],
        ..sample_batch()
    };
    let mut b = encode_event_chunk(&one);
    // 末尾から 2 バイト目が payload_tag（最後が args_tag=0）
    let n = b.len();
    b[n - 2] = 9;
    assert!(decode_event_chunk(&b).is_err());
    // args_tag が未知
    let mut b = encode_event_chunk(&one);
    let n = b.len();
    b[n - 1] = 7;
    assert!(decode_event_chunk(&b).is_err());
}
