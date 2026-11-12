//! Protobuf 手書きワイヤ形式とメタデータメッセージの単体テスト。
//! 形式の正は docs/trace-format.md のメッセージ定義。

use shirusu_trace::error::ProtoError;
use shirusu_trace::proto::*;

fn sample_env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "shirusu-host 0.1".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        os_build: 26100,
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        capture_config: "level=L2".into(),
        feature_flags: 0b101,
        target_description: "game.exe".into(),
        modules: Vec::new(),
        static_dependencies: Vec::new(),
        hook_evidence: Vec::new(),
    }
}

#[test]
fn environment_roundtrip() {
    let env = sample_env();
    let bytes = env.encode();
    assert_eq!(CaptureEnvironment::decode(&bytes).unwrap(), env);
}

/// L07: モジュール分類付きの Environment の往復と、旧バイト列
/// （field 9 無し）が modules 空として読めること。
#[test]
fn environment_with_modules_roundtrip() {
    use shirusu_trace::module::{classify_module, ModuleEvidence};
    let mut env = sample_env();
    env.modules.push(classify_module(
        &ModuleEvidence::new(r"C:\Windows\System32\kernel32.dll").signed(true),
    ));
    env.modules
        .push(classify_module(&ModuleEvidence::new(r"C:\tools\game.exe")));
    let bytes = env.encode();
    assert_eq!(CaptureEnvironment::decode(&bytes).unwrap(), env);
    let old = sample_env();
    assert!(CaptureEnvironment::decode(&old.encode())
        .unwrap()
        .modules
        .is_empty());
}

#[test]
fn session_metadata_defaults_encode_to_empty() {
    // proto3 の既定値は省略されるため、全て既定のメッセージは空になる。
    assert!(SessionMetadata::default().encode().is_empty());
    assert_eq!(
        SessionMetadata::decode(&[]).unwrap(),
        SessionMetadata::default()
    );
}

#[test]
fn schema_set_roundtrip() {
    let set = SchemaSet {
        schemas: vec![
            SchemaDef {
                schema_id: 1,
                name: "kernel32!CreateFileW".into(),
                content_hash: 0xdead_beef,
                fields: vec![
                    FieldDef {
                        name: "path".into(),
                        ty: 9,
                        flags: 0,
                    },
                    FieldDef {
                        name: "access".into(),
                        ty: 3,
                        flags: 1,
                    },
                ],
                annotation: "v1".into(),
            },
            SchemaDef {
                schema_id: 2,
                name: "ntdll!NtReadFile".into(),
                content_hash: 7,
                fields: vec![],
                annotation: String::new(),
            },
        ],
    };
    let bytes = set.encode();
    assert_eq!(SchemaSet::decode(&bytes).unwrap(), set);
}

#[test]
fn batch_header_roundtrip() {
    let h = BatchHeader {
        session_id: u64::MAX,
        process_id: 3,
        raw_pid: 1234,
        thread_id: 9,
        base_timestamp_qpc: 1 << 60,
        qpc_frequency: 3_579_545,
        first_sequence: 0,
        event_count: 77,
        has_global_order: false,
    };
    let bytes = h.encode();
    assert_eq!(BatchHeader::decode(&bytes).unwrap(), h);
}

#[test]
fn loss_block_roundtrip_all_kinds() {
    let records = vec![
        LossRecord {
            kind: loss_kind::SEQUENCE_GAP,
            count: 5,
            process_id: 1,
            thread_id: 2,
            ..Default::default()
        },
        LossRecord {
            kind: loss_kind::COUNTERS,
            count: 9,
            dropped_payload_bytes: 4096,
            degraded_events: 3,
            process_id: 1,
            thread_id: 2,
            ..Default::default()
        },
        LossRecord {
            kind: loss_kind::UNKNOWN_TERMINATION,
            call_id: 123,
            process_id: 1,
            thread_id: 0,
            ..Default::default()
        },
        LossRecord {
            kind: loss_kind::INTEGRITY_LOST,
            reason: "cursor regressed".into(),
            process_id: 1,
            thread_id: 2,
            ..Default::default()
        },
    ];
    let bytes = encode_loss_block(&records);
    assert_eq!(decode_loss_block(&bytes).unwrap(), records);
    assert!(encode_loss_block(&[]).is_empty());
    assert_eq!(decode_loss_block(&[]).unwrap(), Vec::<LossRecord>::new());
}

#[test]
fn block_index_roundtrip() {
    let index = BlockIndex {
        entries: vec![
            IndexEntry {
                offset: 0,
                block_type: 1,
                sequence: 0,
            },
            IndexEntry {
                offset: 1 << 40,
                block_type: 4,
                sequence: 300,
            },
        ],
    };
    let bytes = index.encode();
    assert_eq!(BlockIndex::decode(&bytes).unwrap(), index);
}

#[test]
fn finalization_roundtrip_incl_empty_note() {
    let fin = Finalization {
        total_events: 100,
        total_blobs: 4,
        total_loss_records: 2,
        capture_coverage: integrity_level::DEGRADED,
        event_integrity: integrity_level::LOST,
        semantic_completeness: integrity_level::UNKNOWN,
        notes: vec!["".into(), "host restarted".into()],
    };
    let bytes = fin.encode();
    let (decoded, cleanly) = Finalization::decode(&bytes).unwrap();
    assert_eq!(decoded, fin);
    // 符号化時は finalized_cleanly が常に true として出る。
    assert!(cleanly);
}

#[test]
fn unknown_fields_are_skipped() {
    let mut bytes = SessionMetadata {
        session_id: 5,
        created_by: String::new(),
        qpc_frequency: 0,
    }
    .encode();
    // 未知フィールド 99 (varint) と 100 (LEN) と 101 (I64) と 102 (I32) を追加。
    let mut extra = ProtoWriter::new();
    extra.u64_field(99, 777);
    extra.bytes_field(100, b"future");
    bytes.extend_from_slice(extra.as_slice());
    let mut raw = bytes.clone();
    // I64 フィールドを手で組む（key + 8 バイト）
    raw.push(((101u8) << 3) | 1);
    raw.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    // I32 フィールド（key + 4 バイト）
    raw.push(((102u8) << 3) | 5);
    raw.extend_from_slice(&[9, 10, 11, 12]);
    let decoded = SessionMetadata::decode(&raw).unwrap();
    assert_eq!(decoded.session_id, 5);
}

#[test]
fn field_number_zero_is_invalid() {
    // key = 0 は field 0 / wire 0。
    assert_eq!(
        SessionMetadata::decode(&[0x00, 0x01]),
        Err(ProtoError::InvalidFieldNumber)
    );
}

#[test]
fn group_wire_types_are_invalid() {
    // field 1, wire 3 (start group)
    assert_eq!(
        SessionMetadata::decode(&[0x0b, 0x00]),
        Err(ProtoError::InvalidWireType(3))
    );
    // field 1, wire 7
    assert!(matches!(
        SessionMetadata::decode(&[0x0f, 0x00]),
        Err(ProtoError::InvalidWireType(7))
    ));
}

#[test]
fn varint_too_long_is_invalid() {
    // field 1 の varint が 11 バイト続く
    let mut buf = vec![0x08];
    buf.extend(std::iter::repeat_n(0x80, 10));
    buf.push(0x01);
    assert_eq!(
        SessionMetadata::decode(&buf),
        Err(ProtoError::VarintTooLong)
    );
    // 10 バイト目が 2 以上（u64 に収まらない）
    let mut buf = vec![0x08];
    buf.extend(std::iter::repeat_n(0xff, 9));
    buf.push(0x02);
    assert_eq!(
        SessionMetadata::decode(&buf),
        Err(ProtoError::VarintTooLong)
    );
}

#[test]
fn length_beyond_remaining_is_invalid() {
    // field 2 (string) に長さ 100 を宣言するが 2 バイトしかない
    let buf = [0x12, 0x64, b'a', b'b'];
    assert!(matches!(
        SessionMetadata::decode(&buf),
        Err(ProtoError::LengthOutOfRange { .. })
    ));
}

#[test]
fn invalid_utf8_string_is_invalid() {
    // field 2 (string) に不正な UTF-8
    let buf = [0x12, 0x02, 0xff, 0xfe];
    assert_eq!(SessionMetadata::decode(&buf), Err(ProtoError::InvalidUtf8));
}

#[test]
fn truncated_fixed_width_skip_is_invalid() {
    // 未知フィールド 50 を I64 として宣言するが 3 バイトしか残っていない
    let mut buf = SessionMetadata {
        session_id: 1,
        ..Default::default()
    }
    .encode();
    buf.push(((50u8) << 3) | 1);
    buf.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        SessionMetadata::decode(&buf),
        Err(ProtoError::TruncatedFixed)
    );
}

#[test]
fn varint_max_u64_roundtrip() {
    let m = SessionMetadata {
        session_id: u64::MAX,
        created_by: String::new(),
        qpc_frequency: u64::MAX,
    };
    let bytes = m.encode();
    assert_eq!(SessionMetadata::decode(&bytes).unwrap(), m);
}

#[test]
fn wrong_wire_type_for_known_field_is_skipped_not_fatal() {
    // session_id (field 1) を LEN として送る。他実装が書いた想定外の
    // 形でも、未知フィールド扱いで読み飛ばし全体は壊れない。
    let mut w = ProtoWriter::new();
    w.bytes_field(1, &[1, 2, 3]);
    w.u64_field(3, 55);
    let decoded = SessionMetadata::decode(w.as_slice()).unwrap();
    assert_eq!(decoded.session_id, 0);
    assert_eq!(decoded.qpc_frequency, 55);
}

/// L09: ProfileSummary の往復（空と複数 API）。0 の min/max は
/// 「呼び出し無し」を表し、proto3 の既定値省略と一致する。
#[test]
fn profile_summary_roundtrip() {
    let summary = ProfileSummary {
        qpc_frequency: 10_000_000,
        total_events_seen: 6,
        apis: vec![
            ApiProfile {
                api_id: 1,
                calls: 2,
                enters: 3,
                leaves: 2,
                total_duration_qpc: 500,
                min_duration_qpc: 100,
                max_duration_qpc: 400,
            },
            ApiProfile {
                api_id: 2,
                calls: 0,
                enters: 1,
                leaves: 0,
                total_duration_qpc: 0,
                min_duration_qpc: 0,
                max_duration_qpc: 0,
            },
        ],
    };
    let bytes = summary.encode();
    assert_eq!(ProfileSummary::decode(&bytes).unwrap(), summary);
    let empty = ProfileSummary::default();
    assert_eq!(ProfileSummary::decode(&empty.encode()).unwrap(), empty);
}

#[test]
fn environment_hook_evidence_roundtrips_and_is_optional() {
    use shirusu_trace::proto::{CaptureEnvironment, HookEvidence};
    let old = CaptureEnvironment::default();
    let mut current = old.clone();
    current.hook_evidence.push(HookEvidence {
        api_id: 2,
        module: "kernel32.dll".into(),
        function: "ReadFile".into(),
        method: "inline".into(),
        outcome: "not-installed".into(),
        reason: "thread-set-changed".into(),
        scope: "resolved-exports-at-initialization".into(),
        semantic_level: 2,
        semantic_detail: "synchronous output only".into(),
    });
    assert_eq!(
        CaptureEnvironment::decode(&current.encode()).unwrap(),
        current
    );
    assert!(CaptureEnvironment::decode(&old.encode())
        .unwrap()
        .hook_evidence
        .is_empty());
    current.hook_evidence.clear();
    assert_eq!(current.encode(), old.encode());
}
