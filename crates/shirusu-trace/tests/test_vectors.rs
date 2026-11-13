//! 言語非依存テストベクター：最小 Trace をバイト列として手で組み立て、
//! Reader の復号結果と突き合わせる。Writer / Protobuf 実装を経由しない
//! 経路で組み立てることで、符号化側と復号側が同じ誤りを共有して
//! 「往復は通るが形式が違う」事態を防ぐ。
//!
//! CRC32C だけは転送側と共用する検証済み実装（shirusu-crc32c）を
//! 使う。形式仕様上の正は docs/trace-format.md と本ベクターである。

use shirusu_trace::model::PayloadRef;
use shirusu_trace::reader::read_trace;
use shirusu_trace::schema::EventCapture;

fn uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Block を手組みする（shirusu_trace::container を使わない）。
fn block(sequence: u64, block_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(b"SBLK");
    h[4] = block_type;
    h[5] = 0; // 無圧縮
    h[6..8].copy_from_slice(&32u16.to_le_bytes());
    h[8..16].copy_from_slice(&sequence.to_le_bytes());
    h[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    h[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let crc = shirusu_crc32c::crc32c_update(shirusu_crc32c::crc32c(&h), payload);
    h[24..28].copy_from_slice(&crc.to_le_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(payload);
    out
}

fn file_header_payload(session_id: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"SHIRUSU\0TR");
    p.extend_from_slice(&1u16.to_le_bytes()); // container_version
    p.extend_from_slice(&1u16.to_le_bytes()); // schema_version
    p.extend_from_slice(&0u16.to_le_bytes()); // header_flags
    p.extend_from_slice(&session_id.to_le_bytes());
    assert_eq!(p.len(), 24);
    p
}

/// 最小 Trace：Header + Environment + Event Chunk（イベント 1 件）。
/// Finalization は付けない（未完の Trace として読めることも確かめる）。
fn minimal_trace() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&block(0, 1, &file_header_payload(42)));
    // CaptureEnvironment：session = SessionMetadata{42, "vec", 10_000_000}
    let mut session = Vec::new();
    session.push(0x08); // field 1 varint
    uleb(&mut session, 42);
    session.push(0x12); // field 2 string
    uleb(&mut session, 3);
    session.extend_from_slice(b"vec");
    session.push(0x18); // field 3 varint
    uleb(&mut session, 10_000_000);
    let mut env = Vec::new();
    env.push(0x0a); // field 1 LEN
    uleb(&mut env, session.len() as u64);
    env.extend_from_slice(&session);
    env.push(0x22); // field 4 string (cpu_arch)
    uleb(&mut env, 6);
    env.extend_from_slice(b"x86_64");
    out.extend_from_slice(&block(1, 2, &env));
    // Event Chunk：BatchHeader + イベント 1 件
    let mut bh = Vec::new();
    bh.push(0x08);
    uleb(&mut bh, 42); // session_id
    bh.push(0x10);
    uleb(&mut bh, 7); // process_id
    bh.push(0x18);
    uleb(&mut bh, 1234); // raw_pid
    bh.push(0x20);
    uleb(&mut bh, 3); // thread_id
    bh.push(0x28);
    uleb(&mut bh, 1000); // base_timestamp_qpc
    bh.push(0x30);
    uleb(&mut bh, 10_000_000); // qpc_frequency
    bh.push(0x38);
    uleb(&mut bh, 5); // first_sequence
    bh.push(0x40);
    uleb(&mut bh, 1); // event_count
    let mut chunk = Vec::new();
    uleb(&mut chunk, bh.len() as u64);
    chunk.extend_from_slice(&bh);
    // イベント：seq_delta 0, ts_delta 0, kind=CallEnter(1), call_id 9,
    // parent 0, api_id 77, schema_id 0, capture 0, payload なし, args なし
    chunk.extend_from_slice(&[0, 0, 1, 9, 0, 77, 0, 0, 0, 0]);
    out.extend_from_slice(&block(2, 4, &chunk));
    out
}

#[test]
fn minimal_trace_vector_decodes() {
    let bytes = minimal_trace();
    let trace = read_trace(&bytes).expect("hand-built trace must decode");
    assert_eq!(trace.header.session_id, 42);
    assert_eq!(trace.header.container_version, 1);
    assert_eq!(trace.header.schema_version, 1);
    let env = trace.environment.as_ref().expect("environment");
    assert_eq!(env.session.session_id, 42);
    assert_eq!(env.session.created_by, "vec");
    assert_eq!(env.session.qpc_frequency, 10_000_000);
    assert_eq!(env.cpu_arch, "x86_64");
    assert_eq!(trace.batches.len(), 1);
    let batch = &trace.batches[0];
    assert_eq!(batch.process_id, 7);
    assert_eq!(batch.raw_pid, 1234);
    assert_eq!(batch.thread_id, 3);
    assert_eq!(batch.qpc_frequency, 10_000_000);
    assert_eq!(batch.events.len(), 1);
    let e = &batch.events[0];
    assert_eq!(e.kind, 1);
    assert_eq!(e.sequence, 5);
    assert_eq!(e.timestamp_qpc, 1000);
    assert_eq!(e.call_id, 9);
    assert_eq!(e.parent_call_id, 0);
    assert_eq!(e.api_id, 77);
    assert_eq!(e.schema_id, 0);
    assert_eq!(e.capture, EventCapture::Captured);
    assert_eq!(e.payload, PayloadRef::None);
    assert_eq!(e.args, None);
    assert!(trace.finalization.is_none());
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
}

#[test]
fn header_only_trace_vector() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&block(0, 1, &file_header_payload(7)));
    let trace = read_trace(&bytes).expect("header-only trace must decode");
    assert_eq!(trace.header.session_id, 7);
    assert!(trace.batches.is_empty());
    assert!(trace.environment.is_none());
    assert!(trace.finalization.is_none());
    assert!(trace.issues.is_empty());
}

#[test]
fn vector_with_wrong_crc_is_rejected() {
    let mut bytes = minimal_trace();
    // 3 つ目の Block（Event Chunk）の開始位置を実測し、その stored_crc を壊す
    // → その Block は破損として隔離される
    let mut pos = 0usize;
    for _ in 0..2 {
        let len = u32::from_le_bytes(bytes[pos + 16..pos + 20].try_into().unwrap()) as usize;
        pos += 32 + len;
    }
    bytes[pos + 24] ^= 0xff; // stored_crc を壊す
    let trace = read_trace(&bytes).expect("trace with one bad block still reads");
    assert!(trace.batches.is_empty());
    assert!(trace
        .issues
        .iter()
        .any(|i| matches!(i, shirusu_trace::RecoveryIssue::CorruptBlock { offset, .. } if *offset == pos as u64)));
}
