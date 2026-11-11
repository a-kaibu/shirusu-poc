//! L11 `--order=global`: 全体順序番号の Compact Binary 符号化と
//! Writer の不変条件テスト。
//!
//! - Batch 内で全件 Some なら BatchHeader に旗を立て、args の後に
//!   差分（先頭は絶対値）を ULEB128 で 1 個書く。
//! - 全件 None なら旧形式と同じバイト列になり、旧ファイルも読める。
//! - 混在・非増加は Writer が拒否し、破損した差分は Reader が拒否する。

use shirusu_trace::compact::{decode_event_chunk, encode_event_chunk};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{BatchHeader, CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::read_trace;
use shirusu_trace::schema::EventCapture;
use shirusu_trace::writer::{DurableWrite, FinalizationInfo};
use shirusu_trace::TraceWriter;
use std::sync::{Arc, Mutex};

fn env(session_id: u64) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by: "shirusu-host test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        os_build: 26100,
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        capture_config: "L2".into(),
        feature_flags: 3,
        target_description: "game.exe".into(),
        modules: Vec::new(),
        static_dependencies: Vec::new(),
    }
}

fn event(seq: u64, global_order: Option<u64>) -> TraceEvent {
    TraceEvent {
        kind: 1,
        sequence: seq,
        timestamp_qpc: 1000 + seq * 10,
        call_id: seq,
        parent_call_id: 0,
        api_id: 77,
        schema_id: 0,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: None,
        global_order,
    }
}

fn batch(events: Vec<TraceEvent>) -> EventBatch {
    EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 3,
        qpc_frequency: 10_000_000,
        events,
    }
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl DurableWrite for SharedBuf {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl SharedBuf {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

fn orders(b: &EventBatch) -> Vec<Option<u64>> {
    b.events.iter().map(|e| e.global_order).collect()
}

#[test]
fn compact_roundtrip_with_global_order() {
    let b = batch(vec![
        event(1, Some(5)),
        event(2, Some(9)),
        event(3, Some(10)),
    ]);
    let bytes = encode_event_chunk(&b);
    let back = decode_event_chunk(&bytes).unwrap();
    assert_eq!(orders(&back), vec![Some(5), Some(9), Some(10)]);
}

#[test]
fn compact_roundtrip_without_global_order_matches_old_format() {
    let b = batch(vec![event(1, None), event(2, None)]);
    let bytes = encode_event_chunk(&b);
    // 旗が立たないのでイベント列に全体順序の欄は無く、旧ファイルと同じ形で読める。
    let back = decode_event_chunk(&bytes).unwrap();
    assert_eq!(orders(&back), vec![None, None]);
    // 再符号化しても同じバイト列になる（旧形式との往復が安定）。
    assert_eq!(encode_event_chunk(&back), bytes);
}

#[test]
fn compact_rejects_equal_or_decreasing_global_order() {
    // 同値: 差分 0 は破損
    let b = batch(vec![event(1, Some(5)), event(2, Some(5))]);
    assert!(decode_event_chunk(&encode_event_chunk(&b)).is_err());
    // 減少: 差分が折り返して overflow するので破損
    let b = batch(vec![event(1, Some(10)), event(2, Some(9))]);
    assert!(decode_event_chunk(&encode_event_chunk(&b)).is_err());
}

#[test]
fn batch_header_flag_roundtrips_and_old_bytes_read_as_false() {
    let mut h = BatchHeader {
        session_id: 1,
        process_id: 2,
        raw_pid: 3,
        thread_id: 4,
        base_timestamp_qpc: 5,
        qpc_frequency: 6,
        first_sequence: 7,
        event_count: 8,
        has_global_order: true,
    };
    assert_eq!(BatchHeader::decode(&h.encode()).unwrap(), h);
    // field 9 の無い旧バイト列は false として読む。
    h.has_global_order = false;
    assert_eq!(BatchHeader::decode(&h.encode()).unwrap(), h);
}

#[test]
fn writer_rejects_mixed_global_order() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let b = batch(vec![event(1, Some(1)), event(2, None)]);
    assert!(w.write_batch(&b).is_err());
}

#[test]
fn writer_rejects_nonincreasing_global_order() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let b = batch(vec![event(1, Some(3)), event(2, Some(2))]);
    assert!(w.write_batch(&b).is_err());
    let b = batch(vec![event(1, Some(3)), event(2, Some(3))]);
    assert!(w.write_batch(&b).is_err());
}

#[test]
fn writer_roundtrip_preserves_global_order() {
    let buf = SharedBuf::default();
    let mut w = TraceWriter::new(buf.clone(), env(42)).unwrap();
    w.write_batch(&batch(vec![
        event(1, Some(11)),
        event(2, Some(12)),
        event(3, Some(20)),
    ]))
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap();
    let trace = read_trace(&buf.bytes()).unwrap();
    assert_eq!(trace.batches.len(), 1);
    assert_eq!(
        orders(&trace.batches[0]),
        vec![Some(11), Some(12), Some(20)]
    );
}
