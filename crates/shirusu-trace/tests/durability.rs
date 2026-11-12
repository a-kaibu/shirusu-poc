//! F21: Writer の永続化設定（`Durability`）。
//!
//! 設定ごとに `sync_all` の呼び出し回数が決まることを、呼び出し回数を
//! 数える書き先で検証する。`Buffered`（既定）は sync しない、
//! `SyncOnFinish` は `finish` 時に 1 回だけ、`SyncPerBlock` は各 Block
//! の書き込み後に 1 回ずつ（＋ `finish` の最終 flush 分 1 回）sync する。

use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::read_trace;
use shirusu_trace::schema::EventCapture;
use shirusu_trace::writer::{
    Durability, DurableWrite, FinalizationInfo, TraceWriter, WriterOptions,
};
use std::cell::Cell;
use std::io::{self, Write};
use std::rc::Rc;

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
        hook_evidence: Vec::new(),
    }
}

fn batch() -> EventBatch {
    EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![TraceEvent {
            kind: 1,
            sequence: 1,
            timestamp_qpc: 1010,
            call_id: 1,
            parent_call_id: 0,
            api_id: 77,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: PayloadRef::Inline(vec![]),
            args: None,
            global_order: None,
        }],
    }
}

/// `sync_all` の呼び出し回数を数えるメモリ上の書き先。
struct CountingWriter {
    inner: Vec<u8>,
    syncs: Rc<Cell<usize>>,
}

impl CountingWriter {
    fn new() -> (Self, Rc<Cell<usize>>) {
        let syncs = Rc::new(Cell::new(0));
        (
            Self {
                inner: Vec::new(),
                syncs: Rc::clone(&syncs),
            },
            syncs,
        )
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl DurableWrite for CountingWriter {
    fn sync_all(&mut self) -> io::Result<()> {
        self.syncs.set(self.syncs.get() + 1);
        Ok(())
    }
}

#[test]
fn buffered_never_syncs() {
    let (w, syncs) = CountingWriter::new();
    let mut writer = TraceWriter::new(w, env(42)).unwrap();
    assert_eq!(syncs.get(), 0);
    writer.write_batch(&batch()).unwrap();
    assert_eq!(syncs.get(), 0);
    let w = writer.finish(FinalizationInfo::default()).unwrap();
    assert_eq!(syncs.get(), 0);
    let trace = read_trace(&w.inner).unwrap();
    assert_eq!(
        trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
        1
    );
    assert!(trace.issues.is_empty());
}

#[test]
fn sync_on_finish_syncs_once_at_finish() {
    let (w, syncs) = CountingWriter::new();
    let options = WriterOptions {
        durability: Durability::SyncOnFinish,
        ..Default::default()
    };
    let mut writer = TraceWriter::with_options(w, env(42), options).unwrap();
    assert_eq!(syncs.get(), 0);
    writer.write_batch(&batch()).unwrap();
    assert_eq!(syncs.get(), 0, "batch 書き込みだけでは sync しない");
    let w = writer.finish(FinalizationInfo::default()).unwrap();
    assert_eq!(syncs.get(), 1, "finish 時にちょうど 1 回 sync する");
    let trace = read_trace(&w.inner).unwrap();
    assert_eq!(
        trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
        1
    );
}

#[test]
fn sync_per_block_syncs_after_each_block() {
    let (w, syncs) = CountingWriter::new();
    let options = WriterOptions {
        durability: Durability::SyncPerBlock,
        ..Default::default()
    };
    let mut writer = TraceWriter::with_options(w, env(42), options).unwrap();
    // Header + Environment の 2 Block。
    assert_eq!(syncs.get(), 2);
    writer.write_batch(&batch()).unwrap();
    // Event Chunk が 1 Block 増える。
    assert_eq!(syncs.get(), 3);
    let w = writer.finish(FinalizationInfo::default()).unwrap();
    // Index + Finalization の 2 Block と、finish の最終 flush 分の sync 1 回。
    assert_eq!(syncs.get(), 6);
    let trace = read_trace(&w.inner).unwrap();
    assert_eq!(
        trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
        1
    );
    assert!(trace.issues.is_empty());
}

#[test]
fn file_sync_on_finish_roundtrip() {
    // `File` の `DurableWrite` 実装（`File::sync_all` への委譲）が
    // 実際に動くことを、実ファイルで確かめる。
    let path = std::env::temp_dir().join(format!(
        "shirusu-durability-{}-{}.trace",
        std::process::id(),
        "sync-on-finish"
    ));
    let file = std::fs::File::create(&path).unwrap();
    let options = WriterOptions {
        durability: Durability::SyncOnFinish,
        ..Default::default()
    };
    let mut writer = TraceWriter::with_options(file, env(42), options).unwrap();
    writer.write_batch(&batch()).unwrap();
    let _file = writer.finish(FinalizationInfo::default()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let trace = read_trace(&bytes).unwrap();
    assert_eq!(
        trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
        1
    );
    assert!(trace.issues.is_empty());
    std::fs::remove_file(&path).unwrap();
}
