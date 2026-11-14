//! ディスク満杯でも Trace を閉じられること（2026-11-14 レビュー P2-10）。

use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::EventCapture;
use shirusu_trace::writer::{
    is_storage_full, DurableWrite, FinalizationInfo, TraceWriter, WriterOptions,
    FINAL_RESERVE_BYTES,
};
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

/// A file on a volume with `capacity` bytes, like NTFS: space is taken by
/// writes past the allocated end and by `reserve_to`.
struct Disk {
    data: Rc<RefCell<Vec<u8>>>,
    pos: usize,
    capacity: usize,
}

impl Write for Disk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut data = self.data.borrow_mut();
        let room = self.capacity.saturating_sub(self.pos);
        if room == 0 {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"));
        }
        let n = room.min(buf.len());
        let end = self.pos + n;
        if data.len() < end {
            data.resize(end, 0);
        }
        data[self.pos..end].copy_from_slice(&buf[..n]);
        self.pos = end;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableWrite for Disk {
    fn sync_all(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn truncate_to(&mut self, len: u64) -> io::Result<bool> {
        self.data.borrow_mut().truncate(len as usize);
        self.pos = len as usize;
        Ok(true)
    }
    fn reserve_to(&mut self, len: u64) -> io::Result<bool> {
        if len as usize > self.capacity {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"));
        }
        let mut data = self.data.borrow_mut();
        if data.len() < len as usize {
            data.resize(len as usize, 0);
        }
        Ok(true)
    }
}

fn env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "storage full test".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    }
}

fn batch(seq: u64, blob: shirusu_trace::BlobId) -> EventBatch {
    EventBatch {
        session_id: 42,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![TraceEvent {
            kind: 1,
            sequence: seq,
            timestamp_qpc: seq,
            call_id: seq,
            parent_call_id: 0,
            api_id: 1,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: PayloadRef::Blob(blob),
            args: None,
            global_order: None,
        }],
    }
}

/// Incompressible bytes, different for every `seed`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn a_full_disk_still_gets_a_finalized_trace() {
    let data = Rc::new(RefCell::new(Vec::new()));
    let capacity = 8 * 1024 * 1024;
    let disk = Disk {
        data: data.clone(),
        pos: 0,
        capacity,
    };
    let options = WriterOptions {
        reserve_bytes: 2 * FINAL_RESERVE_BYTES,
        ..Default::default()
    };
    let mut w = TraceWriter::with_options(disk, env(), options).unwrap();
    let mut written = 0u64;
    let error = loop {
        let blob = w.add_payload(&noise(written + 1, 64 * 1024)).unwrap();
        match w.write_batch(&batch(written + 1, blob)) {
            Ok(()) => written += 1,
            Err(e) => break e,
        }
        assert!(written < 1000, "the disk never filled up");
    };
    assert!(is_storage_full(&error), "{error}");
    assert!(written > 0);
    w.finish(FinalizationInfo {
        event_integrity: 2,
        notes: vec!["storage full".into()],
        ..Default::default()
    })
    .expect("finalization fits in the reserve");
    let bytes = data.borrow().clone();
    assert!(bytes.len() <= capacity);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.finalized_cleanly, "issues: {:?}", trace.issues);
    assert!(trace.issues.is_empty(), "no zero tail: {:?}", trace.issues);
    let events: usize = trace.batches.iter().map(|b| b.events.len()).sum();
    assert!(events as u64 <= written);
}

#[test]
fn a_failed_write_leaves_the_writer_at_a_block_boundary() {
    // Without a reservation the disk fills mid-block: the partial block is
    // discarded and Finalization is attempted from the last whole block.
    let data = Rc::new(RefCell::new(Vec::new()));
    let disk = Disk {
        data: data.clone(),
        pos: 0,
        capacity: 300 * 1024,
    };
    let mut w = TraceWriter::new(disk, env()).unwrap();
    let mut seq = 0u64;
    let error = loop {
        seq += 1;
        let blob = w.add_payload(&noise(seq, 64 * 1024)).unwrap();
        if let Err(e) = w.write_batch(&batch(seq, blob)) {
            break e;
        }
    };
    assert!(is_storage_full(&error));
    let len_after_failure = data.borrow().len();
    let trace = shirusu_trace::read_trace(&data.borrow()).unwrap();
    assert!(trace.issues.is_empty(), "no torn block: {:?}", trace.issues);
    assert!(len_after_failure < 300 * 1024);
}

#[test]
fn an_unfinished_reserved_trace_is_still_readable() {
    // A Host crash leaves the reserved zero tail behind.
    let data = Rc::new(RefCell::new(Vec::new()));
    let disk = Disk {
        data: data.clone(),
        pos: 0,
        capacity: 16 * 1024 * 1024,
    };
    let options = WriterOptions {
        reserve_bytes: 2 * FINAL_RESERVE_BYTES,
        ..Default::default()
    };
    let mut w = TraceWriter::with_options(disk, env(), options).unwrap();
    let blob = w.add_payload(&noise(1, 1024)).unwrap();
    w.write_batch(&batch(1, blob)).unwrap();
    drop(w);
    let bytes = data.borrow().clone();
    assert!(bytes.len() as u64 >= 2 * FINAL_RESERVE_BYTES, "reserved");
    let trace = shirusu_trace::read_trace(&bytes).expect("readable");
    assert!(trace.finalization.is_none());
    assert_eq!(
        trace.batches.iter().map(|b| b.events.len()).sum::<usize>(),
        1
    );
}
