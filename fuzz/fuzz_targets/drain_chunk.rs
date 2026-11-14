#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_host::{CommittedRangeCollector, DrainWorker};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::flags;
use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::sync::Arc;
use std::time::Duration;

// Host が写し取った CommittedChunk は対象プロセスが任意に書き換えられる。
// 正規の書き込みと回収で作った Chunk 列を入力の指示どおりに改変し
// （任意の欄・任意の位置のバイト反転、Cursor・Payload 位置のずれ、切り詰め）、
// 検証側に順に与える。panic しないこと、停止が戻らないこと、受理した
// Event の Sequence が狭義単調で Payload 長が Descriptor の格納長と一致する
// ことを確かめる (drain_chunk)。
//
// 入力: [書き込み数 n][n 個の Payload 長（下位 6bit）と回収フラグ（最上位 bit）]
//       [4 バイト単位の改変指示: chunk, 欄, 位置, 値]...
fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = (n as usize % 64).min(rest.len());
    let (writes, edits) = rest.split_at(n);
    let cfg = RingConfig::new(8, 128);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut writer = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let mut collector = unsafe { CommittedRangeCollector::new(region.base(), cfg) };
    let mut chunks = Vec::new();
    for (i, w) in writes.iter().enumerate() {
        let body = vec![i as u8; (w & 0x3f) as usize];
        let _ = writer.write(EventInput {
            kind: EventKind::CallEnter,
            api_id: 1,
            schema_id: 1,
            call_id: i as u64 + 1,
            parent_call_id: 0,
            payload: &body,
            capture_state: CaptureState::Captured,
            global_order: 0,
        });
        if w & 0x80 != 0 {
            if let Some(c) = collector.collect(|| {}) {
                chunks.push(c);
            }
        }
    }
    if let Some(c) = collector.collect(|| {}) {
        chunks.push(c);
    }
    drop(writer);
    drop(region);
    if chunks.is_empty() {
        return;
    }
    for e in edits.chunks_exact(4) {
        let len = chunks.len();
        let c = &mut chunks[e[0] as usize % len];
        let pos = e[2] as usize;
        match e[1] % 8 {
            0 if !c.control.is_empty() => {
                let i = pos % c.control.len();
                c.control[i] ^= e[3];
            }
            1 if !c.descriptors.is_empty() => {
                let i = (pos * 7 + e[3] as usize) % c.descriptors.len();
                c.descriptors[i] ^= e[3] | 1;
            }
            2 if !c.payload.is_empty() => {
                let i = pos % c.payload.len();
                c.payload[i] ^= e[3] | 1;
            }
            3 => c.first_cursor = c.first_cursor.wrapping_add(e[3] as i8 as i64 as u64),
            4 => c.payload_position = c.payload_position.wrapping_add(e[3] as i8 as i64 as u64),
            5 => {
                let keep = c.descriptors.len().saturating_sub(pos);
                c.descriptors.truncate(keep);
            }
            6 => {
                let keep = c.payload.len().saturating_sub(pos);
                c.payload.truncate(keep);
            }
            _ => c.payload.extend(std::iter::repeat_n(e[3], pos % 9)),
        }
    }
    let mut worker = DrainWorker::for_chunks(cfg, 1);
    let mut stopped = false;
    let mut last = 0u64;
    for chunk in &chunks {
        let batch = worker.ingest_chunk(chunk);
        if stopped {
            assert!(batch.events.is_empty(), "accepted after stop");
        }
        for e in &batch.events {
            assert!(e.descriptor.sequence > last);
            last = e.descriptor.sequence;
            let stored = if e.descriptor.flags & flags::PAYLOAD_DROPPED != 0 {
                0
            } else {
                e.descriptor.payload_len as usize
            };
            assert_eq!(e.payload.len(), stored);
        }
        stopped |= worker.is_stopped();
    }
});
