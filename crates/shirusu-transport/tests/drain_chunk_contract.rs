//! `ValidatingReader::drain_chunk`（Host が写し取った確定分の検証）と
//! `RingReader::drain`（共有メモリを直接読む多層防御つき回収）の契約。
//!
//! 1. 差分検査: 同じ Ring の同じ範囲を両方で読み、取り出した Event、
//!    Sequence 欠番、読み位置（Cursor・Payload 位置）が一致すること。
//!    欠番と受理件数の合計が最後の Sequence と一致すること（モデル）。
//! 2. Chunk の各検査を 1 つずつ破り、期待どおりの理由で止まること。
//!    境界値（ちょうど容量、ちょうど書込み済み位置）は受理すること。
//! 3. `RingReader` の Descriptor 検査（種別、global_order、落とした元の長さ）。
//!
//! Host の `CommittedRangeCollector` と同じ手順で Chunk を作る（Host crate に
//! 依存せず、Transport 単体のテストで `drain_chunk` を検証するため）。

use proptest::prelude::*;
use shirusu_transport::clock::{ManualClock, ManualTimestampSource};
use shirusu_transport::descriptor::{flags, CaptureState, EventDescriptor, EventKind};
use shirusu_transport::layout::{self, CONTROL_SIZE};
use shirusu_transport::ring::{EventInput, RingReader, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::validate::{CommittedChunk, IntegrityError, KnownConfig, ValidatingReader};
use shirusu_transport::{Clock, RingConfig};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

struct Rig {
    cfg: RingConfig,
    region: SharedRegion,
    writer: RingWriter,
    reader: RingReader,
}

fn rig(cfg: RingConfig, wait: bool) -> Rig {
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let ts = Arc::new(ManualTimestampSource::new(100, 10_000_000));
    let policy = WriterPolicy {
        max_wait: if wait {
            Duration::from_micros(100)
        } else {
            Duration::ZERO
        },
        ..Default::default()
    };
    let writer = unsafe { region.writer_with_timestamps(policy, clock, ts) };
    let reader = unsafe { region.reader() };
    Rig {
        cfg,
        region,
        writer,
        reader,
    }
}

impl Rig {
    fn write(&mut self, len: usize, order: u64, tag: u8) {
        let payload: Vec<u8> = (0..len).map(|j| tag.wrapping_add(j as u8)).collect();
        self.writer.write(EventInput {
            kind: EventKind::CallEnter,
            api_id: 3,
            schema_id: 4,
            call_id: tag as u64 + 1,
            parent_call_id: 0,
            payload: &payload,
            capture_state: CaptureState::Captured,
            global_order: order,
        });
    }
    fn known(&self) -> KnownConfig {
        KnownConfig::new(self.cfg, self.cfg.required_len())
    }
    fn load(&self, off: usize) -> u64 {
        layout::load(self.region.base(), off, Ordering::Acquire)
    }
    /// Host の回収と同じ手順: Control を写し、`[read_cursor, +max)` の
    /// Descriptor と、最後の Descriptor の格納終端までの Payload を写す。
    fn chunk(&self, read_cursor: u64, payload_read: u64, max: usize) -> CommittedChunk {
        let image = self.region.as_slice();
        let control = image[..CONTROL_SIZE].to_vec();
        let wc = self.load(layout::OFF_WRITE_CURSOR);
        let count = (wc - read_cursor).min(max as u64);
        let cap = self.cfg.descriptor_capacity as u64;
        let mut descriptors = Vec::new();
        for c in read_cursor..read_cursor + count {
            let off = self.cfg.descriptors_offset() + ((c % cap) as usize) * 64;
            descriptors.extend_from_slice(&image[off..off + 64]);
        }
        let mut payload = Vec::new();
        if count > 0 {
            let last = EventDescriptor::from_bytes(&descriptors[descriptors.len() - 64..]).unwrap();
            let stored = if last.payload_dropped() {
                0
            } else {
                last.payload_len as u64
            };
            let end = last.payload_position + stored;
            let pcap = self.cfg.payload_capacity as u64;
            for p in payload_read..end {
                payload.push(image[self.cfg.payload_offset() + (p % pcap) as usize]);
            }
        }
        CommittedChunk {
            control,
            first_cursor: read_cursor,
            descriptors,
            payload_position: payload_read,
            payload,
        }
    }
    fn full_chunk(&self) -> CommittedChunk {
        self.chunk(0, 0, usize::MAX)
    }
}

#[derive(Debug, Clone)]
enum Op {
    Write { len: usize, order: u64 },
    Drain(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0usize..70, 1u64..4).prop_map(|(len, order)| Op::Write { len, order }),
        2 => (0usize..6).prop_map(Op::Drain),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("SHIRUSU_PBT_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256)
    ))]

    #[test]
    fn drain_chunk_agrees_with_ring_reader(
        ops in proptest::collection::vec(op(), 0..100),
        desc in 2usize..8,
        pay in 16usize..160,
        global in any::<bool>(),
    ) {
        let cfg = RingConfig::new(desc, pay);
        let mut r = rig(cfg, false);
        if global {
            r.reader = unsafe { r.region.reader() }.with_global_order(true);
        }
        let mut vr = ValidatingReader::new(r.known(), 1);
        vr.set_global_order(global);
        let mut received = 0u64;
        let mut gaps = 0u64;
        let mut last_sequence = 0u64;
        for (i, op) in ops.iter().enumerate() {
            match *op {
                Op::Write { len, order } => {
                    r.write(len, if global { order } else { 0 }, i as u8)
                }
                Op::Drain(n) => {
                    let chunk = r.chunk(vr.read_cursor(), vr.payload_read_position(), n);
                    prop_assert_eq!(chunk.descriptor_count(), chunk.descriptors.len() / 64);
                    prop_assert_eq!(
                        chunk.owned_bytes(),
                        chunk.control.len() + chunk.descriptors.len() + chunk.payload.len()
                    );
                    let from_chunk = vr.drain_chunk(&chunk);
                    prop_assert!(from_chunk.is_ok(), "op {}: {:?}", i, from_chunk);
                    let from_chunk = from_chunk.unwrap();
                    let batch = r.reader.drain(n);
                    prop_assert_eq!(&batch.integrity_error, &None);
                    prop_assert_eq!(&from_chunk, &batch.events, "op {} events", i);
                    let chunk_gaps = vr.take_sequence_gaps();
                    prop_assert_eq!(chunk_gaps, batch.sequence_gaps, "op {} gaps", i);
                    prop_assert_eq!(vr.take_sequence_gaps(), 0, "gaps are taken once");
                    prop_assert_eq!(vr.read_cursor(), r.reader.read_cursor());
                    prop_assert_eq!(vr.read_cursor(), r.load(layout::OFF_READ_CURSOR));
                    prop_assert_eq!(
                        vr.payload_read_position(),
                        r.load(layout::OFF_PAYLOAD_READ_POSITION),
                        "op {} payload read position", i
                    );
                    received += from_chunk.len() as u64;
                    gaps += chunk_gaps;
                    if let Some(e) = from_chunk.last() {
                        last_sequence = e.descriptor.sequence;
                    }
                    for e in &from_chunk {
                        let stored = if e.descriptor.payload_dropped() { 0 } else { e.descriptor.payload_len as usize };
                        prop_assert_eq!(e.payload.len(), stored);
                    }
                }
            }
        }
        // 受理した Event と欠番で、最後に受理した Sequence までを過不足なく数える。
        prop_assert_eq!(received + gaps, last_sequence);
        prop_assert!(!vr.is_stopped());
    }
}

/// 3 件（Payload 10・0・20 バイト）を書いた Ring。
fn three_events() -> Rig {
    let mut r = rig(RingConfig::new(4, 64), false);
    r.write(10, 0, 1);
    r.write(0, 0, 2);
    r.write(20, 0, 3);
    r
}

fn rejects(r: &Rig, chunk: &CommittedChunk, check: impl Fn(&IntegrityError) -> bool) {
    let mut vr = ValidatingReader::new(r.known(), 1);
    let err = vr.drain_chunk(chunk).expect_err("chunk must be rejected");
    assert!(check(&err), "unexpected error {err:?}");
    assert!(vr.is_stopped());
    assert_eq!(
        vr.drain_chunk(&r.full_chunk()),
        Err(IntegrityError::RingStopped)
    );
}

#[test]
fn untouched_chunk_is_accepted_whole() {
    let r = three_events();
    let mut vr = ValidatingReader::new(r.known(), 1);
    let events = vr.drain_chunk(&r.full_chunk()).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events.iter().map(|e| e.payload.len()).collect::<Vec<_>>(),
        [10, 0, 20]
    );
    assert_eq!(events[2].payload[0], 3);
    assert_eq!(vr.read_cursor(), 3);
    assert_eq!(vr.payload_read_position(), 30);
    assert_eq!(vr.take_sequence_gaps(), 0);
}

#[test]
fn mapping_exactly_required_len_is_accepted_and_shorter_is_not() {
    let r = three_events();
    let mut ok = ValidatingReader::new(KnownConfig::new(r.cfg, r.cfg.required_len()), 1);
    assert!(ok.drain_chunk(&r.full_chunk()).is_ok());
    let mut short = ValidatingReader::new(KnownConfig::new(r.cfg, r.cfg.required_len() - 1), 1);
    assert_eq!(
        short.drain_chunk(&r.full_chunk()),
        Err(IntegrityError::ImageTooSmall)
    );
    assert!(short.is_stopped());
}

#[test]
fn chunk_from_another_generation_is_rejected() {
    let r = three_events();
    let mut vr = ValidatingReader::new(r.known(), 2);
    assert!(matches!(
        vr.drain_chunk(&r.full_chunk()),
        Err(IntegrityError::GenerationMismatch {
            expected: 2,
            found: 1
        })
    ));
}

#[test]
fn chunk_must_continue_both_read_positions() {
    let r = three_events();
    let mut c = r.full_chunk();
    c.first_cursor = 1;
    rejects(&r, &c, |e| {
        matches!(e, IntegrityError::CursorRegressed { .. })
    });
    let mut c = r.full_chunk();
    c.payload_position = 1;
    rejects(&r, &c, |e| {
        matches!(e, IntegrityError::CursorRegressed { .. })
    });
}

#[test]
fn partial_descriptor_bytes_are_rejected() {
    let r = three_events();
    let mut c = r.full_chunk();
    c.descriptors.pop();
    rejects(&r, &c, |e| *e == IntegrityError::ImageTooSmall);
}

#[test]
fn descriptors_beyond_the_write_cursor_are_rejected() {
    let r = three_events();
    let mut c = r.full_chunk();
    let extra = c.descriptors[128..192].to_vec();
    c.descriptors.extend_from_slice(&extra);
    rejects(&r, &c, |e| {
        matches!(
            e,
            IntegrityError::CursorRegressed {
                which: "chunk beyond committed descriptors"
            }
        )
    });
}

#[test]
fn chunk_of_exactly_capacity_is_accepted_and_more_is_not() {
    let mut r = rig(RingConfig::new(4, 64), false);
    for i in 0..4 {
        r.write(4, 0, i);
    }
    let mut vr = ValidatingReader::new(r.known(), 1);
    assert_eq!(vr.drain_chunk(&r.full_chunk()).unwrap().len(), 4);

    // 1 件回収して 1 件書けば write_cursor = 5。新しい Reader に 5 件を渡す
    // （内容は見る前に件数で弾かれる）。
    let mut r = rig(RingConfig::new(4, 64), false);
    for i in 0..4 {
        r.write(4, 0, i);
    }
    assert_eq!(r.reader.drain(1).events.len(), 1);
    r.write(4, 0, 9);
    assert_eq!(r.load(layout::OFF_WRITE_CURSOR), 5);
    let mut c = r.chunk(0, 0, 4);
    let extra = c.descriptors[..64].to_vec();
    c.descriptors.extend_from_slice(&extra);
    rejects(&r, &c, |e| {
        matches!(
            e,
            IntegrityError::CursorRegressed {
                which: "chunk beyond committed descriptors"
            }
        )
    });
}

#[test]
fn payload_filling_the_whole_capacity_is_accepted() {
    let mut r = rig(RingConfig::new(4, 64), false);
    r.write(32, 0, 1);
    r.write(32, 0, 2);
    let c = r.full_chunk();
    assert_eq!(c.payload.len(), 64);
    let mut vr = ValidatingReader::new(r.known(), 1);
    let events = vr.drain_chunk(&c).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(vr.payload_read_position(), 64);
}

#[test]
fn payload_longer_than_capacity_is_rejected() {
    let r = three_events();
    let mut c = r.full_chunk();
    c.payload.resize(65, 0);
    rejects(&r, &c, |e| *e == IntegrityError::PayloadRangeInvalid);
}

#[test]
fn payload_beyond_the_write_position_is_rejected() {
    let r = three_events();
    let mut c = r.full_chunk();
    c.payload.push(0);
    rejects(&r, &c, |e| {
        matches!(
            e,
            IntegrityError::PayloadPositionOutOfRange {
                position: 0,
                end: 31,
                write_position: 30
            }
        )
    });
}

#[test]
fn control_only_chunk_is_accepted_but_payload_without_descriptors_is_not() {
    let r = three_events();
    let mut c = r.full_chunk();
    c.descriptors.clear();
    c.payload.clear();
    let mut vr = ValidatingReader::new(r.known(), 1);
    assert_eq!(vr.drain_chunk(&c).unwrap(), vec![]);
    assert_eq!(vr.read_cursor(), 0);

    let mut c = r.full_chunk();
    c.descriptors.clear();
    c.payload.truncate(5);
    rejects(&r, &c, |e| *e == IntegrityError::PayloadRangeInvalid);
}

#[test]
fn payload_after_the_last_copied_descriptor_is_rejected() {
    let r = three_events();
    // 1 件目だけを写し、Payload は 3 件分（未確定分の解放に相当）。
    let mut c = r.chunk(0, 0, 1);
    assert_eq!(c.payload.len(), 10);
    c.payload = r.full_chunk().payload;
    rejects(&r, &c, |e| {
        matches!(
            e,
            IntegrityError::PayloadPositionNotContiguous {
                expected: 30,
                found: 10
            }
        )
    });
}

#[test]
fn chunks_continue_across_calls_and_count_sequence_gaps() {
    // 小さな Payload 容量で後半の Payload を落とさせ、Descriptor 満杯で
    // 書けなかった分は Sequence 欠番になる。
    let mut r = rig(RingConfig::new(2, 16), false);
    r.write(8, 0, 1);
    r.write(8, 0, 2);
    r.write(8, 0, 3); // Descriptor 満杯: 欠番
    let mut vr = ValidatingReader::new(r.known(), 1);
    let first = vr.drain_chunk(&r.chunk(0, 0, 1)).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!((vr.read_cursor(), vr.payload_read_position()), (1, 8));
    assert_eq!(r.reader.drain(1).events, first);
    let second = vr
        .drain_chunk(&r.chunk(vr.read_cursor(), vr.payload_read_position(), 9))
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(r.reader.drain(9).events, second);
    r.write(8, 0, 4);
    let third = vr
        .drain_chunk(&r.chunk(vr.read_cursor(), vr.payload_read_position(), 9))
        .unwrap();
    assert_eq!(third.len(), 1);
    assert!(third[0].descriptor.sequence > second[0].descriptor.sequence + 1);
    let gaps = third[0].descriptor.sequence - second[0].descriptor.sequence - 1;
    assert_eq!(vr.take_sequence_gaps(), gaps);
    let batch = r.reader.drain(9);
    assert_eq!(batch.events, third);
    assert_eq!(batch.sequence_gaps, gaps);
}

#[test]
fn global_order_needs_the_session_setting_on_both_readers() {
    let mut r = rig(RingConfig::new(4, 64), false);
    r.write(4, 0, 1);
    r.write(4, 7, 2);
    let mut strict = ValidatingReader::new(r.known(), 1);
    assert_eq!(
        strict.drain_chunk(&r.full_chunk()),
        Err(IntegrityError::GlobalOrderNotAllowed)
    );
    let mut late = ValidatingReader::new(r.known(), 1);
    late.set_global_order(true);
    assert_eq!(late.drain_chunk(&r.full_chunk()).unwrap().len(), 2);

    let batch = r.reader.drain(9);
    assert_eq!(batch.events.len(), 1);
    assert_eq!(
        batch.integrity_error,
        Some(IntegrityError::GlobalOrderNotAllowed)
    );
    let mut allowing = unsafe { r.region.reader() }.with_global_order(true);
    let batch = allowing.drain(9);
    assert_eq!(batch.integrity_error, None);
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].descriptor.global_order, 7);
}

/// 共有メモリ上の Descriptor を書き換える（対象プロセスの改竄に相当）。
fn tamper(r: &Rig, cursor: u64, f: impl FnOnce(&mut EventDescriptor)) {
    let off =
        r.cfg.descriptors_offset() + ((cursor % r.cfg.descriptor_capacity as u64) as usize) * 64;
    let mut d = EventDescriptor::from_bytes(&r.region.as_slice()[off..off + 64]).unwrap();
    f(&mut d);
    let bytes = d.to_bytes();
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), r.region.base().add(off), 64) };
}

#[test]
fn ring_reader_rejects_unknown_and_undefined_kinds() {
    for kind in [EventKind::Unknown as u16, 9, 0xffff] {
        let mut r = three_events();
        tamper(&r, 1, |d| d.kind = kind);
        let batch = r.reader.drain(9);
        assert_eq!(batch.events.len(), 1, "kind {kind}");
        assert_eq!(
            batch.integrity_error,
            Some(IntegrityError::UnknownKind(kind))
        );
        assert_eq!(r.reader.read_cursor(), 1);
    }
}

#[test]
fn ring_reader_accepts_every_defined_kind() {
    for kind in 1u16..=8 {
        let mut r = three_events();
        tamper(&r, 1, |d| d.kind = kind);
        let batch = r.reader.drain(9);
        assert_eq!(batch.integrity_error, None, "kind {kind}");
        assert_eq!(batch.events.len(), 3);
    }
}

#[test]
fn dropped_payload_may_declare_the_largest_original_length() {
    let mut r = three_events();
    // 2 件目（Payload 0 バイト）を「u32::MAX バイトを落とした」に書き換える。
    tamper(&r, 1, |d| {
        d.flags |= flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE;
        d.payload_len = u32::MAX;
    });
    let batch = r.reader.drain(9);
    assert_eq!(batch.integrity_error, None);
    assert_eq!(batch.events.len(), 3);
    assert!(batch.events[1].payload.is_empty());
    assert_eq!(
        batch.events[1].descriptor.capture_state(),
        CaptureState::DroppedByBackpressure
    );
    // 最後の Descriptor の終端まで Payload の読み位置が進む。
    assert_eq!(r.load(layout::OFF_PAYLOAD_READ_POSITION), 30);
}

#[test]
fn dropped_last_descriptor_still_releases_the_payload_before_it() {
    let mut r = three_events();
    tamper(&r, 2, |d| {
        d.flags |= flags::PAYLOAD_DROPPED;
    });
    let batch = r.reader.drain(9);
    assert_eq!(batch.integrity_error, None);
    assert!(batch.events[2].payload.is_empty());
    // 落とした Descriptor は Payload を持たないので、読み位置は 2 件目の終端。
    assert_eq!(r.load(layout::OFF_PAYLOAD_READ_POSITION), 10);
}

#[test]
fn mapping_larger_than_required_is_accepted() {
    let r = three_events();
    let mut vr = ValidatingReader::new(KnownConfig::new(r.cfg, r.cfg.required_len() + 4096), 1);
    assert_eq!(vr.drain_chunk(&r.full_chunk()).unwrap().len(), 3);
}

#[test]
fn empty_drain_does_not_count_as_a_host_drain() {
    let mut r = three_events();
    let before = r.load(layout::OFF_HOST_DRAIN_COUNT);
    assert!(r.reader.drain(0).events.is_empty());
    assert_eq!(r.load(layout::OFF_HOST_DRAIN_COUNT), before);
    assert_eq!(r.reader.drain(2).events.len(), 2);
    assert_eq!(r.load(layout::OFF_HOST_DRAIN_COUNT), before + 1);
    assert_eq!(r.reader.drain(9).events.len(), 1);
    assert!(r.reader.drain(9).events.is_empty());
    assert_eq!(r.load(layout::OFF_HOST_DRAIN_COUNT), before + 2);
}

#[test]
fn drain_all_takes_every_committed_event() {
    let mut r = three_events();
    let batch = r.reader.drain_all();
    assert_eq!(batch.events.len(), 3);
    assert_eq!(r.reader.read_cursor(), 3);
    assert_eq!(r.load(layout::OFF_PAYLOAD_READ_POSITION), 30);
}
