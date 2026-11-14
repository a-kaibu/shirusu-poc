//! Host が対象プロセスから写し取った `CommittedChunk` は信頼できない
//! （対象が共有メモリを任意に書き換えられる）。正規の書き込みと回収で作った
//! Chunk 列に任意の改変（バイト反転、Cursor・Payload 位置のずれ、切り詰め・
//! 継ぎ足し、Chunk の重複・欠落・入れ替え）を 1 つ加え、検証側
//! （`DrainWorker::ingest_chunk` → `ValidatingReader::drain_chunk`）に順に
//! 与える。既存の DST は Descriptor の特定フィールドの破損だけを扱うため、
//! ここでは Chunk の構造そのものを広く崩す。
//!
//! 不変条件:
//! - どの改変でも panic しない。
//! - 停止は戻らない: 一度止まった後の Chunk からは何も受理しない。
//! - 受理した Event の Sequence は狭義単調増加で、Payload の長さは
//!   Descriptor の格納長と一致する。
//! - Descriptor と Payload のバイトに触れない改変（構造の改変）では、受理した
//!   Event は公開した Event の先頭からの並びと一致する（内容も同一）。
//! - 改変なしでは全件を受理し、Ring は止まらない。

use proptest::prelude::*;
use shirusu_host::{CommittedRangeCollector, DrainWorker};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::flags;
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriteOutcome, WriterPolicy};
use shirusu_transport::validate::CommittedChunk;
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::sync::Arc;
use std::time::Duration;

fn pbt_cases(default: u32) -> u32 {
    std::env::var("SHIRUSU_PBT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
enum Step {
    Write(u8),
    Collect,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0u8..48).prop_map(Step::Write),
        1 => Just(Step::Collect),
    ]
}

#[derive(Debug, Clone, Copy)]
enum Area {
    Control,
    Descriptors,
    Payload,
}

#[derive(Debug, Clone)]
enum Mutation {
    None,
    Flip { area: Area, at: usize, mask: u8 },
    FirstCursor(i8),
    PayloadPosition(i8),
    TruncateDescriptors(usize),
    ExtendDescriptors(Vec<u8>),
    TruncatePayload(usize),
    ExtendPayload(Vec<u8>),
    TruncateControl(usize),
    Duplicate,
    Drop,
    SwapWithNext,
}

impl Mutation {
    /// Descriptor・Payload のバイト内容を変えない改変か。
    fn structural(&self) -> bool {
        !matches!(
            self,
            Mutation::Flip {
                area: Area::Descriptors | Area::Payload,
                ..
            } | Mutation::ExtendDescriptors(_)
                | Mutation::ExtendPayload(_)
        )
    }
}

fn mutation() -> impl Strategy<Value = Mutation> {
    let area = prop_oneof![
        Just(Area::Control),
        Just(Area::Descriptors),
        Just(Area::Payload)
    ];
    prop_oneof![
        2 => Just(Mutation::None),
        4 => (area, any::<usize>(), 1u8..=255)
            .prop_map(|(area, at, mask)| Mutation::Flip { area, at, mask }),
        1 => any::<i8>().prop_filter("nonzero", |d| *d != 0).prop_map(Mutation::FirstCursor),
        1 => any::<i8>().prop_filter("nonzero", |d| *d != 0).prop_map(Mutation::PayloadPosition),
        1 => (1usize..200).prop_map(Mutation::TruncateDescriptors),
        1 => proptest::collection::vec(any::<u8>(), 1..130).prop_map(Mutation::ExtendDescriptors),
        1 => (1usize..64).prop_map(Mutation::TruncatePayload),
        1 => proptest::collection::vec(any::<u8>(), 1..64).prop_map(Mutation::ExtendPayload),
        1 => (1usize..64).prop_map(Mutation::TruncateControl),
        1 => Just(Mutation::Duplicate),
        1 => Just(Mutation::Drop),
        1 => Just(Mutation::SwapWithNext),
    ]
}

fn shift(v: u64, d: i8) -> u64 {
    v.wrapping_add_signed(d as i64)
}

fn mutate(chunks: &mut Vec<CommittedChunk>, which: usize, m: &Mutation) {
    if chunks.is_empty() {
        return;
    }
    let i = which % chunks.len();
    match m {
        Mutation::None => {}
        Mutation::Flip { area, at, mask } => {
            let c = &mut chunks[i];
            let bytes = match area {
                Area::Control => &mut c.control,
                Area::Descriptors => &mut c.descriptors,
                Area::Payload => &mut c.payload,
            };
            if !bytes.is_empty() {
                let n = bytes.len();
                bytes[at % n] ^= mask;
            }
        }
        Mutation::FirstCursor(d) => chunks[i].first_cursor = shift(chunks[i].first_cursor, *d),
        Mutation::PayloadPosition(d) => {
            chunks[i].payload_position = shift(chunks[i].payload_position, *d)
        }
        Mutation::TruncateDescriptors(n) => {
            let c = &mut chunks[i].descriptors;
            c.truncate(c.len().saturating_sub(*n));
        }
        Mutation::ExtendDescriptors(b) => chunks[i].descriptors.extend_from_slice(b),
        Mutation::TruncatePayload(n) => {
            let c = &mut chunks[i].payload;
            c.truncate(c.len().saturating_sub(*n));
        }
        Mutation::ExtendPayload(b) => chunks[i].payload.extend_from_slice(b),
        Mutation::TruncateControl(n) => {
            let c = &mut chunks[i].control;
            c.truncate(c.len().saturating_sub(*n));
        }
        Mutation::Duplicate => {
            let c = chunks[i].clone();
            chunks.insert(i + 1, c);
        }
        Mutation::Drop => {
            chunks.remove(i);
        }
        Mutation::SwapWithNext => {
            if i + 1 < chunks.len() {
                chunks.swap(i, i + 1);
            }
        }
    }
}

struct Produced {
    cfg: RingConfig,
    chunks: Vec<CommittedChunk>,
    /// 公開した Event の (call_id, payload)。
    published: Vec<(u64, Vec<u8>)>,
}

fn produce(steps: &[Step]) -> Produced {
    let cfg = RingConfig::new(8, 128);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut writer: RingWriter = unsafe {
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
    let mut published = Vec::new();
    let mut call = 0u64;
    for s in steps.iter().chain(std::iter::once(&Step::Collect)) {
        match s {
            Step::Write(len) => {
                call += 1;
                let body: Vec<u8> = (0..*len)
                    .map(|i| (call as u8).wrapping_mul(31) ^ i)
                    .collect();
                let outcome = writer.write(EventInput {
                    kind: EventKind::CallEnter,
                    api_id: 1,
                    schema_id: 1,
                    call_id: call,
                    parent_call_id: 0,
                    payload: &body,
                    capture_state: CaptureState::Captured,
                    global_order: 0,
                });
                match outcome {
                    WriteOutcome::Published { .. } => published.push((call, body)),
                    // Payload を落とした Descriptor は内容なしで届く。
                    WriteOutcome::PublishedDegraded { .. } => published.push((call, Vec::new())),
                    WriteOutcome::Dropped { .. } => {}
                }
            }
            Step::Collect => {
                if let Some(c) = collector.collect(|| {}) {
                    chunks.push(c);
                }
            }
        }
    }
    drop(writer);
    drop(region);
    Produced {
        cfg,
        chunks,
        published,
    }
}

fn stored_len(d: &shirusu_transport::descriptor::EventDescriptor) -> usize {
    if d.flags & flags::PAYLOAD_DROPPED != 0 {
        0
    } else {
        d.payload_len as usize
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pbt_cases(768)))]

    #[test]
    fn mutated_chunks_never_panic_or_accept_beyond_the_damage(
        steps in proptest::collection::vec(step(), 0..120),
        which in any::<usize>(),
        m in mutation(),
    ) {
        let Produced { cfg, mut chunks, published } = produce(&steps);
        mutate(&mut chunks, which, &m);
        let mut worker = DrainWorker::for_chunks(cfg, 1);
        let mut accepted: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut last_seq = 0u64;
        let mut stopped = false;
        for chunk in &chunks {
            let batch = worker.ingest_chunk(chunk);
            if stopped {
                prop_assert!(batch.events.is_empty(), "accepted after the Ring stopped");
            }
            for e in &batch.events {
                prop_assert!(e.descriptor.sequence > last_seq, "sequence not increasing");
                last_seq = e.descriptor.sequence;
                prop_assert_eq!(e.payload.len(), stored_len(&e.descriptor));
                accepted.push((e.descriptor.call_id, e.payload.to_vec()));
            }
            stopped |= worker.is_stopped();
        }
        if m.structural() {
            prop_assert!(accepted.len() <= published.len());
            prop_assert_eq!(&accepted[..], &published[..accepted.len()]);
        }
        if matches!(m, Mutation::None) {
            prop_assert!(!worker.is_stopped(), "a valid Ring stopped");
            prop_assert_eq!(&accepted, &published);
        }
    }
}

/// 同じ Chunk を 2 度与える（対象が回収済みの範囲を再提示する）と止まる。
#[test]
fn replayed_chunk_stops_the_ring() {
    let p = produce(&[
        Step::Write(4),
        Step::Write(4),
        Step::Collect,
        Step::Write(1),
    ]);
    assert!(p.chunks.len() >= 2);
    let mut worker = DrainWorker::for_chunks(p.cfg, 1);
    let first = worker.ingest_chunk(&p.chunks[0]);
    assert_eq!(first.events.len(), 2);
    assert!(worker.ingest_chunk(&p.chunks[0]).events.is_empty());
    assert!(worker.is_stopped());
    assert!(worker.ingest_chunk(&p.chunks[1]).events.is_empty());
}
