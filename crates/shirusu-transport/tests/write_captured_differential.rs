//! `RingWriter::write_captured`（取得成功イベントの近道）は、同じ入力の
//! `RingWriter::write` と見分けがつかないこと（差分検査）。
//!
//! 同じ設定の Ring を 2 つ用意し、片方は `write`、もう片方は
//! `write_captured` で同じイベント列を書く。間に読み手の回収（任意件数）を
//! 挟み、満杯・OVERFLOW・Payload の劣化・Enter を落とした後の Leave の
//! 消費・有限待機（仮想時計）を起こす。各操作の後で、戻り値と共有メモリ像の
//! 全バイト（Control・Descriptor・Payload）が一致することを確かめる。

use proptest::prelude::*;
use shirusu_transport::clock::{ManualClock, ManualTimestampSource};
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::ring::{EventInput, RingReader, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::{Clock, RingConfig};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
enum Op {
    Write {
        kind: u8,
        call: u64,
        len: usize,
        parent: u64,
        order: u64,
    },
    Drain(usize),
    Tick(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0u8..4, 1u64..12, 0usize..80, 0u64..3, 0u64..3)
            .prop_map(|(kind, call, len, parent, order)| Op::Write { kind, call, len, parent, order }),
        2 => (0usize..6).prop_map(Op::Drain),
        1 => (1u64..1000).prop_map(Op::Tick),
    ]
}

fn kind(k: u8) -> EventKind {
    match k {
        0 => EventKind::CallEnter,
        1 => EventKind::CallLeave,
        2 => EventKind::CallAborted,
        _ => EventKind::CallCompleted,
    }
}

struct Side {
    region: SharedRegion,
    writer: RingWriter,
    reader: RingReader,
}

fn side(cfg: RingConfig, policy: WriterPolicy, ts: &Arc<ManualTimestampSource>) -> Side {
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let writer = unsafe { region.writer_with_timestamps(policy, clock, ts.clone()) };
    let reader = unsafe { region.reader() };
    Side {
        region,
        writer,
        reader,
    }
}

fn policy(wait: bool, resume: u64) -> WriterPolicy {
    WriterPolicy {
        max_wait: if wait {
            Duration::from_micros(200)
        } else {
            Duration::ZERO
        },
        resume_threshold_percent: resume,
        ..Default::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("SHIRUSU_PBT_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(512)
    ))]

    #[test]
    fn write_captured_is_indistinguishable_from_write(
        ops in proptest::collection::vec(op(), 0..120),
        desc in 2usize..10,
        pay in 16usize..200,
        wait in any::<bool>(),
        resume in 10u64..90,
    ) {
        let cfg = RingConfig::new(desc, pay);
        let ts = Arc::new(ManualTimestampSource::new(100, 10_000_000));
        let mut a = side(cfg, policy(wait, resume), &ts);
        let mut b = side(cfg, policy(wait, resume), &ts);
        for (i, op) in ops.iter().enumerate() {
            match *op {
                Op::Write { kind: k, call, len, parent, order } => {
                    let payload: Vec<u8> = (0..len).map(|j| (i + j) as u8).collect();
                    let ra = a.writer.write(EventInput {
                        kind: kind(k),
                        api_id: 7,
                        schema_id: 9,
                        call_id: call,
                        parent_call_id: parent,
                        payload: &payload,
                        capture_state: CaptureState::Captured,
                        global_order: order,
                    });
                    let rb = b.writer.write_captured(kind(k), 7, 9, call, parent, order, &payload);
                    prop_assert_eq!(format!("{ra:?}"), format!("{rb:?}"), "op {} outcome", i);
                }
                Op::Drain(n) => {
                    let da = a.reader.drain(n);
                    let db = b.reader.drain(n);
                    prop_assert_eq!(format!("{da:?}"), format!("{db:?}"), "op {} drain", i);
                }
                Op::Tick(t) => ts.advance(t),
            }
            prop_assert!(
                a.region.as_slice() == b.region.as_slice(),
                "op {}: shared memory images differ",
                i
            );
        }
    }
}
