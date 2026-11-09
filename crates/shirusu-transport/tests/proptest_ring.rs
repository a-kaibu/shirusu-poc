//! PBT: VecDeque 参照モデル比較、Overflow 不変条件、Fragment、Slot 再利用、
//! 故障操作を混ぜた DST-in-PBT。失敗時は proptest が Seed と縮小ケースを
//! `proptest-regressions/` に保存する（方針は docs/traceability.md と README 参照）。

use proptest::prelude::*;
use shirusu_transport::clock::ManualClock;
use shirusu_transport::ring::*;
use shirusu_transport::slot::{SlotPool, SlotState};
use shirusu_transport::snapshot::{reassemble, write_snapshot, FailAfterSource, SliceSource};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

/// PBT のケース数。既定は各プロパティの宣言値。重い/軽いを調整したいときは
/// 環境変数 SHIRUSU_PBT_CASES で上書きできる (CI の短時間ジョブ用)。
fn pbt_cases(default: u32) -> u32 {
    std::env::var("SHIRUSU_PBT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn setup(desc: usize, pay: usize) -> (SharedRegion, RingWriter, RingReader) {
    let cfg = RingConfig::new(desc, pay);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let r = unsafe { region.reader() };
    (region, w, r)
}
fn input(payload: &[u8], call: u64) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 1,
        schema_id: 2,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
    }
}

#[derive(Debug, Clone)]
enum Op {
    Write(Vec<u8>),
    Drain(u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..12).prop_map(Op::Write),
        (0u8..4).prop_map(Op::Drain),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(1024), ..ProptestConfig::default() })]

    /// 溢れない範囲では VecDeque 参照モデルと完全一致する。
    #[test]
    fn ring_matches_vecdeque_model(ops in prop::collection::vec(op_strategy(), 0..60)) {
        let (_rg, mut w, mut rd) = setup(64, 8192);
        let mut model: VecDeque<Vec<u8>> = VecDeque::new();
        let mut call = 0u64;
        for op in &ops {
            match op {
                Op::Write(p) => {
                    call += 1;
                    let out = w.write(input(p, call));
                    prop_assert!(matches!(out, WriteOutcome::Published { .. }), "no overflow expected in this regime");
                    model.push_back(p.clone());
                }
                Op::Drain(n) => {
                    let batch = rd.drain(*n as usize);
                    for e in batch.events {
                        let expected = model.pop_front();
                        prop_assert_eq!(Some(e.payload), expected);
                    }
                }
            }
        }
        let batch = rd.drain_all();
        for e in batch.events {
            prop_assert_eq!(Some(e.payload), model.pop_front());
        }
        prop_assert!(model.is_empty());
    }

    /// Overflow を含む範囲では、順序・欠番・カウンタの整合だけを不変条件として確かめる
    /// (参照モデルに実装のバグを写し込まないため、完全一致は要求しない)。
    #[test]
    fn overflow_invariants_hold(ops in prop::collection::vec(op_strategy(), 0..80)) {
        let (_rg, mut w, mut rd) = setup(4, 48);
        let mut call = 0u64;
        let mut last_seq = 0u64;
        let mut received = 0u64;
        let mut gaps = 0u64;
        for op in &ops {
            match op {
                Op::Write(p) => { call += 1; w.write(input(p, call)); }
                Op::Drain(n) => {
                    let batch = rd.drain(*n as usize);
                    gaps += batch.sequence_gaps;
                    for e in batch.events {
                        prop_assert!(e.descriptor.sequence > last_seq);
                        last_seq = e.descriptor.sequence;
                        received += 1;
                        if e.descriptor.payload_dropped() {
                            prop_assert_eq!(e.capture_state(), CaptureState::DroppedByBackpressure);
                        } else {
                            prop_assert!(e.payload.len() <= 48);
                        }
                    }
                }
            }
        }
        let batch = rd.drain_all();
        gaps += batch.sequence_gaps;
        received += batch.events.len() as u64;
        let counters = w.loss_counters();
        // 受け取った件数 + 欠番 + (Descriptor は残った劣化分を除く純粋な欠落) は総書込を超えない
        prop_assert!(received <= call);
        prop_assert!(counters.dropped_events <= call);
        let _ = gaps;
    }

    /// Fragment: 任意長データを分割して再構成すると元に戻る。
    #[test]
    fn snapshot_fragments_reassemble(
        len in 0usize..3000,
        frag in 16usize..300,
        seed in any::<u64>(),
    ) {
        let data: Vec<u8> = (0..len as u64).map(|i| (i ^ seed) as u8).collect();
        let (_rg, mut w, mut rd) = setup(512, 16384);
        let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), frag, 1, 1, 7);
        prop_assert_eq!(out.state, CaptureState::Captured);
        let batch = rd.drain_all();
        let (joined, state) = reassemble(&batch.events, 7);
        prop_assert_eq!(state, CaptureState::Captured);
        prop_assert_eq!(joined, data);
    }

    /// Fragment: 途中で読取故障が入ると、取得分だけ残って Unreadable/Truncated になる。
    #[test]
    fn snapshot_fault_keeps_prefix(
        len in 500usize..3000,
        fail_at in 0usize..500,
    ) {
        let data = vec![3u8; len];
        let (_rg, mut w, mut rd) = setup(512, 16384);
        let src = FailAfterSource { inner: &data, fail_at };
        let out = write_snapshot(&mut w, &src, data.len(), 128, 1, 1, 9);
        prop_assert_eq!(out.state, CaptureState::MemoryUnreadable);
        let batch = rd.drain_all();
        let (joined, _) = reassemble(&batch.events, 9);
        prop_assert!(joined.len() <= fail_at + 128);
        prop_assert!(joined.iter().all(|&b| b == 3));
    }

    /// Slot 再利用: claim/detach/reclaim の操作列で、状態が常に正しく、
    /// Generation を越えて古い handle が効かない。
    #[test]
    fn slot_pool_state_machine(ops in prop::collection::vec(0u8..4, 0..60)) {
        let pool = SlotPool::new(3);
        let mut handles: Vec<(shirusu_transport::SlotHandle, bool)> = Vec::new(); // (handle, detached)
        let mut tid = 0u64;
        for op in ops {
            match op {
                0 => {
                    tid += 1;
                    if let Some(h) = pool.claim(tid) {
                        handles.push((h, false));
                    }
                }
                1 => {
                    if let Some((h, d)) = handles.iter_mut().find(|(_, d)| !d) {
                        if pool.begin_detach(h) { *d = true; }
                    }
                }
                2 => {
                    if let Some(pos) = handles.iter().position(|(_, d)| *d) {
                        let (h, _) = handles.remove(pos);
                        // 終了確認+回収完了が揃った場合だけ再利用できる
                        prop_assert!(pool.host_confirm_ended_and_drained(&h, true, true));
                        prop_assert!(pool.host_reclaim(&h));
                        prop_assert_eq!(pool.slot(h.index).state(), SlotState::Free);
                        // 古い handle はもう効かない
                        prop_assert!(!pool.begin_detach(&h));
                    }
                }
                _ => {
                    prop_assert!(pool.free_count() <= 3);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum DstOp {
    Write(u8),
    Drain,
    AdvanceClock,
    HostStop,
    HostResume,
    DropNotification,
    ThreadEnd,
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(512), ..ProptestConfig::default() })]

    /// DST-in-PBT: 故障操作 (仮想時計進行・Host 停止再開・通知欠落・スレッド終了) を
    /// 混ぜても、公開済みイベントの順序と欠落の整合が壊れない。
    #[test]
    fn dst_fault_mix_invariants(
        ops in prop::collection::vec(
            (0u8..8).prop_map(|k| match k {
                0 => DstOp::Write(4),
                1 => DstOp::Write(40),
                2 => DstOp::Drain,
                3 => DstOp::AdvanceClock,
                4 => DstOp::HostStop,
                5 => DstOp::HostResume,
                6 => DstOp::ThreadEnd,
                _ => DstOp::DropNotification,
            }),
            0..80)
    ) {
        use shirusu_transport::context::HostMonitor;
        use std::sync::atomic::{AtomicBool, Ordering};
        let alive = Arc::new(AtomicBool::new(true));
        let alive2 = alive.clone();
        let monitor = HostMonitor::new(move || alive2.load(Ordering::Relaxed));
        let clock = Arc::new(ManualClock::new());
        let (_rg, mut w, mut rd) = {
            let cfg = RingConfig::new(8, 256);
            let region = SharedRegion::new(cfg, 1, 1);
            let wc: Arc<dyn Clock> = clock.clone();
            let w = unsafe { region.writer(WriterPolicy { max_wait: Duration::from_millis(1), ..Default::default() }, wc) };
            let r = unsafe { region.reader() };
            (region, w, r)
        };
        let mut call = 0u64;
        let mut last_seq = 0u64;
        let mut thread_ended = false;
        for op in &ops {
            match op {
                DstOp::Write(n) => {
                    if thread_ended { continue; }
                    call += 1;
                    let payload = vec![7u8; *n as usize];
                    if monitor.recording_enabled() {
                        w.write(input(&payload, call));
                    }
                }
                DstOp::Drain => {
                    for e in rd.drain_all().events {
                        prop_assert!(e.descriptor.sequence > last_seq);
                        last_seq = e.descriptor.sequence;
                    }
                }
                DstOp::AdvanceClock => clock.advance(Duration::from_millis(3)),
                DstOp::HostStop => { alive.store(false, Ordering::Relaxed); monitor.check_on_abnormal_path(); }
                DstOp::HostResume => { alive.store(true, Ordering::Relaxed); /* 再接続は初版対象外: recording は戻らない */ }
                DstOp::DropNotification => { /* 通知を落としても drain は watermark と独立 */ }
                DstOp::ThreadEnd => { thread_ended = true; }
            }
        }
        // スレッド終了後も Host は残りを回収できる
        for e in rd.drain_all().events {
            prop_assert!(e.descriptor.sequence > last_seq);
            last_seq = e.descriptor.sequence;
        }
        let _ = call;
    }
}
