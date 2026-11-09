//! PBT 増強分: 損失会計の保存則、Snapshot の故障モデル照合、通知閾値の意味論、
//! Slot ライフサイクルのインターリーブ (影モデル照合)、Enter/Leave 対応付け。
//! ケース数は SHIRUSU_PBT_CASES で上書き可能 (既定 1024)。

use proptest::prelude::*;
use shirusu_transport::clock::ManualClock;
use shirusu_transport::layout::usage_percent;
use shirusu_transport::notify::{NotifySignal, PublishNotifyTracker};
use shirusu_transport::ring::*;
use shirusu_transport::slot::{SlotHandle, SlotPool, SlotState};
use shirusu_transport::snapshot::{write_snapshot, FailAfterSource, SliceSource};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

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
fn input(kind: EventKind, payload: &[u8], call: u64) -> EventInput<'_> {
    EventInput {
        kind,
        api_id: 1,
        schema_id: 2,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(1024), ..ProptestConfig::default() })]

    /// 損失会計の保存則: 全書込 = 受信 + 欠落 (Dropped) + 滞留。
    /// 最後に全部回収すれば滞留は 0 になり、欠番の合計は Dropped 件数、
    /// カウンタは Outcome の集計と完全一致する (CallEnter のみ。Leave の
    /// 早期ドロップは payload バイトを数えないため別プロパティで扱う)。
    #[test]
    fn loss_accounting_conservation(
        ops in prop::collection::vec(
            prop_oneof![
                prop::collection::vec(any::<u8>(), 0..40).prop_map(|p| (true, p)),
                (0usize..5).prop_map(|n| (false, vec![0u8; n])),
            ],
            0..80)
    ) {
        let (_rg, mut w, mut rd) = setup(4, 48);
        let mut writes = 0u64;
        let mut published = 0u64;   // Published + PublishedDegraded の Outcome 数
        let mut degraded = 0u64;
        let mut dropped = 0u64;
        let mut expected_dropped_bytes = 0u64;
        let mut received = 0u64;
        let mut gaps = 0u64;
        let mut seqs: Vec<u64> = Vec::new();
        let mut dropped_seqs: Vec<u64> = Vec::new();
        for (is_write, arg) in &ops {
            if *is_write {
                writes += 1;
                match w.write(input(EventKind::CallEnter, arg, writes)) {
                    WriteOutcome::Published { sequence, .. } => {
                        prop_assert_eq!(sequence, writes);
                        published += 1;
                    }
                    WriteOutcome::PublishedDegraded { sequence, .. } => {
                        prop_assert_eq!(sequence, writes);
                        published += 1;
                        degraded += 1;
                        expected_dropped_bytes += arg.len() as u64;
                    }
                    WriteOutcome::Dropped { sequence, .. } => {
                        prop_assert_eq!(sequence, writes);
                        dropped += 1;
                        dropped_seqs.push(sequence);
                        expected_dropped_bytes += arg.len() as u64;
                    }
                }
            } else {
                let b = rd.drain(arg.len());
                received += b.events.len() as u64;
                gaps += b.sequence_gaps;
                seqs.extend(b.events.iter().map(|e| e.descriptor.sequence));
                // 滞留 = 公開済み - 受信済み は常に 0 以上 (読み過ぎない)
                prop_assert!(published >= received);
            }
        }
        let b = rd.drain_all();
        received += b.events.len() as u64;
        gaps += b.sequence_gaps;
        seqs.extend(b.events.iter().map(|e| e.descriptor.sequence));
        // 保存則 (滞留 0 の最終状態)
        prop_assert_eq!(writes, received + dropped);
        prop_assert_eq!(received, published);
        // 欠番は「その後に受信イベントがある欠落」だけが観測できる。末尾で落ちた
        // イベントは欠番には現れず、カウンタでのみ分かる (欠落検出の二重性)。
        let last_received = seqs.last().copied().unwrap_or(0);
        let observable_gaps = dropped_seqs.iter().filter(|&&s| s < last_received).count() as u64;
        prop_assert_eq!(gaps, observable_gaps, "gaps only count drops followed by a received event");
        // カウンタは Outcome 集計と一致する
        let c = w.loss_counters();
        prop_assert_eq!(c.dropped_events, dropped);
        prop_assert_eq!(c.degraded_events, degraded);
        prop_assert_eq!(c.dropped_payload_bytes, expected_dropped_bytes);
        // 受信 Sequence は狭義単調増加で重複しない
        prop_assert!(seqs.windows(2).all(|p| p[0] < p[1]));
        prop_assert_eq!(seqs.len() as u64, received);
    }

    /// Snapshot 故障モデル: FailAfterSource の故障点から、公開される Fragment 数と
    /// 再構成長を正確に予測できる (成功した読みは接頭辞で、失敗で即停止する)。
    #[test]
    fn snapshot_fault_model_exact(
        len in 1usize..4000,
        frag in 16usize..400,
        fail_at in 0usize..4000,
        seed in any::<u64>(),
    ) {
        let data: Vec<u8> = (0..len as u64).map(|i| (i ^ seed) as u8).collect();
        let (_rg, mut w, mut rd) = setup(1024, 65536);
        let src = FailAfterSource { inner: &data, fail_at };
        let out = write_snapshot(&mut w, &src, len, frag, 1, 1, 77);
        let batch = rd.drain_all();
        let (joined, state) = shirusu_transport::snapshot::reassemble(&batch.events, 77);
        if fail_at >= len {
            prop_assert_eq!(out.state, CaptureState::Captured);
            prop_assert_eq!(joined, data);
            prop_assert_eq!(state, CaptureState::Captured);
        } else {
            // 成功する読みは (k+1)*frag <= fail_at を満たすものだけ。
            let ok_frags = fail_at / frag;
            let ok_bytes = ok_frags * frag;
            prop_assert_eq!(out.state, CaptureState::MemoryUnreadable);
            prop_assert_eq!(out.fragments_published, ok_frags);
            prop_assert_eq!(out.bytes_captured, ok_bytes);
            prop_assert!(!out.complete_marker_published);
            prop_assert_eq!(joined.len(), ok_bytes);
            prop_assert_eq!(&joined[..], &data[..ok_bytes], "captured part is an exact prefix");
            prop_assert_eq!(state, CaptureState::Truncated);
        }
    }

    /// Snapshot 正常系のモデル照合: ノイズイベント (別 call) が混ざっても、
    /// 再構成は対象 call の Fragment だけを順序どおり連結したものと一致する。
    #[test]
    fn snapshot_reassembly_isolates_calls(
        len in 0usize..2000,
        frag in 16usize..256,
        noise in 0usize..6,
        seed in any::<u64>(),
    ) {
        let data: Vec<u8> = (0..len as u64).map(|i| (i.wrapping_mul(31) ^ seed) as u8).collect();
        let (_rg, mut w, mut rd) = setup(1024, 65536);
        for n in 0..noise {
            w.write(input(EventKind::CallEnter, b"noise", 1000 + n as u64));
        }
        let out = write_snapshot(&mut w, &SliceSource(&data), len, frag, 1, 1, 7);
        prop_assert_eq!(out.state, CaptureState::Captured);
        let batch = rd.drain_all();
        prop_assert_eq!(batch.events.len(), noise + out.fragments_published + 1);
        let (joined, state) = shirusu_transport::snapshot::reassemble(&batch.events, 7);
        prop_assert_eq!(state, CaptureState::Captured);
        prop_assert_eq!(joined, data);
        // 存在しない call は Truncated + 空
        let (none_joined, none_state) = shirusu_transport::snapshot::reassemble(&batch.events, 4242);
        prop_assert!(none_joined.is_empty());
        prop_assert_eq!(none_state, CaptureState::Truncated);
    }

    /// 通知閾値の意味論: 仕様文そのままのモデル
    /// 「使用率が閾値を下から上へ越えたときだけ一度通知する」と照合する。
    /// HostWaiting は越えが無いときに限る。observe_used は回収の反映。
    #[test]
    fn notify_threshold_semantics(
        steps in prop::collection::vec((0u64..130, any::<bool>(), any::<bool>()), 1..60),
        capacity in 1u64..200,
        threshold in 1u64..=100,
    ) {
        let mut tracker = PublishNotifyTracker::new();
        let mut used = 0u64;
        for (target, host_waiting, drain_first) in &steps {
            if *drain_first {
                used = used.saturating_sub(*target % 7);
                tracker.observe_used(used, capacity, threshold);
            }
            let before = used;
            let after = *target % (capacity + 1);
            let sig = tracker.after_publish(before, after, capacity, threshold, *host_waiting);
            let crossed = usage_percent(before, capacity) < threshold
                && usage_percent(after, capacity) >= threshold;
            let want = if crossed {
                NotifySignal::ThresholdCrossing
            } else if *host_waiting {
                NotifySignal::HostWaiting
            } else {
                NotifySignal::None
            };
            prop_assert_eq!(sig, want, "before={} after={} cap={} th={}", before, after, capacity, threshold);
            used = after;
        }
    }
}

// ---------- Slot ライフサイクルのインターリーブ (影モデル) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShadowState {
    Free,
    Active,
    Draining,
    Reclaimable,
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(1024), ..ProptestConfig::default() })]

    /// claim/detach/confirm/reclaim/note を、古い handle 含めランダムに混ぜても、
    /// Pool の状態は影モデルと常に一致し、同一 Slot の Active は 1 つだけ。
    #[test]
    fn slot_lifecycle_interleavings_match_shadow_model(
        ops in prop::collection::vec(0u8..6, 0..80),
        picks in prop::collection::vec(0usize..16, 0..80),
    ) {
        const N: usize = 4;
        let pool = SlotPool::new(N);
        let mut shadow: Vec<(ShadowState, u64)> = (0..N).map(|_| (ShadowState::Free, 1)).collect();
        let mut handles: Vec<SlotHandle> = Vec::new();
        let mut missing = 0u64;
        let mut tid = 0u64;
        for (i, op) in ops.iter().enumerate() {
            let pick = picks.get(i).copied().unwrap_or(0);
            match op {
                0 => {
                    tid += 1;
                    // 影モデル: 先頭の Free を first-fit で取る
                    let expect = shadow.iter().position(|(s, _)| *s == ShadowState::Free);
                    match (pool.claim(tid), expect) {
                        (Some(h), Some(idx)) => {
                            prop_assert_eq!(h.index, idx);
                            prop_assert_eq!(h.generation, shadow[idx].1);
                            shadow[idx].0 = ShadowState::Active;
                            handles.push(h);
                        }
                        (None, None) => missing += 1,
                        (got, exp) => prop_assert!(false, "claim mismatch: got {:?} expected slot {:?}", got, exp),
                    }
                }
                1..=4 => {
                    if handles.is_empty() { continue; }
                    let h = handles[pick % handles.len()];
                    let (st, gen) = shadow[h.index];
                    match op {
                        1 => {
                            let want = gen == h.generation && st == ShadowState::Active;
                            prop_assert_eq!(pool.begin_detach(&h), want);
                            if want { shadow[h.index].0 = ShadowState::Draining; }
                        }
                        2 => {
                            let ended = pick % 2 == 0;
                            let drained = pick % 3 != 0;
                            let want = ended && drained && gen == h.generation && st == ShadowState::Draining;
                            prop_assert_eq!(pool.host_confirm_ended_and_drained(&h, ended, drained), want);
                            if want { shadow[h.index].0 = ShadowState::Reclaimable; }
                        }
                        3 => {
                            let want = gen == h.generation && st == ShadowState::Reclaimable;
                            prop_assert_eq!(pool.host_reclaim(&h), want);
                            if want {
                                shadow[h.index].0 = ShadowState::Free;
                                shadow[h.index].1 += 1;
                            }
                        }
                        _ => {
                            // note_call_after_detach は Generation を見ず状態だけで判定する
                            let want = matches!(st, ShadowState::Draining | ShadowState::Reclaimable);
                            prop_assert_eq!(pool.note_call_after_detach(&h), want);
                            if want { missing += 1; }
                        }
                    }
                }
                _ => {
                    // 影モデルと Pool の全状態が一致すること
                    for (idx, (st, gen)) in shadow.iter().enumerate() {
                        let want_state = match st {
                            ShadowState::Free => SlotState::Free,
                            ShadowState::Active => SlotState::Active,
                            ShadowState::Draining => SlotState::Draining,
                            ShadowState::Reclaimable => SlotState::Reclaimable,
                        };
                        prop_assert_eq!(pool.slot(idx).state(), want_state, "slot {} state", idx);
                        prop_assert_eq!(pool.slot(idx).generation(), *gen, "slot {} generation", idx);
                    }
                    let active = handles.iter().filter(|h| {
                        shadow[h.index].0 == ShadowState::Active && shadow[h.index].1 == h.generation
                    }).count();
                    prop_assert!(active <= N);
                }
            }
            prop_assert_eq!(pool.missing_calls(), missing);
        }
    }

    /// Enter/Leave 対応付け: Enter が Dropped になった呼出の Leave は (その 1 回だけ)
    /// 必ず Dropped になり、受信側では Leave が Enter に先行しない。
    #[test]
    fn enter_leave_pairing_with_drops(
        ops in prop::collection::vec((0u8..3, 1u64..5), 0..60),
    ) {
        let (_rg, mut w, mut rd) = setup(3, 64);
        let mut writer_dropped_enters: HashSet<u64> = HashSet::new();
        let mut open: HashMap<u64, u64> = HashMap::new(); // call -> 未対応 Enter 数
        let mut received_enters = 0u64;
        let mut received_leaves = 0u64;
        let mut last_seq = 0u64;
        // op 列は整形式に保つ: Enter は閉じている呼出にだけ、Leave は開いている
        // 呼出にだけ書く (Enter の無い Leave や二重 Leave はアプリ異常であり
        // 転送層の保証範囲外)。条件に合わない op は Drain として扱う。
        let mut open_calls: HashSet<u64> = HashSet::new();
        for (kind_sel, call) in &ops {
            let malformed = (*kind_sel == 0 && open_calls.contains(call)) // 既に開いている呼出への Enter は書かない
                || (*kind_sel == 1 && !open_calls.contains(call)); // 開いていない呼出への Leave は書かない
            let kind_sel = if malformed { 2 } else { *kind_sel };
            match kind_sel {
                0 => {
                    open_calls.insert(*call);
                    let out = w.write(input(EventKind::CallEnter, b"e", *call));
                    if matches!(out, WriteOutcome::Dropped { .. }) {
                        writer_dropped_enters.insert(*call);
                    }
                }
                1 => {
                    open_calls.remove(call);
                    let expected_forced_drop = writer_dropped_enters.contains(call);
                    let out = w.write(input(EventKind::CallLeave, b"l", *call));
                    if expected_forced_drop {
                        prop_assert!(
                            matches!(out, WriteOutcome::Dropped { .. }),
                            "leave of a dropped enter must be dropped"
                        );
                        writer_dropped_enters.remove(call);
                    }
                }
                _ => {
                    let batch = rd.drain(2);
                    for e in &batch.events {
                        prop_assert!(e.descriptor.sequence > last_seq, "sequences strictly increase");
                        last_seq = e.descriptor.sequence;
                        match e.descriptor.kind_enum() {
                            Some(EventKind::CallEnter) => {
                                received_enters += 1;
                                *open.entry(e.descriptor.call_id).or_insert(0) += 1;
                            }
                            Some(EventKind::CallLeave) => {
                                received_leaves += 1;
                                let n = open.get(&e.descriptor.call_id).copied().unwrap_or(0);
                                prop_assert!(n > 0, "received Leave without a preceding received Enter");
                                if n == 1 { open.remove(&e.descriptor.call_id); }
                                else { open.insert(e.descriptor.call_id, n - 1); }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        let batch = rd.drain_all();
        for e in &batch.events {
            prop_assert!(e.descriptor.sequence > last_seq);
            last_seq = e.descriptor.sequence;
            match e.descriptor.kind_enum() {
                Some(EventKind::CallEnter) => {
                    received_enters += 1;
                    *open.entry(e.descriptor.call_id).or_insert(0) += 1;
                }
                Some(EventKind::CallLeave) => {
                    received_leaves += 1;
                    let n = open.get(&e.descriptor.call_id).copied().unwrap_or(0);
                    prop_assert!(n > 0, "received Leave without a preceding received Enter");
                    if n == 1 { open.remove(&e.descriptor.call_id); }
                    else { open.insert(e.descriptor.call_id, n - 1); }
                }
                _ => {}
            }
        }
        // 会計: 受信 Enter = 受信 Leave + 終了不明 (未対応) の合計と一致する
        let unterminated: u64 = open.values().sum();
        prop_assert_eq!(received_enters, received_leaves + unterminated);
    }
}
