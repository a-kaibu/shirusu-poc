//! loom による公開/回収プロトコルの網羅検査。
//! 実 Ring (shirusu-transport) と同じ順序付けを、loom の原子と UnsafeCell で再現した
//! 最小モデルで検査する。通常メモリのデータ競合も loom::cell::UnsafeCell で追跡させる。
//! 検査する性質: 未公開を読まない / 順序が保たれる / CAS による Slot 取得は排他 /
//! 回収 (Release) の後にだけ上書きできる。
//!
//! 対象外 (レビュー 2026-11-14 V12): WriterCell と Hazard Slot は、片側だけが
//! 重いフェンスを打つ Dekker 型の握手 (Store→Load) に依拠する。loom 0.7 は
//! 2 地点にまたがる SeqCst 全順序を強制せず、全 SeqCst の SB リトマスでも
//! 両側のすれ違いを生成する (`loom_wait_intent_bounded_wait_recovers_from_sb_window`
//! の注記)。そのため loom に転写すると正しい実装でも偽の違反になる。この二つは
//! `tla/AsymmetricHandshake.tla` (フェンスを外す・時間切れで奪う・終了を見ない
//! 変種で反例を必須) と、Windows の最適化ビルドでのストレス
//! (`record_shutdown_reattach_stress`、`writer_cell`) で検査する。

use loom::cell::UnsafeCell;
use loom::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
const CAP: usize = 2;

#[allow(dead_code)]
struct MiniRing {
    write_cursor: AtomicU64,
    read_cursor: AtomicU64,
    cells: [UnsafeCell<u64>; CAP],
}
#[allow(dead_code)]
impl MiniRing {
    fn new() -> Self {
        Self {
            write_cursor: AtomicU64::new(0),
            read_cursor: AtomicU64::new(0),
            cells: [UnsafeCell::new(0), UnsafeCell::new(0)],
        }
    }
    /// 書き手 (単一): セルへ書く → write_cursor を Release 更新 (実 Ring の単一公開点と同じ)
    fn publish(&self, value: u64) {
        let wc = self.write_cursor.load(Ordering::Relaxed);
        let idx = (wc as usize) % CAP;
        self.cells[idx].with_mut(|p| unsafe { *p = value });
        self.write_cursor.store(wc + 1, Ordering::Release);
    }
    /// 読み手 (単一): write_cursor を Acquire → 確定分だけ読む → read_cursor を Release 更新
    fn drain(&self) -> Vec<u64> {
        let wc = self.write_cursor.load(Ordering::Acquire);
        let rc = self.read_cursor.load(Ordering::Relaxed);
        let mut out = Vec::new();
        for c in rc..wc {
            let idx = (c as usize) % CAP;
            let v = self.cells[idx].with(|p| unsafe { *p });
            out.push(v);
        }
        if wc > rc {
            self.read_cursor.store(wc, Ordering::Release);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom::sync::atomic::{fence, AtomicBool};
    use loom::sync::Arc;

    /// 空きがあるときだけ公開する書き手 (実 Ring の BOUNDED_WAIT 相当のスピン)。
    /// loom のスケジュールで行き詰まらないよう試行回数に上限を付ける。
    fn publish_when_space(ring: &MiniRing, value: u64) -> bool {
        for _ in 0..16 {
            let wc = ring.write_cursor.load(Ordering::Relaxed);
            let rc = ring.read_cursor.load(Ordering::Acquire);
            if wc - rc < CAP as u64 {
                ring.publish(value);
                return true;
            }
            loom::thread::yield_now();
        }
        false
    }

    #[test]
    fn loom_publish_acquire_never_reads_unpublished() {
        loom::model(|| {
            let ring = Arc::new(MiniRing::new());
            let r2 = ring.clone();
            let reader = loom::thread::spawn(move || {
                let mut got = Vec::new();
                // 有限回試す (loom の状態爆発を cap 2 / 少回数に抑える)
                for _ in 0..3 {
                    got.extend(r2.drain());
                    if got.len() >= 2 {
                        break;
                    }
                    loom::thread::yield_now();
                }
                got
            });
            ring.publish(11);
            ring.publish(22);
            let got = reader.join().unwrap();
            // 読めた分は必ず公開済みの接頭辞で、順序どおり
            assert!(got.len() <= 2);
            if !got.is_empty() {
                assert_eq!(got[0], 11);
            }
            if got.len() == 2 {
                assert_eq!(got[1], 22);
            }
        });
    }

    #[test]
    fn loom_no_overwrite_before_release() {
        // V12 (review 2026-11-14): the writer fills both cells and then
        // tries a third value, which can only go into cell 0 once the reader
        // has released it. An overwrite before release would either be a data
        // race on cell 0 (reported by loom's UnsafeCell) or make the reader see
        // 3 where 1 was published.
        loom::model(|| {
            let ring = Arc::new(MiniRing::new());
            let r2 = ring.clone();
            let reader = loom::thread::spawn(move || r2.drain());
            ring.publish(1);
            ring.publish(2);
            let mut third = false;
            for _ in 0..2 {
                let wc = ring.write_cursor.load(Ordering::Relaxed);
                let rc = ring.read_cursor.load(Ordering::Acquire);
                assert!(wc - rc <= CAP as u64, "the window never exceeds the ring");
                if wc - rc < CAP as u64 {
                    ring.publish(3);
                    third = true;
                    break;
                }
                loom::thread::yield_now();
            }
            let mut all = reader.join().unwrap();
            all.extend(ring.drain());
            let expected: &[u64] = if third { &[1, 2, 3] } else { &[1, 2] };
            assert_eq!(all, expected, "values and order survive cell reuse");
        });
    }

    #[test]
    fn loom_slot_claim_is_exclusive() {
        loom::model(|| {
            let slot = Arc::new(AtomicU64::new(0)); // 0=FREE, 1=CLAIMED
            let s2 = slot.clone();
            let t = loom::thread::spawn(move || {
                s2.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            });
            let mine = slot
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            let theirs = t.join().unwrap();
            assert!(mine ^ theirs, "exactly one claimant must win");
        });
    }

    #[test]
    fn loom_slot_claim_contention_exactly_one_winner() {
        loom::model(|| {
            let slot = Arc::new(AtomicU64::new(0)); // 0=FREE, 1=CLAIMED
            let winners = Arc::new(AtomicU64::new(0));
            let mut hs = Vec::new();
            for _ in 0..3 {
                let s = slot.clone();
                let w = winners.clone();
                hs.push(loom::thread::spawn(move || {
                    if s.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        w.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
            assert_eq!(
                winners.load(Ordering::Relaxed),
                1,
                "3 threads racing one slot: exactly one claim succeeds"
            );
        });
    }

    #[test]
    fn loom_slot_claim_two_slots_three_threads() {
        // first-fit の再試行が分岐を爆発させるため preemption を制限する
        // (競合そのものは preemption 少数でも十分に踏める)。
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(3);
        builder.check(|| {
            // first-fit スキャンで claim する 3 スレッドが 2 Slot を奪い合う。
            let slots = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
            let winners = Arc::new(AtomicU64::new(0));
            let mut hs = Vec::new();
            for _ in 0..3 {
                let ss = slots.clone();
                let w = winners.clone();
                hs.push(loom::thread::spawn(move || {
                    for s in ss.iter() {
                        if s.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            w.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
            assert_eq!(winners.load(Ordering::Relaxed), 2, "one winner per slot");
            assert_eq!(slots[0].load(Ordering::Relaxed), 1);
            assert_eq!(slots[1].load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn loom_no_overwrite_before_release_ring_reuse() {
        loom::model(|| {
            let ring = Arc::new(MiniRing::new());
            ring.publish(10);
            let r2 = ring.clone();
            let reader = loom::thread::spawn(move || {
                let mut got = Vec::new();
                for _ in 0..3 {
                    got.extend(r2.drain());
                    if !got.is_empty() {
                        break;
                    }
                    loom::thread::yield_now();
                }
                got
            });
            // セル 0 は値 10 が回収されるまで上書きされない。空き待ち公開で
            // 2 件目 (セル 1) と 3 件目 (セル 0 の再利用) を書く。
            assert!(publish_when_space(&ring, 20));
            assert!(publish_when_space(&ring, 30));
            let mut got = reader.join().unwrap();
            got.extend(ring.drain());
            assert_eq!(got, vec![10, 20, 30], "reuse keeps order and values");
        });
    }

    #[test]
    fn loom_reader_always_sees_prefix_with_varied_drain_points() {
        loom::model(|| {
            let ring = Arc::new(MiniRing::new());
            let r2 = ring.clone();
            let reader = loom::thread::spawn(move || {
                let mut got = Vec::new();
                for _ in 0..3 {
                    got.extend(r2.drain());
                    loom::thread::yield_now();
                }
                got
            });
            ring.publish(1);
            ring.publish(2);
            let got = reader.join().unwrap();
            // 読めた分は [1, 2] の接頭辞であること (順序・重複なし)
            assert!(got.len() <= 2);
            if !got.is_empty() {
                assert_eq!(got[0], 1);
            }
            if got.len() == 2 {
                assert_eq!(got[1], 2);
            }
            // 残りは後続の drain で回収でき、全体がちょうど [1, 2] になる
            let rest = ring.drain();
            let mut all = got.clone();
            all.extend(rest);
            assert_eq!(all, vec![1, 2]);
            // 3 件目は再利用セルに乗り、順序は保たれる
            ring.publish(3);
            assert_eq!(ring.drain(), vec![3]);
        });
    }

    #[test]
    fn loom_wait_intent_bounded_wait_recovers_from_sb_window() {
        // 実装どおりのオーダリング (Release/Acquire + 書き手側だけの SeqCst
        // フェンス) では、Store Buffer 型のすれ違い (書き手は空きを見ず、
        // Host は待機フラグを見ない) が C11 でも x86 TSO でも到達可能。
        // プロトコルがそれでもハングしない根拠は BOUNDED_WAIT: 書き手は
        // 期限付きで待ち、タイムアウト後の再確認で必ず空きを観測する。
        // このテストは (a) すれ違いウィンドウが実際に到達可能であること、
        // (b) 全実行で書き手が最終的に空きを回収できることを両方示す。
        //
        // なお「全操作 SeqCst なら Dekker が厳密に成り立つ」は loom 0.7 では
        // 検証できないことも分かった: loom の実行モデルは 2 地点にまたがる
        // SeqCst 全順序を強制せず、全 SeqCst の SB リトマスでも両側すれ違いが
        // 出る (実測)。厳密な Dekker 性はアーキテクチャと仕様解釈の問題として
        // README に記録し、ここでは実装が実際に依拠する回復性を検証する。
        use std::sync::atomic::AtomicBool as StdBool;
        // loom の Arc をモデル外で触ると loom がパニックするため std の Arc を使う
        let sb_window_seen = std::sync::Arc::new(StdBool::new(false));
        let seen2 = sb_window_seen.clone();
        loom::model(move || {
            let read_cursor = Arc::new(AtomicU64::new(0));
            let writer_waiting = Arc::new(AtomicBool::new(false));
            let event_set = Arc::new(AtomicBool::new(false));
            let rc2 = read_cursor.clone();
            let ww2 = writer_waiting.clone();
            let es2 = event_set.clone();
            let host = loom::thread::spawn(move || {
                rc2.store(1, Ordering::Release); // 回収で空きを作る
                if ww2.load(Ordering::Acquire) {
                    es2.store(true, Ordering::Release); // SetEvent(space_available)
                }
            });
            writer_waiting.store(true, Ordering::Release); // 待機の意思表示 (実コードと同じ)
            fence(Ordering::SeqCst); // 実コードの wait_for_space と同じ片側フェンス
            let space_seen = read_cursor.load(Ordering::Acquire) > 0; // 再確認
            host.join().unwrap();
            let notified = event_set.load(Ordering::Relaxed);
            if !space_seen && !notified {
                // SB ウィンドウに入った: 通知は失われたが、書き手は期限付き
                // 待機のタイムアウト後に再確認して空きを見る (ハングしない)。
                seen2.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            // タイムアウト後の再確認 (Host の回収は完了している)
            let recovered = read_cursor.load(Ordering::Acquire) > 0;
            assert!(
                space_seen || notified || recovered,
                "writer must recover via the bounded-wait timeout recheck"
            );
            assert!(recovered, "after the host drained, space is visible");
        });
        assert!(
            sb_window_seen.load(std::sync::atomic::Ordering::Relaxed),
            "the store-buffer window should be reachable in some execution"
        );
    }

    #[test]
    fn loom_slot_lifecycle_excludes_concurrent_holders() {
        // Slot 状態機械 (FREE→CLAIMED→ACTIVE→DRAINING→RECLAIMABLE→FREE) を
        // loom 原子で再現し、所有権フラグが二重に立たないことを検査する。
        const FREE: u64 = 0;
        const ACTIVE: u64 = 2;
        const DRAINING: u64 = 3;
        const RECLAIMABLE: u64 = 4;
        loom::model(|| {
            let state = Arc::new(AtomicU64::new(FREE));
            let holder = Arc::new(AtomicBool::new(false));
            let s2 = state.clone();
            let h2 = holder.clone();
            // 所有者スレッド: claim できたら所有し、DETACH まで進める
            let owner = loom::thread::spawn(move || {
                if s2
                    .compare_exchange(FREE, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let was_held = h2.swap(true, Ordering::AcqRel);
                    assert!(!was_held, "two holders at once");
                    s2.store(DRAINING, Ordering::Release);
                    true
                } else {
                    false
                }
            });
            // Host スレッド: DRAINING を見たら RECLAIMABLE → FREE へ進める
            let s3 = state.clone();
            let h3 = holder.clone();
            let host = loom::thread::spawn(move || {
                if s3
                    .compare_exchange(DRAINING, RECLAIMABLE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    assert!(s3
                        .compare_exchange(RECLAIMABLE, FREE, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok());
                    h3.store(false, Ordering::Release);
                    true
                } else {
                    false
                }
            });
            let claimed = owner.join().unwrap();
            let reclaimed = host.join().unwrap();
            if reclaimed {
                assert!(claimed, "reclaim implies a prior claim and detach");
                assert_eq!(state.load(Ordering::Relaxed), FREE);
                assert!(!holder.load(Ordering::Relaxed));
            }
        });
    }

    /// slot.rs の begin_detach の転写: handle の Generation を確かめてから
    /// ACTIVE→DRAINING の CAS をする。確かめた後に Slot が再利用されると、
    /// CAS は新しい所有者の ACTIVE に当たりうる (ABA)。
    fn begin_detach(state: &AtomicU64, generation: &AtomicU64, handle_gen: u64) -> bool {
        generation.load(Ordering::Acquire) == handle_gen
            && state
                .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Host の再利用と新しい所有者の取得 (slot.rs の host_reclaim と claim の
    /// 順序)。`wait_for_end` が真なら、古い所有者の終了を観測してからにする。
    fn reclaim_and_reclaim_by_new_owner(
        state: &AtomicU64,
        generation: &AtomicU64,
        ended: &AtomicBool,
        wait_for_end: bool,
    ) -> bool {
        if wait_for_end && !ended.load(Ordering::Acquire) {
            return false;
        }
        // RECLAIMABLE (スレッド終了と回収の確認済み) から始める。
        state.store(4, Ordering::Release);
        generation.fetch_add(1, Ordering::AcqRel);
        state.store(0, Ordering::Release); // FREE
        state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire) // 新しい所有者
            .is_ok()
    }

    /// V12: 古い handle (gen 1) を持つスレッドの最後の操作は DETACH で、その
    /// 後に終了する。Host は終了を観測してからだけ再利用する (仕様「Ring を
    /// 再利用できるのは、スレッドの終了を確認し…た後だけ」)。この前提の下
    /// では、古い handle の操作が新しい世代の Slot を DRAINING にすることは
    /// ない。
    #[test]
    fn loom_stale_handle_never_detaches_the_next_generation() {
        loom::model(|| {
            let state = Arc::new(AtomicU64::new(2)); // ACTIVE, gen 1
            let generation = Arc::new(AtomicU64::new(1));
            let ended = Arc::new(AtomicBool::new(false));
            let (s2, g2, e2) = (state.clone(), generation.clone(), ended.clone());
            let old_owner = loom::thread::spawn(move || {
                let detached = begin_detach(&s2, &g2, 1);
                e2.store(true, Ordering::Release); // スレッド終了 (Handle の Signal)
                detached
            });
            let reused = reclaim_and_reclaim_by_new_owner(&state, &generation, &ended, true);
            let detached = old_owner.join().unwrap();
            if reused {
                assert_eq!(generation.load(Ordering::Relaxed), 2);
                assert_eq!(
                    state.load(Ordering::Relaxed),
                    2,
                    "the new owner's slot stays ACTIVE whatever the old handle did"
                );
            } else {
                assert_eq!(state.load(Ordering::Relaxed), if detached { 3 } else { 2 });
            }
        });
    }

    /// 上の前提 (終了を観測してから再利用) を外すと、Generation の確認だけ
    /// では足りず、古い handle の DETACH が新しい所有者の Slot を DRAINING に
    /// する実行がある。前提が必要なことの証跡として、loom がその実行を見つける
    /// ことを固定する。
    #[test]
    #[should_panic(expected = "the new owner's slot stays ACTIVE")]
    fn loom_generation_check_alone_admits_a_stale_detach() {
        loom::model(|| {
            let state = Arc::new(AtomicU64::new(2));
            let generation = Arc::new(AtomicU64::new(1));
            let ended = Arc::new(AtomicBool::new(false));
            let (s2, g2) = (state.clone(), generation.clone());
            let old_owner = loom::thread::spawn(move || begin_detach(&s2, &g2, 1));
            let reused = reclaim_and_reclaim_by_new_owner(&state, &generation, &ended, false);
            old_owner.join().unwrap();
            if reused {
                assert_eq!(
                    state.load(Ordering::Relaxed),
                    2,
                    "the new owner's slot stays ACTIVE whatever the old handle did"
                );
            }
        });
    }

    // ---- R3: Slot host_reclaim と claim の操作順序 (slot.rs の転写モデル) ----
    // slot.rs の claim / host_reclaim が行う原子操作を、同じ順序・同じ
    // Ordering で loom 原子へ転写したモデル。実装の順序を変えたら転写も
    // 合わせること (転写の忠実さがこのモデルの前提であり、MiniRing のような
    // 抽象モデルでは R3 の競合は原理的に検出できない)。
    struct MiniSlot {
        state: AtomicU64,
        generation: AtomicU64,
        owner: AtomicU64,
    }
    const MINI_FREE: u64 = 0;
    const MINI_CLAIMED: u64 = 1;
    const MINI_ACTIVE: u64 = 2;
    const MINI_RECLAIMABLE: u64 = 4;
    const MINI_RECLAIMING: u64 = 5;

    impl MiniSlot {
        fn new_reclaimable() -> Self {
            Self {
                state: AtomicU64::new(MINI_RECLAIMABLE),
                generation: AtomicU64::new(1),
                owner: AtomicU64::new(42),
            }
        }
        /// slot.rs の claim の転写: FREE→CLAIMED の CAS 成功後に所有者を
        /// 書き、ACTIVE を Release で公開し、Generation を読んで handle にする。
        fn claim(&self, thread_id: u64) -> Option<u64> {
            if self
                .state
                .compare_exchange(MINI_FREE, MINI_CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.owner.store(thread_id, Ordering::Relaxed);
                self.state.store(MINI_ACTIVE, Ordering::Release);
                Some(self.generation.load(Ordering::Acquire))
            } else {
                None
            }
        }
        /// slot.rs の host_reclaim の転写 (R3 修正後の順序): RECLAIMING で
        /// 回収権を排他取得し、Generation と所有者を更新してから、最後に
        /// FREE を Release で公開する。
        fn host_reclaim(&self, gen: u64) -> bool {
            if self.generation.load(Ordering::Acquire) != gen {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    MINI_RECLAIMABLE,
                    MINI_RECLAIMING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return false;
            }
            self.generation.fetch_add(1, Ordering::AcqRel);
            self.owner.store(0, Ordering::Release);
            self.state.store(MINI_FREE, Ordering::Release);
            true
        }

        /// R3 修正前の旧順序 (FREE 公開 → Generation 更新) の転写。
        /// 性質を満たさないことが分かっている実装であり、検出側の回帰
        /// (loom_slot_reclaim_old_order_is_detected) 専用に残す。
        /// 実装 (slot.rs) へ戻してはいけない。
        fn host_reclaim_old_order(&self, gen: u64) -> bool {
            if self.generation.load(Ordering::Acquire) != gen {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    MINI_RECLAIMABLE,
                    MINI_FREE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return false;
            }
            self.generation.fetch_add(1, Ordering::AcqRel);
            self.owner.store(0, Ordering::Release);
            true
        }
    }

    #[test]
    fn loom_slot_reclaim_publishes_generation_before_free() {
        // R3 の性質: FREE が公開された後に claim した側は、回収で進んだ
        // Generation を必ず観測しなければならない。進む前の Generation を
        // 読むと、古い handle と新しい handle が同じ (index, generation) を
        // 持ち、世代ガードが無力化する。
        loom::model(|| {
            let slot = Arc::new(MiniSlot::new_reclaimable());
            let s2 = slot.clone();
            let reclaimer = loom::thread::spawn(move || s2.host_reclaim(1));
            let claimed_gen = slot.claim(777);
            let reclaimed = reclaimer.join().unwrap();
            assert!(reclaimed, "sole reclaimer must succeed");
            if let Some(g) = claimed_gen {
                assert_eq!(
                    g, 2,
                    "claimer must observe the advanced generation, never the reclaimed one"
                );
                assert_eq!(slot.owner.load(Ordering::Relaxed), 777);
            }
        });
    }

    #[test]
    fn loom_slot_reclaim_excludes_concurrent_reclaimers() {
        // R3: RECLAIMING への CAS で回収権は 1 者だけが取り、Generation は
        // ちょうど 1 回だけ進む。2 者が両方成功すると Generation が二重に
        // 進んだり、FREE 公開と更新が交錯したりする。
        loom::model(|| {
            let slot = Arc::new(MiniSlot::new_reclaimable());
            let s2 = slot.clone();
            let other = loom::thread::spawn(move || s2.host_reclaim(1));
            let mine = slot.host_reclaim(1);
            let theirs = other.join().unwrap();
            assert!(mine ^ theirs, "exactly one reclaimer wins");
            assert_eq!(
                slot.generation.load(Ordering::Relaxed),
                2,
                "generation advances exactly once"
            );
            assert_eq!(slot.state.load(Ordering::Relaxed), MINI_FREE);
            assert_eq!(slot.owner.load(Ordering::Relaxed), 0);
        });
    }

    // ---- レビュー #4 #10: 動的 Slot 追加の公開順序 (slot.rs / agent の転写モデル) ----
    // 管理スレッドが「Slot 追加 → Mapping 登録 → FREE 公開」を進める間、
    // 記録スレッドが claim を試みる。claim に成功した側は、対応する
    // Mapping が登録済みであることを必ず観測しなければならない
    // (未登録のまま取得すると、Mapping の無いローカル領域で記録が
    // 始まり Host から見えなくなる)。Mapping の登録は AtomicBool、
    // 状態遷移は slot.rs と同じ Ordering で転写する。
    const MINI_PREPARING: u64 = 6;

    struct MiniAddedSlot {
        state: AtomicU64,
        mapping_registered: AtomicBool,
    }
    impl MiniAddedSlot {
        /// 修正後の追加順序: PREPARING で追加する。
        fn new_adding() -> Self {
            Self {
                state: AtomicU64::new(MINI_PREPARING),
                mapping_registered: AtomicBool::new(false),
            }
        }
        /// 修正前の旧順序: 追加時点で FREE、Mapping は後から登録する。
        fn new_adding_old_order() -> Self {
            Self {
                state: AtomicU64::new(MINI_FREE),
                mapping_registered: AtomicBool::new(false),
            }
        }
        /// 管理側 (修正後): Mapping を登録してから FREE を Release で公開。
        fn register_and_publish(&self) {
            self.mapping_registered.store(true, Ordering::Release);
            self.state.store(MINI_FREE, Ordering::Release);
        }
        /// 管理側 (旧順序): Slot は最初から FREE で、Mapping だけ後で登録。
        fn register_only(&self) {
            self.mapping_registered.store(true, Ordering::Release);
        }
        /// 記録側 claim (slot.rs の転写): FREE→CLAIMED の CAS。成功したら
        /// Mapping の登録状態を読む (実コードでは expanded_regions の有無)。
        fn claim_and_check_mapping(&self) -> Option<bool> {
            if self
                .state
                .compare_exchange(MINI_FREE, MINI_CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                Some(self.mapping_registered.load(Ordering::Acquire))
            } else {
                None
            }
        }
    }

    #[test]
    fn loom_added_slot_claim_observes_registered_mapping() {
        // #10 の性質: PREPARING で追加し、登録後に公開する順序では、
        // どのスケジュールで claim が成功しても Mapping は登録済み。
        loom::model(|| {
            let slot = Arc::new(MiniAddedSlot::new_adding());
            let s2 = slot.clone();
            let manager = loom::thread::spawn(move || s2.register_and_publish());
            let claimed = slot.claim_and_check_mapping();
            manager.join().unwrap();
            if let Some(registered) = claimed {
                assert!(
                    registered,
                    "claimer must observe the registered mapping, never claim an unpublished slot"
                );
            }
        });
    }

    #[test]
    #[should_panic(expected = "claimer must observe the registered mapping")]
    fn loom_added_slot_old_order_is_detected() {
        // 旧順序 (追加時点で FREE) では、登録前に claim が割り込んで
        // Mapping 未登録のまま取得するスケジュールが存在する。その
        // スケジュールで上の性質表明が落ちることを回帰として固定する
        // (loom_slot_reclaim_old_order_is_detected と同じ流儀)。
        loom::model(|| {
            let slot = Arc::new(MiniAddedSlot::new_adding_old_order());
            let s2 = slot.clone();
            let manager = loom::thread::spawn(move || s2.register_only());
            let claimed = slot.claim_and_check_mapping();
            manager.join().unwrap();
            if let Some(registered) = claimed {
                assert!(
                    registered,
                    "claimer must observe the registered mapping, never claim an unpublished slot"
                );
            }
        });
    }

    /// Control 領域の最小モデル (レビュー第5回 #4)。実 `init_control`
    /// (shirusu-transport::layout) と同じフィールド構成で、初期化の
    /// 公開順序を検査する。読み手の述語は Host と同じ「Magic を
    /// Acquire で読み、現れたら他フィールドを読む」。
    struct MiniControl {
        magic: AtomicU64,
        version: AtomicU64,
        desc_cap: AtomicU64,
        payload_cap: AtomicU64,
        generation: AtomicU64,
        owner: AtomicU64,
    }
    const MINI_MAGIC: u64 = 0x5348_4952_5553_5531; // 実 MAGIC と同じ値
    impl MiniControl {
        fn new() -> Self {
            Self {
                magic: AtomicU64::new(0),
                version: AtomicU64::new(0),
                desc_cap: AtomicU64::new(0),
                payload_cap: AtomicU64::new(0),
                generation: AtomicU64::new(0),
                owner: AtomicU64::new(0),
            }
        }
        /// 新順序: 全フィールドを書いてから Magic を最後に Release。
        fn init_new_order(&self) {
            self.version.store(1, Ordering::Relaxed);
            self.desc_cap.store(8, Ordering::Relaxed);
            self.payload_cap.store(256, Ordering::Relaxed);
            self.generation.store(7, Ordering::Relaxed);
            self.owner.store(42, Ordering::Relaxed);
            self.magic.store(MINI_MAGIC, Ordering::Release);
        }
        /// 旧順序 (レビュー第5回 #4 の指摘): Magic を最初に Relaxed。
        fn init_old_order(&self) {
            self.magic.store(MINI_MAGIC, Ordering::Relaxed);
            self.version.store(1, Ordering::Relaxed);
            self.desc_cap.store(8, Ordering::Relaxed);
            self.payload_cap.store(256, Ordering::Relaxed);
            self.generation.store(7, Ordering::Relaxed);
            self.owner.store(42, Ordering::Relaxed);
        }
        /// 読み手: Magic が現れたら、全フィールドが初期化済みの値を
        /// 持っていなければならない。
        fn check_if_initialized(&self) {
            if self.magic.load(Ordering::Acquire) == MINI_MAGIC {
                let fields = (
                    self.version.load(Ordering::Relaxed),
                    self.desc_cap.load(Ordering::Relaxed),
                    self.payload_cap.load(Ordering::Relaxed),
                    self.generation.load(Ordering::Relaxed),
                    self.owner.load(Ordering::Relaxed),
                );
                assert_eq!(
                    fields,
                    (1, 8, 256, 7, 42),
                    "reader must never observe a half-initialized control"
                );
            }
        }
    }

    #[test]
    fn loom_control_init_magic_published_last() {
        loom::model(|| {
            let control = Arc::new(MiniControl::new());
            let c2 = control.clone();
            let writer = loom::thread::spawn(move || c2.init_new_order());
            // 書き手と並行に読み手述語を回す (有限回)。
            for _ in 0..3 {
                control.check_if_initialized();
                loom::thread::yield_now();
            }
            writer.join().unwrap();
            control.check_if_initialized();
        });
    }

    #[test]
    #[should_panic(expected = "reader must never observe a half-initialized control")]
    fn loom_control_init_magic_first_is_detected() {
        // 旧順序では「Magic だけが見えて他が 0」のスケジュールが存在し、
        // 同じ表明が落ちることを失敗そのものの回帰として固定する。
        loom::model(|| {
            let control = Arc::new(MiniControl::new());
            let c2 = control.clone();
            let writer = loom::thread::spawn(move || c2.init_old_order());
            for _ in 0..3 {
                control.check_if_initialized();
                loom::thread::yield_now();
            }
            writer.join().unwrap();
            control.check_if_initialized();
        });
    }

    #[test]
    #[should_panic(expected = "claimer must observe the advanced generation")]
    fn loom_slot_reclaim_old_order_is_detected() {
        // D53 (loom 失敗スケジュールの回帰化): R3 修正前の旧順序では、
        // FREE 公開と Generation 更新の間に claim が割り込むと、取得者が
        // 回収前の Generation を観測するスケジュールが存在する。その
        // スケジュールで上の性質テストと同じ表明が落ちることを、失敗
        // そのものを回帰として固定する (TLA+ 側の変種モデル D75 と対)。
        loom::model(|| {
            let slot = Arc::new(MiniSlot::new_reclaimable());
            let s2 = slot.clone();
            let reclaimer = loom::thread::spawn(move || s2.host_reclaim_old_order(1));
            let claimed_gen = slot.claim(777);
            let reclaimed = reclaimer.join().unwrap();
            assert!(reclaimed, "sole reclaimer must succeed");
            if let Some(g) = claimed_gen {
                assert_eq!(
                    g, 2,
                    "claimer must observe the advanced generation, never the reclaimed one"
                );
            }
        });
    }

    /// L11 `--order=global` の採番 (shirusu-agent::Agent::record) の転写モデル。
    /// 実装は書き込み確定の直前に `next_global_order.fetch_add(1, Relaxed)` で
    /// 採番し、そのスレッドの Ring へ Release で公開する。Relaxed でも、
    /// 同一原子への RMW は変更順序で全順序になり、happens-before と整合する。
    /// ここでは「因果的に後の観測は大きい番号を持つ」ことを、Host を経由した
    /// 観測 (別スレッドの Ring の公開を Acquire で見てから採番) で確かめる。
    #[test]
    fn loom_global_order_respects_causality_across_rings() {
        loom::model(|| {
            let counter = Arc::new(AtomicU64::new(1));
            let ring_x = Arc::new(MiniRing::new());
            let (c2, rx2) = (counter.clone(), ring_x.clone());
            let producer = loom::thread::spawn(move || {
                let order = c2.fetch_add(1, Ordering::Relaxed);
                rx2.publish(order);
                order
            });
            // 別スレッド: X の公開を観測したら、自分の採番はそれより後でなければならない。
            let seen = ring_x.drain();
            let mine = counter.fetch_add(1, Ordering::Relaxed);
            let theirs = producer.join().unwrap();
            assert_ne!(mine, theirs, "global order numbers must be unique");
            if let Some(&observed) = seen.first() {
                assert_eq!(observed, theirs);
                assert!(
                    mine > observed,
                    "an observation causally after another must get a larger global order"
                );
            }
        });
    }

    #[test]
    fn loom_global_order_is_unique_and_per_thread_increasing() {
        loom::model(|| {
            let counter = Arc::new(AtomicU64::new(1));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let c = counter.clone();
                    loom::thread::spawn(move || {
                        let a = c.fetch_add(1, Ordering::Relaxed);
                        let b = c.fetch_add(1, Ordering::Relaxed);
                        assert!(b > a, "numbers within one thread must increase");
                        [a, b]
                    })
                })
                .collect();
            let own = counter.fetch_add(1, Ordering::Relaxed);
            let mut all = vec![own];
            for h in handles {
                all.extend(h.join().unwrap());
            }
            all.sort_unstable();
            assert_eq!(
                all,
                vec![1, 2, 3, 4, 5],
                "numbering is dense and starts at 1"
            );
        });
    }
}
