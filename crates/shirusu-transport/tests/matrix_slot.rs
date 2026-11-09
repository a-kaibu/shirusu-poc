//! slot 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - Slot 状態 (Free/Active/Draining/Reclaimable) x 操作 (detach / note /
//!   confirm(終了,回収の4組合せ) / reclaim) の成否と状態の不変性。
//! - 世代不一致の古い handle は (note を除く) 全操作で拒否されること。
//!   note_call_after_detach は世代を見ず状態だけで数える現行仕様も固定する。
//! - claim の順序・枯渇・低水位の拡張要求が「free < watermark になった瞬間」
//!   にだけ立つこと、メモリ上限の境界 (ちょうど/±1 Slot 分)。

use shirusu_transport::slot::{SlotHandle, SlotPool, SlotState, SLOT_MEMORY_BYTES};
use std::sync::atomic::Ordering;

// ---- SlotState の数値往復 ----
macro_rules! state_num_case {
    ($name:ident, $v:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!(SlotState::from_u8($v), $expect);
            if let Some(s) = $expect {
                assert_eq!(s.to_u8(), $v, "roundtrip");
            }
        }
    };
}
state_num_case!(st_0_free, 0, Some(SlotState::Free));
state_num_case!(st_1_claimed, 1, Some(SlotState::Claimed));
state_num_case!(st_2_active, 2, Some(SlotState::Active));
state_num_case!(st_3_draining, 3, Some(SlotState::Draining));
state_num_case!(st_4_reclaimable, 4, Some(SlotState::Reclaimable));
// R3 で追加した過渡状態。回収処理中だけ現れ、claim はできない。
state_num_case!(st_5_reclaiming, 5, Some(SlotState::Reclaiming));
state_num_case!(st_6_invalid, 6, Option::<SlotState>::None);
state_num_case!(st_255_invalid, 255, Option::<SlotState>::None);

// ---- 状態ごとの操作成否 ----
fn pool_in_state(state: &str) -> (SlotPool, SlotHandle) {
    let pool = SlotPool::new(1);
    let handle = match state {
        "free" => SlotHandle {
            index: 0,
            generation: 1,
            thread_id: 0,
        },
        _ => pool.claim(42).unwrap(),
    };
    match state {
        "draining" | "reclaimable" => {
            assert!(pool.begin_detach(&handle));
        }
        _ => {}
    }
    if state == "reclaimable" {
        assert!(pool.host_confirm_ended_and_drained(&handle, true, true));
    }
    (pool, handle)
}
fn state_of(pool: &SlotPool, h: &SlotHandle) -> SlotState {
    pool.slot(h.index).state()
}

#[test]
fn free_state_rejects_all_handle_ops() {
    let (pool, h) = pool_in_state("free");
    assert!(!pool.begin_detach(&h));
    assert!(!pool.note_call_after_detach(&h));
    assert!(!pool.host_confirm_ended_and_drained(&h, true, true));
    assert!(!pool.host_reclaim(&h));
    assert_eq!(state_of(&pool, &h), SlotState::Free);
    assert_eq!(
        pool.missing_calls(),
        0,
        "rejected ops do not count as missing"
    );
}
#[test]
fn active_state_only_detach_succeeds() {
    let (pool, h) = pool_in_state("active");
    assert!(!pool.note_call_after_detach(&h));
    assert!(!pool.host_confirm_ended_and_drained(&h, true, true));
    assert!(!pool.host_reclaim(&h));
    assert_eq!(state_of(&pool, &h), SlotState::Active);
    assert!(pool.begin_detach(&h));
    assert_eq!(state_of(&pool, &h), SlotState::Draining);
    assert!(!pool.begin_detach(&h), "second detach is rejected");
}
#[test]
fn draining_state_confirm_flag_matrix() {
    // (終了確認, 回収完了) の 4 組合せ: 両方 true のときだけ進む
    for (ended, drained, expect) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let (pool, h) = pool_in_state("draining");
        assert_eq!(
            pool.host_confirm_ended_and_drained(&h, ended, drained),
            expect,
            "ended={ended} drained={drained}"
        );
        assert_eq!(
            state_of(&pool, &h),
            if expect {
                SlotState::Reclaimable
            } else {
                SlotState::Draining
            }
        );
    }
}
#[test]
fn draining_state_note_counts_each_call() {
    let (pool, h) = pool_in_state("draining");
    assert!(pool.note_call_after_detach(&h));
    assert!(pool.note_call_after_detach(&h));
    assert_eq!(pool.missing_calls(), 2);
    assert!(!pool.host_reclaim(&h), "cannot reclaim before confirm");
    assert!(!pool.begin_detach(&h));
}
#[test]
fn reclaimable_state_only_reclaim_succeeds() {
    let (pool, h) = pool_in_state("reclaimable");
    assert!(
        pool.note_call_after_detach(&h),
        "reclaimable still counts detach calls"
    );
    assert!(!pool.host_confirm_ended_and_drained(&h, true, true));
    assert!(!pool.begin_detach(&h));
    assert!(pool.host_reclaim(&h));
    assert_eq!(state_of(&pool, &h), SlotState::Free);
    assert_eq!(pool.slot(h.index).generation(), h.generation + 1);
    assert_eq!(
        pool.slot(h.index).owner_thread_id(),
        0,
        "owner cleared on reclaim"
    );
}
#[test]
fn stale_handle_rejected_by_all_generation_checked_ops() {
    let (pool, h) = pool_in_state("reclaimable");
    assert!(pool.host_reclaim(&h)); // generation advances; h is now stale
    let h2 = pool.claim(7).unwrap();
    assert_eq!(h2.generation, h.generation + 1);
    assert!(pool.begin_detach(&h2));
    // 古い世代の handle では、世代を照合する操作は全て失敗する
    assert!(!pool.begin_detach(&h));
    assert!(!pool.host_confirm_ended_and_drained(&h, true, true));
    assert!(!pool.host_reclaim(&h));
    // 現在の handle は影響を受けない
    assert!(pool.host_confirm_ended_and_drained(&h2, true, true));
}
#[test]
fn stale_handle_note_counts_by_state_only() {
    // note_call_after_detach は handle の世代を照合せず、Slot の状態だけで
    // 数える (現行仕様の固定)。DETACH 後の呼出は handle の作り直しを
    // 経ないため、状態が Draining であること自体が根拠になる。
    let (pool, h) = pool_in_state("draining");
    let stale = SlotHandle {
        generation: h.generation + 99,
        ..h
    };
    assert!(pool.note_call_after_detach(&stale));
    assert_eq!(pool.missing_calls(), 1);
}
#[test]
fn generation_increments_each_reuse_cycle() {
    let pool = SlotPool::new(1);
    for expect_gen in 1..=4u64 {
        let h = pool.claim(1).unwrap();
        assert_eq!(h.generation, expect_gen);
        assert!(pool.begin_detach(&h));
        assert!(pool.host_confirm_ended_and_drained(&h, true, true));
        assert!(pool.host_reclaim(&h));
    }
}
#[test]
fn owner_thread_recorded_on_claim() {
    let pool = SlotPool::new(2);
    let h = pool.claim(4242).unwrap();
    assert_eq!(pool.slot(h.index).owner_thread_id(), 4242);
    assert_eq!(h.thread_id, 4242);
}

// ---- claim の順序と枯渇 ----
macro_rules! claim_case {
    ($name:ident, $cap:expr) => {
        #[test]
        fn $name() {
            let pool = SlotPool::new($cap);
            for i in 0..$cap {
                let h = pool.claim(100 + i as u64).expect("slot available");
                assert_eq!(h.index, i, "claims take slots in order");
                assert_eq!(h.generation, 1);
                assert_eq!(pool.free_count(), $cap - i - 1);
            }
            assert!(pool.claim(999).is_none(), "exhausted");
            assert_eq!(pool.missing_calls(), 1);
            assert!(pool.claim(999).is_none());
            assert_eq!(pool.missing_calls(), 2, "each failed claim counts");
        }
    };
}
claim_case!(claim_order_cap1, 1);
claim_case!(claim_order_cap2, 2);
claim_case!(claim_order_cap3, 3);
claim_case!(claim_order_cap5, 5);
#[test]
fn claim_reuses_first_freed_slot() {
    let pool = SlotPool::new(2);
    let a = pool.claim(1).unwrap();
    let _b = pool.claim(2).unwrap();
    assert!(pool.begin_detach(&a));
    assert!(pool.host_confirm_ended_and_drained(&a, true, true));
    assert!(pool.host_reclaim(&a));
    let c = pool.claim(3).unwrap();
    assert_eq!(c.index, a.index, "first free slot is reused");
    assert_eq!(c.generation, a.generation + 1);
}

// ---- 低水位: 拡張要求の発火境界 ----
#[test]
fn watermark_zero_never_requests() {
    let pool = SlotPool::with_low_watermark(2, 0);
    pool.claim(1).unwrap();
    pool.claim(2).unwrap(); // free = 0 でも 0 未満にはならない
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 0);
    assert!(!pool.take_expansion_request());
}
#[test]
fn watermark_one_requests_when_pool_empties() {
    let pool = SlotPool::with_low_watermark(2, 1);
    pool.claim(1).unwrap(); // free = 1, not < 1
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 0);
    pool.claim(2).unwrap(); // free = 0 < 1
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 1);
}
#[test]
fn watermark_above_capacity_requests_on_first_claim() {
    let pool = SlotPool::with_low_watermark(2, 8);
    pool.claim(1).unwrap(); // free = 1 < 8
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 1);
}
#[test]
fn expansion_request_latches_until_taken() {
    let pool = SlotPool::with_low_watermark(10, 8);
    pool.claim(1).unwrap();
    pool.claim(2).unwrap();
    pool.claim(3).unwrap(); // free = 7 < 8: request fires once
    pool.claim(4).unwrap(); // still below, but latched: no second count
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 1);
    assert!(pool.take_expansion_request());
    assert!(!pool.take_expansion_request());
    pool.claim(5).unwrap(); // below watermark again: re-request
    assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 2);
}

// ---- メモリ上限の境界 ----
#[test]
fn memory_limit_exact_slot_boundary() {
    let one = SlotPool::new(1).with_memory_limit(SLOT_MEMORY_BYTES);
    assert_eq!(one.total_memory_bytes(), SLOT_MEMORY_BYTES);
    assert!(!one.can_add_slot(), "2 slots exceed a 1-slot limit");
    let two_room = SlotPool::new(1).with_memory_limit(2 * SLOT_MEMORY_BYTES);
    assert!(two_room.can_add_slot(), "exactly 2 slots fit");
    let two_minus_one = SlotPool::new(1).with_memory_limit(2 * SLOT_MEMORY_BYTES - 1);
    assert!(!two_minus_one.can_add_slot(), "one byte short does not fit");
}
#[test]
fn memory_limit_zero_blocks_and_none_allows() {
    assert!(!SlotPool::new(1).with_memory_limit(0).can_add_slot());
    assert!(SlotPool::new(1).can_add_slot());
    assert_eq!(SlotPool::new(3).total_memory_bytes(), 3 * SLOT_MEMORY_BYTES);
}
