//! Ring Slot 管理: FREE→CLAIMED→ACTIVE→DRAINING→RECLAIMABLE→FREE。
//! - 共有アトミック操作が要るのは取得時（CAS）のみ。
//! - Generation 付き。再利用は「Host がスレッド終了を確認し回収完了した後」だけ。
//! - 低水位では拡張要求イベントを立てるだけ（Hook 中で登録しない。登録は管理側の非同期処理）。
//! - Slot 不足時は記録せず、プロセス共通カウンタ（fetch_add のみ）を更新して Capture Coverage 欠落とする。
//! - 予備 Queue は実装しない（spec v0.4 の判断）。

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::layout::RingConfig;

/// Slot 1 本あたりの共有メモリ量（本番既定構成: Control 256B + Descriptor 256KiB + Payload 1MiB）。
pub const SLOT_MEMORY_BYTES: u64 = RingConfig::PRODUCTION.required_len() as u64;

pub const SLOT_FREE: u8 = 0;
pub const SLOT_CLAIMED: u8 = 1;
pub const SLOT_ACTIVE: u8 = 2;
pub const SLOT_DRAINING: u8 = 3;
pub const SLOT_RECLAIMABLE: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Free,
    Claimed,
    Active,
    Draining,
    Reclaimable,
}
impl SlotState {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            SLOT_FREE => Self::Free,
            SLOT_CLAIMED => Self::Claimed,
            SLOT_ACTIVE => Self::Active,
            SLOT_DRAINING => Self::Draining,
            SLOT_RECLAIMABLE => Self::Reclaimable,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Free => SLOT_FREE,
            Self::Claimed => SLOT_CLAIMED,
            Self::Active => SLOT_ACTIVE,
            Self::Draining => SLOT_DRAINING,
            Self::Reclaimable => SLOT_RECLAIMABLE,
        }
    }
}

pub struct Slot {
    state: AtomicU8,
    generation: AtomicU64,
    owner_thread_id: AtomicU64,
}
impl Slot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_FREE),
            generation: AtomicU64::new(1),
            owner_thread_id: AtomicU64::new(0),
        }
    }
    pub fn state(&self) -> SlotState {
        SlotState::from_u8(self.state.load(Ordering::Acquire)).unwrap_or(SlotState::Free)
    }
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    pub fn owner_thread_id(&self) -> u64 {
        self.owner_thread_id.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotHandle {
    pub index: usize,
    pub generation: u64,
    pub thread_id: u64,
}

pub struct SlotPool {
    slots: Vec<Slot>,
    /// プロセス共通の欠落カウンタ。Slot 不足と DETACH 後呼出を数える（fetch_add のみ）。
    pub process_missing_calls: AtomicU64,
    /// 拡張要求が出ているか（登録はしない。非同期拡張側が消費する）。
    expansion_requested: AtomicBool,
    pub expansion_request_count: AtomicU64,
    pub low_watermark: usize,
    /// 総メモリ上限（設定時のみ）。Slot 拡張の可否を決める。None なら上限なし。
    pub memory_limit_bytes: Option<u64>,
}
impl SlotPool {
    pub fn new(capacity: usize) -> Self {
        Self::with_low_watermark(capacity, 8)
    }
    /// 初期 Pool は 32。
    pub fn production() -> Self {
        Self::new(32)
    }
    pub fn with_low_watermark(capacity: usize, low_watermark: usize) -> Self {
        Self {
            slots: (0..capacity).map(|_| Slot::new()).collect(),
            process_missing_calls: AtomicU64::new(0),
            expansion_requested: AtomicBool::new(false),
            expansion_request_count: AtomicU64::new(0),
            low_watermark,
            memory_limit_bytes: None,
        }
    }
    /// 総メモリ上限を設定する（仕様: 総メモリ上限を設定できるようにする）。
    /// 上限は Slot 拡張の可否に使う。既存 Slot の縮小はしない。
    pub fn with_memory_limit(mut self, limit_bytes: u64) -> Self {
        self.memory_limit_bytes = Some(limit_bytes);
        self
    }
    /// 現在の Pool が消費する共有メモリの概算（Slot 数 × 本番既定 1 Slot 分）。
    pub fn total_memory_bytes(&self) -> u64 {
        self.slots.len() as u64 * SLOT_MEMORY_BYTES
    }
    /// もう 1 Slot 追加しても総メモリ上限に収まるか。上限なしなら常に true。
    pub fn can_add_slot(&self) -> bool {
        match self.memory_limit_bytes {
            None => true,
            Some(limit) => (self.slots.len() as u64 + 1) * SLOT_MEMORY_BYTES <= limit,
        }
    }
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
    pub fn slot(&self, index: usize) -> &Slot {
        &self.slots[index]
    }
    pub fn free_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state() == SlotState::Free)
            .count()
    }
    /// FREE→CLAIMED→ACTIVE。CAS はこの取得時だけ。低水位では拡張要求だけ立てる。
    pub fn claim(&self, thread_id: u64) -> Option<SlotHandle> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.state
                .compare_exchange(SLOT_FREE, SLOT_CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                s.owner_thread_id.store(thread_id, Ordering::Relaxed);
                s.state.store(SLOT_ACTIVE, Ordering::Release);
                let handle = SlotHandle {
                    index: i,
                    generation: s.generation(),
                    thread_id,
                };
                if self.free_count() < self.low_watermark
                    && !self.expansion_requested.swap(true, Ordering::Relaxed)
                {
                    self.expansion_request_count.fetch_add(1, Ordering::Relaxed);
                }
                return Some(handle);
            }
        }
        // Slot 不足: 記録せずプロセス共通カウンタだけ更新する。
        self.process_missing_calls.fetch_add(1, Ordering::Relaxed);
        None
    }
    /// DETACH は DRAINING への移行のみ（Loader Lock 中でも待たない）。
    pub fn begin_detach(&self, handle: &SlotHandle) -> bool {
        let s = &self.slots[handle.index];
        if s.generation() != handle.generation {
            return false;
        }
        s.state
            .compare_exchange(
                SLOT_ACTIVE,
                SLOT_DRAINING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    /// DETACH 後の呼出は記録せず欠落として数える。
    pub fn note_call_after_detach(&self, handle: &SlotHandle) -> bool {
        let s = &self.slots[handle.index];
        if s.state() == SlotState::Draining || s.state() == SlotState::Reclaimable {
            let _ = handle;
            self.process_missing_calls.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    /// Host 側: スレッド終了を確認し、回収が完了したら RECLAIMABLE へ。
    pub fn host_confirm_ended_and_drained(
        &self,
        handle: &SlotHandle,
        thread_ended: bool,
        drained: bool,
    ) -> bool {
        if !thread_ended || !drained {
            return false;
        }
        let s = &self.slots[handle.index];
        if s.generation() != handle.generation {
            return false;
        }
        s.state
            .compare_exchange(
                SLOT_DRAINING,
                SLOT_RECLAIMABLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    /// RECLAIMABLE→FREE。Generation を進めてから解放する（古い handle を無効化）。
    pub fn host_reclaim(&self, handle: &SlotHandle) -> bool {
        let s = &self.slots[handle.index];
        if s.generation() != handle.generation {
            return false;
        }
        if s.state
            .compare_exchange(
                SLOT_RECLAIMABLE,
                SLOT_FREE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            s.generation.fetch_add(1, Ordering::Relaxed);
            s.owner_thread_id.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    pub fn take_expansion_request(&self) -> bool {
        self.expansion_requested.swap(false, Ordering::Relaxed)
    }
    pub fn missing_calls(&self) -> u64 {
        self.process_missing_calls.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_lifecycle_with_generation() {
        let pool = SlotPool::new(2);
        let h = pool.claim(111).unwrap();
        assert_eq!(pool.slot(h.index).state(), SlotState::Active);
        assert!(pool.begin_detach(&h));
        // 終了確認と回収完了の両方が無ければ再利用できない
        assert!(!pool.host_confirm_ended_and_drained(&h, false, true));
        assert!(!pool.host_confirm_ended_and_drained(&h, true, false));
        assert!(pool.host_confirm_ended_and_drained(&h, true, true));
        assert!(pool.host_reclaim(&h));
        let h2 = pool.claim(222).unwrap();
        assert_eq!(h2.index, h.index);
        assert_eq!(h2.generation, h.generation + 1);
        // 古い handle はもう使えない
        assert!(!pool.begin_detach(&h));
    }
    #[test]
    fn exhaustion_counts_coverage_loss() {
        let pool = SlotPool::new(1);
        assert!(pool.claim(1).is_some());
        assert!(pool.claim(2).is_none());
        assert_eq!(pool.missing_calls(), 1);
    }
    #[test]
    fn low_watermark_requests_expansion_only() {
        let pool = SlotPool::with_low_watermark(10, 8);
        pool.claim(1).unwrap();
        pool.claim(2).unwrap();
        pool.claim(3).unwrap(); // free becomes 7 < 8
        assert_eq!(pool.expansion_request_count.load(Ordering::Relaxed), 1);
        assert!(pool.take_expansion_request());
        assert!(!pool.take_expansion_request());
    }
    #[test]
    fn detach_calls_are_counted_not_recorded() {
        let pool = SlotPool::new(1);
        let h = pool.claim(9).unwrap();
        assert!(!pool.note_call_after_detach(&h));
        pool.begin_detach(&h);
        assert!(pool.note_call_after_detach(&h));
        assert_eq!(pool.missing_calls(), 1);
    }
    #[test]
    fn memory_limit_gates_expansion() {
        // 本番既定 1 Slot = 1,310,976 B。32 Slot で約 40MiB。
        assert_eq!(SLOT_MEMORY_BYTES, 1_310_976);
        let pool = SlotPool::production().with_memory_limit(40 * 1024 * 1024);
        assert_eq!(pool.total_memory_bytes(), 32 * SLOT_MEMORY_BYTES);
        assert!(!pool.can_add_slot()); // 33 Slot 目で 40MiB を超える
        let roomy = SlotPool::production().with_memory_limit(100 * 1024 * 1024);
        assert!(roomy.can_add_slot());
        assert!(SlotPool::production().can_add_slot()); // 上限なし
    }
}
