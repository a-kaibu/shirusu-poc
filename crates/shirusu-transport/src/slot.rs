//! Ring Slot 管理: FREE→CLAIMED→ACTIVE→DRAINING→RECLAIMABLE→RECLAIMING→FREE。
//! RECLAIMING は Host の回収処理中だけ現れる過渡状態で、この間は誰も
//! claim できない。Generation と所有者を RECLAIMING の間に更新し、FREE の
//! 公開を最後にすることで、新しい claimer が旧 Generation を読む競合を
//! 断つ (レビュー指摘 R3)。
//! - 共有アトミック操作が要るのは取得時（CAS）のみ。
//! - Generation 付き。再利用は「Host がスレッド終了を確認し回収完了した後」だけ。
//! - 低水位では拡張要求イベントを立てるだけ（Hook 中で登録しない。登録は管理側の非同期処理）。
//! - Slot 不足時は記録せず、プロセス共通カウンタ（fetch_add のみ）を更新して Capture Coverage 欠落とする。
//! - 予備 Queue は実装しない（spec v0.4 の判断）。
//! - 拡張 (A70): 管理スレッドだけが [`SlotPool::add_slot`] で Slot を追加できる。
//!   追加 Slot は generation 0・PREPARING (取得不能) から始まり、既存 Slot の
//!   generation/owner には影響しない。追加は総メモリ上限 (`can_add_slot`)
//!   の範囲内でのみ行う。Mapping の登録と Control の初期化が済んだ後に
//!   [`SlotPool::publish_slot`] で FREE を公開する (公開順序はレビュー #4
//!   の #10: FREE で追加すると、登録前の Slot を別スレッドが取得して
//!   Mapping の無いローカル領域で記録を始める競合があった)。

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

use crate::expansion::EXPANDED_SLOT_GENERATION;
use crate::layout::RingConfig;

/// Slot 1 本あたりの共有メモリ量（本番既定構成: Control 256B + Descriptor 256KiB + Payload 1MiB）。
pub const SLOT_MEMORY_BYTES: u64 = RingConfig::PRODUCTION.required_len() as u64;

pub const SLOT_FREE: u8 = 0;
pub const SLOT_CLAIMED: u8 = 1;
pub const SLOT_ACTIVE: u8 = 2;
pub const SLOT_DRAINING: u8 = 3;
pub const SLOT_RECLAIMABLE: u8 = 4;
/// 回収中 (Host が Generation/所有者を更新している間)。claim はできない。
pub const SLOT_RECLAIMING: u8 = 5;
/// 追加直後 (Mapping 登録と Control 初期化が未完)。claim はできない。
/// 準備が済んだら publish_slot で FREE を公開する。
pub const SLOT_PREPARING: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Free,
    Claimed,
    Active,
    Draining,
    Reclaimable,
    Reclaiming,
    Preparing,
}
impl SlotState {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            SLOT_FREE => Self::Free,
            SLOT_CLAIMED => Self::Claimed,
            SLOT_ACTIVE => Self::Active,
            SLOT_DRAINING => Self::Draining,
            SLOT_RECLAIMABLE => Self::Reclaimable,
            SLOT_RECLAIMING => Self::Reclaiming,
            SLOT_PREPARING => Self::Preparing,
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
            Self::Reclaiming => SLOT_RECLAIMING,
            Self::Preparing => SLOT_PREPARING,
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
        Self::with_generation(1)
    }
    /// 指定した Generation で Slot を作る。追加 Slot (A70) は generation 0
    /// から始める (「まだ誰も使っていない」ことを表す)。
    fn with_generation(generation: u64) -> Self {
        Self {
            state: AtomicU8::new(SLOT_FREE),
            generation: AtomicU64::new(generation),
            owner_thread_id: AtomicU64::new(0),
        }
    }
    /// 追加 Slot 用: 取得不能 (PREPARING) で作る。Mapping 登録などの
    /// 準備が完了するまで claim できてはならない (レビュー #4 の #10)。
    fn preparing(generation: u64) -> Self {
        Self {
            state: AtomicU8::new(SLOT_PREPARING),
            generation: AtomicU64::new(generation),
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
    /// Slot 本体は `Arc` で共有する。`slot()` は `Arc<Slot>` を返し、追加で
    /// Vec が伸びても既存 Slot の同一性は保たれる。Vec 自体の伸長 (追加)
    /// だけが書きロックを取り、Slot の状態遷移は従来どおり原子操作で行う
    /// (追加中も既存 Slot の claim / 回収は止めない)。
    slots: RwLock<Vec<Arc<Slot>>>,
    /// プロセス共通の欠落カウンタ。Slot 不足と DETACH 後呼出を数える（fetch_add のみ）。
    pub process_missing_calls: AtomicU64,
    /// 拡張要求が出ているか（登録はしない。非同期拡張側が消費する）。
    expansion_requested: AtomicBool,
    pub expansion_request_count: AtomicU64,
    /// Slot が FREE になるたびに進む番号 (P1-1)。Slot を取れなかった
    /// スレッドはこの値が変わるまで取得をやり直さない。
    free_epoch: AtomicU64,
    pub low_watermark: usize,
    /// 総メモリ上限（設定時のみ）。Slot 拡張の可否を決める。None なら上限なし。
    pub memory_limit_bytes: Option<u64>,
    slot_memory_bytes: u64,
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
            slots: RwLock::new((0..capacity).map(|_| Arc::new(Slot::new())).collect()),
            process_missing_calls: AtomicU64::new(0),
            expansion_requested: AtomicBool::new(false),
            expansion_request_count: AtomicU64::new(0),
            free_epoch: AtomicU64::new(0),
            low_watermark,
            memory_limit_bytes: None,
            slot_memory_bytes: SLOT_MEMORY_BYTES,
        }
    }
    /// 総メモリ上限を設定する（仕様: 総メモリ上限を設定できるようにする）。
    /// 上限は Slot 拡張の可否に使う。既存 Slot の縮小はしない。
    pub fn with_memory_limit(mut self, limit_bytes: u64) -> Self {
        self.memory_limit_bytes = Some(limit_bytes);
        self
    }
    /// Set the mapping size used for accounting and expansion limits before
    /// sharing this pool. The Agent must use the same Ring configuration.
    /// Existing constructors retain the production configuration by default.
    pub fn with_ring_config(mut self, config: RingConfig) -> Self {
        self.slot_memory_bytes = config.required_len() as u64;
        self
    }
    /// Configured Ring mapping bytes; excludes Host copies and allocator costs.
    pub fn total_memory_bytes(&self) -> u64 {
        (self.slots.read().unwrap().len() as u64).saturating_mul(self.slot_memory_bytes)
    }
    /// もう 1 Slot 追加しても総メモリ上限に収まるか。上限なしなら常に true。
    pub fn can_add_slot(&self) -> bool {
        self.can_add_slot_with_len(self.slots.read().unwrap().len())
    }
    fn can_add_slot_with_len(&self, len: usize) -> bool {
        match self.memory_limit_bytes {
            None => true,
            Some(limit) => (len as u64)
                .checked_add(1)
                .and_then(|count| count.checked_mul(self.slot_memory_bytes))
                .is_some_and(|bytes| bytes <= limit),
        }
    }
    /// 拡張で Slot を 1 本追加する (A70)。管理スレッドだけが呼ぶ。
    /// 追加 Slot は generation 0・PREPARING (取得不能) から始まり、既存
    /// Slot の generation/owner には影響しない。追加された Slot の
    /// index を返す。呼び出し側は Mapping の登録と Control の初期化を
    /// 済ませてから [`publish_slot`](Self::publish_slot) で FREE を
    /// 公開すること (公開前の Slot を別スレッドが取得すると、Mapping
    /// の無い Slot で記録が始まってしまう。レビュー #4 の #10)。
    /// 総メモリ上限を超える場合は追加せず None を返す (既存 Slot は不変)。
    pub fn add_slot(&self) -> Option<usize> {
        let mut slots = self.slots.write().unwrap();
        if !self.can_add_slot_with_len(slots.len()) {
            return None;
        }
        slots.push(Arc::new(Slot::preparing(EXPANDED_SLOT_GENERATION)));
        Some(slots.len() - 1)
    }
    /// 追加 Slot の準備完了を公開する (PREPARING→FREE)。
    ///
    /// 順序が要 (R3 の回収公開と同じ原則): Mapping 登録などの準備が
    /// 全て終わってから FREE を Release で公開する。claim 側の Acquire
    /// CAS と対になるため、FREE を見て claim した側は登録済みの
    /// Mapping を必ず観測する。対象が PREPARING でない (初期 Slot や
    /// 二重公開) 場合は何もせず false を返す。
    pub fn publish_slot(&self, index: usize) -> bool {
        let slots = self.slots.read().unwrap();
        let Some(s) = slots.get(index) else {
            return false;
        };
        let published = s
            .state
            .compare_exchange(
                SLOT_PREPARING,
                SLOT_FREE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if published {
            self.free_epoch.fetch_add(1, Ordering::Release);
        }
        published
    }
    pub fn capacity(&self) -> usize {
        self.slots.read().unwrap().len()
    }
    /// Slot 本体を共有する。返した `Arc<Slot>` は追加で Vec が伸びても同じ
    /// Slot を指し続ける (状態・generation は原子操作で読む)。
    pub fn slot(&self, index: usize) -> Arc<Slot> {
        Arc::clone(&self.slots.read().unwrap()[index])
    }
    pub fn free_count(&self) -> usize {
        self.slots
            .read()
            .unwrap()
            .iter()
            .filter(|s| s.state() == SlotState::Free)
            .count()
    }
    /// FREE→CLAIMED→ACTIVE。CAS はこの取得時だけ。低水位では拡張要求だけ立てる。
    pub fn claim(&self, thread_id: u64) -> Option<SlotHandle> {
        // 1 つの読みロックで走査と低水位判定を済ませる (再ロックしない)。
        let slots = self.slots.read().unwrap();
        for (i, s) in slots.iter().enumerate() {
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
                let free = slots
                    .iter()
                    .filter(|s| s.state() == SlotState::Free)
                    .count();
                if free < self.low_watermark
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
        let slots = self.slots.read().unwrap();
        let s = &slots[handle.index];
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
        let slots = self.slots.read().unwrap();
        let s = &slots[handle.index];
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
        let slots = self.slots.read().unwrap();
        let s = &slots[handle.index];
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
    /// RECLAIMABLE→(RECLAIMING)→FREE。Generation を進めてから解放する（古い handle を無効化）。
    ///
    /// 順序が要 (R3): まず RECLAIMABLE→RECLAIMING の CAS で回収権を排他
    /// 取得する。RECLAIMING の間は FREE ではないので誰も claim できず、
    /// Generation の加算と所有者のクリアを安全に行える。最後に FREE を
    /// Release で公開する。claim 側の Acquire CAS と対になるため、FREE を
    /// 見て claim した側は進んだ Generation を必ず観測する。
    /// 以前の実装は FREE への CAS を先に行っており、公開直後に claim した
    /// 新 Producer が旧 Generation を読む競合があった。
    pub fn host_reclaim(&self, handle: &SlotHandle) -> bool {
        let slots = self.slots.read().unwrap();
        let s = &slots[handle.index];
        if s.generation() != handle.generation {
            return false;
        }
        if s.state
            .compare_exchange(
                SLOT_RECLAIMABLE,
                SLOT_RECLAIMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        s.generation.fetch_add(1, Ordering::AcqRel);
        s.owner_thread_id.store(0, Ordering::Release);
        s.state.store(SLOT_FREE, Ordering::Release);
        self.free_epoch.fetch_add(1, Ordering::Release);
        true
    }
    /// Slot が FREE になった回数 (P1-1)。Slot 不足のスレッドが、空きが
    /// 出る見込みのない間に取得を繰り返さないための目印。
    pub fn free_epoch(&self) -> u64 {
        self.free_epoch.load(Ordering::Acquire)
    }
    /// Slot を取らずに欠落を 1 件数える (取得をやり直さない高速経路)。
    /// 更新後の累計を返す。
    pub fn note_missing_call(&self) -> u64 {
        self.process_missing_calls.fetch_add(1, Ordering::Relaxed) + 1
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
    fn add_slot_starts_preparing_with_generation_zero() {
        // A70 + レビュー #4 の #10: 追加 Slot は generation 0・PREPARING
        // (取得不能) から始まり、既存 Slot には影響しない。公開するまで
        // claim はこの Slot を飛ばす。
        let pool = SlotPool::new(2);
        let h = pool.claim(111).unwrap();
        assert_eq!(pool.capacity(), 2);
        let idx = pool.add_slot().unwrap();
        assert_eq!(idx, 2);
        assert_eq!(pool.capacity(), 3);
        assert_eq!(pool.slot(idx).state(), SlotState::Preparing);
        assert_eq!(pool.slot(idx).generation(), 0);
        assert_eq!(pool.slot(idx).owner_thread_id(), 0);
        // 既存 Slot の generation/owner は不変。
        assert_eq!(pool.slot(h.index).generation(), h.generation);
        assert_eq!(pool.slot(h.index).owner_thread_id(), 111);
        assert_eq!(pool.slot(h.index).state(), SlotState::Active);
        // 未公開の間は claim できない (空き数にも数えない)。
        let h2 = pool.claim(222).unwrap();
        assert_eq!(h2.index, 1, "free initial slot is claimed first");
        assert!(pool.claim(333).is_none(), "preparing slot is not claimable");
        assert_eq!(pool.free_count(), 0);
        // 公開後は通常どおり claim できる。
        assert!(pool.publish_slot(idx));
        assert_eq!(pool.slot(idx).state(), SlotState::Free);
        let h3 = pool.claim(333).unwrap();
        assert_eq!(h3.index, idx);
        assert_eq!(h3.generation, 0);
    }
    #[test]
    fn publish_slot_only_from_preparing() {
        let pool = SlotPool::new(1);
        // 初期 Slot は FREE であって PREPARING ではないので公開できない。
        assert!(!pool.publish_slot(0));
        assert_eq!(pool.slot(0).state(), SlotState::Free);
        let idx = pool.add_slot().unwrap();
        assert!(pool.publish_slot(idx));
        // 二重公開はできない。
        assert!(!pool.publish_slot(idx));
        // 範囲外 index は静かに false。
        assert!(!pool.publish_slot(999));
    }
    #[test]
    fn custom_ring_size_controls_expansion_budget() {
        for config in [RingConfig::new(16, 512), RingConfig::BURST] {
            let bytes = config.required_len() as u64;
            let pool = SlotPool::new(1)
                .with_ring_config(config)
                .with_memory_limit(2 * bytes - 1);
            assert_eq!(pool.total_memory_bytes(), bytes);
            assert!(!pool.can_add_slot());
            assert_eq!(pool.add_slot(), None);
            let pool = SlotPool::new(1)
                .with_memory_limit(2 * bytes)
                .with_ring_config(config);
            assert_eq!(pool.add_slot(), Some(1));
            assert_eq!(pool.total_memory_bytes(), 2 * bytes);
            assert!(!pool.can_add_slot());
            assert_eq!(pool.add_slot(), None);
        }
    }
    #[test]
    fn add_slot_respects_memory_limit() {
        // 総メモリ上限を超える場合は追加せず、既存 Slot は不変。
        let pool = SlotPool::new(2).with_memory_limit(2 * SLOT_MEMORY_BYTES);
        assert!(!pool.can_add_slot());
        assert_eq!(pool.add_slot(), None);
        assert_eq!(pool.capacity(), 2);
        // 1 本分の余裕があれば追加できる。
        let roomy = SlotPool::new(2).with_memory_limit(3 * SLOT_MEMORY_BYTES);
        assert!(roomy.can_add_slot());
        assert_eq!(roomy.add_slot(), Some(2));
        assert!(!roomy.can_add_slot());
        assert_eq!(roomy.add_slot(), None);
        assert_eq!(roomy.capacity(), 3);
    }
    #[test]
    fn added_slot_full_lifecycle_and_reuse() {
        // 追加 Slot も初期 Slot と同じ生命環 (DETACH→回収→再利用) をたどる。
        // 再利用では generation が 0→1 に進む。
        let pool = SlotPool::new(1);
        let idx = pool.add_slot().unwrap();
        assert!(pool.publish_slot(idx));
        let h = pool.claim(7).unwrap();
        assert_eq!(h.index, 0, "initial slot is claimed first");
        let h2 = pool.claim(8).unwrap();
        assert_eq!(h2.index, idx);
        assert_eq!(h2.generation, 0);
        assert!(pool.begin_detach(&h2));
        assert!(pool.host_confirm_ended_and_drained(&h2, true, true));
        assert!(pool.host_reclaim(&h2));
        assert_eq!(pool.slot(idx).state(), SlotState::Free);
        assert_eq!(pool.slot(idx).generation(), 1);
        let h3 = pool.claim(9).unwrap();
        assert_eq!(h3.index, idx);
        assert_eq!(h3.generation, 1);
    }
    #[test]
    fn add_slot_after_exhaustion_unblocks_claim() {
        let pool = SlotPool::new(1);
        assert!(pool.claim(1).is_some());
        assert!(pool.claim(2).is_none());
        assert_eq!(pool.add_slot(), Some(1));
        // 未公開の間は不足のまま。公開して初めて claim が通る。
        assert!(pool.claim(2).is_none());
        assert!(pool.publish_slot(1));
        let h = pool.claim(2).unwrap();
        assert_eq!(h.index, 1);
        assert_eq!(h.generation, 0);
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
