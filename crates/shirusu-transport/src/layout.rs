//! 共有メモリ上のレイアウト定義。
//! Control は「書き手が更新する値」と「読み手が更新する値」を別の 64B キャッシュラインに分離する。
//! 共有領域には生ポインタを置かず、すべての位置は論理オフセットで表す。

use std::sync::atomic::{AtomicU64, Ordering};

pub const CACHE_LINE: usize = 64;
/// Control 領域の大きさ（4 キャッシュライン）。
pub const CONTROL_SIZE: usize = 256;
pub const MAGIC: u64 = 0x5348_4952_5553_5531; // "SHIRUSU1"
pub const LAYOUT_VERSION: u64 = 1;

// --- Writer line (offset 0..64): 書き手だけが更新する ---
pub const OFF_WRITE_CURSOR: usize = 0;
pub const OFF_PAYLOAD_WRITE_POSITION: usize = 8;
pub const OFF_DROPPED_EVENTS: usize = 16;
pub const OFF_DROPPED_PAYLOAD_BYTES: usize = 24;
pub const OFF_DEGRADED_EVENTS: usize = 32;
pub const OFF_OVERFLOW_STATE: usize = 40;
pub const OFF_EXPANSION_REQUESTED: usize = 48;
pub const OFF_LAST_WAIT_NS: usize = 56;
// --- Reader line (offset 64..128): 読み手だけが更新する ---
pub const OFF_READ_CURSOR: usize = 64;
pub const OFF_PAYLOAD_READ_POSITION: usize = 72;
pub const OFF_HOST_WAITING: usize = 80;
pub const OFF_RING_STOPPED: usize = 88;
pub const OFF_HOST_DRAIN_COUNT: usize = 96;
// --- Meta line (offset 128..192): 生成時に一度だけ書く。Host は信用せず自分の既知設定を使う ---
pub const OFF_MAGIC: usize = 128;
pub const OFF_LAYOUT_VERSION: usize = 136;
pub const OFF_DESCRIPTOR_CAPACITY: usize = 144;
pub const OFF_PAYLOAD_CAPACITY: usize = 152;
pub const OFF_GENERATION: usize = 160;
pub const OFF_OWNER_THREAD_ID: usize = 168;
// --- Reserved line (192..256) ---
// 192: 書き手が空き待ち中である意思表示（書き手だけが更新）。仕様の通知節:
// 待機の意思を示した後に全順序フェンスを打ち、空きを再確認する。Host はこの
// フラグを見て、空きができたときに space_available を SetEvent する。
pub const OFF_WRITER_WAITING: usize = 192;
// 200: プロセス全体で Slot を取れずに記録しなかった呼び出しの下限値
// (P1-1)。Agent は自分の全 Mapping へ単調に書き (fetch_max)、Host は全
// Ring の最大値を Capture Coverage の欠落として扱う。Slot を持てない
// スレッドには自分の Ring が無いため、他スレッドの Ring の Control を
// プロセス共通の掲示板として使う。Slot 再利用の初期化で 0 に戻っても、
// Host は観測した最大値を保持し、Agent は次の欠落で書き直す。
pub const OFF_PROCESS_MISSING_CALLS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingConfig {
    pub descriptor_capacity: usize,
    pub payload_capacity: usize,
}

impl RingConfig {
    /// 本番既定: Descriptor 4096 件 (=256KiB) / Payload 1MiB。
    pub const PRODUCTION: Self = Self {
        descriptor_capacity: 4096,
        payload_capacity: 1024 * 1024,
    };
    /// Opt-in burst capacity: 5 MiB + Control per Ring. This absorbs short
    /// producer bursts, but cannot guarantee loss-free sustained capture.
    pub const BURST: Self = Self {
        descriptor_capacity: 65536,
        payload_capacity: 1024 * 1024,
    };
    pub fn new(descriptor_capacity: usize, payload_capacity: usize) -> Self {
        assert!(descriptor_capacity >= 2, "descriptor capacity must be >= 2");
        assert!(payload_capacity >= 16, "payload capacity must be >= 16");
        Self {
            descriptor_capacity,
            payload_capacity,
        }
    }
    pub const fn descriptors_offset(&self) -> usize {
        CONTROL_SIZE
    }
    pub const fn payload_offset(&self) -> usize {
        CONTROL_SIZE + self.descriptor_capacity * 64
    }
    pub const fn required_len(&self) -> usize {
        self.payload_offset() + self.payload_capacity
    }
}

/// 純粋な Cursor 演算（Kani / PBT の対象）。
#[inline]
pub fn occupancy(write_cursor: u64, read_cursor: u64) -> Option<u64> {
    write_cursor.checked_sub(read_cursor)
}
#[inline]
pub fn descriptor_free(write_cursor: u64, read_cursor: u64, capacity: u64) -> Option<u64> {
    capacity.checked_sub(occupancy(write_cursor, read_cursor)?)
}
#[inline]
pub fn slot_index(cursor: u64, capacity: u64) -> u64 {
    if capacity == 0 {
        0
    } else if capacity.is_power_of_two() {
        // Production capacities are powers of two: avoid a 64-bit division
        // (tens of cycles) on every published event. Same result as `%`.
        cursor & (capacity - 1)
    } else {
        cursor % capacity
    }
}
#[inline]
pub fn payload_index(position: u64, capacity: u64) -> u64 {
    slot_index(position, capacity)
}
#[inline]
pub fn usage_percent(used: u64, capacity: u64) -> u64 {
    used.saturating_mul(100)
        .checked_div(capacity)
        .unwrap_or(100)
}

/// 書き手が空き待ち中かどうか（Host が space_available の通知要否を判断する）。
#[inline]
pub fn writer_waiting(base: *const u8) -> bool {
    load(base, OFF_WRITER_WAITING, Ordering::Acquire) != 0
}

/// Agent 側: プロセス全体の欠落呼び出し数を掲示する（単調、P1-1）。
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 呼び手が領域の有効性を保証する内部部品
#[inline]
pub fn publish_process_missing_calls(base: *mut u8, total: u64) {
    // SAFETY: load/store と同じ前提（整列済みの有効な共有領域）。
    unsafe { atomic_at(base, OFF_PROCESS_MISSING_CALLS) }.fetch_max(total, Ordering::Relaxed);
}

/// Host 側: 掲示された欠落呼び出し数を読む（信用しない参考値。下限として使う）。
#[inline]
pub fn process_missing_calls(base: *const u8) -> u64 {
    load(base, OFF_PROCESS_MISSING_CALLS, Ordering::Relaxed)
}

/// # Safety
/// `base + offset` が 8 バイト境界にあり、共有領域の存続期間中有効であること。
/// base は File Mapping / ヒープ確保いずれでもページまたは 64 バイト境界に揃っている前提。
pub(crate) unsafe fn atomic_at<'a>(base: *const u8, offset: usize) -> &'a AtomicU64 {
    &*(base.add(offset) as *const AtomicU64)
}

/// 前提 (load/store/fetch_add/init_control 共通): `base` は 8 バイト境界に
/// 揃い、領域が存続期間中有効であること。AtomicU64 の参照を作るため、
/// 整列していないポインタ (例: Vec<u8> の先頭) を渡すと未定義動作になる
/// (Miri 検出済み)。実ベースは File Mapping か 64 バイト整列の確保であり、
/// テストで画像を自前確保する場合は u64 バッファ等で整列を保証すること。
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 呼び手が領域の有効性を保証する内部部品
#[inline]
pub fn load(base: *const u8, offset: usize, order: Ordering) -> u64 {
    unsafe { atomic_at(base, offset) }.load(order)
}
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 呼び手が領域の有効性を保証する内部部品
#[inline]
pub fn store(base: *mut u8, offset: usize, v: u64, order: Ordering) {
    unsafe { atomic_at(base, offset) }.store(v, order)
}
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 呼び手が領域の有効性を保証する内部部品
#[inline]
pub fn swap(base: *mut u8, offset: usize, v: u64, order: Ordering) -> u64 {
    unsafe { atomic_at(base, offset) }.swap(v, order)
}
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 呼び手が領域の有効性を保証する内部部品
#[inline]
pub fn fetch_add(base: *mut u8, offset: usize, v: u64) -> u64 {
    unsafe { atomic_at(base, offset) }.fetch_add(v, Ordering::Relaxed)
}

/// Control 領域を初期化する（生成者のみが呼ぶ）。前提は load/store と共通。
///
/// 公開順序（レビュー第5回 #4）: Magic は**最後**に `Release` で書く。
/// それ以外の全フィールド（ゼロクリア・版数・容量・Generation・
/// Owner）を先に書き終えてから Magic を公開することで、Magic を
/// `Acquire` で読んだ Host は「現れた Magic の向こうには初期化済みの
/// 全フィールドがある」ことを保証される。旧実装は Magic を最初に
/// Relaxed で書いていたため、Host が半初期化の Control（容量 0 や
/// Generation 0）を検証して Ring を止める競合があった。読み手の
/// 述語は `layout::load(base, OFF_MAGIC, Ordering::Acquire) == MAGIC`
/// に統一する（通常のバイト読みは使わない）。
pub fn init_control(base: *mut u8, cfg: RingConfig, generation: u64, owner_thread_id: u64) {
    init_control_fields(base, cfg, generation, owner_thread_id);
    // 単一公開点: この Release store より前の書き込みは、Acquire で
    // Magic を観測した読み手から全て見える。
    store(base, OFF_MAGIC, MAGIC, Ordering::Release);
}

/// [`init_control`] のうち Magic 以外の全て（ゼロクリアと Meta
/// フィールド）を書く。まだ公開はされない。段階的な公開順序の
/// テスト（書き手の途中段階で読み手述語を回す）ために分離してある。
fn init_control_fields(base: *mut u8, cfg: RingConfig, generation: u64, owner_thread_id: u64) {
    for off in (0..CONTROL_SIZE).step_by(8) {
        store(base, off, 0, Ordering::Relaxed);
    }
    store(base, OFF_LAYOUT_VERSION, LAYOUT_VERSION, Ordering::Relaxed);
    store(
        base,
        OFF_DESCRIPTOR_CAPACITY,
        cfg.descriptor_capacity as u64,
        Ordering::Relaxed,
    );
    store(
        base,
        OFF_PAYLOAD_CAPACITY,
        cfg.payload_capacity as u64,
        Ordering::Relaxed,
    );
    store(base, OFF_GENERATION, generation, Ordering::Relaxed);
    store(
        base,
        OFF_OWNER_THREAD_ID,
        owner_thread_id,
        Ordering::Relaxed,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LossCounters {
    pub dropped_events: u64,
    pub dropped_payload_bytes: u64,
    pub degraded_events: u64,
}
impl LossCounters {
    pub fn read_from(base: *const u8) -> Self {
        Self {
            dropped_events: load(base, OFF_DROPPED_EVENTS, Ordering::Relaxed),
            dropped_payload_bytes: load(base, OFF_DROPPED_PAYLOAD_BYTES, Ordering::Relaxed),
            degraded_events: load(base, OFF_DEGRADED_EVENTS, Ordering::Relaxed),
        }
    }
    /// 前回値との差分（単調増加が前提。後退は破損として None）。
    pub fn diff_since(&self, prev: &Self) -> Option<Self> {
        Some(Self {
            dropped_events: self.dropped_events.checked_sub(prev.dropped_events)?,
            dropped_payload_bytes: self
                .dropped_payload_bytes
                .checked_sub(prev.dropped_payload_bytes)?,
            degraded_events: self.degraded_events.checked_sub(prev.degraded_events)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(clippy::assertions_on_constants)] // 定数の配置自体を固定するのが目的
    fn writer_and_reader_lines_are_separate() {
        assert!(OFF_WRITE_CURSOR / 64 != OFF_READ_CURSOR / 64);
        assert!(OFF_DROPPED_EVENTS / 64 == OFF_WRITE_CURSOR / 64);
        assert!(OFF_PAYLOAD_READ_POSITION / 64 == OFF_READ_CURSOR / 64);
        assert!(OFF_MAGIC / 64 >= 2);
    }
    #[test]
    #[allow(clippy::assertions_on_constants)] // 定数の配置自体を固定するのが目的
    fn writer_waiting_flag_lives_in_reserved_line() {
        // 書き手更新だが Writer line は満杯のため Reserved line を使う。
        // Reader line とは別キャッシュラインで、8 バイト境界にあること。
        assert!(OFF_WRITER_WAITING >= 192 && OFF_WRITER_WAITING < CONTROL_SIZE);
        assert_eq!(OFF_WRITER_WAITING % 8, 0);
        assert!(OFF_WRITER_WAITING / 64 != OFF_READ_CURSOR / 64);
        assert!(OFF_WRITER_WAITING / 64 != OFF_WRITE_CURSOR / 64);
    }
    #[test]
    fn cursor_math() {
        assert_eq!(occupancy(10, 3), Some(7));
        assert_eq!(occupancy(3, 10), None);
        assert_eq!(descriptor_free(10, 3, 16), Some(9));
        assert_eq!(slot_index(4097, 4096), 1);
        assert_eq!(usage_percent(1, 4), 25);
        assert_eq!(usage_percent(0, 0), 100);
    }
    #[test]
    fn production_config_sizes() {
        let c = RingConfig::PRODUCTION;
        assert_eq!(c.descriptor_capacity * 64, 256 * 1024);
        assert_eq!(c.required_len(), 256 + 256 * 1024 + 1024 * 1024);
    }
    /// 読み手述語 (Host と同一の形): Magic を Acquire で読む。
    fn reader_sees_initialized(base: *const u8) -> bool {
        load(base, OFF_MAGIC, Ordering::Acquire) == MAGIC
    }

    #[test]
    fn init_control_publishes_magic_last_staged() {
        // レビュー第5回 #4 の段階テスト: 書き手の途中段階ごとに読み手
        // 述語を回し、最終の Magic 公開より前は「初期化済み」に
        // ならないことを確認する。旧順序 (Magic を最初に書く) では
        // fields 書き込みの前に述語が真になり、このテストが落ちる
        // (旧順序そのものは loom の検出モデルでも固定してある)。
        use crate::validate::{validate_control, IntegrityError, KnownConfig};
        let cfg = RingConfig::new(8, 256);
        let mut words = [0xDEAD_BEEF_DEAD_BEEFu64; CONTROL_SIZE / 8];
        let base = words.as_mut_ptr() as *mut u8;
        // 段階 0: 未初期化 (ゴミ)。述語は偽。
        assert!(!reader_sees_initialized(base));
        // 段階 1: ゼロクリア + 全フィールド書き込み (公開前)。
        // フィールドは直接読めば揃っているが、述語はまだ偽であり、
        // 検証側も BadMagic で弾く (Host が Ring を作らない)。
        init_control_fields(base, cfg, 7, 42);
        assert_eq!(load(base, OFF_LAYOUT_VERSION, Ordering::Relaxed), 1);
        assert_eq!(load(base, OFF_DESCRIPTOR_CAPACITY, Ordering::Relaxed), 8);
        assert_eq!(load(base, OFF_GENERATION, Ordering::Relaxed), 7);
        assert_eq!(load(base, OFF_OWNER_THREAD_ID, Ordering::Relaxed), 42);
        assert!(!reader_sees_initialized(base));
        let copy: [u8; CONTROL_SIZE] = unsafe { *(base as *const [u8; CONTROL_SIZE]) };
        let known = KnownConfig::new(cfg, cfg.required_len());
        assert_eq!(
            validate_control(&copy, &known, None),
            Err(IntegrityError::BadMagic)
        );
        // 段階 2: Magic を Release で公開 (init_control の最終段と同一)。
        store(base, OFF_MAGIC, MAGIC, Ordering::Release);
        assert!(reader_sees_initialized(base));
        let copy: [u8; CONTROL_SIZE] = unsafe { *(base as *const [u8; CONTROL_SIZE]) };
        let snap = validate_control(&copy, &known, None).expect("initialized control validates");
        assert_eq!(snap.generation, 7);
        // 一括の init_control でも同じ到達状態になる。
        let mut words2 = [0u64; CONTROL_SIZE / 8];
        let base2 = words2.as_mut_ptr() as *mut u8;
        init_control(base2, cfg, 7, 42);
        assert!(reader_sees_initialized(base2));
        assert_eq!(words2, words);
    }

    #[test]
    fn loss_counters_are_monotonic_diff() {
        let a = LossCounters {
            dropped_events: 5,
            dropped_payload_bytes: 10,
            degraded_events: 1,
        };
        let b = LossCounters {
            dropped_events: 9,
            dropped_payload_bytes: 10,
            degraded_events: 3,
        };
        assert_eq!(
            b.diff_since(&a),
            Some(LossCounters {
                dropped_events: 4,
                dropped_payload_bytes: 0,
                degraded_events: 2
            })
        );
        assert_eq!(a.diff_since(&b), None);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// 占有量は w >= read のときちょうど差であり、それ以外は None (後退検出)。
    #[kani::proof]
    fn occupancy_is_exact_difference_or_none() {
        let w: u64 = kani::any();
        let r: u64 = kani::any();
        match occupancy(w, r) {
            Some(d) => {
                assert!(w >= r);
                assert!(d == w - r);
            }
            None => assert!(w < r),
        }
    }

    /// 空き容量は容量を超えず、占有量と相補である (全折り返しケース)。
    #[kani::proof]
    fn descriptor_free_never_exceeds_capacity() {
        let w: u64 = kani::any();
        let r: u64 = kani::any();
        let cap: u64 = kani::any();
        if let Some(f) = descriptor_free(w, r, cap) {
            assert!(f <= cap);
            assert!(occupancy(w, r) == Some(cap - f));
        }
    }

    /// スロット位置は剰余そのもので、容量未満に収まる。
    /// 範囲は小さく制限する: 記号除算は CBMC のビットブラストでは幅に
    /// 強く依存して遅く、16 bit 幅でも 20 CPU 分を超えて解けなかった (実測)。
    /// 剰余の定義そのものは幅に依存しないため、小さい範囲で証明し、
    /// 任意幅での等価性は境界テスト (u64 極値) と PBT が担う。
    #[kani::proof]
    fn slot_index_is_remainder_and_in_range() {
        let c: u64 = kani::any();
        let cap: u64 = kani::any();
        kani::assume(c < 4096 && cap >= 1 && cap <= 64);
        let idx = slot_index(c, cap);
        assert!(idx == c % cap);
        assert!(idx < cap);
    }

    /// 容量 0 では除算せず 0 に潰れる (任意の Cursor 値で)。
    #[kani::proof]
    fn slot_index_zero_capacity_is_zero() {
        let c: u64 = kani::any();
        assert!(slot_index(c, 0) == 0);
    }
}
