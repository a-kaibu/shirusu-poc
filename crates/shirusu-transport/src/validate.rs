//! Host による共有メモリの検証（writer 用 API とは分離した純粋関数群）。
//! 共有メモリ上の設定値は信用せず、Host 既知の範囲だけを読む。
//! コピーしてから検証し、読み直さない。矛盾したら Ring 停止 + Event Integrity 喪失。
//! 範囲外コピーは絶対にしない。

use crate::descriptor::{EventDescriptor, EventKind};
use crate::layout::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownConfig {
    pub descriptor_capacity: u64,
    pub payload_capacity: u64,
    pub mapping_len: usize,
}
impl KnownConfig {
    pub fn new(cfg: RingConfig, mapping_len: usize) -> Self {
        Self {
            descriptor_capacity: cfg.descriptor_capacity as u64,
            payload_capacity: cfg.payload_capacity as u64,
            mapping_len,
        }
    }
    fn ring_cfg(&self) -> RingConfig {
        RingConfig {
            descriptor_capacity: self.descriptor_capacity as usize,
            payload_capacity: self.payload_capacity as usize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    ImageTooSmall,
    CursorRegressed {
        which: &'static str,
    },
    OccupancyExceedsCapacity {
        occupancy: u64,
        capacity: u64,
    },
    CounterRegressed,
    UnknownKind(u16),
    ReservedNonZero,
    PayloadTooLarge {
        len: u64,
        capacity: u64,
    },
    PayloadRangeInvalid,
    /// Payload 位置が制御スナップショットの書き込み済み範囲を超えている。
    /// `end` は position + 格納済み長（落とした Payload は 0）。
    PayloadPositionOutOfRange {
        position: u64,
        end: u64,
        write_position: u64,
    },
    /// Payload 位置が前件の終端と連続していない。書き手は Payload を
    /// Descriptor と同じ順に隙間なく確保するため、ずれは矛盾である。
    PayloadPositionNotContiguous {
        expected: u64,
        found: u64,
    },
    GenerationMismatch {
        expected: u64,
        found: u64,
    },
    SequenceRegressed {
        expected_at_least: u64,
        found: u64,
    },
    RingStopped,
    BadMagic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ControlSnapshot {
    pub write_cursor: u64,
    pub read_cursor: u64,
    pub payload_write_position: u64,
    pub payload_read_position: u64,
    pub generation: u64,
    pub loss: LossCounters,
}

/// Cursor 対の検証（純粋関数。Kani/Fuzz の中心）。
pub fn validate_cursor_pair(write: u64, read: u64, capacity: u64) -> Result<u64, IntegrityError> {
    let occ = occupancy(write, read).ok_or(IntegrityError::CursorRegressed {
        which: "write<read",
    })?;
    if occ > capacity {
        return Err(IntegrityError::OccupancyExceedsCapacity {
            occupancy: occ,
            capacity,
        });
    }
    Ok(occ)
}

/// Control 領域（256 バイト）のコピーから検証する。共有メモリを読み直さない前提で、
/// 呼び手は先に 256 バイトを Host 側へコピーしてから渡すこと。
pub fn validate_control(
    control_copy: &[u8],
    known: &KnownConfig,
    prev: Option<&ControlSnapshot>,
) -> Result<ControlSnapshot, IntegrityError> {
    if control_copy.len() < CONTROL_SIZE || known.mapping_len < known.ring_cfg().required_len() {
        return Err(IntegrityError::ImageTooSmall);
    }
    let g =
        |off: usize| -> u64 { u64::from_le_bytes(control_copy[off..off + 8].try_into().unwrap()) };
    if g(OFF_MAGIC) != MAGIC {
        return Err(IntegrityError::BadMagic);
    }
    // 共有メモリ上の容量は信用しない: 使うのは known の値だけ。ここでは矛盾の検出のみ行う。
    let snap = ControlSnapshot {
        write_cursor: g(OFF_WRITE_CURSOR),
        read_cursor: g(OFF_READ_CURSOR),
        payload_write_position: g(OFF_PAYLOAD_WRITE_POSITION),
        payload_read_position: g(OFF_PAYLOAD_READ_POSITION),
        generation: g(OFF_GENERATION),
        loss: LossCounters {
            dropped_events: g(OFF_DROPPED_EVENTS),
            dropped_payload_bytes: g(OFF_DROPPED_PAYLOAD_BYTES),
            degraded_events: g(OFF_DEGRADED_EVENTS),
        },
    };
    validate_cursor_pair(
        snap.write_cursor,
        snap.read_cursor,
        known.descriptor_capacity,
    )?;
    validate_cursor_pair(
        snap.payload_write_position,
        snap.payload_read_position,
        known.payload_capacity,
    )?;
    if let Some(p) = prev {
        // 世代が違う像は別 Ring のものなので、Cursor 比較より先に世代で弾く。
        if snap.generation != p.generation {
            return Err(IntegrityError::GenerationMismatch {
                expected: p.generation,
                found: snap.generation,
            });
        }
        if snap.write_cursor < p.write_cursor || snap.read_cursor < p.read_cursor {
            return Err(IntegrityError::CursorRegressed {
                which: "vs previous snapshot",
            });
        }
        // Payload 位置も単調にしか進まない（書き手は書き込み位置を前にしか進めず、
        // 読み手は読み位置を前にしか進めない）。後退は破壊された像として弾く。
        // D57 の fuzz が見つけた穴：以前は Cursor だけを照合し、Payload 位置の
        // 後退した像を受理していた。
        if snap.payload_write_position < p.payload_write_position
            || snap.payload_read_position < p.payload_read_position
        {
            return Err(IntegrityError::CursorRegressed {
                which: "payload position vs previous snapshot",
            });
        }
        if snap.loss.diff_since(&p.loss).is_none() {
            return Err(IntegrityError::CounterRegressed);
        }
    }
    Ok(snap)
}

/// 64 バイトの Descriptor コピーを検証して復号する。
pub fn decode_descriptor(
    bytes: &[u8],
    known: &KnownConfig,
) -> Result<EventDescriptor, IntegrityError> {
    if bytes.len() < 64 {
        return Err(IntegrityError::ImageTooSmall);
    }
    let d = EventDescriptor::from_bytes(&bytes[..64]).ok_or(IntegrityError::ImageTooSmall)?;
    if EventKind::from_u16(d.kind).is_none() || d.kind == EventKind::Unknown as u16 {
        return Err(IntegrityError::UnknownKind(d.kind));
    }
    if d.reserved != 0 {
        return Err(IntegrityError::ReservedNonZero);
    }
    if d.payload_len as u64 > known.payload_capacity {
        return Err(IntegrityError::PayloadTooLarge {
            len: d.payload_len as u64,
            capacity: known.payload_capacity,
        });
    }
    Ok(d)
}

/// 格納済み Payload 長。落とした Payload は Ring に書かれていないので 0。
/// 劣化 Descriptor の payload_len は「落とした元の長さ」であり、位置の
/// 連続性では 0 として扱う（書き手は落とした分だけ書き込み位置を進めない）。
fn stored_payload_len(desc: &EventDescriptor) -> u64 {
    if desc.payload_dropped() {
        0
    } else {
        desc.payload_len as u64
    }
}

/// Host 検証手順 4（spec）で Descriptor 1 件に期待する値。
/// Sequence は欠番（保存に失敗したイベントにも割り当てる）を許すため下限のみ
/// 照合し、Payload 位置は書き手の単調な論理オフセットなので前件との連続性を
/// 正確に照合する。`payload_position` が None のときは連続性を検査しない
/// （その Reader が初めて見る Descriptor の場合のアンカー）。
/// Generation は EventDescriptor にフィールドが無く（spec の Descriptor 定義
/// にも無い）、Control 領域の世代として validate_control / ValidatingReader
/// で照合する。ここでは扱わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorExpectation {
    pub sequence_at_least: u64,
    pub payload_position: Option<u64>,
    pub payload_write_position: u64,
}

/// decode_descriptor に加え、仕様の Host 検証手順 4 の残り（Sequence・
/// オフセット）を照合する純粋関数。像のコピーが書き手の公開途中で切れた
/// 場合も矛盾として扱う（fail-closed。Ring を止めるのは安全側である）。
pub fn decode_descriptor_checked(
    bytes: &[u8],
    known: &KnownConfig,
    expected: &DescriptorExpectation,
) -> Result<EventDescriptor, IntegrityError> {
    let d = decode_descriptor(bytes, known)?;
    // Sequence: 書き手は 1 から振る。確定済みスロットに 0 が現れるのは
    // 未公開スロットの混入（write_cursor だけが進んだ壊れた像）であり矛盾。
    if d.sequence < expected.sequence_at_least {
        return Err(IntegrityError::SequenceRegressed {
            expected_at_least: expected.sequence_at_least,
            found: d.sequence,
        });
    }
    let stored = stored_payload_len(&d);
    let end = d
        .payload_position
        .checked_add(stored)
        .ok_or(IntegrityError::PayloadRangeInvalid)?;
    if end > expected.payload_write_position {
        return Err(IntegrityError::PayloadPositionOutOfRange {
            position: d.payload_position,
            end,
            write_position: expected.payload_write_position,
        });
    }
    if let Some(pos) = expected.payload_position {
        if d.payload_position != pos {
            return Err(IntegrityError::PayloadPositionNotContiguous {
                expected: pos,
                found: d.payload_position,
            });
        }
    }
    Ok(d)
}

/// Descriptor が指す Payload を、Host 既知の範囲内だけでコピーする（折り返し対応）。
/// Payload を落とした Descriptor は空を返す（範囲に触らない）。
pub fn decode_payload(
    desc: &EventDescriptor,
    payload_region: &[u8],
    known: &KnownConfig,
) -> Result<Vec<u8>, IntegrityError> {
    if desc.payload_dropped() || desc.payload_len == 0 {
        return Ok(Vec::new());
    }
    let cap = known.payload_capacity as usize;
    if payload_region.len() < cap || desc.payload_len as usize > cap {
        return Err(IntegrityError::PayloadRangeInvalid);
    }
    let len = desc.payload_len as usize;
    let start = (desc.payload_position % known.payload_capacity) as usize;
    let mut out = vec![0u8; len];
    let first = core::cmp::min(len, cap - start);
    out[..first].copy_from_slice(&payload_region[start..start + first]);
    if first < len {
        out[first..].copy_from_slice(&payload_region[..len - first]);
    }
    Ok(out)
}

/// 共有メモリ像（バイト列）を読む検証付きリーダー。
/// 一度検証した値はコピーだけを使い、像を読み直さない。
pub struct ValidatingReader {
    known: KnownConfig,
    prev: Option<ControlSnapshot>,
    read_cursor: u64,
    expected_sequence: u64,
    expected_generation: u64,
    /// 次に期待する Payload 論理位置（None は未確立＝初めて見る Descriptor）。
    expected_payload_position: Option<u64>,
    stopped: bool,
}
impl ValidatingReader {
    pub fn new(known: KnownConfig, expected_generation: u64) -> Self {
        Self {
            known,
            prev: None,
            read_cursor: 0,
            expected_sequence: 1,
            expected_generation,
            expected_payload_position: None,
            stopped: false,
        }
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn control_snapshot(&self) -> Option<ControlSnapshot> {
        self.prev
    }
    /// 像全体を受け取り、確定分を検証しながら取り出す。矛盾したら Ring を止める。
    pub fn drain_image(
        &mut self,
        image: &[u8],
    ) -> Result<Vec<crate::ring::ReceivedEvent>, IntegrityError> {
        if self.stopped {
            return Err(IntegrityError::RingStopped);
        }
        let result = self.drain_inner(image);
        if result.is_err() {
            self.stopped = true; // 矛盾を見つけたらその Ring を止める
        }
        result
    }
    fn drain_inner(
        &mut self,
        image: &[u8],
    ) -> Result<Vec<crate::ring::ReceivedEvent>, IntegrityError> {
        let cfg = self.known.ring_cfg();
        if image.len() < cfg.required_len() || self.known.mapping_len < cfg.required_len() {
            return Err(IntegrityError::ImageTooSmall);
        }
        // 1. Control をコピーして検証（共有値を直接使わない）
        let control_copy = image[..CONTROL_SIZE].to_vec();
        let snap = validate_control(&control_copy, &self.known, self.prev.as_ref())?;
        if snap.generation != self.expected_generation {
            return Err(IntegrityError::GenerationMismatch {
                expected: self.expected_generation,
                found: snap.generation,
            });
        }
        self.prev = Some(snap);
        // 2. 確定した範囲の Descriptor だけをコピーして検証
        let mut events = Vec::new();
        // Host 自身が前回までに読んだ位置を正とし、共有 read_cursor は検証材料にのみ使う。
        let mut cursor = self.read_cursor;
        if cursor > snap.write_cursor {
            return Err(IntegrityError::CursorRegressed {
                which: "host read beyond write",
            });
        }
        while cursor < snap.write_cursor {
            let idx = slot_index(cursor, self.known.descriptor_capacity) as usize;
            let off = cfg.descriptors_offset() + idx * 64;
            let desc_copy = image[off..off + 64].to_vec();
            // 仕様の Host 検証手順 4: 長さ・オフセット・Sequence を照合する。
            // Generation は Control 領域で既に照合済み（上記）。
            let expectation = DescriptorExpectation {
                sequence_at_least: self.expected_sequence,
                payload_position: self.expected_payload_position,
                payload_write_position: snap.payload_write_position,
            };
            let desc = decode_descriptor_checked(&desc_copy, &self.known, &expectation)?;
            if desc.sequence >= self.expected_sequence {
                self.expected_sequence = desc.sequence + 1;
            }
            self.expected_payload_position =
                Some(desc.payload_position + stored_payload_len(&desc));
            // 3. 有効範囲に限って Payload をコピー
            let payload_region =
                &image[cfg.payload_offset()..cfg.payload_offset() + cfg.payload_capacity];
            let payload = decode_payload(&desc, payload_region, &self.known)?;
            events.push(crate::ring::ReceivedEvent {
                descriptor: desc,
                payload,
            });
            cursor += 1;
        }
        self.read_cursor = cursor;
        Ok(events)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn occupancy_never_exceeds_capacity_when_valid() {
        let w: u64 = kani::any();
        let r: u64 = kani::any();
        let cap: u64 = kani::any();
        kani::assume(cap <= 1_000_000);
        if let Ok(occ) = validate_cursor_pair(w, r, cap) {
            assert!(occ <= cap);
            assert!(w >= r);
        }
    }
    #[kani::proof]
    fn decode_descriptor_rejects_oversized_payload() {
        let mut bytes = [0u8; 64];
        let len: u32 = kani::any();
        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&len.to_le_bytes());
        let known = KnownConfig {
            descriptor_capacity: 16,
            payload_capacity: 1024,
            mapping_len: usize::MAX,
        };
        if let Ok(d) = decode_descriptor(&bytes, &known) {
            assert!(d.payload_len <= 1024);
        }
    }

    /// Payload 範囲検証: 任意の位置・長さでも、返る内容は領域の回転と一致し、
    /// 範囲外には絶対に触らない。落ちた Descriptor と長さ 0 は空を返す。
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_payload_stays_in_range_and_matches_rotation() {
        let mut desc = EventDescriptor::new(EventKind::CallEnter, 1);
        desc.payload_position = kani::any();
        // 範囲を強く絞る: 記号長での確保+コピーは CBMC では桁違いに重く、
        // 長さ 16 でも現実時間で解けなかった (実測)。回転コピーの性質
        // (折り返し有無と剰余) は長さ<=4・位置<256 でも全分岐が現れるため
        // ここまで絞り、大きな値は境界/PBT/fuzz が担う。
        kani::assume(desc.payload_position < 256);
        let len: u32 = kani::any();
        kani::assume(len <= 4);
        desc.payload_len = len;
        let dropped: bool = kani::any();
        if dropped {
            desc.flags = crate::descriptor::flags::PAYLOAD_DROPPED;
        }
        let mut region = [0u8; 32];
        let mut i = 0usize;
        while i < 32 {
            region[i] = i as u8;
            i += 1;
        }
        let known = KnownConfig {
            descriptor_capacity: 4,
            payload_capacity: 32,
            mapping_len: usize::MAX,
        };
        let out = decode_payload(&desc, &region, &known).unwrap();
        if dropped || len == 0 {
            assert!(out.is_empty());
        } else {
            assert!(out.len() == len as usize);
            let start = (desc.payload_position % 32) as usize;
            let mut j = 0usize;
            while j < out.len() {
                assert!(out[j] == region[(start + j) % 32]);
                j += 1;
            }
        }
    }

    /// Loss カウンタ差分: Some なら各フィールドの正確な差であり、
    /// None ならいずれかのフィールドが後退している (単調性のモデル)。
    #[kani::proof]
    fn loss_counter_diff_is_exact_or_regression() {
        let a = LossCounters {
            dropped_events: kani::any(),
            dropped_payload_bytes: kani::any(),
            degraded_events: kani::any(),
        };
        let b = LossCounters {
            dropped_events: kani::any(),
            dropped_payload_bytes: kani::any(),
            degraded_events: kani::any(),
        };
        match b.diff_since(&a) {
            Some(d) => {
                assert!(d.dropped_events == b.dropped_events - a.dropped_events);
                assert!(
                    d.dropped_payload_bytes == b.dropped_payload_bytes - a.dropped_payload_bytes
                );
                assert!(d.degraded_events == b.degraded_events - a.degraded_events);
            }
            None => {
                assert!(
                    b.dropped_events < a.dropped_events
                        || b.dropped_payload_bytes < a.dropped_payload_bytes
                        || b.degraded_events < a.degraded_events
                );
            }
        }
    }

    /// Descriptor 解釈の安全性: 受理されるのは既知 Kind・reserved 0・
    /// 長さが容量以内のものだけ (全フィールド任意入力)。
    #[kani::proof]
    fn decode_descriptor_accepts_only_safe_descriptors() {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
        d.kind = kani::any();
        d.payload_len = kani::any();
        d.reserved = kani::any();
        let known = KnownConfig {
            descriptor_capacity: 4,
            payload_capacity: 64,
            mapping_len: usize::MAX,
        };
        if let Ok(ok) = decode_descriptor(&d.to_bytes(), &known) {
            assert!(EventKind::from_u16(ok.kind).is_some());
            assert!(ok.kind != EventKind::Unknown as u16);
            assert!(ok.reserved == 0);
            assert!(ok.payload_len <= 64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RingConfig;

    /// Vec<u8> はポインタの 8 バイト整列を保証しないため、layout の原子操作
    /// (AtomicU64 参照を作る) を適用する画像は u64 バッファで保持する。
    /// 整列していないポインタへの原子操作は UB (Miri 検出)。
    pub struct AlignedImage {
        words: Vec<u64>,
        len: usize,
    }
    impl AlignedImage {
        pub fn zeroed(len: usize) -> Self {
            Self {
                words: vec![0; len.div_ceil(8)],
                len,
            }
        }
        pub fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
        }
        pub fn as_mut_ptr(&mut self) -> *mut u8 {
            self.words.as_mut_ptr() as *mut u8
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
        }
    }
    impl std::ops::Deref for AlignedImage {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            self.as_slice()
        }
    }

    fn known() -> KnownConfig {
        KnownConfig::new(
            RingConfig::new(16, 256),
            RingConfig::new(16, 256).required_len(),
        )
    }
    fn control_image(write: u64, read: u64) -> AlignedImage {
        let cfg = RingConfig::new(16, 256);
        let mut img = AlignedImage::zeroed(cfg.required_len());
        init_control(img.as_mut_ptr(), cfg, 3, 9);
        store(
            img.as_mut_ptr(),
            OFF_WRITE_CURSOR,
            write,
            std::sync::atomic::Ordering::Relaxed,
        );
        store(
            img.as_mut_ptr(),
            OFF_READ_CURSOR,
            read,
            std::sync::atomic::Ordering::Relaxed,
        );
        img
    }
    #[test]
    fn validate_control_ok_and_regression() {
        let img = control_image(5, 2);
        let s = validate_control(&img[..CONTROL_SIZE], &known(), None).unwrap();
        assert_eq!(s.write_cursor, 5);
        let img2 = control_image(4, 2);
        assert!(matches!(
            validate_control(&img2[..CONTROL_SIZE], &known(), Some(&s)),
            Err(IntegrityError::CursorRegressed { .. })
        ));
    }
    #[test]
    fn validate_control_rejects_payload_position_regression() {
        // D57 の fuzz が見つけた穴：前像より Payload 位置が後退した像を
        // validate_control が受理していた。書き手の payload_write_position は
        // 単調にしか進まないため、後退は破壊された像として弾く。
        use std::sync::atomic::Ordering::Relaxed;
        let mut img1 = control_image(5, 2);
        store(img1.as_mut_ptr(), OFF_PAYLOAD_WRITE_POSITION, 100, Relaxed);
        store(img1.as_mut_ptr(), OFF_PAYLOAD_READ_POSITION, 40, Relaxed);
        let s = validate_control(&img1[..CONTROL_SIZE], &known(), None).unwrap();
        // 書き込み位置の後退を弾く。
        let mut img2 = control_image(6, 3);
        store(img2.as_mut_ptr(), OFF_PAYLOAD_WRITE_POSITION, 99, Relaxed);
        store(img2.as_mut_ptr(), OFF_PAYLOAD_READ_POSITION, 40, Relaxed);
        assert!(matches!(
            validate_control(&img2[..CONTROL_SIZE], &known(), Some(&s)),
            Err(IntegrityError::CursorRegressed { .. })
        ));
        // 読み位置の後退も弾く。
        let mut img3 = control_image(6, 3);
        store(img3.as_mut_ptr(), OFF_PAYLOAD_WRITE_POSITION, 100, Relaxed);
        store(img3.as_mut_ptr(), OFF_PAYLOAD_READ_POSITION, 39, Relaxed);
        assert!(matches!(
            validate_control(&img3[..CONTROL_SIZE], &known(), Some(&s)),
            Err(IntegrityError::CursorRegressed { .. })
        ));
        // 前進は受理する。
        let mut img4 = control_image(6, 3);
        store(img4.as_mut_ptr(), OFF_PAYLOAD_WRITE_POSITION, 120, Relaxed);
        store(img4.as_mut_ptr(), OFF_PAYLOAD_READ_POSITION, 40, Relaxed);
        assert!(validate_control(&img4[..CONTROL_SIZE], &known(), Some(&s)).is_ok());
    }
    #[test]
    fn validate_control_rejects_occupancy_overflow() {
        let img = control_image(100, 0);
        assert!(matches!(
            validate_control(&img[..CONTROL_SIZE], &known(), None),
            Err(IntegrityError::OccupancyExceedsCapacity { .. })
        ));
    }
    #[test]
    fn decode_descriptor_rejects_unknown_kind_and_huge_len() {
        let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
        d.kind = 999;
        assert!(matches!(
            decode_descriptor(&d.to_bytes(), &known()),
            Err(IntegrityError::UnknownKind(999))
        ));
        let mut d2 = EventDescriptor::new(EventKind::CallEnter, 1);
        d2.payload_len = u32::MAX;
        assert!(matches!(
            decode_descriptor(&d2.to_bytes(), &known()),
            Err(IntegrityError::PayloadTooLarge { .. })
        ));
    }
    #[test]
    fn decode_descriptor_checked_enforces_sequence_and_position() {
        let known = known();
        let exp = |seq: u64, pos: Option<u64>, wp: u64| DescriptorExpectation {
            sequence_at_least: seq,
            payload_position: pos,
            payload_write_position: wp,
        };
        let mut d = EventDescriptor::new(EventKind::CallEnter, 3);
        d.payload_position = 10;
        d.payload_len = 4;
        // 正常: 期待どおりの Sequence・位置・書き込み済み範囲内
        assert!(decode_descriptor_checked(&d.to_bytes(), &known, &exp(3, Some(10), 14)).is_ok());
        // Sequence が下限未満（欠番は許すが後退は許さない）
        assert!(matches!(
            decode_descriptor_checked(&d.to_bytes(), &known, &exp(4, Some(10), 14)),
            Err(IntegrityError::SequenceRegressed {
                expected_at_least: 4,
                found: 3
            })
        ));
        // Sequence 0 は書き手が絶対に振らない値なので後退として扱う
        let mut zero = EventDescriptor::new(EventKind::CallEnter, 0);
        zero.payload_len = 0;
        assert!(matches!(
            decode_descriptor_checked(&zero.to_bytes(), &known, &exp(1, Some(0), 0)),
            Err(IntegrityError::SequenceRegressed {
                expected_at_least: 1,
                found: 0
            })
        ));
        // 位置が前件の終端と連続していない
        assert!(matches!(
            decode_descriptor_checked(&d.to_bytes(), &known, &exp(3, Some(11), 14)),
            Err(IntegrityError::PayloadPositionNotContiguous {
                expected: 11,
                found: 10
            })
        ));
        // 位置＋格納長が書き込み済み範囲を超えている
        assert!(matches!(
            decode_descriptor_checked(&d.to_bytes(), &known, &exp(3, Some(10), 13)),
            Err(IntegrityError::PayloadPositionOutOfRange {
                position: 10,
                end: 14,
                write_position: 13
            })
        ));
        // 落とした Payload は格納長 0: 位置は書き込み位置のままでよく、
        // 次件も同じ位置から始まる（位置の再利用）
        let mut dropped = EventDescriptor::new(EventKind::CallEnter, 3);
        dropped.payload_position = 10;
        dropped.payload_len = 5;
        dropped.flags = crate::descriptor::flags::PAYLOAD_DROPPED;
        assert!(
            decode_descriptor_checked(&dropped.to_bytes(), &known, &exp(3, Some(10), 10)).is_ok()
        );
        // アンカー未確立（初めて見る Descriptor）の場合は位置の連続性を問わない
        let mut far = EventDescriptor::new(EventKind::CallEnter, 7);
        far.payload_position = 999;
        far.payload_len = 0;
        assert!(decode_descriptor_checked(&far.to_bytes(), &known, &exp(7, None, 999)).is_ok());
    }

    #[test]
    fn validating_reader_rejects_corrupt_payload_position() {
        use crate::clock::ManualClock;
        use crate::ring::{SharedRegion, WriterPolicy};
        let cfg = RingConfig::new(8, 256);
        let known = KnownConfig::new(cfg, cfg.required_len());
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: std::sync::Arc<dyn crate::clock::Clock> =
            std::sync::Arc::new(ManualClock::new());
        let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
        for p in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            w.write(crate::ring::EventInput {
                kind: EventKind::CallEnter,
                api_id: 1,
                schema_id: 1,
                call_id: 1,
                parent_call_id: 0,
                payload: p,
                capture_state: crate::descriptor::CaptureState::Captured,
            });
        }
        // 2 件目の Descriptor の payload_position だけを +1 ずらす
        let mut image = AlignedImage::zeroed(cfg.required_len());
        image.as_mut_slice().copy_from_slice(region.as_slice());
        let off = cfg.descriptors_offset() + 64;
        let mut d = EventDescriptor::from_bytes(&image[off..off + 64]).unwrap();
        assert_eq!(d.payload_position, 3);
        d.payload_position = 4;
        image.as_mut_slice()[off..off + 64].copy_from_slice(&d.to_bytes());
        let mut vr = ValidatingReader::new(known, 1);
        assert!(matches!(
            vr.drain_image(image.as_slice()),
            Err(IntegrityError::PayloadPositionNotContiguous {
                expected: 3,
                found: 4
            })
        ));
        assert!(vr.is_stopped());
    }

    #[test]
    fn validating_reader_rejects_zero_sequence_slot() {
        use crate::clock::ManualClock;
        use crate::layout::OFF_WRITE_CURSOR;
        use crate::ring::{SharedRegion, WriterPolicy};
        let cfg = RingConfig::new(8, 256);
        let known = KnownConfig::new(cfg, cfg.required_len());
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: std::sync::Arc<dyn crate::clock::Clock> =
            std::sync::Arc::new(ManualClock::new());
        let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
        w.write(crate::ring::EventInput {
            kind: EventKind::CallEnter,
            api_id: 1,
            schema_id: 1,
            call_id: 1,
            parent_call_id: 0,
            payload: b"one",
            capture_state: crate::descriptor::CaptureState::Captured,
        });
        // write_cursor だけを 2 に進め、slot 1 に Sequence 0 の Descriptor を置く
        // （書き手は 1 から振るため、確定済みスロットの 0 は未公開スロットの混入＝矛盾）
        let mut image = AlignedImage::zeroed(cfg.required_len());
        image.as_mut_slice().copy_from_slice(region.as_slice());
        let off = cfg.descriptors_offset() + 64;
        let zero_seq = EventDescriptor::new(EventKind::CallEnter, 0);
        image.as_mut_slice()[off..off + 64].copy_from_slice(&zero_seq.to_bytes());
        crate::layout::store(
            image.as_mut_ptr(),
            OFF_WRITE_CURSOR,
            2,
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut vr = ValidatingReader::new(known, 1);
        assert!(matches!(
            vr.drain_image(image.as_slice()),
            Err(IntegrityError::SequenceRegressed {
                expected_at_least: 2,
                found: 0
            })
        ));
        assert!(vr.is_stopped());
    }

    #[test]
    fn validating_reader_accepts_dropped_payload_position_reuse() {
        use crate::clock::ManualClock;
        use crate::ring::{SharedRegion, WriterPolicy};
        let cfg = RingConfig::new(8, 256);
        let known = KnownConfig::new(cfg, cfg.required_len());
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: std::sync::Arc<dyn crate::clock::Clock> =
            std::sync::Arc::new(ManualClock::new());
        let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
        let write = |w: &mut crate::ring::RingWriter,
                     state: crate::descriptor::CaptureState,
                     payload: &[u8]| {
            w.write(crate::ring::EventInput {
                kind: EventKind::CallEnter,
                api_id: 1,
                schema_id: 1,
                call_id: 1,
                parent_call_id: 0,
                payload,
                capture_state: state,
            })
        };
        write(&mut w, crate::descriptor::CaptureState::Captured, b"abc");
        // 取得できなかった Payload は格納されず、書き込み位置は進まない
        write(
            &mut w,
            crate::descriptor::CaptureState::MemoryUnreadable,
            b"xy",
        );
        // 次の格納 Payload は落とした件と同じ位置から始まる
        write(&mut w, crate::descriptor::CaptureState::Captured, b"z");
        let mut vr = ValidatingReader::new(known, 1);
        let evs = vr.drain_image(region.as_slice()).unwrap();
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].descriptor.payload_position, 0);
        assert_eq!(evs[1].descriptor.payload_position, 3);
        assert!(evs[1].descriptor.payload_dropped());
        assert_eq!(evs[2].descriptor.payload_position, 3);
        assert_eq!(evs[2].payload, b"z");
        assert!(!vr.is_stopped());
    }
}
