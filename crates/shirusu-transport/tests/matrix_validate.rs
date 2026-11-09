//! validate 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - validate_cursor_pair: (write, read, capacity) の境界表（一致/空/満杯/超過/後退）。
//! - decode_descriptor: Kind x 長さ境界、reserved、検査順序（Kind → reserved → 長さ）。
//! - decode_payload: 容量 x 開始位置 x 長さの回転コピー照合、範囲外の拒否。
//! - validate_control: 像の各フィールド改変 x 前像との単調性（後退は全フィールドで拒否）。
//! - decode_descriptor_checked: Sequence 下限 x Payload 位置の連続性 x 書き込み済み
//!   範囲の境界（A71 の検証手順 4）。ちょうど/±1 を全て押さえる。

use shirusu_transport::descriptor::{flags, EventDescriptor, EventKind};
use shirusu_transport::layout::*;
use shirusu_transport::validate::{
    decode_descriptor, decode_descriptor_checked, decode_payload, validate_control,
    validate_cursor_pair, DescriptorExpectation, IntegrityError, KnownConfig,
};
use std::sync::atomic::Ordering;

fn known() -> KnownConfig {
    let cfg = RingConfig::new(16, 256);
    KnownConfig::new(cfg, cfg.required_len())
}
fn desc(seq: u64, pos: u64, len: u32) -> EventDescriptor {
    let mut d = EventDescriptor::new(EventKind::CallEnter, seq);
    d.payload_position = pos;
    d.payload_len = len;
    d
}

// ---------- validate_cursor_pair の境界表 ----------
macro_rules! pair_case {
    ($name:ident, $w:expr, $r:expr, $cap:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                validate_cursor_pair($w, $r, $cap),
                $expect,
                "pair({},{},{})",
                $w,
                $r,
                $cap
            );
        }
    };
}
pair_case!(pair_empty, 0, 0, 16, Ok(0));
pair_case!(pair_one, 1, 0, 16, Ok(1));
pair_case!(pair_full_exact, 16, 0, 16, Ok(16));
pair_case!(
    pair_over_by_one,
    17,
    0,
    16,
    Err(IntegrityError::OccupancyExceedsCapacity {
        occupancy: 17,
        capacity: 16
    })
);
pair_case!(
    pair_regressed,
    0,
    1,
    16,
    Err(IntegrityError::CursorRegressed {
        which: "write<read"
    })
);
pair_case!(pair_moved_window_full, 100, 84, 16, Ok(16));
pair_case!(
    pair_moved_window_over,
    100,
    83,
    16,
    Err(IntegrityError::OccupancyExceedsCapacity {
        occupancy: 17,
        capacity: 16
    })
);
pair_case!(pair_zero_capacity_empty, 0, 0, 0, Ok(0));
pair_case!(
    pair_zero_capacity_one,
    1,
    0,
    0,
    Err(IntegrityError::OccupancyExceedsCapacity {
        occupancy: 1,
        capacity: 0
    })
);
pair_case!(pair_u64_max_full, u64::MAX, 0, u64::MAX, Ok(u64::MAX));
pair_case!(
    pair_u64_max_over,
    u64::MAX,
    0,
    u64::MAX - 1,
    Err(IntegrityError::OccupancyExceedsCapacity {
        occupancy: u64::MAX,
        capacity: u64::MAX - 1
    })
);

// ---------- decode_descriptor: Kind x 長さ x reserved と検査順序 ----------
#[test]
fn dd_len_at_capacity_accepted() {
    assert!(decode_descriptor(&desc(1, 0, 256).to_bytes(), &known()).is_ok());
}
#[test]
fn dd_len_below_capacity_accepted() {
    assert!(decode_descriptor(&desc(1, 0, 255).to_bytes(), &known()).is_ok());
}
#[test]
fn dd_len_above_capacity_by_one() {
    assert_eq!(
        decode_descriptor(&desc(1, 0, 257).to_bytes(), &known()),
        Err(IntegrityError::PayloadTooLarge {
            len: 257,
            capacity: 256
        })
    );
}
#[test]
fn dd_len_u32_max() {
    assert_eq!(
        decode_descriptor(&desc(1, 0, u32::MAX).to_bytes(), &known()),
        Err(IntegrityError::PayloadTooLarge {
            len: u32::MAX as u64,
            capacity: 256
        })
    );
}
#[test]
fn dd_dropped_len_above_capacity_accepted() {
    // R6: PAYLOAD_DROPPED の payload_len は落とした元の長さであり、格納長は
    // 0 として検証する。容量超過でも正規の劣化イベントとして受理する
    // (修正前は dd_len_above_capacity_by_one と同じく誤拒否していた)。
    let mut d = desc(1, 0, 257);
    d.flags = flags::PAYLOAD_DROPPED;
    assert!(decode_descriptor(&d.to_bytes(), &known()).is_ok());
}
#[test]
fn dd_dropped_len_u32_max_accepted() {
    // 元の長さの受理上限は u32 の表現最大値 (MAX_DROPPED_ORIGINAL_LEN)。
    let mut d = desc(1, 0, u32::MAX);
    d.flags = flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE;
    assert!(decode_descriptor(&d.to_bytes(), &known()).is_ok());
}
#[test]
fn dd_kind_unknown_zero_rejected_even_with_zero_len() {
    let mut d = desc(1, 0, 0);
    d.kind = 0;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::UnknownKind(0))
    );
}
#[test]
fn dd_kind_7_rejected() {
    let mut d = desc(1, 0, 0);
    d.kind = 7;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::UnknownKind(7))
    );
}
#[test]
fn dd_kind_checked_before_length() {
    // Kind が不正で長さも過大なら Kind が先に報告される
    let mut d = desc(1, 0, u32::MAX);
    d.kind = 999;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::UnknownKind(999))
    );
}
#[test]
fn dd_reserved_one_rejected() {
    let mut d = desc(1, 0, 0);
    d.reserved = 1;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::ReservedNonZero)
    );
}
#[test]
fn dd_reserved_max_rejected() {
    let mut d = desc(1, 0, 0);
    d.reserved = u64::MAX;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::ReservedNonZero)
    );
}
#[test]
fn dd_reserved_checked_before_length() {
    // reserved 非ゼロで長さも過大なら reserved が先
    let mut d = desc(1, 0, u32::MAX);
    d.reserved = 5;
    assert_eq!(
        decode_descriptor(&d.to_bytes(), &known()),
        Err(IntegrityError::ReservedNonZero)
    );
}
#[test]
fn dd_short_bytes_rejected() {
    let d = desc(1, 0, 0);
    assert_eq!(
        decode_descriptor(&d.to_bytes()[..63], &known()),
        Err(IntegrityError::ImageTooSmall)
    );
}
#[test]
fn dd_trailing_garbage_ignored() {
    let mut bytes = desc(3, 9, 4).to_bytes().to_vec();
    bytes.extend_from_slice(&[0xEE; 36]);
    let got = decode_descriptor(&bytes, &known()).unwrap();
    assert_eq!(got.sequence, 3);
    assert_eq!(got.payload_position, 9);
}
#[test]
fn dd_all_valid_kinds_accepted() {
    for k in [1u16, 2, 3, 4, 5, 6] {
        let mut d = desc(1, 0, 0);
        d.kind = k;
        assert!(
            decode_descriptor(&d.to_bytes(), &known()).is_ok(),
            "kind {k}"
        );
    }
}

// ---------- decode_payload: 回転コピーの行列 ----------
fn region(cap: usize) -> Vec<u8> {
    (0..cap).map(|i| i as u8).collect()
}
fn rotated(region: &[u8], pos: u64, len: usize) -> Vec<u8> {
    let cap = region.len();
    let start = (pos % cap as u64) as usize;
    (0..len).map(|i| region[(start + i) % cap]).collect()
}
macro_rules! payload_case {
    ($name:ident, $cap:expr, $pos:expr, $len:expr) => {
        #[test]
        fn $name() {
            let cfg = RingConfig::new(4, $cap);
            let known = KnownConfig::new(cfg, cfg.required_len());
            let reg = region($cap);
            let d = desc(1, $pos, $len);
            let got = decode_payload(&d, &reg, &known).expect("in-range decode");
            assert_eq!(
                got,
                rotated(&reg, $pos, $len),
                "cap {} pos {} len {}",
                $cap,
                $pos,
                $len
            );
        }
    };
}
payload_case!(pl16_s00_l5, 16, 0, 5);
payload_case!(pl16_s01_l5, 16, 1, 5);
payload_case!(pl16_s02_l5, 16, 2, 5);
payload_case!(pl16_s03_l5, 16, 3, 5);
payload_case!(pl16_s04_l5, 16, 4, 5);
payload_case!(pl16_s05_l5, 16, 5, 5);
payload_case!(pl16_s06_l5, 16, 6, 5);
payload_case!(pl16_s07_l5, 16, 7, 5);
payload_case!(pl16_s08_l5, 16, 8, 5);
payload_case!(pl16_s09_l5, 16, 9, 5);
payload_case!(pl16_s10_l5, 16, 10, 5);
payload_case!(pl16_s11_l5, 16, 11, 5);
payload_case!(pl16_s12_l5, 16, 12, 5);
payload_case!(pl16_s13_l5, 16, 13, 5);
payload_case!(pl16_s14_l5, 16, 14, 5);
payload_case!(pl16_s15_l5, 16, 15, 5);
payload_case!(pl16_s0_l16, 16, 0, 16);
payload_case!(pl16_s1_l16, 16, 1, 16);
payload_case!(pl16_s15_l16, 16, 15, 16);
payload_case!(pl16_s16_l3, 16, 16, 3);
payload_case!(pl16_s1000003_l7, 16, 1000003, 7);
payload_case!(pl32_s0_l1, 32, 0, 1);
payload_case!(pl32_s1_l31, 32, 1, 31);
payload_case!(pl32_s30_l32, 32, 30, 32);
payload_case!(pl32_s31_l32, 32, 31, 32);
payload_case!(pl32_s31_l1, 32, 31, 1);
payload_case!(pl32_s5_l32, 32, 5, 32);
#[test]
fn dp_dropped_returns_empty_without_touching_range() {
    let mut d = desc(1, 12345, 200);
    d.flags = flags::PAYLOAD_DROPPED;
    // 領域が空でも、落とした Payload は範囲に触らず空を返す
    assert_eq!(decode_payload(&d, &[], &known()), Ok(Vec::new()));
}
#[test]
fn dp_zero_len_returns_empty() {
    assert_eq!(
        decode_payload(&desc(1, 999, 0), &region(256), &known()),
        Ok(Vec::new())
    );
}
#[test]
fn dp_len_above_capacity_rejected() {
    assert_eq!(
        decode_payload(&desc(1, 0, 257), &region(256), &known()),
        Err(IntegrityError::PayloadRangeInvalid)
    );
}
#[test]
fn dp_region_shorter_than_capacity_rejected() {
    assert_eq!(
        decode_payload(&desc(1, 0, 4), &region(255), &known()),
        Err(IntegrityError::PayloadRangeInvalid)
    );
}
#[test]
fn dp_position_u64_max_rotates_by_remainder() {
    let reg = region(256);
    let d = desc(1, u64::MAX, 8);
    let got = decode_payload(&d, &reg, &known()).unwrap();
    assert_eq!(got, rotated(&reg, u64::MAX, 8));
}

// ---------- validate_control: 像の改変行列 ----------
/// u64 バッファで整列を保証する画像 (layout の原子操作は 8B 整列が前提)。
struct Img {
    words: Vec<u64>,
    len: usize,
}
impl Img {
    fn blank(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(8)],
            len,
        }
    }
    fn ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }
    fn set(&mut self, off: usize, v: u64) {
        store(self.ptr(), off, v, Ordering::Relaxed);
    }
}
struct Fields {
    write: u64,
    read: u64,
    pwrite: u64,
    pread: u64,
    gen: u64,
    loss: (u64, u64, u64),
}
fn control(f: &Fields) -> Img {
    let cfg = RingConfig::new(16, 256);
    let mut img = Img::blank(cfg.required_len());
    init_control(img.ptr(), cfg, f.gen, 9);
    img.set(OFF_WRITE_CURSOR, f.write);
    img.set(OFF_READ_CURSOR, f.read);
    img.set(OFF_PAYLOAD_WRITE_POSITION, f.pwrite);
    img.set(OFF_PAYLOAD_READ_POSITION, f.pread);
    img.set(OFF_DROPPED_EVENTS, f.loss.0);
    img.set(OFF_DROPPED_PAYLOAD_BYTES, f.loss.1);
    img.set(OFF_DEGRADED_EVENTS, f.loss.2);
    img
}
fn base_fields() -> Fields {
    Fields {
        write: 5,
        read: 2,
        pwrite: 100,
        pread: 40,
        gen: 3,
        loss: (1, 50, 2),
    }
}
#[test]
fn vc_baseline_ok() {
    let img = control(&base_fields());
    let s = validate_control(&img.bytes()[..CONTROL_SIZE], &known(), None).unwrap();
    assert_eq!(s.write_cursor, 5);
    assert_eq!(s.payload_write_position, 100);
    assert_eq!(s.loss.dropped_payload_bytes, 50);
}
#[test]
fn vc_copy_shorter_than_control_rejected() {
    let img = control(&base_fields());
    assert_eq!(
        validate_control(&img.bytes()[..255], &known(), None),
        Err(IntegrityError::ImageTooSmall)
    );
}
#[test]
fn vc_mapping_smaller_than_required_rejected() {
    let cfg = RingConfig::new(16, 256);
    let small = KnownConfig::new(cfg, cfg.required_len() - 1);
    let img = control(&base_fields());
    assert_eq!(
        validate_control(&img.bytes()[..CONTROL_SIZE], &small, None),
        Err(IntegrityError::ImageTooSmall)
    );
}
#[test]
fn vc_bad_magic_rejected() {
    let mut img = control(&base_fields());
    img.set(OFF_MAGIC, 0xDEAD);
    assert_eq!(
        validate_control(&img.bytes()[..CONTROL_SIZE], &known(), None),
        Err(IntegrityError::BadMagic)
    );
}
#[test]
fn vc_desc_occupancy_at_capacity_ok_over_rejected() {
    let mut f = base_fields();
    f.write = 16;
    f.read = 0;
    assert!(validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), None).is_ok());
    f.write = 17;
    assert!(matches!(
        validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), None),
        Err(IntegrityError::OccupancyExceedsCapacity {
            occupancy: 17,
            capacity: 16
        })
    ));
}
#[test]
fn vc_payload_occupancy_at_capacity_ok_over_rejected() {
    let mut f = base_fields();
    f.pwrite = 256;
    f.pread = 0;
    assert!(validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), None).is_ok());
    f.pwrite = 257;
    assert!(matches!(
        validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), None),
        Err(IntegrityError::OccupancyExceedsCapacity {
            occupancy: 257,
            capacity: 256
        })
    ));
}
#[test]
fn vc_write_behind_read_rejected() {
    let mut f = base_fields();
    f.write = 1;
    f.read = 2;
    assert!(matches!(
        validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), None),
        Err(IntegrityError::CursorRegressed { .. })
    ));
}
fn prev_snapshot() -> shirusu_transport::validate::ControlSnapshot {
    let img = control(&base_fields());
    validate_control(&img.bytes()[..CONTROL_SIZE], &known(), None).unwrap()
}
#[test]
fn vc_prev_equal_snapshot_ok() {
    let prev = prev_snapshot();
    let img = control(&base_fields());
    assert!(validate_control(&img.bytes()[..CONTROL_SIZE], &known(), Some(&prev)).is_ok());
}
#[test]
fn vc_prev_all_fields_forward_ok() {
    let prev = prev_snapshot();
    let f = Fields {
        write: 9,
        read: 5,
        pwrite: 140,
        pread: 90,
        gen: 3,
        loss: (3, 60, 4),
    };
    assert!(validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), Some(&prev)).is_ok());
}
macro_rules! vc_regress {
    ($name:ident, $mutate:expr, $expect:expr) => {
        #[test]
        fn $name() {
            let prev = prev_snapshot();
            let mut f = base_fields();
            $mutate(&mut f);
            assert_eq!(
                validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), Some(&prev)),
                $expect
            );
        }
    };
}
vc_regress!(
    vc_prev_generation_mismatch,
    |f: &mut Fields| f.gen = 4,
    Err(IntegrityError::GenerationMismatch {
        expected: 3,
        found: 4
    })
);
vc_regress!(
    vc_prev_write_cursor_regressed,
    |f: &mut Fields| f.write = 4,
    Err(IntegrityError::CursorRegressed {
        which: "vs previous snapshot"
    })
);
vc_regress!(
    vc_prev_read_cursor_regressed,
    |f: &mut Fields| f.read = 1,
    Err(IntegrityError::CursorRegressed {
        which: "vs previous snapshot"
    })
);
vc_regress!(
    vc_prev_payload_write_regressed,
    |f: &mut Fields| f.pwrite = 99,
    Err(IntegrityError::CursorRegressed {
        which: "payload position vs previous snapshot"
    })
);
vc_regress!(
    vc_prev_payload_read_regressed,
    |f: &mut Fields| f.pread = 39,
    Err(IntegrityError::CursorRegressed {
        which: "payload position vs previous snapshot"
    })
);
vc_regress!(
    vc_prev_counter_events_regressed,
    |f: &mut Fields| f.loss.0 = 0,
    Err(IntegrityError::CounterRegressed)
);
vc_regress!(
    vc_prev_counter_bytes_regressed,
    |f: &mut Fields| f.loss.1 = 49,
    Err(IntegrityError::CounterRegressed)
);
vc_regress!(
    vc_prev_counter_degraded_regressed,
    |f: &mut Fields| f.loss.2 = 1,
    Err(IntegrityError::CounterRegressed)
);
#[test]
fn vc_generation_checked_before_cursor_regression() {
    // 世代が違う像は別 Ring のものとして、Cursor 後退より先に世代で弾く
    let prev = prev_snapshot();
    let mut f = base_fields();
    f.gen = 99;
    f.write = 4; // 像内では整合 (write>=read) だが前像より後退している
    assert_eq!(
        validate_control(&control(&f).bytes()[..CONTROL_SIZE], &known(), Some(&prev)),
        Err(IntegrityError::GenerationMismatch {
            expected: 3,
            found: 99
        })
    );
}

// ---------- decode_descriptor_checked: 検証手順 4 の境界行列 ----------
fn exp(seq_at_least: u64, pos: Option<u64>, wp: u64) -> DescriptorExpectation {
    DescriptorExpectation {
        sequence_at_least: seq_at_least,
        payload_position: pos,
        payload_write_position: wp,
    }
}
macro_rules! checked_case {
    ($name:ident, $d:expr, $e:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                decode_descriptor_checked(&$d.to_bytes(), &known(), &$e),
                $expect
            );
        }
    };
}
checked_case!(
    chk_exact_fit_ok,
    desc(5, 10, 4),
    exp(5, Some(10), 14),
    Ok(desc(5, 10, 4))
);
checked_case!(
    chk_sequence_gap_allowed,
    desc(9, 10, 4),
    exp(5, Some(10), 14),
    Ok(desc(9, 10, 4))
);
checked_case!(
    chk_sequence_below_floor,
    desc(5, 10, 4),
    exp(6, Some(10), 14),
    Err(IntegrityError::SequenceRegressed {
        expected_at_least: 6,
        found: 5
    })
);
checked_case!(
    chk_sequence_zero_vs_floor_one,
    desc(0, 0, 0),
    exp(1, Some(0), 0),
    Err(IntegrityError::SequenceRegressed {
        expected_at_least: 1,
        found: 0
    })
);
checked_case!(
    chk_sequence_zero_floor_zero_ok,
    desc(0, 0, 0),
    exp(0, Some(0), 0),
    Ok(desc(0, 0, 0))
);
checked_case!(
    chk_position_one_before_anchor,
    desc(5, 9, 4),
    exp(5, Some(10), 14),
    Err(IntegrityError::PayloadPositionNotContiguous {
        expected: 10,
        found: 9
    })
);
checked_case!(
    chk_position_one_after_anchor,
    desc(5, 11, 4),
    exp(5, Some(10), 15),
    Err(IntegrityError::PayloadPositionNotContiguous {
        expected: 10,
        found: 11
    })
);
checked_case!(
    chk_end_exactly_at_write_position_ok,
    desc(5, 10, 4),
    exp(5, Some(10), 14),
    Ok(desc(5, 10, 4))
);
checked_case!(
    chk_end_one_over_write_position,
    desc(5, 10, 4),
    exp(5, Some(10), 13),
    Err(IntegrityError::PayloadPositionOutOfRange {
        position: 10,
        end: 14,
        write_position: 13
    })
);
checked_case!(
    chk_end_far_over_write_position,
    desc(5, 10, 4),
    exp(5, Some(10), 10),
    Err(IntegrityError::PayloadPositionOutOfRange {
        position: 10,
        end: 14,
        write_position: 10
    })
);
checked_case!(
    chk_range_checked_before_contiguity,
    desc(5, 11, 4),
    exp(5, Some(10), 14),
    Err(IntegrityError::PayloadPositionOutOfRange {
        position: 11,
        end: 15,
        write_position: 14
    })
);
checked_case!(
    chk_no_anchor_far_position_ok,
    desc(7, 200, 0),
    exp(7, None, 200),
    Ok(desc(7, 200, 0))
);
checked_case!(
    chk_no_anchor_but_end_over,
    desc(7, 200, 1),
    exp(7, None, 200),
    Err(IntegrityError::PayloadPositionOutOfRange {
        position: 200,
        end: 201,
        write_position: 200
    })
);
checked_case!(
    chk_zero_len_at_write_position_ok,
    desc(5, 14, 0),
    exp(5, Some(14), 14),
    Ok(desc(5, 14, 0))
);
checked_case!(
    chk_zero_len_anchor_mismatch_still_checked,
    desc(5, 13, 0),
    exp(5, Some(14), 14),
    Err(IntegrityError::PayloadPositionNotContiguous {
        expected: 14,
        found: 13
    })
);
checked_case!(
    chk_position_add_overflow_is_range_invalid,
    desc(5, u64::MAX - 1, 4),
    exp(5, None, u64::MAX),
    Err(IntegrityError::PayloadRangeInvalid)
);
#[test]
fn chk_dropped_payload_uses_zero_stored_len() {
    // 落とした Payload は格納長 0 として扱う: 元長さ 9 でも終端は位置のまま
    let mut d = desc(5, 10, 9);
    d.flags = flags::PAYLOAD_DROPPED;
    assert_eq!(
        decode_descriptor_checked(&d.to_bytes(), &known(), &exp(5, Some(10), 10)),
        Ok(d)
    );
    // アンカーがずれていれば格納長 0 でも連続性で弾く
    assert_eq!(
        decode_descriptor_checked(&d.to_bytes(), &known(), &exp(5, Some(11), 11)),
        Err(IntegrityError::PayloadPositionNotContiguous {
            expected: 11,
            found: 10
        })
    );
}
#[test]
fn chk_base_decode_error_surfaces_first() {
    // checked でも decode_descriptor の検証 (Kind) が先に効く
    let mut d = desc(5, 10, 4);
    d.kind = 42;
    assert_eq!(
        decode_descriptor_checked(&d.to_bytes(), &known(), &exp(5, Some(10), 14)),
        Err(IntegrityError::UnknownKind(42))
    );
}
