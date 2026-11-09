//! layout 行列スイート（拡充第2弾）。
//! 検証する行列:
//! - occupancy / descriptor_free: 容量 x (write, read) の全順序対を小容量で網羅し、
//!   参照定義 (w>=r なら差、未満なら None / 空き = 容量-占有、占有>容量なら None) と照合。
//! - slot_index / payload_index: 容量 x Cursor 代表値 (0, 1, cap-1, cap, cap+1, 2cap, 2cap+3)
//!   が剰余と一致し、容量 0 では 0 に潰れること。u64 極値も含む。
//! - usage_percent: 切り捨て除算の境界 (ちょうど割り切れる/端数) と容量 0 の扱い。
//! - RingConfig: (Descriptor 容量 x Payload 容量) で offset / required_len の合成式を照合し、
//!   下限未満の容量が panic で拒否されること。
//! - LossCounters::diff_since: フィールドごとの前進/同値/後退の組合せ。

use shirusu_transport::layout::{
    descriptor_free, occupancy, payload_index, slot_index, usage_percent, LossCounters,
};
use shirusu_transport::RingConfig;

macro_rules! occ_case {
    ($name:ident, $cap:expr, $w:expr, $r:expr) => {
        #[test]
        fn $name() {
            let cap: u64 = $cap;
            let w: u64 = $w;
            let r: u64 = $r;
            let expect_occ = if w >= r { Some(w - r) } else { None };
            assert_eq!(occupancy(w, r), expect_occ, "occupancy({w},{r})");
            let expect_free = expect_occ.and_then(|o| cap.checked_sub(o));
            assert_eq!(
                descriptor_free(w, r, cap),
                expect_free,
                "descriptor_free({w},{r},{cap})"
            );
        }
    };
}

occ_case!(occ_c2_w00_r00, 2, 0, 0);
occ_case!(occ_c2_w00_r01, 2, 0, 1);
occ_case!(occ_c2_w00_r02, 2, 0, 2);
occ_case!(occ_c2_w00_r03, 2, 0, 3);
occ_case!(occ_c2_w00_r04, 2, 0, 4);
occ_case!(occ_c2_w01_r00, 2, 1, 0);
occ_case!(occ_c2_w01_r01, 2, 1, 1);
occ_case!(occ_c2_w01_r02, 2, 1, 2);
occ_case!(occ_c2_w01_r03, 2, 1, 3);
occ_case!(occ_c2_w01_r04, 2, 1, 4);
occ_case!(occ_c2_w02_r00, 2, 2, 0);
occ_case!(occ_c2_w02_r01, 2, 2, 1);
occ_case!(occ_c2_w02_r02, 2, 2, 2);
occ_case!(occ_c2_w02_r03, 2, 2, 3);
occ_case!(occ_c2_w02_r04, 2, 2, 4);
occ_case!(occ_c2_w03_r00, 2, 3, 0);
occ_case!(occ_c2_w03_r01, 2, 3, 1);
occ_case!(occ_c2_w03_r02, 2, 3, 2);
occ_case!(occ_c2_w03_r03, 2, 3, 3);
occ_case!(occ_c2_w03_r04, 2, 3, 4);
occ_case!(occ_c2_w04_r00, 2, 4, 0);
occ_case!(occ_c2_w04_r01, 2, 4, 1);
occ_case!(occ_c2_w04_r02, 2, 4, 2);
occ_case!(occ_c2_w04_r03, 2, 4, 3);
occ_case!(occ_c2_w04_r04, 2, 4, 4);
occ_case!(occ_c4_w00_r00, 4, 0, 0);
occ_case!(occ_c4_w00_r01, 4, 0, 1);
occ_case!(occ_c4_w00_r02, 4, 0, 2);
occ_case!(occ_c4_w00_r03, 4, 0, 3);
occ_case!(occ_c4_w00_r04, 4, 0, 4);
occ_case!(occ_c4_w00_r05, 4, 0, 5);
occ_case!(occ_c4_w00_r06, 4, 0, 6);
occ_case!(occ_c4_w00_r07, 4, 0, 7);
occ_case!(occ_c4_w00_r08, 4, 0, 8);
occ_case!(occ_c4_w01_r00, 4, 1, 0);
occ_case!(occ_c4_w01_r01, 4, 1, 1);
occ_case!(occ_c4_w01_r02, 4, 1, 2);
occ_case!(occ_c4_w01_r03, 4, 1, 3);
occ_case!(occ_c4_w01_r04, 4, 1, 4);
occ_case!(occ_c4_w01_r05, 4, 1, 5);
occ_case!(occ_c4_w01_r06, 4, 1, 6);
occ_case!(occ_c4_w01_r07, 4, 1, 7);
occ_case!(occ_c4_w01_r08, 4, 1, 8);
occ_case!(occ_c4_w02_r00, 4, 2, 0);
occ_case!(occ_c4_w02_r01, 4, 2, 1);
occ_case!(occ_c4_w02_r02, 4, 2, 2);
occ_case!(occ_c4_w02_r03, 4, 2, 3);
occ_case!(occ_c4_w02_r04, 4, 2, 4);
occ_case!(occ_c4_w02_r05, 4, 2, 5);
occ_case!(occ_c4_w02_r06, 4, 2, 6);
occ_case!(occ_c4_w02_r07, 4, 2, 7);
occ_case!(occ_c4_w02_r08, 4, 2, 8);
occ_case!(occ_c4_w03_r00, 4, 3, 0);
occ_case!(occ_c4_w03_r01, 4, 3, 1);
occ_case!(occ_c4_w03_r02, 4, 3, 2);
occ_case!(occ_c4_w03_r03, 4, 3, 3);
occ_case!(occ_c4_w03_r04, 4, 3, 4);
occ_case!(occ_c4_w03_r05, 4, 3, 5);
occ_case!(occ_c4_w03_r06, 4, 3, 6);
occ_case!(occ_c4_w03_r07, 4, 3, 7);
occ_case!(occ_c4_w03_r08, 4, 3, 8);
occ_case!(occ_c4_w04_r00, 4, 4, 0);
occ_case!(occ_c4_w04_r01, 4, 4, 1);
occ_case!(occ_c4_w04_r02, 4, 4, 2);
occ_case!(occ_c4_w04_r03, 4, 4, 3);
occ_case!(occ_c4_w04_r04, 4, 4, 4);
occ_case!(occ_c4_w04_r05, 4, 4, 5);
occ_case!(occ_c4_w04_r06, 4, 4, 6);
occ_case!(occ_c4_w04_r07, 4, 4, 7);
occ_case!(occ_c4_w04_r08, 4, 4, 8);
occ_case!(occ_c4_w05_r00, 4, 5, 0);
occ_case!(occ_c4_w05_r01, 4, 5, 1);
occ_case!(occ_c4_w05_r02, 4, 5, 2);
occ_case!(occ_c4_w05_r03, 4, 5, 3);
occ_case!(occ_c4_w05_r04, 4, 5, 4);
occ_case!(occ_c4_w05_r05, 4, 5, 5);
occ_case!(occ_c4_w05_r06, 4, 5, 6);
occ_case!(occ_c4_w05_r07, 4, 5, 7);
occ_case!(occ_c4_w05_r08, 4, 5, 8);
occ_case!(occ_c4_w06_r00, 4, 6, 0);
occ_case!(occ_c4_w06_r01, 4, 6, 1);
occ_case!(occ_c4_w06_r02, 4, 6, 2);
occ_case!(occ_c4_w06_r03, 4, 6, 3);
occ_case!(occ_c4_w06_r04, 4, 6, 4);
occ_case!(occ_c4_w06_r05, 4, 6, 5);
occ_case!(occ_c4_w06_r06, 4, 6, 6);
occ_case!(occ_c4_w06_r07, 4, 6, 7);
occ_case!(occ_c4_w06_r08, 4, 6, 8);
occ_case!(occ_c4_w07_r00, 4, 7, 0);
occ_case!(occ_c4_w07_r01, 4, 7, 1);
occ_case!(occ_c4_w07_r02, 4, 7, 2);
occ_case!(occ_c4_w07_r03, 4, 7, 3);
occ_case!(occ_c4_w07_r04, 4, 7, 4);
occ_case!(occ_c4_w07_r05, 4, 7, 5);
occ_case!(occ_c4_w07_r06, 4, 7, 6);
occ_case!(occ_c4_w07_r07, 4, 7, 7);
occ_case!(occ_c4_w07_r08, 4, 7, 8);
occ_case!(occ_c4_w08_r00, 4, 8, 0);
occ_case!(occ_c4_w08_r01, 4, 8, 1);
occ_case!(occ_c4_w08_r02, 4, 8, 2);
occ_case!(occ_c4_w08_r03, 4, 8, 3);
occ_case!(occ_c4_w08_r04, 4, 8, 4);
occ_case!(occ_c4_w08_r05, 4, 8, 5);
occ_case!(occ_c4_w08_r06, 4, 8, 6);
occ_case!(occ_c4_w08_r07, 4, 8, 7);
occ_case!(occ_c4_w08_r08, 4, 8, 8);
occ_case!(occ_c8_w00_r00, 8, 0, 0);
occ_case!(occ_c8_w00_r01, 8, 0, 1);
occ_case!(occ_c8_w00_r02, 8, 0, 2);
occ_case!(occ_c8_w00_r03, 8, 0, 3);
occ_case!(occ_c8_w00_r04, 8, 0, 4);
occ_case!(occ_c8_w00_r05, 8, 0, 5);
occ_case!(occ_c8_w00_r06, 8, 0, 6);
occ_case!(occ_c8_w00_r07, 8, 0, 7);
occ_case!(occ_c8_w00_r08, 8, 0, 8);
occ_case!(occ_c8_w00_r09, 8, 0, 9);
occ_case!(occ_c8_w00_r10, 8, 0, 10);
occ_case!(occ_c8_w00_r11, 8, 0, 11);
occ_case!(occ_c8_w00_r12, 8, 0, 12);
occ_case!(occ_c8_w00_r13, 8, 0, 13);
occ_case!(occ_c8_w00_r14, 8, 0, 14);
occ_case!(occ_c8_w00_r15, 8, 0, 15);
occ_case!(occ_c8_w00_r16, 8, 0, 16);
occ_case!(occ_c8_w01_r00, 8, 1, 0);
occ_case!(occ_c8_w01_r01, 8, 1, 1);
occ_case!(occ_c8_w01_r02, 8, 1, 2);
occ_case!(occ_c8_w01_r03, 8, 1, 3);
occ_case!(occ_c8_w01_r04, 8, 1, 4);
occ_case!(occ_c8_w01_r05, 8, 1, 5);
occ_case!(occ_c8_w01_r06, 8, 1, 6);
occ_case!(occ_c8_w01_r07, 8, 1, 7);
occ_case!(occ_c8_w01_r08, 8, 1, 8);
occ_case!(occ_c8_w01_r09, 8, 1, 9);
occ_case!(occ_c8_w01_r10, 8, 1, 10);
occ_case!(occ_c8_w01_r11, 8, 1, 11);
occ_case!(occ_c8_w01_r12, 8, 1, 12);
occ_case!(occ_c8_w01_r13, 8, 1, 13);
occ_case!(occ_c8_w01_r14, 8, 1, 14);
occ_case!(occ_c8_w01_r15, 8, 1, 15);
occ_case!(occ_c8_w01_r16, 8, 1, 16);
occ_case!(occ_c8_w02_r00, 8, 2, 0);
occ_case!(occ_c8_w02_r01, 8, 2, 1);
occ_case!(occ_c8_w02_r02, 8, 2, 2);
occ_case!(occ_c8_w02_r03, 8, 2, 3);
occ_case!(occ_c8_w02_r04, 8, 2, 4);
occ_case!(occ_c8_w02_r05, 8, 2, 5);
occ_case!(occ_c8_w02_r06, 8, 2, 6);
occ_case!(occ_c8_w02_r07, 8, 2, 7);
occ_case!(occ_c8_w02_r08, 8, 2, 8);
occ_case!(occ_c8_w02_r09, 8, 2, 9);
occ_case!(occ_c8_w02_r10, 8, 2, 10);
occ_case!(occ_c8_w02_r11, 8, 2, 11);
occ_case!(occ_c8_w02_r12, 8, 2, 12);
occ_case!(occ_c8_w02_r13, 8, 2, 13);
occ_case!(occ_c8_w02_r14, 8, 2, 14);
occ_case!(occ_c8_w02_r15, 8, 2, 15);
occ_case!(occ_c8_w02_r16, 8, 2, 16);
occ_case!(occ_c8_w03_r00, 8, 3, 0);
occ_case!(occ_c8_w03_r01, 8, 3, 1);
occ_case!(occ_c8_w03_r02, 8, 3, 2);
occ_case!(occ_c8_w03_r03, 8, 3, 3);
occ_case!(occ_c8_w03_r04, 8, 3, 4);
occ_case!(occ_c8_w03_r05, 8, 3, 5);
occ_case!(occ_c8_w03_r06, 8, 3, 6);
occ_case!(occ_c8_w03_r07, 8, 3, 7);
occ_case!(occ_c8_w03_r08, 8, 3, 8);
occ_case!(occ_c8_w03_r09, 8, 3, 9);
occ_case!(occ_c8_w03_r10, 8, 3, 10);
occ_case!(occ_c8_w03_r11, 8, 3, 11);
occ_case!(occ_c8_w03_r12, 8, 3, 12);
occ_case!(occ_c8_w03_r13, 8, 3, 13);
occ_case!(occ_c8_w03_r14, 8, 3, 14);
occ_case!(occ_c8_w03_r15, 8, 3, 15);
occ_case!(occ_c8_w03_r16, 8, 3, 16);
occ_case!(occ_c8_w04_r00, 8, 4, 0);
occ_case!(occ_c8_w04_r01, 8, 4, 1);
occ_case!(occ_c8_w04_r02, 8, 4, 2);
occ_case!(occ_c8_w04_r03, 8, 4, 3);
occ_case!(occ_c8_w04_r04, 8, 4, 4);
occ_case!(occ_c8_w04_r05, 8, 4, 5);
occ_case!(occ_c8_w04_r06, 8, 4, 6);
occ_case!(occ_c8_w04_r07, 8, 4, 7);
occ_case!(occ_c8_w04_r08, 8, 4, 8);
occ_case!(occ_c8_w04_r09, 8, 4, 9);
occ_case!(occ_c8_w04_r10, 8, 4, 10);
occ_case!(occ_c8_w04_r11, 8, 4, 11);
occ_case!(occ_c8_w04_r12, 8, 4, 12);
occ_case!(occ_c8_w04_r13, 8, 4, 13);
occ_case!(occ_c8_w04_r14, 8, 4, 14);
occ_case!(occ_c8_w04_r15, 8, 4, 15);
occ_case!(occ_c8_w04_r16, 8, 4, 16);
occ_case!(occ_c8_w05_r00, 8, 5, 0);
occ_case!(occ_c8_w05_r01, 8, 5, 1);
occ_case!(occ_c8_w05_r02, 8, 5, 2);
occ_case!(occ_c8_w05_r03, 8, 5, 3);
occ_case!(occ_c8_w05_r04, 8, 5, 4);
occ_case!(occ_c8_w05_r05, 8, 5, 5);
occ_case!(occ_c8_w05_r06, 8, 5, 6);
occ_case!(occ_c8_w05_r07, 8, 5, 7);
occ_case!(occ_c8_w05_r08, 8, 5, 8);
occ_case!(occ_c8_w05_r09, 8, 5, 9);
occ_case!(occ_c8_w05_r10, 8, 5, 10);
occ_case!(occ_c8_w05_r11, 8, 5, 11);
occ_case!(occ_c8_w05_r12, 8, 5, 12);
occ_case!(occ_c8_w05_r13, 8, 5, 13);
occ_case!(occ_c8_w05_r14, 8, 5, 14);
occ_case!(occ_c8_w05_r15, 8, 5, 15);
occ_case!(occ_c8_w05_r16, 8, 5, 16);
occ_case!(occ_c8_w06_r00, 8, 6, 0);
occ_case!(occ_c8_w06_r01, 8, 6, 1);
occ_case!(occ_c8_w06_r02, 8, 6, 2);
occ_case!(occ_c8_w06_r03, 8, 6, 3);
occ_case!(occ_c8_w06_r04, 8, 6, 4);
occ_case!(occ_c8_w06_r05, 8, 6, 5);
occ_case!(occ_c8_w06_r06, 8, 6, 6);
occ_case!(occ_c8_w06_r07, 8, 6, 7);
occ_case!(occ_c8_w06_r08, 8, 6, 8);
occ_case!(occ_c8_w06_r09, 8, 6, 9);
occ_case!(occ_c8_w06_r10, 8, 6, 10);
occ_case!(occ_c8_w06_r11, 8, 6, 11);
occ_case!(occ_c8_w06_r12, 8, 6, 12);
occ_case!(occ_c8_w06_r13, 8, 6, 13);
occ_case!(occ_c8_w06_r14, 8, 6, 14);
occ_case!(occ_c8_w06_r15, 8, 6, 15);
occ_case!(occ_c8_w06_r16, 8, 6, 16);
occ_case!(occ_c8_w07_r00, 8, 7, 0);
occ_case!(occ_c8_w07_r01, 8, 7, 1);
occ_case!(occ_c8_w07_r02, 8, 7, 2);
occ_case!(occ_c8_w07_r03, 8, 7, 3);
occ_case!(occ_c8_w07_r04, 8, 7, 4);
occ_case!(occ_c8_w07_r05, 8, 7, 5);
occ_case!(occ_c8_w07_r06, 8, 7, 6);
occ_case!(occ_c8_w07_r07, 8, 7, 7);
occ_case!(occ_c8_w07_r08, 8, 7, 8);
occ_case!(occ_c8_w07_r09, 8, 7, 9);
occ_case!(occ_c8_w07_r10, 8, 7, 10);
occ_case!(occ_c8_w07_r11, 8, 7, 11);
occ_case!(occ_c8_w07_r12, 8, 7, 12);
occ_case!(occ_c8_w07_r13, 8, 7, 13);
occ_case!(occ_c8_w07_r14, 8, 7, 14);
occ_case!(occ_c8_w07_r15, 8, 7, 15);
occ_case!(occ_c8_w07_r16, 8, 7, 16);
occ_case!(occ_c8_w08_r00, 8, 8, 0);
occ_case!(occ_c8_w08_r01, 8, 8, 1);
occ_case!(occ_c8_w08_r02, 8, 8, 2);
occ_case!(occ_c8_w08_r03, 8, 8, 3);
occ_case!(occ_c8_w08_r04, 8, 8, 4);
occ_case!(occ_c8_w08_r05, 8, 8, 5);
occ_case!(occ_c8_w08_r06, 8, 8, 6);
occ_case!(occ_c8_w08_r07, 8, 8, 7);
occ_case!(occ_c8_w08_r08, 8, 8, 8);
occ_case!(occ_c8_w08_r09, 8, 8, 9);
occ_case!(occ_c8_w08_r10, 8, 8, 10);
occ_case!(occ_c8_w08_r11, 8, 8, 11);
occ_case!(occ_c8_w08_r12, 8, 8, 12);
occ_case!(occ_c8_w08_r13, 8, 8, 13);
occ_case!(occ_c8_w08_r14, 8, 8, 14);
occ_case!(occ_c8_w08_r15, 8, 8, 15);
occ_case!(occ_c8_w08_r16, 8, 8, 16);
occ_case!(occ_c8_w09_r00, 8, 9, 0);
occ_case!(occ_c8_w09_r01, 8, 9, 1);
occ_case!(occ_c8_w09_r02, 8, 9, 2);
occ_case!(occ_c8_w09_r03, 8, 9, 3);
occ_case!(occ_c8_w09_r04, 8, 9, 4);
occ_case!(occ_c8_w09_r05, 8, 9, 5);
occ_case!(occ_c8_w09_r06, 8, 9, 6);
occ_case!(occ_c8_w09_r07, 8, 9, 7);
occ_case!(occ_c8_w09_r08, 8, 9, 8);
occ_case!(occ_c8_w09_r09, 8, 9, 9);
occ_case!(occ_c8_w09_r10, 8, 9, 10);
occ_case!(occ_c8_w09_r11, 8, 9, 11);
occ_case!(occ_c8_w09_r12, 8, 9, 12);
occ_case!(occ_c8_w09_r13, 8, 9, 13);
occ_case!(occ_c8_w09_r14, 8, 9, 14);
occ_case!(occ_c8_w09_r15, 8, 9, 15);
occ_case!(occ_c8_w09_r16, 8, 9, 16);
occ_case!(occ_c8_w10_r00, 8, 10, 0);
occ_case!(occ_c8_w10_r01, 8, 10, 1);
occ_case!(occ_c8_w10_r02, 8, 10, 2);
occ_case!(occ_c8_w10_r03, 8, 10, 3);
occ_case!(occ_c8_w10_r04, 8, 10, 4);
occ_case!(occ_c8_w10_r05, 8, 10, 5);
occ_case!(occ_c8_w10_r06, 8, 10, 6);
occ_case!(occ_c8_w10_r07, 8, 10, 7);
occ_case!(occ_c8_w10_r08, 8, 10, 8);
occ_case!(occ_c8_w10_r09, 8, 10, 9);
occ_case!(occ_c8_w10_r10, 8, 10, 10);
occ_case!(occ_c8_w10_r11, 8, 10, 11);
occ_case!(occ_c8_w10_r12, 8, 10, 12);
occ_case!(occ_c8_w10_r13, 8, 10, 13);
occ_case!(occ_c8_w10_r14, 8, 10, 14);
occ_case!(occ_c8_w10_r15, 8, 10, 15);
occ_case!(occ_c8_w10_r16, 8, 10, 16);
occ_case!(occ_c8_w11_r00, 8, 11, 0);
occ_case!(occ_c8_w11_r01, 8, 11, 1);
occ_case!(occ_c8_w11_r02, 8, 11, 2);
occ_case!(occ_c8_w11_r03, 8, 11, 3);
occ_case!(occ_c8_w11_r04, 8, 11, 4);
occ_case!(occ_c8_w11_r05, 8, 11, 5);
occ_case!(occ_c8_w11_r06, 8, 11, 6);
occ_case!(occ_c8_w11_r07, 8, 11, 7);
occ_case!(occ_c8_w11_r08, 8, 11, 8);
occ_case!(occ_c8_w11_r09, 8, 11, 9);
occ_case!(occ_c8_w11_r10, 8, 11, 10);
occ_case!(occ_c8_w11_r11, 8, 11, 11);
occ_case!(occ_c8_w11_r12, 8, 11, 12);
occ_case!(occ_c8_w11_r13, 8, 11, 13);
occ_case!(occ_c8_w11_r14, 8, 11, 14);
occ_case!(occ_c8_w11_r15, 8, 11, 15);
occ_case!(occ_c8_w11_r16, 8, 11, 16);
occ_case!(occ_c8_w12_r00, 8, 12, 0);
occ_case!(occ_c8_w12_r01, 8, 12, 1);
occ_case!(occ_c8_w12_r02, 8, 12, 2);
occ_case!(occ_c8_w12_r03, 8, 12, 3);
occ_case!(occ_c8_w12_r04, 8, 12, 4);
occ_case!(occ_c8_w12_r05, 8, 12, 5);
occ_case!(occ_c8_w12_r06, 8, 12, 6);
occ_case!(occ_c8_w12_r07, 8, 12, 7);
occ_case!(occ_c8_w12_r08, 8, 12, 8);
occ_case!(occ_c8_w12_r09, 8, 12, 9);
occ_case!(occ_c8_w12_r10, 8, 12, 10);
occ_case!(occ_c8_w12_r11, 8, 12, 11);
occ_case!(occ_c8_w12_r12, 8, 12, 12);
occ_case!(occ_c8_w12_r13, 8, 12, 13);
occ_case!(occ_c8_w12_r14, 8, 12, 14);
occ_case!(occ_c8_w12_r15, 8, 12, 15);
occ_case!(occ_c8_w12_r16, 8, 12, 16);
occ_case!(occ_c8_w13_r00, 8, 13, 0);
occ_case!(occ_c8_w13_r01, 8, 13, 1);
occ_case!(occ_c8_w13_r02, 8, 13, 2);
occ_case!(occ_c8_w13_r03, 8, 13, 3);
occ_case!(occ_c8_w13_r04, 8, 13, 4);
occ_case!(occ_c8_w13_r05, 8, 13, 5);
occ_case!(occ_c8_w13_r06, 8, 13, 6);
occ_case!(occ_c8_w13_r07, 8, 13, 7);
occ_case!(occ_c8_w13_r08, 8, 13, 8);
occ_case!(occ_c8_w13_r09, 8, 13, 9);
occ_case!(occ_c8_w13_r10, 8, 13, 10);
occ_case!(occ_c8_w13_r11, 8, 13, 11);
occ_case!(occ_c8_w13_r12, 8, 13, 12);
occ_case!(occ_c8_w13_r13, 8, 13, 13);
occ_case!(occ_c8_w13_r14, 8, 13, 14);
occ_case!(occ_c8_w13_r15, 8, 13, 15);
occ_case!(occ_c8_w13_r16, 8, 13, 16);
occ_case!(occ_c8_w14_r00, 8, 14, 0);
occ_case!(occ_c8_w14_r01, 8, 14, 1);
occ_case!(occ_c8_w14_r02, 8, 14, 2);
occ_case!(occ_c8_w14_r03, 8, 14, 3);
occ_case!(occ_c8_w14_r04, 8, 14, 4);
occ_case!(occ_c8_w14_r05, 8, 14, 5);
occ_case!(occ_c8_w14_r06, 8, 14, 6);
occ_case!(occ_c8_w14_r07, 8, 14, 7);
occ_case!(occ_c8_w14_r08, 8, 14, 8);
occ_case!(occ_c8_w14_r09, 8, 14, 9);
occ_case!(occ_c8_w14_r10, 8, 14, 10);
occ_case!(occ_c8_w14_r11, 8, 14, 11);
occ_case!(occ_c8_w14_r12, 8, 14, 12);
occ_case!(occ_c8_w14_r13, 8, 14, 13);
occ_case!(occ_c8_w14_r14, 8, 14, 14);
occ_case!(occ_c8_w14_r15, 8, 14, 15);
occ_case!(occ_c8_w14_r16, 8, 14, 16);
occ_case!(occ_c8_w15_r00, 8, 15, 0);
occ_case!(occ_c8_w15_r01, 8, 15, 1);
occ_case!(occ_c8_w15_r02, 8, 15, 2);
occ_case!(occ_c8_w15_r03, 8, 15, 3);
occ_case!(occ_c8_w15_r04, 8, 15, 4);
occ_case!(occ_c8_w15_r05, 8, 15, 5);
occ_case!(occ_c8_w15_r06, 8, 15, 6);
occ_case!(occ_c8_w15_r07, 8, 15, 7);
occ_case!(occ_c8_w15_r08, 8, 15, 8);
occ_case!(occ_c8_w15_r09, 8, 15, 9);
occ_case!(occ_c8_w15_r10, 8, 15, 10);
occ_case!(occ_c8_w15_r11, 8, 15, 11);
occ_case!(occ_c8_w15_r12, 8, 15, 12);
occ_case!(occ_c8_w15_r13, 8, 15, 13);
occ_case!(occ_c8_w15_r14, 8, 15, 14);
occ_case!(occ_c8_w15_r15, 8, 15, 15);
occ_case!(occ_c8_w15_r16, 8, 15, 16);
occ_case!(occ_c8_w16_r00, 8, 16, 0);
occ_case!(occ_c8_w16_r01, 8, 16, 1);
occ_case!(occ_c8_w16_r02, 8, 16, 2);
occ_case!(occ_c8_w16_r03, 8, 16, 3);
occ_case!(occ_c8_w16_r04, 8, 16, 4);
occ_case!(occ_c8_w16_r05, 8, 16, 5);
occ_case!(occ_c8_w16_r06, 8, 16, 6);
occ_case!(occ_c8_w16_r07, 8, 16, 7);
occ_case!(occ_c8_w16_r08, 8, 16, 8);
occ_case!(occ_c8_w16_r09, 8, 16, 9);
occ_case!(occ_c8_w16_r10, 8, 16, 10);
occ_case!(occ_c8_w16_r11, 8, 16, 11);
occ_case!(occ_c8_w16_r12, 8, 16, 12);
occ_case!(occ_c8_w16_r13, 8, 16, 13);
occ_case!(occ_c8_w16_r14, 8, 16, 14);
occ_case!(occ_c8_w16_r15, 8, 16, 15);
occ_case!(occ_c8_w16_r16, 8, 16, 16);
// occupancy cases: 395

#[test]
fn occupancy_u64_max_full_range() {
    assert_eq!(occupancy(u64::MAX, 0), Some(u64::MAX));
    assert_eq!(descriptor_free(u64::MAX, 0, u64::MAX), Some(0));
}
#[test]
fn occupancy_u64_max_equal_cursors() {
    assert_eq!(occupancy(u64::MAX, u64::MAX), Some(0));
    assert_eq!(descriptor_free(u64::MAX, u64::MAX, 7), Some(7));
}
#[test]
fn occupancy_u64_max_regressed() {
    assert_eq!(occupancy(0, u64::MAX), None);
    assert_eq!(descriptor_free(0, u64::MAX, 7), None);
}
#[test]
fn occupancy_over_capacity_is_none_free() {
    assert_eq!(occupancy(10, 0), Some(10));
    assert_eq!(descriptor_free(10, 0, 9), None);
    assert_eq!(descriptor_free(10, 0, 10), Some(0));
}

macro_rules! idx_case {
    ($name:ident, $cap:expr, $cursor:expr) => {
        #[test]
        fn $name() {
            let cap: u64 = $cap;
            let c: u64 = $cursor;
            let expect = if cap == 0 { 0 } else { c % cap };
            assert_eq!(slot_index(c, cap), expect, "slot_index({c},{cap})");
            assert_eq!(payload_index(c, cap), expect, "payload_index({c},{cap})");
            assert!(expect < cap || cap == 0);
        }
    };
}

idx_case!(idx_c1_v0, 1, 0);
idx_case!(idx_c1_v1, 1, 1);
idx_case!(idx_c1_v2, 1, 2);
idx_case!(idx_c1_v5, 1, 5);
idx_case!(idx_c2_v0, 2, 0);
idx_case!(idx_c2_v1, 2, 1);
idx_case!(idx_c2_v2, 2, 2);
idx_case!(idx_c2_v3, 2, 3);
idx_case!(idx_c2_v4, 2, 4);
idx_case!(idx_c2_v7, 2, 7);
idx_case!(idx_c3_v0, 3, 0);
idx_case!(idx_c3_v1, 3, 1);
idx_case!(idx_c3_v2, 3, 2);
idx_case!(idx_c3_v3, 3, 3);
idx_case!(idx_c3_v4, 3, 4);
idx_case!(idx_c3_v6, 3, 6);
idx_case!(idx_c3_v9, 3, 9);
idx_case!(idx_c5_v0, 5, 0);
idx_case!(idx_c5_v1, 5, 1);
idx_case!(idx_c5_v4, 5, 4);
idx_case!(idx_c5_v5, 5, 5);
idx_case!(idx_c5_v6, 5, 6);
idx_case!(idx_c5_v10, 5, 10);
idx_case!(idx_c5_v13, 5, 13);
idx_case!(idx_c7_v0, 7, 0);
idx_case!(idx_c7_v1, 7, 1);
idx_case!(idx_c7_v6, 7, 6);
idx_case!(idx_c7_v7, 7, 7);
idx_case!(idx_c7_v8, 7, 8);
idx_case!(idx_c7_v14, 7, 14);
idx_case!(idx_c7_v17, 7, 17);
idx_case!(idx_c16_v0, 16, 0);
idx_case!(idx_c16_v1, 16, 1);
idx_case!(idx_c16_v15, 16, 15);
idx_case!(idx_c16_v16, 16, 16);
idx_case!(idx_c16_v17, 16, 17);
idx_case!(idx_c16_v32, 16, 32);
idx_case!(idx_c16_v35, 16, 35);
idx_case!(idx_c100_v0, 100, 0);
idx_case!(idx_c100_v1, 100, 1);
idx_case!(idx_c100_v99, 100, 99);
idx_case!(idx_c100_v100, 100, 100);
idx_case!(idx_c100_v101, 100, 101);
idx_case!(idx_c100_v200, 100, 200);
idx_case!(idx_c100_v203, 100, 203);

idx_case!(idx_zero_cap_zero, 0, 0);
idx_case!(idx_zero_cap_max, 0, u64::MAX);
idx_case!(idx_max_mod_small, 3, u64::MAX);
idx_case!(idx_max_mod_pow2, 16, u64::MAX);
idx_case!(idx_max_exact_multiple, 7, u64::MAX - 1); // 2^64-2 は 7 の倍数
                                                    // ---- usage_percent: 切り捨てと境界 ----
macro_rules! usage_case {
    ($name:ident, $used:expr, $cap:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                usage_percent($used, $cap),
                $expect,
                "usage({},{})",
                $used,
                $cap
            );
        }
    };
}

usage_case!(usage_00, 0, 4, 0);
usage_case!(usage_01, 1, 4, 25);
usage_case!(usage_02, 2, 4, 50);
usage_case!(usage_03, 3, 4, 75);
usage_case!(usage_04, 4, 4, 100);
usage_case!(usage_05, 1, 3, 33);
usage_case!(usage_06, 2, 3, 66);
usage_case!(usage_07, 3, 3, 100);
usage_case!(usage_08, 1, 7, 14);
usage_case!(usage_09, 6, 7, 85);
usage_case!(usage_10, 7, 7, 100);
usage_case!(usage_11, 1, 200, 0);
usage_case!(usage_12, 199, 200, 99);
usage_case!(usage_13, 0, 0, 100);
usage_case!(usage_14, 5, 0, 100);
usage_case!(usage_15, u64::MAX / 100, u64::MAX / 100, 100);
usage_case!(usage_16, u64::MAX / 100, u64::MAX, 0);
// 飽和域の特性化: used*100 が u64 に収まらない入力では saturating_mul で
// 頭打ちになり、比率は意味を持たない（Cursor がこの域に達することは無い）。
// usage_percent(u64::MAX, u64::MAX) は現行実装では (MAX 飽和)/MAX = 1 になる。
// この挙動を変える場合は、ここを意図的に更新すること。
usage_case!(usage_17_saturating_region, u64::MAX, u64::MAX, 1);

// ---- RingConfig: offset / required_len の合成 ----
macro_rules! cfg_case {
    ($name:ident, $dc:expr, $pc:expr) => {
        #[test]
        fn $name() {
            let cfg = RingConfig::new($dc, $pc);
            assert_eq!(cfg.descriptors_offset(), 256);
            assert_eq!(cfg.payload_offset(), 256 + $dc * 64);
            assert_eq!(cfg.required_len(), 256 + $dc * 64 + $pc);
            assert!(cfg.payload_offset() >= cfg.descriptors_offset() + $dc * 64);
        }
    };
}

cfg_case!(cfg_d2_p16, 2, 16);
cfg_case!(cfg_d2_p17, 2, 17);
cfg_case!(cfg_d2_p100, 2, 100);
cfg_case!(cfg_d2_p1048576, 2, 1048576);
cfg_case!(cfg_d3_p16, 3, 16);
cfg_case!(cfg_d3_p17, 3, 17);
cfg_case!(cfg_d3_p100, 3, 100);
cfg_case!(cfg_d3_p1048576, 3, 1048576);
cfg_case!(cfg_d4_p16, 4, 16);
cfg_case!(cfg_d4_p17, 4, 17);
cfg_case!(cfg_d4_p100, 4, 100);
cfg_case!(cfg_d4_p1048576, 4, 1048576);
cfg_case!(cfg_d5_p16, 5, 16);
cfg_case!(cfg_d5_p17, 5, 17);
cfg_case!(cfg_d5_p100, 5, 100);
cfg_case!(cfg_d5_p1048576, 5, 1048576);
cfg_case!(cfg_d8_p16, 8, 16);
cfg_case!(cfg_d8_p17, 8, 17);
cfg_case!(cfg_d8_p100, 8, 100);
cfg_case!(cfg_d8_p1048576, 8, 1048576);
cfg_case!(cfg_d16_p16, 16, 16);
cfg_case!(cfg_d16_p17, 16, 17);
cfg_case!(cfg_d16_p100, 16, 100);
cfg_case!(cfg_d16_p1048576, 16, 1048576);
cfg_case!(cfg_d4096_p16, 4096, 16);
cfg_case!(cfg_d4096_p17, 4096, 17);
cfg_case!(cfg_d4096_p100, 4096, 100);
cfg_case!(cfg_d4096_p1048576, 4096, 1048576);

// ---- RingConfig: 下限未満は拒否 (panic) ----
#[test]
#[should_panic]
fn cfg_rejects_descriptor_capacity_0() {
    let _ = RingConfig::new(0, 16);
}
#[test]
#[should_panic]
fn cfg_rejects_descriptor_capacity_1() {
    let _ = RingConfig::new(1, 16);
}
#[test]
#[should_panic]
fn cfg_rejects_payload_capacity_0() {
    let _ = RingConfig::new(2, 0);
}
#[test]
#[should_panic]
fn cfg_rejects_payload_capacity_15() {
    let _ = RingConfig::new(2, 15);
}
#[test]
fn cfg_accepts_minimums() {
    let cfg = RingConfig::new(2, 16);
    assert_eq!(cfg.required_len(), 256 + 128 + 16);
}

// ---- LossCounters::diff_since ----
fn lc(a: u64, b: u64, c: u64) -> LossCounters {
    LossCounters {
        dropped_events: a,
        dropped_payload_bytes: b,
        degraded_events: c,
    }
}
macro_rules! diff_case {
    ($name:ident, $prev:expr, $now:expr, $expect:expr) => {
        #[test]
        fn $name() {
            assert_eq!($now.diff_since(&$prev), $expect);
        }
    };
}
diff_case!(
    diff_all_advance,
    lc(1, 2, 3),
    lc(4, 6, 9),
    Some(lc(3, 4, 6))
);
diff_case!(diff_all_equal, lc(5, 5, 5), lc(5, 5, 5), Some(lc(0, 0, 0)));
diff_case!(
    diff_zero_to_zero,
    lc(0, 0, 0),
    lc(0, 0, 0),
    Some(lc(0, 0, 0))
);
diff_case!(diff_regress_events, lc(5, 0, 0), lc(4, 9, 9), None);
diff_case!(diff_regress_bytes, lc(0, 5, 0), lc(9, 4, 9), None);
diff_case!(diff_regress_degraded, lc(0, 0, 5), lc(9, 9, 4), None);
diff_case!(
    diff_u64_max_stable,
    lc(u64::MAX, 0, 0),
    lc(u64::MAX, 1, 1),
    Some(lc(0, 1, 1))
);
