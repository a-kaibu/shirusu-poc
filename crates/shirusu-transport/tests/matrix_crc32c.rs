//! CRC32C 行列スイート（拡充第2弾）。
//! 検証する行列: 入力長 0..=256 の全長について、テーブル駆動実装が
//! ビット単位参照実装と一致すること。各長さは内容も長さ依存に変えてあり
//! (byte = i*31 + len)、長さごとの失敗が独立に検出できる。
//! 追加で seed 連結 (crc32c_update の分割位置) と単一バイト値の反復入力も検証する。

use shirusu_transport::crc32c::{crc32c, crc32c_update};

const POLY: u32 = 0x82F6_3B78; // reflected Castagnoli

/// テーブルを使わないビット単位の参照実装。
fn bitwise(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// 長さ依存パターン: 長さが違えば中身も違うため、長さの取り違えも検出できる。
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + len) as u8).collect()
}

macro_rules! crc_len {
    ($name:ident, $len:expr) => {
        #[test]
        fn $name() {
            let data = pattern($len);
            assert_eq!(
                crc32c(&data),
                bitwise(&data),
                "table vs bitwise, len {}",
                $len
            );
            assert_eq!(
                crc32c_update(0, &data),
                crc32c(&data),
                "seed 0 == crc32c, len {}",
                $len
            );
        }
    };
}

crc_len!(len_000, 0);
crc_len!(len_001, 1);
crc_len!(len_002, 2);
crc_len!(len_003, 3);
crc_len!(len_004, 4);
crc_len!(len_005, 5);
crc_len!(len_006, 6);
crc_len!(len_007, 7);
crc_len!(len_008, 8);
crc_len!(len_009, 9);
crc_len!(len_010, 10);
crc_len!(len_011, 11);
crc_len!(len_012, 12);
crc_len!(len_013, 13);
crc_len!(len_014, 14);
crc_len!(len_015, 15);
crc_len!(len_016, 16);
crc_len!(len_017, 17);
crc_len!(len_018, 18);
crc_len!(len_019, 19);
crc_len!(len_020, 20);
crc_len!(len_021, 21);
crc_len!(len_022, 22);
crc_len!(len_023, 23);
crc_len!(len_024, 24);
crc_len!(len_025, 25);
crc_len!(len_026, 26);
crc_len!(len_027, 27);
crc_len!(len_028, 28);
crc_len!(len_029, 29);
crc_len!(len_030, 30);
crc_len!(len_031, 31);
crc_len!(len_032, 32);
crc_len!(len_033, 33);
crc_len!(len_034, 34);
crc_len!(len_035, 35);
crc_len!(len_036, 36);
crc_len!(len_037, 37);
crc_len!(len_038, 38);
crc_len!(len_039, 39);
crc_len!(len_040, 40);
crc_len!(len_041, 41);
crc_len!(len_042, 42);
crc_len!(len_043, 43);
crc_len!(len_044, 44);
crc_len!(len_045, 45);
crc_len!(len_046, 46);
crc_len!(len_047, 47);
crc_len!(len_048, 48);
crc_len!(len_049, 49);
crc_len!(len_050, 50);
crc_len!(len_051, 51);
crc_len!(len_052, 52);
crc_len!(len_053, 53);
crc_len!(len_054, 54);
crc_len!(len_055, 55);
crc_len!(len_056, 56);
crc_len!(len_057, 57);
crc_len!(len_058, 58);
crc_len!(len_059, 59);
crc_len!(len_060, 60);
crc_len!(len_061, 61);
crc_len!(len_062, 62);
crc_len!(len_063, 63);
crc_len!(len_064, 64);
crc_len!(len_065, 65);
crc_len!(len_066, 66);
crc_len!(len_067, 67);
crc_len!(len_068, 68);
crc_len!(len_069, 69);
crc_len!(len_070, 70);
crc_len!(len_071, 71);
crc_len!(len_072, 72);
crc_len!(len_073, 73);
crc_len!(len_074, 74);
crc_len!(len_075, 75);
crc_len!(len_076, 76);
crc_len!(len_077, 77);
crc_len!(len_078, 78);
crc_len!(len_079, 79);
crc_len!(len_080, 80);
crc_len!(len_081, 81);
crc_len!(len_082, 82);
crc_len!(len_083, 83);
crc_len!(len_084, 84);
crc_len!(len_085, 85);
crc_len!(len_086, 86);
crc_len!(len_087, 87);
crc_len!(len_088, 88);
crc_len!(len_089, 89);
crc_len!(len_090, 90);
crc_len!(len_091, 91);
crc_len!(len_092, 92);
crc_len!(len_093, 93);
crc_len!(len_094, 94);
crc_len!(len_095, 95);
crc_len!(len_096, 96);
crc_len!(len_097, 97);
crc_len!(len_098, 98);
crc_len!(len_099, 99);
crc_len!(len_100, 100);
crc_len!(len_101, 101);
crc_len!(len_102, 102);
crc_len!(len_103, 103);
crc_len!(len_104, 104);
crc_len!(len_105, 105);
crc_len!(len_106, 106);
crc_len!(len_107, 107);
crc_len!(len_108, 108);
crc_len!(len_109, 109);
crc_len!(len_110, 110);
crc_len!(len_111, 111);
crc_len!(len_112, 112);
crc_len!(len_113, 113);
crc_len!(len_114, 114);
crc_len!(len_115, 115);
crc_len!(len_116, 116);
crc_len!(len_117, 117);
crc_len!(len_118, 118);
crc_len!(len_119, 119);
crc_len!(len_120, 120);
crc_len!(len_121, 121);
crc_len!(len_122, 122);
crc_len!(len_123, 123);
crc_len!(len_124, 124);
crc_len!(len_125, 125);
crc_len!(len_126, 126);
crc_len!(len_127, 127);
crc_len!(len_128, 128);
crc_len!(len_129, 129);
crc_len!(len_130, 130);
crc_len!(len_131, 131);
crc_len!(len_132, 132);
crc_len!(len_133, 133);
crc_len!(len_134, 134);
crc_len!(len_135, 135);
crc_len!(len_136, 136);
crc_len!(len_137, 137);
crc_len!(len_138, 138);
crc_len!(len_139, 139);
crc_len!(len_140, 140);
crc_len!(len_141, 141);
crc_len!(len_142, 142);
crc_len!(len_143, 143);
crc_len!(len_144, 144);
crc_len!(len_145, 145);
crc_len!(len_146, 146);
crc_len!(len_147, 147);
crc_len!(len_148, 148);
crc_len!(len_149, 149);
crc_len!(len_150, 150);
crc_len!(len_151, 151);
crc_len!(len_152, 152);
crc_len!(len_153, 153);
crc_len!(len_154, 154);
crc_len!(len_155, 155);
crc_len!(len_156, 156);
crc_len!(len_157, 157);
crc_len!(len_158, 158);
crc_len!(len_159, 159);
crc_len!(len_160, 160);
crc_len!(len_161, 161);
crc_len!(len_162, 162);
crc_len!(len_163, 163);
crc_len!(len_164, 164);
crc_len!(len_165, 165);
crc_len!(len_166, 166);
crc_len!(len_167, 167);
crc_len!(len_168, 168);
crc_len!(len_169, 169);
crc_len!(len_170, 170);
crc_len!(len_171, 171);
crc_len!(len_172, 172);
crc_len!(len_173, 173);
crc_len!(len_174, 174);
crc_len!(len_175, 175);
crc_len!(len_176, 176);
crc_len!(len_177, 177);
crc_len!(len_178, 178);
crc_len!(len_179, 179);
crc_len!(len_180, 180);
crc_len!(len_181, 181);
crc_len!(len_182, 182);
crc_len!(len_183, 183);
crc_len!(len_184, 184);
crc_len!(len_185, 185);
crc_len!(len_186, 186);
crc_len!(len_187, 187);
crc_len!(len_188, 188);
crc_len!(len_189, 189);
crc_len!(len_190, 190);
crc_len!(len_191, 191);
crc_len!(len_192, 192);
crc_len!(len_193, 193);
crc_len!(len_194, 194);
crc_len!(len_195, 195);
crc_len!(len_196, 196);
crc_len!(len_197, 197);
crc_len!(len_198, 198);
crc_len!(len_199, 199);
crc_len!(len_200, 200);
crc_len!(len_201, 201);
crc_len!(len_202, 202);
crc_len!(len_203, 203);
crc_len!(len_204, 204);
crc_len!(len_205, 205);
crc_len!(len_206, 206);
crc_len!(len_207, 207);
crc_len!(len_208, 208);
crc_len!(len_209, 209);
crc_len!(len_210, 210);
crc_len!(len_211, 211);
crc_len!(len_212, 212);
crc_len!(len_213, 213);
crc_len!(len_214, 214);
crc_len!(len_215, 215);
crc_len!(len_216, 216);
crc_len!(len_217, 217);
crc_len!(len_218, 218);
crc_len!(len_219, 219);
crc_len!(len_220, 220);
crc_len!(len_221, 221);
crc_len!(len_222, 222);
crc_len!(len_223, 223);
crc_len!(len_224, 224);
crc_len!(len_225, 225);
crc_len!(len_226, 226);
crc_len!(len_227, 227);
crc_len!(len_228, 228);
crc_len!(len_229, 229);
crc_len!(len_230, 230);
crc_len!(len_231, 231);
crc_len!(len_232, 232);
crc_len!(len_233, 233);
crc_len!(len_234, 234);
crc_len!(len_235, 235);
crc_len!(len_236, 236);
crc_len!(len_237, 237);
crc_len!(len_238, 238);
crc_len!(len_239, 239);
crc_len!(len_240, 240);
crc_len!(len_241, 241);
crc_len!(len_242, 242);
crc_len!(len_243, 243);
crc_len!(len_244, 244);
crc_len!(len_245, 245);
crc_len!(len_246, 246);
crc_len!(len_247, 247);
crc_len!(len_248, 248);
crc_len!(len_249, 249);
crc_len!(len_250, 250);
crc_len!(len_251, 251);
crc_len!(len_252, 252);
crc_len!(len_253, 253);
crc_len!(len_254, 254);
crc_len!(len_255, 255);
crc_len!(len_256, 256);

// ---- 単一バイト値の反復入力: バイト値 x 長さの行列 ----
macro_rules! crc_fill {
    ($name:ident, $byte:expr, $len:expr) => {
        #[test]
        fn $name() {
            let data = vec![$byte; $len];
            assert_eq!(
                crc32c(&data),
                bitwise(&data),
                "fill {:#04x} x {}",
                $byte,
                $len
            );
        }
    };
}

crc_fill!(fill_00_1, 0, 1);
crc_fill!(fill_00_2, 0, 2);
crc_fill!(fill_00_3, 0, 3);
crc_fill!(fill_00_7, 0, 7);
crc_fill!(fill_00_31, 0, 31);
crc_fill!(fill_01_1, 1, 1);
crc_fill!(fill_01_2, 1, 2);
crc_fill!(fill_01_3, 1, 3);
crc_fill!(fill_01_7, 1, 7);
crc_fill!(fill_01_31, 1, 31);
crc_fill!(fill_55_1, 85, 1);
crc_fill!(fill_55_2, 85, 2);
crc_fill!(fill_55_3, 85, 3);
crc_fill!(fill_55_7, 85, 7);
crc_fill!(fill_55_31, 85, 31);
crc_fill!(fill_80_1, 128, 1);
crc_fill!(fill_80_2, 128, 2);
crc_fill!(fill_80_3, 128, 3);
crc_fill!(fill_80_7, 128, 7);
crc_fill!(fill_80_31, 128, 31);
crc_fill!(fill_ff_1, 255, 1);
crc_fill!(fill_ff_2, 255, 2);
crc_fill!(fill_ff_3, 255, 3);
crc_fill!(fill_ff_7, 255, 7);
crc_fill!(fill_ff_31, 255, 31);

// ---- seed 連結: 分割位置ごとに update が全体 CRC と一致する ----
fn split_buf() -> Vec<u8> {
    (0..64u32).map(|i| (i * 7 + 3) as u8).collect()
}
macro_rules! crc_split {
    ($name:ident, $at:expr) => {
        #[test]
        fn $name() {
            let data = split_buf();
            let whole = crc32c(&data);
            let joined = crc32c_update(crc32c(&data[..$at]), &data[$at..]);
            assert_eq!(joined, whole, "split at {}", $at);
        }
    };
}

crc_split!(split_00, 0);
crc_split!(split_01, 1);
crc_split!(split_02, 2);
crc_split!(split_31, 31);
crc_split!(split_32, 32);
crc_split!(split_33, 33);
crc_split!(split_63, 63);
crc_split!(split_64, 64);
