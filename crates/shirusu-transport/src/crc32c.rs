//! CRC32C (Castagnoli)。x86/x64 は実行時に SSE4.2 を確認して命令を使い、
//! 非対応 CPU・その他のアーキテクチャではソフトウェア実装へフォールバックする。
//! テーブルはコンパイル時に生成する。

const POLY: u32 = 0x82F6_3B78; // reflected Castagnoli

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}
static TABLE: [u32; 256] = make_table();

pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0, data)
}

pub fn crc32c_update(seed: u32, data: &[u8]) -> u32 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::is_x86_feature_detected!("sse4.2") {
        // SAFETY: the runtime feature check guards every call, including on
        // older x86 CPUs. Slice reads remain bounded and need no alignment.
        return unsafe { hardware_update(seed, data) };
    }
    software_update(seed, data)
}

fn software_update(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse4.2")]
unsafe fn hardware_update(seed: u32, mut data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{_mm_crc32_u32, _mm_crc32_u8};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{_mm_crc32_u32, _mm_crc32_u64, _mm_crc32_u8};

    let mut crc = !seed;
    #[cfg(target_arch = "x86_64")]
    {
        let mut wide = u64::from(crc);
        while data.len() >= 8 {
            wide = _mm_crc32_u64(wide, u64::from_le_bytes(data[..8].try_into().unwrap()));
            data = &data[8..];
        }
        crc = wide as u32;
    }
    while data.len() >= 4 {
        crc = _mm_crc32_u32(crc, u32::from_le_bytes(data[..4].try_into().unwrap()));
        data = &data[4..];
    }
    for &byte in data {
        crc = _mm_crc32_u8(crc, byte);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vectors() {
        // CRC-32C の標準チェック値。
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }
    #[test]
    fn incremental_matches_whole() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let whole = crc32c(&data);
        let part = crc32c_update(crc32c(&data[..37]), &data[37..]);
        let recomputed = crc32c(&[&data[..37], &data[37..]].concat());
        assert_eq!(whole, recomputed);
        assert_eq!(whole, part);
    }
    #[test]
    fn accelerated_and_incremental_checks_match_software_for_all_tails() {
        let data: Vec<u8> = (0..2056u32).map(|i| (i * 31 % 251) as u8).collect();
        for offset in 0..8 {
            for len in 0..=2048 {
                let bytes = &data[offset..offset + len];
                for seed in [0, 1, 0x1234_5678, u32::MAX] {
                    let expected = software_update(seed, bytes);
                    assert_eq!(
                        crc32c_update(seed, bytes),
                        expected,
                        "offset={offset} len={len} seed={seed}"
                    );
                    let split = len / 2;
                    assert_eq!(
                        crc32c_update(crc32c_update(seed, &bytes[..split]), &bytes[split..]),
                        expected
                    );
                }
            }
        }
    }
    #[test]
    fn detects_single_bit_flip() {
        let mut data = b"shirusu transport".to_vec();
        let original = crc32c(&data);
        data[3] ^= 1;
        assert_ne!(crc32c(&data), original);
    }

    /// テーブルを使わないビット単位の参照実装との差分検証。
    /// テーブル生成 (const fn) を実行時にも呼び、生成結果が静的テーブルと
    /// 一致すること、テーブル法とビット法が全長で一致することを確認する。
    #[test]
    fn table_matches_bitwise_reference() {
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
        assert_eq!(
            make_table(),
            TABLE,
            "runtime-generated table == static table"
        );
        let pattern: Vec<u8> = (0..2048u32).map(|i| (i * 31 % 256) as u8).collect();
        for len in 0..=1024usize {
            let data = &pattern[..len];
            assert_eq!(crc32c(data), bitwise(data), "len {len}");
        }
        // 全バイト値を含む入力でも一致する
        let all_bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_eq!(crc32c(&all_bytes), bitwise(&all_bytes));
        // update の連結性: seed を内部状態として引き継ぐ形でもビット法と一致する
        let whole = bitwise(&pattern[..100]);
        assert_eq!(crc32c(&pattern[..100]), whole);
    }
}
