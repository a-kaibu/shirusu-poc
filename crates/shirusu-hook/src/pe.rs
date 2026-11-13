//! PE イメージの最小解析。対象は「メモリイメージ配置（RVA = バッファ内
//! オフセット）」のバイト列であり、ファイルイメージは
//! [`map_file_to_image`] で同配置へ写してから解析する。
//!
//! 用途は 2 つ:
//! - Agent 側（プロセス内）: ロード済みモジュールのインポートディレクトリ
//!   を歩き、IAT フック計画の入力にする。
//! - Host 側: Agent DLL ファイルのエクスポート RVA を求め、注入先での
//!   初期化エントリのアドレスを計算する。
//!
//! 共有メモリではなくファイル/自プロセスのイメージが対象だが、相手は
//! 完全には信用しない前提で全読み取りを境界検査し、不正な入力では
//! パニックせず None / 空を返す。

/// インポート 1 件分。`iat_rva` は IAT スロットの RVA（= イメージ内
/// オフセット）。ここに関数ポインタが格納されている。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSite {
    pub dll_name: String,
    /// 名前インポートの場合の関数名。序数インポートでは None。
    pub func_name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off.checked_add(8)?)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn read_c_string(b: &[u8], off: usize, max: usize) -> Option<String> {
    let end = b.len().min(off.checked_add(max)?);
    let slice = b.get(off..end)?;
    let nul = slice.iter().position(|&c| c == 0)?;
    // DLL 名・関数名は ASCII 前提。不正なバイトは lossy に倒す（照合で外れる）。
    Some(String::from_utf8_lossy(&slice[..nul]).into_owned())
}

struct NtHeaders {
    machine: u16,
    optional_off: usize,
    is64: bool,
    num_sections: usize,
    section_off: usize,
}

fn nt_headers(b: &[u8]) -> Option<NtHeaders> {
    if b.get(0..2)? != b"MZ" {
        return None;
    }
    let nt = rd_u32(b, 0x3C)? as usize;
    if b.get(nt..nt.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = nt + 4;
    let num_sections = rd_u16(b, coff + 2)? as usize;
    let opt_size = rd_u16(b, coff + 16)? as usize;
    let optional_off = coff + 20;
    let magic = rd_u16(b, optional_off)?;
    let is64 = match magic {
        0x10B => false,
        0x20B => true,
        _ => return None,
    };
    if optional_off.checked_add(opt_size)? > b.len() {
        return None;
    }
    Some(NtHeaders {
        machine: rd_u16(b, coff)?,
        optional_off,
        is64,
        num_sections,
        section_off: optional_off + opt_size,
    })
}

/// データディレクトリ (index: 0=export, 1=import) の (RVA, サイズ)。
fn data_directory(b: &[u8], h: &NtHeaders, index: usize) -> Option<(u32, u32)> {
    let base = h.optional_off + if h.is64 { 112 } else { 96 };
    let off = base.checked_add(index.checked_mul(8)?)?;
    if off.checked_add(8)? > h.section_off {
        return None;
    }
    Some((rd_u32(b, off)?, rd_u32(b, off + 4)?))
}

/// イメージの SizeOfImage。
pub fn size_of_image(b: &[u8]) -> Option<u32> {
    let h = nt_headers(b)?;
    rd_u32(b, h.optional_off + 56)
}

/// COFF Machine identifier. Pointer width alone does not identify the ISA.
pub fn machine(b: &[u8]) -> Option<u16> {
    nt_headers(b).map(|h| h.machine)
}

/// 64bit PE (PE32+) かどうか。
pub fn is_pe64(b: &[u8]) -> Option<bool> {
    nt_headers(b).map(|h| h.is64)
}

/// インポートディレクトリを歩き、全インポートを列挙する。
/// 不正なイメージでは空 Vec を返す（部分的に読めた分は返す）。
///
/// 対象は通常のインポートディレクトリ（data directory 1）のみ。
/// 遅延ロードインポート（delay-load、directory 13）は扱わない
/// （レビュー #6 M07）。遅延ロード経由の API は IAT フックの対象に
/// ならず、その呼び出しは Capture Coverage の欠落として数える側に
/// 倒す。L13 の静的依存記録も同じ境界である（理由と合わせて
/// `shirusu_trace::static_dep` のモジュールドキュメントに明記）。
pub fn parse_imports(image: &[u8]) -> Vec<ImportSite> {
    let mut out = Vec::new();
    let Some(h) = nt_headers(image) else {
        return out;
    };
    let Some((dir_rva, _)) = data_directory(image, &h, 1) else {
        return out;
    };
    if dir_rva == 0 {
        return out;
    }
    let thunk_size = if h.is64 { 8 } else { 4 };
    let ordinal_flag: u64 = if h.is64 {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };
    let mut desc_off = dir_rva as usize;
    // ディスクリプタ数の暴走防止（実在のモジュールでも数百が上限）
    for _ in 0..4096 {
        if desc_off.checked_add(20).is_none_or(|end| end > image.len()) {
            break;
        }
        let Some(original_first_thunk) = rd_u32(image, desc_off) else {
            break;
        };
        let Some(name_rva) = rd_u32(image, desc_off + 12) else {
            break;
        };
        let Some(first_thunk) = rd_u32(image, desc_off + 16) else {
            break;
        };
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break; // 終端ディスクリプタ
        }
        desc_off += 20;
        let Some(dll_name) = read_c_string(image, name_rva as usize, 512) else {
            continue;
        };
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        for i in 0..16384usize {
            let Some(entry_off) = (lookup_rva as usize).checked_add(i * thunk_size) else {
                break;
            };
            let val = if h.is64 {
                rd_u64(image, entry_off)
            } else {
                rd_u32(image, entry_off).map(|v| v as u64)
            };
            let Some(val) = val else { break };
            if val == 0 {
                break;
            }
            let Some(iat_rva) = first_thunk.checked_add((i * thunk_size) as u32) else {
                break;
            };
            if (iat_rva as usize)
                .checked_add(thunk_size)
                .is_none_or(|end| end > image.len())
            {
                break;
            }
            if val & ordinal_flag != 0 {
                out.push(ImportSite {
                    dll_name: dll_name.clone(),
                    func_name: None,
                    ordinal: Some((val & 0xFFFF) as u16),
                    iat_rva,
                });
            } else {
                let name = u32::try_from(val)
                    .ok()
                    .and_then(|rva| rva.checked_add(2))
                    .and_then(|rva| read_c_string(image, rva as usize, 512));
                out.push(ImportSite {
                    dll_name: dll_name.clone(),
                    func_name: name,
                    ordinal: None,
                    iat_rva,
                });
            }
        }
    }
    out
}

/// エクスポート名から関数 RVA を引く。見つからない/不正なら None。
pub fn find_export(image: &[u8], name: &str) -> Option<u32> {
    let h = nt_headers(image)?;
    let (dir_rva, _) = data_directory(image, &h, 0)?;
    if dir_rva == 0 {
        return None;
    }
    let d = dir_rva as usize;
    image.get(d..d.checked_add(40)?)?;
    let num_names = rd_u32(image, d + 24)? as usize;
    let names_rva = rd_u32(image, d + 32)? as usize;
    let ordinals_rva = rd_u32(image, d + 36)? as usize;
    let functions_rva = rd_u32(image, d + 28)? as usize;
    if num_names > 1_000_000 {
        return None;
    }
    for i in 0..num_names {
        let name_rva = rd_u32(image, names_rva.checked_add(i.checked_mul(4)?)?)? as usize;
        if read_c_string(image, name_rva, 512).as_deref() == Some(name) {
            let ordinal = rd_u16(image, ordinals_rva.checked_add(i.checked_mul(2)?)?)? as usize;
            let rva = rd_u32(image, functions_rva.checked_add(ordinal.checked_mul(4)?)?)?;
            // Forwarded exports point into the export directory, not executable
            // code. This API resolves only direct addresses.
            let (_, export_size) = data_directory(image, &h, 0)?;
            let export_end = dir_rva.checked_add(export_size)?;
            if rva == 0 || rva as usize >= image.len() || (dir_rva..export_end).contains(&rva) {
                return None;
            }
            return Some(rva);
        }
    }
    None
}

/// ファイルイメージをメモリイメージ配置へ写す。ヘッダーと各セクションの
/// 生データを VirtualAddress へ配置した Vec を返す（長さ = SizeOfImage）。
pub fn map_file_to_image(file: &[u8]) -> Option<Vec<u8>> {
    let h = nt_headers(file)?;
    let size = size_of_image(file)? as usize;
    if size == 0 || size > 512 * 1024 * 1024 {
        return None;
    }
    let size_of_headers = rd_u32(file, h.optional_off + 60)? as usize;
    let mut image = vec![0u8; size];
    let hdr_len = size_of_headers.min(file.len()).min(size);
    image[..hdr_len].copy_from_slice(&file[..hdr_len]);
    for i in 0..h.num_sections {
        let s = h.section_off + i * 40;
        let virtual_size = rd_u32(file, s + 8)? as usize;
        let virtual_addr = rd_u32(file, s + 12)? as usize;
        let raw_size = rd_u32(file, s + 16)? as usize;
        let raw_ptr = rd_u32(file, s + 20)? as usize;
        if raw_size == 0 {
            continue;
        }
        let copy = raw_size.min(if virtual_size == 0 {
            raw_size
        } else {
            virtual_size
        });
        let src = file.get(raw_ptr..raw_ptr.checked_add(copy)?)?;
        let dst = image.get_mut(virtual_addr..virtual_addr.checked_add(copy)?)?;
        dst.copy_from_slice(src);
    }
    Some(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn wstr(b: &mut [u8], off: usize, s: &str) {
        b[off..off + s.len()].copy_from_slice(s.as_bytes());
        b[off + s.len()] = 0;
    }

    /// 最小の PE32+ イメージを合成する。optional header は 240 バイト、
    /// セクション 0 個として、データディレクトリを直接置く。
    fn synthetic_image(size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size];
        b[0..2].copy_from_slice(b"MZ");
        w32(&mut b, 0x3C, 0x80); // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        w16(&mut b, coff + 2, 0); // sections
        w16(&mut b, coff + 16, 240); // size of optional header
        let opt = coff + 20;
        w16(&mut b, opt, 0x20B); // PE32+
        w32(&mut b, opt + 56, size as u32); // SizeOfImage
        w32(&mut b, opt + 60, 0x200); // SizeOfHeaders
        b
    }
    fn set_dir(b: &mut [u8], index: usize, rva: u32, size: u32) {
        let opt = 0x84 + 20;
        let base = opt + 112; // PE32+
        w32(b, base + index * 8, rva);
        w32(b, base + index * 8 + 4, size);
    }

    #[test]
    fn machine_is_distinct_from_pointer_width() {
        let mut image = synthetic_image(0x1000);
        for machine_id in [0x8664, 0xaa64, 0x014c, 0xffff] {
            w16(&mut image, 0x84, machine_id);
            assert_eq!(machine(&image), Some(machine_id));
            assert_eq!(is_pe64(&image), Some(true));
        }
        assert_eq!(machine(&[]), None);
        assert_eq!(machine(&image[..0x85]), None);
    }

    #[test]
    fn parses_imports_with_names_and_ordinals() {
        let mut img = synthetic_image(0x4000);
        // import directory at 0x1000: 2 descriptors + terminator
        set_dir(&mut img, 1, 0x1000, 60);
        // desc 0: kernel32.dll, OFT=0x1100, FT=0x1200
        w32(&mut img, 0x1000, 0x1100);
        w32(&mut img, 0x1000 + 12, 0x1300);
        w32(&mut img, 0x1000 + 16, 0x1200);
        // desc 1: user32.dll, OFT=0, FT=0x1280 (ILT なし)
        w32(&mut img, 0x1014 + 12, 0x1340);
        w32(&mut img, 0x1014 + 16, 0x1280);
        wstr(&mut img, 0x1300, "kernel32.dll");
        wstr(&mut img, 0x1340, "user32.dll");
        // lookup entries for desc0: CreateFileW (by name @0x1400), ordinal 42, end
        w64(&mut img, 0x1100, 0x1400);
        w64(&mut img, 0x1108, 0x8000_0000_0000_0000 | 42);
        w64(&mut img, 0x1110, 0);
        w16(&mut img, 0x1400, 0); // hint
        wstr(&mut img, 0x1402, "CreateFileW");
        // desc1 lookup via FT: MessageBoxW @0x1440
        w64(&mut img, 0x1280, 0x1440);
        w64(&mut img, 0x1288, 0);
        wstr(&mut img, 0x1442, "MessageBoxW");

        let sites = parse_imports(&img);
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].dll_name, "kernel32.dll");
        assert_eq!(sites[0].func_name.as_deref(), Some("CreateFileW"));
        assert_eq!(sites[0].iat_rva, 0x1200);
        assert_eq!(sites[1].ordinal, Some(42));
        assert_eq!(sites[1].iat_rva, 0x1208);
        assert_eq!(sites[2].dll_name, "user32.dll");
        assert_eq!(sites[2].func_name.as_deref(), Some("MessageBoxW"));
        assert_eq!(sites[2].iat_rva, 0x1280);
    }

    #[test]
    fn finds_exports() {
        let mut img = synthetic_image(0x4000);
        set_dir(&mut img, 0, 0x2000, 40);
        let d = 0x2000;
        w32(&mut img, d + 24, 2); // NumberOfNames
        w32(&mut img, d + 28, 0x2100); // AddressOfFunctions
        w32(&mut img, d + 32, 0x2200); // AddressOfNames
        w32(&mut img, d + 36, 0x2300); // AddressOfNameOrdinals
        w32(&mut img, 0x2200, 0x2400);
        w32(&mut img, 0x2204, 0x2500);
        wstr(&mut img, 0x2400, "shirusu_agent_init");
        wstr(&mut img, 0x2500, "shirusu_agent_shutdown");
        w16(&mut img, 0x2300, 0);
        w16(&mut img, 0x2302, 1);
        w32(&mut img, 0x2100, 0x1111);
        w32(&mut img, 0x2104, 0x2222);
        assert_eq!(find_export(&img, "shirusu_agent_init"), Some(0x1111));
        assert_eq!(find_export(&img, "shirusu_agent_shutdown"), Some(0x2222));
        assert_eq!(find_export(&img, "nonexistent"), None);
        for invalid_rva in [0, 0x2008, 0x4000, u32::MAX] {
            w32(&mut img, 0x2100, invalid_rva);
            assert_eq!(find_export(&img, "shirusu_agent_init"), None);
        }
    }

    #[test]
    fn rejects_garbage_without_panic() {
        assert!(parse_imports(&[]).is_empty());
        assert!(parse_imports(&[0u8; 64]).is_empty());
        assert_eq!(find_export(&[1, 2, 3], "x"), None);
        let mut img = synthetic_image(0x1000);
        set_dir(&mut img, 1, 0xFFFF_0000, 20); // 範囲外 RVA
        assert!(parse_imports(&img).is_empty());
    }

    #[test]
    fn rejects_out_of_image_iat() {
        let mut img = synthetic_image(0x4000);
        set_dir(&mut img, 1, 0x1000, 40);
        w32(&mut img, 0x1000, 0x1100);
        w32(&mut img, 0x100c, 0x1300);
        wstr(&mut img, 0x1300, "kernel32.dll");
        w64(&mut img, 0x1100, 0x8000_0000_0000_0042);
        for invalid_iat in [0x3ffc, 0x4000, u32::MAX] {
            w32(&mut img, 0x1010, invalid_iat);
            assert!(parse_imports(&img).is_empty());
        }
    }

    #[test]
    fn maps_file_sections_to_image() {
        // ファイル配置: ヘッダー 0x200、セクション raw は 0x200 から、VA は 0x1000
        let mut file = synthetic_image(0x2000);
        let coff = 0x84;
        w16(&mut file, coff + 2, 1); // 1 section
        let opt_size = 240u16;
        w16(&mut file, coff + 16, opt_size);
        let sec = coff + 20 + opt_size as usize;
        w32(&mut file, sec + 8, 0x100); // VirtualSize
        w32(&mut file, sec + 12, 0x1000); // VirtualAddress
        w32(&mut file, sec + 16, 0x100); // SizeOfRawData
        w32(&mut file, sec + 20, 0x200); // PointerToRawData
        file[0x200..0x204].copy_from_slice(b"DATA");
        let image = map_file_to_image(&file).expect("map");
        assert_eq!(image.len(), 0x2000);
        assert_eq!(&image[0x1000..0x1004], b"DATA");
        assert_eq!(size_of_image(&image), Some(0x2000));
        assert_eq!(is_pe64(&image), Some(true));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const LEN: usize = 160;

    /// 境界検査付きの読み取りは、範囲内なら LE 値そのもの、範囲外なら None。
    /// オフセットの加算あふれ (usize::MAX 付近) でも panic しない。
    #[kani::proof]
    fn bounded_reads_are_exact_or_none() {
        let b: [u8; 16] = kani::any();
        let off: usize = kani::any();
        match rd_u32(&b, off) {
            Some(v) => {
                assert!(off <= b.len() - 4);
                assert!(v == u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]));
            }
            None => assert!(off > b.len() - 4),
        }
        match rd_u16(&b, off) {
            Some(v) => assert!(off <= b.len() - 2 && v == u16::from_le_bytes([b[off], b[off + 1]])),
            None => assert!(off > b.len() - 2),
        }
        assert!(rd_u64(&b, off).is_some() == (off <= b.len() - 8));
    }

    /// 任意のヘッダー領域について、NT ヘッダー解析は panic せず、受理した場合は
    /// MZ / PE シグネチャと Optional Header が実際にバッファ内にある。
    /// データディレクトリの位置もセクション表より前に収まる。
    #[kani::proof]
    fn nt_headers_accepts_only_in_bounds_headers() {
        let mut b: [u8; LEN] = kani::any();
        // 探索を有意な形に寄せる: 先頭は MZ、e_lfanew は記号的な小さい値。
        b[0] = b'M';
        b[1] = b'Z';
        if let Some(h) = nt_headers(&b) {
            let nt = rd_u32(&b, 0x3C).unwrap() as usize;
            assert!(nt + 4 <= LEN);
            assert!(b[nt] == b'P' && b[nt + 1] == b'E' && b[nt + 2] == 0 && b[nt + 3] == 0);
            assert!(h.optional_off == nt + 24);
            assert!(h.section_off <= LEN);
            assert!(h.optional_off <= h.section_off);
            let index: usize = kani::any();
            if let Some(_) = data_directory(&b, &h, index) {
                let base = h.optional_off + if h.is64 { 112 } else { 96 };
                assert!(base + index * 8 + 8 <= h.section_off);
            }
            assert!(is_pe64(&b) == Some(h.is64));
            assert!(machine(&b) == Some(h.machine));
        } else {
            assert!(is_pe64(&b).is_none() && machine(&b).is_none());
        }
        let _ = size_of_image(&b);
    }
}
