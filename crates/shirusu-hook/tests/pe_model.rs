//! PE 解析のモデルベース PBT。任意のインポート表 / エクスポート表 / セクション
//! 配置を「仕様どおりの配置」で合成し、解析結果がモデルと完全に一致することを
//! 確かめる。単体テストの固定イメージでは触れない組み合わせ (PE32 と PE32+、
//! ILT の有無、名前と序数の混在、複数 DLL、セクションの写像) を網羅する。
//! 合成器は pe.rs の実装を参照せず、PE/COFF 仕様の構造定義から書き起こしている。

use proptest::prelude::*;
use shirusu_hook::pe::{
    find_export, is_pe64, map_file_to_image, parse_imports, size_of_image, ImportSite,
};
use std::collections::BTreeMap;

const IMAGE_LEN: usize = 0x20000;

#[derive(Debug, Clone)]
enum Func {
    Named(String),
    Ordinal(u16),
}

#[derive(Debug, Clone)]
struct Dll {
    name: String,
    funcs: Vec<Func>,
    with_ilt: bool,
}

fn ident() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_.]{0,30}"
}

fn arb_dll() -> impl Strategy<Value = Dll> {
    (
        ident(),
        prop::collection::vec(
            prop_oneof![
                ident().prop_map(Func::Named),
                any::<u16>().prop_map(Func::Ordinal)
            ],
            1..6,
        ),
        any::<bool>(),
    )
        .prop_map(|(name, funcs, with_ilt)| Dll {
            name,
            funcs,
            with_ilt,
        })
}

struct Image {
    b: Vec<u8>,
    is64: bool,
    bump: usize,
}

impl Image {
    fn new(is64: bool) -> Self {
        let mut b = vec![0u8; IMAGE_LEN];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        b[coff..coff + 2].copy_from_slice(&(if is64 { 0x8664u16 } else { 0x014C }).to_le_bytes());
        // Optional header: PE32 は 224、PE32+ は 240 バイト (データディレクトリ 16 個)。
        let opt_size: u16 = if is64 { 240 } else { 224 };
        b[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&(if is64 { 0x20Bu16 } else { 0x10B }).to_le_bytes());
        b[opt + 56..opt + 60].copy_from_slice(&(IMAGE_LEN as u32).to_le_bytes());
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        Self {
            b,
            is64,
            bump: 0x4000,
        }
    }
    fn dir(&mut self, index: usize, rva: u32, size: u32) {
        let base = 0x84 + 20 + if self.is64 { 112 } else { 96 } + index * 8;
        self.b[base..base + 4].copy_from_slice(&rva.to_le_bytes());
        self.b[base + 4..base + 8].copy_from_slice(&size.to_le_bytes());
    }
    fn alloc(&mut self, len: usize, align: usize) -> usize {
        self.bump = self.bump.div_ceil(align) * align;
        let at = self.bump;
        self.bump += len;
        assert!(self.bump < IMAGE_LEN, "synthetic image overflow");
        at
    }
    fn w32(&mut self, off: usize, v: u32) {
        self.b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn thunk(&mut self, off: usize, v: u64) {
        if self.is64 {
            self.b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            self.w32(off, v as u32);
        }
    }
    fn cstr(&mut self, s: &str, prefix: usize) -> usize {
        let at = self.alloc(prefix + s.len() + 1, 2);
        self.b[at + prefix..at + prefix + s.len()].copy_from_slice(s.as_bytes());
        at
    }
}

/// インポート表を仕様どおりに合成し、期待される ImportSite 列を返す。
fn build_imports(img: &mut Image, dlls: &[Dll]) -> Vec<ImportSite> {
    let thunk = if img.is64 { 8 } else { 4 };
    let flag: u64 = if img.is64 { 1 << 63 } else { 1 << 31 };
    let dir = img.alloc((dlls.len() + 1) * 20, 4);
    img.dir(1, dir as u32, ((dlls.len() + 1) * 20) as u32);
    let mut expected = Vec::new();
    for (i, dll) in dlls.iter().enumerate() {
        let desc = dir + i * 20;
        let name = img.cstr(&dll.name, 0);
        let iat = img.alloc((dll.funcs.len() + 1) * thunk, thunk);
        let ilt = if dll.with_ilt {
            img.alloc((dll.funcs.len() + 1) * thunk, thunk)
        } else {
            0
        };
        img.w32(desc, ilt as u32);
        img.w32(desc + 12, name as u32);
        img.w32(desc + 16, iat as u32);
        for (j, f) in dll.funcs.iter().enumerate() {
            let value = match f {
                Func::Named(n) => img.cstr(n, 2) as u64, // IMAGE_IMPORT_BY_NAME: Hint(2) + Name
                Func::Ordinal(o) => flag | *o as u64,
            };
            img.thunk(iat + j * thunk, value);
            if dll.with_ilt {
                img.thunk(ilt + j * thunk, value);
            }
            expected.push(ImportSite {
                dll_name: dll.name.clone(),
                func_name: match f {
                    Func::Named(n) => Some(n.clone()),
                    Func::Ordinal(_) => None,
                },
                ordinal: match f {
                    Func::Named(_) => None,
                    Func::Ordinal(o) => Some(*o),
                },
                iat_rva: (iat + j * thunk) as u32,
            });
        }
    }
    expected
}

/// エクスポート表を合成する。名前は重複しない (BTreeMap)、RVA は 0 でなく
/// エクスポートディレクトリの外にある直接アドレス。
fn build_exports(img: &mut Image, exports: &BTreeMap<String, u32>) {
    let n = exports.len();
    let dir = img.alloc(40, 4);
    img.dir(0, dir as u32, 40);
    let functions = img.alloc(n * 4, 4);
    let names = img.alloc(n * 4, 4);
    let ordinals = img.alloc(n * 2, 2);
    img.w32(dir + 24, n as u32);
    img.w32(dir + 28, functions as u32);
    img.w32(dir + 32, names as u32);
    img.w32(dir + 36, ordinals as u32);
    // 序数表で名前と関数を逆順に結び、名前の位置と関数の位置を独立させる。
    for (i, (name, rva)) in exports.iter().enumerate() {
        let ordinal = n - 1 - i;
        let s = img.cstr(name, 0);
        img.w32(names + i * 4, s as u32);
        img.b[ordinals + i * 2..ordinals + i * 2 + 2]
            .copy_from_slice(&(ordinal as u16).to_le_bytes());
        img.w32(functions + ordinal * 4, *rva);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn imports_match_model(is64 in any::<bool>(), dlls in prop::collection::vec(arb_dll(), 0..5)) {
        let mut img = Image::new(is64);
        let expected = build_imports(&mut img, &dlls);
        prop_assert_eq!(is_pe64(&img.b), Some(is64));
        prop_assert_eq!(parse_imports(&img.b), expected);
    }

    #[test]
    fn exports_match_model(
        is64 in any::<bool>(),
        exports in prop::collection::btree_map(ident(), 0x1_0000u32..IMAGE_LEN as u32, 0..12),
        probe in ident(),
    ) {
        let mut img = Image::new(is64);
        build_exports(&mut img, &exports);
        for (name, rva) in &exports {
            prop_assert_eq!(find_export(&img.b, name), Some(*rva));
        }
        prop_assert_eq!(find_export(&img.b, &probe), exports.get(&probe).copied());
    }

    /// 切り詰めたイメージでも panic せず、返す IAT はすべて切り詰め後の範囲内。
    #[test]
    fn truncated_images_stay_in_bounds(is64 in any::<bool>(), dlls in prop::collection::vec(arb_dll(), 1..4), cut in 0usize..0x6000) {
        let mut img = Image::new(is64);
        let expected = build_imports(&mut img, &dlls);
        let short = &img.b[..cut.min(img.b.len())];
        let got = parse_imports(short);
        let thunk = if is64 { 8 } else { 4 };
        for site in &got {
            prop_assert!(site.iat_rva as usize + thunk <= short.len());
        }
        // 読めた分は完全なイメージの結果の部分列 (捏造しない)。
        for site in &got {
            prop_assert!(expected.iter().any(|e| e.iat_rva == site.iat_rva && e.dll_name == site.dll_name));
        }
    }

    /// ファイル配置からメモリ配置への写像は、各セクションの生データを
    /// VirtualAddress へ min(raw, virtual) バイトだけ写し、残りは 0 のまま。
    #[test]
    fn file_mapping_places_sections(sections in prop::collection::vec((1usize..0x800, 0usize..0x900, any::<u8>()), 1..5)) {
        let header = 0x400usize;
        let mut file = Image::new(true).b[..header].to_vec();
        let coff = 0x84;
        file[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        let section_table = coff + 20 + 240;
        let mut va = 0x1000usize;
        let mut model = vec![0u8; 0];
        let mut placements = Vec::new();
        for (i, (raw, vsize, fill)) in sections.iter().enumerate() {
            let raw_ptr = file.len();
            file.extend((0..*raw).map(|k| fill.wrapping_add(k as u8)));
            let s = section_table + i * 40;
            file[s + 8..s + 12].copy_from_slice(&(*vsize as u32).to_le_bytes());
            file[s + 12..s + 16].copy_from_slice(&(va as u32).to_le_bytes());
            file[s + 16..s + 20].copy_from_slice(&(*raw as u32).to_le_bytes());
            file[s + 20..s + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
            placements.push((va, raw_ptr, if *vsize == 0 { *raw } else { (*raw).min(*vsize) }));
            va += 0x1000;
        }
        let size = va;
        let opt = coff + 20;
        file[opt + 56..opt + 60].copy_from_slice(&(size as u32).to_le_bytes());
        model.resize(size, 0);
        model[..header].copy_from_slice(&file[..header]);
        for (va, raw_ptr, copy) in &placements {
            model[*va..*va + copy].copy_from_slice(&file[*raw_ptr..*raw_ptr + copy]);
        }
        let image = map_file_to_image(&file).expect("valid file image");
        prop_assert_eq!(size_of_image(&file), Some(size as u32));
        prop_assert!(image == model);
    }
}
