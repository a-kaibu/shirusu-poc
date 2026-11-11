//! 静的依存情報の収集（L13、overview「観測レベル L0〜L4」節）。
//!
//! 起動対象の exe ファイルの PE インポートテーブルを読み、
//! （DLL、関数）の静的依存の列を作る。収集は `shirusu capture` の
//! 起動対象に対してだけ行い、結果は `CaptureEnvironment` の
//! `static_dependencies`（field 10）に載せる。`attach` では対象 exe
//! のパスを解決しないため収集しない（L23 の範囲）。
//!
//! 読めない入力（存在しない・PE でない・壊れている）では空を返す。
//! 静的依存は診断情報であり、読めないことが capture 自体を失敗させ
//! てはならない。遅延ロード・インポートは含まない（形式は
//! `shirusu_trace::static_dep` の境界を参照）。

use shirusu_hook::pe::{self, ImportSite};
use shirusu_trace::static_dep::{StaticDependency, StaticImport};
use std::path::Path;

/// `ImportSite` の列を DLL ごとにまとめる。DLL は初出順、関数は
/// テーブルに現れた順を保つ（決定的）。同じ DLL が複数のディスクリプタ
/// に分かれている場合は 1 件にまとめる（名前の一致は大文字小文字を
/// 区別する。リンカが吐く表記は 1 通りのため）。
pub fn group_import_sites(sites: &[ImportSite]) -> Vec<StaticDependency> {
    let mut deps: Vec<StaticDependency> = Vec::new();
    for site in sites {
        let dep = match deps.iter_mut().find(|d| d.module == site.dll_name) {
            Some(d) => d,
            None => {
                deps.push(StaticDependency {
                    module: site.dll_name.clone(),
                    imports: Vec::new(),
                });
                deps.last_mut().expect("just pushed")
            }
        };
        dep.imports.push(StaticImport {
            name: site.func_name.clone(),
            ordinal: site.ordinal,
        });
    }
    deps
}

/// exe ファイルの PE インポートテーブルから静的依存を読む。
/// 読めない場合は空を返す（失敗を capture に波及させない）。
pub fn static_dependencies_for_exe(path: &Path) -> Vec<StaticDependency> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Some(image) = pe::map_file_to_image(&bytes) else {
        return Vec::new();
    };
    group_import_sites(&pe::parse_imports(&image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn site(dll: &str, name: Option<&str>, ordinal: Option<u16>) -> ImportSite {
        ImportSite {
            dll_name: dll.to_string(),
            func_name: name.map(str::to_string),
            ordinal,
            iat_rva: 0,
        }
    }

    #[test]
    fn groups_import_sites_by_dll_preserving_order() {
        let sites = vec![
            site("kernel32.dll", Some("CreateFileW"), None),
            site("kernel32.dll", None, Some(42)),
            site("user32.dll", Some("MessageBoxW"), None),
            site("kernel32.dll", Some("CloseHandle"), None),
        ];
        let deps = group_import_sites(&sites);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].module, "kernel32.dll");
        assert_eq!(deps[0].imports.len(), 3);
        assert_eq!(deps[0].imports[0].name.as_deref(), Some("CreateFileW"));
        assert_eq!(deps[0].imports[1].ordinal, Some(42));
        assert_eq!(deps[0].imports[2].name.as_deref(), Some("CloseHandle"));
        assert_eq!(deps[1].module, "user32.dll");
        assert_eq!(deps[1].imports.len(), 1);
    }

    #[test]
    fn empty_sites_give_no_dependencies() {
        assert!(group_import_sites(&[]).is_empty());
    }

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

    /// インポートディレクトリを持つ最小の PE32+ **ファイル**を合成する。
    /// ヘッダー 0x200 バイト＋セクション 1 個（VA 0x1000、生データは
    /// ファイル 0x200 から、大きさ 0x200）。インポート表は kernel32.dll
    /// の 2 件（CreateFileW と序数 42）。表の要素はすべてセクション内
    /// （イメージ 0x1000..0x1200）に収める。
    fn synthetic_pe_file() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        w32(&mut b, 0x3C, 0x80); // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        w16(&mut b, coff + 2, 1); // 1 section
        w16(&mut b, coff + 16, 240); // size of optional header
        let opt = coff + 20;
        w16(&mut b, opt, 0x20B); // PE32+
        w32(&mut b, opt + 56, 0x2000); // SizeOfImage
        w32(&mut b, opt + 60, 0x200); // SizeOfHeaders
                                      // import directory (index 1) at RVA 0x1000
        w32(&mut b, opt + 112 + 8, 0x1000);
        w32(&mut b, opt + 112 + 12, 40);
        // section header: VA 0x1000, raw at 0x200, size 0x200
        let sec = opt + 240;
        w32(&mut b, sec + 8, 0x200); // VirtualSize
        w32(&mut b, sec + 12, 0x1000); // VirtualAddress
        w32(&mut b, sec + 16, 0x200); // SizeOfRawData
        w32(&mut b, sec + 20, 0x200); // PointerToRawData
                                      // section contents (image 0x1000 == file 0x200)
        let s = |off: usize| 0x200 + (off - 0x1000);
        // descriptor 0: OFT=0x1030, Name=0x1060, FT=0x1050
        w32(&mut b, s(0x1000), 0x1030);
        w32(&mut b, s(0x1000) + 12, 0x1060);
        w32(&mut b, s(0x1000) + 16, 0x1050);
        // ILT at 0x1030: CreateFileW @0x1070, ordinal 42, end
        w64(&mut b, s(0x1030), 0x1070);
        w64(&mut b, s(0x1038), 0x8000_0000_0000_0000 | 42);
        w64(&mut b, s(0x1040), 0);
        wstr(&mut b, s(0x1060), "kernel32.dll");
        w16(&mut b, s(0x1070), 0); // hint
        wstr(&mut b, s(0x1072), "CreateFileW");
        b
    }

    fn write_temp_pe(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("shirusu-l13-{name}-{}.exe", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        drop(f);
        path
    }

    #[test]
    fn static_dependencies_for_exe_reads_synthetic_pe_file() {
        let path = write_temp_pe("synthetic", &synthetic_pe_file());
        let deps = static_dependencies_for_exe(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].module, "kernel32.dll");
        assert_eq!(deps[0].imports.len(), 2);
        assert_eq!(deps[0].imports[0].name.as_deref(), Some("CreateFileW"));
        assert_eq!(deps[0].imports[1].ordinal, Some(42));
    }

    #[test]
    fn static_dependencies_for_exe_missing_file_is_empty() {
        let path = std::env::temp_dir().join("shirusu-l13-no-such-file.exe");
        assert!(static_dependencies_for_exe(&path).is_empty());
    }

    #[test]
    fn static_dependencies_for_exe_non_pe_is_empty() {
        let path = write_temp_pe("text", b"this is not a PE file");
        let deps = static_dependencies_for_exe(&path);
        let _ = std::fs::remove_file(&path);
        assert!(deps.is_empty());
    }

    #[test]
    fn static_dependencies_for_exe_truncated_pe_is_empty() {
        let path = write_temp_pe("truncated", b"MZ");
        let deps = static_dependencies_for_exe(&path);
        let _ = std::fs::remove_file(&path);
        assert!(deps.is_empty());
    }
}
