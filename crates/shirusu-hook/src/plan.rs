//! IAT フック計画。モジュールのインポート一覧（[`ImportSite`]）から、
//! 定義表に一致するものだけをパッチ対象として抽出する純粋な変換。
//! 実際に IAT を書き換える作業（engine、Windows）から分離し、計画の
//! 正しさを Linux で検証できるようにする。
//!
//! 計画に現れない API は、そのモジュール経由ではフックできない
//! （= Capture Coverage の欠落）として `missing` に残す。呼び出し側は
//! これを Trace の完全性情報へ写すための材料にする。

use crate::api::{api_by_import, ApiDef, API_TABLE};
use crate::pe::ImportSite;

/// パッチ 1 件分。`iat_rva` の位置にある関数ポインタを Detour へ
/// 差し替える（元の値は実行時に読み取って保存する）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    pub api: &'static ApiDef,
    pub dll_name: String,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookPlan {
    pub entries: Vec<PatchEntry>,
    /// このモジュールのインポートに現れず、フックできなかった API。
    /// 序数インポートは名前で照合できないため、対象関数の序数
    /// インポートもここに残る（正直な Coverage 欠落として扱う）。
    pub missing: Vec<&'static ApiDef>,
}

pub fn build_plan(sites: &[ImportSite]) -> HookPlan {
    let mut entries: Vec<PatchEntry> = Vec::new();
    let mut seen_iat = std::collections::HashSet::new();
    for site in sites {
        let Some(name) = &site.func_name else {
            continue; // 序数インポートは照合不能
        };
        let Some(api) = api_by_import(&site.dll_name, name) else {
            continue;
        };
        if !seen_iat.insert(site.iat_rva) {
            continue; // 同一スロットの重複は 1 件に
        }
        entries.push(PatchEntry {
            api,
            dll_name: site.dll_name.clone(),
            iat_rva: site.iat_rva,
        });
    }
    let hooked: std::collections::HashSet<u32> = entries.iter().map(|e| e.api.api_id).collect();
    let missing = API_TABLE
        .iter()
        .filter(|a| !hooked.contains(&a.api_id))
        .collect();
    HookPlan { entries, missing }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::*;

    fn site(dll: &str, func: Option<&str>, iat: u32) -> ImportSite {
        ImportSite {
            dll_name: dll.into(),
            func_name: func.map(str::to_string),
            ordinal: if func.is_none() { Some(7) } else { None },
            iat_rva: iat,
        }
    }

    #[test]
    fn plan_matches_table_apis_only() {
        let sites = vec![
            site("kernel32.dll", Some("CreateFileW"), 0x100),
            site("KERNEL32.DLL", Some("ReadFile"), 0x108),
            site("kernel32.dll", Some("CreateFileA"), 0x110), // 対象外 (A 版)
            site("user32.dll", Some("CreateFileW"), 0x118),   // DLL 不一致
            site("kernel32.dll", None, 0x120),                // 序数は照合不能
            site("kernel32.dll", Some("WriteFile"), 0x128),
        ];
        let plan = build_plan(&sites);
        let got: Vec<u32> = plan.entries.iter().map(|e| e.api.api_id).collect();
        assert_eq!(got, vec![API_CREATE_FILE_W, API_READ_FILE, API_WRITE_FILE]);
        // CloseHandle はこのモジュール経由でフックできない = Coverage 欠落
        assert_eq!(plan.missing.len(), 1);
        assert_eq!(plan.missing[0].api_id, API_CLOSE_HANDLE);
    }

    #[test]
    fn plan_dedups_same_slot_and_empty_input() {
        let sites = vec![
            site("kernel32.dll", Some("CloseHandle"), 0x200),
            site("kernel32.dll", Some("CloseHandle"), 0x200),
        ];
        let plan = build_plan(&sites);
        assert_eq!(plan.entries.len(), 1);
        let empty = build_plan(&[]);
        assert!(empty.entries.is_empty());
        assert_eq!(empty.missing.len(), API_TABLE.len());
    }
}
