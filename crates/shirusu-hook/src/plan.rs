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

/// 設置失敗時の巻き戻し結果（レビュー第5回 #8）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRollback<E> {
    /// 失敗したパッチのインデックス。
    pub failed_index: usize,
    /// パッチ失敗そのもののエラー。
    pub source: E,
    /// 復元も失敗したパッチ済みインデックス。空でなければ、対象
    /// プロセスにパッチが残存する（呼び出し側は重大な状態として
    /// 伝播させること）。
    pub unrestored: Vec<usize>,
}

/// パッチの列をトランザクションとして実行する順序制御
/// （プラットフォーム非依存。実際の IAT 書き換えは engine が担う）。
///
/// `patch(i)` は対象 i を書き換え、復元に必要な元値を返す。
/// いずれかの `patch` が失敗したら、パッチ済みの範囲を**逆順**に
/// `restore(i, 元値)` で戻す。復元に失敗したものは
/// [`PatchRollback::unrestored`] に残し、残りの復元は続ける。
/// 全部成功した場合だけ、元値の列を対象順で返す。
pub fn patch_transactionally<E>(
    count: usize,
    mut patch: impl FnMut(usize) -> Result<usize, E>,
    mut restore: impl FnMut(usize, usize) -> Result<(), E>,
) -> Result<Vec<usize>, PatchRollback<E>> {
    let mut originals: Vec<usize> = Vec::with_capacity(count);
    for i in 0..count {
        match patch(i) {
            Ok(original) => originals.push(original),
            Err(source) => {
                let mut unrestored = Vec::new();
                for j in (0..i).rev() {
                    if restore(j, originals[j]).is_err() {
                        unrestored.push(j);
                    }
                }
                return Err(PatchRollback {
                    failed_index: i,
                    source,
                    unrestored,
                });
            }
        }
    }
    Ok(originals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::*;
    use std::cell::RefCell;
    use std::rc::Rc;

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
    fn transactional_patch_all_succeeds_without_restore() {
        let restored: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let r2 = Rc::clone(&restored);
        let out: Result<Vec<usize>, PatchRollback<&str>> = patch_transactionally(
            3,
            |i| Ok(1000 + i),
            move |i, _orig| {
                r2.borrow_mut().push(i);
                Ok(())
            },
        );
        assert_eq!(out, Ok(vec![1000, 1001, 1002]));
        assert!(restored.borrow().is_empty(), "no restore on success");
    }

    #[test]
    fn transactional_patch_failure_rolls_back_in_reverse() {
        // レビュー第5回 #8: N 番目で失敗したら、それまでのパッチを
        // 逆順に復元してからエラーを返す。
        let restored: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let r2 = Rc::clone(&restored);
        let out: Result<Vec<usize>, PatchRollback<&str>> = patch_transactionally(
            4,
            |i| {
                if i == 2 {
                    Err("write failed")
                } else {
                    Ok(1000 + i)
                }
            },
            move |i, orig| {
                assert_eq!(orig, 1000 + i, "restore gets the saved original");
                r2.borrow_mut().push(i);
                Ok(())
            },
        );
        let rb = out.unwrap_err();
        assert_eq!(rb.failed_index, 2);
        assert_eq!(rb.source, "write failed");
        assert!(rb.unrestored.is_empty());
        assert_eq!(*restored.borrow(), vec![1, 0], "reverse order");
    }

    #[test]
    fn transactional_patch_failure_at_first_needs_no_rollback() {
        let out: Result<Vec<usize>, PatchRollback<&str>> =
            patch_transactionally(2, |_| Err("boom"), |_, _| Ok(()));
        let rb = out.unwrap_err();
        assert_eq!(rb.failed_index, 0);
        assert!(rb.unrestored.is_empty());
    }

    #[test]
    fn transactional_patch_rollback_failure_is_reported() {
        // 復元自体が失敗したスロットは unrestored に残り、
        // 残りの復元は続けられる。
        let restored: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let r2 = Rc::clone(&restored);
        let out: Result<Vec<usize>, PatchRollback<&str>> = patch_transactionally(
            4,
            |i| {
                if i == 3 {
                    Err("write failed")
                } else {
                    Ok(1000 + i)
                }
            },
            move |i, _orig| {
                r2.borrow_mut().push(i);
                if i == 1 {
                    Err("restore failed")
                } else {
                    Ok(())
                }
            },
        );
        let rb = out.unwrap_err();
        assert_eq!(rb.failed_index, 3);
        assert_eq!(rb.unrestored, vec![1]);
        assert_eq!(*restored.borrow(), vec![2, 1, 0], "all attempted, reverse");
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
