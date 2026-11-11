//! L23: Host 側のモジュール列挙と分類。
//!
//! capture 開始時に対象プロセスのロード済みモジュールを列挙し、署名を
//! 確認して分類し、Trace の `CaptureEnvironment.modules` へ載せる。
//! 呼び出し側は次の 3 段を使う：
//!
//! 1. `merge_module_snapshots`: 起動直後の列挙（注入直後・再開前）と
//!    再開後の安定化待ち列挙を合成する（起動対象が再開直後に終了して
//!    しまった場合でも、注入直後の分は残る）。
//! 2. `classify_loaded_modules`: 列挙結果を `ModuleEvidence`（署名
//!    確認・API Set 解決付き）へ変換し、分類する。純粋関数で、Linux
//!    でもテストできる。
//! 3. `merge_environment_modules`: CLI が作った既存の
//!    `environment.modules`（起動対象 exe の分類と `--module-class` の
//!    未使用エントリ）と列挙で得た分類を合成する。CLI の上書きは残し、
//!    それ以外の既存エントリは列挙の新しい証拠（署名確認済み）で
//!    置き換える。
//!
//! 列挙そのものは `shirusu_transport_win::modules`（Windows 側）が担う。
//! Windows 以外では列挙できず、既存の `environment.modules` をそのまま
//! 使う（CLI の exe 分類のみ）。

use shirusu_trace::module::{
    classify_module, is_api_set_contract, ModuleClassification, ModuleEvidence,
};
use shirusu_transport_win::modules::LoadedModule;
use std::collections::HashMap;

/// ファイル名部分だけを抜く（`classify_module` と同じ規則）。
fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// 列挙したモジュールを分類する。`resolve_api_set` は API Set 契約名を
/// 実装モジュールへ解決する関数（`shirusu_transport_win::modules::
/// resolve_api_set_contract`）。`verify_signature` はパスごとの Microsoft
/// 署名の確認結果を返す関数（`None` = 未確認）。署名確認は呼び出し側で
/// パス単位にキャッシュすること（`WinVerifyTrust` はファイル I/O と
/// 暗号処理を伴い、モジュールごとに 1 回で十分なため）。
pub fn classify_loaded_modules(
    modules: &[LoadedModule],
    resolve_api_set: &dyn Fn(&str) -> Option<String>,
    verify_signature: &mut dyn FnMut(&str) -> Option<bool>,
) -> Vec<ModuleClassification> {
    modules
        .iter()
        .map(|m| {
            let mut evidence = ModuleEvidence::new(&m.path);
            let implementation = if is_api_set_contract(&m.path) {
                resolve_api_set(&m.path)
            } else {
                None
            };
            if let Some(impl_path) = &implementation {
                evidence = evidence.implementation(impl_path);
            }
            // 署名は実装モジュール（契約の場合は解決先）のファイルで確認
            // する。契約名自体はファイルではないため、そのまま確認すると
            // 必ず false になり、解決先が署名付きでも Unknown になる。
            // 分類器はこの証拠を実装モジュールの分類へ引き継ぐ。
            let verify_path = implementation.as_deref().unwrap_or(&m.path);
            if let Some(signed) = verify_signature(verify_path) {
                evidence = evidence.signed(signed);
            }
            classify_module(&evidence)
        })
        .collect()
}

/// CLI が作った既存の `environment.modules` と、列挙で得た分類を合成する。
/// - ファイル名が一致する既存エントリが CLI の上書き（`overridden`）なら
///   そちらを残す（ユーザーの指定が優先）。
/// - 上書きでない既存エントリは、列挙の新しい証拠（署名確認済み）で
///   置き換える。
/// - 列挙に無かった既存エントリ（未ロードモジュールへの上書き等）は
///   末尾へ残す（黙って消えないようにする。L07 と同じ扱い）。
pub fn merge_environment_modules(
    existing: Vec<ModuleClassification>,
    enumerated: Vec<ModuleClassification>,
) -> Vec<ModuleClassification> {
    let mut used = vec![false; existing.len()];
    let mut out: Vec<ModuleClassification> = Vec::with_capacity(enumerated.len() + existing.len());
    for e in enumerated {
        let file = file_name_of(&e.module_name).to_ascii_lowercase();
        let matched = existing
            .iter()
            .position(|x| file_name_of(&x.module_name).to_ascii_lowercase() == file);
        match matched {
            Some(i) if existing[i].overridden => {
                used[i] = true;
                out.push(existing[i].clone());
            }
            Some(i) => {
                used[i] = true;
                out.push(e);
            }
            None => out.push(e),
        }
    }
    for (i, x) in existing.iter().enumerate() {
        if !used[i] {
            out.push(x.clone());
        }
    }
    out
}

/// 2 回のスナップショットを合成する。パス（大文字小文字を区別しない）で
/// 突き合わせ、重複は後（`later`）のものを採用する（再ロードでベースが
/// 変わった場合は新しい方が正しい）。返値はベースアドレスの昇順。
pub fn merge_module_snapshots(
    earlier: Vec<LoadedModule>,
    later: Vec<LoadedModule>,
) -> Vec<LoadedModule> {
    let mut by_path: HashMap<String, LoadedModule> = HashMap::new();
    for m in earlier {
        by_path.entry(m.path.to_ascii_lowercase()).or_insert(m);
    }
    for m in later {
        by_path.insert(m.path.to_ascii_lowercase(), m);
    }
    let mut out: Vec<LoadedModule> = by_path.into_values().collect();
    out.sort_by_key(|m| m.base_address);
    out
}

/// 対象プロセスのモジュールを列挙して分類する。列挙に失敗した場合は
/// 空を返す（capture を失敗させない。呼び出し側は CLI の
/// `environment.modules` をそのまま使う）。
pub fn enumerate_and_classify_modules(pid: u32) -> Vec<ModuleClassification> {
    let modules = enumerate_modules_for_process(pid);
    classify_module_list(&modules)
}

/// 対象プロセスのモジュールを列挙する（失敗時は空）。
pub fn enumerate_modules_for_process(pid: u32) -> Vec<LoadedModule> {
    shirusu_transport_win::modules::enumerate_modules(pid).unwrap_or_default()
}

/// モジュールの一覧を分類する（署名確認付き）。署名確認はパス単位に
/// 1 回だけ行う。Windows 以外では署名確認は常に未確認（`None` 相当）
/// になるため、System32 のモジュールは Unknown になる。
pub fn classify_module_list(modules: &[LoadedModule]) -> Vec<ModuleClassification> {
    use shirusu_transport_win::modules as winmod;
    let mut cache: HashMap<String, Option<bool>> = HashMap::new();
    classify_loaded_modules(
        modules,
        &|name| winmod::resolve_api_set_contract(name),
        &mut |path: &str| {
            *cache
                .entry(path.to_string())
                .or_insert_with(|| Some(winmod::verify_microsoft_signature(path)))
        },
    )
}

/// 安定化待ち付きの列挙（Windows）。起動直後のようにモジュールが増えて
/// いる間は 10ms ごとに列挙し直し、2 回連続で同じ一覧（パス集合）に
/// なったら返す。最大 200ms。プロセスが終了して列挙できなくなった
/// 場合は最後に得られた一覧を返す（1 回も得られなければ空）。
#[cfg(windows)]
pub fn enumerate_modules_settled(pid: u32) -> Vec<LoadedModule> {
    use shirusu_transport_win::modules as winmod;
    use std::time::{Duration, Instant};
    let mut last: Vec<LoadedModule> = Vec::new();
    let mut last_paths: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(200);
    loop {
        match winmod::enumerate_modules(pid) {
            Ok(modules) => {
                let paths = snapshot_paths(&modules);
                if paths == last_paths && !last.is_empty() {
                    return modules;
                }
                last_paths = paths;
                last = modules;
            }
            Err(_) => {
                if !last.is_empty() {
                    return last;
                }
                // 1 回も取れていない場合は少し待って再試行する
                // （起動直後のプロセスがまだ開けない場合がある）。
            }
        }
        if Instant::now() >= deadline {
            return last;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn snapshot_paths(modules: &[LoadedModule]) -> Vec<String> {
    let mut paths: Vec<String> = modules
        .iter()
        .map(|m| m.path.to_ascii_lowercase())
        .collect();
    paths.sort();
    paths
}

/// Windows 以外では安定化待ち列挙はできない（空を返す）。
#[cfg(not(windows))]
pub fn enumerate_modules_settled(_pid: u32) -> Vec<LoadedModule> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::module::ModuleClass;

    fn no_resolve(_name: &str) -> Option<String> {
        None
    }

    fn no_verify(_path: &str) -> Option<bool> {
        None
    }

    fn signed_verify(path: &str) -> Option<bool> {
        // テスト用の署名確認：System32 配下だけ署名付きとする。
        Some(path.to_ascii_lowercase().contains("system32"))
    }

    #[test]
    fn classify_loaded_modules_uses_signature_and_names() {
        let modules = vec![
            LoadedModule::new(0x1000, 0x1000, r"C:\Windows\System32\kernel32.dll"),
            LoadedModule::new(0x2000, 0x1000, r"C:\Windows\System32\ucrtbase.dll"),
            LoadedModule::new(0x3000, 0x1000, r"C:\tools\app\game.exe"),
            LoadedModule::new(0x4000, 0x1000, r"C:\Windows\System32\weird.dll"),
        ];
        let mut verify = |p: &str| signed_verify(p);
        let list = classify_loaded_modules(&modules, &no_resolve, &mut verify);
        assert_eq!(list.len(), 4);
        assert_eq!(list[0].class, ModuleClass::Windows);
        assert!(!list[0].uncertain);
        assert_eq!(list[1].class, ModuleClass::Runtime);
        assert_eq!(list[2].class, ModuleClass::Application);
        // 署名付きだが既知の分類に当たらない System32 モジュールは Windows。
        assert_eq!(list[3].class, ModuleClass::Windows);
    }

    #[test]
    fn classify_loaded_modules_without_signature_is_unknown() {
        let modules = vec![LoadedModule::new(
            0x1000,
            0x1000,
            r"C:\Windows\System32\kernel32.dll",
        )];
        let list = classify_loaded_modules(&modules, &no_resolve, &mut no_verify);
        assert_eq!(list[0].class, ModuleClass::Unknown);
        assert!(list[0].uncertain);
    }

    #[test]
    fn classify_loaded_modules_resolves_api_set_contract() {
        let modules = vec![LoadedModule::new(
            0x1000,
            0x1000,
            "api-ms-win-core-file-l1-1-0.dll",
        )];
        let mut verify = |p: &str| signed_verify(p);
        // 解決先が System32＋署名付きなら Windows になる。
        let list = classify_loaded_modules(
            &modules,
            &|_| Some(r"C:\Windows\System32\kernel32.dll".to_string()),
            &mut verify,
        );
        assert_eq!(list[0].class, ModuleClass::Windows);
        assert_eq!(
            list[0].implementation_module.as_deref(),
            Some(r"C:\Windows\System32\kernel32.dll")
        );
        // 解決できなければ Unknown。
        let list = classify_loaded_modules(&modules, &no_resolve, &mut verify);
        assert_eq!(list[0].class, ModuleClass::Unknown);
        assert!(list[0].uncertain);
    }

    #[test]
    fn merge_environment_modules_prefers_cli_overrides() {
        use shirusu_trace::module::{classify_module, ModuleEvidence};
        // 既存：exe（上書き済み）と未使用の上書きエントリ。
        let mut existing = vec![classify_module(&ModuleEvidence::new(
            r"C:\tools\app\game.exe",
        ))];
        existing[0].class = ModuleClass::Windows;
        existing[0].overridden = true;
        existing[0].reason = "CLI override".to_string();
        existing.push(ModuleClassification {
            module_name: "not-loaded.dll".into(),
            class: ModuleClass::Runtime,
            reason: "CLI override (module not loaded at capture start)".into(),
            uncertain: false,
            implementation_module: None,
            overridden: true,
        });
        // 列挙：exe（署名なしのため Application 相当の新しい証拠）と
        // kernel32（Windows）。
        let enumerated = vec![
            classify_module(&ModuleEvidence::new(r"C:\tools\app\game.exe")),
            classify_module(&ModuleEvidence::new(r"C:\Windows\System32\kernel32.dll").signed(true)),
        ];
        let merged = merge_environment_modules(existing, enumerated);
        assert_eq!(merged.len(), 3);
        // exe は CLI の上書き（Windows）が残る。
        assert_eq!(merged[0].module_name, r"C:\tools\app\game.exe");
        assert_eq!(merged[0].class, ModuleClass::Windows);
        assert!(merged[0].overridden);
        // kernel32 は列挙の分類（Windows）。
        assert_eq!(merged[1].class, ModuleClass::Windows);
        assert!(!merged[1].overridden);
        // 未使用の上書きエントリは末尾へ残る。
        assert_eq!(merged[2].module_name, "not-loaded.dll");
        assert!(merged[2].overridden);
    }

    #[test]
    fn merge_environment_modules_replaces_non_overridden_with_fresh_evidence() {
        use shirusu_trace::module::{classify_module, ModuleEvidence};
        // 既存の exe エントリ（上書きなし・署名未確認のため Unknown）。
        let existing = vec![classify_module(&ModuleEvidence::new(
            r"C:\Windows\System32\game.exe",
        ))];
        assert_eq!(existing[0].class, ModuleClass::Unknown);
        // 列挙の exe エントリ（署名確認済みのため Windows）。
        let enumerated = vec![classify_module(
            &ModuleEvidence::new(r"C:\Windows\System32\game.exe").signed(true),
        )];
        let merged = merge_environment_modules(existing, enumerated);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].class, ModuleClass::Windows);
        assert!(!merged[0].overridden);
    }

    #[test]
    fn merge_module_snapshots_unions_and_later_wins() {
        let earlier = vec![
            LoadedModule::new(0x1000, 0x1000, r"C:\Windows\System32\kernel32.dll"),
            LoadedModule::new(0x2000, 0x1000, r"C:\tools\app\game.exe"),
        ];
        let later = vec![
            // kernel32 が再ロードでベースが変わったとする。
            LoadedModule::new(0x5000, 0x1000, r"C:\WINDOWS\System32\KERNEL32.DLL"),
            LoadedModule::new(0x3000, 0x1000, r"C:\Windows\System32\user32.dll"),
        ];
        let merged = merge_module_snapshots(earlier, later);
        assert_eq!(merged.len(), 3);
        // 後勝ち：kernel32 は later のベース。
        let k = merged
            .iter()
            .find(|m| m.path.to_ascii_lowercase().contains("kernel32"))
            .unwrap();
        assert_eq!(k.base_address, 0x5000);
        // ベースアドレスの昇順。
        assert!(merged
            .windows(2)
            .all(|w| w[0].base_address <= w[1].base_address));
    }

    /// Windows での実働テスト。CI の windows.ps1（`cargo test
    /// --workspace`）で実行される。
    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn enumerate_and_classify_own_process() {
            let pid = std::process::id();
            let list = enumerate_and_classify_modules(pid);
            assert!(!list.is_empty(), "own process has modules");
            let by_file = |name: &str| {
                list.iter()
                    .find(|m| file_name_of(&m.module_name).eq_ignore_ascii_case(name))
            };
            // kernel32.dll は Windows（署名確認済み）。
            let k = by_file("kernel32.dll").expect("kernel32 listed");
            assert_eq!(k.class, ModuleClass::Windows, "{}", k.reason);
            assert!(!k.uncertain, "{}", k.reason);
            assert!(k.reason.contains("Microsoft"), "{}", k.reason);
            // 実行ファイル自身は Application。
            let exe = std::env::current_exe().expect("current exe");
            let exe_name = exe.file_name().expect("exe name").to_string_lossy();
            let e = by_file(&exe_name).expect("self listed");
            assert_eq!(e.class, ModuleClass::Application);
            // ucrtbase.dll がロードされていれば Runtime。
            if let Some(u) = by_file("ucrtbase.dll") {
                assert_eq!(u.class, ModuleClass::Runtime);
            }
        }

        #[test]
        fn enumerate_modules_settled_returns_stable_snapshot() {
            let pid = std::process::id();
            let modules = enumerate_modules_settled(pid);
            assert!(!modules.is_empty());
            assert!(modules
                .iter()
                .any(|m| m.path.to_ascii_lowercase().ends_with("kernel32.dll")));
        }
    }
}
