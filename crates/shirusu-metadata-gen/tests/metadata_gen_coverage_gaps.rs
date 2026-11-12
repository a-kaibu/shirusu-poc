//! metadata-gen のカバレッジ gap テスト（2026-11-12 17:29 回）。
//!
//! 2026-11-12 16:29 回の全ワークスペース llvm-cov 計測で、lib.rs は
//! 456/487 行だった。`has_count` フィルタで数え直すと完全未実行は
//! 31 行で、ここではそのうち到達可能なものを覆う。残りは実 winmd
//! に実例が無く、到達不能として記録する（下記）。
//!
//! 到達不能として残す行（実 winmd 18,364 件の Apis メソッドを走査
//! して確認。走査は一時プローブで行い、結果のみここに記録する）：
//! - lib.rs 254 (HASTHIS スキップ): Apis メソッドに HASTHIS は 0 件。
//! - lib.rs 263 (ImplMap 無しスキップ): ImplMap を持たない Apis
//!   メソッドは 0 件。
//! - lib.rs 286 (引数名と引数型の個数不一致): 実例なし。防御的検査。
//! - lib.rs 405 (enum に value__ が無い): winmd の全 enum が持つ。
//! - lib.rs 410-412 (enum の基底型が非整数): winmd の enum の基底型
//!   は全て整数。防御的検査。
//! - lib.rs 473 (COM/クラス/インターフェイス型): Apis の引数・戻り値
//!   は値渡しでは現れない（ポインタ経由のみ）。防御的検査。
//! - lib.rs 867/871-872 (`generate_seed_from_real_winmd` のスキップ腕):
//!   winmd が無い環境でのみ通る。CI では fetch-winmd.sh が先に取得
//!   するため、通常は通らない。
//!
//! winmd が要るテストは、取得済みの winmd が無い環境では飛ばす
//! （CI では fetch-winmd.sh が事前に取得する）。

use shirusu_metadata_gen::{
    emit_api_inc, generate, load_config, map_type, ApiConfig, Config, EntryOutcome, Generated,
    MappedApi,
};
use shirusu_trace::schema::{LastErrorMeaning, Ty, ValueKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_metadata::reader::TypeIndex;
use windows_metadata::{Type, TypeName};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

fn winmd_path() -> PathBuf {
    repo_root().join("target/winmd/Windows.Win32.winmd")
}

/// 取得済みの winmd が無ければテストを飛ばす。
macro_rules! require_winmd {
    () => {
        if !winmd_path().exists() {
            eprintln!("skip: winmd が無い（fetch-winmd.sh で取得する）");
            return;
        }
    };
}

fn read_index() -> TypeIndex {
    TypeIndex::read(winmd_path()).expect("winmd を読める")
}

/// テスト用の一時ディレクトリ（終了時に削除する）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("shirusu-meta-gen-gap-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn empty_index() -> TypeIndex {
    TypeIndex::new(vec![])
}

fn api(namespace: &str, module: &str, function: &str) -> ApiConfig {
    ApiConfig {
        namespace: namespace.to_string(),
        module: module.to_string(),
        function: function.to_string(),
        last_error: None,
    }
}

fn config_with(apis: Vec<ApiConfig>, max_params: usize) -> Config {
    Config {
        first_api_id: 7,
        reserved_api_ids: vec![],
        max_params,
        winmd_version: "71.0.45-preview".to_string(),
        apis,
        skips: vec![],
    }
}

/// 生成結果が 1 件のスキップで、その理由が期待する文言を含むこと。
fn assert_single_skip(generated: &Generated, module: &str, function: &str, reason_part: &str) {
    let skipped = generated.skipped();
    assert_eq!(skipped.len(), 1, "スキップは 1 件のはず: {skipped:?}");
    let (m, f, reason) = skipped[0];
    assert_eq!(m, module);
    assert_eq!(f, function);
    assert!(
        reason.contains(reason_part),
        "スキップ理由に {reason_part:?} を含むはず: {reason}"
    );
}

#[test]
fn load_config_defaults_max_params_when_missing() {
    // lib.rs 55-57: `default_max_params` は max_params 欄の無い設定で
    // serde の既定として呼ばれる。
    let dir = TempDir::new();
    let path = dir.path().join("apis.toml");
    std::fs::write(
        &path,
        "first_api_id = 7\nwinmd_version = \"71.0.45-preview\"\n",
    )
    .expect("設定を書く");
    let config = load_config(path.to_str().unwrap()).expect("設定を読める");
    assert_eq!(config.max_params, 12);
    assert_eq!(config.first_api_id, 7);
    assert!(config.apis.is_empty());
}

#[test]
fn load_config_rejects_invalid_toml() {
    // lib.rs 178: TOML の解析失敗。
    let dir = TempDir::new();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "first_api_id = [\n").expect("設定を書く");
    let err = load_config(path.to_str().unwrap()).expect_err("解析に失敗するはず");
    assert!(err.contains("解析に失敗"), "err: {err}");
}

#[test]
fn generate_rejects_empty_api_list() {
    // lib.rs 187: 生成対象 0 件。
    let err = generate(&empty_index(), &config_with(vec![], 12)).expect_err("0 件は誤り");
    assert!(err.contains("0 件"), "err: {err}");
}

#[test]
fn generate_rejects_duplicate_api() {
    // lib.rs 198: 同じ module!function の重複。1 件目は生成に成功
    // するため実 winmd が要る（空の index では 1 件目の map_api で
    // 先に失敗する）。重複検査は各反復の map_api より先に行われる。
    require_winmd!();
    let index = read_index();
    let dup = api(
        "Windows.Win32.System.Registry",
        "advapi32.dll",
        "RegCloseKey",
    );
    let err = generate(&index, &config_with(vec![dup.clone(), dup], 12)).expect_err("重複は誤り");
    assert!(err.contains("重複"), "err: {err}");
}

#[test]
fn generate_reports_missing_apis_class() {
    // lib.rs 204 (`?` による map_api 誤りの伝播) と 230 (Apis クラス無し)。
    let err = generate(
        &empty_index(),
        &config_with(
            vec![api(
                "Windows.Win32.System.Registry",
                "advapi32.dll",
                "RegCloseKey",
            )],
            12,
        ),
    )
    .expect_err("空の index では Apis クラスが無い");
    assert!(err.contains("Apis クラスが無い"), "err: {err}");
}

#[test]
fn generate_reports_missing_function() {
    // lib.rs 234: 名前空間はあるが関数が存在しない。
    require_winmd!();
    let index = read_index();
    let err = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.System.Registry",
                "advapi32.dll",
                "NoSuchFunctionXYZ",
            )],
            12,
        ),
    )
    .expect_err("存在しない関数は誤り");
    assert!(err.contains("存在しない"), "err: {err}");
}

#[test]
fn generate_reports_overloaded_function() {
    // lib.rs 242: 同名の重載が複数ある (JsCreateContext は
    // Windows.Win32.System.Js に 2 件ある)。
    require_winmd!();
    let index = read_index();
    let err = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.System.Js",
                "chakra.dll",
                "JsCreateContext",
            )],
            12,
        ),
    )
    .expect_err("重載は決められない");
    assert!(err.contains("重載"), "err: {err}");
}

#[test]
fn generate_skips_vararg_api() {
    // lib.rs 249: 可変長引数。VARARG 検査は ImplMap より先なので
    // module は到達しないが、実在の DLL を書いておく。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.System.DeploymentServices",
                "WDSCLIENTAPI.dll",
                "WdsCliLog",
            )],
            12,
        ),
    )
    .expect("生成できる");
    assert_single_skip(&generated, "WDSCLIENTAPI.dll", "WdsCliLog", "可変長引数");
}

#[test]
fn generate_skips_non_system_calling_convention() {
    // lib.rs 257: 呼出規約が system ではない (ldap_openW は C)。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.Networking.Ldap",
                "WLDAP32.dll",
                "ldap_openW",
            )],
            12,
        ),
    )
    .expect("生成できる");
    assert_single_skip(
        &generated,
        "WLDAP32.dll",
        "ldap_openW",
        "呼出規約が system ではない",
    );
}

#[test]
fn generate_skips_import_name_mismatch() {
    // lib.rs 266: エクスポート名が関数名と異なる (RtlGenRandom は
    // SystemFunction036 としてエクスポートされる)。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.Security.Authentication.Identity",
                "ADVAPI32.dll",
                "RtlGenRandom",
            )],
            12,
        ),
    )
    .expect("生成できる");
    assert_single_skip(
        &generated,
        "ADVAPI32.dll",
        "RtlGenRandom",
        "エクスポート名が SystemFunction036 と異なる",
    );
}

#[test]
fn generate_rejects_dll_mismatch() {
    // lib.rs 273: ImplMap の DLL と設定の module が一致しない。
    require_winmd!();
    let index = read_index();
    let err = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.System.Registry",
                "kernel32.dll",
                "RegCloseKey",
            )],
            12,
        ),
    )
    .expect_err("DLL 不一致は誤り");
    assert!(err.contains("ImplMap DLL"), "err: {err}");
}

#[test]
fn generate_skips_too_many_params() {
    // lib.rs 295: 引数が上限を超える (CreateProcessW は 10 引数)。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.System.Threading",
                "kernel32.dll",
                "CreateProcessW",
            )],
            2,
        ),
    )
    .expect("生成できる");
    assert_single_skip(
        &generated,
        "kernel32.dll",
        "CreateProcessW",
        "上限 2 を超える",
    );
}

#[test]
fn generate_skips_struct_by_value_arg() {
    // lib.rs 312-313 (引数の写像失敗をスキップへ) と 444 (複数
    // フィールドの値渡し構造体)。WindowFromPoint は POINT (2 フィー
    // ルド) を値渡しで取る。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.UI.WindowsAndMessaging",
                "USER32.dll",
                "WindowFromPoint",
            )],
            12,
        ),
    )
    .expect("生成できる");
    assert_single_skip(&generated, "USER32.dll", "WindowFromPoint", "値渡し構造体");
    assert!(
        generated.skipped()[0].2.contains("2 フィールド"),
        "理由: {}",
        generated.skipped()[0].2
    );
}

#[test]
fn generate_preserves_float_return() {
    // lib.rs 329: 戻り値の写像失敗をスキップへ。
    // D2D1ComputeMaximumScaleFactor は引数がポインタ 1 個だけで
    // 通り、戻り値 F32 で落ちる (cc=system)。
    require_winmd!();
    let index = read_index();
    let generated = generate(
        &index,
        &config_with(
            vec![api(
                "Windows.Win32.Graphics.Direct2D",
                "d2d1.dll",
                "D2D1ComputeMaximumScaleFactor",
            )],
            12,
        ),
    )
    .expect("生成できる");
    assert!(generated.skipped().is_empty());
    assert_eq!(generated.emitted()[0].abi_return, "f32");
}

#[test]
fn generate_rejects_bad_last_error() {
    // lib.rs 334: last_error の指定が不正。Sleep は void 戻りで
    // 引数も通るため、ここまで届く。
    require_winmd!();
    let index = read_index();
    let mut sleep = api("Windows.Win32.System.Threading", "kernel32.dll", "Sleep");
    sleep.last_error = Some("bogus".to_string());
    let err = generate(&index, &config_with(vec![sleep], 12)).expect_err("不正な指定は誤り");
    assert!(err.contains("last_error が不正"), "err: {err}");
}

#[test]
fn map_type_maps_array_ref_and_rejects_attribute_enum() {
    // lib.rs 382: ArrayRef はポインタ。386: 属性用 enum は対象外。
    let idx = empty_index();
    let m = map_type(&idx, &Type::ArrayRef(Box::new(Type::U8))).expect("ArrayRef は写せる");
    assert_eq!(m.ty, Ty::U64);
    assert_eq!(m.kind, ValueKind::Pointer);
    assert!(map_type(&idx, &Type::AttributeEnum).is_err());
}

#[test]
fn map_type_rejects_generic_named_type() {
    // lib.rs 394: ジェネリックな名前付き型は対象外。
    let idx = empty_index();
    let tn = TypeName {
        namespace: "Windows.Win32.Foundation".to_string(),
        name: "HANDLE".to_string(),
        generics: vec![Type::U32],
    };
    let err = map_type(&idx, &Type::Name(tn)).expect_err("ジェネリックは対象外");
    assert!(err.contains("ジェネリックな名前付き型"), "err: {err}");
}

#[test]
fn emit_api_inc_escapes_quotes_and_backslashes() {
    // lib.rs 535-536: rust_str の `"` と `\` のエスケープ。
    let api = MappedApi {
        api_id: 7,
        module: "we\"ird.dll".into(),
        function: "Na\\me".into(),
        abi_params: vec![],
        abi_return: "()",
        enter_fields: vec![],
        return_ty: None,
        last_error_meaning: LastErrorMeaning::Never,
    };
    let generated = Generated {
        entries: vec![EntryOutcome::Emitted(api)],
        intentional_skips: vec![],
    };
    let text = emit_api_inc(&generated, "71.0.45-preview");
    assert!(text.contains("module: \"we\\\"ird.dll\","), "text: {text}");
    assert!(text.contains("function: \"Na\\\\me\","), "text: {text}");
}

#[test]
fn reserved_ids_preserve_handwritten_api_identity() {
    require_winmd!();
    let mut config = config_with(
        vec![
            api("Windows.Win32.System.Threading", "kernel32.dll", "Sleep"),
            api(
                "Windows.Win32.System.SystemInformation",
                "kernel32.dll",
                "GetTickCount64",
            ),
        ],
        12,
    );
    config.first_api_id = 78;
    config.reserved_api_ids = (79..=85).collect();
    let generated = generate(&read_index(), &config).unwrap();
    assert_eq!(
        generated
            .emitted()
            .iter()
            .map(|a| a.api_id)
            .collect::<Vec<_>>(),
        vec![78, 86]
    );
}
