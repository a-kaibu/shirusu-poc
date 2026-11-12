//! win32-metadata-gen バイナリの CLI 呼び出しテスト（main.rs）。
//!
//! main.rs はバイナリ全体がテストから一度も起動されておらず、
//! カバレッジ初測定（2026-11-12）で行 0% だった。実際のバイナリを
//! 起動して引数処理・`--check`・生成を固定する。winmd が必要な
//! テストは、取得済みの winmd が無い環境では飛ばす（CI では
//! fetch-winmd.sh が事前に取得する）。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// テスト対象のバイナリ。解決順序：
/// 1. `CARGO_BIN_EXE_win32_metadata_gen`（Cargo が設定する場合）
/// 2. 実行中のテストバイナリと同じ `<target-dir>/debug/` 直下
///    （`current_exe()` は `<target-dir>/debug/deps/cli-<hash>`）。
///    llvm-cov 実行時（`target/llvm-cov-target` 配下）も同じ配置に
///    なるため、計測対象のバイナリが子プロセスとして走り、main.rs
///    のカバレッジが付く。
/// 3. 既定の target dir の直下（最後のフォールバック）。
///
/// なお `env!("CARGO_BIN_EXE_win32_metadata_gen")` はこのパッケージ
/// （lib＋bin の両方を持つ）ではコンパイル時に設定されず、実行時も
/// 未設定だった（`cargo test` で確認）。bin 専用の shirusu-cli では
/// `env!` が通るのと対照的である。
fn bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_win32_metadata_gen") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(debug) = exe.parent().and_then(|p| p.parent()) {
            for name in ["win32-metadata-gen", "win32-metadata-gen.exe"] {
                let candidate = debug.join(name);
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    repo_root().join("target/debug/win32-metadata-gen")
}

/// リポジトリルート（`CARGO_MANIFEST_DIR` は
/// `crates/shirusu-metadata-gen`）。
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

fn config_path() -> PathBuf {
    repo_root().join("crates/shirusu-metadata-gen/apis.toml")
}

fn hook_src_dir() -> PathBuf {
    repo_root().join("crates/shirusu-hook/src")
}

/// 取得済みの winmd が無ければテストを飛ばす。winmd が要る
/// テストの先頭で呼ぶ。
macro_rules! require_winmd {
    () => {
        if !winmd_path().exists() {
            eprintln!("skip: winmd が無い（fetch-winmd.sh で取得する）");
            return;
        }
    };
}

/// テスト用の一時ディレクトリ（終了時に削除する）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("shirusu-meta-gen-test-{}-{n}", std::process::id()));
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

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("win32-metadata-gen を起動する")
}

/// 環境変数を差し替えて起動する（`SHIRUSU_WINMD` の既定値確認用）。
fn run_env(args: &[&str], set: &[(&str, &str)], remove: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in set {
        cmd.env(k, v);
    }
    for k in remove {
        cmd.env_remove(k);
    }
    cmd.output().expect("win32-metadata-gen を起動する")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn check_passes_when_generated_files_are_current() {
    require_winmd!();
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        hook_src_dir().to_str().unwrap(),
        "--check",
    ]);
    assert!(
        out.status.success(),
        "check が失敗した: stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("ok: "), "stdout: {}", stdout(&out));
}

#[test]
fn check_fails_when_out_dir_has_no_generated_files() {
    require_winmd!();
    let dir = TempDir::new();
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        dir.path().to_str().unwrap(),
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("DIFF: "), "stdout: {}", stdout(&out));
}

#[test]
fn check_fails_when_a_generated_file_differs() {
    require_winmd!();
    let dir = TempDir::new();
    // api だけ中身の違うファイルを置く（engine は無し）。
    std::fs::write(dir.path().join("api_generated.inc"), "// stale\n").expect("stale file");
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        dir.path().to_str().unwrap(),
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("異なる"), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("DIFF: "), "stdout: {}", stdout(&out));
}

#[test]
fn generate_writes_files_identical_to_checked_in() {
    require_winmd!();
    let dir = TempDir::new();
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        dir.path().to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "生成が失敗した: stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("wrote "), "stdout: {}", stdout(&out));
    for name in ["api_generated.inc", "engine_generated.inc"] {
        let generated = std::fs::read_to_string(dir.path().join(name)).expect("生成物を読む");
        let checked_in = std::fs::read_to_string(hook_src_dir().join(name)).expect("既存物を読む");
        assert_eq!(
            generated, checked_in,
            "{name} がチェックイン済みの内容と違う"
        );
    }
}

#[test]
fn unknown_flag_exits_2() {
    let out = run(&["--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("usage: "), "stderr: {}", stderr(&out));
}

#[test]
fn missing_value_for_winmd_exits_2() {
    let out = run(&["--winmd"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("usage: "), "stderr: {}", stderr(&out));
}

#[test]
fn missing_winmd_file_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path().join("no-such.winmd");
    let out = run(&[
        "--winmd",
        missing.to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("読めない"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn missing_config_exits_1() {
    let dir = TempDir::new();
    let missing = dir.path().join("no-such.toml");
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        missing.to_str().unwrap(),
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("読めない"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn missing_value_for_config_exits_2() {
    // main.rs 39: `--config` の値無しは usage で終了 2。
    let out = run(&["--config"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("usage: "), "stderr: {}", stderr(&out));
}

#[test]
fn missing_value_for_out_dir_exits_2() {
    // main.rs 40: `--out-dir` の値無しは usage で終了 2。
    let out = run(&["--out-dir"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("usage: "), "stderr: {}", stderr(&out));
}

#[test]
fn winmd_env_var_is_used_when_flag_absent() {
    // main.rs 46: `--winmd` が無ければ `SHIRUSU_WINMD` を使う。
    require_winmd!();
    let out = run_env(
        &[
            "--config",
            config_path().to_str().unwrap(),
            "--out-dir",
            hook_src_dir().to_str().unwrap(),
            "--check",
        ],
        &[("SHIRUSU_WINMD", winmd_path().to_str().unwrap())],
        &[],
    );
    assert!(
        out.status.success(),
        "環境変数からの winmd で check が通るはず: stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("ok: "), "stdout: {}", stdout(&out));
}

#[test]
fn winmd_default_path_is_used_when_flag_and_env_absent() {
    // main.rs 47: フラグも環境変数も無ければ既定パスを使う。テスト
    // の cwd（パッケージ dir）にはそのパスが無いため読めず終了 1。
    let out = run_env(
        &["--config", config_path().to_str().unwrap(), "--check"],
        &[],
        &["SHIRUSU_WINMD"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("読めない"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn generate_error_exits_1() {
    // main.rs 58: 生成の誤り（対象 API 0 件）は `?` で終了 1 になる。
    require_winmd!();
    let dir = TempDir::new();
    let config = dir.path().join("empty.toml");
    std::fs::write(
        &config,
        "first_api_id = 7\nwinmd_version = \"71.0.45-preview\"\n",
    )
    .expect("設定を書く");
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--check",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("0 件"), "stderr: {}", stderr(&out));
}

#[test]
fn write_error_for_api_inc_exits_1() {
    // main.rs 84: 出力先がファイルだと api_generated.inc を書けない。
    require_winmd!();
    let dir = TempDir::new();
    let not_a_dir = dir.path().join("not-a-dir");
    std::fs::write(&not_a_dir, "x").expect("ファイルを置く");
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        not_a_dir.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("書けない"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn write_error_for_engine_inc_exits_1() {
    // main.rs 86: api は書けるが engine_generated.inc がディレクトリ
    // だと engine 側で書けない。
    require_winmd!();
    let dir = TempDir::new();
    std::fs::create_dir(dir.path().join("engine_generated.inc")).expect("同名ディレクトリ");
    let out = run(&[
        "--winmd",
        winmd_path().to_str().unwrap(),
        "--config",
        config_path().to_str().unwrap(),
        "--out-dir",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("engine_generated.inc"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("書けない"),
        "stderr: {}",
        stderr(&out)
    );
    // api 側は書けていること。
    assert!(dir.path().join("api_generated.inc").exists());
}

#[test]
fn inventory_audits_unselected_apis_without_rewriting_wrappers() {
    require_winmd!();
    let path = std::env::temp_dir().join(format!("shirusu-inventory-{}.tsv", std::process::id()));
    let winmd = winmd_path();
    let config = config_path();
    let args = [
        "--winmd",
        winmd.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ];
    let result = Command::new(bin())
        .args(args)
        .arg("--inventory")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let content = std::fs::read_to_string(&path).unwrap();
    let rows: Vec<_> = content
        .lines()
        .skip(1)
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .collect();
    assert!(rows.len() > 10_000);
    assert!(rows.iter().all(|r| r.len() == 5));
    assert!(rows
        .iter()
        .any(|r| r[2] == "ldap_openW" && r[3] == "selected"));
    assert!(rows.iter().any(|r| r[3] == "generatable"));
    assert!(rows
        .iter()
        .any(|r| r[3] == "unsupported" && !r[4].is_empty()));
    let result = Command::new(bin())
        .args(args)
        .arg("--inventory")
        .arg(&path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(result.status.success());
    std::fs::write(&path, "stale").unwrap();
    let result = Command::new(bin())
        .args(args)
        .arg("--inventory")
        .arg(&path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(!result.status.success());
    std::fs::remove_file(path).unwrap();
}
