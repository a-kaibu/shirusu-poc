//! JSON Runner の統合テスト（ライブラリ＋CLI）。
//!
//! 実行そのものは Windows でしかできないため、Linux では dry-run と
//! 計画の誤り・CLI の終了コードを検証する。Windows での実実行は
//! `scripts/ci/probe-l20.ps1`（CI）で確かめる。

use shirusu_test::json_parse::parse_json;
use shirusu_test::{run_spec, RunMode, TestSpec};
use std::process::Command;

fn sample_spec_path() -> String {
    format!(
        "{}/tests/data/probe-sample.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn sample_spec() -> TestSpec {
    let text = std::fs::read_to_string(sample_spec_path()).unwrap();
    TestSpec::parse(&text).unwrap()
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shirusu-test")
}

#[test]
fn dry_run_sample_spec() {
    let spec = sample_spec();
    assert_eq!(spec.name, "probe-sample");
    assert_eq!(spec.steps.len(), 8);
    let report = run_spec(&spec, RunMode::DryRun).unwrap();
    assert!(!report.executed);
    assert!(report.all_ok);
    assert_eq!(report.outcomes.len(), 8);
    assert_eq!(report.outcomes[0].call, "kernel32!CreateFileW");
    assert_eq!(report.outcomes[5].call, "kernel32!ReadFile");
    assert_eq!(report.outcomes[7].call, "kernel32!DeleteFileW");
}

#[test]
fn cli_run_dry_run_exits_zero() {
    let out = Command::new(bin())
        .args(["run", &sample_spec_path(), "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry-run"));
    assert!(stdout.contains("CreateFileW"));
}

#[test]
fn cli_run_dry_run_json_is_parseable() {
    let out = Command::new(bin())
        .args(["run", &sample_spec_path(), "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let value = parse_json(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let rendered = value.render();
    assert!(rendered.contains("\"executed\":false"));
    assert!(rendered.contains("\"all_ok\":true"));
}

#[test]
#[cfg(not(windows))]
fn cli_run_without_dry_run_needs_windows_on_linux() {
    // Linux では実行できない。終了コード 2 と、Windows が必要だという
    // 誤りになること。Windows ではこのテストは存在しない（実実行は
    // `scripts/ci/probe-l20.ps1` で確かめる）。
    let out = Command::new(bin())
        .args(["run", &sample_spec_path()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires Windows"));
}

#[test]
fn cli_run_rejects_bad_spec() {
    let dir = std::env::temp_dir().join(format!("shirusu-test-runner-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.json");
    std::fs::write(
        &bad,
        r#"{"version":1,"name":"bad","steps":[{"call":"kernel32!NoSuchApi","args":{}}],"rules":[]}"#,
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["run", bad.to_str().unwrap(), "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown call"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn schema_file_parses_and_covers_steps() {
    // overview の決定「JSON Schema も公開する」。Schema 自体が JSON
    // として読め、steps / rules の両方を定義していること。
    let path = format!(
        "{}/../../docs/test-spec-schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap();
    let value = parse_json(&text).unwrap();
    let rendered = value.render();
    assert!(rendered.contains("\"steps\""));
    assert!(rendered.contains("\"rules\""));
    assert!(rendered.contains("\"buffer\""));
    assert!(rendered.contains("\"out\""));
    assert!(rendered.contains("\"ref\""));
}
