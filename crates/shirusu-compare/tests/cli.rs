//! shirusu-compare バイナリの統合テスト（終了コードと出力形式）。

mod common;

use common::{Builder, Env};
use shirusu_trace::writer::FinalizationInfo;
use std::process::Command;

fn pair_bytes() -> (Vec<u8>, Vec<u8>) {
    let mut l = Builder::new(Env::default());
    l.create_file(1, 0, "a.dat");
    l.read_file(2, 0, 4, 4, &[1, 2, 3, 4], true, 0);
    l.close_handle(3, 0);
    let left = l.finish_bytes(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.create_file(1, 0, "a.dat");
    r.read_file(2, 0, 4, 0, &[], false, 5);
    r.close_handle(3, 0);
    let right = r.finish_bytes(FinalizationInfo::default(), &[]);
    (left, right)
}

#[test]
fn compare_cli_exit_codes_and_json() {
    let dir = std::env::temp_dir().join(format!("shirusu-compare-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = pair_bytes();
    let lp = dir.join("left.trace");
    let rp = dir.join("right.trace");
    std::fs::write(&lp, &left).unwrap();
    std::fs::write(&rp, &right).unwrap();
    let bin = env!("CARGO_BIN_EXE_shirusu-compare");
    let lps = lp.to_str().unwrap();
    let rps = rp.to_str().unwrap();

    // 同一ファイル同士: 候補なし、終了コード 0、留保文つき。
    let out = Command::new(bin).args([lps, lps]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("candidates: 0"), "{stdout}");
    assert!(stdout.contains("note:"), "{stdout}");

    // 読み取り失敗側との比較: 候補あり、終了コード 1。
    let out = Command::new(bin).args([lps, rps]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("return-difference"), "{stdout}");

    // JSON: notice と候補の構造。
    let out = Command::new(bin)
        .args([lps, rps, "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"notice\""), "{stdout}");
    assert!(
        stdout.contains("\"kind\": \"return-difference\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"severity\": \"high\""), "{stdout}");

    // 使い方の誤り: 終了コード 2。
    let out = Command::new(bin).args([lps]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn compare_cli_output_option_writes_file() {
    let dir =
        std::env::temp_dir().join(format!("shirusu-compare-cli-output-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = pair_bytes();
    let lp = dir.join("left.trace");
    let rp = dir.join("right.trace");
    std::fs::write(&lp, &left).unwrap();
    std::fs::write(&rp, &right).unwrap();
    let bin = env!("CARGO_BIN_EXE_shirusu-compare");
    let lps = lp.to_str().unwrap();
    let rps = rp.to_str().unwrap();

    // 候補ありのペア: --output に書いて終了コード 1。
    let out_path = dir.join("report.txt");
    let out = Command::new(bin)
        .args([lps, rps, "--output", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("return-difference"), "{written}");
    assert!(out.stdout.is_empty(), "output goes to the file, not stdout");

    // 候補なしのペア: --output に書いて終了コード 0。
    let out_path2 = dir.join("report-same.txt");
    let out = Command::new(bin)
        .args([lps, lps, "--output", out_path2.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let written = std::fs::read_to_string(&out_path2).unwrap();
    assert!(written.contains("candidates: 0"), "{written}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compare_cli_output_option_needs_value() {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-compare-cli-output-missing-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = pair_bytes();
    let lp = dir.join("left.trace");
    let rp = dir.join("right.trace");
    std::fs::write(&lp, &left).unwrap();
    std::fs::write(&rp, &right).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-compare"))
        .args([lp.to_str().unwrap(), rp.to_str().unwrap(), "--output"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--output needs a value"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compare_cli_output_write_failure() {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-compare-cli-output-fail-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = pair_bytes();
    let lp = dir.join("left.trace");
    let rp = dir.join("right.trace");
    std::fs::write(&lp, &left).unwrap();
    std::fs::write(&rp, &right).unwrap();
    // 出力先がディレクトリだと書き込めない（終了コード 1）。
    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-compare"))
        .args([
            lp.to_str().unwrap(),
            rp.to_str().unwrap(),
            "--output",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compare_cli_load_errors() {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-compare-cli-load-errors-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = pair_bytes();
    let lp = dir.join("left.trace");
    let rp = dir.join("right.trace");
    std::fs::write(&lp, &left).unwrap();
    std::fs::write(&rp, &right).unwrap();
    let garbage = dir.join("garbage.trace");
    std::fs::write(&garbage, b"not a trace at all").unwrap();
    let bin = env!("CARGO_BIN_EXE_shirusu-compare");

    // 存在しないファイルは読み取り失敗（終了コード 1）。
    let out = Command::new(bin)
        .args([
            dir.join("missing.trace").to_str().unwrap(),
            rp.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // 右側が存在しないファイルも失敗（終了コード 1）。
    let out = Command::new(bin)
        .args([
            lp.to_str().unwrap(),
            dir.join("missing.trace").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // 読めない内容のファイルも終了コード 1。
    let out = Command::new(bin)
        .args([garbage.to_str().unwrap(), rp.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compare_cli_help_and_unknown_option() {
    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-compare"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-compare"));

    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-compare"))
        .args(["--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
