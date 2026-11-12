//! shirusu-probe バイナリのカバレッジ gap テスト（2026-11-12 計測分）。
//!
//! `tests/cli.rs` では到達しない分岐が対象：`--name` / `--candidate`
//! の値欠落・非数値・範囲外、`--help`、未知オプション、`--json`、
//! ブリーフのみバンドル（終了コード 3）。
//!
//! 到達しない行（2026-11-12 18:29 時点）：bin の 110 行目
//! （`build_bundle` の `map_err`。NoSuchCandidate は CLI 側で
//! 範囲検査済み、SpecRoundtrip は生成規則が識別することを
//! generate_rules 内で保証済み、トリムはメモリ内 Writer のため
//! I/O・Trace エラーが起きない）と 133-134 行目
//! （`trim_reproduced == Some(false)` と `None` の表示。
//! build_bundle は常に Some を詰め、トリムは候補の証跡を
//! 必ず残すため、どちらも正直な fixture では到達しない）。

use shirusu_emit::{file_io_api_set, Emitter, EventMeta, PayloadData, SessionConfig};
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

/// CloseHandle まで記録するかだけが違う、最小の 2 呼び出し Trace。
fn trace(close: bool) -> Vec<u8> {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "cli-test"),
    )
    .unwrap();
    let create = em
        .begin_call(
            1,
            "kernel32!CreateFileW",
            &[
                cv(TypedValue::Str16("x".encode_utf16().collect())),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::U32(3)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
            ],
            1,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        create,
        &[cv(TypedValue::U64(0x10)), cv(TypedValue::U32(0))],
        2,
        EventMeta::default(),
    )
    .unwrap();
    if close {
        let c = em
            .begin_call(
                1,
                "kernel32!CloseHandle",
                &[cv(TypedValue::U64(0x10))],
                3,
                EventMeta::default(),
            )
            .unwrap();
        em.end_call(
            c,
            &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            4,
            EventMeta::default(),
        )
        .unwrap();
    }
    em.finish(FinalizationInfo::default()).unwrap()
}

/// 引数・戻り値は一致し、ReadFile の Payload（Blob）内容だけが違う
/// ペアを作る。scenario.rs の `record_with_payload` と同型で、
/// 候補は PayloadDifference 1 件だけになり、v1 ルールでは識別
/// できないためバンドルはブリーフのみになる。
fn payload_pair() -> (Vec<u8>, Vec<u8>) {
    let build = |read_payload: &[u8]| {
        let mut em = Emitter::new(
            Vec::new(),
            file_io_api_set(),
            SessionConfig::new(100, "scenario-emitter 1.0"),
        )
        .unwrap();
        let mut ts = 0u64;
        let mut tick = move || {
            ts += 100;
            ts
        };
        let create = em
            .begin_call(
                1,
                "kernel32!CreateFileW",
                &[
                    cv(str16("save.dat")),
                    cv(TypedValue::U32(0x8000_0000)),
                    cv(TypedValue::U32(0)),
                    cv(TypedValue::U64(0)),
                    cv(TypedValue::U32(3)),
                    cv(TypedValue::U32(0)),
                    cv(TypedValue::U64(0)),
                ],
                tick(),
                EventMeta::default(),
            )
            .unwrap();
        em.end_call(
            create,
            &[cv(TypedValue::U64(0x100)), cv(TypedValue::U32(0))],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
        let read = em
            .begin_call(
                1,
                "kernel32!ReadFile",
                &[
                    cv(TypedValue::U64(0x100)),
                    cv(TypedValue::U64(0x5000)),
                    cv(TypedValue::U32(4)),
                ],
                tick(),
                EventMeta::default(),
            )
            .unwrap();
        em.end_call(
            read,
            &[
                cv(TypedValue::I32(1)),
                cv(TypedValue::U32(4)),
                cv(TypedValue::Bytes(b"DATA".to_vec())),
                cv(TypedValue::U32(0)),
            ],
            tick(),
            EventMeta::with_payload(PayloadData::Blob(read_payload.to_vec())),
        )
        .unwrap();
        let close = em
            .begin_call(
                1,
                "kernel32!CloseHandle",
                &[cv(TypedValue::U64(0x100))],
                tick(),
                EventMeta::default(),
            )
            .unwrap();
        em.end_call(
            close,
            &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
        em.finish(FinalizationInfo::default()).unwrap()
    };
    (build(b"DATA"), build(b"DATB"))
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-probe-coverage-gaps-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shirusu-probe")
}

/// 識別ルールの付く差分配列（CloseHandle の有無だけが違う）。
fn discriminating_pair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let left = dir.join("left.trace");
    let right = dir.join("right.trace");
    std::fs::write(&left, trace(true)).unwrap();
    std::fs::write(&right, trace(false)).unwrap();
    (left, right)
}

#[test]
fn cli_name_option_names_the_bundle() {
    let dir = tmp_dir("name");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--name")
        .arg("custom-name")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest = std::fs::read_to_string(out_dir.join("manifest.json")).unwrap();
    assert!(manifest.contains("\"name\": \"custom-name\""), "{manifest}");
    assert!(out_dir.join("rules.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_name_and_candidate_options_need_values() {
    let dir = tmp_dir("needs-value");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");

    // --name の値欠落。
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--name")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // --candidate の値欠落。
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--candidate")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // --candidate の非数値。
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--candidate")
        .arg("abc")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--candidate must be a number: abc"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_candidate_out_of_range_exits_two() {
    let dir = tmp_dir("out-of-range");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--candidate")
        .arg("9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("out of range"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_help_and_unknown_option() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-probe"));

    let dir = tmp_dir("unknown");
    let (left, right) = discriminating_pair(&dir);
    let out = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--bogus")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_json_prints_manifest() {
    let dir = tmp_dir("json");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("shirusu-probe-bundle"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_out_option_and_right_load_errors() {
    let dir = tmp_dir("out-and-right-errors");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");
    let garbage = dir.join("garbage.trace");
    std::fs::write(&garbage, b"not a trace at all").unwrap();

    // --out の値欠落。
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // --out 自体の欠落（位置引数は 2 個揃っている）。
    let output = Command::new(bin()).arg(&left).arg(&right).output().unwrap();
    assert_eq!(output.status.code(), Some(2));

    // 右側が存在しないファイル（終了コード 2）。
    let output = Command::new(bin())
        .arg(&left)
        .arg(dir.join("missing.trace"))
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // 右側が読めない内容（終了コード 1）。
    let output = Command::new(bin())
        .arg(&left)
        .arg(&garbage)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_load_errors() {
    let dir = tmp_dir("load-errors");
    let (left, right) = discriminating_pair(&dir);
    let out_dir = dir.join("bundle");
    let garbage = dir.join("garbage.trace");
    std::fs::write(&garbage, b"not a trace at all").unwrap();

    // 存在しないファイルは読み取り失敗（終了コード 2）。
    let output = Command::new(bin())
        .arg(dir.join("missing.trace"))
        .arg(&right)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // 読めない内容のファイルも失敗（終了コード 1）。
    let output = Command::new(bin())
        .arg(&garbage)
        .arg(&left)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_write_bundle_failure() {
    let dir = tmp_dir("write-failure");
    let (left, right) = discriminating_pair(&dir);
    // 出力先の親がファイルだとディレクトリを作れない。
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"x").unwrap();
    let output = Command::new(bin())
        .arg(&left)
        .arg(&right)
        .arg("--out")
        .arg(blocker.join("bundle"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_brief_only_bundle_exits_three() {
    let dir = tmp_dir("brief-only");
    let left_path = dir.join("left.trace");
    let right_path = dir.join("right.trace");
    let (left_bytes, right_bytes) = payload_pair();
    std::fs::write(&left_path, left_bytes).unwrap();
    std::fs::write(&right_path, right_bytes).unwrap();
    let out_dir = dir.join("bundle");
    let output = Command::new(bin())
        .arg(&left_path)
        .arg(&right_path)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("discriminating rule: NO"), "{stdout}");
    assert!(
        stdout.contains("trimmed pair reproduces the candidate: yes"),
        "{stdout}"
    );
    assert!(out_dir.join("manifest.json").exists());
    assert!(out_dir.join("brief.md").exists());
    assert!(!out_dir.join("rules.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
