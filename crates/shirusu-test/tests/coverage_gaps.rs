//! shirusu-test バイナリのカバレッジ gap テスト（2026-11-12 計測分）。
//!
//! 既存の cli.rs / golden.rs / prereq.rs / runner.rs / probe_exe.rs
//! では到達しない分岐が対象：従来形の `--help`・未知オプション・
//! 引数個数違い、`golden` のサブコマンド無し・`--help`・未知
//! サブコマンド・record の引数個数違い・`--name` の重複・
//! `--os-build` の非数値と正常値・record の note 表示・check /
//! fresh の未知オプションと引数個数違い・fresh の `--json`、
//! `run` / `probe-exe` / `prereq` の `--help`・未知オプション・
//! 引数個数違い。
//!
//! 到達しない行（2026-11-12 18:29 時点）：bin の 317 行目
//! （`generate_probe_main_rs` の `map_err`。同関数は文字列を
//! 組み立てるだけで常に Ok を返すため、エラー腕が実行されない）。

use shirusu_test::golden::Golden;
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};
use std::process::Command;

/// CreateFileW → CloseHandle の最小 Trace。`close` が false の
/// 場合は CloseHandle を記録せず、Golden 導出で object-closed
/// ルールが note 付きで省かれる（未終了オブジェクト）。
fn trace_bytes_with_close(close: bool) -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 1,
            created_by: "cli".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![("lpFileName".into(), Ty::Str16, 0)],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![("return".into(), Ty::U64, 0)],
        ),
        make_schema(
            7,
            "kernel32!CloseHandle/enter",
            vec![("hObject".into(), Ty::U64, 0)],
        ),
        make_schema(
            8,
            "kernel32!CloseHandle/leave",
            vec![("return".into(), Ty::I32, 0)],
        ),
    ] {
        w.register_schema(def).unwrap();
    }
    let ev =
        |kind: u16, seq: u64, api: u32, schema: u32, types: &[Ty], values: Vec<CapturedValue>| {
            TraceEvent {
                kind,
                sequence: seq,
                timestamp_qpc: seq * 10,
                call_id: 1,
                parent_call_id: 0,
                api_id: api,
                schema_id: schema,
                capture: EventCapture::Captured,
                payload: PayloadRef::None,
                args: Some(encode_values(types, &values).unwrap()),
                global_order: None,
            }
        };
    let mut events = vec![
        ev(
            1,
            1,
            1,
            1,
            &[Ty::Str16],
            vec![CapturedValue::captured(TypedValue::Str16(
                "x".encode_utf16().collect(),
            ))],
        ),
        ev(
            2,
            2,
            1,
            2,
            &[Ty::U64],
            vec![CapturedValue::captured(TypedValue::U64(0x100))],
        ),
    ];
    if close {
        events.push(ev(
            1,
            3,
            4,
            7,
            &[Ty::U64],
            vec![CapturedValue::captured(TypedValue::U64(0x100))],
        ));
        events.push(ev(
            2,
            4,
            4,
            8,
            &[Ty::I32],
            vec![CapturedValue::captured(TypedValue::I32(1))],
        ));
    }
    w.write_batch(&EventBatch {
        session_id: 1,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events,
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shirusu-test")
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-test-coverage-gaps-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 参照 Trace・候補 Trace・仕様ファイルを置いた作業ディレクトリ。
/// 戻り値は (dir, trace, spec)。
fn fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = tmp_dir(tag);
    let trace = dir.join("t.trace");
    std::fs::write(&trace, trace_bytes_with_close(true)).unwrap();
    let spec = dir.join("pass.json");
    std::fs::write(
        &spec,
        r#"{"name":"p","rules":[
            {"type":"api-called","api":"kernel32!CreateFileW"},
            {"type":"object-closed","created_by":"kernel32!CreateFileW"},
            {"type":"no-integrity-loss"}
        ]}"#,
    )
    .unwrap();
    (dir, trace, spec)
}

#[test]
fn cli_legacy_help_unknown_option_and_arg_count() {
    let (dir, trace, spec) = fixture("legacy");
    let tp = trace.to_str().unwrap();
    let sp = spec.to_str().unwrap();

    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-test"));

    // 未知オプションは終了コード 2。
    let out = Command::new(bin())
        .args([tp, sp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 位置引数が 1 個・3 個の場合も終了コード 2。
    let out = Command::new(bin()).args([tp]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .args([tp, sp, "extra"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_dispatch_errors() {
    let (dir, trace, _spec) = fixture("golden-dispatch");
    let tp = trace.to_str().unwrap();

    // サブコマンド無し。
    let out = Command::new(bin()).arg("golden").output().unwrap();
    assert_eq!(out.status.code(), Some(2));

    // golden --help。
    let out = Command::new(bin())
        .args(["golden", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-test"));

    // 未知サブコマンド。
    let out = Command::new(bin())
        .args(["golden", "bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // record の引数個数違い（参照 1 個だけ）。
    let out = Command::new(bin())
        .args(["golden", "record", tp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_record_duplicate_flag_and_bad_os_build() {
    let (dir, trace, _spec) = fixture("golden-record-flags");
    let tp = trace.to_str().unwrap();
    let gold = dir.join("golden.json");
    let gp = gold.to_str().unwrap();

    // --name の重複。
    let out = Command::new(bin())
        .args(["golden", "record", tp, gp, "--name", "a", "--name", "b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--name is given twice"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // --os-build の非数値。
    let out = Command::new(bin())
        .args(["golden", "record", tp, gp, "--os-build", "abc"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--os-build needs an integer"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_record_os_build_and_notes() {
    let dir = tmp_dir("golden-record-notes");
    // 未終了オブジェクトの参照：object-closed が note 付きで省かれる。
    let reference = dir.join("ref.trace");
    std::fs::write(&reference, trace_bytes_with_close(false)).unwrap();
    let gold = dir.join("golden.json");
    let out = Command::new(bin())
        .args([
            "golden",
            "record",
            reference.to_str().unwrap(),
            gold.to_str().unwrap(),
            "--os-build",
            "26100",
            "--os-version",
            "Windows 11",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("note:"), "{stdout}");
    let saved = std::fs::read_to_string(&gold).unwrap();
    let golden = Golden::parse(&saved).unwrap();
    assert_eq!(golden.environment.os_build, Some(26100));
    assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 11"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_check_and_fresh_arg_errors() {
    let (dir, trace, _spec) = fixture("golden-arg-errors");
    let tp = trace.to_str().unwrap();
    let gold = dir.join("golden.json");
    let gp = gold.to_str().unwrap();

    // check の未知オプション・引数個数違い。
    let out = Command::new(bin())
        .args(["golden", "check", tp, gp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .args(["golden", "check", tp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // fresh の未知オプション・引数個数違い。
    let out = Command::new(bin())
        .args(["golden", "fresh", tp, tp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .args(["golden", "fresh", tp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_legacy_load_errors() {
    let (dir, trace, spec) = fixture("legacy-load-errors");
    let tp = trace.to_str().unwrap();
    let sp = spec.to_str().unwrap();
    let garbage = dir.join("garbage.trace");
    std::fs::write(&garbage, b"not a trace at all").unwrap();

    // 存在しない仕様ファイルは終了コード 2。
    let out = Command::new(bin())
        .args([tp, dir.join("missing.json").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 存在しない Trace は終了コード 1。
    let out = Command::new(bin())
        .args([dir.join("missing.trace").to_str().unwrap(), sp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // 読めない内容の Trace も終了コード 1。
    let out = Command::new(bin())
        .args([garbage.to_str().unwrap(), sp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_record_load_and_write_errors() {
    let dir = tmp_dir("golden-record-errors");
    let reference = dir.join("ref.trace");
    std::fs::write(&reference, trace_bytes_with_close(true)).unwrap();
    let garbage = dir.join("garbage.trace");
    std::fs::write(&garbage, b"not a trace at all").unwrap();
    let gold = dir.join("golden.json");

    // 読めない内容の参照 Trace は終了コード 2。
    let out = Command::new(bin())
        .args([
            "golden",
            "record",
            garbage.to_str().unwrap(),
            gold.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 書き込み先のディレクトリが無ければ終了コード 2。
    let out = Command::new(bin())
        .args([
            "golden",
            "record",
            reference.to_str().unwrap(),
            dir.join("no-such-dir")
                .join("golden.json")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_check_golden_load_errors() {
    let dir = tmp_dir("golden-check-errors");
    let trace = dir.join("t.trace");
    std::fs::write(&trace, trace_bytes_with_close(true)).unwrap();
    let tp = trace.to_str().unwrap();

    // 存在しない Golden は終了コード 2。
    let out = Command::new(bin())
        .args([
            "golden",
            "check",
            tp,
            dir.join("missing.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // Golden でない JSON も終了コード 2。
    let not_golden = dir.join("not-golden.json");
    std::fs::write(&not_golden, r#"{"rules":[{"type":"no-integrity-loss"}]}"#).unwrap();
    let out = Command::new(bin())
        .args(["golden", "check", tp, not_golden.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_take_opt_needs_value() {
    let (dir, trace, _spec) = fixture("take-opt-needs-value");
    let tp = trace.to_str().unwrap();
    let gold = dir.join("golden.json");
    // --name の直後に値が無い。
    let out = Command::new(bin())
        .args(["golden", "record", tp, gold.to_str().unwrap(), "--name"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--name needs a value"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_run_spec_load_errors() {
    let dir = tmp_dir("run-spec-errors");

    // 存在しない仕様ファイルは終了コード 2。
    let out = Command::new(bin())
        .args(["run", dir.join("missing.json").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 解釈できない仕様ファイルも終了コード 2。
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{oops").unwrap();
    let out = Command::new(bin())
        .args(["run", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_keep_source_write_failure() {
    let (dir, _trace, spec) = fixture("probe-exe-keep-source");
    let sp = spec.to_str().unwrap();
    // --keep-source の書き込み先ディレクトリが無い（ビルド前に失敗）。
    let out = Command::new(bin())
        .args([
            "probe-exe",
            sp,
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            dir.join("probe.exe").to_str().unwrap(),
            "--keep-source",
            dir.join("no-such-dir").join("main.rs").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_prereq_missing_trace() {
    let dir = tmp_dir("prereq-missing");
    let out = Command::new(bin())
        .args(["prereq", dir.join("missing.trace").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_duplicate_flags_and_missing_spec() {
    let (dir, _trace, spec) = fixture("probe-exe-dup-flags");
    let sp = spec.to_str().unwrap();
    let out = dir.join("probe.exe");
    let op = out.to_str().unwrap();

    // --target の重複。
    let status = Command::new(bin())
        .args([
            "probe-exe",
            sp,
            "--target",
            "x86_64-pc-windows-gnu",
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            op,
        ])
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(2));

    // --out の重複。
    let status = Command::new(bin())
        .args([
            "probe-exe",
            sp,
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            op,
            "--out",
            op,
        ])
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(2));

    // --keep-source の重複。
    let status = Command::new(bin())
        .args([
            "probe-exe",
            sp,
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            op,
            "--keep-source",
            dir.join("a.rs").to_str().unwrap(),
            "--keep-source",
            dir.join("b.rs").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(2));

    // 存在しない仕様ファイル。
    let status = Command::new(bin())
        .args([
            "probe-exe",
            dir.join("missing.json").to_str().unwrap(),
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            op,
        ])
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_take_overrides_duplicate_flags() {
    let (dir, trace, _spec) = fixture("overrides-dup-flags");
    let tp = trace.to_str().unwrap();
    let gold = dir.join("golden.json");
    let gp = gold.to_str().unwrap();

    // 環境指定フラグは take_overrides 内で 1 件ずつ読むため、
    // 重複はフラグごとに別の `?` 経路を通る。
    for (flag, value) in [
        ("--os-version", "Windows 11"),
        ("--os-build", "26100"),
        ("--cpu", "Test CPU"),
        ("--locale", "ja-JP"),
        ("--gpu", "Test GPU"),
    ] {
        let out = Command::new(bin())
            .args(["golden", "record", tp, gp, flag, value, flag, value])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "duplicate {flag}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_check_missing_trace_and_fresh_errors() {
    let (dir, trace, _spec) = fixture("golden-check-fresh-errors");
    let tp = trace.to_str().unwrap();
    let gold = dir.join("golden.json");
    let gp = gold.to_str().unwrap();

    // check の参照 Trace が存在しない。
    let out = Command::new(bin())
        .args([
            "golden",
            "check",
            dir.join("missing.trace").to_str().unwrap(),
            gp,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // fresh の --name の重複。
    let out = Command::new(bin())
        .args(["golden", "fresh", tp, tp, "--name", "a", "--name", "b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // fresh の環境フラグの重複（take_overrides の `?` 経路）。
    let out = Command::new(bin())
        .args(["golden", "fresh", tp, tp, "--cpu", "a", "--cpu", "b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // fresh の候補 Trace が存在しない。
    let out = Command::new(bin())
        .args([
            "golden",
            "fresh",
            tp,
            dir.join("missing.trace").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_golden_fresh_json() {
    let (dir, trace, _spec) = fixture("golden-fresh-json");
    let tp = trace.to_str().unwrap();
    let out = Command::new(bin())
        .args(["golden", "fresh", tp, tp, "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"mode\": \"golden\""), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_run_dispatch_errors() {
    let (dir, _trace, spec) = fixture("run-dispatch");
    let sp = spec.to_str().unwrap();

    let out = Command::new(bin())
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-test"));

    // 未知オプション・引数個数違い。
    let out = Command::new(bin())
        .args(["run", sp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin()).arg("run").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_dispatch_errors() {
    let (dir, _trace, spec) = fixture("probe-exe-dispatch");
    let sp = spec.to_str().unwrap();

    let out = Command::new(bin())
        .args(["probe-exe", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-test"));

    // 未知オプション・引数個数違い。
    let out = Command::new(bin())
        .args(["probe-exe", sp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin()).arg("probe-exe").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin())
        .args(["probe-exe", sp, sp])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_prereq_dispatch_errors() {
    let (dir, trace, _spec) = fixture("prereq-dispatch");
    let tp = trace.to_str().unwrap();

    let out = Command::new(bin())
        .args(["prereq", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-test"));

    // 未知オプションは終了コード 2。
    let out = Command::new(bin())
        .args(["prereq", tp, "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
