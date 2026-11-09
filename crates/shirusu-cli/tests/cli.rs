//! `shirusu` バイナリの統合テスト。合成 Trace を一時ファイルに書き、
//! 実バイナリを起動して inspect / dump / export の出力をゴールデンと
//! 照合する。ゴールデンの更新は UPDATE_GOLDEN=1 で明示的に行う。

use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::TraceWriter;
use std::path::PathBuf;
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn sample_trace_bytes() -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
                ("hTemplateFile".into(), Ty::U64, 0),
            ],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![
                ("return".into(), Ty::U64, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            7,
            "kernel32!CloseHandle/enter",
            vec![("hObject".into(), Ty::U64, 0)],
        ),
        make_schema(
            8,
            "kernel32!CloseHandle/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
    ] {
        w.register_schema(def).unwrap();
    }
    let ev = |kind: u16,
              sequence: u64,
              api_id: u32,
              schema_id: u32,
              types: &[Ty],
              values: Vec<CapturedValue>| {
        TraceEvent {
            kind,
            sequence,
            timestamp_qpc: 1_000 + sequence * 10,
            call_id: 1,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload: shirusu_trace::PayloadRef::None,
            args: Some(encode_values(types, &values).unwrap()),
        }
    };
    let events = vec![
        ev(
            1,
            1,
            1,
            1,
            &[Ty::Str16, Ty::U32, Ty::U64],
            vec![
                cv(TypedValue::Str16("a.txt".encode_utf16().collect())),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U64(0)),
            ],
        ),
        ev(
            2,
            2,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(0x2a4)), cv(TypedValue::U32(0))],
        ),
        ev(1, 3, 4, 7, &[Ty::U64], vec![cv(TypedValue::U64(0x2a4))]),
        ev(
            2,
            4,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        ),
    ];
    w.write_batch(&EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events,
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

/// 一時ディレクトリに sample.trace を置き、その中でバイナリを起動する。
fn run_cli(args: &[&str]) -> (String, String, bool) {
    let dir = std::env::temp_dir().join(format!("shirusu-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sample.trace"), sample_trace_bytes()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_shirusu"))
        .args(args)
        .current_dir(&dir)
        .output()
        .unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
        out.status.success(),
    )
}

fn check_golden(name: &str, actual: &str) {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "golden", name]
        .iter()
        .collect();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
    assert_eq!(
        actual, expected,
        "golden mismatch for {name}; rerun with UPDATE_GOLDEN=1 to refresh"
    );
}

#[test]
fn inspect_matches_golden() {
    let (stdout, stderr, ok) = run_cli(&["inspect", "sample.trace"]);
    assert!(ok, "stderr: {stderr}");
    check_golden("inspect.txt", &stdout);
}

#[test]
fn dump_matches_golden() {
    let (stdout, stderr, ok) = run_cli(&["dump", "sample.trace"]);
    assert!(ok, "stderr: {stderr}");
    check_golden("dump.txt", &stdout);
}

#[test]
fn dump_json_and_filters() {
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--json"]);
    assert!(ok);
    assert!(
        stdout.contains("\"api\":\"kernel32!CreateFileW\""),
        "{stdout}"
    );
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--api", "CloseHandle"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--text", "a.txt"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--seq", "2..3", "--kind", "leave"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
}

#[test]
fn export_jsonl_line_count() {
    let (stdout, _, ok) = run_cli(&["export", "sample.trace", "--format", "jsonl"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 4);
    assert!(stdout
        .lines()
        .all(|l| l.starts_with('{') && l.ends_with('}')));
}

#[test]
fn bad_inputs_exit_nonzero() {
    let (_, stderr, ok) = run_cli(&["inspect", "missing.trace"]);
    assert!(!ok);
    assert!(stderr.contains("cannot read"), "{stderr}");
    let (_, _, ok) = run_cli(&["frobnicate", "sample.trace"]);
    assert!(!ok);
    let (_, _, ok) = run_cli(&["export", "sample.trace", "--format", "parquet"]);
    assert!(!ok);
}
