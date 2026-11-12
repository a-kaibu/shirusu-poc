//! shirusu-conformance バイナリのカバレッジ gap テスト（2026-11-12 計測分）。
//!
//! `tests/cli.rs` では到達しない分岐が対象：`--help`、`--bogus`、
//! 引数の個数違い。Trace 読み取り・適合判定の本体は cli.rs で
//! 既に駆動されている。

use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, EventCapture, Ty};
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};
use std::process::Command;

fn valid_trace_bytes() -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 3,
            created_by: "cli-test writer".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    w.register_schema(make_schema(1, "x!Y/enter", vec![("h".into(), Ty::U64, 0)]))
        .unwrap();
    w.register_schema(make_schema(
        2,
        "x!Y/leave",
        vec![
            ("return".into(), Ty::U64, 0),
            ("last_error".into(), Ty::U32, 0),
        ],
    ))
    .unwrap();
    let ev = |kind, sequence| TraceEvent {
        kind,
        sequence,
        timestamp_qpc: sequence * 10,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: if kind == 1 { 1 } else { 2 },
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: None,
        global_order: None,
    };
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![ev(1, 1), ev(2, 2)],
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shirusu-conformance")
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-conformance-coverage-gaps-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_help_exits_zero() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("usage: shirusu-conformance"));
}

#[test]
fn cli_unknown_option_exits_two() {
    let dir = tmp_dir("unknown");
    let good = dir.join("good.trace");
    std::fs::write(&good, valid_trace_bytes()).unwrap();
    let out = Command::new(bin())
        .arg(&good)
        .arg("--bogus")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_wrong_arg_count_exits_two() {
    let dir = tmp_dir("argc");
    let good = dir.join("good.trace");
    std::fs::write(&good, valid_trace_bytes()).unwrap();

    // 引数なし。
    let out = Command::new(bin()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 位置引数が 2 個。
    let out = Command::new(bin()).arg(&good).arg(&good).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
