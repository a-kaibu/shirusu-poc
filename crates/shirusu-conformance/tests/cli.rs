//! shirusu-conformance CLI の統合テスト：終了コードを確認する。

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

#[test]
fn cli_exit_codes() {
    let dir = std::env::temp_dir().join(format!("shirusu-conformance-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.trace");
    std::fs::write(&good, valid_trace_bytes()).unwrap();
    let bad = dir.join("bad.trace");
    std::fs::write(&bad, b"not a trace at all").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-conformance"))
        .arg(&good)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-conformance"))
        .arg(&good)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"conformant\": true"));

    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-conformance"))
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    let out = Command::new(env!("CARGO_BIN_EXE_shirusu-conformance"))
        .arg(dir.join("missing.trace"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
