//! shirusu-test バイナリの統合テスト（終了コードと JSON 出力）。

use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};
use std::process::Command;

fn trace_bytes() -> Vec<u8> {
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
            }
        };
    let events = vec![
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
        ev(
            1,
            3,
            4,
            7,
            &[Ty::U64],
            vec![CapturedValue::captured(TypedValue::U64(0x100))],
        ),
        ev(
            2,
            4,
            4,
            8,
            &[Ty::I32],
            vec![CapturedValue::captured(TypedValue::I32(1))],
        ),
    ];
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

#[test]
fn cli_exit_codes() {
    let dir = std::env::temp_dir().join(format!("shirusu-test-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let trace_path = dir.join("t.trace");
    std::fs::write(&trace_path, trace_bytes()).unwrap();
    let pass_spec = dir.join("pass.json");
    std::fs::write(
        &pass_spec,
        r#"{"name":"p","rules":[
            {"type":"api-called","api":"kernel32!CreateFileW"},
            {"type":"object-closed","created_by":"kernel32!CreateFileW"},
            {"type":"no-integrity-loss"}
        ]}"#,
    )
    .unwrap();
    let fail_spec = dir.join("fail.json");
    std::fs::write(
        &fail_spec,
        r#"{"rules":[{"type":"api-called","api":"kernel32!WriteFile"}]}"#,
    )
    .unwrap();
    let bad_spec = dir.join("bad.json");
    std::fs::write(&bad_spec, "{oops").unwrap();

    let bin = env!("CARGO_BIN_EXE_shirusu-test");
    let tp = trace_path.to_str().unwrap();

    let out = Command::new(bin)
        .args([tp, pass_spec.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("PASS api-called"), "{stdout}");
    assert!(stdout.contains("all rules passed"), "{stdout}");

    let out = Command::new(bin)
        .args([tp, fail_spec.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    let out = Command::new(bin)
        .args([tp, bad_spec.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    let out = Command::new(bin)
        .args([tp, pass_spec.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"passed\": true"), "{stdout}");
}
