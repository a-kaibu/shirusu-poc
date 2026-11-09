//! shirusu-probe CLI の統合テスト：終了コードと生成ファイルを確認する。

use shirusu_emit::{file_io_api_set, Emitter, EventMeta, SessionConfig};
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
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

fn workspace(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("shirusu-probe-cli-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let left = dir.join("left.trace");
    let right = dir.join("right.trace");
    (dir, left, right)
}

#[test]
fn cli_generates_bundle_and_exit_codes() {
    let (dir, left_path, right_path) = workspace("diff");
    std::fs::write(&left_path, trace(true)).unwrap();
    std::fs::write(&right_path, trace(false)).unwrap();
    let out_dir = dir.join("bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_shirusu-probe"))
        .arg(&left_path)
        .arg(&right_path)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("rules.json").exists());
    assert!(out_dir.join("brief.md").exists());

    // 差分が無ければ終了コード 1 で、バンドルは作らない。
    let out2 = dir.join("bundle2");
    let output = Command::new(env!("CARGO_BIN_EXE_shirusu-probe"))
        .arg(&left_path)
        .arg(&left_path)
        .arg("--out")
        .arg(&out2)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!out2.exists());

    // 使い方エラーは 2。
    let output = Command::new(env!("CARGO_BIN_EXE_shirusu-probe"))
        .arg(&left_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
