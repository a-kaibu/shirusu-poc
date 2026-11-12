//! Golden 期待値（L18）の検証。参照 Trace からの導出、保存済み
//! Golden の読み書き、環境の照合、CLI の `golden` 副コマンドを確認する。

use shirusu_test::golden::{
    check, derive_from_trace, fresh_check, Golden, GoldenEnvironment, GoldenOverrides,
};
use shirusu_test::TestSpec;
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

struct B {
    events: Vec<TraceEvent>,
    seq: u64,
}

impl B {
    fn new() -> Self {
        B {
            events: Vec::new(),
            seq: 0,
        }
    }
    fn push(
        &mut self,
        kind: u16,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
        payload: PayloadRef,
    ) {
        self.seq += 1;
        self.events.push(TraceEvent {
            kind,
            sequence: self.seq,
            timestamp_qpc: 100 + self.seq * 10,
            call_id: if kind == 2 { self.seq - 1 } else { self.seq },
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
    }
    fn create(&mut self, handle: u64, path: &str) {
        self.push(
            1,
            1,
            1,
            &[Ty::Str16, Ty::U32],
            vec![
                cv(TypedValue::Str16(path.encode_utf16().collect())),
                cv(TypedValue::U32(0x8000_0000)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }
    fn read(&mut self, handle: u64, want: u32, payload: PayloadRef) {
        self.push(
            1,
            2,
            3,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(handle)), cv(TypedValue::U32(want))],
            payload,
        );
        self.push(
            2,
            2,
            4,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(want))],
            PayloadRef::None,
        );
    }
    fn close(&mut self, handle: u64) {
        self.push(
            1,
            4,
            7,
            &[Ty::U64],
            vec![cv(TypedValue::U64(handle))],
            PayloadRef::None,
        );
        self.push(
            2,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }
    fn finish(self, env: CaptureEnvironment, fin: FinalizationInfo) -> ReadTrace {
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        for def in [
            make_schema(
                1,
                "kernel32!CreateFileW/enter",
                vec![
                    ("lpFileName".into(), Ty::Str16, 0),
                    ("dwDesiredAccess".into(), Ty::U32, 0),
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
                3,
                "kernel32!ReadFile/enter",
                vec![
                    ("hFile".into(), Ty::U64, 0),
                    ("nNumberOfBytesToRead".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                4,
                "kernel32!ReadFile/leave",
                vec![
                    ("return".into(), Ty::I32, 0),
                    ("lpNumberOfBytesRead".into(), Ty::U32, 0),
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
        if !self.events.is_empty() {
            w.write_batch(&EventBatch {
                session_id: 1,
                process_id: 1,
                raw_pid: 10,
                thread_id: 1,
                qpc_frequency: 10_000_000,
                events: self.events,
            })
            .unwrap();
        }
        let bytes = w.finish(fin).unwrap();
        shirusu_trace::read_trace(&bytes).unwrap()
    }
}

fn env(os_version: &str, os_build: u32, cpu_arch: &str) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 1,
            created_by: "golden-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: os_version.into(),
        os_build,
        cpu_arch: cpu_arch.into(),
        ..Default::default()
    }
}

fn clean_trace() -> ReadTrace {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(0x100, 4, PayloadRef::None);
    b.close(0x100);
    b.finish(
        env("Windows 11", 26100, "x86_64"),
        FinalizationInfo::default(),
    )
}

fn write_trace_file(path: &std::path::Path, build: impl FnOnce(&mut B)) {
    let mut b = B::new();
    build(&mut b);
    let mut w = TraceWriter::new(Vec::new(), env("Windows 11", 26100, "x86_64")).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
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
            3,
            "kernel32!ReadFile/enter",
            vec![
                ("hFile".into(), Ty::U64, 0),
                ("nNumberOfBytesToRead".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            4,
            "kernel32!ReadFile/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("lpNumberOfBytesRead".into(), Ty::U32, 0),
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
    if !b.events.is_empty() {
        w.write_batch(&EventBatch {
            session_id: 1,
            process_id: 1,
            raw_pid: 10,
            thread_id: 1,
            qpc_frequency: 10_000_000,
            events: b.events,
        })
        .unwrap();
    }
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn derive_from_clean_trace() {
    let trace = clean_trace();
    let (golden, notes) = derive_from_trace(&trace, "save-flow", GoldenOverrides::default());
    assert_eq!(golden.name, "save-flow");
    // 参照 Trace 自身に対して導出ルールはすべて pass する。
    let report = check(&golden, &trace);
    assert!(report.all_passed(), "{}", report.render_human());
    let described: Vec<String> = golden.spec.rules.iter().map(|r| r.describe()).collect();
    assert!(
        described
            .iter()
            .any(|d| d == "api-called kernel32!CreateFileW"),
        "{described:?}"
    );
    assert!(
        described
            .iter()
            .any(|d| d == "api-called kernel32!ReadFile"),
        "{described:?}"
    );
    assert!(
        described
            .iter()
            .any(|d| d == "api-called kernel32!CloseHandle"),
        "{described:?}"
    );
    assert!(
        described.iter().any(|d| d == "no-integrity-loss"),
        "{described:?}"
    );
    assert!(
        described
            .iter()
            .any(|d| d == "object-closed created_by=kernel32!CreateFileW"),
        "{described:?}"
    );
    // event-count は実行ごとに変動するため導出しない。
    assert!(
        !described.iter().any(|d| d.starts_with("event-count")),
        "{described:?}"
    );
    // 環境は参照 Trace から引き継がれる。
    assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 11"));
    assert_eq!(golden.environment.os_build, Some(26100));
    assert_eq!(golden.environment.cpu_arch.as_deref(), Some("x86_64"));
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn derive_skips_rules_the_reference_fails() {
    // Payload が落ちた参照からは no-integrity-loss を導出しない。
    let mut b = B::new();
    b.create(0x100, "x");
    b.read(
        0x100,
        4,
        PayloadRef::Dropped {
            original_len: 4096,
            reason: PayloadLossReason::Overflow,
        },
    );
    b.close(0x100);
    let dropped = b.finish(
        env("Windows 11", 26100, "x86_64"),
        FinalizationInfo::default(),
    );
    let (golden, notes) = derive_from_trace(&dropped, "d", GoldenOverrides::default());
    assert!(
        !golden
            .spec
            .rules
            .iter()
            .any(|r| r.describe() == "no-integrity-loss"),
        "{:?}",
        golden.spec.rules
    );
    assert!(
        notes.iter().any(|n| n.contains("no-integrity-loss")),
        "{notes:?}"
    );
    // 導出したものは参照自身に pass する（自己矛盾が無い）。
    assert!(check(&golden, &dropped).all_passed());

    // 閉じていないオブジェクトがある参照からは object-closed を導出しない。
    let mut b = B::new();
    b.create(0x100, "x");
    b.read(0x100, 4, PayloadRef::None);
    let unclosed = b.finish(
        env("Windows 11", 26100, "x86_64"),
        FinalizationInfo::default(),
    );
    let (golden, notes) = derive_from_trace(&unclosed, "u", GoldenOverrides::default());
    assert!(
        !golden
            .spec
            .rules
            .iter()
            .any(|r| r.describe().starts_with("object-closed")),
        "{:?}",
        golden.spec.rules
    );
    assert!(
        notes.iter().any(|n| n.contains("object-closed")),
        "{notes:?}"
    );
    assert!(check(&golden, &unclosed).all_passed());
}

#[test]
fn derive_overrides_fill_environment() {
    let trace = clean_trace();
    let (golden, _) = derive_from_trace(
        &trace,
        "g",
        GoldenOverrides {
            cpu: Some("Test CPU 9 7950X".into()),
            locale: Some("ja-JP".into()),
            gpu: Some("Test GPU".into()),
            ..Default::default()
        },
    );
    assert_eq!(golden.environment.cpu.as_deref(), Some("Test CPU 9 7950X"));
    assert_eq!(golden.environment.locale.as_deref(), Some("ja-JP"));
    assert_eq!(golden.environment.gpu.as_deref(), Some("Test GPU"));
    // Trace 由来の値は上書きされない（--os-version/--os-build 指定時のみ上書き）。
    assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 11"));
    let (golden, _) = derive_from_trace(
        &trace,
        "g",
        GoldenOverrides {
            os_version: Some("Windows 10".into()),
            os_build: Some(19045),
            ..Default::default()
        },
    );
    assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 10"));
    assert_eq!(golden.environment.os_build, Some(19045));
}

#[test]
fn golden_roundtrips_through_json() {
    let trace = clean_trace();
    let (golden, _) = derive_from_trace(
        &trace,
        "save-flow",
        GoldenOverrides {
            cpu: Some("Test CPU".into()),
            locale: Some("ja-JP".into()),
            gpu: Some("Test GPU".into()),
            ..Default::default()
        },
    );
    let text = golden.to_pretty_json();
    let reparsed = Golden::parse(&text).unwrap();
    assert_eq!(reparsed, golden);
    assert!(text.contains("\"kind\": \"golden\""), "{text}");
    assert!(text.contains("\"os_version\": \"Windows 11\""), "{text}");
    assert!(text.contains("\"cpu\": \"Test CPU\""), "{text}");
    assert!(text.contains("\"locale\": \"ja-JP\""), "{text}");
    assert!(text.contains("\"gpu\": \"Test GPU\""), "{text}");
}

#[test]
fn golden_parse_rejects_non_golden() {
    assert!(Golden::parse(r#"{"version":1,"rules":[]}"#).is_err());
    assert!(Golden::parse(r#"{"version":1,"kind":"spec","rules":[]}"#).is_err());
    assert!(Golden::parse(r#"{"version":2,"kind":"golden","rules":[]}"#).is_err());
    assert!(Golden::parse(r#"{"version":1,"kind":"golden"}"#).is_err());
    assert!(Golden::parse(r#"{"version":1,"kind":"golden","rules":[{"type":"nope"}]}"#).is_err());
    // 環境が無くても読める（すべて unknown）。
    let g = Golden::parse(r#"{"version":1,"kind":"golden","name":"n","rules":[]}"#).unwrap();
    assert_eq!(g.environment, GoldenEnvironment::default());
    // TestSpec としても読める（Golden は仕様のスーパーセット）。
    let s = TestSpec::parse(
        r#"{"version":1,"kind":"golden","name":"n","rules":[{"type":"no-integrity-loss"}]}"#,
    )
    .unwrap();
    assert_eq!(s.rules.len(), 1);
}

#[test]
fn environment_mismatch_is_a_warning_not_a_failure() {
    let trace = clean_trace();
    let (mut golden, _) = derive_from_trace(&trace, "g", GoldenOverrides::default());
    // 候補の環境が違っても、ルールが通れば pass する。
    golden.environment.os_build = Some(22000);
    let report = check(&golden, &trace);
    assert!(report.all_passed(), "{}", report.render_human());
    assert_eq!(report.environment_notes.len(), 1);
    assert!(
        report.environment_notes[0].contains("os_build"),
        "{}",
        report.environment_notes[0]
    );
    assert!(
        report.render_human().contains("os_build"),
        "{}",
        report.render_human()
    );

    // 環境が一致すれば注記は無い。
    let (golden, _) = derive_from_trace(&trace, "g", GoldenOverrides::default());
    let report = check(&golden, &trace);
    assert!(report.environment_notes.is_empty());

    // 候補 Trace に環境が無ければ、その旨を注記する。環境 Block を
    // 持たない Trace は Header だけのファイルとして作る。
    let header_only = {
        use shirusu_trace::container::{
            serialize_header, BlockHeader, BlockType, Compression, FileHeader,
        };
        let payload = FileHeader::new(1).encode();
        let header = BlockHeader {
            block_type: BlockType::Header,
            compression: Compression::None,
            sequence: 0,
            stored_len: payload.len() as u32,
            raw_len: payload.len() as u32,
        };
        let mut bytes = serialize_header(&header, &payload).to_vec();
        bytes.extend_from_slice(&payload);
        bytes
    };
    let no_env = shirusu_trace::read_trace(&header_only).unwrap();
    assert!(no_env.environment.is_none());
    let report = check(&golden, &no_env);
    assert!(
        report
            .environment_notes
            .iter()
            .any(|n| n.contains("no environment")),
        "{:?}",
        report.environment_notes
    );
}

#[test]
fn fresh_check_matches_saved_golden() {
    let reference = clean_trace();
    // 候補は参照と同じ内容（別インスタンス）。
    let candidate = clean_trace();
    let fresh = fresh_check(&reference, &candidate, "g", GoldenOverrides::default());
    assert!(fresh.all_passed(), "{}", fresh.render_human());

    // 候補に ReadFile が無い Trace は fresh でも失敗する。
    let mut b = B::new();
    b.create(0x100, "x");
    b.close(0x100);
    let no_read = b.finish(
        env("Windows 11", 26100, "x86_64"),
        FinalizationInfo::default(),
    );
    let fresh = fresh_check(&reference, &no_read, "g", GoldenOverrides::default());
    assert!(!fresh.all_passed());
    assert!(
        fresh
            .report
            .results
            .iter()
            .any(|r| r.rule.contains("ReadFile") && !r.passed),
        "{}",
        fresh.render_human()
    );
}

#[test]
fn golden_cli_record_check_fresh() {
    let dir = std::env::temp_dir().join(format!("shirusu-test-golden-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ref_path = dir.join("ref.trace");
    write_trace_file(&ref_path, |b| {
        b.create(0x100, "C:\\game\\save.dat");
        b.read(0x100, 4, PayloadRef::None);
        b.close(0x100);
    });
    let cand_path = dir.join("cand.trace");
    write_trace_file(&cand_path, |b| {
        b.create(0x100, "C:\\game\\save.dat");
        b.read(0x100, 4, PayloadRef::None);
        b.close(0x100);
    });
    let golden_path = dir.join("golden.json");
    let bin = env!("CARGO_BIN_EXE_shirusu-test");

    // record: 保存済み Golden を書き出す。
    let out = Command::new(bin)
        .args([
            "golden",
            "record",
            ref_path.to_str().unwrap(),
            golden_path.to_str().unwrap(),
            "--name",
            "save-flow",
            "--cpu",
            "Test CPU",
            "--locale",
            "ja-JP",
            "--gpu",
            "Test GPU",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = std::fs::read_to_string(&golden_path).unwrap();
    let golden = Golden::parse(&saved).unwrap();
    assert_eq!(golden.name, "save-flow");
    assert_eq!(golden.environment.cpu.as_deref(), Some("Test CPU"));
    assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 11"));

    // check: 保存済み Golden で候補を評価する。
    let out = Command::new(bin)
        .args([
            "golden",
            "check",
            cand_path.to_str().unwrap(),
            golden_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("all rules passed"), "{stdout}");

    // check --json: 環境と結果が JSON に出る。
    let out = Command::new(bin)
        .args([
            "golden",
            "check",
            cand_path.to_str().unwrap(),
            golden_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"mode\": \"golden\""), "{stdout}");
    assert!(
        stdout.contains("\"os_version\": \"Windows 11\""),
        "{stdout}"
    );

    // fresh: 参照からその場で導出して評価する（ファイル不要）。
    let out = Command::new(bin)
        .args([
            "golden",
            "fresh",
            ref_path.to_str().unwrap(),
            cand_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // check に普通の仕様ファイルを渡すと kind 不一致で終了コード 2。
    let spec_path = dir.join("spec.json");
    std::fs::write(&spec_path, r#"{"rules":[{"type":"no-integrity-loss"}]}"#).unwrap();
    let out = Command::new(bin)
        .args([
            "golden",
            "check",
            cand_path.to_str().unwrap(),
            spec_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // 存在しない参照 Trace は終了コード 2。
    let out = Command::new(bin)
        .args([
            "golden",
            "fresh",
            dir.join("missing.trace").to_str().unwrap(),
            cand_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
