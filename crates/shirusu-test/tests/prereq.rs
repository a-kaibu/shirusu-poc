//! 前提条件の検査（L19）の検証。Trace からテストを作る前に不足を
//! 報告する各検査と、CLI の `prereq` 副コマンドを確認する。

use shirusu_test::prereq::{check_prerequisites, PrereqKind};
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::module::{ModuleClass, ModuleClassification};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::schema::{
    make_schema, CapturedValue, EventCapture, Ty, TypedValue, ValueCapture, ValueKind,
};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{BlobId, PayloadRef, TraceWriter};
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn not_captured(v: TypedValue) -> CapturedValue {
    CapturedValue {
        capture: ValueCapture::Unreadable,
        value: v,
    }
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
    ) -> u64 {
        self.push_parent(kind, api_id, schema_id, types, values, payload, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_parent(
        &mut self,
        kind: u16,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
        payload: PayloadRef,
        parent_call_id: u64,
    ) -> u64 {
        self.seq += 1;
        let call_id = self.seq;
        self.events.push(TraceEvent {
            kind,
            sequence: self.seq,
            timestamp_qpc: 100 + self.seq * 10,
            call_id,
            parent_call_id,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
        call_id
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
            &[Ty::U64, Ty::U64, Ty::U32],
            vec![
                cv(TypedValue::U64(handle)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::U32(want)),
            ],
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

    /// lpBuffer が取得できなかった ReadFile（トップレベルの入力欠落）。
    /// `nested` が true の場合は親呼び出し付き（下位呼び出し）にする。
    fn read_unreadable_buffer(&mut self, handle: u64, nested: bool) {
        let parent = if nested { 1 } else { 0 };
        self.push_parent(
            1,
            2,
            3,
            &[Ty::U64, Ty::U64, Ty::U32],
            vec![
                cv(TypedValue::U64(handle)),
                not_captured(TypedValue::U64(0)),
                cv(TypedValue::U32(4)),
            ],
            PayloadRef::None,
            parent,
        );
        self.push(
            2,
            2,
            4,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(4))],
            PayloadRef::None,
        );
    }

    fn close(&mut self, handle: u64) {
        self.push(
            1,
            4,
            5,
            &[Ty::U64],
            vec![cv(TypedValue::U64(handle))],
            PayloadRef::None,
        );
        self.push(
            2,
            4,
            6,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }

    /// hKey を使うだけの呼び出し（生成はしない）。
    fn reg_query(&mut self, hkey: u64) {
        self.push(
            1,
            9,
            9,
            &[Ty::U64, Ty::U64],
            vec![cv(TypedValue::U64(hkey)), cv(TypedValue::U64(0))],
            PayloadRef::None,
        );
        self.push(
            2,
            9,
            10,
            &[Ty::U32, Ty::U32],
            vec![cv(TypedValue::U32(0)), cv(TypedValue::U32(0))],
            PayloadRef::None,
        );
    }

    /// コールバックの enter / leave 1 回分。proc は元の WndProc の
    /// アドレス（`callback!enter` の `proc` フィールド）。
    fn callback(&mut self, proc: u64, message: u32) {
        self.push(
            1,
            1002,
            10021,
            &[Ty::U64, Ty::U32, Ty::U32, Ty::U64, Ty::I64, Ty::U64],
            vec![
                cv(TypedValue::U64(0x500)),
                cv(TypedValue::U32(1)),
                cv(TypedValue::U32(message)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::I64(0)),
                cv(TypedValue::U64(proc)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            1002,
            10022,
            &[Ty::I64],
            vec![cv(TypedValue::I64(0))],
            PayloadRef::None,
        );
    }

    /// proc が取得できなかったコールバック。
    fn callback_unreadable_proc(&mut self, message: u32) {
        self.push(
            1,
            1002,
            10021,
            &[Ty::U64, Ty::U32, Ty::U32, Ty::U64, Ty::I64, Ty::U64],
            vec![
                cv(TypedValue::U64(0x500)),
                cv(TypedValue::U32(1)),
                cv(TypedValue::U32(message)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::I64(0)),
                not_captured(TypedValue::U64(0)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            1002,
            10022,
            &[Ty::I64],
            vec![cv(TypedValue::I64(0))],
            PayloadRef::None,
        );
    }

    fn finish(self, env: CaptureEnvironment) -> ReadTrace {
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
                    ("return".into(), Ty::U64, ValueKind::CreatedObject.flags()),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                3,
                "kernel32!ReadFile/enter",
                vec![
                    ("hFile".into(), Ty::U64, ValueKind::Handle.flags()),
                    ("lpBuffer".into(), Ty::U64, ValueKind::Pointer.flags()),
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
                5,
                "kernel32!CloseHandle/enter",
                vec![("hObject".into(), Ty::U64, ValueKind::Handle.flags())],
            ),
            make_schema(
                6,
                "kernel32!CloseHandle/leave",
                vec![
                    ("return".into(), Ty::I32, 0),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                9,
                "advapi32!RegQueryValueExW/enter",
                vec![
                    ("hKey".into(), Ty::U64, ValueKind::Handle.flags()),
                    ("lpValueName".into(), Ty::U64, ValueKind::Pointer.flags()),
                ],
            ),
            make_schema(
                10,
                "advapi32!RegQueryValueExW/leave",
                vec![
                    ("return".into(), Ty::U32, 0),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ),
            make_schema(
                10021,
                "callback!enter",
                vec![
                    ("hwnd".into(), Ty::U64, ValueKind::Pointer.flags()),
                    ("kind".into(), Ty::U32, ValueKind::Scalar.flags()),
                    ("message".into(), Ty::U32, ValueKind::Scalar.flags()),
                    ("wparam".into(), Ty::U64, ValueKind::Scalar.flags()),
                    ("lparam".into(), Ty::I64, ValueKind::Scalar.flags()),
                    ("proc".into(), Ty::U64, ValueKind::Pointer.flags()),
                ],
            ),
            make_schema(10022, "callback!leave", vec![("result".into(), Ty::I64, 0)]),
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
        let bytes = w.finish(FinalizationInfo::default()).unwrap();
        shirusu_trace::read_trace(&bytes).unwrap()
    }
}

fn env(os_version: &str, os_build: u32, cpu_arch: &str) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 1,
            created_by: "prereq-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: os_version.into(),
        os_build,
        cpu_arch: cpu_arch.into(),
        ..Default::default()
    }
}

/// モジュール分類を 1 件だけ持つ環境。L19 のモジュール一覧の検査は
/// 「空かどうか」だけを見る。
fn env_with_modules() -> CaptureEnvironment {
    let mut e = env("Windows 11", 26100, "x86_64");
    e.modules = vec![ModuleClassification {
        module_name: "test.exe".into(),
        class: ModuleClass::Application,
        reason: "test".into(),
        uncertain: false,
        implementation_module: None,
        overridden: false,
    }];
    e
}

fn kinds(report: &shirusu_test::prereq::PrereqReport) -> Vec<PrereqKind> {
    report.items.iter().map(|i| i.kind).collect()
}

fn has_kind(report: &shirusu_test::prereq::PrereqReport, kind: PrereqKind) -> bool {
    report.items.iter().any(|i| i.kind == kind)
}

#[test]
fn clean_trace_is_ready() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(0x100, 4, PayloadRef::None);
    b.close(0x100);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(report.is_ready(), "{}", report.render_human());
    assert_eq!(report.total_events, 6);
}

#[test]
fn missing_environment_is_reported() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.close(0x100);
    let mut trace = b.finish(env_with_modules());
    trace.environment = None;
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingEnvironment));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::MissingEnvironment)
        .unwrap();
    assert!(item.detail.contains("no environment"), "{}", item.detail);
}

#[test]
fn empty_environment_is_reported() {
    // 環境ブロックはあるが OS・ビルド・アーキテクチャがすべて空。
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    let empty = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 1,
            created_by: "prereq-test".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    };
    let trace = b.finish(empty);
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingEnvironment));
}

#[test]
fn unfinalized_trace_is_reported() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    let mut trace = b.finish(env_with_modules());
    trace.finalization = None;
    trace.finalized_cleanly = false;
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::IncompleteTrace));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::IncompleteTrace)
        .unwrap();
    assert!(item.detail.contains("no finalization"), "{}", item.detail);

    // Finalization はあるが正常終了でない場合も同じ種別で報告する。
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    let mut trace = b.finish(env_with_modules());
    trace.finalized_cleanly = false;
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::IncompleteTrace));
}

#[test]
fn recovery_issues_are_reported() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    let mut trace = b.finish(env_with_modules());
    trace
        .issues
        .push(RecoveryIssue::TruncatedTail { offset: 42 });
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::IncompleteTrace));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::IncompleteTrace)
        .unwrap();
    assert!(item.detail.contains("truncated_tail"), "{}", item.detail);
}

#[test]
fn empty_trace_has_no_calls() {
    let b = B::new();
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert_eq!(kinds(&report), vec![PrereqKind::NoCalls]);
    assert!(
        report.items[0].detail.contains("no events"),
        "{}",
        report.items[0].detail
    );
}

#[test]
fn missing_module_list_is_reported() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    // モジュール分類も静的依存も無い環境。
    let trace = b.finish(env("Windows 11", 26100, "x86_64"));
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingModuleList));
}

#[test]
fn unlinked_handle_is_reported() {
    // 生成の記録が無いハンドル 0x200 を使うだけの呼び出し。
    let mut b = B::new();
    b.reg_query(0x200);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::UnlinkedHandle));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::UnlinkedHandle)
        .unwrap();
    assert!(item.detail.contains("0x200"), "{}", item.detail);
    assert!(item.detail.contains("RegQueryValueExW"), "{}", item.detail);
    assert!(
        item.detail.contains("not linked to any recorded creation"),
        "{}",
        item.detail
    );
}

#[test]
fn linked_handle_is_not_flagged() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(0x100, 4, PayloadRef::None);
    b.close(0x100);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(
        !has_kind(&report, PrereqKind::UnlinkedHandle),
        "{}",
        report.render_human()
    );
}

#[test]
fn predefined_hkey_is_not_flagged() {
    // HKEY_CURRENT_USER (0x80000001) は定義済み定数であり、生成は不要。
    let mut b = B::new();
    b.reg_query(0x8000_0001);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(
        !has_kind(&report, PrereqKind::UnlinkedHandle),
        "{}",
        report.render_human()
    );
}

#[test]
fn unreadable_argument_is_reported_only_for_top_level_calls() {
    // トップレベル：lpBuffer の未取得を報告する。
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read_unreadable_buffer(0x100, false);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingInputValue));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::MissingInputValue)
        .unwrap();
    assert!(item.detail.contains("lpBuffer"), "{}", item.detail);
    assert!(item.detail.contains("unreadable"), "{}", item.detail);

    // 下位呼び出し（親あり）：再実行では親の実行の一部なので報告しない。
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read_unreadable_buffer(0x100, true);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(
        !has_kind(&report, PrereqKind::MissingInputValue),
        "{}",
        report.render_human()
    );
}

#[test]
fn dropped_payload_is_reported() {
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(
        0x100,
        4,
        PayloadRef::Dropped {
            original_len: 64,
            reason: PayloadLossReason::Backpressure,
        },
    );
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingInputValue));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::MissingInputValue)
        .unwrap();
    assert!(item.detail.contains("dropped"), "{}", item.detail);
}

#[test]
fn missing_blob_payload_is_reported() {
    // Writer は Blob 参照の事前登録を強制するため、読んだ Trace の
    // Payload を直接欠落 Blob へ差し替えて検査する（Reader が出す
    // MissingBlob issue 自体は reader 側の責務で別途検証済み）。
    let mut b = B::new();
    b.create(0x100, "C:\\game\\save.dat");
    b.read(0x100, 4, PayloadRef::None);
    let mut trace = b.finish(env_with_modules());
    trace.batches[0].events[2].payload = PayloadRef::Blob(BlobId::of_content(b"absent"));
    let report = check_prerequisites(&trace);
    assert!(has_kind(&report, PrereqKind::MissingInputValue));
    let item = report
        .items
        .iter()
        .find(|i| i.kind == PrereqKind::MissingInputValue)
        .unwrap();
    assert!(item.detail.contains("missing"), "{}", item.detail);
}

#[test]
fn callback_proc_without_identity_is_reported() {
    // 同じ proc のコールバック 2 回は 1 件にまとめる。
    let mut b = B::new();
    b.callback(0x7ff0_0000, 0x2);
    b.callback(0x7ff0_0000, 0x111);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    let found: Vec<_> = report
        .items
        .iter()
        .filter(|i| i.kind == PrereqKind::CallbackWithoutIdentity)
        .collect();
    assert_eq!(found.len(), 1, "{}", report.render_human());
    assert!(
        found[0].detail.contains("0x7ff00000"),
        "{}",
        found[0].detail
    );
    assert!(found[0].detail.contains("2 time(s)"), "{}", found[0].detail);
    assert!(
        found[0].detail.contains("cannot be determined"),
        "{}",
        found[0].detail
    );
}

#[test]
fn callback_without_proc_is_reported() {
    let mut b = B::new();
    b.callback_unreadable_proc(0x2);
    let trace = b.finish(env_with_modules());
    let report = check_prerequisites(&trace);
    let found: Vec<_> = report
        .items
        .iter()
        .filter(|i| i.kind == PrereqKind::CallbackWithoutIdentity)
        .collect();
    assert_eq!(found.len(), 1, "{}", report.render_human());
    assert!(
        found[0].detail.contains("no recorded proc address"),
        "{}",
        found[0].detail
    );
}

fn write_trace_file(path: &std::path::Path, build: impl FnOnce(&mut B)) {
    let mut b = B::new();
    build(&mut b);
    let mut w = TraceWriter::new(Vec::new(), env_with_modules()).unwrap();
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
                ("return".into(), Ty::U64, ValueKind::CreatedObject.flags()),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            3,
            "kernel32!ReadFile/enter",
            vec![
                ("hFile".into(), Ty::U64, ValueKind::Handle.flags()),
                ("lpBuffer".into(), Ty::U64, ValueKind::Pointer.flags()),
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
            5,
            "kernel32!CloseHandle/enter",
            vec![("hObject".into(), Ty::U64, ValueKind::Handle.flags())],
        ),
        make_schema(
            6,
            "kernel32!CloseHandle/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            9,
            "advapi32!RegQueryValueExW/enter",
            vec![
                ("hKey".into(), Ty::U64, ValueKind::Handle.flags()),
                ("lpValueName".into(), Ty::U64, ValueKind::Pointer.flags()),
            ],
        ),
        make_schema(
            10,
            "advapi32!RegQueryValueExW/leave",
            vec![
                ("return".into(), Ty::U32, 0),
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
fn prereq_cli_reports_missing_and_ready() {
    let dir = std::env::temp_dir().join(format!("shirusu-test-prereq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dirty_path = dir.join("dirty.trace");
    write_trace_file(&dirty_path, |b| {
        b.reg_query(0x200);
    });
    let clean_path = dir.join("clean.trace");
    write_trace_file(&clean_path, |b| {
        b.create(0x100, "C:\\game\\save.dat");
        b.close(0x100);
    });
    let bin = env!("CARGO_BIN_EXE_shirusu-test");

    // 不足あり：終了コード 1、MISSING を出す。
    let out = Command::new(bin)
        .args(["prereq", dirty_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("MISSING"), "{stdout}");
    assert!(stdout.contains("0x200"), "{stdout}");

    // 不足なし：終了コード 0、ready を出す。
    let out = Command::new(bin)
        .args(["prereq", clean_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("ready"), "{stdout}");

    // --json：mode と ready が出る。
    let out = Command::new(bin)
        .args(["prereq", clean_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"mode\": \"prereq\""), "{stdout}");
    assert!(stdout.contains("\"ready\": true"), "{stdout}");

    // 使い方エラー：終了コード 2。
    let out = Command::new(bin).args(["prereq"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
