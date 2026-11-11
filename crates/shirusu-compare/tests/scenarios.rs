//! シナリオ検証：合成 Trace の組を作り、期待する候補だけが出る
//! ことを確認する（テスト仕様 §4 のシナリオ群）。

mod common;

use common::{Builder, Env};
use shirusu_compare::{compare_traces, CandidateKind, Severity};
use shirusu_trace::proto::LossRecord;
use shirusu_trace::writer::FinalizationInfo;

/// 標準シナリオ: Create → Read → Close（+ Ping）。
fn standard(env: Env) -> Builder {
    let mut b = Builder::new(env);
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.read_file(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0);
    b.close_handle(3, 0);
    b.ping(4, 7, 7);
    b
}

fn kinds(report: &shirusu_compare::DiffReport) -> Vec<CandidateKind> {
    report.candidates.iter().map(|c| c.kind).collect()
}

#[test]
fn identical_traces_have_no_candidates() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let right = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(report.is_identical(), "candidates: {:?}", report.candidates);
    assert_eq!(report.paired_objects, 1);
}

#[test]
fn renumbered_handles_and_ids_have_no_candidates() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let right = standard(Env {
        handle_base: 0x9_0000,
        raw_pid: 7777,
        process_id: 99,
        thread_id: 31337,
        ts_base: 555_000,
    })
    .finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(
        report.is_identical(),
        "renumbering must be normalized away: {:?}",
        report.candidates
    );
}

#[test]
fn single_argument_change_is_the_only_candidate() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = Builder::new(Env::default());
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.read_file(2, 0, 8, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0); // want: 4 -> 8
    b.close_handle(3, 0);
    b.ping(4, 7, 7);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(report.candidates.len(), 1, "{:?}", report.candidates);
    let c = &report.candidates[0];
    assert_eq!(c.kind, CandidateKind::ArgumentDifference);
    assert_eq!(c.field.as_deref(), Some("nNumberOfBytesToRead"));
    assert_eq!(c.left_value.as_deref(), Some("4"));
    assert_eq!(c.right_value.as_deref(), Some("8"));
}

#[test]
fn return_failure_is_a_high_return_difference() {
    // sake 側で ReadFile が失敗した想定（レビュー第3回の LockRect 例の型）。
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = Builder::new(Env::default());
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.read_file(2, 0, 4, 0, &[], false, 5);
    b.close_handle(3, 0);
    b.ping(4, 7, 7);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    let returns: Vec<_> = report
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::ReturnDifference)
        .collect();
    assert!(
        returns
            .iter()
            .any(|c| c.field.as_deref() == Some("return") && c.severity == Severity::High),
        "candidates: {:?}",
        report.candidates
    );
    assert!(
        returns
            .iter()
            .any(|c| c.field.as_deref() == Some("last_error")),
        "candidates: {:?}",
        report.candidates
    );
}

#[test]
fn missing_call_is_reported_once() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = Builder::new(Env::default());
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.close_handle(3, 0);
    b.ping(4, 7, 7);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(kinds(&report), vec![CandidateKind::MissingCall]);
    assert_eq!(
        report.candidates[0].api.as_deref(),
        Some("kernel32!ReadFile")
    );
    assert_eq!(
        report.candidates[0]
            .object
            .as_ref()
            .map(|o| o.describe())
            .as_deref(),
        Some("kernel32!CreateFileW#0")
    );
}

#[test]
fn extra_non_object_call_is_reported() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = standard(Env::default());
    b.ping(5, 1, 1);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(kinds(&report), vec![CandidateKind::ExtraCall]);
}

#[test]
fn unclosed_object_shows_missing_close() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = Builder::new(Env::default());
    b.create_file(1, 0, "C:\\game\\save.dat");
    b.read_file(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0);
    b.ping(4, 7, 7);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(kinds(&report), vec![CandidateKind::MissingCall]);
    assert_eq!(
        report.candidates[0].api.as_deref(),
        Some("kernel32!CloseHandle")
    );
}

#[test]
fn operation_order_difference_is_one_state_candidate() {
    let mut lb = Builder::new(Env::default());
    lb.create_file(1, 0, "x");
    lb.read_file(2, 0, 4, 4, &[1, 2, 3, 4], true, 0);
    lb.write_file(3, 0, &[9, 9]);
    lb.close_handle(4, 0);
    let left = lb.finish(FinalizationInfo::default(), &[]);
    let mut rb = Builder::new(Env::default());
    rb.create_file(1, 0, "x");
    rb.write_file(3, 0, &[9, 9]);
    rb.read_file(2, 0, 4, 4, &[1, 2, 3, 4], true, 0);
    rb.close_handle(4, 0);
    let right = rb.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(
        kinds(&report),
        vec![CandidateKind::ObjectStateDifference],
        "{:?}",
        report.candidates
    );
}

#[test]
fn object_created_only_in_right_is_a_state_candidate() {
    let left = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let mut b = standard(Env::default());
    b.create_file(5, 1, "other.dat");
    b.close_handle(6, 1);
    let right = b.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::ObjectStateDifference
                && c.object.as_ref().map(|o| o.ordinal) == Some(1)),
        "{:?}",
        report.candidates
    );
}

#[test]
fn integrity_difference_is_reported() {
    let left = standard(Env::default()).finish(
        FinalizationInfo {
            event_integrity: 1, // Degraded
            ..Default::default()
        },
        &[LossRecord {
            kind: 3,
            count: 1,
            ..Default::default()
        }],
    );
    let right = standard(Env::default()).finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .all(|c| c.kind == CandidateKind::IntegrityDifference),
        "{:?}",
        report.candidates
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.field.as_deref() == Some("event_integrity")),
        "{:?}",
        report.candidates
    );
}

#[test]
fn aborted_on_both_sides_is_identical() {
    // L08: 両側とも中断した呼び出しは、同じ形として一致する。
    let mut l = Builder::new(Env::default());
    l.abort_create_file(1, 0, "C:\\game\\save.dat");
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.abort_create_file(1, 0, "C:\\game\\save.dat");
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(report.is_identical(), "candidates: {:?}", report.candidates);
}

#[test]
fn aborted_vs_normal_return_is_shape_difference() {
    // L08: 片側だけ中断した呼び出しは、正常終了との形の相違になる。
    // （オブジェクトに関与しない Ping なら、整列で対応づいて比較される）
    let mut l = Builder::new(Env::default());
    l.abort_ping(1, 7);
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.ping(1, 7, 7);
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(report.candidates.len(), 1, "{:?}", report.candidates);
    assert_eq!(
        report.candidates[0].kind,
        CandidateKind::CallShapeDifference
    );
}

#[test]
fn async_completed_read_equals_sync_read() {
    // F27: 非同期 ReadFile が完了で実値を運べば、同期 ReadFile と同じ
    // 振る舞いとして一致する（leave の Unsupported 値列ではなく、完了
    // イベントの値列を実効 leave として比べる）。
    let mut l = Builder::new(Env::default());
    l.create_file(1, 0, "C:\\\\game\\\\save.dat");
    l.read_file_async(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef]);
    l.close_handle(3, 0);
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.create_file(1, 0, "C:\\\\game\\\\save.dat");
    r.read_file(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0);
    r.close_handle(3, 0);
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(report.is_identical(), "candidates: {:?}", report.candidates);
}

#[test]
fn async_completed_read_data_difference_is_detected() {
    // F27: 完了で運ばれたデータが違えば、同期側との差分になる。
    let mut l = Builder::new(Env::default());
    l.create_file(1, 0, "C:\\\\game\\\\save.dat");
    l.read_file_async(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef]);
    l.close_handle(3, 0);
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.create_file(1, 0, "C:\\\\game\\\\save.dat");
    r.read_file(2, 0, 4, 4, &[0x11, 0x22, 0x33, 0x44], true, 0);
    r.close_handle(3, 0);
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.field.as_deref() == Some("data")),
        "candidates: {:?}",
        report.candidates
    );
}

#[test]
fn async_read_without_completion_differs_from_sync() {
    // F27: 完了が観測されなかった非同期 ReadFile は、leave の
    // Unsupported 値列のままなので同期 ReadFile と差分になる。
    let mut l = Builder::new(Env::default());
    l.create_file(1, 0, "C:\\\\game\\\\save.dat");
    l.read_file_async(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef]);
    l.events.pop(); // 完了イベントを取り除く
    l.close_handle(3, 0);
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.create_file(1, 0, "C:\\\\game\\\\save.dat");
    r.read_file(2, 0, 4, 4, &[0xde, 0xad, 0xbe, 0xef], true, 0);
    r.close_handle(3, 0);
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert!(
        !report.is_identical(),
        "must differ: {:?}",
        report.candidates
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.field.as_deref() == Some("data")),
        "candidates: {:?}",
        report.candidates
    );
}

#[test]
fn aborted_creator_call_reports_missing_object() {
    // L08: オブジェクトを生成するはずの呼び出しが中断すると、生成物が
    // 無いことが差分になる（生成する側と対にできず、呼び出しの欠落と
    // オブジェクトの状態差分の 2 候補が出る）。
    let mut l = Builder::new(Env::default());
    l.abort_create_file(1, 0, "C:\\game\\save.dat");
    let left = l.finish(FinalizationInfo::default(), &[]);
    let mut r = Builder::new(Env::default());
    r.create_file(1, 0, "C:\\game\\save.dat");
    let right = r.finish(FinalizationInfo::default(), &[]);
    let report = compare_traces(&left, &right);
    assert_eq!(report.candidates.len(), 2, "{:?}", report.candidates);
    assert_eq!(report.candidates[0].kind, CandidateKind::MissingCall);
    assert_eq!(
        report.candidates[1].kind,
        CandidateKind::ObjectStateDifference
    );
}
