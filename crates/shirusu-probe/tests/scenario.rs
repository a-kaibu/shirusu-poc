//! Phase 5 の中核シナリオ（通し）:
//!
//! エミッタキットで「Windows 側」と「sake 側」の 2 つの Trace を
//! 作る（片方だけ挙動を変える）→ 適合性チェッカが両方を通す →
//! compare が候補を出す → Probe バンドルを生成 → バンドル内の
//! ルールが Windows 側 pass / sake 側 fail を再現する。
//!
//! ハンドル値とタイムスタンプは両側で変えてあり、正規化が
//! それを吸収することも同時に固定する（再番号付けだけのペアは
//! 候補ゼロ）。

use shirusu_compare::{compare_traces, CandidateKind};
use shirusu_emit::{file_io_api_set, Emitter, EventMeta, PayloadData, SessionConfig};
use shirusu_probe::{build_bundle, write_bundle, BundleOptions};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::writer::FinalizationInfo;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

/// ファイルを開いて読み書きして閉じる流れ。`read_ok` が false の
/// 側は ReadFile が失敗する（レビュー第3回 §1 の「LockRect が
/// 失敗する」型の差異を、ファイル API で再現したもの）。
fn record(handle: u64, read_ok: bool, close: bool, ts_base: u64) -> Vec<u8> {
    record_with_payload(handle, read_ok, close, ts_base, b"DATA")
}

fn record_with_payload(
    handle: u64,
    read_ok: bool,
    close: bool,
    ts_base: u64,
    read_payload: &[u8],
) -> Vec<u8> {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(100, "scenario-emitter 1.0"),
    )
    .unwrap();
    let mut ts = ts_base;
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
        &[cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
        tick(),
        EventMeta::default(),
    )
    .unwrap();
    let write = em
        .begin_call(
            1,
            "kernel32!WriteFile",
            &[
                cv(TypedValue::U64(handle)),
                cv(TypedValue::Bytes(b"DATA".to_vec())),
                cv(TypedValue::U32(4)),
                cv(TypedValue::U64(0)),
            ],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        write,
        &[
            cv(TypedValue::I32(1)),
            cv(TypedValue::U32(4)),
            cv(TypedValue::U32(0)),
        ],
        tick(),
        EventMeta::default(),
    )
    .unwrap();
    let read = em
        .begin_call(
            1,
            "kernel32!ReadFile",
            &[
                cv(TypedValue::U64(handle)),
                cv(TypedValue::U64(0x5000)),
                cv(TypedValue::U32(4)),
                cv(TypedValue::U64(0)),
            ],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
    if read_ok {
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
    } else {
        em.end_call(
            read,
            &[
                cv(TypedValue::I32(0)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::Bytes(Vec::new())),
                cv(TypedValue::U32(6)),
            ],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
    }
    if close {
        let close_call = em
            .begin_call(
                1,
                "kernel32!CloseHandle",
                &[cv(TypedValue::U64(handle))],
                tick(),
                EventMeta::default(),
            )
            .unwrap();
        em.end_call(
            close_call,
            &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            tick(),
            EventMeta::default(),
        )
        .unwrap();
    }
    em.finish(FinalizationInfo::default()).unwrap()
}

fn read(bytes: &[u8]) -> ReadTrace {
    shirusu_trace::read_trace(bytes).unwrap()
}

fn temp_bundle_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shirusu-probe-scenario-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn full_pipeline_read_failure_becomes_a_discriminating_probe() {
    // Windows 側: ハンドル 0x100、ReadFile 成功。
    // sake 側: ハンドル 0xABC（再番号付け）、ReadFile 失敗。
    let left_bytes = record(0x100, true, true, 1_000_000);
    let right_bytes = record(0xABC, false, true, 555_000_000);
    let left = read(&left_bytes);
    let right = read(&right_bytes);

    // 1. 適合性：エミッタ製の Trace は両側とも全項目パスする。
    for (label, t) in [("left", &left), ("right", &right)] {
        let report = shirusu_conformance::check_trace(t);
        assert!(
            report.conformant(),
            "{label} must conform: {}",
            report.render_human(label)
        );
    }

    // 2. compare：ReadFile の戻り値差分（High）が候補に出る。
    let report = compare_traces(&left, &right);
    assert!(!report.candidates.is_empty());
    let idx = report
        .candidates
        .iter()
        .position(|c| {
            c.kind == CandidateKind::ReturnDifference
                && c.api.as_deref() == Some("kernel32!ReadFile")
                && c.field.as_deref() == Some("return")
        })
        .expect("ReadFile return difference candidate");

    // 3. バンドル生成：識別ルールが付き、トリムが候補を再現する。
    let bundle = build_bundle(
        &left,
        &right,
        &report,
        idx,
        &BundleOptions {
            name: "probe-return-difference-readfile".into(),
            left_label: "windows.trace".into(),
            right_label: "sake.trace".into(),
        },
    )
    .unwrap();
    assert!(bundle.has_discriminating_rule());
    assert_eq!(bundle.trim_reproduced, Some(true));

    // 4. バンドル内ルールが Windows 側 pass / sake 側 fail を再現。
    let rules_text = bundle.rules_json.as_ref().unwrap();
    let spec = shirusu_test::TestSpec::parse(rules_text).unwrap();
    assert!(shirusu_test::evaluate(&spec, &left).all_passed());
    assert!(!shirusu_test::evaluate(&spec, &right).all_passed());

    // 5. ディレクトリへ書き出すと 5 ファイル揃う。
    let dir = temp_bundle_dir("read-failure");
    let written = write_bundle(&bundle, &dir).unwrap();
    assert_eq!(written.len(), 5);
    for name in [
        "manifest.json",
        "brief.md",
        "rules.json",
        "left.trimmed.trace",
        "right.trimmed.trace",
    ] {
        assert!(dir.join(name).exists(), "missing {name}");
    }
    let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
    assert!(manifest.contains("\"format\": \"shirusu-probe-bundle\""));
    assert!(manifest.contains("\"discriminating\": true"));
    let brief = std::fs::read_to_string(dir.join("brief.md")).unwrap();
    assert!(brief.contains("kernel32!ReadFile"));
    assert!(
        brief.contains("kernel32!CreateFileW#0"),
        "brief shows the normalized object key"
    );

    // 6. トリム済み Trace 自体も適合性を保つ（切り詰めが形式を壊さない）。
    for name in ["left.trimmed.trace", "right.trimmed.trace"] {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let t = read(&bytes);
        let rep = shirusu_conformance::check_trace(&t);
        assert!(
            rep.conformant(),
            "trimmed {name} must conform: {}",
            rep.render_human(name)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn handle_renumbering_alone_produces_no_candidates() {
    let a = read(&record(0x100, true, true, 1_000));
    let b = read(&record(0x777, true, true, 9_999_999));
    let report = compare_traces(&a, &b);
    assert!(
        report.is_identical(),
        "renumbering must be normalized away: {:?}",
        report
            .candidates
            .iter()
            .map(|c| &c.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn missing_close_becomes_a_missing_call_probe() {
    let left = read(&record(0x100, true, true, 0));
    let right = read(&record(0x100, true, false, 0));
    let report = compare_traces(&left, &right);
    let idx = report
        .candidates
        .iter()
        .position(|c| {
            c.kind == CandidateKind::MissingCall && c.api.as_deref() == Some("kernel32!CloseHandle")
        })
        .expect("missing CloseHandle candidate");
    let bundle = build_bundle(
        &left,
        &right,
        &report,
        idx,
        &BundleOptions {
            name: "probe-missing-call-closehandle".into(),
            left_label: "windows.trace".into(),
            right_label: "sake.trace".into(),
        },
    )
    .unwrap();
    assert!(bundle.has_discriminating_rule());
    let spec = shirusu_test::TestSpec::parse(bundle.rules_json.as_ref().unwrap()).unwrap();
    assert!(shirusu_test::evaluate(&spec, &left).all_passed());
    assert!(!shirusu_test::evaluate(&spec, &right).all_passed());
    assert_eq!(bundle.trim_reproduced, Some(true));
}

#[test]
fn payload_only_difference_is_brief_only_honestly() {
    // 引数・戻り値は一致し、ReadFile の Payload（Blob）内容だけが
    // 違うペア。v1 ルールには Payload を見る規則が無いため、
    // バンドルは「ルール化できない」ことを正直に記録する。
    let left = read(&record(0x100, true, true, 0));
    // sake 側は同じ流れだが、ReadFile の Payload だけ別内容で記録する。
    let right = read(&record_with_payload(0x100, true, true, 0, b"DATB"));
    let report = compare_traces(&left, &right);
    assert_eq!(
        report.candidates.len(),
        1,
        "candidates: {:?}",
        report.candidates
    );
    assert_eq!(report.candidates[0].kind, CandidateKind::PayloadDifference);
    let bundle = build_bundle(
        &left,
        &right,
        &report,
        0,
        &BundleOptions {
            name: "probe-payload-difference-readfile".into(),
            left_label: "windows.trace".into(),
            right_label: "sake.trace".into(),
        },
    )
    .unwrap();
    assert!(
        !bundle.has_discriminating_rule(),
        "payload differences cannot be expressed in v1 rules"
    );
    assert!(bundle.rules_json.is_none());
    assert!(
        bundle.brief_md.contains("識別ルール化できなかった"),
        "brief must state the limitation honestly"
    );
    // トリムは Payload の差分も保持する（Blob を一緒に切り詰める）。
    assert_eq!(bundle.trim_reproduced, Some(true));
}
