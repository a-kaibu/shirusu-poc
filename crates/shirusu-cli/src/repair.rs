//! `shirusu repair`（L12）。

use super::*;

// ---------------------------------------------------------------------------
// L12: `shirusu repair`
//
// 回復読み（F11）で読めたイベントだけを新しい Trace に書き出す。
// 正常なチャンクと参照関係を検証し、読めるイベントを回収する。
// 失われたイベントを推測で作らない（overview「完全性と復旧」）。
//
// 回収できないもの（数えて報告する）：
// - 参照先 Blob がファイル内に無いイベント（MissingBlob）。
//   Blob の内容を推測して補うことはしない。
// - Header と session_id が異なる Batch（SessionMismatch）。
//   session_id を書き換えて取り込むことはしない。
// - 同一スレッドで sequence が退行する Batch。Writer の不変条件に
//   反するため、順序を並べ替えて取り込むことはしない。
// - 空の Batch。
//
// 出力に残すもの：読めたイベント（元の Batch 順・元の内容のまま）、
// 参照された Blob（内容の BLAKE3 から同じ ID を再計算する。重複排除
// 済み）、Schema 定義、Loss Record。Blob の部分的な更新（F18）は
// 再発行しない。派生版の内容は `blobs` へ具体化済みで、イベントが
// 参照する版 ID の内容を `add_payload` で運べば十分なため。更新の
// 履歴そのものは修復出力には残らない。
//
// Finalization は元の Trace の三つの指標を引き継ぐ。ただし修復で
// イベントを失った場合、Complete の宣言は維持できないため
// event_integrity を Degraded（1）へ落とす。Finalization が無い
// 入力は三つとも Unknown（3）とする。修復の来歴は notes に残す。
// ---------------------------------------------------------------------------

/// repair の集計。`lost_by_cause` は初出順。
#[derive(Default)]
pub(crate) struct RepairReport {
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) scanned: u64,
    pub(crate) recovered: u64,
    pub(crate) lost: u64,
    pub(crate) batches_written: usize,
    pub(crate) batches_skipped: usize,
    pub(crate) blobs_carried: usize,
    pub(crate) schemas_registered: usize,
    pub(crate) schemas_skipped: usize,
    pub(crate) loss_records: usize,
    pub(crate) issues: Vec<String>,
    pub(crate) lost_by_cause: Vec<(String, u64)>,
}

pub(crate) fn add_lost(report: &mut RepairReport, cause: &str, n: u64) {
    report.lost += n;
    if let Some(entry) = report.lost_by_cause.iter_mut().find(|(c, _)| c == cause) {
        entry.1 += n;
    } else {
        report.lost_by_cause.push((cause.to_string(), n));
    }
}

/// view.rs の IntegritySummary と同じ文字列で issue を表す。
/// 新しい RecoveryIssue バリアントが増えたらここも非網羅マッチで
/// コンパイルエラーになる（view.rs と同じ方針）。
pub(crate) fn format_issue(issue: &RecoveryIssue) -> String {
    match issue {
        RecoveryIssue::TruncatedTail { offset } => {
            format!("truncated_tail(offset={offset})")
        }
        RecoveryIssue::CorruptBlock { offset, reason } => {
            format!("corrupt_block(offset={offset}, reason={reason})")
        }
        RecoveryIssue::Resync { from, to } => format!("resync({from}..{to})"),
        RecoveryIssue::DuplicateBlob { id } => format!("duplicate_blob({id})"),
        RecoveryIssue::BlobHashMismatch { id, computed } => {
            format!("blob_hash_mismatch(id={id}, computed={computed})")
        }
        RecoveryIssue::MissingBlob { id } => format!("missing_blob({id})"),
        RecoveryIssue::ForwardBlobReference { id } => {
            format!("forward_blob_reference({id})")
        }
        RecoveryIssue::IndexMismatch => "index_mismatch".to_string(),
        RecoveryIssue::LimitExceeded { what } => format!("limit_exceeded({what})"),
        RecoveryIssue::SessionMismatch {
            what,
            expected,
            found,
        } => {
            format!("session_mismatch(what={what}, expected={expected}, found={found})")
        }
        RecoveryIssue::BlobUpdateMissingBase { resource_id } => {
            format!("blob_update_missing_base(resource={resource_id})")
        }
        RecoveryIssue::BlobUpdateOutOfRange {
            resource_id,
            offset,
            size,
            base_len,
        } => {
            format!(
                "blob_update_out_of_range(resource={resource_id}, offset={offset}, size={size}, base_len={base_len})"
            )
        }
        RecoveryIssue::BlobUpdateHashMismatch {
            resource_id,
            expected,
            computed,
        } => {
            format!(
                "blob_update_hash_mismatch(resource={resource_id}, expected={expected}, computed={computed})"
            )
        }
    }
}

/// 回復読み済みの Trace から修復済み Trace のバイト列と報告を作る。
/// 途中で失敗しても部分的な出力ファイルは作らない（呼び出し側が
/// 返されたバイト列を書き出すまでは、ファイルは作られない）。
pub(crate) fn repair_trace(
    input: &str,
    trace: &ReadTrace,
) -> Result<(Vec<u8>, RepairReport), ToolError> {
    let mut report = RepairReport {
        input: input.to_string(),
        scanned: trace.total_events(),
        issues: trace.issues.iter().map(format_issue).collect(),
        ..Default::default()
    };
    // Environment が無い入力でも Header の session_id だけは分かる
    // ため、空の Environment で Writer を作る（元の session_id を保つ）。
    let env = match &trace.environment {
        Some(env) => env.clone(),
        None => CaptureEnvironment {
            session: SessionMetadata {
                session_id: trace.header.session_id,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut writer = TraceWriter::new(Vec::new(), env)
        .map_err(|e| ToolError::Runtime(format!("cannot start repaired trace: {e}")))?;
    // Schema は同一内容の再登録は受理される。内容の違う再定義や
    // content_hash の不一致は Writer が拒否するため、その定義だけ
    // 落として数える（修復全体は止めない）。
    for def in &trace.schemas {
        match writer.register_schema(def.clone()) {
            Ok(()) => report.schemas_registered += 1,
            Err(_) => report.schemas_skipped += 1,
        }
    }
    let mut carried: HashSet<BlobId> = HashSet::new();
    let mut last_sequence_by_thread: HashMap<u64, u64> = HashMap::new();
    for batch in &trace.batches {
        if batch.events.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        if batch.session_id != trace.header.session_id {
            report.batches_skipped += 1;
            add_lost(&mut report, "session_mismatch", batch.events.len() as u64);
            continue;
        }
        // 参照先 Blob が無いイベントは落とす（内容を推測しない）。
        let mut kept: Vec<TraceEvent> = Vec::new();
        for e in &batch.events {
            if let PayloadRef::Blob(id) = &e.payload {
                if !trace.blobs.contains_key(id) {
                    add_lost(&mut report, "missing_blob", 1);
                    continue;
                }
            }
            kept.push(e.clone());
        }
        if kept.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        // シーケンス退行の事前検査。Writer の validate_batch と同じ
        // 規則（スレッドごとに単調。書けた Batch だけが水位を進める）。
        let mut prev = last_sequence_by_thread.get(&batch.thread_id).copied();
        let mut regressed = false;
        for e in &kept {
            if let Some(p) = prev {
                if e.sequence < p {
                    regressed = true;
                    break;
                }
            }
            prev = Some(e.sequence);
        }
        if regressed {
            report.batches_skipped += 1;
            add_lost(&mut report, "sequence_regression", kept.len() as u64);
            continue;
        }
        for e in &kept {
            if let PayloadRef::Blob(id) = &e.payload {
                let data = &trace.blobs[id];
                writer
                    .add_payload(data)
                    .map_err(|err| ToolError::Runtime(format!("cannot carry blob {id}: {err}")))?;
                carried.insert(*id);
            }
        }
        let filtered = EventBatch {
            session_id: batch.session_id,
            process_id: batch.process_id,
            raw_pid: batch.raw_pid,
            thread_id: batch.thread_id,
            qpc_frequency: batch.qpc_frequency,
            events: kept,
        };
        match writer.write_batch(&filtered) {
            Ok(()) => {
                report.batches_written += 1;
                report.recovered += filtered.events.len() as u64;
                if let Some(last) = filtered.events.last() {
                    last_sequence_by_thread.insert(batch.thread_id, last.sequence);
                }
            }
            Err(err) => {
                // 事前検査をすり抜けた Writer 側の拒否。Batch ごと落とし、
                // 理由を issue として残す（推測で補わない）。
                report.batches_skipped += 1;
                add_lost(&mut report, "write_failed", filtered.events.len() as u64);
                report.issues.push(format!(
                    "write_failed(thread={}, reason={err})",
                    batch.thread_id
                ));
            }
        }
    }
    report.blobs_carried = carried.len();
    writer
        .write_loss_records(&trace.loss_records)
        .map_err(|e| ToolError::Runtime(format!("cannot write loss records: {e}")))?;
    report.loss_records = trace.loss_records.len();
    let (capture_coverage, mut event_integrity, semantic_completeness, mut notes) =
        match &trace.finalization {
            Some(f) => (
                f.capture_coverage,
                f.event_integrity,
                f.semantic_completeness,
                f.notes.clone(),
            ),
            None => (3, 3, 3, Vec::new()),
        };
    if report.lost > 0 && event_integrity == 0 {
        event_integrity = 1;
    }
    notes.push(format!(
        "repaired from {}: {} events recovered, {} lost; {} recovery issues",
        input,
        report.recovered,
        report.lost,
        report.issues.len()
    ));
    let bytes = writer
        .finish(FinalizationInfo {
            capture_coverage,
            event_integrity,
            semantic_completeness,
            notes,
        })
        .map_err(|e| ToolError::Runtime(format!("cannot finish repaired trace: {e}")))?;
    Ok((bytes, report))
}

pub(crate) fn repair_lines(report: &RepairReport) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("repaired: {} -> {}", report.input, report.output));
    out.push(format!(
        "events: {} recovered, {} lost (scanned {})",
        report.recovered, report.lost, report.scanned
    ));
    out.push(format!(
        "batches: {} written, {} skipped",
        report.batches_written, report.batches_skipped
    ));
    out.push(format!("blobs: {} carried over", report.blobs_carried));
    let mut schemas = format!("schemas: {} registered", report.schemas_registered);
    if report.schemas_skipped > 0 {
        schemas.push_str(&format!(", {} skipped", report.schemas_skipped));
    }
    out.push(schemas);
    out.push(format!("loss_records: {} preserved", report.loss_records));
    out.push(format!("recovery_issues: {}", report.issues.len()));
    for issue in &report.issues {
        out.push(format!("  - {issue}"));
    }
    if report.lost > 0 {
        out.push("lost_events:".into());
        for (cause, count) in &report.lost_by_cause {
            out.push(format!("  - {cause}: {count}"));
        }
    }
    out
}

pub(crate) fn repair_json(report: &RepairReport) -> JsonValue {
    JsonValue::obj(vec![
        ("input", JsonValue::Str(report.input.clone())),
        ("output", JsonValue::Str(report.output.clone())),
        (
            "events",
            JsonValue::obj(vec![
                ("recovered", JsonValue::U64(report.recovered)),
                ("lost", JsonValue::U64(report.lost)),
                ("scanned", JsonValue::U64(report.scanned)),
            ]),
        ),
        (
            "batches",
            JsonValue::obj(vec![
                ("written", JsonValue::U64(report.batches_written as u64)),
                ("skipped", JsonValue::U64(report.batches_skipped as u64)),
            ]),
        ),
        ("blobs_carried", JsonValue::U64(report.blobs_carried as u64)),
        (
            "schemas",
            JsonValue::obj(vec![
                (
                    "registered",
                    JsonValue::U64(report.schemas_registered as u64),
                ),
                ("skipped", JsonValue::U64(report.schemas_skipped as u64)),
            ]),
        ),
        (
            "loss_records_preserved",
            JsonValue::U64(report.loss_records as u64),
        ),
        (
            "recovery_issues",
            JsonValue::Array(report.issues.iter().cloned().map(JsonValue::Str).collect()),
        ),
        (
            "lost_by_cause",
            JsonValue::Array(
                report
                    .lost_by_cause
                    .iter()
                    .map(|(cause, count)| {
                        JsonValue::obj(vec![
                            ("cause", JsonValue::Str(cause.clone())),
                            ("count", JsonValue::U64(*count)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn cmd_repair(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&["json", "output"])?;
    let (input, trace) = load_trace(&parsed)?;
    let output = match parsed.opt("output") {
        Some(path) => path.to_string(),
        None => format!("{input}.repaired"),
    };
    let mut file = prepare_output(&input, &output)?;
    let (bytes, mut report) = repair_trace(&input, &trace)?;
    file.write_all(&bytes)
        .map_err(|e| ToolError::Runtime(format!("cannot write {output}: {e}")))?;
    file.persist(&output)
        .map_err(|e| ToolError::Runtime(format!("cannot publish repaired trace {output}: {e}")))?;
    report.output = output;
    if parsed.has("json") {
        println!("{}", repair_json(&report).render_pretty());
    } else {
        for line in repair_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}
