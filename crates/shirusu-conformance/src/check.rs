//! 適合性検査：外部で生成された Trace が「形式仕様＋compare/test が
//! 依存する規約」を満たすかを検証する。
//!
//! 検査は `ReadTrace`（Reader の回復読み結果）に対して行う。前提
//! として、Reader が受理できない入力（先頭が Header Block でない）
//! は Trace ではないので検査以前の問題であり、CLI はその旨を
//! 1 件の Fail として報告する。
//!
//! 各検査は独立した Finding を返し、レポートの合否は「Fail が
//! 1 件も無いこと」で決まる。Warn は適合を妨げないが、契約の
//! 解釈が割れる境界（sequence の重複）を示すために残す。
//!
//! 検査項目と、壊れたときに何が困るか（＝誰がこの規約に依存
//! しているか）:
//!
//! - clean-scan: Reader が破損を記録していないこと。破損した
//!   Trace は「読めた範囲」の比較しかできず、差分の根拠にできない。
//! - environment: CaptureEnvironment があり、生成者（created_by）
//!   が特定できること。由来不明の Trace は取り込まない。
//! - finalization: Finalization があり正常終了が宣言されている
//!   こと。無い Trace は完全性を確定できず、shirusu-test の
//!   no-integrity-loss が常に失敗する。
//! - finalization-counts: Finalization の総数が実内容と一致する
//!   こと（書き手の自己申告と実体の乖離は改竄/バグの兆候）。
//! - schemas-registered: 全イベントの Schema が登録済みで、
//!   引数値列が Schema で復号できること。compare は Schema 名から
//!   API 名を引くため、未登録は「比較できないイベント」になる。
//! - sequence-monotonic: スレッドごとの sequence が後退しない
//!   こと（形式仕様と Writer の不変条件）。重複は Warn。
//! - enter-leave-pairing: Enter/Leave が call_id で対応すること。
//!   対応しない Leave、終了しない Enter は compare の呼び出し
//!   構築を壊す。記録が途中で終わった呼び出しは Leave を捏造
//!   せず、Loss Record（UNKNOWN_TERMINATION）で表すのが規約。
//! - blob-refs-resolvable: Payload / BlobRef の参照先 Blob が
//!   ファイル内に実在すること。解決できない参照は Payload 比較を
//!   「不明」にする。
//! - integrity-consistent: 完全性 3 指標の自己申告が記録内容と
//!   矛盾しないこと（Complete を名乗りながら損失が記録されて
//!   いる、等）。Capture Coverage の真偽は Trace の中からは
//!   検証できない（何を Hook できなかったかは記録に残らない）
//!   ため、範囲外であることを明記するに留める。

use shirusu_analysis::{JsonValue, Phase, TraceView};
use shirusu_trace::model::PayloadRef;
use shirusu_trace::proto::integrity_level;
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::schema::{EventCapture, TypedValue};
use std::collections::{HashMap, HashSet};

/// 検査 1 件の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn name(self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

/// 検査 1 件の所見。
#[derive(Debug, Clone, PartialEq)]
pub struct CheckFinding {
    pub id: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

impl CheckFinding {
    fn pass(id: &'static str, detail: String) -> Self {
        CheckFinding {
            id,
            status: CheckStatus::Pass,
            detail,
        }
    }
    fn warn(id: &'static str, detail: String) -> Self {
        CheckFinding {
            id,
            status: CheckStatus::Warn,
            detail,
        }
    }
    fn fail(id: &'static str, detail: String) -> Self {
        CheckFinding {
            id,
            status: CheckStatus::Fail,
            detail,
        }
    }
}

/// 検査レポート全体。`conformant` が取り込み可否の判定。
#[derive(Debug, Clone, PartialEq)]
pub struct ConformanceReport {
    pub findings: Vec<CheckFinding>,
}

impl ConformanceReport {
    pub fn conformant(&self) -> bool {
        self.findings.iter().all(|f| f.status != CheckStatus::Fail)
    }

    pub fn finding(&self, id: &str) -> Option<&CheckFinding> {
        self.findings.iter().find(|f| f.id == id)
    }

    pub fn render_human(&self, label: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("shirusu-conformance: {label}\n"));
        for f in &self.findings {
            out.push_str(&format!(
                "{} {} — {}\n",
                f.status.name().to_uppercase(),
                f.id,
                f.detail
            ));
        }
        out.push_str(&format!(
            "result: {}\n",
            if self.conformant() {
                "conformant"
            } else {
                "NON-CONFORMANT"
            }
        ));
        out
    }

    pub fn to_json(&self, label: &str) -> JsonValue {
        JsonValue::obj(vec![
            ("tool", JsonValue::Str("shirusu-conformance".into())),
            ("trace", JsonValue::Str(label.to_string())),
            ("conformant", JsonValue::Bool(self.conformant())),
            (
                "checks",
                JsonValue::Array(
                    self.findings
                        .iter()
                        .map(|f| {
                            JsonValue::obj(vec![
                                ("id", JsonValue::Str(f.id.to_string())),
                                ("status", JsonValue::Str(f.status.name().to_string())),
                                ("detail", JsonValue::Str(f.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

/// Trace の適合性を検査する。
pub fn check_trace(trace: &ReadTrace) -> ConformanceReport {
    let view = TraceView::build(trace);
    ConformanceReport {
        findings: vec![
            check_clean_scan(trace),
            check_environment(trace),
            check_finalization(trace),
            check_finalization_counts(trace),
            check_schemas(trace, &view),
            check_sequence_monotonic(trace),
            check_enter_leave_pairing(&view),
            check_blob_refs(trace, &view),
            check_integrity_consistency(trace, &view),
        ],
    }
}

fn check_clean_scan(trace: &ReadTrace) -> CheckFinding {
    let id = "clean-scan";
    let damaging: Vec<String> = trace
        .issues
        .iter()
        .filter_map(|i| match i {
            RecoveryIssue::CorruptBlock { offset, reason } => {
                Some(format!("corrupt block at {offset}: {reason}"))
            }
            RecoveryIssue::TruncatedTail { offset } => Some(format!("truncated tail at {offset}")),
            RecoveryIssue::DuplicateBlob { id: blob } => Some(format!("duplicate blob {blob}")),
            RecoveryIssue::IndexMismatch => Some("stored index does not match scan".into()),
            RecoveryIssue::LimitExceeded { what } => Some(format!("reader limit exceeded: {what}")),
            RecoveryIssue::Resync { .. } | RecoveryIssue::MissingBlob { .. } => None,
        })
        .collect();
    if damaging.is_empty() {
        CheckFinding::pass(id, "reader scan reported no damaged blocks".into())
    } else {
        CheckFinding::fail(
            id,
            format!(
                "{} damaging issue(s): {}",
                damaging.len(),
                damaging.join("; ")
            ),
        )
    }
}

fn check_environment(trace: &ReadTrace) -> CheckFinding {
    let id = "environment";
    let Some(env) = &trace.environment else {
        return CheckFinding::fail(id, "no CaptureEnvironment block".into());
    };
    if env.session.session_id != trace.header.session_id {
        return CheckFinding::fail(
            id,
            format!(
                "environment session_id {} != header session_id {}",
                env.session.session_id, trace.header.session_id
            ),
        );
    }
    if env.session.created_by.trim().is_empty() {
        return CheckFinding::fail(
            id,
            "created_by is empty (the producing implementation must identify itself)".into(),
        );
    }
    CheckFinding::pass(id, format!("produced by {:?}", env.session.created_by))
}

fn check_finalization(trace: &ReadTrace) -> CheckFinding {
    let id = "finalization";
    match &trace.finalization {
        None => CheckFinding::fail(
            id,
            "no Finalization block (integrity cannot be confirmed for this trace)".into(),
        ),
        Some(_) if !trace.finalized_cleanly => CheckFinding::fail(
            id,
            "Finalization block is present but the trace did not end cleanly".into(),
        ),
        Some(fin) => CheckFinding::pass(
            id,
            format!(
                "finalized cleanly: events={} blobs={} loss_records={}",
                fin.total_events, fin.total_blobs, fin.total_loss_records
            ),
        ),
    }
}

fn check_finalization_counts(trace: &ReadTrace) -> CheckFinding {
    let id = "finalization-counts";
    let Some(fin) = &trace.finalization else {
        return CheckFinding::fail(id, "no Finalization block to verify counts against".into());
    };
    let mut problems = Vec::new();
    let events = trace.total_events();
    if fin.total_events != events {
        problems.push(format!(
            "total_events: declared {}, actual {events}",
            fin.total_events
        ));
    }
    if fin.total_loss_records != trace.loss_records.len() as u64 {
        problems.push(format!(
            "total_loss_records: declared {}, actual {}",
            fin.total_loss_records,
            trace.loss_records.len()
        ));
    }
    if fin.total_blobs != trace.blobs.len() as u64 {
        problems.push(format!(
            "total_blobs: declared {}, actual {}",
            fin.total_blobs,
            trace.blobs.len()
        ));
    }
    if problems.is_empty() {
        CheckFinding::pass(id, "declared totals match the trace content".into())
    } else {
        CheckFinding::fail(id, problems.join("; "))
    }
}

fn check_schemas(trace: &ReadTrace, view: &TraceView) -> CheckFinding {
    let id = "schemas-registered";
    let mut problems: Vec<String> = Vec::new();
    for batch in &trace.batches {
        for e in &batch.events {
            if e.schema_id == 0 {
                if e.args.is_some() {
                    problems.push(format!(
                        "event seq={} carries args with schema_id 0",
                        e.sequence
                    ));
                }
                continue;
            }
            if trace.registry.get(e.schema_id).is_none() {
                problems.push(format!(
                    "event seq={} references unregistered schema {}",
                    e.sequence, e.schema_id
                ));
            }
        }
    }
    for ev in &view.events {
        if let Some(err) = &ev.args_error {
            problems.push(format!("event #{} args: {err}", ev.index));
        }
        if ev.schema_id != 0 && ev.api_name.is_none() {
            problems.push(format!("event #{} has no resolvable api name", ev.index));
        }
    }
    if problems.is_empty() {
        CheckFinding::pass(
            id,
            format!(
                "{} schema(s) registered; all event args decode",
                trace.registry.len()
            ),
        )
    } else {
        let shown = problems.len().min(5);
        CheckFinding::fail(
            id,
            format!(
                "{} problem(s): {}",
                problems.len(),
                problems[..shown].join("; ")
            ),
        )
    }
}

/// スレッド文脈のキー（形式上のスレッド同一性）。
type ThreadKey = (u64, u64, u64);

fn thread_key(session_id: u64, process_id: u64, thread_id: u64) -> ThreadKey {
    (session_id, process_id, thread_id)
}

fn check_sequence_monotonic(trace: &ReadTrace) -> CheckFinding {
    let id = "sequence-monotonic";
    let mut last: HashMap<ThreadKey, u64> = HashMap::new();
    let mut duplicates = 0usize;
    for batch in &trace.batches {
        let key = thread_key(batch.session_id, batch.process_id, batch.thread_id);
        for e in &batch.events {
            if let Some(prev) = last.get(&key).copied() {
                if e.sequence < prev {
                    return CheckFinding::fail(
                        id,
                        format!(
                            "sequence regressed on thread {}: {prev} -> {}",
                            batch.thread_id, e.sequence
                        ),
                    );
                }
                if e.sequence == prev {
                    duplicates += 1;
                }
            }
            last.insert(key, e.sequence);
        }
    }
    if duplicates > 0 {
        CheckFinding::warn(
            id,
            format!(
                "monotonic, but {duplicates} duplicate sequence value(s) within a thread \
                 (the format tolerates them; emitters should assign strictly increasing values)"
            ),
        )
    } else {
        CheckFinding::pass(id, "sequences strictly increase per thread".into())
    }
}

fn check_enter_leave_pairing(view: &TraceView) -> CheckFinding {
    let id = "enter-leave-pairing";
    // スレッドごとに、call_id の Enter が開いているかを数える。
    let mut open: HashMap<ThreadKey, HashMap<u64, usize>> = HashMap::new();
    for ev in &view.events {
        let key = thread_key(ev.session_id, ev.process_id, ev.thread_id);
        match ev.phase() {
            Phase::Enter => {
                *open.entry(key).or_default().entry(ev.call_id).or_default() += 1;
            }
            Phase::Leave => {
                let calls = open.entry(key).or_default();
                match calls.get_mut(&ev.call_id) {
                    Some(n) if *n > 0 => *n -= 1,
                    _ => {
                        return CheckFinding::fail(
                            id,
                            format!(
                                "leave for call {} on thread {} has no matching enter",
                                ev.call_id, ev.thread_id
                            ),
                        );
                    }
                }
            }
            Phase::Other(_) => {}
        }
    }
    let unclosed: Vec<String> = open
        .iter()
        .flat_map(|((_, _, tid), calls)| {
            calls
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(move |(cid, n)| format!("thread {tid} call {cid} x{n}"))
        })
        .collect();
    if unclosed.is_empty() {
        CheckFinding::pass(
            id,
            "every enter has a matching leave (by call_id, per thread)".into(),
        )
    } else {
        CheckFinding::fail(
            id,
            format!(
                "{} enter(s) never leave: {}. Calls cut off by the end of recording must be \
                 represented as Loss Records (kind=unknown_termination), not left open",
                unclosed.len(),
                unclosed.join(", ")
            ),
        )
    }
}

fn check_blob_refs(trace: &ReadTrace, view: &TraceView) -> CheckFinding {
    let id = "blob-refs-resolvable";
    let mut missing: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let note = |missing: &mut Vec<String>, seen: &mut HashSet<String>, what: String| {
        if seen.insert(what.clone()) {
            missing.push(what);
        }
    };
    for batch in &trace.batches {
        for e in &batch.events {
            if let PayloadRef::Blob(blob) = &e.payload {
                if !trace.blobs.contains_key(blob) {
                    note(
                        &mut missing,
                        &mut seen,
                        format!("payload blob {blob} (event seq={})", e.sequence),
                    );
                }
            }
        }
    }
    for ev in &view.events {
        for f in &ev.fields {
            if let TypedValue::BlobRef(blob) = &f.value {
                if !trace.blobs.contains_key(blob) {
                    note(
                        &mut missing,
                        &mut seen,
                        format!("field {} blob {} (event #{})", f.name, blob, ev.index),
                    );
                }
            }
        }
    }
    if missing.is_empty() {
        CheckFinding::pass(
            id,
            format!(
                "all blob references resolve ({} blob(s) in file)",
                trace.blobs.len()
            ),
        )
    } else {
        CheckFinding::fail(
            id,
            format!(
                "{} unresolvable reference(s): {}",
                missing.len(),
                missing.join("; ")
            ),
        )
    }
}

fn check_integrity_consistency(trace: &ReadTrace, view: &TraceView) -> CheckFinding {
    let id = "integrity-consistent";
    let Some(fin) = &trace.finalization else {
        return CheckFinding::fail(
            id,
            "no Finalization block (nothing to check consistency of)".into(),
        );
    };
    let mut problems: Vec<String> = Vec::new();
    for (aspect, level) in [
        ("capture_coverage", fin.capture_coverage),
        ("event_integrity", fin.event_integrity),
        ("semantic_completeness", fin.semantic_completeness),
    ] {
        if level > integrity_level::UNKNOWN {
            problems.push(format!("{aspect} has invalid level value {level}"));
        }
    }
    let s = &view.integrity;
    if fin.event_integrity == integrity_level::COMPLETE {
        if !trace.loss_records.is_empty() {
            problems.push(format!(
                "event_integrity claims Complete but {} loss record(s) are present",
                trace.loss_records.len()
            ));
        }
        if s.dropped_payload_events > 0 {
            problems.push(format!(
                "event_integrity claims Complete but {} payload(s) were dropped",
                s.dropped_payload_events
            ));
        }
    }
    if fin.semantic_completeness == integrity_level::COMPLETE {
        let degraded = view
            .events
            .iter()
            .filter(|e| e.capture != EventCapture::Captured)
            .count();
        if degraded > 0 {
            problems.push(format!(
                "semantic_completeness claims Complete but {degraded} event(s) are not fully captured"
            ));
        }
    }
    if problems.is_empty() {
        CheckFinding::pass(
            id,
            "declared integrity levels do not contradict the recorded content \
             (capture_coverage itself cannot be verified from inside a trace)"
                .into(),
        )
    } else {
        CheckFinding::fail(id, problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::container::FileHeader;
    use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
    use shirusu_trace::proto::{CaptureEnvironment, Finalization, SessionMetadata};
    use shirusu_trace::schema::{make_schema, EventCapture, SchemaRegistry, Ty};

    fn ev(kind: u16, sequence: u64, call_id: u64, schema_id: u32) -> TraceEvent {
        TraceEvent {
            kind,
            sequence,
            timestamp_qpc: sequence * 10,
            call_id,
            parent_call_id: 0,
            api_id: 1,
            schema_id,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
        }
    }

    /// 規約どおりの最小 Trace（メモリ内 ReadTrace）。
    /// CreateFileW 風の Enter/Leave 1 組だけを含む。
    fn valid_trace() -> ReadTrace {
        let mut registry = SchemaRegistry::new();
        registry
            .register(make_schema(1, "x!Y/enter", vec![("h".into(), Ty::U64, 0)]))
            .unwrap();
        registry
            .register(make_schema(
                2,
                "x!Y/leave",
                vec![
                    ("return".into(), Ty::U64, 0),
                    ("last_error".into(), Ty::U32, 0),
                ],
            ))
            .unwrap();
        let schemas: Vec<_> = registry
            .ids()
            .iter()
            .map(|id| registry.get(*id).unwrap().clone())
            .collect();
        ReadTrace {
            header: FileHeader::new(7),
            environment: Some(CaptureEnvironment {
                session: SessionMetadata {
                    session_id: 7,
                    created_by: "fabricated-test".into(),
                    qpc_frequency: 10_000_000,
                },
                ..Default::default()
            }),
            schemas,
            registry,
            batches: vec![EventBatch {
                session_id: 7,
                process_id: 1,
                raw_pid: 100,
                thread_id: 5,
                qpc_frequency: 10_000_000,
                events: vec![ev(1, 1, 1, 1), ev(2, 2, 1, 2)],
            }],
            blobs: Default::default(),
            loss_records: Vec::new(),
            stored_index: None,
            index_matches_scan: false,
            finalization: Some(Finalization {
                total_events: 2,
                ..Default::default()
            }),
            finalized_cleanly: true,
            blocks: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn status(report: &ConformanceReport, id: &str) -> CheckStatus {
        report
            .finding(id)
            .unwrap_or_else(|| panic!("no finding {id}"))
            .status
    }

    #[test]
    fn valid_trace_is_conformant() {
        let report = check_trace(&valid_trace());
        assert!(report.conformant(), "{}", report.render_human("t"));
        for f in &report.findings {
            assert_eq!(f.status, CheckStatus::Pass, "{}: {}", f.id, f.detail);
        }
    }

    #[test]
    fn unregistered_schema_fails_only_schema_check() {
        let mut t = valid_trace();
        t.batches[0].events[0].schema_id = 99;
        let report = check_trace(&t);
        assert!(!report.conformant());
        assert_eq!(status(&report, "schemas-registered"), CheckStatus::Fail);
        assert_eq!(status(&report, "sequence-monotonic"), CheckStatus::Pass);
        assert_eq!(status(&report, "enter-leave-pairing"), CheckStatus::Pass);
    }

    #[test]
    fn sequence_regression_fails_and_duplicate_warns() {
        let mut t = valid_trace();
        t.batches[0].events[1].sequence = 0;
        let report = check_trace(&t);
        assert_eq!(status(&report, "sequence-monotonic"), CheckStatus::Fail);

        let mut t = valid_trace();
        t.batches[0].events[1].sequence = 1;
        let report = check_trace(&t);
        assert_eq!(status(&report, "sequence-monotonic"), CheckStatus::Warn);
        assert!(report.conformant(), "warn does not break conformance");
    }

    #[test]
    fn pairing_violations_fail() {
        // Leave の欠落（Enter が開いたまま）。
        let mut t = valid_trace();
        t.batches[0].events.pop();
        t.finalization.as_mut().unwrap().total_events = 1;
        let report = check_trace(&t);
        assert_eq!(status(&report, "enter-leave-pairing"), CheckStatus::Fail);

        // 対応する Enter の無い Leave。
        let mut t = valid_trace();
        t.batches[0].events[0].call_id = 42;
        let report = check_trace(&t);
        assert_eq!(status(&report, "enter-leave-pairing"), CheckStatus::Fail);
    }

    #[test]
    fn missing_finalization_and_count_mismatch_fail() {
        let mut t = valid_trace();
        t.finalization = None;
        t.finalized_cleanly = false;
        let report = check_trace(&t);
        assert_eq!(status(&report, "finalization"), CheckStatus::Fail);
        assert_eq!(status(&report, "finalization-counts"), CheckStatus::Fail);

        let mut t = valid_trace();
        t.finalization.as_mut().unwrap().total_events = 5;
        let report = check_trace(&t);
        assert_eq!(status(&report, "finalization-counts"), CheckStatus::Fail);
        assert_eq!(status(&report, "finalization"), CheckStatus::Pass);
    }

    #[test]
    fn unresolvable_blob_fails() {
        let mut t = valid_trace();
        t.batches[0].events[1].payload =
            PayloadRef::Blob(shirusu_trace::BlobId::of_content(b"ghost"));
        let report = check_trace(&t);
        assert_eq!(status(&report, "blob-refs-resolvable"), CheckStatus::Fail);
    }

    #[test]
    fn integrity_claim_contradiction_fails() {
        let mut t = valid_trace();
        t.batches[0].events[1].payload = PayloadRef::Dropped {
            original_len: 10,
            reason: shirusu_trace::model::PayloadLossReason::Overflow,
        };
        let report = check_trace(&t);
        assert_eq!(status(&report, "integrity-consistent"), CheckStatus::Fail);
    }

    #[test]
    fn anonymous_or_missing_environment_fails() {
        let mut t = valid_trace();
        t.environment.as_mut().unwrap().session.created_by = "  ".into();
        let report = check_trace(&t);
        assert_eq!(status(&report, "environment"), CheckStatus::Fail);

        let mut t = valid_trace();
        t.environment = None;
        let report = check_trace(&t);
        assert_eq!(status(&report, "environment"), CheckStatus::Fail);
    }
}
