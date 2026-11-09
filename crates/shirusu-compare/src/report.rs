//! 比較結果の描画（人間向け要約と JSON）。どちらの形式にも
//! `CANDIDATE_NOTICE`（候補であって断定ではない旨）を必ず含める。

use crate::diff::{Candidate, DiffReport, Severity, CANDIDATE_NOTICE};
use shirusu_analysis::JsonValue;

pub fn render_human(report: &DiffReport, left_label: &str, right_label: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "shirusu-compare: {left_label} (left) vs {right_label} (right)\n"
    ));
    out.push_str(&format!(
        "events: left={} right={}; calls: left={} right={}\n",
        report.left_events, report.right_events, report.left_calls, report.right_calls
    ));
    out.push_str(&format!(
        "objects: left={} right={} paired={}\n",
        report.left_objects, report.right_objects, report.paired_objects
    ));
    out.push_str(&format!(
        "candidates: {} (high={} medium={} low={} info={})\n",
        report.candidates.len(),
        report.count_by_severity(Severity::High),
        report.count_by_severity(Severity::Medium),
        report.count_by_severity(Severity::Low),
        report.count_by_severity(Severity::Info),
    ));
    for c in &report.candidates {
        out.push_str(&format!(
            "\n[{}] {} {}\n",
            c.severity.name(),
            c.kind.name(),
            c.message
        ));
        if let Some(ev) = &c.left_event {
            out.push_str(&format!(
                "  left: thread={} seq={} api={}\n",
                ev.thread, ev.sequence, ev.api
            ));
        }
        if let Some(ev) = &c.right_event {
            out.push_str(&format!(
                "  right: thread={} seq={} api={}\n",
                ev.thread, ev.sequence, ev.api
            ));
        }
    }
    if !report.api_counts.is_empty() {
        out.push_str("\napi call counts (left/right):\n");
        for (api, (l, r)) in &report.api_counts {
            out.push_str(&format!("  {api}: {l}/{r}\n"));
        }
    }
    out.push_str(&format!("\nnote: {CANDIDATE_NOTICE}\n"));
    out
}

pub fn report_json(report: &DiffReport, left_label: &str, right_label: &str) -> JsonValue {
    let candidate_json = |c: &Candidate| {
        let ev = |e: &crate::diff::EventEvidence| {
            JsonValue::obj(vec![
                ("side", JsonValue::Str(e.side.to_string())),
                ("thread", JsonValue::U64(e.thread as u64)),
                ("sequence", JsonValue::U64(e.sequence)),
                ("api", JsonValue::Str(e.api.clone())),
            ])
        };
        JsonValue::obj(vec![
            ("kind", JsonValue::Str(c.kind.name().to_string())),
            ("severity", JsonValue::Str(c.severity.name().to_string())),
            ("message", JsonValue::Str(c.message.clone())),
            (
                "api",
                c.api.clone().map(JsonValue::Str).unwrap_or(JsonValue::Null),
            ),
            (
                "object",
                c.object
                    .as_ref()
                    .map(|o| JsonValue::Str(o.describe()))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "field",
                c.field
                    .clone()
                    .map(JsonValue::Str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "left_value",
                c.left_value
                    .clone()
                    .map(JsonValue::Str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "right_value",
                c.right_value
                    .clone()
                    .map(JsonValue::Str)
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "left_event",
                c.left_event.as_ref().map(ev).unwrap_or(JsonValue::Null),
            ),
            (
                "right_event",
                c.right_event.as_ref().map(ev).unwrap_or(JsonValue::Null),
            ),
        ])
    };
    let counts = |sev: Severity| JsonValue::U64(report.count_by_severity(sev) as u64);
    JsonValue::obj(vec![
        ("tool", JsonValue::Str("shirusu-compare".into())),
        ("left", JsonValue::Str(left_label.to_string())),
        ("right", JsonValue::Str(right_label.to_string())),
        ("notice", JsonValue::Str(CANDIDATE_NOTICE.to_string())),
        (
            "summary",
            JsonValue::obj(vec![
                ("left_events", JsonValue::U64(report.left_events as u64)),
                ("right_events", JsonValue::U64(report.right_events as u64)),
                ("left_calls", JsonValue::U64(report.left_calls as u64)),
                ("right_calls", JsonValue::U64(report.right_calls as u64)),
                ("left_objects", JsonValue::U64(report.left_objects as u64)),
                ("right_objects", JsonValue::U64(report.right_objects as u64)),
                (
                    "paired_objects",
                    JsonValue::U64(report.paired_objects as u64),
                ),
                ("candidates", JsonValue::U64(report.candidates.len() as u64)),
                ("high", counts(Severity::High)),
                ("medium", counts(Severity::Medium)),
                ("low", counts(Severity::Low)),
                ("info", counts(Severity::Info)),
            ]),
        ),
        (
            "candidates",
            JsonValue::Array(report.candidates.iter().map(candidate_json).collect()),
        ),
        (
            "api_counts",
            JsonValue::Object(
                report
                    .api_counts
                    .iter()
                    .map(|(api, (l, r))| {
                        (
                            api.clone(),
                            JsonValue::obj(vec![
                                ("left", JsonValue::U64(*l as u64)),
                                ("right", JsonValue::U64(*r as u64)),
                            ]),
                        )
                    })
                    .collect(),
            ),
        ),
    ])
}
