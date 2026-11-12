//! ルール評価：仕様を Trace に対して判定し、規則ごとの pass/fail と
//! 根拠（何を見て、なぜそう判定したか）を返す。
//!
//! 評価は記録の範囲内でのみ行う。例えば `api-called` の失敗は
//! 「記録の中にその呼び出しが無い」ことを意味し、「実際には呼ばれ
//! なかった」ことまでは意味しない（Capture Coverage が欠けていれば
//! 記録自体が不完全でありうる）。その留保は各ルールの detail に
//! 必要な範囲で書く。

use crate::spec::{Rule, TestSpec};
use shirusu_analysis::{EventView, JsonValue, TraceView};
use shirusu_compare::NormTrace;
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{TypedValue, ValueCapture};

/// ルール 1 件の結果。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleResult {
    pub rule: String,
    pub passed: bool,
    pub detail: String,
}

/// 仕様全体の結果。
#[derive(Debug, Clone)]
pub struct TestReport {
    pub spec_name: String,
    pub results: Vec<RuleResult>,
}

impl TestReport {
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::obj(vec![
            ("tool", JsonValue::Str("shirusu-test".into())),
            ("spec", JsonValue::Str(self.spec_name.clone())),
            ("passed", JsonValue::Bool(self.all_passed())),
            (
                "results",
                JsonValue::Array(
                    self.results
                        .iter()
                        .map(|r| {
                            JsonValue::obj(vec![
                                ("rule", JsonValue::Str(r.rule.clone())),
                                ("passed", JsonValue::Bool(r.passed)),
                                ("detail", JsonValue::Str(r.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("shirusu-test: spec {:?}\n", self.spec_name));
        for r in &self.results {
            out.push_str(&format!(
                "{} {} — {}\n",
                if r.passed { "PASS" } else { "FAIL" },
                r.rule,
                r.detail
            ));
        }
        out.push_str(&format!(
            "result: {}\n",
            if self.all_passed() {
                "all rules passed"
            } else {
                "some rules failed"
            }
        ));
        out
    }
}

pub fn evaluate(spec: &TestSpec, trace: &ReadTrace) -> TestReport {
    let view = TraceView::build(trace);
    let results = spec
        .rules
        .iter()
        .map(|rule| eval_rule(rule, trace, &view))
        .collect();
    TestReport {
        spec_name: spec.name.clone(),
        results,
    }
}

fn result(rule: &Rule, passed: bool, detail: String) -> RuleResult {
    RuleResult {
        rule: rule.describe(),
        passed,
        detail,
    }
}

fn eval_rule(rule: &Rule, trace: &ReadTrace, view: &TraceView) -> RuleResult {
    match rule {
        Rule::ApiCalled {
            api,
            field,
            equals,
            contains,
        } => eval_api_called(
            rule,
            view,
            api,
            field.as_deref(),
            equals.as_ref(),
            contains.as_deref(),
        ),
        Rule::NoIntegrityLoss => {
            let s = &view.integrity;
            let mut problems: Vec<String> = Vec::new();
            if !s.has_finalization {
                problems.push("no finalization block (integrity cannot be confirmed)".into());
            }
            for (aspect, level) in [
                ("capture_coverage", s.capture_coverage),
                ("event_integrity", s.event_integrity),
                ("semantic_completeness", s.semantic_completeness),
            ] {
                if let Some(level) = level {
                    if level != 0 {
                        problems.push(format!(
                            "{aspect} is {} ({level}), not Complete",
                            shirusu_analysis::integrity_level_name(level)
                        ));
                    }
                }
            }
            if !s.loss_records_by_kind.is_empty() {
                problems.push(format!(
                    "{} loss record(s) present",
                    s.loss_records_by_kind.values().sum::<u64>()
                ));
            }
            if s.dropped_payload_events > 0 {
                problems.push(format!("{} dropped payload(s)", s.dropped_payload_events));
            }
            if s.missing_blob_refs > 0 {
                problems.push(format!("{} missing blob reference(s)", s.missing_blob_refs));
            }
            if !s.finalized_cleanly {
                problems.push("trace was not finalized cleanly".into());
            }
            if !s.recovery_issues.is_empty() {
                problems.push(format!(
                    "{} reader recovery issue(s)",
                    s.recovery_issues.len()
                ));
            }
            if s.degraded_events > 0 {
                problems.push(format!("{} degraded event(s)", s.degraded_events));
            }
            if problems.is_empty() {
                result(
                    rule,
                    true,
                    "no loss recorded; all three levels Complete".into(),
                )
            } else {
                result(rule, false, problems.join("; "))
            }
        }
        Rule::ObjectClosed { created_by } => {
            let norm = NormTrace::build(trace);
            let created: Vec<_> = norm
                .objects
                .iter()
                .filter(|o| o.key.creator_api == *created_by)
                .collect();
            if created.is_empty() {
                return result(
                    rule,
                    false,
                    format!("no object is created by {created_by} in this trace"),
                );
            }
            let mut unclosed: Vec<String> = Vec::new();
            for obj in &created {
                let empty = Vec::new();
                let calls = norm.object_calls.get(&obj.key).unwrap_or(&empty);
                let closed = calls.iter().any(|&ci| {
                    let call = &norm.calls[ci];
                    // 生成呼び出し自身は数えない。
                    if call.created.as_ref() == Some(&obj.key) {
                        return false;
                    }
                    let Some(leave) = &call.leave else {
                        return false;
                    };
                    let Some(ret) = leave.fields.iter().find(|f| f.name == "return") else {
                        return false;
                    };
                    // Closing was attempted is not evidence that it succeeded.
                    match function_part(&call.api) {
                        "CloseHandle" | "CloseServiceHandle" | "CloseDesktop"
                        | "CloseWindowStation" | "FindClose" => {
                            matches!(ret.value, shirusu_compare::NormValue::Int(n) if n != 0)
                                || ret.value == shirusu_compare::NormValue::Bool(true)
                        }
                        "RegCloseKey" | "closesocket" => {
                            ret.value == shirusu_compare::NormValue::Int(0)
                        }
                        _ => false,
                    }
                });
                if !closed {
                    unclosed.push(obj.key.describe());
                }
            }
            if unclosed.is_empty() {
                result(
                    rule,
                    true,
                    format!(
                        "all {} object(s) created by {created_by} are closed",
                        created.len()
                    ),
                )
            } else {
                result(
                    rule,
                    false,
                    format!("unclosed object(s): {}", unclosed.join(", ")),
                )
            }
        }
        Rule::EventCount { min, max } => {
            let total = trace.total_events();
            let mut problems = Vec::new();
            if let Some(min) = min {
                if total < *min {
                    problems.push(format!("events {total} < min {min}"));
                }
            }
            if let Some(max) = max {
                if total > *max {
                    problems.push(format!("events {total} > max {max}"));
                }
            }
            if problems.is_empty() {
                result(rule, true, format!("events = {total}"))
            } else {
                result(rule, false, problems.join("; "))
            }
        }
    }
}

/// API 名（`kernel32!CloseHandle`）の関数部分（`CloseHandle`）。
fn function_part(api: &str) -> &str {
    api.rsplit('!').next().unwrap_or(api)
}

fn eval_api_called(
    rule: &Rule,
    view: &TraceView,
    api: &str,
    field: Option<&str>,
    equals: Option<&JsonValue>,
    contains: Option<&str>,
) -> RuleResult {
    let events: Vec<&EventView> = view
        .events
        .iter()
        .filter(|e| e.api_name.as_deref() == Some(api))
        .collect();
    if events.is_empty() {
        return result(
            rule,
            false,
            format!("no event for {api} in this trace (within what was captured)"),
        );
    }
    let Some(field_name) = field else {
        return result(rule, true, format!("{} event(s) recorded", events.len()));
    };
    let mut observed: Vec<String> = Vec::new();
    for ev in &events {
        let Some(f) = ev.field(field_name) else {
            continue;
        };
        if f.capture != ValueCapture::Captured {
            observed.push(format!(
                "<{}>",
                shirusu_analysis::view::value_capture_name(f.capture)
            ));
            continue;
        }
        observed.push(shirusu_analysis::view::format_value(&f.value));
        if let Some(want) = equals {
            if json_equals_typed(want, &f.value) {
                return result(
                    rule,
                    true,
                    format!(
                        "field {field_name} equals {} in event #{}",
                        want.render(),
                        ev.index
                    ),
                );
            }
        }
        if let Some(needle) = contains {
            if let Some(text) = typed_as_text(&f.value) {
                if text.contains(needle) {
                    return result(
                        rule,
                        true,
                        format!(
                            "field {field_name} contains {needle:?} in event #{}",
                            ev.index
                        ),
                    );
                }
            }
        }
    }
    if observed.is_empty() {
        result(
            rule,
            false,
            format!("no event of {api} carries field {field_name}"),
        )
    } else {
        result(
            rule,
            false,
            format!(
                "field {field_name} present but condition not met (observed: {})",
                observed.join(", ")
            ),
        )
    }
}

/// JSON 値と型付き値の等価（ルールの `equals` 用）。整数は幅を
/// またいで数値として比べ、文字列は Str/Str16 と比べる。
fn json_equals_typed(json: &JsonValue, value: &TypedValue) -> bool {
    match (json, value) {
        (JsonValue::U64(a), TypedValue::U64(b)) => a == b,
        (JsonValue::U64(a), TypedValue::U32(b)) => *a == *b as u64,
        (JsonValue::U64(a), TypedValue::I32(b)) => *b >= 0 && *a == *b as u64,
        (JsonValue::U64(a), TypedValue::I64(b)) => *b >= 0 && *a == *b as u64,
        (JsonValue::U64(a), TypedValue::Ptr32(b)) => *a == *b as u64,
        (JsonValue::U64(a), TypedValue::Ptr64(b)) => a == b,
        (JsonValue::I64(a), TypedValue::I32(b)) => *a == *b as i64,
        (JsonValue::I64(a), TypedValue::I64(b)) => a == b,
        (JsonValue::I64(a), TypedValue::U32(b)) => *a == *b as i64,
        (JsonValue::I64(a), TypedValue::U64(b)) => *b <= i64::MAX as u64 && *a == *b as i64,
        (JsonValue::Str(a), TypedValue::Str(b)) => a == b,
        (JsonValue::Str(a), TypedValue::Str16(b)) => a.encode_utf16().eq(b.iter().copied()),
        (JsonValue::Bool(a), TypedValue::Bool(b)) => a == b,
        (JsonValue::Object(fields), TypedValue::Str16(units)) if fields.len() == 1 => {
            fields[0].0 == "utf16"
                && json_units_equal(&fields[0].1, units.iter().map(|&v| u64::from(v)))
        }
        (JsonValue::Object(fields), TypedValue::Bytes(bytes)) if fields.len() == 1 => {
            fields[0].0 == "bytes"
                && json_units_equal(&fields[0].1, bytes.iter().map(|&v| u64::from(v)))
        }
        _ => false,
    }
}

fn json_units_equal(json: &JsonValue, units: impl Iterator<Item = u64>) -> bool {
    let JsonValue::Array(values) = json else {
        return false;
    };
    values
        .iter()
        .map(|v| match v {
            JsonValue::U64(n) => Some(*n),
            JsonValue::I64(n) => u64::try_from(*n).ok(),
            _ => None,
        })
        .eq(units.map(Some))
}

fn typed_as_text(value: &TypedValue) -> Option<String> {
    match value {
        TypedValue::Str(s) => Some(s.clone()),
        TypedValue::Str16(units) => String::from_utf16(units).ok(),
        _ => None,
    }
}
