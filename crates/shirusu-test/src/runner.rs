//! JSON Runner: JSON 仕様の `steps` を解釈して実行する。
//!
//! 使い方:
//! - `RunMode::DryRun` — 計画だけを行い、呼び出し列の正しさ（呼び出し名・
//!   引数・`$ref`・期待値）を検証する。どの OS でも動く。
//! - `RunMode::Execute` — 計画のうえで実際に呼び出す。Windows でのみ
//!   動く。Windows 以外では誤りになる（`--dry-run` を使うこと）。
//!
//! 実行の意味論は `runner_exec` にあり、生成する Probe exe と共有する。
//! ここは仕様の受け取りと報告の形（`JsonValue` / 人間向け表示）だけを
//! 担う。実行結果の JSON の形は `runner_exec::report_to_json` と
//! 一致させること。両者の一致はテストで確かめる。

#[cfg(windows)]
use crate::runner_exec::execute_planned;
use crate::runner_exec::{
    dry_run_report, plan_steps, report_to_text, OutputValue, RunReportData, StepOutcome,
};
use crate::spec::TestSpec;
use shirusu_analysis::JsonValue;

/// Runner の動作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// 計画だけ（実行しない）。
    DryRun,
    /// 実際に呼び出す（Windows でのみ）。
    Execute,
}

/// Runner の報告。
#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    pub environment: Option<crate::runner_exec::RunEnvironment>,
    pub spec_name: String,
    pub executed: bool,
    pub all_ok: bool,
    pub outcomes: Vec<StepOutcome>,
}

impl RunReport {
    /// `runner_exec::report_to_json` と同じ形の JSON にする。
    pub fn to_json(&self) -> JsonValue {
        let data = RunReportData {
            environment: self.environment.clone(),
            spec_name: self.spec_name.clone(),
            executed: self.executed,
            all_ok: self.all_ok,
            steps: self.outcomes.clone(),
        };
        report_data_to_json(&data)
    }

    /// 人間向けの表示（`runner_exec::report_to_text` と同じ）。
    pub fn render_human(&self) -> String {
        let data = RunReportData {
            environment: self.environment.clone(),
            spec_name: self.spec_name.clone(),
            executed: self.executed,
            all_ok: self.all_ok,
            steps: self.outcomes.clone(),
        };
        report_to_text(&data)
    }
}

fn report_data_to_json(data: &RunReportData) -> JsonValue {
    let steps: Vec<JsonValue> = data
        .steps
        .iter()
        .map(|s| {
            let outputs: Vec<(String, JsonValue)> = s
                .outputs
                .iter()
                .map(|(n, v)| {
                    (
                        n.clone(),
                        match v {
                            OutputValue::U64(n) => JsonValue::U64(*n),
                            OutputValue::Hex(h) => JsonValue::Str(h.clone()),
                        },
                    )
                })
                .collect();
            JsonValue::obj(vec![
                ("index", JsonValue::U64(s.index as u64)),
                ("call", JsonValue::Str(s.call.clone())),
                ("ok", JsonValue::Bool(s.ok)),
                ("executed", JsonValue::Bool(s.executed)),
                (
                    "returned",
                    s.returned.map(JsonValue::U64).unwrap_or(JsonValue::Null),
                ),
                (
                    "last_error",
                    s.last_error
                        .map(|v| JsonValue::U64(v as u64))
                        .unwrap_or(JsonValue::Null),
                ),
                ("outputs", JsonValue::Object(outputs)),
                (
                    "outputs_truncated",
                    JsonValue::Array(
                        s.outputs_truncated
                            .iter()
                            .map(|n| JsonValue::Str(n.clone()))
                            .collect(),
                    ),
                ),
                (
                    "error",
                    s.error
                        .as_ref()
                        .map(|e| JsonValue::Str(e.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();
    let mut fields = vec![
        ("spec", JsonValue::Str(data.spec_name.clone())),
        ("executed", JsonValue::Bool(data.executed)),
        ("all_ok", JsonValue::Bool(data.all_ok)),
        ("steps", JsonValue::Array(steps)),
    ];
    if let Some(env) = &data.environment {
        fields.push((
            "environment",
            crate::json_parse::parse_json(&crate::runner_exec::environment_to_json(env))
                .expect("Runner environment serializer emits valid JSON"),
        ));
    }
    JsonValue::obj(fields)
}

/// 仕様を実行する。計画の誤り（呼び出し名・引数・`$ref`・期待値）は
/// `Err` で返す。Windows 以外での `Execute` も `Err` になる。
pub fn run_spec(spec: &TestSpec, mode: RunMode) -> Result<RunReport, String> {
    let planned = plan_steps(&spec.steps)?;
    match mode {
        RunMode::DryRun => {
            let data = dry_run_report(&spec.name, &planned);
            Ok(RunReport {
                environment: data.environment,
                spec_name: data.spec_name,
                executed: data.executed,
                all_ok: data.all_ok,
                outcomes: data.steps,
            })
        }
        RunMode::Execute => {
            #[cfg(not(windows))]
            {
                let _ = planned;
                Err("executing steps requires Windows (use --dry-run to validate the spec on this platform)"
                    .to_string())
            }
            #[cfg(windows)]
            {
                let data = execute_planned(&spec.name, &planned);
                Ok(RunReport {
                    environment: data.environment,
                    spec_name: data.spec_name,
                    executed: data.executed,
                    all_ok: data.all_ok,
                    outcomes: data.steps,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_parse::parse_json;
    use crate::runner_exec::report_to_json;

    const SPEC_JSON: &str = r#"{"version":1,"name":"sample","steps":[
        {"call":"kernel32!CreateFileW","args":{"lpFileName":"probe.txt","dwDesiredAccess":3221225472,"dwShareMode":0,"lpSecurityAttributes":null,"dwCreationDisposition":2,"dwFlagsAndAttributes":128,"hTemplateFile":null},"store":"hFile","expect":{"return":"nonzero"}},
        {"call":"kernel32!WriteFile","args":{"hFile":{"ref":"hFile"},"lpBuffer":{"buffer":5,"fill_text":"hello"},"nNumberOfBytesToWrite":5,"lpNumberOfBytesWritten":{"out":"u32"},"lpOverlapped":null}},
        {"call":"kernel32!CloseHandle","args":{"hObject":{"ref":"hFile"}}}
    ],"rules":[]}"#;

    fn spec() -> TestSpec {
        TestSpec::parse(SPEC_JSON).unwrap()
    }

    #[test]
    fn dry_run_reports_planned_steps() {
        let report = run_spec(&spec(), RunMode::DryRun).unwrap();
        assert_eq!(report.spec_name, "sample");
        assert!(!report.executed);
        assert!(report.all_ok);
        assert_eq!(report.outcomes.len(), 3);
        assert!(report.outcomes.iter().all(|o| !o.executed && o.ok));
        assert_eq!(report.outcomes[0].call, "kernel32!CreateFileW");
    }

    #[test]
    fn execute_on_non_windows_is_an_error() {
        // このテストは Linux で走る。Windows では実行経路に入るため、
        // ここでは到達しない（`#[cfg]` で分岐する）。
        #[cfg(not(windows))]
        {
            let err = run_spec(&spec(), RunMode::Execute).unwrap_err();
            assert!(err.contains("requires Windows"));
        }
    }

    #[test]
    fn plan_errors_surface() {
        let mut bad = spec();
        bad.steps[0].call = "kernel32!NoSuchApi".to_string();
        assert!(run_spec(&bad, RunMode::DryRun).is_err());
    }

    #[test]
    fn json_rendering_matches_runner_exec() {
        // `RunReport::to_json`（`JsonValue` 経由）と
        // `runner_exec::report_to_json`（文字列直書き）は同じ形で
        // なければならない。両方をパースして比べる。
        let report = run_spec(&spec(), RunMode::DryRun).unwrap();
        let via_value = report.to_json().render();
        let data = RunReportData {
            environment: report.environment.clone(),
            spec_name: report.spec_name.clone(),
            executed: report.executed,
            all_ok: report.all_ok,
            steps: report.outcomes.clone(),
        };
        let via_text = report_to_json(&data);
        assert_eq!(
            parse_json(&via_value).unwrap(),
            parse_json(&via_text).unwrap()
        );
        // 人間向け表示も同じものになること。
        assert_eq!(report.render_human(), report_to_text(&data));
    }
}
