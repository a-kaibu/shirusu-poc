//! Strict, bounded decoding of the JSON emitted by both Runner frontends.
//! Parsing a report does not prove its provenance or that it was executed.
use crate::json_parse::{get, parse_json};
use crate::runner_exec::{OutputValue, RunReportData, StepOutcome, MAX_CAPTURED_BUFFER};
use shirusu_analysis::JsonValue as J;
use std::collections::BTreeSet;

pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REPORT_STEPS: usize = 65_536;

pub fn parse_runner_report_json(text: &str) -> Result<RunReportData, String> {
    if text.len() > MAX_REPORT_BYTES {
        return Err("runner report exceeds 8 MiB".into());
    }
    let root = parse_json(text)?;
    object(&root, &["spec", "executed", "all_ok", "steps"])?;
    let values = array(field(&root, "steps")?)?;
    if values.len() > MAX_REPORT_STEPS {
        return Err("too many runner steps".into());
    }
    let mut steps = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        object(
            value,
            &[
                "index",
                "call",
                "ok",
                "executed",
                "returned",
                "last_error",
                "outputs",
                "outputs_truncated",
                "error",
            ],
        )?;
        if unsigned(field(value, "index")?)? != index as u64 {
            return Err("runner step indices must be contiguous and ordered".into());
        }
        let J::Object(outputs_json) = field(value, "outputs")? else {
            return Err("outputs must be an object".into());
        };
        let mut outputs = Vec::with_capacity(outputs_json.len());
        for (name, output) in outputs_json {
            let parsed = match output {
                J::U64(n) => OutputValue::U64(*n),
                J::Str(hex)
                    if hex.len() <= MAX_CAPTURED_BUFFER * 2
                        && hex.len() % 2 == 0
                        && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    OutputValue::Hex(hex.clone())
                }
                _ => return Err(format!("invalid or oversized runner output {name:?}")),
            };
            outputs.push((name.clone(), parsed));
        }
        let mut outputs_truncated = Vec::new();
        let mut seen = BTreeSet::new();
        for name in array(field(value, "outputs_truncated")?)? {
            let name = string(name)?;
            if !seen.insert(name)
                || !outputs
                    .iter()
                    .any(|(n, v)| n == name && matches!(v, OutputValue::Hex(_)))
            {
                return Err("truncation names must identify unique buffer outputs".into());
            }
            outputs_truncated.push(name.to_owned());
        }
        let error = match field(value, "error")? {
            J::Null => None,
            v => Some(string(v)?.to_owned()),
        };
        let ok = boolean(field(value, "ok")?)?;
        if ok != error.is_none() {
            return Err("runner step success/error disagree".into());
        }
        steps.push(StepOutcome {
            index,
            call: string(field(value, "call")?)?.to_owned(),
            ok,
            executed: boolean(field(value, "executed")?)?,
            returned: optional_unsigned(field(value, "returned")?)?,
            last_error: optional_unsigned(field(value, "last_error")?)?
                .map(|n| u32::try_from(n).map_err(|_| "last_error exceeds u32".to_owned()))
                .transpose()?,
            outputs,
            outputs_truncated,
            error,
        });
    }
    if steps.iter().any(|step| {
        !step.executed
            && (step.returned.is_some() || step.last_error.is_some() || !step.outputs.is_empty())
    }) {
        return Err("unexecuted step contains execution results".into());
    }
    let executed = boolean(field(&root, "executed")?)?;
    let all_ok = boolean(field(&root, "all_ok")?)?;
    if all_ok != steps.iter().all(|step| step.ok) {
        return Err("runner aggregate success disagrees with steps".into());
    }
    if !executed && steps.iter().any(|step| step.executed) {
        return Err("runner execution flags disagree".into());
    }
    Ok(RunReportData {
        spec_name: string(field(&root, "spec")?)?.to_owned(),
        executed,
        all_ok,
        steps,
    })
}

fn object(value: &J, fields: &[&str]) -> Result<(), String> {
    let J::Object(entries) = value else {
        return Err("expected report object".into());
    };
    if entries.len() != fields.len()
        || entries
            .iter()
            .any(|(key, _)| !fields.contains(&key.as_str()))
    {
        return Err("missing or unknown runner report fields".into());
    }
    Ok(())
}
fn field<'a>(value: &'a J, key: &str) -> Result<&'a J, String> {
    get(value, key).ok_or_else(|| format!("missing runner field {key}"))
}
fn array(value: &J) -> Result<&[J], String> {
    match value {
        J::Array(v) => Ok(v),
        _ => Err("expected array".into()),
    }
}
fn string(value: &J) -> Result<&str, String> {
    match value {
        J::Str(v) => Ok(v),
        _ => Err("expected string".into()),
    }
}
fn unsigned(value: &J) -> Result<u64, String> {
    match value {
        J::U64(v) => Ok(*v),
        _ => Err("expected unsigned integer".into()),
    }
}
fn optional_unsigned(value: &J) -> Result<Option<u64>, String> {
    match value {
        J::Null => Ok(None),
        _ => unsigned(value).map(Some),
    }
}
fn boolean(value: &J) -> Result<bool, String> {
    match value {
        J::Bool(v) => Ok(*v),
        _ => Err("expected boolean".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner_exec::report_to_json;

    fn report() -> RunReportData {
        RunReportData {
            spec_name: "escaped\"name\\日本語".into(),
            executed: true,
            all_ok: true,
            steps: vec![StepOutcome {
                index: 0,
                call: "kernel32!ReadFile".into(),
                ok: true,
                executed: true,
                returned: Some(u64::MAX),
                last_error: Some(u32::MAX),
                outputs: vec![
                    ("count".into(), OutputValue::U64(u64::MAX)),
                    ("data".into(), OutputValue::Hex("00FF".into())),
                ],
                outputs_truncated: vec!["data".into()],
                error: None,
            }],
        }
    }

    #[test]
    fn both_frontends_round_trip_without_losing_unsigned_bits_or_capture_state() {
        let data = report();
        assert_eq!(
            parse_runner_report_json(&report_to_json(&data)).unwrap(),
            data
        );
        let frontend = crate::runner::RunReport {
            spec_name: data.spec_name.clone(),
            executed: data.executed,
            all_ok: data.all_ok,
            outcomes: data.steps.clone(),
        };
        assert_eq!(
            parse_runner_report_json(&frontend.to_json().render_pretty()).unwrap(),
            data
        );
        let mut dry = data.clone();
        dry.executed = false;
        dry.steps[0].executed = false;
        dry.steps[0].returned = None;
        dry.steps[0].last_error = None;
        dry.steps[0].outputs.clear();
        dry.steps[0].outputs_truncated.clear();
        assert_eq!(
            parse_runner_report_json(&report_to_json(&dry)).unwrap(),
            dry
        );
        let mut failed = data;
        failed.all_ok = false;
        failed.steps[0].ok = false;
        failed.steps[0].error = Some("expectation failed".into());
        assert_eq!(
            parse_runner_report_json(&report_to_json(&failed)).unwrap(),
            failed
        );
    }

    #[test]
    fn rejects_malformed_inconsistent_and_oversized_reports() {
        let original = report_to_json(&report());
        for bad in [
            original.replacen("\"all_ok\":true", "\"all_ok\":false", 1),
            original.replacen("\"ok\":true", "\"ok\":false", 1),
            original.replacen("\"executed\":true", "\"executed\":false", 1),
            original.replacen("\"index\":0", "\"index\":1", 1),
            original.replacen("\"index\":0", "\"index\":-1", 1),
            original.replacen("4294967295", "4294967296", 1),
            original.replacen("00FF", "xyz", 1),
            original.replacen("00FF", "fff", 1),
            original.replacen(
                "\"outputs_truncated\":[\"data\"]",
                "\"outputs_truncated\":[\"count\"]",
                1,
            ),
            original.replacen(
                "\"outputs_truncated\":[\"data\"]",
                "\"outputs_truncated\":[\"data\",\"data\"]",
                1,
            ),
            original.replacen("\"all_ok\":true", "\"all_ok\":true,\"all_ok\":true", 1),
            original.replacen("\"all_ok\":true,", "", 1),
            original.replacen("\"all_ok\":true", "\"all_ok\":true,\"unknown\":1", 1),
            format!("runner log\n{original}"),
            format!("{original} trailing"),
            original.replacen("00FF", &"00".repeat(MAX_CAPTURED_BUFFER + 1), 1),
        ] {
            assert!(
                parse_runner_report_json(&bad).is_err(),
                "accepted malformed report"
            );
        }
        assert!(parse_runner_report_json(&" ".repeat(MAX_REPORT_BYTES + 1)).is_err());
        let too_many = format!(
            "{{\"spec\":\"x\",\"executed\":false,\"all_ok\":true,\"steps\":[{}]}}",
            vec!["null"; MAX_REPORT_STEPS + 1].join(",")
        );
        assert!(parse_runner_report_json(&too_many)
            .unwrap_err()
            .contains("too many"));
        let mut impossible = report();
        impossible.steps[0].executed = false;
        assert!(parse_runner_report_json(&report_to_json(&impossible)).is_err());
    }
}
