//! Immutable, content-bound Windows file-I/O reference entries. Environment
//! identity is runner-reported evidence, never native-Windows attestation.
use crate::external::{run_external, RunnerCommand};
use shirusu_analysis::JsonValue as J;
use shirusu_test::runner_exec::{environment_to_json, plan_steps, ArgValue, RunReportData};
use shirusu_test::{
    json_parse::{get, parse_json},
    parse_runner_report_json, TestSpec,
};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

const LIMIT: u64 = 8 * 1024 * 1024;

fn read(path: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("corpus input exceeds 8 MiB".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
fn write(path: &Path, text: &str) -> Result<(), String> {
    if text.len() as u64 > LIMIT {
        return Err("corpus output exceeds 8 MiB".into());
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| e.to_string())
}
fn digest(text: &str) -> String {
    shirusu_trace::blob::BlobId::of_content(text.as_bytes()).to_hex()
}
fn canonical(mut value: J) -> J {
    match &mut value {
        J::Object(fields) => {
            for (_, v) in fields.iter_mut() {
                *v = canonical(v.clone());
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
        }
        J::Array(values) => {
            for v in values {
                *v = canonical(v.clone());
            }
        }
        _ => {}
    }
    value
}
fn basename(s: &str) -> bool {
    if s.is_empty()
        || s.len() > 128
        || s.ends_with('.')
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        || s == "."
        || s == ".."
    {
        return false;
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}
/// V1 deliberately restricts inputs to bounded synchronous file I/O in a fresh
/// working directory. This validation is not a sandbox for the runner program.
fn validate(spec: &TestSpec) -> Result<(), String> {
    plan_steps(&spec.steps)?;
    if spec.steps.is_empty() || spec.steps.len() > 4096 {
        return Err("corpus needs 1..4096 steps".into());
    }
    let mut handles = std::collections::BTreeSet::new();
    for step in &spec.steps {
        if !matches!(
            step.call.as_str(),
            "kernel32!CreateFileW"
                | "kernel32!ReadFile"
                | "kernel32!WriteFile"
                | "kernel32!CloseHandle"
        ) {
            return Err(format!("unsupported corpus call: {}", step.call));
        }
        for (name, arg) in &step.args {
            let valid = match name.as_str() {
                "lpFileName" => matches!(arg, ArgValue::Text(s) if basename(s)),
                "lpSecurityAttributes" | "hTemplateFile" | "lpOverlapped" => {
                    matches!(arg, ArgValue::Null)
                }
                "hFile" | "hObject" => matches!(arg, ArgValue::Ref(name) if handles.contains(name)),
                "lpBuffer" => {
                    matches!(arg, ArgValue::Buffer { size, fill } if *size <= 4096 && fill.len() <= *size)
                }
                "nNumberOfBytesToRead" | "nNumberOfBytesToWrite" => {
                    matches!(arg, ArgValue::Int(n) if *n <= 4096)
                }
                "lpNumberOfBytesRead" | "lpNumberOfBytesWritten" => matches!(arg, ArgValue::OutU32),
                "dwCreationDisposition" => matches!(arg, ArgValue::Int(1..=5)),
                // Normal synchronous files only: no overlapped, delete-on-close,
                // backup/device/reparse semantics or external filesystem state.
                "dwFlagsAndAttributes" => matches!(arg, ArgValue::Int(128)),
                "dwDesiredAccess" => {
                    matches!(arg, ArgValue::Int(n) if *n <= u32::MAX as u64 && *n & !0xc0000000 == 0)
                }
                "dwShareMode" => matches!(arg, ArgValue::Int(0..=7)),
                _ => false,
            };
            if !valid {
                return Err(format!("unsupported corpus argument {}.{name}", step.call));
            }
        }
        if let Some(name) = &step.store {
            if step.call != "kernel32!CreateFileW" {
                return Err("corpus stores must originate from CreateFileW".into());
            }
            handles.insert(name.clone());
        }
    }
    Ok(())
}
fn observations(spec: &TestSpec, report: &RunReportData) -> Result<J, String> {
    validate(spec)?;
    let env = report
        .environment
        .as_ref()
        .ok_or("missing runner environment")?;
    if env.target_os != "windows"
        || !matches!(env.pointer_width, 32 | 64)
        || env.windows_version.as_ref().is_none_or(String::is_empty)
        || env.windows_build.is_none_or(|build| build == 0)
        || env.version_source.as_deref() != Some("RtlGetVersion")
    {
        return Err("missing Windows version identity".into());
    }
    if !report.executed
        || report.spec_name != spec.name
        || report.steps.len() != spec.steps.len()
        || report.all_ok != report.steps.iter().all(|s| s.ok)
    {
        return Err("report does not match executed probe".into());
    }
    let mut values = Vec::new();
    for (i, (step, result)) in spec.steps.iter().zip(&report.steps).enumerate() {
        if result.index != i
            || result.call != step.call
            || !result.executed
            || result.returned.is_none()
            || !result.outputs_truncated.is_empty()
            || result.ok != result.error.is_none()
        {
            return Err(format!("incomplete or mismatched step {i}"));
        }
        let value = if step.call == "kernel32!CreateFileW" {
            let raw = result.returned.unwrap();
            let invalid = if env.pointer_width == 32 {
                u32::MAX as u64
            } else {
                u64::MAX
            };
            if raw > invalid {
                return Err("handle exceeds process pointer width".into());
            }
            let status = if raw == invalid {
                "invalid"
            } else if raw == 0 {
                "null"
            } else {
                "valid"
            };
            let meaningful_error = status != "valid"
                || step.args.iter().any(|(n, a)| {
                    n == "dwCreationDisposition" && matches!(a, ArgValue::Int(2 | 4))
                });
            J::obj(vec![
                ("handle", J::Str(status.into())),
                (
                    "last_error",
                    if meaningful_error {
                        J::U64(result.last_error.ok_or("missing meaningful last-error")? as u64)
                    } else {
                        J::Null
                    },
                ),
            ])
        } else {
            let o = crate::oracle::observe(step, result)
                .ok_or_else(|| format!("incomplete observation at step {i}"))?;
            J::obj(vec![
                ("succeeded", J::Bool(o.succeeded)),
                (
                    "failure_error",
                    o.failure_error.map(|n| J::U64(n as u64)).unwrap_or(J::Null),
                ),
                ("transferred", o.transferred.map(J::U64).unwrap_or(J::Null)),
                ("data", o.data.map(J::Str).unwrap_or(J::Null)),
            ])
        };
        values.push(value);
    }
    Ok(J::Array(values))
}
fn manifest(spec: &TestSpec, raw: &str, label: &str) -> Result<J, String> {
    let report = parse_runner_report_json(raw)?;
    let observed = observations(spec, &report)?;
    Ok(J::obj(vec![
        ("version", J::U64(1)),
        ("label", J::Str(label.into())),
        (
            "probe_digest",
            J::Str(digest(&canonical(spec.to_json()).render())),
        ),
        ("report_digest", J::Str(digest(raw))),
        (
            "environment",
            parse_json(&environment_to_json(report.environment.as_ref().unwrap()))?,
        ),
        ("all_expectations_met", J::Bool(report.all_ok)),
        ("observations", observed),
    ]))
}
/// Execute and seal a new entry only after a complete, bound report is available.
/// On failure the directory retains raw execution evidence, without entry.json.
pub fn record(
    spec_path: &Path,
    runner: &RunnerCommand,
    out: &Path,
    label: &str,
    timeout: Duration,
) -> Result<(), String> {
    if label.len() > 1024 {
        return Err("label exceeds 1024 bytes".into());
    }
    let spec = TestSpec::parse(&read(spec_path)?)?;
    validate(&spec)?;
    fs::create_dir(out).map_err(|e| e.to_string())?;
    write(&out.join("probe.json"), &canonical(spec.to_json()).render())?;
    run_external(runner, &spec, &out.join("run"), timeout)?;
    let raw = read(&out.join("run/stdout.json"))?;
    write(
        &out.join("entry.json"),
        &manifest(&spec, &raw, label)?.render_pretty(),
    )
}
/// Recompute the complete manifest from fixed local paths; stored observations
/// or hashes are never trusted on their own. Hashes detect damage, not forgery.
pub fn load(out: &Path) -> Result<J, String> {
    let stored = parse_json(&read(&out.join("entry.json"))?)?;
    let label = match get(&stored, "label") {
        Some(J::Str(s)) if s.len() <= 1024 => s,
        _ => return Err("invalid entry label".into()),
    };
    let spec = TestSpec::parse(&read(&out.join("probe.json"))?)?;
    let actual = manifest(&spec, &read(&out.join("run/stdout.json"))?, label)?;
    if canonical(stored) != canonical(actual.clone()) {
        return Err("corpus entry integrity mismatch".into());
    }
    Ok(actual)
}
/// Differences are observations, not verdicts about which OS is correct.
pub fn compare(left: &Path, right: &Path) -> Result<J, String> {
    let a = load(left)?;
    let b = load(right)?;
    if get(&a, "probe_digest") != get(&b, "probe_digest") {
        return Err("entries execute different probes".into());
    }
    let (Some(J::Array(av)), Some(J::Array(bv))) =
        (get(&a, "observations"), get(&b, "observations"))
    else {
        return Err("missing observations".into());
    };
    let diffs = av
        .iter()
        .zip(bv)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, (a, b))| {
            J::obj(vec![
                ("step", J::U64(i as u64)),
                ("left", a.clone()),
                ("right", b.clone()),
            ])
        })
        .collect();
    Ok(J::obj(vec![
        ("left_environment", get(&a, "environment").unwrap().clone()),
        ("right_environment", get(&b, "environment").unwrap().clone()),
        ("differences", J::Array(diffs)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_test::runner_exec::{report_to_json, RunEnvironment, StepOutcome};
    fn fixture() -> (TestSpec, RunReportData) {
        let spec = TestSpec::parse(r#"{"name":"reference","rules":[],"steps":[{"call":"kernel32!CreateFileW","args":{"lpFileName":"sample.bin","dwDesiredAccess":3221225472,"dwShareMode":0,"lpSecurityAttributes":null,"dwCreationDisposition":1,"dwFlagsAndAttributes":128,"hTemplateFile":null},"store":"file"},{"call":"kernel32!CloseHandle","args":{"hObject":{"ref":"file"}}}]}"#).unwrap();
        let report = RunReportData {
            environment: Some(RunEnvironment {
                target_os: "windows".into(),
                process_arch: "x86_64".into(),
                pointer_width: 64,
                windows_version: Some("10.0".into()),
                windows_build: Some(26100),
                version_source: Some("RtlGetVersion".into()),
            }),
            spec_name: spec.name.clone(),
            executed: true,
            all_ok: true,
            steps: spec
                .steps
                .iter()
                .enumerate()
                .map(|(index, s)| StepOutcome {
                    index,
                    call: s.call.clone(),
                    ok: true,
                    executed: true,
                    returned: Some(if index == 0 { 100 } else { 1 }),
                    last_error: Some(0),
                    outputs: vec![],
                    outputs_truncated: vec![],
                    error: None,
                })
                .collect(),
        };
        (spec, report)
    }
    #[test]
    fn normalizes_handles_and_stale_error_but_keeps_meaningful_error() {
        let (mut spec, mut r) = fixture();
        let before = observations(&spec, &r).unwrap();
        r.steps[0].returned = Some(200);
        r.steps[0].last_error = Some(99);
        r.steps[1].returned = Some(42);
        r.steps[1].last_error = Some(77);
        assert_eq!(before, observations(&spec, &r).unwrap());
        spec.steps[0]
            .args
            .iter_mut()
            .find(|(n, _)| n == "dwCreationDisposition")
            .unwrap()
            .1 = ArgValue::Int(4);
        let before = observations(&spec, &r).unwrap();
        r.steps[0].last_error = Some(183);
        assert_ne!(before, observations(&spec, &r).unwrap());
        r.steps[0].returned = Some(u64::MAX);
        assert_ne!(before, observations(&spec, &r).unwrap());
    }
    #[test]
    fn rejects_partial_unbound_or_unversioned_reports() {
        let (s, r) = fixture();
        let mut bad = r.clone();
        bad.environment = None;
        assert!(observations(&s, &bad).is_err());
        let mut bad = r.clone();
        bad.environment.as_mut().unwrap().windows_build = Some(0);
        assert!(observations(&s, &bad).is_err());
        let mut bad = r.clone();
        bad.steps[1].executed = false;
        assert!(observations(&s, &bad).is_err());
        let mut bad = r.clone();
        bad.spec_name = "other".into();
        assert!(observations(&s, &bad).is_err());
        let mut bad = r.clone();
        bad.steps[1].call = "kernel32!ReadFile".into();
        assert!(observations(&s, &bad).is_err());
        let mut bad = r;
        bad.steps[0].outputs_truncated.push("data".into());
        assert!(observations(&s, &bad).is_err());
    }
    #[test]
    fn checked_in_probes_are_within_corpus_scope() {
        for input in [
            include_str!("../tests/fixtures/corpus-file-io.json"),
            include_str!("../tests/fixtures/corpus-file-errors.json"),
        ] {
            validate(&TestSpec::parse(input).unwrap()).unwrap();
        }
    }

    #[test]
    fn paths_are_local_and_not_devices() {
        for s in [
            "../a", "a/b", "C:a", "CON", "con.txt", "LPT9.bin", "a.", "..", "", "a b", "NUL",
        ] {
            assert!(!basename(s), "{s}");
        }
        for s in ["file.bin", "hello-world_1", "COM10.txt"] {
            assert!(basename(s), "{s}");
        }
    }
    #[test]
    fn key_order_does_not_change_probe_identity() {
        let (mut s, r) = fixture();
        let a = manifest(&s, &report_to_json(&r), "").unwrap();
        s.steps[0].args.reverse();
        assert_eq!(a, manifest(&s, &report_to_json(&r), "").unwrap());
    }
    #[test]
    fn entry_is_revalidated_and_existing_files_are_not_overwritten() {
        let (s, r) = fixture();
        let dir = std::env::temp_dir().join(format!(
            "shirusu-corpus-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::create_dir(dir.join("run")).unwrap();
        let raw = report_to_json(&r);
        write(&dir.join("probe.json"), &s.to_json().render()).unwrap();
        write(&dir.join("run/stdout.json"), &raw).unwrap();
        write(
            &dir.join("entry.json"),
            &manifest(&s, &raw, "test").unwrap().render(),
        )
        .unwrap();
        assert!(load(&dir).is_ok());
        assert!(compare(&dir, &dir).is_ok());
        let other = dir.join("other");
        fs::create_dir(&other).unwrap();
        fs::create_dir(other.join("run")).unwrap();
        let mut changed = r.clone();
        changed.environment.as_mut().unwrap().windows_build = Some(20348);
        changed.steps[1].returned = Some(0);
        changed.steps[1].last_error = Some(6);
        let changed_raw = report_to_json(&changed);
        write(&other.join("probe.json"), &s.to_json().render()).unwrap();
        write(&other.join("run/stdout.json"), &changed_raw).unwrap();
        write(
            &other.join("entry.json"),
            &manifest(&s, &changed_raw, "other build").unwrap().render(),
        )
        .unwrap();
        let comparison = compare(&dir, &other).unwrap();
        let Some(J::Array(differences)) = get(&comparison, "differences") else {
            panic!("missing differences")
        };
        assert_eq!(differences.len(), 1);
        assert_eq!(get(&differences[0], "step"), Some(&J::U64(1)));
        assert!(write(&dir.join("entry.json"), "{}").is_err());
        let oversized = dir.join("oversized.json");
        assert!(write(&oversized, &" ".repeat(LIMIT as usize + 1)).is_err());
        assert!(!oversized.exists());
        fs::write(dir.join("run/stdout.json"), format!("{raw} ")).unwrap();
        assert!(load(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn published_native_entries_remain_content_bound_and_comparable() {
        for suite in ["file-io-v1", "file-errors-v1"] {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/windows")
                .join(suite);
            for sample in ["26100-x86", "26100-x64"] {
                let result = compare(&root.join(sample), &root.join("20348-x64")).unwrap();
                assert_eq!(get(&result, "differences"), Some(&J::Array(Vec::new())));
            }
        }
    }

    #[test]
    fn record_executes_transport_and_refuses_reusing_an_entry() {
        let (spec, report) = fixture();
        let root = std::env::temp_dir().join(format!(
            "shirusu-corpus-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("runner.rs");
        let program = root.join(if cfg!(windows) {
            "runner.exe"
        } else {
            "runner"
        });
        let raw = report_to_json(&report);
        fs::write(
            &source,
            format!(
                r#"fn main() {{
            let args: Vec<_> = std::env::args().collect();
            assert_eq!(args.len(), 4); assert_eq!(args[1], "run"); assert_eq!(args[3], "--json");
            assert!(std::path::Path::new(&args[2]).is_absolute());
            std::fs::OpenOptions::new().write(true).create_new(true).open("fresh.marker").unwrap();
            println!("{{}}", {raw:?});
        }}"#
            ),
        )
        .unwrap();
        assert!(std::process::Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap()
            .success());
        let input = root.join("input.json");
        fs::write(&input, spec.to_json().render()).unwrap();
        let runner = RunnerCommand::new(&program).unwrap();
        let entry = root.join("entry");
        record(
            &input,
            &runner,
            &entry,
            "mock transport, not Windows evidence",
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(entry.join("run/work/fresh.marker").is_file());
        assert!(load(&entry).is_ok());
        assert!(record(&input, &runner, &entry, "", Duration::from_secs(10)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
