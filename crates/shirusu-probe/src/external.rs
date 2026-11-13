//! Run a configured, trusted Runner executable without a shell. Each process
//! receives a fresh working directory and its own JSON spec. Evidence remains
//! on disk, including failures; directories are never reused or deleted here.
use shirusu_test::runner_report::MAX_REPORT_BYTES;
use shirusu_test::{parse_runner_report_json, RunReportData, TestSpec};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunnerCommand {
    pub program: PathBuf,
}

impl RunnerCommand {
    /// Resolve relative paths before changing the child working directory.
    pub fn new(program: &Path) -> Result<Self, String> {
        let program = fs::canonicalize(program).map_err(|e| format!("runner path: {e}"))?;
        if !program.is_file() {
            return Err("runner must be a file".into());
        }
        Ok(Self { program })
    }
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) && self.0.kill().is_ok() {
            let _ = self.0.wait();
        }
    }
}

/// The executable receives `run <absolute-spec-path> --json`, just like
/// shirusu-test. Wrappers must manage their own remote/descendant processes.
/// On any process/report error the caller must abort the reduction, not retry in
/// the same directory. Output limits are polled disk limits, not OS disk quotas.
pub fn run_external(
    runner: &RunnerCommand,
    spec: &TestSpec,
    directory: &Path,
    timeout: Duration,
) -> Result<RunReportData, String> {
    if timeout.is_zero() {
        return Err("runner timeout must be positive".into());
    }
    if !runner.program.is_absolute() {
        return Err("runner path must be absolute".into());
    }
    fs::create_dir(directory).map_err(|e| format!("create fresh runner directory: {e}"))?;
    let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    let work = directory.join("work");
    fs::create_dir(&work).map_err(|e| e.to_string())?;
    let input = directory.join("spec.json");
    fs::write(&input, spec.to_json().render_pretty()).map_err(|e| e.to_string())?;
    let stdout_path = directory.join("stdout.json");
    let stderr_path = directory.join("stderr.txt");
    let output = |path: &Path| OpenOptions::new().write(true).create_new(true).open(path);
    let stdout = output(&stdout_path).map_err(|e| e.to_string())?;
    let stderr = output(&stderr_path).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut child = Running(
        Command::new(&runner.program)
            .args(["run".as_ref(), input.as_os_str(), "--json".as_ref()])
            .current_dir(&work)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("start runner {}: {e}", runner.program.display()))?,
    );
    let process_id = child.0.id();
    let mut exit_description = None;
    let result = (|| {
        let status = loop {
            for path in [&stdout_path, &stderr_path] {
                if fs::metadata(path).map_err(|e| e.to_string())?.len() > MAX_REPORT_BYTES as u64 {
                    return Err("runner output exceeded 8 MiB; reduction aborted".into());
                }
            }
            if started.elapsed() >= timeout {
                return Err("runner timed out; reduction aborted".into());
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                exit_description = Some(status.to_string());
                break status;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        for path in [&stdout_path, &stderr_path] {
            if fs::metadata(path).map_err(|e| e.to_string())?.len() > MAX_REPORT_BYTES as u64 {
                return Err("runner output exceeded 8 MiB".into());
            }
        }
        let mut bytes = Vec::new();
        File::open(&stdout_path)
            .map_err(|e| e.to_string())?
            .take(MAX_REPORT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err("runner output exceeded 8 MiB".into());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|e| format!("runner output is not UTF-8: {e}"))?;
        let report = parse_runner_report_json(text)?;
        // A process error cannot become evidence just by printing a valid report.
        let expected_exit = if report.all_ok { 0 } else { 1 };
        if status.code() != Some(expected_exit) {
            return Err("runner exit status disagrees with JSON result".into());
        }
        if !report.executed {
            return Err("runner returned dry-run/unexecuted evidence".into());
        }
        Ok(report)
    })();
    // Drop kills/reaps the direct child before writing the outcome. A configured
    // wrapper remains responsible for any detached/remote work it started.
    drop(child);
    use shirusu_analysis::JsonValue as J;
    let reported_environment = result
        .as_ref()
        .ok()
        .and_then(|report| report.environment.as_ref())
        .map(|env| {
            shirusu_test::json_parse::parse_json(&shirusu_test::runner_exec::environment_to_json(
                env,
            ))
        })
        .transpose()?
        .unwrap_or(J::Null);
    let evidence = J::obj(vec![
        (
            "program",
            J::Str(runner.program.to_string_lossy().into_owned()),
        ),
        (
            "elapsed_ms",
            J::U64(started.elapsed().as_millis().min(u64::MAX as u128) as u64),
        ),
        (
            "timeout_ms",
            J::U64(timeout.as_millis().min(u64::MAX as u128) as u64),
        ),
        ("process_id", J::U64(process_id as u64)),
        (
            "exit_status",
            exit_description.map(J::Str).unwrap_or(J::Null),
        ),
        ("report_accepted", J::Bool(result.is_ok())),
        ("runner_environment", reported_environment),
        (
            "error",
            result
                .as_ref()
                .err()
                .cloned()
                .map(J::Str)
                .unwrap_or(J::Null),
        ),
        (
            "environment_provenance",
            J::Str("runner-reported API identity when present; not OS attestation".into()),
        ),
    ]);
    fs::write(directory.join("execution.json"), evidence.render_pretty())
        .map_err(|e| e.to_string())?;
    result
}
