//! shirusu-probe CLI: 2 つの Trace を比較し、差分候補 1 件から
//! 回帰バンドルを生成する。
//!
//! 終了コード: 0 = バンドル生成（識別ルールあり）、
//! 1 = 差分候補が無い、2 = 使い方/入力エラー、
//! 3 = バンドルは生成したが識別ルールを生成できなかった
//! （ブリーフのみ。候補が違反かどうかはこの時点では未判定）。

use shirusu_probe::{build_bundle, write_bundle, BundleOptions};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err((code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

fn run(args: &[String]) -> Result<u8, (u8, String)> {
    if args.first().map(String::as_str) == Some("corpus") {
        return run_corpus(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("reduce") {
        return run_reduction(&args[1..]);
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut out: Option<String> = None;
    let mut name: Option<String> = None;
    let mut candidate: usize = 0;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--out" => {
                i += 1;
                out = Some(
                    args.get(i)
                        .ok_or((2, "--out needs a value".to_string()))?
                        .clone(),
                );
            }
            "--name" => {
                i += 1;
                name = Some(
                    args.get(i)
                        .ok_or((2, "--name needs a value".to_string()))?
                        .clone(),
                );
            }
            "--candidate" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or((2, "--candidate needs a value".to_string()))?;
                candidate = v
                    .parse::<usize>()
                    .map_err(|_| (2, format!("--candidate must be a number: {v}")))?;
            }
            "--help" | "-h" => {
                println!(
                    "usage: shirusu-probe <left.trace> <right.trace> --out <dir> [--candidate <n>] [--name <name>] [--json]\n       shirusu-probe reduce --help\n       shirusu-probe corpus --help"
                );
                return Ok(0);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}")));
            }
            other => positional.push(other),
        }
        i += 1;
    }
    if positional.len() != 2 {
        return Err((
            2,
            "usage: shirusu-probe <left.trace> <right.trace> --out <dir> [--candidate <n>] [--name <name>] [--json]"
                .to_string(),
        ));
    }
    let out = out.ok_or((2, "--out <dir> is required".to_string()))?;
    let load = |path: &str| -> Result<shirusu_trace::reader::ReadTrace, (u8, String)> {
        let data = std::fs::read(path).map_err(|e| (2, format!("cannot read {path}: {e}")))?;
        shirusu_trace::read_trace(&data)
            .map_err(|e| (1, format!("{path} is not a readable trace: {e}")))
    };
    let left = load(positional[0])?;
    let right = load(positional[1])?;
    let report = shirusu_compare::compare_traces(&left, &right);
    if report.candidates.is_empty() {
        eprintln!("no difference candidates; nothing to package");
        return Ok(1);
    }
    let cand = report.candidates.get(candidate).ok_or((
        2,
        format!(
            "--candidate {candidate} out of range ({} candidate(s))",
            report.candidates.len()
        ),
    ))?;
    let name = name.unwrap_or_else(|| default_name(cand));
    let bundle = build_bundle(
        &left,
        &right,
        &report,
        candidate,
        &BundleOptions {
            name: name.clone(),
            left_label: positional[0].to_string(),
            right_label: positional[1].to_string(),
        },
    )
    .map_err(|e| (1, format!("bundle generation failed: {e}")))?;
    let written = write_bundle(&bundle, std::path::Path::new(&out))
        .map_err(|e| (1, format!("cannot write bundle to {out}: {e}")))?;
    if json {
        println!("{}", bundle.manifest_json);
    } else {
        println!("bundle written to {out}:");
        for p in &written {
            println!("  {}", p.display());
        }
        match &bundle.rules_json {
            Some(_) => println!(
                "discriminating rule: yes (rules.json passes on {}, fails on {})",
                positional[0], positional[1]
            ),
            None => println!(
                "discriminating rule: NO (brief-only bundle; see manifest.json rule_generation)"
            ),
        }
        match &bundle.replay {
            Ok(_) => println!(
                "API replay: replay.json (recorded calls only; run in a fresh scratch directory)"
            ),
            Err(reason) => println!("API replay unavailable: {reason}"),
        }
        println!(
            "trimmed pair reproduces the candidate: {}",
            match bundle.trim_reproduced {
                Some(true) => "yes",
                Some(false) => "no",
                None => "not attempted",
            }
        );
    }
    Ok(if bundle.has_discriminating_rule() {
        0
    } else {
        3
    })
}

fn default_name(cand: &shirusu_compare::Candidate) -> String {
    shirusu_probe::rules::spec_name(cand)
}

fn run_reduction(args: &[String]) -> Result<u8, (u8, String)> {
    const USAGE: &str = "usage: shirusu-probe reduce <left.trace> <right.trace> --out <new-dir> --left-runner <executable> --right-runner <executable> [--candidate N] [--max-trials N] [--timeout-ms N]";
    let mut options = std::collections::BTreeMap::new();
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(0);
            }
            "--out" | "--left-runner" | "--right-runner" | "--candidate" | "--max-trials"
            | "--timeout-ms" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| (2, format!("{arg} requires a value")))?;
                if options.insert(arg, value.as_str()).is_some() {
                    return Err((2, format!("duplicate option: {arg}")));
                }
            }
            other if other.starts_with('-') => return Err((2, format!("unknown option: {other}"))),
            path => paths.push(path),
        }
        i += 1;
    }
    if paths.len() != 2 {
        return Err((2, USAGE.into()));
    }
    let required = |name: &str| {
        options
            .get(name)
            .copied()
            .ok_or_else(|| (2, format!("{name} is required")))
    };
    let number = |name: &str, default: usize| -> Result<usize, (u8, String)> {
        options
            .get(name)
            .map(|s| {
                s.parse()
                    .map_err(|_| (2, format!("{name} must be an unsigned integer")))
            })
            .unwrap_or(Ok(default))
    };
    let candidate = number("--candidate", 0)?;
    let max_trials = number("--max-trials", 64)?;
    let timeout_ms = number("--timeout-ms", 30_000)?;
    if !(2..=10_000).contains(&max_trials) || !(1..=3_600_000).contains(&timeout_ms) {
        return Err((
            2,
            "max-trials must be 2..10000 and timeout-ms must be 1..3600000".into(),
        ));
    }
    let out = std::path::Path::new(required("--out")?);
    let baseline = shirusu_probe::external::RunnerCommand::new(std::path::Path::new(required(
        "--left-runner",
    )?))
    .map_err(|e| (2, e))?;
    let comparison = shirusu_probe::external::RunnerCommand::new(std::path::Path::new(required(
        "--right-runner",
    )?))
    .map_err(|e| (2, e))?;
    let load = |path: &str| std::fs::read(path).map_err(|e| (2, format!("read {path}: {e}")));
    let left = load(paths[0])?;
    let right = load(paths[1])?;
    let result = shirusu_probe::reduction_run::reduce_with_runners(
        &left,
        &right,
        candidate,
        &shirusu_probe::reduction_run::ReductionConfig {
            baseline,
            candidate: comparison,
            max_trials,
            timeout: std::time::Duration::from_millis(timeout_ms as u64),
        },
        out,
    )
    .map_err(|e| (1, format!("{e}; output path: {}", out.display())))?;
    println!("verified replay: {} ({} source calls -> {} retained; {} paired trials; globally minimal: no)",
        out.join("reduced.json").display(), result.replay.source_steps,
        result.replay.spec.steps.len(), result.trials);
    Ok(0)
}

fn run_corpus(args: &[String]) -> Result<u8, (u8, String)> {
    const USAGE: &str = "usage: shirusu-probe corpus record <spec.json> --runner <executable> --out <new-dir> [--label <text>] [--timeout-ms N]\n       shirusu-probe corpus compare <left-entry> <right-entry>";
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return Ok(0);
    }
    if args[0] == "compare" {
        if args.len() != 3 {
            return Err((2, USAGE.into()));
        }
        let result = shirusu_probe::corpus::compare(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
        )
        .map_err(|e| (2, e))?;
        println!("{}", result.render_pretty());
        return Ok(0);
    }
    if args[0] != "record" || args.len() < 2 {
        return Err((2, USAGE.into()));
    }
    let mut options = std::collections::BTreeMap::new();
    let mut i = 2;
    while i < args.len() {
        let key = args[i].as_str();
        if !matches!(key, "--runner" | "--out" | "--label" | "--timeout-ms") {
            return Err((2, format!("unknown option: {key}")));
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| (2, format!("{key} requires a value")))?;
        if options.insert(key, value.as_str()).is_some() {
            return Err((2, format!("duplicate option: {key}")));
        }
        i += 2;
    }
    let required = |key: &str| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| (2, format!("{key} is required")))
    };
    let runner =
        shirusu_probe::external::RunnerCommand::new(std::path::Path::new(required("--runner")?))
            .map_err(|e| (2, e))?;
    let out = required("--out")?;
    let ms: u64 = options
        .get("--timeout-ms")
        .unwrap_or(&"30000")
        .parse()
        .map_err(|_| (2, "invalid timeout".into()))?;
    if !(1..=3_600_000).contains(&ms) {
        return Err((2, "timeout-ms must be 1..3600000".into()));
    }
    shirusu_probe::corpus::record(
        std::path::Path::new(&args[1]),
        &runner,
        std::path::Path::new(out),
        options.get("--label").unwrap_or(&""),
        std::time::Duration::from_millis(ms),
    )
    .map_err(|e| (1, e))?;
    println!("reference entry: {out}");
    Ok(0)
}
