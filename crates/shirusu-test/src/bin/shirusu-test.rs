//! shirusu-test CLI: Trace と JSON 仕様を読み、ルールを評価する。
//!
//! 使い方（従来形）:
//!   shirusu-test <trace> <spec.json> [--json]
//!
//! Golden 期待値（L18）:
//!   shirusu-test golden record <reference.trace> <golden.json>
//!       [--name N] [--cpu S] [--locale S] [--gpu S]
//!       [--os-version S] [--os-build N]
//!   shirusu-test golden check <candidate.trace> <golden.json> [--json]
//!   shirusu-test golden fresh <reference.trace> <candidate.trace> [--json]
//!       [--name N] [--cpu S] [--locale S] [--gpu S]
//!       [--os-version S] [--os-build N]
//!
//! 前提条件の検査（L19）:
//!   shirusu-test prereq <trace> [--json]
//!
//! JSON Runner と Probe exe 生成（L20）:
//!   shirusu-test run <spec.json> [--dry-run] [--json]
//!   shirusu-test probe-exe <spec.json> --target <triple> --out <path.exe>
//!       [--keep-source <main.rs>]
//!
//! 終了コード: 0 = 全ルール pass／前提条件に不足なし／Runner・生成の成功、
//! 1 = いずれか fail／不足あり／ステップの失敗・ビルドの失敗、
//! 2 = 使い方/入力/仕様の解釈エラー。
//! 環境の不一致は警告どまりで、終了コードには影響しない。

use shirusu_test::golden::{check, derive_from_trace, fresh_check, Golden, GoldenOverrides};
use shirusu_trace::reader::ReadTrace;
use std::process::ExitCode;

const USAGE: &str = "usage: shirusu-test <trace> <spec.json> [--json]\n       shirusu-test golden record <reference.trace> <golden.json> [--name N] [--cpu S] [--locale S] [--gpu S] [--os-version S] [--os-build N]\n       shirusu-test golden check <candidate.trace> <golden.json> [--json]\n       shirusu-test golden fresh <reference.trace> <candidate.trace> [--json] [--name N] [--cpu S] [--locale S] [--gpu S] [--os-version S] [--os-build N]\n       shirusu-test prereq <trace> [--json]\n       shirusu-test run <spec.json> [--dry-run] [--json]\n       shirusu-test probe-exe <spec.json> --target <triple> --out <path.exe> [--keep-source <main.rs>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(all_passed) => ExitCode::from(if all_passed { 0 } else { 1 }),
        Err((code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

fn run(args: &[String]) -> Result<bool, (u8, String)> {
    if args.first().map(|s| s.as_str()) == Some("golden") {
        return run_golden(&args[1..]);
    }
    if args.first().map(|s| s.as_str()) == Some("prereq") {
        return run_prereq(&args[1..]);
    }
    if args.first().map(|s| s.as_str()) == Some("run") {
        return run_runner(&args[1..]);
    }
    if args.first().map(|s| s.as_str()) == Some("probe-exe") {
        return run_probe_exe(&args[1..]);
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        return Err((2, USAGE.to_string()));
    }
    let spec_text = std::fs::read_to_string(positional[1])
        .map_err(|e| (2, format!("cannot read spec {}: {e}", positional[1])))?;
    let spec = shirusu_test::TestSpec::parse(&spec_text)
        .map_err(|e| (2, format!("invalid spec {}: {e}", positional[1])))?;
    let data = std::fs::read(positional[0])
        .map_err(|e| (1, format!("cannot read {}: {e}", positional[0])))?;
    let trace = shirusu_trace::read_trace(&data)
        .map_err(|e| (1, format!("{} is not a readable trace: {e}", positional[0])))?;
    let report = shirusu_test::evaluate(&spec, &trace);
    if json {
        println!("{}", report.to_json().render_pretty());
    } else {
        print!("{}", report.render_human());
    }
    Ok(report.all_passed())
}

fn read_trace_file(path: &str) -> Result<ReadTrace, (u8, String)> {
    let data = std::fs::read(path).map_err(|e| (2, format!("cannot read {path}: {e}")))?;
    shirusu_trace::read_trace(&data)
        .map_err(|e| (2, format!("{path} is not a readable trace: {e}")))
}

/// `--flag value` 形式のオプションを 1 件取り出す。残りの引数を返す。
fn take_opt(args: &[String], flag: &str) -> Result<(Option<String>, Vec<String>), (u8, String)> {
    let mut value = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if value.is_some() {
                return Err((2, format!("{flag} is given twice")));
            }
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| (2, format!("{flag} needs a value")))?;
            value = Some(v.clone());
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    Ok((value, rest))
}

/// Golden 用の環境指定フラグをまとめて読む。
fn take_overrides(args: &[String]) -> Result<(GoldenOverrides, Vec<String>), (u8, String)> {
    let (os_version, args) = take_opt(args, "--os-version")?;
    let (os_build_s, args) = take_opt(&args, "--os-build")?;
    let (cpu, args) = take_opt(&args, "--cpu")?;
    let (locale, args) = take_opt(&args, "--locale")?;
    let (gpu, args) = take_opt(&args, "--gpu")?;
    let os_build = match os_build_s {
        Some(s) => Some(
            s.parse::<u64>()
                .map_err(|_| (2, format!("--os-build needs an integer, got {s:?}")))?,
        ),
        None => None,
    };
    Ok((
        GoldenOverrides {
            os_version,
            os_build,
            cpu,
            locale,
            gpu,
        },
        args,
    ))
}

fn run_golden(args: &[String]) -> Result<bool, (u8, String)> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err((2, USAGE.to_string()));
    };
    match sub {
        "record" => run_golden_record(&args[1..]),
        "check" => run_golden_check(&args[1..]),
        "fresh" => run_golden_fresh(&args[1..]),
        "--help" | "-h" => {
            println!("{USAGE}");
            Ok(true)
        }
        other => Err((2, format!("unknown golden subcommand: {other}\n{USAGE}"))),
    }
}

fn run_golden_record(args: &[String]) -> Result<bool, (u8, String)> {
    let (name, args) = take_opt(args, "--name")?;
    let (overrides, args) = take_overrides(&args)?;
    if args.len() != 2 {
        return Err((2, USAGE.to_string()));
    }
    let reference = read_trace_file(&args[0])?;
    let name = name.as_deref().unwrap_or("golden");
    let (golden, notes) = derive_from_trace(&reference, name, overrides);
    let text = golden.to_pretty_json();
    std::fs::write(&args[1], &text).map_err(|e| (2, format!("cannot write {}: {e}", args[1])))?;
    println!(
        "golden {:?} written to {} ({} rules)",
        golden.name,
        args[1],
        golden.spec.rules.len()
    );
    println!("environment: {}", golden.environment.describe());
    for n in &notes {
        println!("note: {n}");
    }
    Ok(true)
}

fn run_golden_check(args: &[String]) -> Result<bool, (u8, String)> {
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        return Err((2, USAGE.to_string()));
    }
    let trace = read_trace_file(positional[0])?;
    let golden_text = std::fs::read_to_string(positional[1])
        .map_err(|e| (2, format!("cannot read golden {}: {e}", positional[1])))?;
    let golden = Golden::parse(&golden_text)
        .map_err(|e| (2, format!("invalid golden {}: {e}", positional[1])))?;
    let report = check(&golden, &trace);
    if json {
        println!("{}", report.to_json().render_pretty());
    } else {
        print!("{}", report.render_human());
    }
    Ok(report.all_passed())
}

fn run_golden_fresh(args: &[String]) -> Result<bool, (u8, String)> {
    let (name, args) = take_opt(args, "--name")?;
    let (overrides, args) = take_overrides(&args)?;
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in &args {
        match arg.as_str() {
            "--json" => json = true,
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        return Err((2, USAGE.to_string()));
    }
    let reference = read_trace_file(positional[0])?;
    let candidate = read_trace_file(positional[1])?;
    let name = name.as_deref().unwrap_or("golden");
    let report = fresh_check(&reference, &candidate, name, overrides);
    if json {
        println!("{}", report.to_json().render_pretty());
    } else {
        print!("{}", report.render_human());
    }
    Ok(report.all_passed())
}

/// JSON Runner（L20）：`shirusu-test run <spec.json> [--dry-run] [--json]`。
/// 終了コードは 0 = 全ステップ成功、1 = ステップの失敗あり、
/// 2 = 使い方/仕様の解釈エラー・Windows 以外での実行。
fn run_runner(args: &[String]) -> Result<bool, (u8, String)> {
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    let mut dry_run = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 1 {
        return Err((2, USAGE.to_string()));
    }
    let spec = read_spec_file(positional[0])?;
    let mode = if dry_run {
        shirusu_test::RunMode::DryRun
    } else {
        shirusu_test::RunMode::Execute
    };
    let report = shirusu_test::run_spec(&spec, mode).map_err(|e| (2, e))?;
    if json {
        println!("{}", report.to_json().render_pretty());
    } else {
        print!("{}", report.render_human());
    }
    Ok(report.all_ok)
}

/// Probe exe 生成（L20）:
/// `shirusu-test probe-exe <spec.json> --target <triple> --out <path.exe>
/// [--keep-source <main.rs>]`。終了コードは 0 = ビルド成功、
/// 1 = ビルドの失敗、2 = 使い方/仕様の解釈エラー。
fn run_probe_exe(args: &[String]) -> Result<bool, (u8, String)> {
    let (target, args) = take_opt(args, "--target")?;
    let (out, args) = take_opt(&args, "--out")?;
    let (keep_source, args) = take_opt(&args, "--keep-source")?;
    let mut positional: Vec<&str> = Vec::new();
    for arg in &args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 1 {
        return Err((2, USAGE.to_string()));
    }
    let Some(target) = target else {
        return Err((2, "--target <triple> is required\n".to_string() + USAGE));
    };
    let Some(out) = out else {
        return Err((2, "--out <path.exe> is required\n".to_string() + USAGE));
    };
    let spec = read_spec_file(positional[0])?;
    if let Some(keep) = &keep_source {
        let source = shirusu_test::generate_probe_main_rs(&spec).map_err(|e| (2, e))?;
        std::fs::write(keep, &source).map_err(|e| (2, format!("cannot write {keep}: {e}")))?;
        println!("probe source written to {keep}");
    }
    let out_path = std::path::Path::new(&out);
    match shirusu_test::build_probe_exe(&spec, &target, out_path) {
        Ok(path) => {
            println!("probe exe written to {} (target {target})", path.display());
            Ok(true)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(false)
        }
    }
}

fn read_spec_file(path: &str) -> Result<shirusu_test::TestSpec, (u8, String)> {
    let spec_text =
        std::fs::read_to_string(path).map_err(|e| (2, format!("cannot read spec {path}: {e}")))?;
    shirusu_test::TestSpec::parse(&spec_text).map_err(|e| (2, format!("invalid spec {path}: {e}")))
}

/// 前提条件の検査（L19）：`shirusu-test prereq <trace> [--json]`。
/// 終了コードは 0 = 不足なし、1 = 不足あり、2 = 使い方/入力エラー。
fn run_prereq(args: &[String]) -> Result<bool, (u8, String)> {
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}\n{USAGE}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 1 {
        return Err((2, USAGE.to_string()));
    }
    let trace = read_trace_file(positional[0])?;
    let report = shirusu_test::check_prerequisites(&trace);
    if json {
        println!("{}", report.to_json().render_pretty());
    } else {
        print!("{}", report.render_human());
    }
    Ok(report.is_ready())
}
