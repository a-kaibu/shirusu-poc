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
                    "usage: shirusu-probe <left.trace> <right.trace> --out <dir> [--candidate <n>] [--name <name>] [--json]"
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
