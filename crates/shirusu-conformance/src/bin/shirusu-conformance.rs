//! shirusu-conformance CLI: 外部生成 Trace の適合性を検査する。
//!
//! 終了コード: 0 = 適合、1 = 不適合（Trace として読めない場合を
//! 含む）、2 = 使い方/入力エラー。

use shirusu_conformance::{CheckFinding, CheckStatus, ConformanceReport};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(conformant) => ExitCode::from(if conformant { 0 } else { 1 }),
        Err((code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

fn run(args: &[String]) -> Result<bool, (u8, String)> {
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("usage: shirusu-conformance <trace> [--json]");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 1 {
        return Err((2, "usage: shirusu-conformance <trace> [--json]".to_string()));
    }
    let path = positional[0];
    let data = std::fs::read(path).map_err(|e| (2, format!("cannot read {path}: {e}")))?;
    let report = match shirusu_trace::read_trace(&data) {
        Ok(trace) => shirusu_conformance::check_trace(&trace),
        Err(e) => ConformanceReport {
            findings: vec![CheckFinding {
                id: "readable",
                status: CheckStatus::Fail,
                detail: format!("not a readable trace: {e}"),
            }],
        },
    };
    if json {
        println!("{}", report.to_json(path).render_pretty());
    } else {
        print!("{}", report.render_human(path));
    }
    Ok(report.conformant())
}
