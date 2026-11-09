//! shirusu-test CLI: Trace と JSON 仕様を読み、ルールを評価する。
//!
//! 終了コード: 0 = 全ルール pass、1 = いずれか fail、
//! 2 = 使い方/入力/仕様の解釈エラー。

use std::process::ExitCode;

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
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("usage: shirusu-test <trace> <spec.json> [--json]");
                return Ok(true);
            }
            other if other.starts_with("--") => {
                return Err((2, format!("unknown option: {other}")));
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        return Err((
            2,
            "usage: shirusu-test <trace> <spec.json> [--json]".to_string(),
        ));
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
