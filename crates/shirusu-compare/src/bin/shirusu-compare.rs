//! shirusu-compare CLI: 2 つの Trace を比較し、差分候補を表示する。
//!
//! 終了コード: 0 = 候補なし、1 = 候補あり、2 = 使い方/入力エラー。
//! 「候補あり」は「違反が確定した」意味ではない（ライブラリの
//! CANDIDATE_NOTICE を参照）。CI で落とすかどうかは利用側の判断。

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(has_candidates) => ExitCode::from(if has_candidates { 1 } else { 0 }),
        Err((code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

fn run(args: &[String]) -> Result<bool, (u8, String)> {
    let mut positional: Vec<&str> = Vec::new();
    let mut json = false;
    let mut output: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--output" => {
                i += 1;
                output = Some(
                    args.get(i)
                        .ok_or((2, "--output needs a value".to_string()))?
                        .clone(),
                );
            }
            "--help" | "-h" => {
                println!(
                    "usage: shirusu-compare <left.trace> <right.trace> [--json] [--output <path>]"
                );
                return Ok(false);
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
            "usage: shirusu-compare <left.trace> <right.trace> [--json] [--output <path>]"
                .to_string(),
        ));
    }
    let load = |path: &str| -> Result<shirusu_trace::reader::ReadTrace, (u8, String)> {
        let data = std::fs::read(path).map_err(|e| (1, format!("cannot read {path}: {e}")))?;
        shirusu_trace::read_trace(&data)
            .map_err(|e| (1, format!("{path} is not a readable trace: {e}")))
    };
    let left = load(positional[0])?;
    let right = load(positional[1])?;
    let report = shirusu_compare::compare_traces(&left, &right);
    let rendered = if json {
        shirusu_compare::report_json(&report, positional[0], positional[1]).render_pretty()
    } else {
        shirusu_compare::render_human(&report, positional[0], positional[1])
    };
    match &output {
        Some(path) => {
            std::fs::write(path, rendered).map_err(|e| (1, format!("cannot write {path}: {e}")))?;
        }
        None => print!("{rendered}"),
    }
    Ok(!report.candidates.is_empty())
}
