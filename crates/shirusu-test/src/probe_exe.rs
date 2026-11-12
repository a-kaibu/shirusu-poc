//! Probe exe 生成: JSON 仕様から Windows 向け Probe exe を作る。
//!
//! 生成物は自己完結した 1 ファイルの Rust プログラム（`main.rs`）で、
//! 仕様のステップ列を Rust リテラルとして埋め込み、実行の中核
//! （`runner_exec.rs` の全文）をそのまま含む。依存クレートを持たない
//! ため、ネットワーク不要で `rustc` 1 本でビルドできる。
//!
//! ビルドは `rustc --target <triple>` に任せる。対象は Windows の
//! トリプル（`x86_64-pc-windows-msvc` / `i686-pc-windows-msvc` /
//! `x86_64-pc-windows-gnu` / `i686-pc-windows-gnu`）。x64 の gnu
//! 対象はこの Linux VM でも mingw のリンカでビルドできる。msvc 対象と
//! i686 の gnu 対象は、それぞれ link.exe / mingw（i686）が必要で、
//! 無い環境では `rustc` の誤りをそのまま返す（隠さない）。
//!
//! 生成した exe は、実行すると stdout に JSON の報告を出し、
//! 終了コード 0 = すべて成功 / 1 = 失敗あり / 2 = 計画の誤りで終わる
//! （`runner_exec::run_embedded` と同じ）。

use crate::runner_exec::{ArgValue, Expect, ExpectedOutput, RetExpect, Step};
use crate::spec::TestSpec;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 生成する `main.rs` の全文を作る。`runner_exec.rs` の原文＋
/// ステップ列のリテラル＋`main` からなる。
pub fn generate_probe_main_rs(spec: &TestSpec) -> Result<String, String> {
    let mut src = String::new();
    src.push_str(include_str!("runner_exec.rs"));
    src.push_str("\nfn embedded_steps() -> Vec<Step> {\n    vec![\n");
    for step in &spec.steps {
        src.push_str(&step_to_rust(step));
    }
    src.push_str("    ]\n}\n\nfn main() {\n    std::process::exit(run_embedded(");
    src.push_str(&rust_string(&spec.name));
    src.push_str(", &embedded_steps()));\n}\n");
    Ok(src)
}

fn step_to_rust(step: &Step) -> String {
    let mut out = String::new();
    out.push_str("        Step {\n            call: ");
    out.push_str(&rust_string(&step.call));
    out.push_str(".to_string(),\n            args: vec![\n");
    for (name, value) in &step.args {
        out.push_str("                (");
        out.push_str(&rust_string(name));
        out.push_str(".to_string(), ");
        out.push_str(&arg_value_to_rust(value));
        out.push_str("),\n");
    }
    out.push_str("            ],\n            store: ");
    match &step.store {
        Some(name) => {
            out.push_str("Some(");
            out.push_str(&rust_string(name));
            out.push_str(".to_string())");
        }
        None => out.push_str("None"),
    }
    out.push_str(",\n            expect: ");
    match &step.expect {
        Some(expect) => {
            out.push_str("Some(");
            out.push_str(&expect_to_rust(expect));
            out.push(')');
        }
        None => out.push_str("None"),
    }
    out.push_str(",\n        },\n");
    out
}

fn arg_value_to_rust(value: &ArgValue) -> String {
    match value {
        ArgValue::Int(n) => format!("ArgValue::Int({n})"),
        ArgValue::Ref(name) => format!("ArgValue::Ref({}.to_string())", rust_string(name)),
        ArgValue::Text(s) => format!("ArgValue::Text({}.to_string())", rust_string(s)),
        ArgValue::Null => "ArgValue::Null".to_string(),
        ArgValue::Bool(b) => format!("ArgValue::Bool({b})"),
        ArgValue::Buffer { size, fill } => {
            let bytes: Vec<String> = fill.iter().map(|b| b.to_string()).collect();
            format!(
                "ArgValue::Buffer {{ size: {size}, fill: vec![{}] }}",
                bytes.join(", ")
            )
        }
        ArgValue::OutU32 => "ArgValue::OutU32".to_string(),
        ArgValue::OutU64 => "ArgValue::OutU64".to_string(),
    }
}

fn expect_to_rust(expect: &Expect) -> String {
    let mut out = String::new();
    out.push_str("Expect { ret: ");
    match expect.ret {
        Some(RetExpect::ValidHandle) => out.push_str("Some(RetExpect::ValidHandle)"),
        Some(RetExpect::NonZero) => out.push_str("Some(RetExpect::NonZero)"),
        Some(RetExpect::Zero) => out.push_str("Some(RetExpect::Zero)"),
        Some(RetExpect::Equals(n)) => out.push_str(&format!("Some(RetExpect::Equals({n}))")),
        None => out.push_str("None"),
    }
    out.push_str(", outputs: vec![");
    for (i, (name, expected)) in expect.outputs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('(');
        out.push_str(&rust_string(name));
        out.push_str(".to_string(), ");
        match expected {
            ExpectedOutput::U64(n) => out.push_str(&format!("ExpectedOutput::U64({n})")),
            ExpectedOutput::HexPrefix(h) => {
                out.push_str(&format!(
                    "ExpectedOutput::HexPrefix({}.to_string())",
                    rust_string(h)
                ));
            }
        }
        out.push(')');
    }
    out.push_str("] }");
    out
}

/// 文字列を Rust の文字列リテラルにする。
fn rust_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `rustc` の在り処。`RUSTC` 環境変数があればそれを使う。
fn rustc_path() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string())
}

/// 仕様から Probe exe をビルドする。`out_path` に exe を書き出す。
/// 生成した `main.rs` は一時ディレクトリに置き、ビルド後に消す。
/// 失敗時は `rustc` の出力を含む誤りを返す。
pub fn build_probe_exe(spec: &TestSpec, target: &str, out_path: &Path) -> Result<PathBuf, String> {
    if !target.contains("windows") {
        return Err(format!(
            "target {target:?} is not a Windows triple (expected e.g. x86_64-pc-windows-msvc)"
        ));
    }
    if spec.steps.is_empty() {
        return Err("spec has no steps; nothing to generate".to_string());
    }
    // 計画が通る仕様だけを生成する（実行時の計画誤りを防ぐ）。
    crate::runner_exec::plan_steps(&spec.steps)
        .map_err(|e| format!("cannot generate probe exe: {e}"))?;
    let source = generate_probe_main_rs(spec)?;
    let rustc = rustc_path();
    let version = Command::new(&rustc)
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run {rustc}: {e}"))?;
    if !version.status.success() {
        return Err(format!(
            "{rustc} --version failed: {}",
            String::from_utf8_lossy(&version.stderr)
        ));
    }
    let dir = std::env::temp_dir().join(format!(
        "shirusu-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {dir:?}: {e}"))?;
    let main_rs = dir.join("main.rs");
    let result = (|| -> Result<PathBuf, String> {
        std::fs::write(&main_rs, &source).map_err(|e| format!("cannot write {main_rs:?}: {e}"))?;
        let out = Command::new(&rustc)
            .arg("--edition")
            .arg("2021")
            .arg("-O")
            .arg("--target")
            .arg(target)
            .arg(&main_rs)
            .arg("-o")
            .arg(out_path)
            .output()
            .map_err(|e| format!("cannot run {rustc}: {e}"))?;
        if !out.status.success() {
            let mut msg = format!("rustc failed for target {target}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.is_empty() {
                msg.push_str(": ");
                msg.push_str(stderr.trim());
            }
            return Err(msg);
        }
        let bytes = std::fs::read(out_path)
            .map_err(|e| format!("cannot read built exe {out_path:?}: {e}"))?;
        if bytes.len() < 2 || &bytes[..2] != b"MZ" {
            return Err(format!(
                "rustc succeeded but {out_path:?} is not a PE executable"
            ));
        }
        Ok(out_path.to_path_buf())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_parse::parse_json;

    const SPEC_JSON: &str = r#"{"version":1,"name":"sample","steps":[
        {"call":"kernel32!CreateFileW","args":{"lpFileName":"C:\\temp\\probe.txt","dwDesiredAccess":3221225472,"dwShareMode":0,"lpSecurityAttributes":null,"dwCreationDisposition":2,"dwFlagsAndAttributes":128,"hTemplateFile":null},"store":"hFile"},
        {"call":"kernel32!CloseHandle","args":{"hObject":{"ref":"hFile"}}}
    ],"rules":[]}"#;

    fn spec() -> TestSpec {
        TestSpec::parse(SPEC_JSON).unwrap()
    }

    #[test]
    fn generated_source_embeds_steps_and_executor() {
        let src = generate_probe_main_rs(&spec()).unwrap();
        // 実行の中核が埋め込まれていること。
        assert!(src.contains("fn run_embedded"));
        assert!(src.contains("CALL_TABLE"));
        // ステップが Rust リテラルになっていること。パスは正しく
        // エスケープされていること（`\\` が 2 文字になる）。
        assert!(src.contains("CreateFileW"));
        assert!(src.contains("C:\\\\temp\\\\probe.txt"));
        assert!(src.contains("ArgValue::Ref(\"hFile\".to_string())"));
        assert!(src.contains("fn main()"));
        // 生成物は自己完結していること（クレートへの依存が無い）。
        assert!(!src.contains("shirusu_"));
        assert!(!src.contains("extern crate"));
    }

    #[test]
    fn build_rejects_non_windows_target_and_empty_steps() {
        let dir = std::env::temp_dir();
        let out = dir.join("shirusu-probe-l20-test-nope.exe");
        assert!(build_probe_exe(&spec(), "x86_64-unknown-linux-gnu", &out).is_err());
        let empty = TestSpec::parse(r#"{"version":1,"name":"e","steps":[],"rules":[]}"#).unwrap();
        assert!(build_probe_exe(&empty, "x86_64-pc-windows-gnu", &out).is_err());
    }

    #[test]
    fn rust_string_escapes() {
        assert_eq!(rust_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(rust_string("C:\\temp\\x"), "\"C:\\\\temp\\\\x\"");
    }

    #[test]
    fn sample_spec_parses() {
        // サンプル仕様ファイルが読めることは統合テストでも確かめるが、
        // ここでは同じ JSON 文字列が仕様として成立することを見る。
        let text = include_str!("../tests/data/probe-sample.json");
        let parsed = TestSpec::parse(text).unwrap();
        assert_eq!(parsed.name, "probe-sample");
        assert!(!parsed.steps.is_empty());
        let _ = parse_json(text).unwrap();
    }
}
