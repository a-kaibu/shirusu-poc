//! shirusu 解析 CLI（overview のコンポーネント表に対応）。
//!
//! - `shirusu inspect <trace>`: セッションメタデータ、三つの完全性
//!   指標、API 別集計を表示する。
//! - `shirusu dump <trace> [フィルタ]`: イベントを 1 行ずつ表示する。
//!   `--json` で JSON 配列。フィルタは CLI オプションの組であり、
//!   独自のクエリ言語は作らない（overview の方針）。
//! - `shirusu export <trace> --format jsonl|parquet`: JSON Lines / Parquet へ書き出す。
//! - `shirusu repair <trace> [--output <path>] [--json]`: 回復読みで
//!   読めたイベントだけを新しい Trace に書き出す（L12）。失われた
//!   イベントを推測で作らない（overview「完全性と復旧」）。
//! - `shirusu capture [--output <path>] [--dll <path>] [--timeout <secs>]
//!   [--order=global] [--module-class <module>=<class>] [--record-runtime-apis]
//!   [--mode <full|profile|filtered|detailed>] [--api <name>]
//!   -- <exe> [args...]`: 対象を起動して最初から記録する
//!   （L22、Windows 専用）。
//! - `shirusu attach <PID> [options]`: 動作中のプロセスに途中から記録する
//!   （L22、Windows 専用）。アタッチ前の来歴は不明として Trace に残す。
//!
//! 解析はクロスプラットフォーム（記録は Windows、解析は任意 OS）。
//! 終了コード: 0 = 成功、1 = 入力/形式エラー、記録の失敗、または Event Integrity
//! を失った Trace の inspect（H14: incomplete の通知）、2 = 使い方の誤り。
//! repair の失敗（入力が読めない・出力が書けない・入出力が同一）も 1。
//! Windows 以外での capture / attach も 1（引数の検証まで済ませてから
//! プラットフォーム制限を明言する）。

mod capture;
mod coverage;
mod dump_export;
mod inspect;
mod parquet_export;
mod repair;

use shirusu_analysis::{
    api_name_of_schema, integrity_level_name, loss_kind_name, EventFilter, JsonValue, TraceView,
};
use shirusu_host::trace_convert::{resolve_api_names, RecordMode};
use shirusu_trace::blob::BlobId;
use shirusu_trace::module::{
    apply_overrides, classify_module, ModuleClassification, ModuleEvidence, ModuleOverride,
};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::{EventBatch, FinalizationInfo, PayloadRef, TraceEvent, TraceWriter};
use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use capture::*;
use dump_export::*;
use inspect::*;
use repair::*;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::from(0),
        Err(ToolError::Usage(msg)) => {
            eprintln!("usage error: {msg}\n\n{}", usage());
            ExitCode::from(2)
        }
        Err(ToolError::Runtime(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(1)
        }
        Err(ToolError::Incomplete(msg)) => {
            eprintln!("incomplete trace: {msg}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum ToolError {
    Usage(String),
    Runtime(String),
    /// Trace は読めたが Event Integrity を失っている (H14)。
    /// 表示は出したうえで終了 1 にする (Runtime と同じ終了値)。
    Incomplete(String),
}

fn usage() -> &'static str {
    "shirusu <command> <trace> [options]\n\
     \n\
     commands:\n\
     \x20 capabilities [--json]           supported APIs and capture limits\n\
     \x20 coverage <trace> [--json]         per-API evidence ledger\n\
     \x20 inspect <trace> [--json]          metadata, integrity, per-API counts\n\
     \x20 dump <trace> [filters] [--json]   one line per event\n\
     \x20 export <trace> --format jsonl|parquet [--output <path>]\n\
     \x20 \x20 Parquet requires --output; see docs/parquet-export.md\n\
     \x20 repair <trace> [--output <path>] [--json]\n\
     \x20 \x20 recover readable events into a new trace (default: <trace>.repaired)\n\
     \x20 capture [options] -- <exe> [args...]\n\
     \x20 \x20 launch <exe> and record from the start (Windows only;\n\
     \x20 \x20 waits until the target exits; default output: <exe>.trace)\n\
     \x20 attach <PID> [options]\n\
     \x20 \x20 attach to a running process and record from now on (Windows only;\n\
     \x20 \x20 waits until the target exits; default output: shirusu-attach-<PID>.trace)\n\
     \n\
     capture / attach options:\n\
     \x20 --output <path>  --dll <path>  --timeout <secs> (init timeout, default 30)\n\
     \x20 --buffer <standard|burst>  (burst uses ~40 MiB shared Rings/process; default: standard)\n\
     \x20 --order=global  (record with a global observation order, L11)\n\
     \x20 --module-class <module>=<class>  (repeatable; windows/runtime/application/unknown, L07)\n\
     \x20 --record-runtime-apis  (also record the Runtime's own APIs, L07; default: off)\n\
     \x20 --diagnostic-query-interface  (let the interceptor call QueryInterface(IID_IUnknown) to confirm identity, L02; default: off)\n\
     \x20 --mode <full|profile|filtered|detailed>  (record mode, L09/L15; default: full)\n\
     \x20 --api <name>  (repeatable; only with --mode filtered, e.g. CreateFileW)\n\
     \x20 --follow-children  (also record child processes of the launched target, L05; capture only)\n\
     \n\
     detailed mode (L15) also records Windows internal calls (Nt*) as separate\n\
     calls with a parent link, and forces --record-runtime-apis on.\n\
     \n\
     dump filters:\n\
     \x20 --api <substr|api_id>  --kind <enter|leave|number>\n\
     \x20 --seq <min>..<max>     --thread <id>  --text <substr>\n\
     \x20 --limit <n>  --order=global  (global observation order)"
}

fn run(args: &[String]) -> Result<(), ToolError> {
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => return Err(ToolError::Usage("no command given".into())),
    };
    match cmd {
        "inspect" => cmd_inspect(rest),
        "coverage" => coverage::run(rest),
        "capabilities" => cmd_capabilities(rest),
        "dump" => cmd_dump(rest),
        "export" => cmd_export(rest),
        "repair" => cmd_repair(rest),
        "capture" => cmd_capture(rest),
        "attach" => cmd_attach(rest),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(ToolError::Usage(format!("unknown command: {other}"))),
    }
}

fn cmd_capabilities(args: &[String]) -> Result<(), ToolError> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return Err(ToolError::Usage("capabilities accepts only --json".into())),
    };
    let mut apis: Vec<_> = shirusu_hook::api::api_table().collect();
    apis.sort_by_key(|a| a.api_id);
    if json {
        let report = JsonValue::obj(vec![
            (
                "apis",
                JsonValue::Array(
                    apis.iter()
                        .map(|a| {
                            JsonValue::obj(vec![
                                ("id", JsonValue::U64(u64::from(a.api_id))),
                                ("module", JsonValue::Str(a.module.into())),
                                ("function", JsonValue::Str(a.function.into())),
                                ("level", JsonValue::U64(u64::from(a.level))),
                                ("detail", JsonValue::Str(a.level_note.into())),
                                (
                                    "detailed_mode_only",
                                    JsonValue::Bool(shirusu_hook::api::is_internal_api(a.api_id)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "com",
                JsonValue::obj(vec![
                    (
                        "known_iids",
                        JsonValue::U64(shirusu_trace::com_catalog::COM_INTERFACES.len() as u64),
                    ),
                    (
                        "factories",
                        JsonValue::Array(vec![
                            JsonValue::Str("CoCreateInstance".into()),
                            JsonValue::Str("CoGetClassObject".into()),
                        ]),
                    ),
                    ("standard_method_interception", JsonValue::Bool(true)),
                    (
                        "method_limit",
                        JsonValue::Str("image-backed-iunknown-only".into()),
                    ),
                ]),
            ),
        ]);
        println!("{}", report.render_pretty());
    } else {
        println!(
            "{} supported Win32/internal APIs (L1: values; L2: captured data)",
            apis.len()
        );
        for api in apis {
            println!(
                "L{} {}!{}{}",
                api.level,
                api.module,
                api.function,
                if shirusu_hook::api::is_internal_api(api.api_id) {
                    " [detailed mode]"
                } else {
                    ""
                }
            );
        }
        println!("COM: {} known IIDs; factory observation; partial method interception (image-backed-iunknown-only)", shirusu_trace::com_catalog::COM_INTERFACES.len());
    }
    Ok(())
}

/// 位置引数（Trace パス）と `--key value` / `--flag` を分ける。
struct Parsed {
    positional: Vec<String>,
    opts: Vec<(String, Option<String>)>,
}

fn parse_args(args: &[String], flags: &[&str]) -> Result<Parsed, ToolError> {
    let mut parsed = Parsed {
        positional: Vec::new(),
        opts: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(name) = arg.strip_prefix("--") {
            // `--key=value` 形式も受け付ける（overview の `--order=global`
            // の表記どおり打てるようにする。値は最初の `=` で区切る）。
            if let Some((name, value)) = name.split_once('=') {
                if flags.contains(&name) {
                    return Err(ToolError::Usage(format!("--{name} does not take a value")));
                }
                parsed
                    .opts
                    .push((name.to_string(), Some(value.to_string())));
                i += 1;
                continue;
            }
            if flags.contains(&name) {
                parsed.opts.push((name.to_string(), None));
                i += 1;
            } else {
                let value = args
                    .get(i + 1)
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| ToolError::Usage(format!("--{name} needs a value")))?;
                parsed.opts.push((name.to_string(), Some(value.clone())));
                i += 2;
            }
        } else {
            parsed.positional.push(arg.clone());
            i += 1;
        }
    }
    Ok(parsed)
}

impl Parsed {
    fn validate_options(&self, allowed: &[&str]) -> Result<(), ToolError> {
        for (name, _) in &self.opts {
            if !allowed.contains(&name.as_str()) {
                return Err(ToolError::Usage(format!("unknown option: --{name}")));
            }
        }
        Ok(())
    }
    fn opt(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }
    /// 繰り返し指定できるオプションの全値（指定順）。
    fn opts_all(&self, name: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(n, _)| n == name)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }
    fn has(&self, name: &str) -> bool {
        self.opts.iter().any(|(n, _)| n == name)
    }
}

fn load_trace(parsed: &Parsed) -> Result<(String, ReadTrace), ToolError> {
    let path = parsed
        .positional
        .first()
        .ok_or_else(|| ToolError::Usage("missing <trace> path".to_string()))?
        .clone();
    if parsed.positional.len() > 1 {
        return Err(ToolError::Usage("too many positional arguments".into()));
    }
    let data =
        std::fs::read(&path).map_err(|e| ToolError::Runtime(format!("cannot read {path}: {e}")))?;
    let trace = shirusu_trace::read_trace(&data)
        .map_err(|e| ToolError::Runtime(format!("{path} is not a readable trace: {e}")))?;
    Ok((path, trace))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::module::ModuleClass;
    use std::collections::BTreeSet;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cmdline_joins_plain_parts() {
        assert_eq!(build_cmdline(&args(&["a.exe", "b", "c"])), "a.exe b c");
    }

    #[test]
    fn cmdline_quotes_parts_with_spaces() {
        assert_eq!(
            build_cmdline(&args(&["C:\\Program Files\\app.exe", "--flag", "a b"])),
            "\"C:\\Program Files\\app.exe\" --flag \"a b\""
        );
    }

    #[test]
    fn cmdline_escapes_inner_quotes() {
        assert_eq!(build_cmdline(&args(&["say \"hi\""])), "\"say \\\"hi\\\"\"");
    }

    /// Reference decoder for the argument rules of `CommandLineToArgvW`
    /// (arguments after the program name).
    fn parse_windows_args(cmdline: &str) -> Vec<String> {
        let chars: Vec<char> = cmdline.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                i += 1;
            }
            if i >= chars.len() {
                return out;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while i < chars.len() && (quoted || !matches!(chars[i], ' ' | '\t')) {
                let mut slashes = 0;
                while i < chars.len() && chars[i] == '\\' {
                    slashes += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    arg.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        arg.push('"');
                    } else if quoted && i + 1 < chars.len() && chars[i + 1] == '"' {
                        arg.push('"');
                        i += 1;
                    } else {
                        quoted = !quoted;
                    }
                    i += 1;
                } else {
                    arg.extend(std::iter::repeat_n('\\', slashes));
                    if i < chars.len() && (quoted || !matches!(chars[i], ' ' | '\t')) {
                        arg.push(chars[i]);
                        i += 1;
                    }
                }
            }
            out.push(arg);
        }
    }

    #[test]
    fn cmdline_roundtrips_backslashes_quotes_and_empty_args() {
        let cases = args(&[
            "",
            r"C:\dir with space\",
            r"trailing\\",
            r"a\b",
            r#"a\"b"#,
            r#"a\\"b c"#,
            "tab\there",
            "plain",
            r#"""#,
            r"\\server\share\x y",
        ]);
        let line = build_cmdline(&cases);
        assert_eq!(parse_windows_args(&line), cases, "{line}");
        assert_eq!(build_cmdline(&args(&["a.exe", "", "b"])), "a.exe \"\" b");
        assert_eq!(
            build_cmdline(&args(&[r"C:\dir with space\"])),
            r#""C:\dir with space\\""#
        );
    }

    #[test]
    fn split_dashdash_without_separator() {
        let a = args(&["--timeout", "10"]);
        let (before, after) = split_dashdash(&a);
        assert_eq!(before, &a[..]);
        assert!(after.is_empty());
    }

    #[test]
    fn split_dashdash_splits_at_first_separator() {
        let a = args(&["--timeout", "10", "--", "a.exe", "--", "x"]);
        let (before, after) = split_dashdash(&a);
        assert_eq!(before, args(&["--timeout", "10"]));
        assert_eq!(after, args(&["a.exe", "--", "x"]));
    }

    #[test]
    fn default_capture_output_uses_exe_stem() {
        assert_eq!(default_capture_output("app.exe"), "app.trace");
        assert_eq!(
            default_capture_output("C:/Program Files/my app.exe"),
            "my app.trace"
        );
        assert_eq!(default_capture_output("app"), "app.trace");
    }

    /// Windows では `\` もパス区切りになる（Linux では通常文字のため、
    /// この期待値は Windows でのみ成り立つ）。
    #[cfg(windows)]
    #[test]
    fn default_capture_output_windows_path() {
        assert_eq!(
            default_capture_output("C:\\Program Files\\my app.exe"),
            "my app.trace"
        );
    }

    #[test]
    fn default_attach_output_names_pid() {
        assert_eq!(default_attach_output(1234), "shirusu-attach-1234.trace");
    }

    #[test]
    fn capture_options_parse_all() {
        let parsed = parse_args(
            &args(&[
                "--output",
                "o.trace",
                "--dll",
                "d.dll",
                "--timeout",
                "10",
                "--order=global",
            ]),
            &[],
        )
        .unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.output.as_deref(), Some("o.trace"));
        assert_eq!(opts.dll, Some(PathBuf::from("d.dll")));
        assert_eq!(opts.timeout_secs, 10);
        assert!(opts.order_global);
    }

    #[test]
    fn capture_options_defaults() {
        let parsed = parse_args(&[], &[]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.output, None);
        assert_eq!(opts.dll, None);
        assert_eq!(opts.timeout_secs, 30);
        assert!(!opts.order_global);
        assert_eq!(opts.ring_config, shirusu_transport::RingConfig::PRODUCTION);
    }

    #[test]
    fn capture_buffer_profiles_are_explicit_and_bounded() {
        for (name, expected) in [
            ("standard", shirusu_transport::RingConfig::PRODUCTION),
            ("burst", shirusu_transport::RingConfig::BURST),
        ] {
            let parsed = parse_args(&args(&["--buffer", name]), &[]).unwrap();
            let opts = CaptureOptions::parse(&parsed).unwrap();
            assert_eq!(opts.ring_config, expected);
            assert_eq!(opts.ring_config.payload_capacity, 1024 * 1024);
        }
        let parsed = parse_args(&args(&["--buffer=unlimited"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_rejects_bad_timeout() {
        let parsed = parse_args(&args(&["--timeout", "abc"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_rejects_bad_order() {
        let parsed = parse_args(&args(&["--order=bogus"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn launch_environment_records_target_and_session() {
        let mode = CaptureMode::Launch {
            cmdline: "app.exe".into(),
            exe: "C:\\tools\\app.exe".into(),
        };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert_eq!(env.session.session_id, 4242);
        assert_eq!(env.session.created_by, "shirusu capture");
        assert_eq!(env.session.qpc_frequency, 10_000_000);
        assert_eq!(env.target_description, "C:\\tools\\app.exe");
        assert_eq!(env.capture_config, "launched; mode=full");
    }

    #[test]
    fn attach_environment_marks_unknown_provenance() {
        let mode = CaptureMode::Attach { pid: 1234 };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert_eq!(env.session.session_id, 4242);
        assert_eq!(env.session.created_by, "shirusu attach");
        assert_eq!(env.target_description, "pid 1234");
        assert!(
            env.capture_config.contains("unknown provenance"),
            "{}",
            env.capture_config
        );
        assert!(
            env.capture_config.contains("attached pid=1234"),
            "{}",
            env.capture_config
        );
    }

    // L07: `--module-class` と `--record-runtime-apis` の解析と、
    // capture_environment へのモジュール分類の記録。
    #[test]
    fn capture_options_parses_module_class_repeated() {
        let parsed = parse_args(
            &args(&[
                "--module-class",
                "kernel32.dll=windows",
                "--module-class",
                "foo.dll=runtime",
            ]),
            &[],
        )
        .unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.module_classes.len(), 2);
        assert_eq!(opts.module_classes[0].module, "kernel32.dll");
        assert_eq!(opts.module_classes[0].class, ModuleClass::Windows);
        assert_eq!(opts.module_classes[1].module, "foo.dll");
        assert_eq!(opts.module_classes[1].class, ModuleClass::Runtime);
    }

    #[test]
    fn capture_options_rejects_bad_module_class() {
        let parsed = parse_args(&args(&["--module-class", "foo=banana"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_record_runtime_apis_flag() {
        let parsed =
            parse_args(&args(&["--record-runtime-apis"]), &["record-runtime-apis"]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert!(opts.record_runtime_apis);
    }

    #[test]
    fn capture_options_record_runtime_apis_default_off() {
        let parsed = parse_args(&[], &[]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert!(!opts.record_runtime_apis);
        assert!(opts.module_classes.is_empty());
    }

    #[test]
    fn launch_environment_classifies_target_exe() {
        let mode = CaptureMode::Launch {
            cmdline: "app.exe".into(),
            exe: r"C:\tools\app.exe".into(),
        };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert_eq!(env.modules.len(), 1);
        assert_eq!(env.modules[0].module_name, r"C:\tools\app.exe");
        assert_eq!(env.modules[0].class, ModuleClass::Application);
        assert!(!env.modules[0].overridden);
    }

    #[test]
    fn launch_environment_applies_module_overrides() {
        let mode = CaptureMode::Launch {
            cmdline: "app.exe".into(),
            exe: r"C:\tools\app.exe".into(),
        };
        let overrides = vec![ModuleOverride::parse("kernel32.dll=windows").unwrap()];
        let env = capture_environment(&mode, 4242, 10_000_000, &overrides, &RecordMode::Full, &[]);
        assert_eq!(env.modules.len(), 2);
        let k = env
            .modules
            .iter()
            .find(|m| m.module_name == "kernel32.dll")
            .unwrap();
        assert_eq!(k.class, ModuleClass::Windows);
        assert!(k.overridden);
    }

    #[test]
    fn attach_environment_without_overrides_has_no_modules() {
        let mode = CaptureMode::Attach { pid: 1234 };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert!(env.modules.is_empty());
    }

    // L13: 起動対象の exe の PE インポートテーブルを静的依存として記録する。
    // attach では対象 exe のパスが分からないため空のまま。
    fn write_synthetic_pe_file(name: &str) -> PathBuf {
        // host の synthetic_pe_file と同じ最小 PE32+ ファイル（1 セクション、
        // kernel32.dll の 2 インポート）。ここでは CLI の単体テスト用に
        // 最小限の複製を持つ。
        fn w16(b: &mut [u8], off: usize, v: u16) {
            b[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn w32(b: &mut [u8], off: usize, v: u32) {
            b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn w64(b: &mut [u8], off: usize, v: u64) {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        fn wstr(b: &mut [u8], off: usize, s: &str) {
            b[off..off + s.len()].copy_from_slice(s.as_bytes());
            b[off + s.len()] = 0;
        }
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        w32(&mut b, 0x3C, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        w16(&mut b, coff + 2, 1);
        w16(&mut b, coff + 16, 240);
        let opt = coff + 20;
        w16(&mut b, opt, 0x20B);
        w32(&mut b, opt + 56, 0x2000);
        w32(&mut b, opt + 60, 0x200);
        w32(&mut b, opt + 112 + 8, 0x1000);
        w32(&mut b, opt + 112 + 12, 40);
        let sec = opt + 240;
        w32(&mut b, sec + 8, 0x200);
        w32(&mut b, sec + 12, 0x1000);
        w32(&mut b, sec + 16, 0x200);
        w32(&mut b, sec + 20, 0x200);
        let s = |off: usize| 0x200 + (off - 0x1000);
        w32(&mut b, s(0x1000), 0x1030);
        w32(&mut b, s(0x1000) + 12, 0x1060);
        w32(&mut b, s(0x1000) + 16, 0x1050);
        w64(&mut b, s(0x1030), 0x1070);
        w64(&mut b, s(0x1038), 0x8000_0000_0000_0000 | 42);
        w64(&mut b, s(0x1040), 0);
        wstr(&mut b, s(0x1060), "kernel32.dll");
        w16(&mut b, s(0x1070), 0);
        wstr(&mut b, s(0x1072), "CreateFileW");
        let path =
            std::env::temp_dir().join(format!("shirusu-l13-cli-{name}-{}.exe", std::process::id()));
        std::fs::write(&path, &b).unwrap();
        path
    }

    #[test]
    fn launch_environment_records_static_dependencies_from_pe_file() {
        let exe_path = write_synthetic_pe_file("launch");
        let mode = CaptureMode::Launch {
            cmdline: exe_path.to_string_lossy().into_owned(),
            exe: exe_path.to_string_lossy().into_owned(),
        };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        let _ = std::fs::remove_file(&exe_path);
        assert_eq!(env.static_dependencies.len(), 1);
        assert_eq!(env.static_dependencies[0].module, "kernel32.dll");
        assert_eq!(env.static_dependencies[0].imports.len(), 2);
        assert_eq!(
            env.static_dependencies[0].imports[0].name.as_deref(),
            Some("CreateFileW")
        );
        assert_eq!(env.static_dependencies[0].imports[1].ordinal, Some(42));
    }

    #[test]
    fn launch_environment_with_missing_exe_has_no_static_dependencies() {
        let mode = CaptureMode::Launch {
            cmdline: "no-such-target.exe".into(),
            exe: "no-such-target.exe".into(),
        };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert!(env.static_dependencies.is_empty());
    }

    #[test]
    fn attach_environment_has_no_static_dependencies() {
        let mode = CaptureMode::Attach { pid: 1234 };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Full, &[]);
        assert!(env.static_dependencies.is_empty());
    }

    // L09: `--mode` / `--api` の解析と、Environment への記録モードの明記。
    #[test]
    fn capture_options_parses_mode_profile() {
        let parsed = parse_args(&args(&["--mode", "profile"]), &[]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.record_mode, RecordMode::Profile);
    }

    // L15: `--mode detailed` は詳細調査モードになり、Runtime 起源の
    // 呼び出しの記録も強制的に有効になる。
    #[test]
    fn capture_options_parses_mode_detailed() {
        let parsed = parse_args(&args(&["--mode", "detailed"]), &[]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.record_mode, RecordMode::Detailed);
        assert!(opts.record_runtime_apis);
    }

    #[test]
    fn capture_options_parses_mode_filtered_with_apis() {
        let parsed = parse_args(
            &args(&[
                "--mode",
                "filtered",
                "--api",
                "CreateFileW",
                "--api",
                "kernel32!ReadFile",
            ]),
            &[],
        )
        .unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(
            opts.record_mode,
            RecordMode::Filtered {
                apis: BTreeSet::from([1, 2])
            }
        );
        assert_eq!(opts.api_names, vec!["CreateFileW", "kernel32!ReadFile"]);
    }

    #[test]
    fn capture_options_defaults_to_full_mode() {
        let parsed = parse_args(&[], &[]).unwrap();
        let opts = CaptureOptions::parse(&parsed).unwrap();
        assert_eq!(opts.record_mode, RecordMode::Full);
        assert!(opts.api_names.is_empty());
    }

    #[test]
    fn capture_options_rejects_bad_mode() {
        let parsed = parse_args(&args(&["--mode", "bogus"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_rejects_api_without_filtered() {
        let parsed = parse_args(&args(&["--api", "CreateFileW"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_rejects_filtered_without_api() {
        let parsed = parse_args(&args(&["--mode", "filtered"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn capture_options_rejects_unknown_api() {
        let parsed = parse_args(&args(&["--mode", "filtered", "--api", "NoSuchApi"]), &[]).unwrap();
        assert!(matches!(
            CaptureOptions::parse(&parsed),
            Err(ToolError::Usage(_))
        ));
    }

    #[test]
    fn launch_environment_records_profile_mode() {
        let mode = CaptureMode::Launch {
            cmdline: "app.exe".into(),
            exe: r"C:\tools\app.exe".into(),
        };
        let env = capture_environment(&mode, 4242, 10_000_000, &[], &RecordMode::Profile, &[]);
        assert!(
            env.capture_config.contains("mode=profile"),
            "{}",
            env.capture_config
        );
    }

    #[test]
    fn launch_environment_records_filtered_apis() {
        let mode = CaptureMode::Launch {
            cmdline: "app.exe".into(),
            exe: r"C:\tools\app.exe".into(),
        };
        let env = capture_environment(
            &mode,
            4242,
            10_000_000,
            &[],
            &RecordMode::Filtered {
                apis: BTreeSet::from([1, 2]),
            },
            &["CreateFileW".to_string(), "ReadFile".to_string()],
        );
        assert!(
            env.capture_config
                .contains("mode=filtered apis=CreateFileW,ReadFile"),
            "{}",
            env.capture_config
        );
    }
}
