//! shirusu 解析 CLI（overview のコンポーネント表に対応）。
//!
//! - `shirusu inspect <trace>`: セッションメタデータ、三つの完全性
//!   指標、API 別集計を表示する。
//! - `shirusu dump <trace> [フィルタ]`: イベントを 1 行ずつ表示する。
//!   `--json` で JSON 配列。フィルタは CLI オプションの組であり、
//!   独自のクエリ言語は作らない（overview の方針）。
//! - `shirusu export <trace> --format jsonl`: JSON Lines で書き出す。
//!
//! 解析はクロスプラットフォーム（記録は Windows、解析は任意 OS）。
//! 終了コード: 0 = 成功、1 = 入力/形式エラー、2 = 使い方の誤り。

use shirusu_analysis::{integrity_level_name, loss_kind_name, EventFilter, JsonValue, TraceView};
use shirusu_trace::reader::ReadTrace;
use std::io::Write as _;
use std::process::ExitCode;

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
    }
}

enum ToolError {
    Usage(String),
    Runtime(String),
}

fn usage() -> &'static str {
    "shirusu <command> <trace> [options]\n\
     \n\
     commands:\n\
     \x20 inspect <trace> [--json]          metadata, integrity, per-API counts\n\
     \x20 dump <trace> [filters] [--json]   one line per event\n\
     \x20 export <trace> --format jsonl [--output <path>]\n\
     \n\
     dump filters:\n\
     \x20 --api <substr|api_id>  --kind <enter|leave|number>\n\
     \x20 --seq <min>..<max>     --thread <id>  --text <substr>\n\
     \x20 --limit <n>"
}

fn run(args: &[String]) -> Result<(), ToolError> {
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => return Err(ToolError::Usage("no command given".into())),
    };
    match cmd {
        "inspect" => cmd_inspect(rest),
        "dump" => cmd_dump(rest),
        "export" => cmd_export(rest),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(ToolError::Usage(format!("unknown command: {other}"))),
    }
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
            if flags.contains(&name) {
                parsed.opts.push((name.to_string(), None));
                i += 1;
            } else {
                let value = args
                    .get(i + 1)
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
    fn opt(&self, name: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
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

fn cmd_inspect(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    let (path, trace) = load_trace(&parsed)?;
    let view = TraceView::build(&trace);
    if parsed.has("json") {
        println!("{}", inspect_json(&path, &view).render_pretty());
    } else {
        for line in inspect_lines(&path, &view) {
            println!("{line}");
        }
    }
    Ok(())
}

fn inspect_lines(path: &str, view: &TraceView) -> Vec<String> {
    let trace = view.trace;
    let s = &view.integrity;
    let mut out = Vec::new();
    out.push(format!("file: {path}"));
    out.push(format!(
        "container: version={} schema={} session={}",
        trace.header.container_version, trace.header.schema_version, trace.header.session_id
    ));
    match &trace.environment {
        Some(env) => {
            out.push("environment:".into());
            out.push(format!("  created_by: {}", env.session.created_by));
            out.push(format!("  os: {} (build {})", env.os_version, env.os_build));
            out.push(format!(
                "  cpu_arch: {} pointer_width: {}",
                env.cpu_arch, env.pointer_width
            ));
            out.push(format!(
                "  session_qpc_frequency: {}",
                env.session.qpc_frequency
            ));
            if !env.target_description.is_empty() {
                out.push(format!("  target: {}", env.target_description));
            }
            if !env.capture_config.is_empty() {
                out.push(format!("  capture_config: {}", env.capture_config));
            }
        }
        None => out.push("environment: (absent)".into()),
    }
    let blob_bytes: u64 = trace.blobs.values().map(|b| b.len() as u64).sum();
    out.push(format!(
        "events: {} in {} batches, {} threads",
        trace.total_events(),
        trace.batches.len(),
        view.thread_count()
    ));
    out.push(format!(
        "blobs: {} stored, {} bytes",
        trace.blobs.len(),
        blob_bytes
    ));
    out.push(format!("schemas: {} registered", trace.schemas.len()));
    out.push("integrity:".into());
    let level = |v: Option<u32>| match v {
        Some(v) => format!("{} ({v})", integrity_level_name(v)),
        None => "Unknown (no finalization)".to_string(),
    };
    out.push(format!("  capture_coverage: {}", level(s.capture_coverage)));
    out.push(format!("  event_integrity: {}", level(s.event_integrity)));
    out.push(format!(
        "  semantic_completeness: {}",
        level(s.semantic_completeness)
    ));
    out.push(format!(
        "  finalized_cleanly: {}",
        if s.finalized_cleanly {
            "yes"
        } else if s.has_finalization {
            "no (finalization present but not clean)"
        } else {
            "unknown (no finalization block)"
        }
    ));
    for note in &s.finalization_notes {
        out.push(format!("  note: {note}"));
    }
    if s.loss_records_by_kind.is_empty() {
        out.push("  loss_records: none".into());
    } else {
        for (kind, records) in &s.loss_records_by_kind {
            out.push(format!(
                "  loss_records: {} x{records} (total count {})",
                loss_kind_name(*kind),
                s.total_loss_count
            ));
        }
    }
    out.push(format!(
        "  dropped_payloads: {} events, {} bytes",
        s.dropped_payload_events, s.dropped_payload_bytes
    ));
    out.push(format!("  degraded_events: {}", s.degraded_events));
    out.push(format!("  missing_blob_refs: {}", s.missing_blob_refs));
    out.push(format!("  recovery_issues: {}", s.recovery_issues.len()));
    for issue in &s.recovery_issues {
        out.push(format!("    - {issue}"));
    }
    out.push(format!(
        "  index: {}",
        if !s.has_stored_index {
            "absent"
        } else if s.index_matches_scan {
            "matches scan"
        } else {
            "mismatch (scan wins, index ignored)"
        }
    ));
    out.push("api:".into());
    for (api, enter, leave) in view.api_stats() {
        out.push(format!("  {api} enter={enter} leave={leave}"));
    }
    out
}

fn inspect_json(path: &str, view: &TraceView) -> JsonValue {
    let trace = view.trace;
    let s = &view.integrity;
    let env = trace.environment.as_ref().map(|env| {
        JsonValue::obj(vec![
            ("created_by", JsonValue::Str(env.session.created_by.clone())),
            ("os_version", JsonValue::Str(env.os_version.clone())),
            ("os_build", JsonValue::U64(env.os_build as u64)),
            ("cpu_arch", JsonValue::Str(env.cpu_arch.clone())),
            ("pointer_width", JsonValue::U64(env.pointer_width as u64)),
            (
                "session_qpc_frequency",
                JsonValue::U64(env.session.qpc_frequency),
            ),
            ("target", JsonValue::Str(env.target_description.clone())),
            ("capture_config", JsonValue::Str(env.capture_config.clone())),
        ])
    });
    let level = |v: Option<u32>| match v {
        Some(v) => JsonValue::Str(integrity_level_name(v).to_string()),
        None => JsonValue::Null,
    };
    let loss = s
        .loss_records_by_kind
        .iter()
        .map(|(kind, records)| {
            JsonValue::obj(vec![
                ("kind", JsonValue::Str(loss_kind_name(*kind).to_string())),
                ("records", JsonValue::U64(*records)),
            ])
        })
        .collect();
    let apis = view
        .api_stats()
        .into_iter()
        .map(|(api, enter, leave)| {
            JsonValue::obj(vec![
                ("api", JsonValue::Str(api)),
                ("enter", JsonValue::U64(enter)),
                ("leave", JsonValue::U64(leave)),
            ])
        })
        .collect();
    JsonValue::obj(vec![
        ("file", JsonValue::Str(path.to_string())),
        ("session_id", JsonValue::U64(trace.header.session_id)),
        (
            "container_version",
            JsonValue::U64(trace.header.container_version as u64),
        ),
        (
            "schema_version",
            JsonValue::U64(trace.header.schema_version as u64),
        ),
        ("environment", env.unwrap_or(JsonValue::Null)),
        ("events", JsonValue::U64(trace.total_events())),
        ("batches", JsonValue::U64(trace.batches.len() as u64)),
        ("threads", JsonValue::U64(view.thread_count() as u64)),
        ("blobs", JsonValue::U64(trace.blobs.len() as u64)),
        ("schemas", JsonValue::U64(trace.schemas.len() as u64)),
        (
            "integrity",
            JsonValue::obj(vec![
                ("capture_coverage", level(s.capture_coverage)),
                ("event_integrity", level(s.event_integrity)),
                ("semantic_completeness", level(s.semantic_completeness)),
                ("finalized_cleanly", JsonValue::Bool(s.finalized_cleanly)),
                ("has_finalization", JsonValue::Bool(s.has_finalization)),
                ("loss_records", JsonValue::Array(loss)),
                ("total_loss_count", JsonValue::U64(s.total_loss_count)),
                (
                    "dropped_payload_events",
                    JsonValue::U64(s.dropped_payload_events),
                ),
                (
                    "dropped_payload_bytes",
                    JsonValue::U64(s.dropped_payload_bytes),
                ),
                ("degraded_events", JsonValue::U64(s.degraded_events)),
                ("missing_blob_refs", JsonValue::U64(s.missing_blob_refs)),
                (
                    "recovery_issues",
                    JsonValue::Array(
                        s.recovery_issues
                            .iter()
                            .cloned()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
                (
                    "index",
                    JsonValue::Str(
                        if !s.has_stored_index {
                            "absent"
                        } else if s.index_matches_scan {
                            "matches_scan"
                        } else {
                            "mismatch"
                        }
                        .to_string(),
                    ),
                ),
            ]),
        ),
        ("api_stats", JsonValue::Array(apis)),
    ])
}

fn build_filter(parsed: &Parsed) -> Result<EventFilter, ToolError> {
    let mut filter = EventFilter {
        api: parsed.opt("api").map(str::to_string),
        text: parsed.opt("text").map(str::to_string),
        ..Default::default()
    };
    if let Some(kind) = parsed.opt("kind") {
        filter.kind = Some(match kind {
            "enter" => shirusu_analysis::KIND_ENTER,
            "leave" => shirusu_analysis::KIND_LEAVE,
            other => other
                .parse::<u16>()
                .map_err(|_| ToolError::Usage(format!("bad --kind: {other}")))?,
        });
    }
    if let Some(seq) = parsed.opt("seq") {
        let (min, max) = seq
            .split_once("..")
            .ok_or_else(|| ToolError::Usage(format!("bad --seq (want A..B): {seq}")))?;
        filter.seq_min = Some(
            min.parse()
                .map_err(|_| ToolError::Usage(format!("bad --seq min: {min}")))?,
        );
        filter.seq_max = Some(
            max.parse()
                .map_err(|_| ToolError::Usage(format!("bad --seq max: {max}")))?,
        );
    }
    if let Some(tid) = parsed.opt("thread") {
        filter.thread_id = Some(
            tid.parse()
                .map_err(|_| ToolError::Usage(format!("bad --thread: {tid}")))?,
        );
    }
    Ok(filter)
}

fn cmd_dump(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    let (_path, trace) = load_trace(&parsed)?;
    let view = TraceView::build(&trace);
    let filter = build_filter(&parsed)?;
    let limit = match parsed.opt("limit") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| ToolError::Usage(format!("bad --limit: {v}")))?,
        ),
        None => None,
    };
    let matched: Vec<_> = view
        .events
        .iter()
        .filter(|e| filter.matches(e))
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if parsed.has("json") {
        let array = JsonValue::Array(matched.iter().map(|e| e.to_json()).collect());
        writeln!(lock, "{}", array.render())
            .map_err(|e| ToolError::Runtime(format!("write failed: {e}")))?;
    } else {
        for ev in matched {
            writeln!(lock, "{}", ev.line())
                .map_err(|e| ToolError::Runtime(format!("write failed: {e}")))?;
        }
    }
    Ok(())
}

fn cmd_export(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &[])?;
    let format = parsed
        .opt("format")
        .ok_or_else(|| ToolError::Usage("export needs --format".into()))?;
    if format != "jsonl" {
        return Err(ToolError::Usage(format!(
            "unsupported format: {format} (only jsonl is implemented)"
        )));
    }
    let (_path, trace) = load_trace(&parsed)?;
    let view = TraceView::build(&trace);
    let mut sink: Box<dyn std::io::Write> = match parsed.opt("output") {
        Some(path) => Box::new(
            std::fs::File::create(path)
                .map_err(|e| ToolError::Runtime(format!("cannot create {path}: {e}")))?,
        ),
        None => Box::new(std::io::stdout()),
    };
    for ev in &view.events {
        writeln!(sink, "{}", ev.to_json().render())
            .map_err(|e| ToolError::Runtime(format!("write failed: {e}")))?;
    }
    Ok(())
}
