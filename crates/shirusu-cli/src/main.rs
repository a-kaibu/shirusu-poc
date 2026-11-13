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

mod coverage;
mod parquet_export;

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
                    ("standard_method_interception", JsonValue::Bool(false)),
                    (
                        "method_limit",
                        JsonValue::Str("shared-object-safety-unproven".into()),
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
        println!("COM: {} known IIDs; factory observation; standard method interception unavailable (shared-object-safety-unproven)", shirusu_trace::com_catalog::COM_INTERFACES.len());
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
    // H14: Event Integrity を失った Trace は incomplete と判定し、
    // 終了ステータスでも失敗を知らせる (overview「Traceの完全性」)。
    // 判定は shirusu-test の no-integrity-loss と同じ述語
    // (`has_event_loss`) を使う。Finalization なし (Unknown) や
    // Index の不一致のみは別扱いだが、破損・切断・上限超過は incomplete。
    if view.integrity.has_event_loss() {
        return Err(ToolError::Incomplete(format!(
            "{path} lost event integrity (see the loss / dropped-payload / missing-blob lines above)"
        )));
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
            // L07: モジュール分類（無い Trace では出さない）。
            if !env.modules.is_empty() {
                out.push("  modules:".into());
                for m in &env.modules {
                    let mut line = format!("    {}: {} ({})", m.module_name, m.class, m.reason);
                    if m.uncertain {
                        line.push_str(" [uncertain]");
                    }
                    if m.overridden {
                        line.push_str(" [override]");
                    }
                    out.push(line);
                }
            }
            // L13: 静的依存情報（無い Trace では出さない）。
            if !env.static_dependencies.is_empty() {
                out.push("  static_dependencies:".into());
                for d in &env.static_dependencies {
                    let n = d.imports.len();
                    out.push(format!(
                        "    {}: {} import{}",
                        d.module,
                        n,
                        if n == 1 { "" } else { "s" }
                    ));
                    for imp in &d.imports {
                        out.push(format!("      {}", imp.label()));
                    }
                }
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
    // L11: 全体順序の有無を表示する（無い Trace では absent の 1 行）。
    let with_global = view
        .events
        .iter()
        .filter(|e| e.global_order.is_some())
        .count();
    out.push(if with_global == 0 {
        "global_order: absent".into()
    } else {
        format!(
            "global_order: present ({} of {} events)",
            with_global,
            view.events.len()
        )
    });
    out.push(format!(
        "blobs: {} stored, {} bytes",
        trace.blobs.len(),
        blob_bytes
    ));
    out.push(format!("schemas: {} registered", trace.schemas.len()));
    // L09: profile 集計（無い Trace では出さない）。
    if let Some(profile) = &trace.profile_summary {
        out.push("profile:".into());
        out.push(format!("  events seen: {}", profile.total_events_seen));
        for api in &profile.apis {
            let name = profile_api_name(trace, api.api_id);
            out.push(format!(
                "  {name}: {} calls, {} enters, {} leaves, total {}, min {}, max {}",
                api.calls,
                api.enters,
                api.leaves,
                qpc_ms(profile.qpc_frequency, api.total_duration_qpc),
                qpc_ms(profile.qpc_frequency, api.min_duration_qpc),
                qpc_ms(profile.qpc_frequency, api.max_duration_qpc),
            ));
        }
    }
    out.push("integrity:".into());
    out.push(format!(
        "  status: {}",
        if view.integrity.has_event_loss() {
            "incomplete"
        } else {
            "complete"
        }
    ));
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

/// QPC ティックをミリ秒表示にする（L09 の profile 表示用）。周波数が
/// 0（不明）のときはティック数をそのまま出す。
fn qpc_ms(qpc_frequency: u64, ticks: u64) -> String {
    if qpc_frequency == 0 {
        format!("{ticks} ticks")
    } else {
        format!("{:.3} ms", ticks as f64 * 1000.0 / qpc_frequency as f64)
    }
}

/// ProfileSummary の api_id から表示名を引く。enter Schema の名前
/// （`kernel32!CreateFileW/enter`）から API 名を取り出す。Schema が
/// 無ければ `api#<id>` とする。
fn profile_api_name(trace: &ReadTrace, api_id: u32) -> String {
    if api_id == 0 {
        return "api#0".to_string();
    }
    let enter_schema_id = (api_id - 1) * 2 + 1;
    trace
        .schemas
        .iter()
        .find(|s| s.schema_id == enter_schema_id)
        .map(|s| api_name_of_schema(&s.name).to_string())
        .unwrap_or_else(|| format!("api#{api_id}"))
}

fn inspect_json(path: &str, view: &TraceView) -> JsonValue {
    let trace = view.trace;
    let s = &view.integrity;
    let env = trace.environment.as_ref().map(|env| {
        let mut fields = vec![
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
        ];
        // L07: モジュール分類（無い Trace では出さない）。
        if !env.modules.is_empty() {
            let modules = env
                .modules
                .iter()
                .map(|m| {
                    JsonValue::obj(vec![
                        ("module", JsonValue::Str(m.module_name.clone())),
                        ("class", JsonValue::Str(m.class.as_str().to_string())),
                        ("reason", JsonValue::Str(m.reason.clone())),
                        ("uncertain", JsonValue::Bool(m.uncertain)),
                        (
                            "implementation_module",
                            m.implementation_module
                                .as_ref()
                                .map(|s| JsonValue::Str(s.clone()))
                                .unwrap_or(JsonValue::Null),
                        ),
                        ("overridden", JsonValue::Bool(m.overridden)),
                    ])
                })
                .collect();
            fields.push(("modules", JsonValue::Array(modules)));
        }
        // L13: 静的依存情報（無い Trace では出さない）。
        if !env.static_dependencies.is_empty() {
            let deps = env
                .static_dependencies
                .iter()
                .map(|d| {
                    JsonValue::obj(vec![
                        ("module", JsonValue::Str(d.module.clone())),
                        (
                            "imports",
                            JsonValue::Array(
                                d.imports
                                    .iter()
                                    .map(|imp| {
                                        JsonValue::obj(vec![
                                            (
                                                "name",
                                                imp.name
                                                    .as_ref()
                                                    .map(|s| JsonValue::Str(s.clone()))
                                                    .unwrap_or(JsonValue::Null),
                                            ),
                                            (
                                                "ordinal",
                                                imp.ordinal
                                                    .map(|o| JsonValue::U64(o as u64))
                                                    .unwrap_or(JsonValue::Null),
                                            ),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                    ])
                })
                .collect();
            fields.push(("static_dependencies", JsonValue::Array(deps)));
        }
        JsonValue::obj(fields)
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
        (
            "global_order_events",
            JsonValue::U64(
                view.events
                    .iter()
                    .filter(|e| e.global_order.is_some())
                    .count() as u64,
            ),
        ),
        ("batches", JsonValue::U64(trace.batches.len() as u64)),
        ("threads", JsonValue::U64(view.thread_count() as u64)),
        ("blobs", JsonValue::U64(trace.blobs.len() as u64)),
        ("schemas", JsonValue::U64(trace.schemas.len() as u64)),
        // L09: profile 集計（無い Trace では null）。
        (
            "profile_summary",
            match &trace.profile_summary {
                Some(p) => {
                    let apis = p
                        .apis
                        .iter()
                        .map(|a| {
                            JsonValue::obj(vec![
                                ("api", JsonValue::Str(profile_api_name(trace, a.api_id))),
                                ("api_id", JsonValue::U64(a.api_id as u64)),
                                ("calls", JsonValue::U64(a.calls)),
                                ("enters", JsonValue::U64(a.enters)),
                                ("leaves", JsonValue::U64(a.leaves)),
                                ("total_duration_qpc", JsonValue::U64(a.total_duration_qpc)),
                                ("min_duration_qpc", JsonValue::U64(a.min_duration_qpc)),
                                ("max_duration_qpc", JsonValue::U64(a.max_duration_qpc)),
                            ])
                        })
                        .collect();
                    JsonValue::obj(vec![
                        ("qpc_frequency", JsonValue::U64(p.qpc_frequency)),
                        ("total_events_seen", JsonValue::U64(p.total_events_seen)),
                        ("apis", JsonValue::Array(apis)),
                    ])
                }
                None => JsonValue::Null,
            },
        ),
        (
            "integrity",
            JsonValue::obj(vec![
                (
                    "status",
                    JsonValue::Str(
                        if s.has_event_loss() {
                            "incomplete"
                        } else {
                            "complete"
                        }
                        .to_string(),
                    ),
                ),
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
    // L11: --order=global は全スレッド共通の観測順序で並べ替える。
    // 値が global 以外なら使い方エラーにする。
    let order_global = match parsed.opt("order") {
        None => false,
        Some("global") => true,
        Some(other) => {
            return Err(ToolError::Usage(format!(
                "unknown --order value: {other} (expected global)"
            )))
        }
    };
    let limit = match parsed.opt("limit") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| ToolError::Usage(format!("bad --limit: {v}")))?,
        ),
        None => None,
    };
    let mut matched: Vec<_> = view.events.iter().filter(|e| filter.matches(e)).collect();
    if order_global {
        // 全体順序を持たないイベントが 1 件でもあれば、その Trace は
        // --order=global で記録されたものではない。
        if matched.iter().any(|e| e.global_order.is_none()) {
            return Err(ToolError::Runtime(
                "this trace was not recorded with --order=global".into(),
            ));
        }
        // global_order はイベントごとに一意なので安定ソートで十分。
        matched.sort_by_key(|e| e.global_order.unwrap());
    }
    let matched: Vec<_> = matched
        .into_iter()
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
    if !matches!(format, "jsonl" | "parquet") {
        return Err(ToolError::Usage(format!(
            "unsupported format: {format} (expected jsonl or parquet)"
        )));
    }
    if format == "parquet" && parsed.opt("output").is_none() {
        return Err(ToolError::Usage(
            "Parquet export requires --output <path>".into(),
        ));
    }
    let (path, trace) = load_trace(&parsed)?;
    let view = TraceView::build(&trace);
    if format == "parquet" {
        let output = parsed.opt("output").expect("validated output path");
        if std::fs::canonicalize(output)
            .ok()
            .zip(std::fs::canonicalize(&path).ok())
            .is_some_and(|(a, b)| a == b)
        {
            return Err(ToolError::Runtime(
                "refusing to overwrite the input trace".into(),
            ));
        }
        let parent = Path::new(output)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            ToolError::Runtime(format!("cannot create temporary output for {output}: {e}"))
        })?;
        parquet_export::write(
            file.as_file_mut(),
            &view,
            inspect_json(&path, &view).render(),
        )
        .map_err(|e| ToolError::Runtime(format!("Parquet export failed: {e}")))?;
        file.persist(output).map_err(|e| {
            ToolError::Runtime(format!("cannot publish Parquet output {output}: {e}"))
        })?;
        return Ok(());
    }
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

// ---------------------------------------------------------------------------
// L12: `shirusu repair`
//
// 回復読み（F11）で読めたイベントだけを新しい Trace に書き出す。
// 正常なチャンクと参照関係を検証し、読めるイベントを回収する。
// 失われたイベントを推測で作らない（overview「完全性と復旧」）。
//
// 回収できないもの（数えて報告する）：
// - 参照先 Blob がファイル内に無いイベント（MissingBlob）。
//   Blob の内容を推測して補うことはしない。
// - Header と session_id が異なる Batch（SessionMismatch）。
//   session_id を書き換えて取り込むことはしない。
// - 同一スレッドで sequence が退行する Batch。Writer の不変条件に
//   反するため、順序を並べ替えて取り込むことはしない。
// - 空の Batch。
//
// 出力に残すもの：読めたイベント（元の Batch 順・元の内容のまま）、
// 参照された Blob（内容の BLAKE3 から同じ ID を再計算する。重複排除
// 済み）、Schema 定義、Loss Record。Blob の部分的な更新（F18）は
// 再発行しない。派生版の内容は `blobs` へ具体化済みで、イベントが
// 参照する版 ID の内容を `add_payload` で運べば十分なため。更新の
// 履歴そのものは修復出力には残らない。
//
// Finalization は元の Trace の三つの指標を引き継ぐ。ただし修復で
// イベントを失った場合、Complete の宣言は維持できないため
// event_integrity を Degraded（1）へ落とす。Finalization が無い
// 入力は三つとも Unknown（3）とする。修復の来歴は notes に残す。
// ---------------------------------------------------------------------------

/// repair の集計。`lost_by_cause` は初出順。
#[derive(Default)]
struct RepairReport {
    input: String,
    output: String,
    scanned: u64,
    recovered: u64,
    lost: u64,
    batches_written: usize,
    batches_skipped: usize,
    blobs_carried: usize,
    schemas_registered: usize,
    schemas_skipped: usize,
    loss_records: usize,
    issues: Vec<String>,
    lost_by_cause: Vec<(String, u64)>,
}

fn add_lost(report: &mut RepairReport, cause: &str, n: u64) {
    report.lost += n;
    if let Some(entry) = report.lost_by_cause.iter_mut().find(|(c, _)| c == cause) {
        entry.1 += n;
    } else {
        report.lost_by_cause.push((cause.to_string(), n));
    }
}

/// view.rs の IntegritySummary と同じ文字列で issue を表す。
/// 新しい RecoveryIssue バリアントが増えたらここも非網羅マッチで
/// コンパイルエラーになる（view.rs と同じ方針）。
fn format_issue(issue: &RecoveryIssue) -> String {
    match issue {
        RecoveryIssue::TruncatedTail { offset } => {
            format!("truncated_tail(offset={offset})")
        }
        RecoveryIssue::CorruptBlock { offset, reason } => {
            format!("corrupt_block(offset={offset}, reason={reason})")
        }
        RecoveryIssue::Resync { from, to } => format!("resync({from}..{to})"),
        RecoveryIssue::DuplicateBlob { id } => format!("duplicate_blob({id})"),
        RecoveryIssue::BlobHashMismatch { id, computed } => {
            format!("blob_hash_mismatch(id={id}, computed={computed})")
        }
        RecoveryIssue::MissingBlob { id } => format!("missing_blob({id})"),
        RecoveryIssue::ForwardBlobReference { id } => {
            format!("forward_blob_reference({id})")
        }
        RecoveryIssue::IndexMismatch => "index_mismatch".to_string(),
        RecoveryIssue::LimitExceeded { what } => format!("limit_exceeded({what})"),
        RecoveryIssue::SessionMismatch {
            what,
            expected,
            found,
        } => {
            format!("session_mismatch(what={what}, expected={expected}, found={found})")
        }
        RecoveryIssue::BlobUpdateMissingBase { resource_id } => {
            format!("blob_update_missing_base(resource={resource_id})")
        }
        RecoveryIssue::BlobUpdateOutOfRange {
            resource_id,
            offset,
            size,
            base_len,
        } => {
            format!(
                "blob_update_out_of_range(resource={resource_id}, offset={offset}, size={size}, base_len={base_len})"
            )
        }
        RecoveryIssue::BlobUpdateHashMismatch {
            resource_id,
            expected,
            computed,
        } => {
            format!(
                "blob_update_hash_mismatch(resource={resource_id}, expected={expected}, computed={computed})"
            )
        }
    }
}

/// 回復読み済みの Trace から修復済み Trace のバイト列と報告を作る。
/// 途中で失敗しても部分的な出力ファイルは作らない（呼び出し側が
/// 返されたバイト列を書き出すまでは、ファイルは作られない）。
fn repair_trace(input: &str, trace: &ReadTrace) -> Result<(Vec<u8>, RepairReport), ToolError> {
    let mut report = RepairReport {
        input: input.to_string(),
        scanned: trace.total_events(),
        issues: trace.issues.iter().map(format_issue).collect(),
        ..Default::default()
    };
    // Environment が無い入力でも Header の session_id だけは分かる
    // ため、空の Environment で Writer を作る（元の session_id を保つ）。
    let env = match &trace.environment {
        Some(env) => env.clone(),
        None => CaptureEnvironment {
            session: SessionMetadata {
                session_id: trace.header.session_id,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut writer = TraceWriter::new(Vec::new(), env)
        .map_err(|e| ToolError::Runtime(format!("cannot start repaired trace: {e}")))?;
    // Schema は同一内容の再登録は受理される。内容の違う再定義や
    // content_hash の不一致は Writer が拒否するため、その定義だけ
    // 落として数える（修復全体は止めない）。
    for def in &trace.schemas {
        match writer.register_schema(def.clone()) {
            Ok(()) => report.schemas_registered += 1,
            Err(_) => report.schemas_skipped += 1,
        }
    }
    let mut carried: HashSet<BlobId> = HashSet::new();
    let mut last_sequence_by_thread: HashMap<u64, u64> = HashMap::new();
    for batch in &trace.batches {
        if batch.events.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        if batch.session_id != trace.header.session_id {
            report.batches_skipped += 1;
            add_lost(&mut report, "session_mismatch", batch.events.len() as u64);
            continue;
        }
        // 参照先 Blob が無いイベントは落とす（内容を推測しない）。
        let mut kept: Vec<TraceEvent> = Vec::new();
        for e in &batch.events {
            if let PayloadRef::Blob(id) = &e.payload {
                if !trace.blobs.contains_key(id) {
                    add_lost(&mut report, "missing_blob", 1);
                    continue;
                }
            }
            kept.push(e.clone());
        }
        if kept.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        // シーケンス退行の事前検査。Writer の validate_batch と同じ
        // 規則（スレッドごとに単調。書けた Batch だけが水位を進める）。
        let mut prev = last_sequence_by_thread.get(&batch.thread_id).copied();
        let mut regressed = false;
        for e in &kept {
            if let Some(p) = prev {
                if e.sequence < p {
                    regressed = true;
                    break;
                }
            }
            prev = Some(e.sequence);
        }
        if regressed {
            report.batches_skipped += 1;
            add_lost(&mut report, "sequence_regression", kept.len() as u64);
            continue;
        }
        for e in &kept {
            if let PayloadRef::Blob(id) = &e.payload {
                let data = &trace.blobs[id];
                writer
                    .add_payload(data)
                    .map_err(|err| ToolError::Runtime(format!("cannot carry blob {id}: {err}")))?;
                carried.insert(*id);
            }
        }
        let filtered = EventBatch {
            session_id: batch.session_id,
            process_id: batch.process_id,
            raw_pid: batch.raw_pid,
            thread_id: batch.thread_id,
            qpc_frequency: batch.qpc_frequency,
            events: kept,
        };
        match writer.write_batch(&filtered) {
            Ok(()) => {
                report.batches_written += 1;
                report.recovered += filtered.events.len() as u64;
                if let Some(last) = filtered.events.last() {
                    last_sequence_by_thread.insert(batch.thread_id, last.sequence);
                }
            }
            Err(err) => {
                // 事前検査をすり抜けた Writer 側の拒否。Batch ごと落とし、
                // 理由を issue として残す（推測で補わない）。
                report.batches_skipped += 1;
                add_lost(&mut report, "write_failed", filtered.events.len() as u64);
                report.issues.push(format!(
                    "write_failed(thread={}, reason={err})",
                    batch.thread_id
                ));
            }
        }
    }
    report.blobs_carried = carried.len();
    writer
        .write_loss_records(&trace.loss_records)
        .map_err(|e| ToolError::Runtime(format!("cannot write loss records: {e}")))?;
    report.loss_records = trace.loss_records.len();
    let (capture_coverage, mut event_integrity, semantic_completeness, mut notes) =
        match &trace.finalization {
            Some(f) => (
                f.capture_coverage,
                f.event_integrity,
                f.semantic_completeness,
                f.notes.clone(),
            ),
            None => (3, 3, 3, Vec::new()),
        };
    if report.lost > 0 && event_integrity == 0 {
        event_integrity = 1;
    }
    notes.push(format!(
        "repaired from {}: {} events recovered, {} lost; {} recovery issues",
        input,
        report.recovered,
        report.lost,
        report.issues.len()
    ));
    let bytes = writer
        .finish(FinalizationInfo {
            capture_coverage,
            event_integrity,
            semantic_completeness,
            notes,
        })
        .map_err(|e| ToolError::Runtime(format!("cannot finish repaired trace: {e}")))?;
    Ok((bytes, report))
}

fn repair_lines(report: &RepairReport) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("repaired: {} -> {}", report.input, report.output));
    out.push(format!(
        "events: {} recovered, {} lost (scanned {})",
        report.recovered, report.lost, report.scanned
    ));
    out.push(format!(
        "batches: {} written, {} skipped",
        report.batches_written, report.batches_skipped
    ));
    out.push(format!("blobs: {} carried over", report.blobs_carried));
    let mut schemas = format!("schemas: {} registered", report.schemas_registered);
    if report.schemas_skipped > 0 {
        schemas.push_str(&format!(", {} skipped", report.schemas_skipped));
    }
    out.push(schemas);
    out.push(format!("loss_records: {} preserved", report.loss_records));
    out.push(format!("recovery_issues: {}", report.issues.len()));
    for issue in &report.issues {
        out.push(format!("  - {issue}"));
    }
    if report.lost > 0 {
        out.push("lost_events:".into());
        for (cause, count) in &report.lost_by_cause {
            out.push(format!("  - {cause}: {count}"));
        }
    }
    out
}

fn repair_json(report: &RepairReport) -> JsonValue {
    JsonValue::obj(vec![
        ("input", JsonValue::Str(report.input.clone())),
        ("output", JsonValue::Str(report.output.clone())),
        (
            "events",
            JsonValue::obj(vec![
                ("recovered", JsonValue::U64(report.recovered)),
                ("lost", JsonValue::U64(report.lost)),
                ("scanned", JsonValue::U64(report.scanned)),
            ]),
        ),
        (
            "batches",
            JsonValue::obj(vec![
                ("written", JsonValue::U64(report.batches_written as u64)),
                ("skipped", JsonValue::U64(report.batches_skipped as u64)),
            ]),
        ),
        ("blobs_carried", JsonValue::U64(report.blobs_carried as u64)),
        (
            "schemas",
            JsonValue::obj(vec![
                (
                    "registered",
                    JsonValue::U64(report.schemas_registered as u64),
                ),
                ("skipped", JsonValue::U64(report.schemas_skipped as u64)),
            ]),
        ),
        (
            "loss_records_preserved",
            JsonValue::U64(report.loss_records as u64),
        ),
        (
            "recovery_issues",
            JsonValue::Array(report.issues.iter().cloned().map(JsonValue::Str).collect()),
        ),
        (
            "lost_by_cause",
            JsonValue::Array(
                report
                    .lost_by_cause
                    .iter()
                    .map(|(cause, count)| {
                        JsonValue::obj(vec![
                            ("cause", JsonValue::Str(cause.clone())),
                            ("count", JsonValue::U64(*count)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn cmd_repair(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    let (input, trace) = load_trace(&parsed)?;
    let output = match parsed.opt("output") {
        Some(path) => path.to_string(),
        None => format!("{input}.repaired"),
    };
    // 入力そのものへの上書きを拒否する（修復元を壊さない）。
    let same = output == input
        || std::fs::canonicalize(&output)
            .ok()
            .zip(std::fs::canonicalize(&input).ok())
            .map(|(a, b)| a == b)
            .unwrap_or(false);
    if same {
        return Err(ToolError::Runtime(format!(
            "refusing to overwrite the input trace: {output} is the same file as {input}"
        )));
    }
    let (bytes, mut report) = repair_trace(&input, &trace)?;
    std::fs::write(&output, &bytes)
        .map_err(|e| ToolError::Runtime(format!("cannot write {output}: {e}")))?;
    report.output = output;
    if parsed.has("json") {
        println!("{}", repair_json(&report).render_pretty());
    } else {
        for line in repair_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// L22: `shirusu capture` / `shirusu attach`
//
// 記録コマンドは Windows 専用（overview のコマンド表）。実働は
// `LaunchedCapture`（host/recorder_launch.rs、L04 でライブラリ層は
// 検証済み）に委ね、CLI は引数の検証・設定の組み立て・要約の表示だけを
// 担う。引数の検証はプラットフォームゲートの前に行うため、Windows 以外
// でも使い方の誤りは終了 2 で、制限そのものは終了 1 で返す。
//
// 来歴不明の記録（overview「プロセスの起動・アタッチ」節）:
// attach は動作中のプロセスへ途中から入るため、アタッチ前の呼び出しや
// その時点で既に存在するオブジェクトの来歴は分からない。これを
// CaptureEnvironment.capture_config に明記する（`shirusu inspect` が
// そのまま表示する）。capture は CREATE_SUSPENDED で起動し、アプリの
// コードが動く前に Agent を準備するため、来歴は起動時から完全である。
// 形式の変更は無い（既存の文字列欄を使う）。
// ---------------------------------------------------------------------------

/// capture / attach の記録方法。Linux では単体テスト以外に読む場所が
/// 無いため（実働は Windows の `run_capture` のみ）、未使用警告を抑える。
#[cfg_attr(not(windows), allow(dead_code))]
enum CaptureMode {
    /// 起動して最初から記録する。`cmdline` は Windows のコマンドライン
    /// 文字列（`build_cmdline` で組み立てたもの）。
    Launch { cmdline: String, exe: String },
    /// 動作中のプロセスへ途中から記録する。
    Attach { pid: u32 },
}

/// 検証済みの引数をひとまとめにした記録要求。プラットフォーム非依存。
#[cfg_attr(not(windows), allow(dead_code))]
struct CaptureRequest {
    mode: CaptureMode,
    output: PathBuf,
    dll: Option<PathBuf>,
    timeout: Duration,
    order_global: bool,
    /// L07: モジュール単位の分類の上書き（`--module-class` の指定順）。
    module_classes: Vec<ModuleOverride>,
    /// L07: Runtime 独自の API も記録するか（既定は false）。
    record_runtime_apis: bool,
    /// L02: 診断用の追加 QueryInterface を有効にするか（既定は false）。
    diagnostic_query_interface: bool,
    /// L09: 記録モード（`--mode`。既定は `full`）。
    record_mode: RecordMode,
    /// L09: `--api` で指定された通りの名前列（`filtered` のときだけ
    /// 使い、Environment の capture_config に載せる）。
    api_names: Vec<String>,
    /// L05: 起動した対象の子プロセスも追跡するか
    /// （`--follow-children`。capture 専用）。
    follow_children: bool,
}

/// capture / attach の共通オプション（`--output` / `--dll` /
/// `--timeout` / `--order=global` / `--module-class` /
/// `--record-runtime-apis` / `--diagnostic-query-interface` /
/// `--mode` / `--api` / `--follow-children`）。
struct CaptureOptions {
    output: Option<String>,
    dll: Option<PathBuf>,
    timeout_secs: u64,
    order_global: bool,
    module_classes: Vec<ModuleOverride>,
    record_runtime_apis: bool,
    /// L02: 診断用の追加 QueryInterface を有効にするか（既定は false）。
    diagnostic_query_interface: bool,
    /// L09: 記録モード（`--mode`。既定は `full`）。
    record_mode: RecordMode,
    /// L09: `--api` で指定された通りの名前列。
    api_names: Vec<String>,
    /// L05: 子プロセスも追跡するか（`--follow-children`）。
    follow_children: bool,
}

impl CaptureOptions {
    fn parse(parsed: &Parsed) -> Result<Self, ToolError> {
        let timeout_secs = match parsed.opt("timeout") {
            Some(v) => v
                .parse()
                .map_err(|_| ToolError::Usage(format!("bad --timeout: {v}")))?,
            None => 30,
        };
        // dump と同じ `--order=global` の表記。値が global 以外なら
        // 使い方エラーにする。
        let order_global = match parsed.opt("order") {
            None => false,
            Some("global") => true,
            Some(other) => {
                return Err(ToolError::Usage(format!(
                    "unknown --order value: {other} (expected global)"
                )))
            }
        };
        // L07: 繰り返し指定できる `--module-class <module>=<class>`。
        // 1 件でも不正なら使い方エラーにする。
        let mut module_classes = Vec::new();
        for v in parsed.opts_all("module-class") {
            module_classes.push(
                ModuleOverride::parse(v)
                    .map_err(|e| ToolError::Usage(format!("bad --module-class: {e}")))?,
            );
        }
        // L09: `--mode` と `--api`。`--api` は `--mode filtered` の
        // ときだけ意味があり、`filtered` には 1 件以上の `--api` が要る。
        // 未知の API 名も使い方エラーにする。
        let api_names: Vec<String> = parsed
            .opts_all("api")
            .iter()
            .map(|s| s.to_string())
            .collect();
        let record_mode = match parsed.opt("mode") {
            None | Some("full") => RecordMode::Full,
            Some("profile") => RecordMode::Profile,
            // L15: 詳細調査モード。Windows 内部の呼び出し (Nt*) も記録する。
            Some("detailed") => RecordMode::Detailed,
            Some("filtered") => {
                if api_names.is_empty() {
                    return Err(ToolError::Usage(
                        "--mode filtered requires at least one --api".into(),
                    ));
                }
                RecordMode::Filtered {
                    apis: resolve_api_names(&api_names).map_err(ToolError::Usage)?,
                }
            }
            Some(other) => {
                return Err(ToolError::Usage(format!(
                    "unknown --mode value: {other} (expected full, profile, filtered, or detailed)"
                )))
            }
        };
        if !matches!(record_mode, RecordMode::Filtered { .. }) && !api_names.is_empty() {
            return Err(ToolError::Usage("--api requires --mode filtered".into()));
        }
        Ok(Self {
            output: parsed.opt("output").map(str::to_string),
            dll: parsed.opt("dll").map(PathBuf::from),
            timeout_secs,
            order_global,
            module_classes,
            // L07: Runtime 独自の API を記録するか（既定は記録しない）。
            // L15: 詳細調査モードでは Runtime 起源の内部呼び出しも記録
            // するため、ここで強制的に有効にする。
            record_runtime_apis: parsed.has("record-runtime-apis")
                || matches!(record_mode, RecordMode::Detailed),
            // L02: 診断用の追加 QueryInterface を有効にするか
            // （既定は無効。標準では Interceptor 自身は QI を呼ばない）。
            diagnostic_query_interface: parsed.has("diagnostic-query-interface"),
            record_mode,
            api_names,
            // L05: 子プロセスも追跡するか（既定はしない）。
            follow_children: parsed.has("follow-children"),
        })
    }
}

/// 引数列を `--` の前後で分ける。`--` が無ければ後半は空。
fn split_dashdash(args: &[String]) -> (&[String], &[String]) {
    match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    }
}

/// Windows のコマンドライン文字列へ組み立てる。空白・引用符を含む要素は
/// 二重引用符で囲み、内側の引用符は `\"` にする。完全な引用規則は対象の
/// CRT に依存するため、ここでは空白を含む場合だけを扱う（CreateProcess
/// の慣習に沿う最小限の引用）。
fn build_cmdline(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.chars().any(|c| c.is_whitespace() || c == '"') {
                format!("\"{}\"", p.replace('"', "\\\""))
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// capture の既定の出力パス：exe のファイル stem に `.trace` を付けたもの。
fn default_capture_output(exe: &str) -> String {
    let stem = Path::new(exe)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| exe.to_string());
    format!("{stem}.trace")
}

/// attach の既定の出力パス。
fn default_attach_output(pid: u32) -> String {
    format!("shirusu-attach-{pid}.trace")
}

/// 記録セッションの CaptureEnvironment を作る。`session_id` は
/// config.session_id と同じ値にすること（recorder が一致を検証する）。
/// attach では来歴不明の旨を capture_config に明記する（L22 の要求）。
///
/// L07: 起動対象の exe をモジュールとして分類して `modules` に載せる。
/// `--module-class` の上書きは、既知のモジュールに当たれば分類を置き換え、
/// 当たらなければ（capture 開始時に未ロードのモジュールへの上書きは
/// 黙って消えないよう）上書きエントリとして残す。署名の確認は Windows
/// 側の仕事のため、ここでは `microsoft_signed: None` の証拠で分類する
/// （対象 exe はシステム配置でない限り Application になる）。
/// L23: Host が capture 開始時に全モジュールを列挙・署名検証して
/// `modules` を置き換えるため、ここのエントリは暫定のものである
/// （列挙に失敗した場合はこちらが残る。CLI の上書きは置き換え時にも
/// 温存される）。
/// L13: 起動対象の exe の PE インポートテーブルから静的依存を読み、
/// `static_dependencies` に載せる（読めなければ空のまま）。
/// Linux では単体テスト以外に呼ぶ場所が無いため、未使用警告を抑える。
#[cfg_attr(not(windows), allow(dead_code))]
fn capture_environment(
    mode: &CaptureMode,
    session_id: u64,
    qpc_frequency: u64,
    overrides: &[ModuleOverride],
    record_mode: &RecordMode,
    api_names: &[String],
) -> CaptureEnvironment {
    let (created_by, target_description, base_config) = match mode {
        CaptureMode::Launch { exe, .. } => (
            "shirusu capture".to_string(),
            exe.clone(),
            "launched".to_string(),
        ),
        CaptureMode::Attach { pid } => (
            "shirusu attach".to_string(),
            format!("pid {pid}"),
            format!(
                "attached pid={pid}; pre-attach calls and pre-existing objects have unknown provenance"
            ),
        ),
    };
    // L09: 記録モードも capture_config に明記する（`mode=full` /
    // `mode=profile` / `mode=filtered apis=...`）。`full` でも明記する
    // のは、後から Trace を見たときに「間引き無しで記録された」ことが
    // 分かるようにするため。
    let capture_config = format!("{base_config}; {}", record_mode.config_text(api_names));
    let mut modules = Vec::new();
    let mut static_dependencies = Vec::new();
    if let CaptureMode::Launch { exe, .. } = mode {
        modules.push(classify_module(&ModuleEvidence::new(exe)));
        // L13: 起動対象の exe の PE インポートテーブルから静的依存を
        // 読む。読めなければ空のまま（capture を失敗させない）。
        static_dependencies = shirusu_host::static_dep::static_dependencies_for_exe(Path::new(exe));
    }
    let unused = apply_overrides(&mut modules, overrides);
    for ov in unused {
        modules.push(ModuleClassification {
            module_name: ov.module.clone(),
            class: ov.class,
            reason: "CLI override (module not loaded at capture start)".to_string(),
            uncertain: false,
            implementation_module: None,
            overridden: true,
        });
    }
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by,
            qpc_frequency,
        },
        target_description,
        capture_config,
        modules,
        static_dependencies,
        ..Default::default()
    }
}

fn cmd_capture(args: &[String]) -> Result<(), ToolError> {
    let (opts_args, cmdline_parts) = split_dashdash(args);
    let parsed = parse_args(
        opts_args,
        &[
            "record-runtime-apis",
            "diagnostic-query-interface",
            "follow-children",
        ],
    )?;
    if !parsed.positional.is_empty() {
        return Err(ToolError::Usage(format!(
            "unexpected argument: {} (put the command line after --)",
            parsed.positional[0]
        )));
    }
    let opts = CaptureOptions::parse(&parsed)?;
    if cmdline_parts.is_empty() {
        return Err(ToolError::Usage(
            "capture needs a command line after -- (shirusu capture -- <exe> [args...])".into(),
        ));
    }
    let exe = cmdline_parts[0].clone();
    let cmdline = build_cmdline(cmdline_parts);
    let output = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_capture_output(&exe)));
    run_capture(&CaptureRequest {
        mode: CaptureMode::Launch { cmdline, exe },
        output,
        dll: opts.dll,
        timeout: Duration::from_secs(opts.timeout_secs),
        order_global: opts.order_global,
        module_classes: opts.module_classes,
        record_runtime_apis: opts.record_runtime_apis,
        diagnostic_query_interface: opts.diagnostic_query_interface,
        record_mode: opts.record_mode,
        api_names: opts.api_names,
        follow_children: opts.follow_children,
    })
}

fn cmd_attach(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(
        args,
        &[
            "record-runtime-apis",
            "diagnostic-query-interface",
            "follow-children",
        ],
    )?;
    let pid_s = parsed
        .positional
        .first()
        .ok_or_else(|| ToolError::Usage("attach needs a <PID>".into()))?;
    if parsed.positional.len() > 1 {
        return Err(ToolError::Usage(format!(
            "unexpected argument: {}",
            parsed.positional[1]
        )));
    }
    let pid: u32 = pid_s
        .parse()
        .map_err(|_| ToolError::Usage(format!("bad pid: {pid_s}")))?;
    let opts = CaptureOptions::parse(&parsed)?;
    // L05: --follow-children は起動（capture）専用。
    if opts.follow_children {
        return Err(ToolError::Usage(
            "--follow-children requires capture (launch)".into(),
        ));
    }
    let output = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_attach_output(pid)));
    run_capture(&CaptureRequest {
        mode: CaptureMode::Attach { pid },
        output,
        dll: opts.dll,
        timeout: Duration::from_secs(opts.timeout_secs),
        order_global: opts.order_global,
        module_classes: opts.module_classes,
        record_runtime_apis: opts.record_runtime_apis,
        diagnostic_query_interface: opts.diagnostic_query_interface,
        record_mode: opts.record_mode,
        api_names: opts.api_names,
        follow_children: false,
    })
}

/// capture / attach の実働（Windows）。対象の終了まで回収を続け、終了
/// したら最終回収して Trace を閉じる（`LaunchedCapture::run_to_completion`）。
/// 対象を生かしたまま終える場合は `finish` が Agent の終了手順を呼ぶ。
#[cfg(windows)]
fn run_capture(req: &CaptureRequest) -> Result<(), ToolError> {
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture};
    use shirusu_trace::writer::Durability;
    use shirusu_transport::RingConfig;

    let dll = resolve_dll(req.dll.as_deref())?;
    let session_id = new_session_id();
    let freq = qpc_frequency();
    let session_cfg = CaptureSessionConfig {
        session_id,
        // e2e と同じ調整済みの既定値（A73）。CLI は Ring の詳細を
        // 露出しない。
        ring_config: RingConfig::PRODUCTION,
        environment: capture_environment(
            &req.mode,
            session_id,
            freq,
            &req.module_classes,
            &req.record_mode,
            &req.api_names,
        ),
        qpc_frequency: freq,
        // F21: 永続化は既定の Buffered（flush のみ）。
        durability: Durability::Buffered,
        order_global: req.order_global,
        // L07: Runtime 独自の API を記録するか（既定は記録しない）。
        // L23: フック時の呼び出し元分類による強制を実装済み
        // （Bootstrap v5 で Agent DLL へ伝え、Detour の入口で Runtime
        // からの呼び出しを記録しない。呼び出し元不明時は記録する）。
        record_runtime_apis: req.record_runtime_apis,
        // L02: 診断用の追加 QueryInterface を有効にするか
        // （既定は無効。Bootstrap v6 で Agent DLL へ伝える）。
        diagnostic_query_interface: req.diagnostic_query_interface,
        // L09: 記録モード。
        record_mode: req.record_mode.clone(),
    };
    let mut launch_cfg = LaunchConfig::new(session_cfg, dll);
    launch_cfg.init_timeout = req.timeout;
    // L05: --follow-children のときは TreeCapture で子プロセスも追跡する。
    if req.follow_children {
        use shirusu_host::child_tree::child_trace_path;
        use shirusu_host::recorder_launch::TreeCapture;
        let cmdline = match &req.mode {
            CaptureMode::Launch { cmdline, .. } => cmdline,
            // attach での指定は cmd_attach で使い方エラーにしている。
            CaptureMode::Attach { .. } => {
                return Err(ToolError::Runtime(
                    "--follow-children requires capture (launch)".into(),
                ))
            }
        };
        let tree = TreeCapture::launch(cmdline, &req.output, launch_cfg)
            .map_err(|e| ToolError::Runtime(format!("failed to start capture: {e}")))?;
        let summary = tree
            .run_tree_to_completion(Duration::from_millis(2))
            .map_err(|e| ToolError::Runtime(format!("capture failed: {e}")))?;
        print_summary(&req.output, &summary.root);
        for (pid, child) in &summary.children {
            println!("child {pid}:");
            print_summary(&child_trace_path(&req.output, *pid), child);
        }
        for (pid, reason) in &summary.uninjectable {
            println!("child {pid} not recorded: {reason}");
        }
        return Ok(());
    }
    let capture = match &req.mode {
        CaptureMode::Launch { cmdline, .. } => {
            LaunchedCapture::launch(cmdline, &req.output, launch_cfg)
        }
        CaptureMode::Attach { pid } => LaunchedCapture::attach(*pid, &req.output, launch_cfg),
    }
    .map_err(|e| ToolError::Runtime(format!("failed to start capture: {e}")))?;
    let summary = capture
        .run_to_completion(Duration::from_millis(2))
        .map_err(|e| ToolError::Runtime(format!("capture failed: {e}")))?;
    print_summary(&req.output, &summary);
    Ok(())
}

/// Windows 以外では記録はできない。引数の検証は済ませてあるため、ここ
/// ではプラットフォーム制限を明言する（終了 1）。
#[cfg(not(windows))]
fn run_capture(_req: &CaptureRequest) -> Result<(), ToolError> {
    Err(ToolError::Runtime(
        "capture and attach are only available on Windows".into(),
    ))
}

#[cfg(windows)]
fn resolve_dll(explicit: Option<&Path>) -> Result<PathBuf, ToolError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    // e2e と同じ既定値：shirusu 実行ファイルの隣の shirusu_agent_dll.dll。
    let exe = std::env::current_exe()
        .map_err(|e| ToolError::Runtime(format!("cannot locate shirusu executable: {e}")))?;
    let dll = exe
        .parent()
        .map(|d| d.join("shirusu_agent_dll.dll"))
        .unwrap_or_else(|| PathBuf::from("shirusu_agent_dll.dll"));
    if dll.exists() {
        Ok(dll)
    } else {
        Err(ToolError::Runtime(format!(
            "agent dll not found next to shirusu ({}); pass --dll <path>",
            dll.display()
        )))
    }
}

/// セッション ID は起動時刻のナノ秒（UNIX エポック起点）から作る。
/// 時刻が取れない環境では 0 とする（environment と config で同じ値を
/// 使うため、一致検証には通る）。
#[cfg(windows)]
fn new_session_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// QueryPerformanceFrequency（e2e と同じ読み方。失敗時は 10MHz の保険値）。
#[cfg(windows)]
fn qpc_frequency() -> u64 {
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryPerformanceFrequency(out: *mut i64) -> i32;
    }
    let mut f: i64 = 0;
    // SAFETY: out は有効なローカルを指す。
    let ok = unsafe { QueryPerformanceFrequency(&mut f) };
    if ok != 0 && f > 0 {
        f as u64
    } else {
        10_000_000
    }
}

#[cfg(windows)]
fn print_summary(trace: &Path, summary: &shirusu_host::recorder::SessionSummary) {
    use shirusu_host::trace_convert::integrity_level_code;
    println!("captured: {}", trace.display());
    if let Some(code) = summary.target_exit_code {
        println!("target exit code: {code} (0x{code:08X})");
    }
    println!(
        "events: {} (loss records: {})",
        summary.total_events, summary.total_loss_records
    );
    // L09: `profile` モードでは個別イベントが保存されないため、集計を
    // ここで表示する（API 名の解決には Schema が要るため、ここでは
    // api_id のまま出す。名前付きの表示は `shirusu inspect` が担う）。
    if let Some(profile) = &summary.profile_summary {
        println!(
            "profile: {} events seen (individual events not saved)",
            profile.total_events_seen
        );
        for api in &profile.apis {
            println!(
                "  api {}: {} calls, {} enters, {} leaves, total {}",
                api.api_id,
                api.calls,
                api.enters,
                api.leaves,
                qpc_ms(profile.qpc_frequency, api.total_duration_qpc)
            );
        }
    }
    println!(
        "rings: {}/{} active ({} never initialized, {} stopped)",
        summary.rings_active,
        summary.rings_total,
        summary.rings_never_initialized,
        summary.rings_stopped
    );
    println!(
        "args: {} attached, {} fallback to blob",
        summary.args_attached, summary.args_fallback_blob
    );
    let pipeline = &summary.host_pipeline;
    println!(
        "host pipeline: {} commands, queue full {}, drain wait {:.3}ms, conversion wall {:.3}ms",
        pipeline.commands_processed,
        pipeline.queue_full_count,
        pipeline.drain_wait_ns as f64 / 1_000_000.0,
        pipeline.conversion_wall_ns as f64 / 1_000_000.0,
    );
    if let Some((hooked, missing)) = summary.hook_coverage {
        println!("hook coverage: {hooked} hooked, {missing} missing");
    }
    let i = &summary.integrity;
    println!(
        "integrity: capture_coverage={} event_integrity={} semantic_completeness={}",
        integrity_level_name(integrity_level_code(i.capture_coverage)),
        integrity_level_name(integrity_level_code(i.event_integrity)),
        integrity_level_name(integrity_level_code(i.semantic_completeness)),
    );
    for note in &i.notes {
        println!("note: {note}");
    }
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
