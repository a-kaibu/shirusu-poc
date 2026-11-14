//! Evidence ledger: installation, imports and observations are independent facts.
use super::*;
use shirusu_analysis::{capture_name, value_capture_name, EventView, KIND_ENTER, KIND_LEAVE};
use shirusu_trace::proto::HookEvidence;
use std::collections::BTreeMap;

#[derive(Default)]
struct Row {
    imports: Vec<String>,
    hooks: Vec<HookEvidence>,
    enter: u64,
    leave: u64,
    other: u64,
    decode_errors: u64,
    profile_enter: u64,
    profile_leave: u64,
    captures: BTreeMap<String, u64>,
    value_captures: BTreeMap<String, u64>,
}
fn key(module: &str, function: &str) -> String {
    let module = module.to_ascii_lowercase();
    format!(
        "{}!{}",
        module.strip_suffix(".dll").unwrap_or(&module),
        function
    )
}
fn observed_key(name: &str) -> String {
    match name.split_once('!') {
        Some((module, function)) => key(module, function),
        None => name.to_string(),
    }
}
/// 観測イベントを 1 件ずつ行へ足す (P1-4: 全イベントを保持しない)。
#[derive(Default)]
struct Observed {
    rows: BTreeMap<String, Row>,
    /// api_id ごとに最初に観測した API 名 (profile 集計の名前解決用)。
    names: HashMap<u32, Option<String>>,
}

impl Observed {
    fn note(&mut self, event: &EventView) {
        self.names
            .entry(event.api_id)
            .or_insert_with(|| event.api_name.clone());
        let name = event
            .api_name
            .as_deref()
            .map(observed_key)
            .unwrap_or_else(|| format!("unknown-api-id:{}", event.api_id));
        let row = self.rows.entry(name).or_default();
        match event.kind {
            KIND_ENTER => row.enter += 1,
            KIND_LEAVE => row.leave += 1,
            _ => row.other += 1,
        }
        for field in &event.fields {
            *row.value_captures
                .entry(value_capture_name(field.capture).to_string())
                .or_default() += 1;
        }
        row.decode_errors += u64::from(event.args_error.is_some());
        *row.captures
            .entry(capture_name(event.capture).to_string())
            .or_default() += 1;
    }
}

fn rows(trace: &ReadTrace, observed: Observed) -> BTreeMap<String, Row> {
    let Observed {
        rows: mut observed_rows,
        names,
    } = observed;
    let mut rows = BTreeMap::<String, Row>::new();
    if let Some(env) = &trace.environment {
        for dep in &env.static_dependencies {
            for import in &dep.imports {
                let function = import.name.clone().unwrap_or_else(|| {
                    import
                        .ordinal
                        .map(|n| format!("#{n}"))
                        .unwrap_or_else(|| "unknown-import".into())
                });
                let row = rows.entry(key(&dep.module, &function)).or_default();
                let source = format!("main-executable: {}", env.target_description);
                if !row.imports.contains(&source) {
                    row.imports.push(source);
                }
            }
        }
        for evidence in &env.hook_evidence {
            rows.entry(key(&evidence.module, &evidence.function))
                .or_default()
                .hooks
                .push(evidence.clone());
        }
    }
    for (name, seen) in std::mem::take(&mut observed_rows) {
        let row = rows.entry(name).or_default();
        row.enter += seen.enter;
        row.leave += seen.leave;
        row.other += seen.other;
        row.decode_errors += seen.decode_errors;
        for (k, v) in seen.captures {
            *row.captures.entry(k).or_default() += v;
        }
        for (k, v) in seen.value_captures {
            *row.value_captures.entry(k).or_default() += v;
        }
    }
    if let Some(profile) = &trace.profile_summary {
        for api in &profile.apis {
            // IDs are session evidence, never interpreted using today's API table.
            let name = trace
                .environment
                .as_ref()
                .and_then(|e| e.hook_evidence.iter().find(|h| h.api_id == api.api_id))
                .map(|h| key(&h.module, &h.function))
                .or_else(|| {
                    names
                        .get(&api.api_id)
                        .and_then(|n| n.as_deref())
                        .map(observed_key)
                })
                .unwrap_or_else(|| format!("unknown-api-id:{}", api.api_id));
            let row = rows.entry(name).or_default();
            row.profile_enter = api.enters;
            row.profile_leave = api.leaves;
        }
    }
    rows
}
const LIMITS: &str = "Imports cover only the captured main executable's normal import table; absence does not exclude dynamic resolution, delay imports or calls from other modules. Hook evidence describes initialization, not all later execution paths. Zero observations never prove an API was unused. Semantic levels describe recorder capability, not complete state for every call. Missing evidence in older traces remains unknown. COM/WinRT method interception is not covered by Win32 hook evidence.";
pub(super) fn run(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&["json"])?;
    let path = trace_path_arg(&parsed)?;
    let file = std::fs::File::open(&path)
        .map_err(|e| ToolError::Runtime(format!("cannot read {path}: {e}")))?;
    let mut observed = Observed::default();
    let mut index = 0usize;
    let streamed = shirusu_analysis::stream_trace(std::io::BufReader::new(file), |r, b, e| {
        observed.note(&EventView::of(r, b, e, index));
        index += 1;
    })
    .map_err(|e| ToolError::Runtime(format!("{path} is not a readable trace: {e}")))?;
    let trace = &streamed.meta;
    let integrity = &streamed.integrity;
    let rows = rows(trace, observed);
    if parsed.has("json") {
        let report = JsonValue::obj(vec![
            ("trace", JsonValue::Str(path.clone())),
            (
                "capture_config",
                trace
                    .environment
                    .as_ref()
                    .map(|e| JsonValue::Str(e.capture_config.clone()))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "has_finalization",
                JsonValue::Bool(integrity.has_finalization),
            ),
            (
                "finalized_cleanly",
                JsonValue::Bool(integrity.finalized_cleanly),
            ),
            (
                "capture_coverage",
                integrity
                    .capture_coverage
                    .map(|n| JsonValue::Str(integrity_level_name(n).into()))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "event_integrity",
                integrity
                    .event_integrity
                    .map(|n| JsonValue::Str(integrity_level_name(n).into()))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "semantic_completeness",
                integrity
                    .semantic_completeness
                    .map(|n| JsonValue::Str(integrity_level_name(n).into()))
                    .unwrap_or(JsonValue::Null),
            ),
            ("limitations", JsonValue::Str(LIMITS.into())),
            (
                "event_integrity_lost",
                JsonValue::Bool(integrity.has_event_loss()),
            ),
            (
                "apis",
                JsonValue::Array(rows.iter().map(|(name, row)| row_json(name, row)).collect()),
            ),
        ]);
        println!("{}", report.render_pretty());
    } else {
        println!("API coverage evidence: {path}\n{LIMITS}");
        println!(
            "capture_config: {}",
            trace
                .environment
                .as_ref()
                .map(|e| e.capture_config.as_str())
                .unwrap_or("unknown")
        );
        println!(
            "finalized_cleanly={} event_integrity={}",
            integrity.finalized_cleanly,
            integrity
                .event_integrity
                .map(integrity_level_name)
                .unwrap_or("unknown")
        );
        for (name, row) in &rows {
            let hooks = if row.hooks.is_empty() {
                "unknown".into()
            } else {
                row.hooks
                    .iter()
                    .map(|h| format!("{}={} ({}, {})", h.method, h.outcome, h.reason, h.scope))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            println!(
                "{name}: static={} enter={} leave={} other={} decode_errors={} hooks=[{hooks}]",
                if row.imports.is_empty() {
                    "not-detected-or-unavailable"
                } else {
                    "detected"
                },
                row.enter,
                row.leave,
                row.other,
                row.decode_errors
            );
            println!(
                "  profile aggregates: enter={} leave={} (separate from retained events)",
                row.profile_enter, row.profile_leave
            );
            for source in &row.imports {
                println!("  import source: {source}");
            }
            for h in row.hooks.iter().take(1) {
                println!(
                    "  declared semantics: L{} {}",
                    h.semantic_level, h.semantic_detail
                );
            }
            println!("  observed capture states: {:?}", row.captures);
            println!("  observed value capture states: {:?}", row.value_captures);
        }
    }
    if integrity.has_event_loss() {
        return Err(ToolError::Incomplete(format!(
            "{path} has event loss; coverage counts are observed counts only"
        )));
    }
    Ok(())
}
fn row_json(name: &str, row: &Row) -> JsonValue {
    JsonValue::obj(vec![
        ("api", JsonValue::Str(name.into())),
        (
            "static_import_sources",
            JsonValue::Array(row.imports.iter().cloned().map(JsonValue::Str).collect()),
        ),
        (
            "observation",
            JsonValue::Str(
                if row.enter == 0
                    && row.leave == 0
                    && row.other == 0
                    && row.profile_enter == 0
                    && row.profile_leave == 0
                {
                    "not-observed"
                } else {
                    "observed"
                }
                .into(),
            ),
        ),
        ("enter", JsonValue::U64(row.enter)),
        ("leave", JsonValue::U64(row.leave)),
        ("other", JsonValue::U64(row.other)),
        ("profile_enter", JsonValue::U64(row.profile_enter)),
        ("profile_leave", JsonValue::U64(row.profile_leave)),
        ("args_decode_errors", JsonValue::U64(row.decode_errors)),
        (
            "capture_states",
            JsonValue::Array(
                row.captures
                    .iter()
                    .map(|(state, count)| {
                        JsonValue::obj(vec![
                            ("state", JsonValue::Str(state.clone())),
                            ("events", JsonValue::U64(*count)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "hook_evidence",
            JsonValue::Array(
                row.hooks
                    .iter()
                    .map(|h| {
                        JsonValue::obj(vec![
                            ("method", JsonValue::Str(h.method.clone())),
                            ("outcome", JsonValue::Str(h.outcome.clone())),
                            ("reason", JsonValue::Str(h.reason.clone())),
                            ("scope", JsonValue::Str(h.scope.clone())),
                            (
                                "declared_semantic_level",
                                JsonValue::U64(h.semantic_level.into()),
                            ),
                            (
                                "declared_semantic_detail",
                                JsonValue::Str(h.semantic_detail.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "value_capture_states",
            JsonValue::Array(
                row.value_captures
                    .iter()
                    .map(|(state, count)| {
                        JsonValue::obj(vec![
                            ("state", JsonValue::Str(state.clone())),
                            ("values", JsonValue::U64(*count)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "hook_evidence_status",
            JsonValue::Str(
                if row.hooks.is_empty() {
                    "unknown"
                } else {
                    "reported"
                }
                .into(),
            ),
        ),
    ])
}
