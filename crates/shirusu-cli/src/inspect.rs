//! `shirusu inspect` の表示（テキストと JSON）。

use super::*;

pub(crate) fn cmd_inspect(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&["json"])?;
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

pub(crate) fn inspect_lines(path: &str, view: &TraceView) -> Vec<String> {
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
pub(crate) fn qpc_ms(qpc_frequency: u64, ticks: u64) -> String {
    if qpc_frequency == 0 {
        format!("{ticks} ticks")
    } else {
        format!("{:.3} ms", ticks as f64 * 1000.0 / qpc_frequency as f64)
    }
}

/// ProfileSummary の api_id から表示名を引く。enter Schema の名前
/// （`kernel32!CreateFileW/enter`）から API 名を取り出す。Schema が
/// 無ければ `api#<id>` とする。
pub(crate) fn profile_api_name(trace: &ReadTrace, api_id: u32) -> String {
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

pub(crate) fn inspect_json(path: &str, view: &TraceView) -> JsonValue {
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
