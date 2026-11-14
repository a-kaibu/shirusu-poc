//! `shirusu inspect` の表示（テキストと JSON）。

use super::*;

/// inspect が表示する材料。全体読み込み ([`TraceView`]) からも、
/// ストリーミング読み ([`shirusu_analysis::stream_trace`]) からも作れる
/// (2026-11-14 レビュー P1-4: inspect は全イベントを保持しない)。
pub(crate) struct InspectData<'a> {
    pub(crate) trace: &'a ReadTrace,
    pub(crate) integrity: &'a shirusu_analysis::IntegritySummary,
    pub(crate) total_events: u64,
    pub(crate) batch_count: u64,
    pub(crate) threads: usize,
    pub(crate) with_global: u64,
    pub(crate) blob_count: u64,
    pub(crate) blob_bytes: u64,
    pub(crate) api_stats: Vec<(String, u64, u64)>,
}

impl<'a> InspectData<'a> {
    #[cfg(test)]
    pub(crate) fn from_view(view: &'a shirusu_analysis::TraceView<'a>) -> Self {
        InspectData {
            trace: view.trace,
            integrity: &view.integrity,
            total_events: view.trace.total_events(),
            batch_count: view.trace.batches.len() as u64,
            threads: view.thread_count(),
            with_global: view
                .events
                .iter()
                .filter(|e| e.global_order.is_some())
                .count() as u64,
            blob_count: view.trace.blobs.len() as u64,
            blob_bytes: view.trace.blobs.values().map(|b| b.len() as u64).sum(),
            api_stats: view.api_stats(),
        }
    }
}

/// イベントを 1 件ずつ集計する (Enter/Leave 件数、スレッド、全体順序)。
#[derive(Default)]
pub(crate) struct EventTally {
    api: std::collections::BTreeMap<String, (u64, u64)>,
    names: HashMap<u32, Option<String>>,
    threads: HashSet<(u64, u64, u64)>,
    with_global: u64,
}

impl EventTally {
    pub(crate) fn note(
        &mut self,
        registry: &shirusu_trace::SchemaRegistry,
        batch: &EventBatch,
        e: &TraceEvent,
    ) {
        self.threads
            .insert((batch.session_id, batch.process_id, batch.thread_id));
        if e.global_order.is_some() {
            self.with_global += 1;
        }
        let name = self
            .names
            .entry(e.schema_id)
            .or_insert_with(|| {
                registry
                    .get(e.schema_id)
                    .map(|def| api_name_of_schema(&def.name).to_string())
            })
            .clone()
            .unwrap_or_else(|| format!("api#{}", e.api_id));
        let entry = self.api.entry(name).or_default();
        // TraceView::api_stats と同じ数え方。
        match shirusu_analysis::Phase::of_kind(e.kind) {
            shirusu_analysis::Phase::Enter => entry.0 += 1,
            shirusu_analysis::Phase::Leave => entry.1 += 1,
            _ => {}
        }
    }
}

/// Trace をストリーミングで読み、inspect の材料を作る。
pub(crate) fn stream_for_inspect(
    path: &str,
) -> Result<(shirusu_analysis::StreamedTrace, EventTally), ToolError> {
    let file = std::fs::File::open(path)
        .map_err(|e| ToolError::Runtime(format!("cannot read {path}: {e}")))?;
    let mut tally = EventTally::default();
    let streamed = shirusu_analysis::stream_trace(std::io::BufReader::new(file), |r, b, e| {
        tally.note(r, b, e)
    })
    .map_err(|e| ToolError::Runtime(format!("{path} is not a readable trace: {e}")))?;
    Ok((streamed, tally))
}

pub(crate) fn inspect_data<'a>(
    streamed: &'a shirusu_analysis::StreamedTrace,
    tally: &EventTally,
) -> InspectData<'a> {
    InspectData {
        trace: &streamed.meta,
        integrity: &streamed.integrity,
        total_events: streamed.total_events,
        batch_count: streamed.batch_count,
        threads: tally.threads.len(),
        with_global: tally.with_global,
        blob_count: streamed.blob_count,
        blob_bytes: streamed.blob_bytes,
        api_stats: tally
            .api
            .iter()
            .map(|(k, (a, b))| (k.clone(), *a, *b))
            .collect(),
    }
}

pub(crate) fn cmd_inspect(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&["json"])?;
    let path = trace_path_arg(&parsed)?;
    let (streamed, tally) = stream_for_inspect(&path)?;
    let data = inspect_data(&streamed, &tally);
    if parsed.has("json") {
        println!("{}", inspect_json(&path, &data).render_pretty());
    } else {
        for line in inspect_lines(&path, &data) {
            println!("{line}");
        }
    }
    // H14: Event Integrity を失った Trace は incomplete と判定し、
    // 終了ステータスでも失敗を知らせる (overview「Traceの完全性」)。
    // 判定は shirusu-test の no-integrity-loss と同じ述語
    // (`has_event_loss`) を使う。Finalization なし (Unknown) や
    // Index の不一致のみは別扱いだが、破損・切断・上限超過は incomplete。
    if data.integrity.has_event_loss() {
        return Err(ToolError::Incomplete(format!(
            "{path} lost event integrity (see the loss / dropped-payload / missing-blob lines above)"
        )));
    }
    Ok(())
}

pub(crate) fn inspect_lines(path: &str, d: &InspectData) -> Vec<String> {
    let trace = d.trace;
    let s = d.integrity;
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
    out.push(format!(
        "events: {} in {} batches, {} threads",
        d.total_events, d.batch_count, d.threads
    ));
    // L11: 全体順序の有無を表示する（無い Trace では absent の 1 行）。
    out.push(if d.with_global == 0 {
        "global_order: absent".into()
    } else {
        format!(
            "global_order: present ({} of {} events)",
            d.with_global, d.total_events
        )
    });
    out.push(format!(
        "blobs: {} stored, {} bytes",
        d.blob_count, d.blob_bytes
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
        if d.integrity.has_event_loss() {
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
    for (api, enter, leave) in &d.api_stats {
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
    // api_id comes from the file: an id past u32::MAX / 2 has no Schema
    // (2026-11-14 review P3-13: the multiplication overflowed).
    let enter_schema_id = (api_id - 1).checked_mul(2).and_then(|n| n.checked_add(1));
    trace
        .schemas
        .iter()
        .find(|s| Some(s.schema_id) == enter_schema_id)
        .map(|s| api_name_of_schema(&s.name).to_string())
        .unwrap_or_else(|| format!("api#{api_id}"))
}

pub(crate) fn inspect_json(path: &str, d: &InspectData) -> JsonValue {
    let trace = d.trace;
    let s = d.integrity;
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
    let apis = d
        .api_stats
        .iter()
        .cloned()
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
        ("events", JsonValue::U64(d.total_events)),
        ("global_order_events", JsonValue::U64(d.with_global)),
        ("batches", JsonValue::U64(d.batch_count)),
        ("threads", JsonValue::U64(d.threads as u64)),
        ("blobs", JsonValue::U64(d.blob_count)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::schema::{make_schema, EventCapture, Ty};

    #[test]
    fn profile_names_survive_api_ids_from_the_file() {
        // P3-13: a crafted api_id overflowed the Schema ID computation.
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 3,
                created_by: "inspect-test".into(),
                qpc_frequency: 1000,
            },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        w.register_schema(make_schema(1, "k32!T/enter", vec![]))
            .unwrap();
        let bytes = w.finish(Default::default()).unwrap();
        let trace = shirusu_trace::read_trace(&bytes).unwrap();
        assert_eq!(
            profile_api_name(&trace, u32::MAX),
            format!("api#{}", u32::MAX)
        );
        assert_eq!(profile_api_name(&trace, 0), "api#0");
    }

    /// P1-4: ストリーミングで作った inspect の出力は、全体読み込みと同じ。
    #[test]
    fn streamed_inspect_matches_full_read() {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 3,
                created_by: "inspect-test".into(),
                qpc_frequency: 1000,
            },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        w.register_schema(make_schema(
            1,
            "k32!T/enter",
            vec![("x".into(), Ty::U32, 0)],
        ))
        .unwrap();
        w.register_schema(make_schema(2, "k32!T/leave", vec![]))
            .unwrap();
        let blob = w.add_payload(b"payload").unwrap();
        for thread in 1..=3u64 {
            let events = (1..=4u64)
                .map(|seq| TraceEvent {
                    kind: if seq % 2 == 1 { 1 } else { 2 },
                    sequence: seq,
                    timestamp_qpc: seq,
                    call_id: seq.div_ceil(2),
                    parent_call_id: 0,
                    api_id: 1,
                    schema_id: if seq % 2 == 1 { 1 } else { 2 },
                    capture: EventCapture::Captured,
                    payload: if seq == 1 {
                        PayloadRef::Blob(blob)
                    } else {
                        PayloadRef::None
                    },
                    args: None,
                    global_order: None,
                })
                .collect();
            w.write_batch(&EventBatch {
                session_id: 3,
                process_id: 1,
                raw_pid: 9,
                thread_id: thread,
                qpc_frequency: 1000,
                events,
            })
            .unwrap();
        }
        let bytes = w.finish(FinalizationInfo::default()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.trace");
        std::fs::write(&path, &bytes).unwrap();
        let path = path.to_str().unwrap();
        let full = shirusu_trace::read_trace(&bytes).unwrap();
        let view = shirusu_analysis::TraceView::build(&full);
        let expected = InspectData::from_view(&view);
        let (streamed, tally) = stream_for_inspect(path).unwrap();
        let got = inspect_data(&streamed, &tally);
        assert_eq!(inspect_lines(path, &got), inspect_lines(path, &expected));
        assert_eq!(
            inspect_json(path, &got).render(),
            inspect_json(path, &expected).render()
        );
    }
}
