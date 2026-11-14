//! `shirusu dump` / `shirusu export` とイベントフィルタ。

use super::*;

pub(crate) fn build_filter(parsed: &Parsed) -> Result<EventFilter, ToolError> {
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

/// Trace をストリーミング読み取り用に開く（全体をメモリへ読み込まない）。
pub(crate) fn open_trace_stream(
    parsed: &Parsed,
) -> Result<
    (
        String,
        shirusu_trace::stream::TraceStream<std::io::BufReader<std::fs::File>>,
    ),
    ToolError,
> {
    let path = parsed
        .positional
        .first()
        .ok_or_else(|| ToolError::Usage("missing <trace> path".to_string()))?
        .clone();
    if parsed.positional.len() > 1 {
        return Err(ToolError::Usage("too many positional arguments".into()));
    }
    let file = std::fs::File::open(&path)
        .map_err(|e| ToolError::Runtime(format!("cannot read {path}: {e}")))?;
    let stream = shirusu_trace::stream::TraceStream::open(std::io::BufReader::new(file))
        .map_err(|e| ToolError::Runtime(format!("{path} is not a readable trace: {e}")))?;
    Ok((path, stream))
}

pub(crate) fn cmd_dump(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&[
        "json", "api", "kind", "seq", "thread", "text", "limit", "order",
    ])?;
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
    // ストリーミング読み取り: Event Chunk を 1 つずつ復号し、条件に合う
    // イベントだけを保持する。--order=global でなければ --limit に達した
    // 時点で読み終える。
    let (path, mut stream) = open_trace_stream(&parsed)?;
    let read_error = |e: shirusu_trace::TraceError| ToolError::Runtime(format!("{path}: {e}"));
    let write_error = |e: std::io::Error| ToolError::Runtime(format!("write failed: {e}"));
    let json = parsed.has("json");
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    // P1-4: --order=global でなければ一致したイベントをすぐ書き出す
    // (以前は全件を EventView の Vec に溜めてから出力していた)。
    // --order=global は並べ替えのため、出力行と順序だけを保持する。
    let mut ordered: Vec<(u64, String)> = Vec::new();
    let mut written = 0usize;
    let mut missing_global = false;
    let mut index = 0usize;
    let wanted = limit.unwrap_or(usize::MAX);
    if json && !order_global {
        out.write_all(b"[").map_err(write_error)?;
    }
    let mut stopped_early = false;
    'read: while let Some(item) = stream.next_item().map_err(read_error)? {
        if let shirusu_trace::stream::StreamItem::Events(batch) = item {
            for e in &batch.events {
                let ev = shirusu_analysis::EventView::of(stream.registry(), &batch, e, index);
                index += 1;
                if !filter.matches(&ev) {
                    continue;
                }
                let rendered = if json {
                    ev.to_json().render()
                } else {
                    ev.line()
                };
                if order_global {
                    match ev.global_order {
                        Some(g) => ordered.push((g, rendered)),
                        None => missing_global = true,
                    }
                    continue;
                }
                if json && written > 0 {
                    out.write_all(b",").map_err(write_error)?;
                }
                out.write_all(rendered.as_bytes()).map_err(write_error)?;
                if !json {
                    out.write_all(b"\n").map_err(write_error)?;
                }
                written += 1;
                if written >= wanted {
                    stopped_early = true;
                    break 'read;
                }
            }
        }
    }
    if order_global {
        // 全体順序を持たないイベントが 1 件でもあれば、その Trace は
        // --order=global で記録されたものではない。
        if missing_global {
            return Err(ToolError::Runtime(
                "this trace was not recorded with --order=global".into(),
            ));
        }
        // global_order はイベントごとに一意なので安定ソートで十分。
        ordered.sort_by_key(|(g, _)| *g);
        if json {
            out.write_all(b"[").map_err(write_error)?;
        }
        for (i, (_, rendered)) in ordered.iter().take(wanted).enumerate() {
            if json && i > 0 {
                out.write_all(b",").map_err(write_error)?;
            }
            out.write_all(rendered.as_bytes()).map_err(write_error)?;
            if !json {
                out.write_all(b"\n").map_err(write_error)?;
            }
        }
        if json {
            out.write_all(b"]\n").map_err(write_error)?;
        }
    } else if json {
        out.write_all(b"]\n").map_err(write_error)?;
    }
    out.flush().map_err(write_error)?;
    if !stopped_early {
        report_stream_issues(&path, stream.issues())?;
    }
    Ok(())
}

/// P1-3: 読み終えた Trace の問題を stderr に出す。Reader の上限で読み
/// 止めた場合は出力が途中までなので失敗として返す (以前は黙って出力を
/// 止め、終了コード 0 だった)。
pub(crate) fn report_stream_issues(
    path: &str,
    issues: &[shirusu_trace::RecoveryIssue],
) -> Result<(), ToolError> {
    let mut limit = None;
    for issue in issues {
        eprintln!("warning: {path}: {issue:?}");
        if let shirusu_trace::RecoveryIssue::LimitExceeded { what } = issue {
            limit = Some(*what);
        }
    }
    match limit {
        Some(what) => Err(ToolError::Runtime(format!(
            "{path}: reader limit reached ({what}); output is incomplete"
        ))),
        None => Ok(()),
    }
}

/// Build output beside its destination and publish only after writing succeeds.
/// Replacing the directory entry also avoids truncating an input hard-link alias.
pub(crate) fn prepare_output(
    input: &str,
    output: &str,
) -> Result<tempfile::NamedTempFile, ToolError> {
    if output == input
        || std::fs::canonicalize(output)
            .ok()
            .zip(std::fs::canonicalize(input).ok())
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
    tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        ToolError::Runtime(format!("cannot create temporary output for {output}: {e}"))
    })
}

pub(crate) fn cmd_export(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &[])?;
    parsed.validate_options(&["format", "output"])?;
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
        let mut file = prepare_output(&path, output)?;
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
    let mut file = parsed
        .opt("output")
        .map(|output| prepare_output(&path, output))
        .transpose()?;
    {
        let mut sink: Box<dyn std::io::Write + '_> = match file.as_mut() {
            Some(file) => Box::new(std::io::BufWriter::new(file.as_file_mut())),
            None => Box::new(std::io::stdout()),
        };
        for ev in &view.events {
            writeln!(sink, "{}", ev.to_json().render())
                .map_err(|e| ToolError::Runtime(format!("write failed: {e}")))?;
        }
        sink.flush()
            .map_err(|e| ToolError::Runtime(format!("flush failed: {e}")))?;
    }
    if let Some(file) = file {
        let output = parsed.opt("output").expect("output file was prepared");
        file.persist(output).map_err(|e| {
            ToolError::Runtime(format!("cannot publish JSONL output {output}: {e}"))
        })?;
    }
    Ok(())
}
