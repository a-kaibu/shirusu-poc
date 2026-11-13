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
    let mut matched: Vec<shirusu_analysis::EventView> = Vec::new();
    let mut index = 0usize;
    let wanted = if order_global {
        usize::MAX
    } else {
        limit.unwrap_or(usize::MAX)
    };
    'read: while let Some(item) = stream.next_item().map_err(read_error)? {
        if let shirusu_trace::stream::StreamItem::Events(batch) = item {
            for e in &batch.events {
                let ev = shirusu_analysis::EventView::of(stream.registry(), &batch, e, index);
                index += 1;
                if filter.matches(&ev) {
                    matched.push(ev);
                    if matched.len() >= wanted {
                        break 'read;
                    }
                }
            }
        }
    }
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
