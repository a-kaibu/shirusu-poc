//! Conservative replay of complete, single-threaded synchronous file traces.
//! Paths are remapped; CREATE_NEW prevents overwriting an existing replay file.
use std::collections::{BTreeMap, BTreeSet};

use shirusu_analysis::{EventView, TraceView};
use shirusu_test::runner_exec::{
    plan_steps, ArgValue, Expect, ExpectedOutput, RetExpect, Step, MAX_CAPTURED_BUFFER,
};
use shirusu_test::TestSpec;
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{EventCapture, TypedValue, ValueCapture};

/// Generate an executable spec, or explain the first unmet prerequisite.
/// This preserves the full supported call sequence; it is not a minimized probe.
/// Run in a fresh scratch directory. Generated files remain there for inspection.
pub fn generate_replay(trace: &ReadTrace) -> Result<TestSpec, String> {
    let view = TraceView::build(trace);
    let integrity = &view.integrity;
    // Coverage describes which APIs were observable, not loss of recorded events.
    // Reconstruct the recorded sequence only; never claim whole-program replay.
    if !integrity.has_finalization
        || !integrity.finalized_cleanly
        || integrity.event_integrity != Some(0)
        || integrity.semantic_completeness != Some(0)
        || !integrity.loss_records_by_kind.is_empty()
        || !integrity.recovery_issues.is_empty()
        || integrity.dropped_payload_events != 0
        || integrity.missing_blob_refs != 0
        || integrity.degraded_events != 0
    {
        return Err("replay requires a finalized trace without event loss, semantic loss or reader recovery issues".into());
    }
    let contexts: BTreeSet<_> = view
        .events
        .iter()
        .map(|e| (e.session_id, e.process_id, e.thread_id))
        .collect();
    if contexts.len() != 1 {
        return Err("replay requires exactly one process and thread".into());
    }
    let mut events: Vec<_> = view.events.iter().collect();
    events.sort_by_key(|e| e.sequence);
    if events.len() % 2 != 0 || events.windows(2).any(|w| w[0].sequence == w[1].sequence) {
        return Err("unpaired or duplicate events".into());
    }
    let mut seen = BTreeSet::new();
    let mut files: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    // raw handle -> (stored variable, original filename, cursor, access)
    let mut handles: BTreeMap<u64, (String, String, usize, u64)> = BTreeMap::new();
    let mut steps = Vec::new();
    for pair in events.chunks_exact(2) {
        let (enter, leave) = (pair[0], pair[1]);
        if enter.kind != 1
            || leave.kind != 2
            || enter.call_id != leave.call_id
            || enter.api_name != leave.api_name
            || !seen.insert(enter.call_id)
            || [enter, leave].iter().any(|e| {
                e.parent_call_id != 0
                    || e.capture != EventCapture::Captured
                    || e.args_error.is_some()
            })
        {
            return Err("replay requires paired, captured, top-level synchronous calls".into());
        }
        let api = enter.api_name.as_deref().ok_or("missing API schema")?;
        let mut step = Step {
            call: api.into(),
            args: vec![],
            store: None,
            expect: Some(Expect {
                ret: Some(RetExpect::NonZero),
                outputs: vec![],
            }),
        };
        let ret = number(leave, "return")?;
        match api {
            "kernel32!CreateFileW" => {
                let path = match value(enter, "lpFileName")? {
                    TypedValue::Str16(v) => {
                        String::from_utf16(v).map_err(|_| "filename contains ill-formed UTF-16")?
                    }
                    TypedValue::Str(v) => v.clone(),
                    _ => return Err("filename is not text".into()),
                };
                let disposition = number(enter, "dwCreationDisposition")?;
                let access = number(enter, "dwDesiredAccess")?;
                let flags = number(enter, "dwFlagsAndAttributes")?;
                if ret == 0
                    || ret == u64::MAX
                    || ret == u32::MAX as u64
                    || handles.contains_key(&ret)
                {
                    return Err("failed creation or reused live handle".into());
                }
                if access == 0
                    || access & !0xc000_0000 != 0
                    || number(enter, "dwShareMode")? != 0
                    || number(enter, "lpSecurityAttributes")? != 0
                    || number(enter, "hTemplateFile")? != 0
                    || ![0, 128].contains(&flags)
                {
                    return Err("replay supports generic read/write, exclusive sharing, normal synchronous files and no security/template pointers".into());
                }
                if handles.values().any(|(_, p, _, _)| p == &path) {
                    return Err("concurrent opens of one file are unsupported".into());
                }
                match (disposition, files.contains_key(&path)) {
                    (1, false) => { files.insert(path.clone(), (format!("shirusu-replay-{}.bin", files.len()), vec![])); }
                    (3, true) => {}
                    _ => return Err("initial file state is unknown: first open must be CREATE_NEW; subsequent opens must be OPEN_EXISTING".into()),
                }
                let name = format!("file_{}", steps.len());
                step.args = vec![
                    ("lpFileName".into(), ArgValue::Text(files[&path].0.clone())),
                    ("dwDesiredAccess".into(), ArgValue::Int(access)),
                    ("dwShareMode".into(), ArgValue::Int(0)),
                    ("lpSecurityAttributes".into(), ArgValue::Null),
                    ("dwCreationDisposition".into(), ArgValue::Int(disposition)),
                    ("dwFlagsAndAttributes".into(), ArgValue::Int(flags)),
                    ("hTemplateFile".into(), ArgValue::Null),
                ];
                step.store = Some(name.clone());
                step.expect.as_mut().unwrap().ret = Some(RetExpect::ValidHandle);
                handles.insert(ret, (name, path, 0, access));
            }
            "kernel32!WriteFile" | "kernel32!ReadFile" => {
                if ret != 1 {
                    return Err(format!(
                        "{api}: only successful synchronous I/O is supported"
                    ));
                }
                if number(enter, "lpOverlapped")? != 0 {
                    return Err("explicit OVERLAPPED offsets are not supported".into());
                }
                let write = api.ends_with("WriteFile");
                let handle = number(enter, "hFile")?;
                let (name, path, cursor, access) = handles
                    .get_mut(&handle)
                    .ok_or("unlinked or closed file handle")?;
                if *access & if write { 0x4000_0000 } else { 0x8000_0000 } == 0 {
                    return Err("I/O access does not match open mode".into());
                }
                let (requested_field, count_field) = if write {
                    ("nNumberOfBytesToWrite", "lpNumberOfBytesWritten")
                } else {
                    ("nNumberOfBytesToRead", "lpNumberOfBytesRead")
                };
                let requested = number(enter, requested_field)?;
                let count = number(leave, count_field)?;
                if requested > MAX_CAPTURED_BUFFER as u64 || count > requested {
                    return Err("I/O size exceeds replay capture budget or requested length".into());
                }
                let bytes = match value(if write { enter } else { leave }, "data")? {
                    TypedValue::Bytes(bytes) => bytes,
                    _ => return Err("I/O data was not captured as bytes".into()),
                };
                let data = &mut files.get_mut(path).unwrap().1;
                let end = cursor
                    .checked_add(count as usize)
                    .ok_or("file offset overflow")?;
                if write {
                    if bytes.len() != requested as usize {
                        return Err("write input is incomplete".into());
                    }
                    // Bound retained model data independently of the input Trace size.
                    if end > 1024 * 1024 {
                        return Err("file model exceeds 1 MiB replay budget".into());
                    }
                    data.resize(data.len().max(end), 0);
                    data[*cursor..end].copy_from_slice(&bytes[..count as usize]);
                } else if bytes.len() != count as usize
                    || end > data.len()
                    || &data[*cursor..end] != bytes
                    || count as usize != (data.len() - *cursor).min(requested as usize)
                {
                    return Err("read result cannot be reconstructed from earlier writes".into());
                }
                *cursor = end;
                step.args = vec![
                    ("hFile".into(), ArgValue::Ref(name.clone())),
                    (
                        "lpBuffer".into(),
                        ArgValue::Buffer {
                            size: requested as usize,
                            fill: if write { bytes.clone() } else { vec![] },
                        },
                    ),
                    (requested_field.into(), ArgValue::Int(requested)),
                    (count_field.into(), ArgValue::OutU32),
                    ("lpOverlapped".into(), ArgValue::Null),
                ];
                step.expect
                    .as_mut()
                    .unwrap()
                    .outputs
                    .push((count_field.into(), ExpectedOutput::U64(count)));
                if !write {
                    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    step.expect
                        .as_mut()
                        .unwrap()
                        .outputs
                        .push(("lpBuffer".into(), ExpectedOutput::HexPrefix(hex)));
                }
            }
            "kernel32!CloseHandle" => {
                if ret != 1 {
                    return Err("CloseHandle did not succeed".into());
                }
                let handle = number(enter, "hObject")?;
                let (name, _, _, _) = handles
                    .remove(&handle)
                    .ok_or("close refers to an unknown handle")?;
                step.args.push(("hObject".into(), ArgValue::Ref(name)));
            }
            _ => return Err(format!("unsupported replay API: {api}")),
        }
        steps.push(step);
    }
    if files.is_empty() || !handles.is_empty() {
        return Err("replay requires at least one file and all handles closed".into());
    }
    plan_steps(&steps)?;
    Ok(TestSpec {
        name: "recorded-file-io".into(),
        steps,
        rules: vec![],
    })
}

fn value<'a>(event: &'a EventView, name: &str) -> Result<&'a TypedValue, String> {
    let field = event
        .field(name)
        .ok_or_else(|| format!("missing field {name}"))?;
    if field.capture != ValueCapture::Captured {
        return Err(format!("field {name} was not fully captured"));
    }
    Ok(&field.value)
}
fn number(event: &EventView, name: &str) -> Result<u64, String> {
    match value(event, name)? {
        TypedValue::U64(v) | TypedValue::Ptr64(v) => Ok(*v),
        TypedValue::U32(v) | TypedValue::Ptr32(v) => Ok(u64::from(*v)),
        TypedValue::I32(v) if *v >= 0 => Ok(*v as u64),
        _ => Err(format!("field {name} is not a nonnegative integer")),
    }
}
