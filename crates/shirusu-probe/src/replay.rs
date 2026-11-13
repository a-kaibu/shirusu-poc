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
    let invalid_handle = match trace.environment.as_ref().map(|env| env.pointer_width) {
        Some(32) => u32::MAX as u64,
        Some(64) => u64::MAX,
        _ => return Err("replay requires a known 32/64-bit process pointer width".into()),
    };
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
        match api {
            "kernel32!CreateFileW" => {
                let ret = number(leave, "return")?;
                let path = match value(enter, "lpFileName")? {
                    TypedValue::Str16(v) => {
                        String::from_utf16(v).map_err(|_| "filename contains ill-formed UTF-16")?
                    }
                    TypedValue::Str(v) => v.clone(),
                    _ => return Err("filename is not text".into()),
                };
                validate_regular_file_path(&path)?;
                let disposition = number(enter, "dwCreationDisposition")?;
                let access = number(enter, "dwDesiredAccess")?;
                let flags = number(enter, "dwFlagsAndAttributes")?;
                if ret == 0 || ret >= invalid_handle || handles.contains_key(&ret) {
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
                if !bool_return(leave)? {
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
                if !bool_return(leave)? {
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

/// Path remapping only models ordinary file bytes. Device/stream/network
/// namespaces and Win32 normalization are not reproduced by a fresh local file.
/// This rejects known incompatible spellings, not an attestation about reparse
/// points or filesystem state that was never captured.
fn validate_regular_file_path(path: &str) -> Result<(), String> {
    let unsupported = || {
        "replay requires an ordinary file path; device, network, stream and normalized-name semantics are unsupported".to_string()
    };
    let normalized = path.replace('/', "\\");
    if normalized.is_empty()
        || normalized.starts_with("\\\\")
        || normalized
            .chars()
            .any(|c| c <= '\u{1f}' || "<>\"|?*".contains(c))
    {
        return Err(unsupported());
    }
    let rest = if normalized.as_bytes().get(1) == Some(&b':') {
        if !normalized.as_bytes()[0].is_ascii_alphabetic()
            || normalized.as_bytes().get(2) != Some(&b'\\')
        {
            return Err(unsupported());
        }
        &normalized[3..]
    } else {
        normalized.as_str()
    };
    if rest.is_empty() || rest.contains(':') || rest.ends_with('\\') {
        return Err(unsupported());
    }
    for component in rest.split('\\').filter(|s| !s.is_empty()) {
        if component.ends_with(['.', ' ']) {
            return Err(unsupported());
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ');
        let upper = stem.to_ascii_uppercase();
        let numbered_device = upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            });
        if numbered_device
            || matches!(
                upper.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
            )
        {
            return Err(unsupported());
        }
    }
    Ok(())
}

/// A conservative file dependency slice, not an execution-verified minimum.
#[derive(Debug)]
pub struct ReplaySlice {
    pub spec: TestSpec,
    pub source_steps: usize,
    /// Zero-based step positions in the complete supported baseline sequence.
    pub kept_steps: Vec<usize>,
    pub target_source_step: usize,
    pub target_replay_step: usize,
}

/// Keep every recorded lifetime of the file touched by the candidate's baseline
/// event. A reopened handle depends on writes through older, already closed
/// handles; handle-only slicing would silently lose those prerequisites.
/// Validate the entire source first: unsupported side effects cannot be discarded
/// just because they do not carry a recognized file handle.
pub fn generate_candidate_replay(
    trace: &ReadTrace,
    candidate: &shirusu_compare::Candidate,
) -> Result<ReplaySlice, String> {
    let full = generate_replay(trace)?;
    let evidence = candidate
        .left_event
        .as_ref()
        .ok_or("candidate has no baseline event; cannot identify a replay dependency root")?;
    let norm = shirusu_compare::NormTrace::build(trace);
    let call = crate::select::locate_call(&norm, evidence)
        .and_then(|i| norm.calls[i].enter.as_ref())
        .ok_or("candidate baseline call cannot be located")?;
    let view = TraceView::build(trace);
    let sequence = view
        .events
        .get(call.source_index)
        .ok_or("candidate source event is missing")?
        .sequence;
    let mut enters: Vec<_> = view.events.iter().filter(|e| e.kind == 1).collect();
    enters.sort_by_key(|e| e.sequence);
    let target = enters
        .iter()
        .position(|e| e.sequence == sequence)
        .ok_or("candidate baseline step is missing")?;
    if enters.len() != full.steps.len() {
        return Err("replay step provenance does not match source calls".into());
    }
    let mut variables = BTreeMap::<String, String>::new();
    let mut paths = Vec::with_capacity(full.steps.len());
    for step in &full.steps {
        let path = if step.call == "kernel32!CreateFileW" {
            let path = step
                .args
                .iter()
                .find_map(|(name, value)| match (name.as_str(), value) {
                    ("lpFileName", ArgValue::Text(path)) => Some(path.clone()),
                    _ => None,
                })
                .ok_or("file creation lacks a replay path")?;
            variables.insert(
                step.store.clone().ok_or("file creation lacks a variable")?,
                path.clone(),
            );
            path
        } else {
            step.args
                .iter()
                .find_map(|(name, value)| match (name.as_str(), value) {
                    ("hFile" | "hObject", ArgValue::Ref(var)) => variables.get(var).cloned(),
                    _ => None,
                })
                .ok_or("file operation lacks a linked replay path")?
        };
        paths.push(path);
    }
    let kept_steps: Vec<_> = paths
        .iter()
        .enumerate()
        .filter_map(|(i, path)| (path == &paths[target]).then_some(i))
        .collect();
    let target_replay_step = kept_steps
        .iter()
        .position(|i| *i == target)
        .ok_or("dependency slice lost its root")?;
    let source_steps = full.steps.len();
    let spec = TestSpec {
        name: "candidate-file-dependencies".into(),
        steps: kept_steps.iter().map(|i| full.steps[*i].clone()).collect(),
        rules: vec![],
    };
    plan_steps(&spec.steps)?;
    Ok(ReplaySlice {
        spec,
        source_steps,
        kept_steps,
        target_source_step: target,
        target_replay_step,
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

/// Win32 BOOL is a signed 32-bit value: every nonzero value means success.
/// Keep this separate from unsigned counts, handles and buffer lengths.
pub(crate) fn bool_return(event: &EventView) -> Result<bool, String> {
    match value(event, "return")? {
        TypedValue::I32(value) => Ok(*value != 0),
        TypedValue::U32(value) => Ok(*value != 0),
        _ => Err("return is not a 32-bit BOOL".into()),
    }
}
