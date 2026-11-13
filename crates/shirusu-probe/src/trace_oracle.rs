//! Bind a replay fingerprint to a recorded output difference. Deliberately
//! reject divergent prerequisites instead of guessing which state caused it.
use crate::oracle::{DifferenceFingerprint, TargetObservation};
use crate::replay::{generate_candidate_replay, ReplaySlice};
use shirusu_analysis::{EventView, TraceView};
use shirusu_compare::{Candidate, CandidateKind, NormCall, NormTrace};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{EventCapture, TypedValue, ValueCapture};

pub fn fingerprint_from_traces(
    left: &ReadTrace,
    right: &ReadTrace,
    candidate: &Candidate,
) -> Result<(ReplaySlice, DifferenceFingerprint), String> {
    if !matches!(
        candidate.kind,
        CandidateKind::ArgumentDifference | CandidateKind::ReturnDifference
    ) || !shirusu_compare::compare_traces(left, right)
        .candidates
        .contains(candidate)
    {
        return Err("candidate is not a current recorded value difference".into());
    }
    let replay = generate_candidate_replay(left, candidate)?;
    let lv = TraceView::build(left);
    let rv = TraceView::build(right);
    let ln = NormTrace::build(left);
    let rn = NormTrace::build(right);
    let lc = ordered_calls(&lv, &ln)?;
    let rc = ordered_calls(&rv, &rn)?;
    let target = replay.target_source_step;
    let lcall = lc.get(target).ok_or("baseline target is missing")?;
    let evidence = candidate
        .right_event
        .as_ref()
        .ok_or("candidate has no comparison event")?;
    let ri = crate::select::locate_call(&rn, evidence).ok_or("comparison target is missing")?;
    let rtarget = rc
        .iter()
        .position(|c| std::ptr::eq(*c, &rn.calls[ri]))
        .ok_or("comparison target position is missing")?;
    if rtarget != target {
        return Err("recorded prerequisite sequences differ".into());
    }
    for (l, r) in lc.iter().zip(&rc).take(target) {
        if l.api != r.api
            || l.enter.as_ref().unwrap().fields != r.enter.as_ref().unwrap().fields
            || l.leave.as_ref().unwrap().fields != r.leave.as_ref().unwrap().fields
        {
            return Err("recorded prerequisites differ before the target".into());
        }
    }
    let rcall = rc[target];
    if lcall.api != rcall.api
        || lcall.enter.as_ref().unwrap().fields != rcall.enter.as_ref().unwrap().fields
    {
        return Err("target inputs differ; one replay cannot represent both".into());
    }
    let baseline = observation(&lv, lcall)?;
    let comparison = observation(&rv, rcall)?;
    if baseline == comparison {
        return Err("candidate has no supported semantic output difference".into());
    }
    let fingerprint = DifferenceFingerprint {
        source_step: target,
        call: lcall.api.clone(),
        baseline,
        candidate: comparison,
    };
    Ok((replay, fingerprint))
}

fn ordered_calls<'a>(view: &TraceView, norm: &'a NormTrace) -> Result<Vec<&'a NormCall>, String> {
    let i = &view.integrity;
    if !i.has_finalization
        || !i.finalized_cleanly
        || i.event_integrity != Some(0)
        || i.semantic_completeness != Some(0)
        || !i.loss_records_by_kind.is_empty()
        || !i.recovery_issues.is_empty()
        || i.dropped_payload_events != 0
        || i.missing_blob_refs != 0
        || i.degraded_events != 0
    {
        return Err("trace has incomplete recorded evidence".into());
    }
    let contexts: std::collections::BTreeSet<_> = view
        .events
        .iter()
        .map(|e| (e.session_id, e.process_id, e.thread_id))
        .collect();
    if contexts.len() != 1
        || view.events.iter().any(|e| {
            e.parent_call_id != 0 || e.capture != EventCapture::Captured || e.args_error.is_some()
        })
    {
        return Err("trace must contain one captured top-level synchronous thread".into());
    }
    let mut calls: Vec<_> = norm.calls.iter().collect();
    calls.sort_by_key(|c| c.first_sequence);
    if calls.len().checked_mul(2) != Some(view.events.len())
        || calls.iter().any(|c| {
            c.enter.is_none()
                || c.leave.is_none()
                || c.completed.is_some()
                || c.aborted.is_some()
                || c.solo.is_some()
        })
    {
        return Err("trace calls must have paired synchronous enter/leave events".into());
    }
    let mut previous = None;
    for c in &calls {
        let enter = c.enter.as_ref().unwrap();
        let leave = c.leave.as_ref().unwrap();
        if enter.sequence >= leave.sequence || previous.is_some_and(|p| p >= enter.sequence) {
            return Err("trace calls overlap or have duplicate sequence numbers".into());
        }
        previous = Some(leave.sequence);
    }
    Ok(calls)
}

fn observation(view: &TraceView, call: &NormCall) -> Result<TargetObservation, String> {
    let enter = &view.events[call.enter.as_ref().unwrap().source_index];
    let leave = &view.events[call.leave.as_ref().unwrap().source_index];
    if !matches!(
        call.api.as_str(),
        "kernel32!ReadFile" | "kernel32!WriteFile" | "kernel32!CloseHandle"
    ) {
        return Err("target API has no supported output fingerprint".into());
    }
    let succeeded = number(leave, "return")? != 0;
    let mut result = TargetObservation {
        succeeded,
        failure_error: None,
        transferred: None,
        data: None,
    };
    if !succeeded {
        result.failure_error = Some(
            u32::try_from(number(leave, "last_error")?).map_err(|_| "last-error exceeds u32")?,
        );
        return Ok(result);
    }
    if call.api == "kernel32!CloseHandle" {
        return Ok(result);
    }
    let read = call.api == "kernel32!ReadFile";
    let requested = number(
        enter,
        if read {
            "nNumberOfBytesToRead"
        } else {
            "nNumberOfBytesToWrite"
        },
    )?;
    let count = number(
        leave,
        if read {
            "lpNumberOfBytesRead"
        } else {
            "lpNumberOfBytesWritten"
        },
    )?;
    if count > requested {
        return Err("transfer exceeds requested buffer capacity".into());
    }
    result.transferred = Some(count);
    if read {
        let TypedValue::Bytes(bytes) = value(leave, "data")? else {
            return Err("read data is not bytes".into());
        };
        if bytes.len() as u64 != count {
            return Err("read data is incomplete".into());
        }
        result.data = Some(bytes.iter().map(|b| format!("{b:02x}")).collect());
    }
    Ok(result)
}

fn value<'a>(event: &'a EventView, name: &str) -> Result<&'a TypedValue, String> {
    let field = event
        .field(name)
        .ok_or_else(|| format!("missing field {name}"))?;
    if field.capture != ValueCapture::Captured {
        return Err(format!("field {name} was not captured"));
    }
    Ok(&field.value)
}
fn number(event: &EventView, name: &str) -> Result<u64, String> {
    match value(event, name)? {
        TypedValue::U64(n) | TypedValue::Ptr64(n) => Ok(*n),
        TypedValue::U32(n) | TypedValue::Ptr32(n) => Ok(*n as u64),
        TypedValue::I32(n) if *n >= 0 => Ok(*n as u64),
        _ => Err(format!("field {name} is not a nonnegative number")),
    }
}
