//! Complete synchronous-file reduction workflow with retained local evidence.
use crate::external::{run_external, RunnerCommand};
use crate::reduce::{reduce_file_io, Reduction, TrialOutcome};
use shirusu_analysis::JsonValue as J;
use std::fs;
use std::path::Path;
use std::time::Duration;

pub struct ReductionConfig {
    pub baseline: RunnerCommand,
    pub candidate: RunnerCommand,
    pub max_trials: usize,
    pub timeout: Duration,
}

/// The output directory must not exist. Each oracle invocation runs both
/// configured executables with identical specs in separate fresh directories.
/// Source traces, specs, stdout, stderr and decisions remain available on error.
pub fn reduce_with_runners(
    left_bytes: &[u8],
    right_bytes: &[u8],
    candidate_index: usize,
    config: &ReductionConfig,
    out: &Path,
) -> Result<Reduction, String> {
    if config.max_trials < 2 || config.timeout.is_zero() {
        return Err("at least two trials and a positive timeout are required".into());
    }
    let left = shirusu_trace::read_trace(left_bytes).map_err(|e| e.to_string())?;
    let right = shirusu_trace::read_trace(right_bytes).map_err(|e| e.to_string())?;
    let diff = shirusu_compare::compare_traces(&left, &right);
    let candidate = diff
        .candidates
        .get(candidate_index)
        .ok_or("candidate index out of range")?;
    let (replay, fingerprint) =
        crate::trace_oracle::fingerprint_from_traces(&left, &right, candidate)?;
    fs::create_dir(out).map_err(|e| format!("create new reduction directory: {e}"))?;
    let out = fs::canonicalize(out).map_err(|e| e.to_string())?;
    fs::write(out.join("source-left.trace"), left_bytes).map_err(|e| e.to_string())?;
    fs::write(out.join("source-right.trace"), right_bytes).map_err(|e| e.to_string())?;
    fs::write(
        out.join("expected-difference.json"),
        fingerprint.to_json().render_pretty(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        out.join("config.json"),
        J::obj(vec![
            ("candidate_index", J::U64(candidate_index as u64)),
            ("max_trials", J::U64(config.max_trials as u64)),
            (
                "timeout_ms",
                J::U64(config.timeout.as_millis().min(u64::MAX as u128) as u64),
            ),
            (
                "baseline_program",
                J::Str(config.baseline.program.to_string_lossy().into_owned()),
            ),
            (
                "candidate_program",
                J::Str(config.candidate.program.to_string_lossy().into_owned()),
            ),
        ])
        .render_pretty(),
    )
    .map_err(|e| e.to_string())?;
    let mut number = 0;
    let mut pending: Option<(Vec<usize>, usize)> = None;
    let mut verified: Option<(Vec<usize>, [usize; 2])> = None;
    let result = reduce_file_io(replay, config.max_trials, |trial| {
        number += 1;
        let directory = out.join(format!("trial-{number:05}"));
        fs::create_dir(&directory).map_err(|e| e.to_string())?;
        let provenance = J::obj(vec![
            ("source_steps", indices(trial.source_steps)),
            (
                "target_replay_step",
                J::U64(trial.target_replay_step as u64),
            ),
        ]);
        fs::write(directory.join("trial.json"), provenance.render_pretty())
            .map_err(|e| e.to_string())?;
        let baseline = run_external(
            &config.baseline,
            trial.spec,
            &directory.join("baseline"),
            config.timeout,
        )?;
        let candidate = run_external(
            &config.candidate,
            trial.spec,
            &directory.join("candidate"),
            config.timeout,
        )?;
        let outcome = fingerprint.evaluate(&trial, &baseline, &candidate);
        let label = match outcome {
            TrialOutcome::SameTargetDifference => "same-target-difference",
            TrialOutcome::DifferenceAbsent => "difference-absent",
            TrialOutcome::Inconclusive => "inconclusive",
        };
        fs::write(
            directory.join("decision.json"),
            J::obj(vec![("outcome", J::Str(label.into()))]).render_pretty(),
        )
        .map_err(|e| e.to_string())?;
        if outcome == TrialOutcome::SameTargetDifference {
            if let Some((source, first)) = pending.take().filter(|(s, _)| s == trial.source_steps) {
                verified = Some((source, [first, number]));
            } else {
                pending = Some((trial.source_steps.to_vec(), number));
            }
        } else {
            pending = None;
        }
        Ok::<_, String>(outcome)
    });
    let reduction = match result {
        Ok(value) => value,
        Err(error) => {
            let reason = format!("reduction failed: {error:?}");
            fs::write(
                out.join("result.json"),
                J::obj(vec![
                    ("execution_verified", J::Bool(false)),
                    ("error", J::Str(reason.clone())),
                ])
                .render_pretty(),
            )
            .map_err(|e| e.to_string())?;
            return Err(reason);
        }
    };
    let (source, evidence) = verified.ok_or("missing repeated execution evidence")?;
    if source != reduction.replay.kept_steps {
        return Err("final replay does not match verified trials".into());
    }
    fs::write(
        out.join("reduced.json"),
        reduction.replay.spec.to_json().render_pretty(),
    )
    .map_err(|e| e.to_string())?;
    let summary = J::obj(vec![
        ("execution_verified", J::Bool(true)),
        ("minimal", J::Bool(false)),
        ("scope", J::Str("supported target observation in configured runners; no global minimality or OS attestation".into())),
        ("candidate_index", J::U64(candidate_index as u64)),
        ("trials", J::U64(reduction.trials as u64)),
        ("source_steps", J::U64(reduction.replay.source_steps as u64)),
        ("kept_source_steps", indices(&reduction.replay.kept_steps)),
        ("target_replay_step", J::U64(reduction.replay.target_replay_step as u64)),
        ("verification_trials", indices(&evidence)),
        ("single_deletion_fixed_point", J::Bool(reduction.single_deletion_fixed_point)),
    ]);
    fs::write(out.join("result.json"), summary.render_pretty()).map_err(|e| e.to_string())?;
    Ok(reduction)
}

fn indices(values: &[usize]) -> J {
    J::Array(values.iter().map(|v| J::U64(*v as u64)).collect())
}
