//! Bounded, oracle-guided reduction of a file dependency replay.
//!
//! The oracle must execute both environments in fresh isolated directories and
//! confirm the *same target difference*, not merely any failure/nonzero exit.
//! This module does not launch a process or claim a global minimum. It removes
//! non-target ReadFile/WriteFile steps individually and in bounded groups;
//! creation, stored results, the target and cleanup remain.
use crate::replay::ReplaySlice;
use shirusu_test::TestSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialOutcome {
    SameTargetDifference,
    DifferenceAbsent,
    /// Timeout, capture loss, unsupported operation or invalid prerequisites.
    Inconclusive,
}

/// Source positions remain stable even when the replay positions change.
pub struct Trial<'a> {
    pub spec: &'a TestSpec,
    pub source_steps: &'a [usize],
    pub target_replay_step: usize,
}

#[derive(Debug)]
pub struct Reduction {
    pub replay: ReplaySlice,
    pub trials: usize,
    /// True only when a complete pass found no further accepted single deletion.
    /// This is not a proof of global minimality or absence of flaky behavior.
    pub single_deletion_fixed_point: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReductionError<E> {
    InvalidInput(&'static str),
    BaselineNotReproduced,
    Oracle(E),
}

/// Require two consecutive confirmations before accepting either the original
/// replay or a deletion. An inconclusive trial never authorizes a deletion.
/// The budget counts oracle invocations, including original replay validation.
/// A caller can persist the returned replay but must retain the oracle evidence
/// separately; this result is not itself proof about a particular Windows build.
pub fn reduce_file_io<E>(
    mut replay: ReplaySlice,
    max_trials: usize,
    mut oracle: impl FnMut(Trial<'_>) -> Result<TrialOutcome, E>,
) -> Result<Reduction, ReductionError<E>> {
    if max_trials < 2 {
        return Err(ReductionError::InvalidInput(
            "at least two trials are required",
        ));
    }
    if replay.spec.steps.len() != replay.kept_steps.len()
        || replay.kept_steps.get(replay.target_replay_step) != Some(&replay.target_source_step)
        || replay.kept_steps.windows(2).any(|w| w[0] >= w[1])
        || replay.kept_steps.iter().any(|i| *i >= replay.source_steps)
    {
        return Err(ReductionError::InvalidInput("invalid replay provenance"));
    }
    if replay.spec.steps.iter().any(|s| {
        !matches!(
            s.call.as_str(),
            "kernel32!CreateFileW"
                | "kernel32!ReadFile"
                | "kernel32!WriteFile"
                | "kernel32!CloseHandle"
        )
    }) || shirusu_test::runner_exec::plan_steps(&replay.spec.steps).is_err()
    {
        return Err(ReductionError::InvalidInput(
            "unsupported or invalid file replay",
        ));
    }
    let mut trials = 0;
    for _ in 0..2 {
        trials += 1;
        if oracle(Trial {
            spec: &replay.spec,
            source_steps: &replay.kept_steps,
            target_replay_step: replay.target_replay_step,
        })
        .map_err(ReductionError::Oracle)?
            != TrialOutcome::SameTargetDifference
        {
            return Err(ReductionError::BaselineNotReproduced);
        }
    }
    loop {
        let mut changed = false;
        for i in (0..replay.spec.steps.len()).rev() {
            if i == replay.target_replay_step
                || replay.spec.steps[i].store.is_some()
                || !matches!(
                    replay.spec.steps[i].call.as_str(),
                    "kernel32!ReadFile" | "kernel32!WriteFile"
                )
            {
                continue;
            }
            if max_trials - trials < 2 {
                return Ok(Reduction {
                    replay,
                    trials,
                    single_deletion_fixed_point: false,
                });
            }
            let mut spec = replay.spec.clone();
            spec.steps.remove(i);
            let mut kept = replay.kept_steps.clone();
            kept.remove(i);
            let target = replay.target_replay_step - usize::from(i < replay.target_replay_step);
            let mut accepted = true;
            for _ in 0..2 {
                trials += 1;
                if oracle(Trial {
                    spec: &spec,
                    source_steps: &kept,
                    target_replay_step: target,
                })
                .map_err(ReductionError::Oracle)?
                    != TrialOutcome::SameTargetDifference
                {
                    accepted = false;
                    break;
                }
            }
            if accepted {
                replay.spec = spec;
                replay.kept_steps = kept;
                replay.target_replay_step = target;
                changed = true;
            }
        }
        if !changed {
            // A single-deletion fixed point can still contain coupled redundant
            // operations. Try progressively smaller windows of removable
            // steps; the execution oracle, not static independence, decides.
            let eligible: Vec<usize> = replay
                .spec
                .steps
                .iter()
                .enumerate()
                .filter(|(i, step)| {
                    *i != replay.target_replay_step
                        && step.store.is_none()
                        && matches!(
                            step.call.as_str(),
                            "kernel32!ReadFile" | "kernel32!WriteFile"
                        )
                })
                .map(|(i, _)| i)
                .collect();
            let mut width = eligible.len();
            'groups: while width >= 2 {
                for removed in eligible.windows(width) {
                    if max_trials - trials < 2 {
                        return Ok(Reduction {
                            replay,
                            trials,
                            single_deletion_fixed_point: true,
                        });
                    }
                    let mut spec = replay.spec.clone();
                    spec.steps = replay
                        .spec
                        .steps
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| removed.binary_search(i).is_err())
                        .map(|(_, step)| step.clone())
                        .collect();
                    let kept: Vec<_> = replay
                        .kept_steps
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| removed.binary_search(i).is_err())
                        .map(|(_, source)| *source)
                        .collect();
                    let target = replay.target_replay_step
                        - removed
                            .iter()
                            .filter(|&&i| i < replay.target_replay_step)
                            .count();
                    let mut accepted = true;
                    for _ in 0..2 {
                        trials += 1;
                        if oracle(Trial {
                            spec: &spec,
                            source_steps: &kept,
                            target_replay_step: target,
                        })
                        .map_err(ReductionError::Oracle)?
                            != TrialOutcome::SameTargetDifference
                        {
                            accepted = false;
                            break;
                        }
                    }
                    if accepted {
                        replay.spec = spec;
                        replay.kept_steps = kept;
                        replay.target_replay_step = target;
                        changed = true;
                        break 'groups;
                    }
                }
                width = width.div_ceil(2);
            }
            if !changed {
                return Ok(Reduction {
                    replay,
                    trials,
                    single_deletion_fixed_point: true,
                });
            }
        }
        // Revisit earlier rejected removals after later changes. This matters for
        // file cursor and content dependencies; deletion predicates need not be monotone.
    }
}
