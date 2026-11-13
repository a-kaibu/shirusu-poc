//! Compare typed Runner reports at a stable source call, without treating a
//! crash, dry run or failed prerequisite as reproduction. Process launch and
//! isolation are the caller's responsibility.
use crate::reduce::{Trial, TrialOutcome};
use shirusu_test::runner_exec::{ArgValue, OutputValue, RunReportData, Step, StepOutcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetObservation {
    /// BOOL semantics: successful nonzero results are normalized to 1.
    pub succeeded: bool,
    /// Last-error is meaningful here only after failure.
    pub failure_error: Option<u32>,
    pub transferred: Option<u64>,
    /// Only the bytes actually read, never the uninitialized/unused buffer tail.
    pub data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferenceFingerprint {
    pub source_step: usize,
    pub call: String,
    pub baseline: TargetObservation,
    pub candidate: TargetObservation,
}

impl DifferenceFingerprint {
    /// Stable values to retain beside the source step in a probe manifest.
    pub fn to_json(&self) -> shirusu_analysis::JsonValue {
        use shirusu_analysis::JsonValue as J;
        let observation = |o: &TargetObservation| {
            J::obj(vec![
                ("succeeded", J::Bool(o.succeeded)),
                (
                    "failure_error",
                    o.failure_error.map(|n| J::U64(n as u64)).unwrap_or(J::Null),
                ),
                ("transferred", o.transferred.map(J::U64).unwrap_or(J::Null)),
                ("data", o.data.clone().map(J::Str).unwrap_or(J::Null)),
            ])
        };
        J::obj(vec![
            ("source_step", J::U64(self.source_step as u64)),
            ("call", J::Str(self.call.clone())),
            ("baseline", observation(&self.baseline)),
            ("candidate", observation(&self.candidate)),
        ])
    }

    /// Establish a target difference from executions of the original replay.
    /// Callers must additionally match this to the originating Trace candidate
    /// before claiming that the original application difference was reproduced.
    pub fn establish(
        trial: &Trial<'_>,
        baseline: &RunReportData,
        candidate: &RunReportData,
    ) -> Result<Self, TrialOutcome> {
        let (source_step, step, left, right) =
            observations(trial, baseline, candidate).ok_or(TrialOutcome::Inconclusive)?;
        if left == right {
            return Err(TrialOutcome::DifferenceAbsent);
        }
        Ok(Self {
            source_step,
            call: step.call.clone(),
            baseline: left,
            candidate: right,
        })
    }

    pub fn evaluate(
        &self,
        trial: &Trial<'_>,
        baseline: &RunReportData,
        candidate: &RunReportData,
    ) -> TrialOutcome {
        match Self::establish(trial, baseline, candidate) {
            Ok(actual) if actual == *self => TrialOutcome::SameTargetDifference,
            Ok(_) => TrialOutcome::DifferenceAbsent,
            Err(outcome) => outcome,
        }
    }
}

fn observations<'a>(
    trial: &'a Trial<'_>,
    baseline: &RunReportData,
    candidate: &RunReportData,
) -> Option<(usize, &'a Step, TargetObservation, TargetObservation)> {
    let target = trial.target_replay_step;
    let source = *trial.source_steps.get(target)?;
    if trial.source_steps.len() != trial.spec.steps.len()
        || !shape(trial, baseline)
        || !shape(trial, candidate)
        || !baseline.all_ok
        || baseline.steps.iter().any(|s| !complete(s))
        || candidate
            .steps
            .iter()
            .take(target)
            .any(|s| !s.ok || !complete(s))
    {
        return None;
    }
    let step = trial.spec.steps.get(target)?;
    Some((
        source,
        step,
        observe(step, baseline.steps.get(target)?)?,
        observe(step, candidate.steps.get(target)?)?,
    ))
}

fn shape(trial: &Trial<'_>, report: &RunReportData) -> bool {
    report.executed
        && report.spec_name == trial.spec.name
        && report.steps.len() == trial.spec.steps.len()
        && report.all_ok == report.steps.iter().all(|s| s.ok)
        && report
            .steps
            .iter()
            .zip(&trial.spec.steps)
            .enumerate()
            .all(|(i, (result, step))| {
                result.index == i && result.call == step.call && result.ok == result.error.is_none()
            })
}

fn complete(step: &StepOutcome) -> bool {
    step.executed && step.returned.is_some() && step.outputs_truncated.is_empty()
}

pub(crate) fn observe(step: &Step, result: &StepOutcome) -> Option<TargetObservation> {
    if !complete(result)
        || !matches!(
            step.call.as_str(),
            "kernel32!ReadFile" | "kernel32!WriteFile" | "kernel32!CloseHandle"
        )
    {
        return None;
    }
    let succeeded = result.returned? != 0;
    let mut observation = TargetObservation {
        succeeded,
        failure_error: None,
        transferred: None,
        data: None,
    };
    if !succeeded {
        observation.failure_error = Some(result.last_error?);
        return Some(observation);
    }
    if step.call == "kernel32!CloseHandle" {
        return Some(observation);
    }
    let read = step.call == "kernel32!ReadFile";
    let count_name = if read {
        "lpNumberOfBytesRead"
    } else {
        "lpNumberOfBytesWritten"
    };
    let size_name = if read {
        "nNumberOfBytesToRead"
    } else {
        "nNumberOfBytesToWrite"
    };
    let requested = step.args.iter().find_map(|(name, arg)| match arg {
        ArgValue::Int(n) if name == size_name => Some(*n),
        _ => None,
    })?;
    // Reject duplicate output keys rather than accepting whichever arrived first.
    let output = |name: &str| {
        let mut values = result.outputs.iter().filter(|(n, _)| n == name);
        let value = &values.next()?.1;
        if values.next().is_some() {
            None
        } else {
            Some(value)
        }
    };
    let OutputValue::U64(count) = output(count_name)? else {
        return None;
    };
    if *count > requested {
        return None;
    }
    observation.transferred = Some(*count);
    if read {
        let OutputValue::Hex(hex) = output("lpBuffer")? else {
            return None;
        };
        if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let capacity = step.args.iter().find_map(|(name, arg)| match arg {
            ArgValue::Buffer { size, .. } if name == "lpBuffer" => Some(*size),
            _ => None,
        })?;
        if hex.len() != capacity.checked_mul(2)? {
            return None;
        }
        let length = usize::try_from(*count).ok()?.checked_mul(2)?;
        observation.data = Some(hex.get(..length)?.to_ascii_lowercase());
    }
    Some(observation)
}
