use shirusu_emit::{file_io_api_set, Emitter, EventMeta, SessionConfig};
use shirusu_probe::replay::generate_replay;
use shirusu_test::runner_exec::{plan_steps, ArgValue};
use shirusu_trace::schema::{CapturedValue, TypedValue as V};
use shirusu_trace::writer::FinalizationInfo;

fn record(initial_disposition: u32, read_byte: u8) -> shirusu_trace::reader::ReadTrace {
    record_with_unrelated(initial_disposition, read_byte, false)
}

fn record_with_unrelated(
    initial_disposition: u32,
    read_byte: u8,
    unrelated: bool,
) -> shirusu_trace::reader::ReadTrace {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "replay-test"),
    )
    .unwrap();
    let mut tick = 0;
    let mut call = |api, input: Vec<V>, output: Vec<V>| {
        tick += 1;
        let token = em
            .begin_call(
                1,
                api,
                &input
                    .into_iter()
                    .map(CapturedValue::captured)
                    .collect::<Vec<_>>(),
                tick,
                EventMeta::default(),
            )
            .unwrap();
        tick += 1;
        em.end_call(
            token,
            &output
                .into_iter()
                .map(CapturedValue::captured)
                .collect::<Vec<_>>(),
            tick,
            EventMeta::default(),
        )
        .unwrap();
    };
    let path = || V::Str16(r"C:\private\original.bin".encode_utf16().collect());
    for (disposition, access, handle) in [
        (initial_disposition, 0x4000_0000, 100),
        (3, 0x8000_0000, 200),
    ] {
        if unrelated {
            // Reuse the same raw handle as the interesting first lifetime.
            // These separate files must not become dependencies via handle reuse.
            call(
                "kernel32!CreateFileW",
                vec![
                    V::Str16(
                        format!("C:\\private\\unrelated-{disposition}.bin")
                            .encode_utf16()
                            .collect(),
                    ),
                    V::U32(0x4000_0000),
                    V::U32(0),
                    V::U64(0),
                    V::U32(1),
                    V::U32(128),
                    V::U64(0),
                ],
                vec![V::U64(100), V::U32(0)],
            );
            call(
                "kernel32!CloseHandle",
                vec![V::U64(100)],
                vec![V::I32(1), V::U32(0)],
            );
        }
        call(
            "kernel32!CreateFileW",
            vec![
                path(),
                V::U32(access),
                V::U32(0),
                V::U64(0),
                V::U32(disposition),
                V::U32(128),
                V::U64(0),
            ],
            vec![V::U64(handle), V::U32(0)],
        );
        if handle == 100 {
            call(
                "kernel32!WriteFile",
                vec![V::U64(handle), V::Bytes(vec![42]), V::U32(1), V::U64(0)],
                vec![V::I32(1), V::U32(1), V::U32(0)],
            );
        } else {
            call(
                "kernel32!ReadFile",
                vec![V::U64(handle), V::U64(0x1234), V::U32(1), V::U64(0)],
                vec![V::I32(1), V::U32(1), V::Bytes(vec![read_byte]), V::U32(0)],
            );
        }
        call(
            "kernel32!CloseHandle",
            vec![V::U64(handle)],
            vec![V::I32(1), V::U32(0)],
        );
    }
    shirusu_trace::read_trace(&em.finish(FinalizationInfo::default()).unwrap()).unwrap()
}

#[test]
fn serialized_trace_generates_plannable_replay_without_original_paths_or_handles() {
    let trace = record(1, 42);
    let spec = generate_replay(&trace).unwrap();
    let text = shirusu_probe::rules::spec_to_json(&spec);
    assert!(!text.contains("private"));
    assert!(text.contains("valid-handle"));
    let parsed = shirusu_test::TestSpec::parse(&text).unwrap();
    assert_eq!(spec, parsed);
    assert_eq!(plan_steps(&parsed.steps).unwrap().len(), 6);
    assert!(matches!(&parsed.steps[1].args[0].1, ArgValue::Ref(name) if name == "file_0"));
    assert!(shirusu_test::probe_exe::generate_probe_main_rs(&parsed)
        .unwrap()
        .contains("RetExpect::ValidHandle"));
    let right = record(1, 43);
    let diff = shirusu_compare::compare_traces(&trace, &right);
    let bundle = shirusu_probe::build_bundle(
        &trace,
        &right,
        &diff,
        0,
        &shirusu_probe::BundleOptions {
            name: "replay".into(),
            left_label: "left".into(),
            right_label: "right".into(),
        },
    )
    .unwrap();
    assert!(bundle.replay.is_ok());
    assert!(bundle.manifest_json.contains("replay.json"));
    assert!(bundle
        .manifest_json
        .contains("\"execution_verified\": false"));
    assert!(bundle.manifest_json.contains("\"minimal\": false"));
    assert!(bundle.manifest_json.contains("kept_source_steps"));
}

#[test]
fn missing_initial_state_and_inconsistent_read_are_explicitly_rejected() {
    assert!(generate_replay(&record(3, 42))
        .unwrap_err()
        .contains("initial file state"));
    assert!(generate_replay(&record(1, 43))
        .unwrap_err()
        .contains("earlier writes"));
    let mut trace = record(1, 42);
    trace.batches[0].events[1].kind = 8;
    assert!(generate_replay(&trace).is_err());
}

// Windows CI executes the generated standalone probe in an isolated directory.
// A second run must fail at CREATE_NEW and preserve the existing file.
#[cfg(windows)]
#[test]
fn generated_replay_executes_and_refuses_to_overwrite() {
    let dir = std::env::temp_dir().join(format!("shirusu-replay-e2e-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let left = record_with_unrelated(1, 42, true);
    let right = record_with_unrelated(1, 43, true);
    let diff = shirusu_compare::compare_traces(&left, &right);
    let candidate = diff
        .candidates
        .iter()
        .find(|c| {
            c.left_event
                .as_ref()
                .is_some_and(|e| e.api == "kernel32!ReadFile")
        })
        .unwrap();
    let spec = shirusu_probe::replay::generate_candidate_replay(&left, candidate)
        .unwrap()
        .spec;
    let target = if cfg!(target_arch = "x86") {
        "i686-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    };
    let exe = dir.join("replay.exe");
    shirusu_test::probe_exe::build_probe_exe(&spec, target, &exe).unwrap();
    let run = || {
        std::process::Command::new(&exe)
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    let report =
        shirusu_test::parse_runner_report_json(std::str::from_utf8(&first.stdout).unwrap())
            .unwrap();
    assert!(report.executed && report.all_ok);
    assert_eq!(report.spec_name, spec.name);
    std::fs::write(dir.join("shirusu-replay-1.bin"), b"keep").unwrap();
    assert!(!run().status.success());
    assert_eq!(
        std::fs::read(dir.join("shirusu-replay-1.bin")).unwrap(),
        b"keep"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn explicit_overlapped_offset_is_not_silently_replayed_at_current_position() {
    use shirusu_trace::{
        compact::{decode_values, encode_values},
        schema::Ty,
    };
    let mut trace = record(1, 42);
    let write = &mut trace.batches[0].events[2];
    let types = [Ty::U64, Ty::Bytes, Ty::U32, Ty::U64];
    let mut values = decode_values(&types, write.args.as_ref().unwrap()).unwrap();
    values[3].value = V::U64(0x1234);
    write.args = Some(encode_values(&types, &values).unwrap());
    assert!(generate_replay(&trace).unwrap_err().contains("OVERLAPPED"));
}

#[test]
fn coverage_warning_is_preserved_but_recorded_event_loss_blocks_replay() {
    let mut trace = record(1, 42);
    trace.finalization.as_mut().unwrap().capture_coverage = 1;
    assert!(generate_replay(&trace).is_ok());
    trace.finalization.as_mut().unwrap().event_integrity = 1;
    assert!(generate_replay(&trace).is_err());
    trace.finalization.as_mut().unwrap().event_integrity = 0;
    trace.finalization.as_mut().unwrap().semantic_completeness = 1;
    assert!(generate_replay(&trace).is_err());
}

#[test]
fn candidate_slice_retains_reopened_file_history_and_excludes_reused_handles() {
    let left = record_with_unrelated(1, 42, true);
    let right = record_with_unrelated(1, 43, true);
    let diff = shirusu_compare::compare_traces(&left, &right);
    let candidate = diff
        .candidates
        .iter()
        .find(|c| {
            c.left_event
                .as_ref()
                .is_some_and(|e| e.api == "kernel32!ReadFile")
        })
        .unwrap();
    let slice = shirusu_probe::replay::generate_candidate_replay(&left, candidate).unwrap();
    assert_eq!(slice.source_steps, 10);
    assert_eq!(slice.kept_steps, [2, 3, 4, 7, 8, 9]);
    assert_eq!(slice.target_source_step, 8);
    assert_eq!(slice.target_replay_step, 4);
    assert_eq!(slice.spec.steps.len(), 6);
    let serialized = slice.spec.to_json().render_pretty();
    assert!(!serialized.contains("private"));
    assert!(!serialized.contains("shirusu-replay-0.bin"));
    assert!(!serialized.contains("shirusu-replay-2.bin"));
    assert!(serialized.contains("shirusu-replay-1.bin"));
    assert_eq!(
        shirusu_test::TestSpec::parse(&serialized).unwrap(),
        slice.spec
    );
    plan_steps(&slice.spec.steps).unwrap();
    let mut no_baseline = candidate.clone();
    no_baseline.left_event = None;
    assert!(
        shirusu_probe::replay::generate_candidate_replay(&left, &no_baseline)
            .unwrap_err()
            .contains("no baseline event")
    );
    assert!(shirusu_probe::replay::generate_candidate_replay(
        &record_with_unrelated(3, 42, true),
        candidate
    )
    .is_err());
}

fn reduction_fixture() -> shirusu_probe::replay::ReplaySlice {
    let mut spec = generate_replay(&record(1, 42)).unwrap();
    spec.steps.insert(2, spec.steps[1].clone());
    // Read one byte from a two-byte buffer, leaving a semantically unused tail.
    for (name, arg) in &mut spec.steps[5].args {
        if name == "nNumberOfBytesToRead" {
            *arg = ArgValue::Int(2);
        }
        if name == "lpBuffer" {
            *arg = ArgValue::Buffer {
                size: 2,
                fill: vec![],
            };
        }
    }
    shirusu_probe::replay::ReplaySlice {
        spec,
        source_steps: 7,
        kept_steps: (0..7).collect(),
        target_source_step: 5,
        target_replay_step: 5,
    }
}

#[test]
fn reduction_preserves_target_creation_cleanup_and_required_write() {
    use shirusu_probe::reduce::{reduce_file_io, TrialOutcome::*};
    let reduced = reduce_file_io(reduction_fixture(), 30, |trial| {
        assert_eq!(trial.source_steps[trial.target_replay_step], 5);
        assert_eq!(
            trial.spec.steps[trial.target_replay_step].call,
            "kernel32!ReadFile"
        );
        for fixed in [0, 3, 4, 5, 6] {
            assert!(trial.source_steps.contains(&fixed));
        }
        Ok::<_, ()>(if trial.source_steps.contains(&1) {
            SameTargetDifference
        } else {
            DifferenceAbsent
        })
    })
    .unwrap();
    assert_eq!(reduced.replay.kept_steps, [0, 1, 3, 4, 5, 6]);
    assert_eq!(reduced.replay.target_replay_step, 4);
    assert!(reduced.single_deletion_fixed_point);
    assert!(reduced.trials <= 30);
}

#[test]
fn reduction_refuses_unconfirmed_baselines_and_inconclusive_or_flaky_deletions() {
    use shirusu_probe::reduce::{reduce_file_io, ReductionError, TrialOutcome::*};
    let error = reduce_file_io(reduction_fixture(), 20, |_| Ok::<_, ()>(Inconclusive)).unwrap_err();
    assert_eq!(error, ReductionError::BaselineNotReproduced);
    let mut calls = 0;
    let unchanged = reduce_file_io(reduction_fixture(), 20, |_| {
        calls += 1;
        // Original twice, then a flaky deletion once, never twice.
        Ok::<_, ()>(if calls <= 3 {
            SameTargetDifference
        } else {
            Inconclusive
        })
    })
    .unwrap();
    assert_eq!(unchanged.replay.kept_steps, [0, 1, 2, 3, 4, 5, 6]);
    let limited = reduce_file_io(reduction_fixture(), 2, |_| {
        Ok::<_, ()>(SameTargetDifference)
    })
    .unwrap();
    assert_eq!(limited.trials, 2);
    assert!(!limited.single_deletion_fixed_point);
    assert_eq!(limited.replay.kept_steps.len(), 7);
    let error = reduce_file_io(reduction_fixture(), 20, |_| Err("runner crashed")).unwrap_err();
    assert_eq!(error, ReductionError::Oracle("runner crashed"));
}

#[test]
fn reduction_checks_provenance_before_running_an_oracle() {
    let mut input = reduction_fixture();
    input.target_source_step = 99;
    assert!(
        shirusu_probe::reduce::reduce_file_io(input, 10, |_| -> Result<_, ()> {
            panic!("invalid input must not execute")
        })
        .is_err()
    );
}

#[test]
fn reduction_revisits_rejected_deletions_after_dependencies_change() {
    use shirusu_probe::reduce::{reduce_file_io, TrialOutcome::*};
    let result = reduce_file_io(reduction_fixture(), 30, |trial| {
        // Removing step 2 alone changes the target, but after step 1 is removed
        // it becomes redundant. A single pass cannot discover that reduction.
        Ok::<_, ()>(
            if trial.source_steps.contains(&1) && !trial.source_steps.contains(&2) {
                DifferenceAbsent
            } else {
                SameTargetDifference
            },
        )
    })
    .unwrap();
    assert_eq!(result.replay.kept_steps, [0, 3, 4, 5, 6]);
    assert!(result.single_deletion_fixed_point);
}

fn oracle_reports(
    trial: &shirusu_probe::reduce::Trial<'_>,
) -> (
    shirusu_test::runner_exec::RunReportData,
    shirusu_test::runner_exec::RunReportData,
) {
    use shirusu_test::runner_exec::{dry_run_report, OutputValue};
    let mut baseline = dry_run_report(&trial.spec.name, &plan_steps(&trial.spec.steps).unwrap());
    baseline.executed = true;
    for step in &mut baseline.steps {
        step.executed = true;
        step.returned = Some(1);
        step.last_error = Some(0);
    }
    baseline.steps[trial.target_replay_step].outputs = vec![
        ("lpNumberOfBytesRead".into(), OutputValue::U64(1)),
        ("lpBuffer".into(), OutputValue::Hex("2a00".into())),
    ];
    let mut candidate = baseline.clone();
    candidate.all_ok = false;
    let target = &mut candidate.steps[trial.target_replay_step];
    target.ok = false;
    target.error = Some("output expectation mismatch".into());
    target.outputs[1].1 = OutputValue::Hex("2b00".into());
    (baseline, candidate)
}

#[test]
fn report_oracle_pins_target_values_and_rejects_unrelated_failures() {
    use shirusu_probe::{
        oracle::DifferenceFingerprint,
        reduce::{Trial, TrialOutcome::*},
    };
    use shirusu_test::runner_exec::OutputValue;
    let replay = reduction_fixture();
    let trial = Trial {
        spec: &replay.spec,
        source_steps: &replay.kept_steps,
        target_replay_step: 5,
    };
    let (baseline, candidate) = oracle_reports(&trial);
    let fingerprint = DifferenceFingerprint::establish(&trial, &baseline, &candidate).unwrap();
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &candidate),
        SameTargetDifference
    );
    let mut changed = candidate.clone();
    changed.steps[5].outputs[1].1 = OutputValue::Hex("2c00".into());
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        DifferenceAbsent
    );
    changed = candidate.clone();
    changed.steps[0].ok = false;
    changed.steps[0].error = Some("CREATE_NEW failed".into());
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    changed = candidate.clone();
    changed.steps[5].executed = false;
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    changed = candidate.clone();
    changed.steps[5].outputs_truncated.push("lpBuffer".into());
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    changed = candidate.clone();
    let duplicate = changed.steps[5].outputs[0].clone();
    changed.steps[5].outputs.push(duplicate);
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    let mut dry = baseline.clone();
    dry.executed = false;
    assert_eq!(fingerprint.evaluate(&trial, &dry, &candidate), Inconclusive);
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &baseline),
        DifferenceAbsent
    );
    changed = candidate.clone();
    changed.steps[5].outputs[0].1 = OutputValue::U64(3);
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    changed = candidate.clone();
    changed.steps.pop();
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        Inconclusive
    );
    changed = candidate.clone();
    changed.steps[5].returned = Some(0);
    changed.steps[5].last_error = Some(5);
    let failed = DifferenceFingerprint::establish(&trial, &baseline, &changed).unwrap();
    assert_eq!(failed.candidate.failure_error, Some(5));
    assert_eq!(failed.candidate.data, None);
    changed.steps[5].last_error = Some(6);
    assert_eq!(
        failed.evaluate(&trial, &baseline, &changed),
        DifferenceAbsent
    );
    // Successful last-error and the unused buffer tail are not semantic data.
    changed = candidate.clone();
    changed.steps[5].last_error = Some(999);
    changed.steps[5].outputs[1].1 = OutputValue::Hex("2Bff".into());
    assert_eq!(
        fingerprint.evaluate(&trial, &baseline, &changed),
        SameTargetDifference
    );
}

#[test]
fn typed_runner_oracle_drives_reduction_with_stable_source_identity() {
    use shirusu_probe::{
        oracle::DifferenceFingerprint,
        reduce::{reduce_file_io, Trial},
    };
    let replay = reduction_fixture();
    let trial = Trial {
        spec: &replay.spec,
        source_steps: &replay.kept_steps,
        target_replay_step: 5,
    };
    let (baseline, candidate) = oracle_reports(&trial);
    let fingerprint = DifferenceFingerprint::establish(&trial, &baseline, &candidate).unwrap();
    let result = reduce_file_io(replay, 30, |trial| {
        let (mut baseline, candidate) = oracle_reports(&trial);
        if !trial.source_steps.contains(&1) {
            baseline.all_ok = false;
            baseline.steps[trial.target_replay_step].ok = false;
            baseline.steps[trial.target_replay_step].error = Some("required write missing".into());
        }
        Ok::<_, ()>(fingerprint.evaluate(&trial, &baseline, &candidate))
    })
    .unwrap();
    assert_eq!(result.replay.kept_steps, [0, 1, 3, 4, 5, 6]);
}

#[cfg(windows)]
#[test]
fn native_runner_pair_does_not_invent_a_difference_between_windows_runs() {
    use shirusu_probe::{
        oracle::DifferenceFingerprint,
        reduce::{Trial, TrialOutcome},
    };
    use shirusu_test::runner_exec::execute_planned;
    let spec = generate_replay(&record(1, 42)).unwrap();
    let root = std::env::temp_dir().join(format!(
        "shirusu-oracle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let execute = |side: &str| {
        let dir = root.join(side);
        std::fs::create_dir(&dir).unwrap();
        let mut isolated = spec.clone();
        for step in &mut isolated.steps {
            for (name, arg) in &mut step.args {
                if name == "lpFileName" {
                    if let ArgValue::Text(path) = arg {
                        *path = dir.join(&*path).to_str().unwrap().to_owned();
                    }
                }
            }
        }
        let report = execute_planned(&isolated.name, &plan_steps(&isolated.steps).unwrap());
        shirusu_test::parse_runner_report_json(&shirusu_test::runner_exec::report_to_json(&report))
            .unwrap()
    };
    let left = execute("left");
    let right = execute("right");
    assert!(left.all_ok && right.all_ok, "{left:?} / {right:?}");
    let source_steps: Vec<_> = (0..spec.steps.len()).collect();
    let trial = Trial {
        spec: &spec,
        source_steps: &source_steps,
        target_replay_step: 4,
    };
    assert_eq!(
        DifferenceFingerprint::establish(&trial, &left, &right),
        Err(TrialOutcome::DifferenceAbsent)
    );
    std::fs::remove_dir_all(root).unwrap();
}
