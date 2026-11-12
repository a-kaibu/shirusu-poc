use shirusu_emit::{file_io_api_set, Emitter, EventMeta, SessionConfig};
use shirusu_probe::replay::generate_replay;
use shirusu_test::runner_exec::{plan_steps, ArgValue};
use shirusu_trace::schema::{CapturedValue, TypedValue as V};
use shirusu_trace::writer::FinalizationInfo;

fn record(initial_disposition: u32, read_byte: u8) -> shirusu_trace::reader::ReadTrace {
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
    let spec = generate_replay(&record(1, 42)).unwrap();
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
    std::fs::write(dir.join("shirusu-replay-0.bin"), b"keep").unwrap();
    assert!(!run().status.success());
    assert_eq!(
        std::fs::read(dir.join("shirusu-replay-0.bin")).unwrap(),
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
