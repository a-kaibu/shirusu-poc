//! Serialized Trace -> Reader -> compare -> trimmed Trace -> Reader -> compare.
//! Drain permutations are deterministic schedules, independent of wall time.
#[path = "../../shirusu-compare/tests/common/mod.rs"]
mod common;
use common::{Builder, Env};
use shirusu_compare::{compare_traces, NormTrace};
use shirusu_trace::{
    compact::{decode_values, encode_values},
    reader::ReadTrace,
    schema::{Ty, TypedValue},
    writer::FinalizationInfo,
    TraceWriter,
};
fn serialized(trace: &ReadTrace) -> ReadTrace {
    let mut w = TraceWriter::new(Vec::new(), trace.environment.clone().unwrap()).unwrap();
    for s in &trace.schemas {
        w.register_schema(s.clone()).unwrap();
    }
    for b in &trace.batches {
        w.write_batch(b).unwrap();
    }
    shirusu_trace::read_trace(&w.finish(FinalizationInfo::default()).unwrap()).unwrap()
}

#[test]
fn trimming_does_not_turn_unclean_source_into_complete_evidence() {
    let make = |path| {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, path);
        b.finish(FinalizationInfo::default(), &[])
    };
    let mut left = make("a");
    let right = make("b");
    let diff = compare_traces(&left, &right);
    left.finalized_cleanly = false;
    let trimmed =
        shirusu_probe::trim::trim_trace(&left, &diff.candidates[0], "left", "unclean").unwrap();
    let trace = shirusu_trace::read_trace(&trimmed.bytes).unwrap();
    assert_eq!(
        trace.finalization.unwrap().event_integrity,
        shirusu_trace::proto::integrity_level::DEGRADED
    );
}
#[test]
fn utf16_distinct_code_units_survive_compare() {
    let make = |unit| {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        let types = [Ty::Str16, Ty::U32, Ty::U64];
        let mut values = decode_values(&types, b.events[0].args.as_ref().unwrap()).unwrap();
        values[0].value = TypedValue::Str16(vec![unit]);
        b.events[0].args = Some(encode_values(&types, &values).unwrap());
        b.finish(FinalizationInfo::default(), &[])
    };
    for unit in [0xd801, 0xdc00, 0xfffd] {
        let left = make(0xd800);
        let right = make(unit);
        let diff = compare_traces(&left, &right);
        assert!(!diff.is_identical());
        let rule = shirusu_probe::generate_rules(&left, &right, &diff.candidates[0])
            .spec
            .unwrap();
        let parsed =
            shirusu_test::TestSpec::parse(&shirusu_probe::rules::spec_to_json(&rule)).unwrap();
        assert!(shirusu_test::evaluate(&parsed, &left).all_passed());
        assert!(!shirusu_test::evaluate(&parsed, &right).all_passed());
    }
}
#[test]
fn process_handle_namespaces_are_independent() {
    let mut a = Builder::new(Env::default());
    a.create_file(1, 0, "a");
    a.read_file(2, 0, 1, 1, b"a", true, 0);
    let mut t = a.finish(FinalizationInfo::default(), &[]);
    let mut b = Builder::new(Env {
        process_id: 8,
        ts_base: 1005,
        ..Env::default()
    });
    b.create_file(1, 0, "b");
    let b = b.finish(FinalizationInfo::default(), &[]);
    let mut read = t.batches[0].clone();
    read.events = read.events.split_off(2);
    t.batches[0].events.truncate(2);
    t.batches.push(b.batches[0].clone());
    t.batches.push(read);
    let n = NormTrace::build(&serialized(&t));
    let read = n
        .calls
        .iter()
        .find(|c| c.api.ends_with("ReadFile"))
        .unwrap();
    assert_eq!(read.referenced.len(), 1);
    assert_eq!(read.referenced[0].ordinal, 0);
}
#[test]
fn drain_permutations_preserve_cross_thread_objects_and_completions() {
    for global in [false, true] {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        b.read_file_async(2, 0, 1, 1, b"a");
        let mut t = b.finish(FinalizationInfo::default(), &[]);
        let original = t.batches.remove(0);
        for (thread, range) in [(10, 0..2), (20, 2..4), (30, 4..5)] {
            let mut batch = original.clone();
            batch.events = original.events[range.clone()].to_vec();
            if global {
                for (offset, e) in batch.events.iter_mut().enumerate() {
                    e.global_order = Some((range.start + offset + 1) as u64);
                }
            }
            batch.thread_id = thread;
            t.batches.push(batch);
        }
        let expected = serialized(&t);
        // Rotate/reverse every possible chunk start: causal order is unchanged.
        for shift in 0..t.batches.len() {
            t.batches.rotate_left(1);
            if shift % 2 == 0 {
                t.batches.reverse();
            }
            let actual = serialized(&t);
            assert!(
                compare_traces(&expected, &actual).is_identical(),
                "global={global} shift={shift}"
            );
            let n = NormTrace::build(&actual);
            let read = n
                .calls
                .iter()
                .find(|c| c.api.ends_with("ReadFile"))
                .unwrap();
            assert_eq!(read.referenced.len(), 1);
            assert!(read.completed.is_some());
        }
    }
}
#[test]
fn async_difference_survives_probe_trim_on_another_thread() {
    let make = |byte| {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        b.read_file_async(2, 0, 1, 1, &[byte]);
        let mut t = b.finish(FinalizationInfo::default(), &[]);
        let mut completion = t.batches[0].clone();
        completion.events = vec![t.batches[0].events.pop().unwrap()];
        completion.thread_id = 99;
        t.batches.push(completion);
        serialized(&t)
    };
    let left = make(1);
    let right = make(2);
    let diff = compare_traces(&left, &right);
    assert_eq!(diff.candidates.len(), 1);
    let rule = shirusu_probe::generate_rules(&left, &right, &diff.candidates[0])
        .spec
        .unwrap();
    let parsed = shirusu_test::TestSpec::parse(&shirusu_probe::rules::spec_to_json(&rule)).unwrap();
    assert!(shirusu_test::evaluate(&parsed, &left).all_passed());
    assert!(!shirusu_test::evaluate(&parsed, &right).all_passed());
    let trim = |t, side| {
        let out =
            shirusu_probe::trim::trim_trace(t, &diff.candidates[0], side, "regression").unwrap();
        shirusu_trace::read_trace(&out.bytes).unwrap()
    };
    let l = trim(&left, "left");
    let r = trim(&right, "right");
    assert!(l
        .batches
        .iter()
        .any(|b| b.thread_id == 99 && b.events.iter().any(|e| e.kind == 8)));
    assert!(!compare_traces(&l, &r).is_identical());
}

#[test]
fn failed_or_unfinished_close_does_not_satisfy_lifecycle_rule() {
    let rule = shirusu_test::TestSpec::parse(
        r#"{"rules":[{"type":"object-closed","created_by":"kernel32!CreateFileW"}]}"#,
    )
    .unwrap();
    for completed in [false, true] {
        let mut b = Builder::new(Env::default());
        b.create_file(1, 0, "x");
        b.close_handle(2, 0);
        if completed {
            let types = [Ty::I32, Ty::U32];
            let event = b.events.last_mut().unwrap();
            let mut values = decode_values(&types, event.args.as_ref().unwrap()).unwrap();
            values[0].value = TypedValue::I32(0);
            event.args = Some(encode_values(&types, &values).unwrap());
        } else {
            b.events.pop();
        }
        let trace = b.finish(FinalizationInfo::default(), &[]);
        assert!(!shirusu_test::evaluate(&rule, &trace).all_passed());
    }
}
