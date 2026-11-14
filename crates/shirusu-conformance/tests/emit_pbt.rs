//! エミッタキット（shirusu-emit）が書いた Trace は、任意の呼び出し列で
//! 適合性チェッカの 11 項目すべてに合格する（キットが約束する規約と
//! チェッカが検査する規約の差分検査）。入れ子の呼び出し、複数スレッド、
//! 途中の flush、放棄（abandon）、Loss Record、Inline / Blob の Payload を
//! 混ぜる。
//!
//! さらに、合格した Trace を 1 バイトでも壊すと、Reader が報告した損傷が
//! clean-scan の不合格として必ず現れる（損傷の見落としがない）。

use proptest::prelude::*;
use shirusu_conformance::check::check_trace;
use shirusu_emit::{
    file_io_api_set, ApiSet, CallToken, Emitter, EventMeta, PayloadData, SessionConfig,
};
use shirusu_trace::reader::RecoveryIssue;
use shirusu_trace::schema::{CapturedValue, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;

#[derive(Debug, Clone)]
enum Op {
    Begin {
        thread: u64,
        api: usize,
        seed: u64,
        payload: u8,
    },
    End {
        thread: u64,
        seed: u64,
    },
    Abandon {
        thread: u64,
    },
    Flush {
        thread: u64,
    },
    Loss(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (1u64..4, any::<usize>(), any::<u64>(), 0u8..3)
            .prop_map(|(thread, api, seed, payload)| Op::Begin { thread, api, seed, payload }),
        4 => (1u64..4, any::<u64>()).prop_map(|(thread, seed)| Op::End { thread, seed }),
        1 => (1u64..4).prop_map(|thread| Op::Abandon { thread }),
        1 => (1u64..4).prop_map(|thread| Op::Flush { thread }),
        1 => (1u64..50).prop_map(Op::Loss),
    ]
}

fn value(ty: Ty, seed: u64) -> CapturedValue {
    let v = match ty {
        Ty::I32 => TypedValue::I32(seed as i32),
        Ty::I64 => TypedValue::I64(seed as i64),
        Ty::U32 => TypedValue::U32(seed as u32),
        Ty::U64 => TypedValue::U64(seed),
        Ty::F32 => TypedValue::F32Bits(seed as u32),
        Ty::F64 => TypedValue::F64Bits(seed),
        Ty::Bool => TypedValue::Bool(seed & 1 == 1),
        Ty::Str => TypedValue::Str(format!("s{}", seed % 97)),
        Ty::Str16 => TypedValue::Str16(format!("C:\\f{}", seed % 89).encode_utf16().collect()),
        Ty::Bytes => TypedValue::Bytes(seed.to_le_bytes()[..(seed % 9) as usize].to_vec()),
        Ty::Ptr32 => TypedValue::Ptr32(seed as u32),
        Ty::Ptr64 => TypedValue::Ptr64(seed),
        Ty::BlobRef => unreachable!("file I/O set has no BlobRef field"),
    };
    CapturedValue::captured(v)
}

fn values(
    fields: &[(
        String,
        Ty,
        shirusu_trace::schema::ValueKind,
        shirusu_trace::schema::CaptureTiming,
    )],
    seed: u64,
) -> Vec<CapturedValue> {
    fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            value(
                f.1,
                seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(i as u64),
            )
        })
        .collect()
}

fn names(set: &ApiSet) -> Vec<String> {
    (1..=1000u32)
        .filter_map(|id| set.spec(id).map(|s| s.name.clone()))
        .collect()
}

fn emit(ops: &[Op]) -> Vec<u8> {
    let set = file_io_api_set();
    let apis = names(&set);
    assert!(!apis.is_empty());
    let mut em = Emitter::new(Vec::new(), set, SessionConfig::new(11, "emit-pbt 0.1")).unwrap();
    let mut open: std::collections::HashMap<u64, Vec<(CallToken, String)>> = Default::default();
    let mut ts = 1u64;
    for op in ops {
        ts += 1;
        match op {
            Op::Begin {
                thread,
                api,
                seed,
                payload,
            } => {
                let name = &apis[api % apis.len()];
                let spec = em.api_set().spec_by_name(name).unwrap().clone();
                let meta = EventMeta {
                    payload: match payload {
                        0 => PayloadData::None,
                        1 => PayloadData::Inline(seed.to_le_bytes().to_vec()),
                        _ => PayloadData::Blob((seed % 5).to_le_bytes().to_vec()),
                    },
                    ..Default::default()
                };
                let token = em
                    .begin_call(*thread, name, &values(&spec.enter_fields, *seed), ts, meta)
                    .unwrap();
                open.entry(*thread).or_default().push((token, name.clone()));
            }
            Op::End { thread, seed } => {
                let Some((token, name)) = open.get_mut(thread).and_then(|v| v.pop()) else {
                    continue;
                };
                let spec = em.api_set().spec_by_name(&name).unwrap().clone();
                em.end_call(
                    token,
                    &values(&spec.leave_fields, *seed),
                    ts,
                    EventMeta::default(),
                )
                .unwrap();
            }
            Op::Abandon { thread } => {
                // 契約（Emitter::abandon_call）: 痕跡は呼び出し側が
                // UNKNOWN_TERMINATION の Loss Record として残す。
                if let Some((token, _)) = open.get_mut(thread).and_then(|v| v.pop()) {
                    em.abandon_call(token).unwrap();
                    let process_id = em.session_config().process_id;
                    em.write_loss_records(&[shirusu_trace::proto::LossRecord {
                        kind: shirusu_trace::proto::loss_kind::UNKNOWN_TERMINATION,
                        call_id: token.call_id,
                        thread_id: token.thread_id,
                        process_id,
                        ..Default::default()
                    }])
                    .unwrap();
                }
            }
            Op::Flush { thread } => em.flush_thread(*thread).unwrap(),
            Op::Loss(n) => em
                .write_loss_records(&[shirusu_trace::proto::LossRecord {
                    kind: 1,
                    count: *n,
                    ..Default::default()
                }])
                .unwrap(),
        }
    }
    // 開いたままの呼び出しは内側から閉じる。
    for calls in open.values_mut() {
        while let Some((token, name)) = calls.pop() {
            ts += 1;
            let spec = em.api_set().spec_by_name(&name).unwrap().clone();
            em.end_call(
                token,
                &values(&spec.leave_fields, ts),
                ts,
                EventMeta::default(),
            )
            .unwrap();
        }
    }
    // 完全性の 3 指標は呼び出し側が正直に決める契約（Emitter::finish）。
    let lossy = ops
        .iter()
        .any(|o| matches!(o, Op::Loss(_) | Op::Abandon { .. }));
    em.finish(FinalizationInfo {
        event_integrity: if lossy { 1 } else { 0 },
        ..Default::default()
    })
    .unwrap()
}

fn damaging(issue: &RecoveryIssue) -> bool {
    !matches!(
        issue,
        RecoveryIssue::Resync { .. } | RecoveryIssue::MissingBlob { .. }
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("SHIRUSU_PBT_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(192)
    ))]

    #[test]
    fn emitted_traces_are_conformant(ops in proptest::collection::vec(op(), 0..60)) {
        let bytes = emit(&ops);
        let trace = shirusu_trace::read_trace(&bytes).unwrap();
        let report = check_trace(&trace);
        prop_assert!(
            report.conformant(),
            "{}",
            report.render_human("emitted")
        );
    }

    #[test]
    fn damage_reported_by_the_reader_fails_clean_scan(
        ops in proptest::collection::vec(op(), 1..30),
        at in any::<usize>(),
        mask in 1u8..=255,
    ) {
        let mut bytes = emit(&ops);
        let i = at % bytes.len();
        bytes[i] ^= mask;
        let Ok(trace) = shirusu_trace::read_trace(&bytes) else { return Ok(()) };
        let report = check_trace(&trace);
        let clean = report.finding("clean-scan").unwrap();
        let damaged = trace.issues.iter().any(damaging);
        prop_assert_eq!(
            clean.status == shirusu_conformance::check::CheckStatus::Fail,
            damaged,
            "{:?} / {:?}", clean, trace.issues
        );
        if damaged {
            prop_assert!(!report.conformant());
        }
    }
}

/// 規約どおり UNKNOWN_TERMINATION で表した未終了の呼び出しは
/// enter-leave-pairing に合格し、Loss Record の無い未終了は不合格のまま。
/// 別スレッド・別 call_id の記録では閉じない。
#[test]
fn unknown_termination_closes_only_its_own_open_call() {
    use shirusu_conformance::check::CheckStatus;
    let pairing = |records: &[(u64, u64)]| {
        let set = file_io_api_set();
        let mut em = Emitter::new(Vec::new(), set, SessionConfig::new(3, "t")).unwrap();
        let spec = em
            .api_set()
            .spec_by_name("kernel32!CloseHandle")
            .unwrap()
            .clone();
        let token = em
            .begin_call(
                5,
                "kernel32!CloseHandle",
                &values(&spec.enter_fields, 1),
                1,
                EventMeta::default(),
            )
            .unwrap();
        em.abandon_call(token).unwrap();
        let process_id = em.session_config().process_id;
        for &(thread_id, call_id) in records {
            em.write_loss_records(&[shirusu_trace::proto::LossRecord {
                kind: shirusu_trace::proto::loss_kind::UNKNOWN_TERMINATION,
                call_id,
                thread_id,
                process_id,
                ..Default::default()
            }])
            .unwrap();
        }
        let bytes = em
            .finish(FinalizationInfo {
                event_integrity: 1,
                ..Default::default()
            })
            .unwrap();
        let trace = shirusu_trace::read_trace(&bytes).unwrap();
        (
            token.call_id,
            check_trace(&trace)
                .finding("enter-leave-pairing")
                .unwrap()
                .status,
        )
    };
    let (call, status) = pairing(&[]);
    assert_eq!(status, CheckStatus::Fail);
    assert_eq!(pairing(&[(5, call)]).1, CheckStatus::Pass);
    assert_eq!(pairing(&[(6, call)]).1, CheckStatus::Fail, "other thread");
    assert_eq!(pairing(&[(5, call + 1)]).1, CheckStatus::Fail, "other call");
}
