//! 正規化の不変性 PBT:
//! - 同じ抽象スクリプトを、ハンドル値・PID・スレッド・時刻を変えて
//!   描いた 2 つの Trace は、比較で候補ゼロになる（再番号付け不変性）。
//! - 任意のスクリプトは自分自身との比較で候補ゼロになる（反射性）。

mod common;

use common::{Builder, Env};
use proptest::prelude::*;
use shirusu_trace::writer::FinalizationInfo;

/// 抽象操作（オブジェクトは生成序数で指す）。
#[derive(Debug, Clone)]
enum Op {
    Create,
    Read(u32, u32), // (対象を開いている中から選ぶ種, 読み取り長)
    Write(u32),
    Close(u32),
    Ping(u32),
}

fn op_strategy() -> impl Strategy<Value = (u8, u32, u32)> {
    (0u8..5, 0u32..16, 0u32..8)
}

/// 種列を、開いているオブジェクトへの操作として解釈する。
/// 開いているものが無い操作は Create に読み替える（決定的）。
fn interpret(tags: &[(u8, u32, u32)]) -> Vec<Op> {
    let mut open: Vec<u32> = Vec::new();
    let mut next_obj = 0u32;
    let mut ops = Vec::new();
    for &(kind, a, b) in tags {
        let pick = |open: &Vec<u32>, seed: u32| -> Option<u32> {
            if open.is_empty() {
                None
            } else {
                Some(open[(seed as usize) % open.len()])
            }
        };
        match kind {
            0 => {
                ops.push(Op::Create);
                open.push(next_obj);
                next_obj += 1;
            }
            1 => match pick(&open, a) {
                Some(obj) => ops.push(Op::Read(obj, 1 + b)),
                None => {
                    ops.push(Op::Create);
                    open.push(next_obj);
                    next_obj += 1;
                }
            },
            2 => match pick(&open, a) {
                Some(obj) => ops.push(Op::Write(obj)),
                None => ops.push(Op::Ping(a)),
            },
            3 => match pick(&open, a) {
                Some(obj) => {
                    ops.push(Op::Close(obj));
                    open.retain(|&o| o != obj);
                }
                None => ops.push(Op::Ping(a)),
            },
            _ => ops.push(Op::Ping(a)),
        }
    }
    ops
}

fn render(ops: &[Op], env: Env) -> shirusu_trace::reader::ReadTrace {
    let mut b = Builder::new(env);
    let mut call = 0u64;
    for (i, op) in ops.iter().enumerate() {
        call += 1;
        match op {
            Op::Create => {
                let obj = ops[..=i].iter().filter(|o| matches!(o, Op::Create)).count() as u32 - 1;
                b.create_file(call, obj, &format!("file{obj}.dat"));
            }
            Op::Read(obj, want) => {
                let data: Vec<u8> = (0..*want)
                    .map(|k| (i as u8).wrapping_add(k as u8))
                    .collect();
                b.read_file(call, *obj, *want, *want, &data, true, 0);
            }
            Op::Write(obj) => {
                b.write_file(call, *obj, &[i as u8; 3]);
            }
            Op::Close(obj) => b.close_handle(call, *obj),
            Op::Ping(x) => b.ping(call, *x, *x),
        }
    }
    b.finish(FinalizationInfo::default(), &[])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn renumbering_is_invisible(tags in prop::collection::vec(op_strategy(), 0..24)) {
        let ops = interpret(&tags);
        let left = render(&ops, Env::default());
        let right = render(
            &ops,
            Env {
                handle_base: 0x8_0000,
                raw_pid: 999,
                process_id: 123,
                thread_id: 777,
                ts_base: 42_000,
            },
        );
        let report = shirusu_compare::compare_traces(&left, &right);
        prop_assert!(
            report.is_identical(),
            "renumbered trace must produce no candidates: {:?}",
            report.candidates
        );
    }

    #[test]
    fn reflexivity(tags in prop::collection::vec(op_strategy(), 0..24)) {
        let ops = interpret(&tags);
        let trace = render(&ops, Env::default());
        let report = shirusu_compare::compare_traces(&trace, &trace);
        prop_assert!(report.is_identical(), "self-compare: {:?}", report.candidates);
    }
}
