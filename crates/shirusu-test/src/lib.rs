//! shirusu-test（基礎）: Trace に対する期待ルールを評価する。
//!
//! 期待は言語非依存の JSON 仕様で書く（overview の決定）。本クレート
//! は Phase 4 の基礎として、ルールの解釈と pass/fail の評価までを
//! 担う。Phase 5 では shirusu-compare の差分候補から、この形式の
//! 最小仕様（Probe）を生成して ippai の回帰テストへ渡す想定であり、
//! 形式と評価器をここに固定することが、その土台になる。
//!
//! 線引きは compare と同じ：ルールの失敗は「記録の中に期待した
//! 振る舞いが無い」ことであり、「実装が契約違反である」ことの
//! 断定ではない。記録の完全性（Capture Coverage）が欠けていれば、
//! まずそちらを疑うべきであり、その判断材料は `no-integrity-loss`
//! ルールと inspect の完全性表示が提供する。
//!
//! L20: 仕様は `steps`（実行する呼び出し列）も持てる。JSON Runner
//! （`runner`）が仕様をそのまま解釈して実行し、Probe exe 生成
//! （`probe_exe`）が同じ仕様から Windows 向け exe を作る。実行の
//! 意味論は `runner_exec` に一か所だけあり、両者はそれを共有する。

pub mod eval;
pub mod golden;
pub mod json_parse;
pub mod prereq;
pub mod probe_exe;
pub mod runner;
pub mod runner_exec;
pub mod runner_report;
pub mod spec;
pub mod steps;

pub use eval::{evaluate, RuleResult, TestReport};
pub use golden::{
    check, derive_from_trace, fresh_check, Golden, GoldenEnvironment, GoldenOverrides, GoldenReport,
};
pub use prereq::{check_prerequisites, PrereqItem, PrereqKind, PrereqReport};
pub use probe_exe::{build_probe_exe, generate_probe_main_rs};
pub use runner::{run_spec, RunMode, RunReport};
pub use runner_exec::{
    plan_steps, ArgValue, Expect, ExpectedOutput, ParamKind, RetExpect, RunReportData, Step,
    StepOutcome,
};
pub use runner_report::parse_runner_report_json;
pub use spec::{Rule, TestSpec};
