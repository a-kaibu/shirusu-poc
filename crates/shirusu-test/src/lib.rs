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

pub mod eval;
pub mod json_parse;
pub mod spec;

pub use eval::{evaluate, RuleResult, TestReport};
pub use spec::{Rule, TestSpec};
