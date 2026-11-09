//! shirusu-conformance: 外部生成 Trace の適合性チェッカ。
//!
//! shirusu 本体以外の実装が出した Trace を ippai の回帰テスト等へ
//! 取り込む前に、「公開 Trace 仕様（docs/trace-format.md）」と
//! 「compare / shirusu-test が依存する規約」を満たすかを検証する。
//! 検査項目の定義と根拠は [`check`] モジュールの文書が正。
//!
//! 位置づけの明記：ここで言う「適合」は形式と規約への適合であり、
//! 記録された振る舞いが正しいことの証明ではない（正しさの判定は
//! Probe / 回帰テストの仕事、という線引きは compare と同じ）。
//! また Capture Coverage の真偽（本当に全呼び出しを観測できたか）
//! は Trace の中からは検証できないため、本チェッカの範囲外である。

pub mod check;

pub use check::{check_trace, CheckFinding, CheckStatus, ConformanceReport};
