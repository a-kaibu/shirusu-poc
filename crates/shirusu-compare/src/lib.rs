//! shirusu-compare: 正規化つき差分エンジン。
//!
//! 2 つの公開 Trace（想定: Windows 実機の記録と、sake 等の互換実装が
//! 同形式で出した記録）を比較し、振る舞いの相違を構造化された
//! 「差分候補」として提示する。
//!
//! 設計の要点は overview「比較とテスト生成」とレビュー第3回 §4 に
//! ある。呼び出し列を単純照合せず、オブジェクトの同一性（生成
//! イベントからの相関）と状態遷移（オブジェクトへの操作列）で
//! 対応づけ、ハンドル値・ポインタ・タイミング等の非決定値は
//! 正規化で吸収する。そして本エンジンが出すのは契約違反の
//! 「候補」までであり、正しさの判定はしない。判定は Probe /
//! 回帰テスト（shirusu-test と Phase 5 の取り込み）の仕事である。

pub mod diff;
pub mod normalize;
pub mod report;

pub use diff::{compare_traces, Candidate, CandidateKind, DiffReport, Severity, CANDIDATE_NOTICE};
pub use normalize::{NormCall, NormEvent, NormField, NormPayload, NormTrace, NormValue, ObjectKey};
pub use report::{render_human, report_json};
