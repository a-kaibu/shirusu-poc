//! shirusu-probe: 差分候補から回帰テスト用 Probe バンドルを生成する。
//!
//! shirusu-compare が出した「契約違反の候補」1 件を、ippai 側の
//! テストスイートが取り込める再現パッケージ（回帰バンドル）に
//! 変換する：
//!
//! - **rules.json**: 候補を「基準側（Windows）で pass、被検側
//!   （sake）で fail」として言い直した shirusu-test 仕様 v1。
//!   生成は推測ではなく、両 Trace で実際に評価して識別が成立
//!   したものだけを採用する（[`rules`]）。
//! - **brief.md**: 関与した API 呼び出し列を正規化済み引数つきで
//!   提示する Probe ブリーフ（[`brief`]）。
//! - **left/right.trimmed.trace**: 関与オブジェクト／スレッド／
//!   イベントだけに切り詰めた Trace ペア。切り詰めても同じ候補が
//!   再現することを生成時に確認し、結果を manifest に残す
//!   （[`trim`]）。
//! - **manifest.json**: バンドルの素性と生成結果の要約。
//!
//! 線引きは compare と同じ：バンドルは「再現パッケージ」であって
//! 「違反の判定」ではない。候補が本当に契約違反かどうかは、
//! ippai 側で Probe として実行・調査して決める。バンドル形式と
//! ippai 側に残る作業は docs/ippai-integration.md が正。

pub mod brief;
pub mod bundle;
pub mod oracle;
pub mod reduce;
pub mod replay;
pub mod rules;
pub mod select;
pub mod trim;

pub use bundle::{build_bundle, write_bundle, BundleOptions, ProbeBundle, ProbeError};
pub use rules::{generate_rules, RuleGeneration};
