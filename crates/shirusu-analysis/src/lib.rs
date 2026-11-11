//! shirusu-analysis: 公開 Trace の解析ビュー（共有基盤）。
//!
//! 解析系コンポーネント（`shirusu` CLI の inspect/dump/export、
//! `shirusu-compare`、`shirusu-test`）が共通で使う「Trace を読んで
//! 見せる」層。イベントの平坦化、Schema による引数復号、値の決定的な
//! 文字列表現、完全性サマリ、最小 JSON ライタを提供する。
//!
//! 値そのものの解釈（環境差を吸収する正規化やオブジェクト同一性）は
//! ここでは行わない。それは shirusu-compare の責務であり、本クレート
//! は「記録されたものを、記録されたとおりに」返すことに徹する。

pub mod json;
pub mod view;

pub use json::JsonValue;
pub use view::{
    api_name_of_schema, capture_name, format_field, integrity_level_name, loss_kind_name,
    reason_name, value_capture_name, EventFilter, EventView, FieldView, IntegritySummary,
    PayloadView, Phase, TraceView, KIND_ABORTED, KIND_COMPLETED, KIND_ENTER, KIND_LEAVE,
};
