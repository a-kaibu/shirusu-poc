//! shirusu-emit: 外部レコーダ向けエミッタキット。
//!
//! shirusu 本体以外の実装（sake 等の互換レイヤ、他言語の
//! レコーダ）が公開 Trace 仕様（docs/trace-format.md）に適合した
//! Trace を出力するための高水準 API。生の `TraceWriter` は形式の
//! 不変条件（前方参照禁止、チャンク分割、Index）までは保証するが、
//! 「compare と適合性チェッカが前提とする規約」――セッション
//! 管理、共有 API セットの Schema 登録、sequence の単調性、
//! Enter/Leave の対応、完全性メタデータの存在――は呼び出し側の
//! 責任になっていた。本クレートはその規約側を肩代わりする。
//!
//! 境界の明記：このキットは「仕様に適合した Trace を書く手段」で
//! あり、sake 側の実装そのものではない。sake がこのキット（また
//! は同等の自前実装）を使って Trace を出すところまでが ippai 側の
//! 作業として残る。契約の全体は docs/ippai-integration.md に置く。

pub mod api_set;
pub mod emitter;

pub use api_set::{file_io_api_set, ApiSet, ApiSpec};
pub use emitter::{
    CallToken, EmitError, Emitter, EventMeta, PayloadData, Result, SessionConfig, KIND_ENTER,
    KIND_LEAVE,
};
