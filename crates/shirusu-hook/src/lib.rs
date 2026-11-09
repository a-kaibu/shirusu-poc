//! shirusu-hook: フックエンジン。
//!
//! 構成:
//! - `api`: フック対象 API の定義表と Schema（プラットフォーム非依存）
//! - `capture`: 型付き引数取得（メモリ読み取りを抽象化、非依存）
//! - `pe`: PE イメージのインポート/エクスポート解析（非依存）
//! - `plan`: IAT フック計画（非依存）
//! - `bootstrap`: Host → Agent DLL の初期化受け渡し構造（共有定義）
//! - `runtime`: Detour が共有する記録ランタイム
//! - `engine`（Windows のみ）: IAT パッチと Detour 本体
//!
//! フック方式は IAT フック（overview の実装順序 1）。判断理由と限界は
//! docs/traceability.md の G セクションに記録する。

pub mod api;
pub mod bootstrap;
pub mod capture;
pub mod pe;
pub mod plan;
pub mod runtime;

#[cfg(windows)]
pub mod engine;
