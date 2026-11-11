//! shirusu-hook: フックエンジン。
//!
//! 構成:
//! - `api`: フック対象 API の定義表と Schema（プラットフォーム非依存）
//! - `caller` (L23): フック時の呼び出し元分類（戻りアドレスから
//!   モジュールを特定し、Runtime からの呼び出しを記録しない）
//! - `capture`: 型付き引数取得（メモリ読み取りを抽象化、非依存）
//! - `pe`: PE イメージのインポート/エクスポート解析（非依存）
//! - `plan`: IAT フック計画（非依存）
//! - `bootstrap`: Host → Agent DLL の初期化受け渡し構造（共有定義）
//! - `runtime`: Detour が共有する記録ランタイム
//! - `fls`: スレッド終了の検出 (FLS デストラクタ。Slot 再利用の契機)
//! - `com` (L02): COM Interception の追跡表・既知インターフェイス・
//!   COM メソッドイベントの Schema（プラットフォーム非依存）
//! - `winrt` (L14): WinRT の定義表（既知インターフェイス・ランタイム
//!   クラス）とアクティベーションイベントの Schema（プラットフォーム非依存）
//! - `inline` (L01): Inline Hook のトランポリン構築（iced-x86 による
//!   命令再配置。プラットフォーム非依存で Linux でも検証できる）
//! - `engine`（Windows のみ）: IAT パッチと Detour 本体、Inline Hook の設置・解除
//!
//! フック方式は IAT フック（overview の実装順序 1）と Inline Hook
//! （同 2）の併用。判断理由と限界は docs/traceability.md の G/L 節に記録する。

pub mod api;
pub mod bootstrap;
pub mod caller;
pub mod capture;
pub mod com;
pub mod fls;
pub mod inline;
pub mod pe;
pub mod plan;
pub mod runtime;
pub mod winrt;

#[cfg(windows)]
pub mod engine;
