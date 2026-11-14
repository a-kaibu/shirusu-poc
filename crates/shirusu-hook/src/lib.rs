//! shirusu-hook: フックエンジン。
//!
//! 構成:
//! - `api`: フック対象 API の定義表と Schema（プラットフォーム非依存）
//! - `caller` (L23): フック時の呼び出し元分類（戻りアドレスから
//!   モジュールを特定する。除外設定は Runtime 自身の API が対象）
//! - `capture`: 型付き引数取得（メモリ読み取りを抽象化、非依存）
//! - `pe`: PE イメージのインポート/エクスポート解析（非依存）
//! - `plan`: IAT フック計画（非依存）
//! - `bootstrap`: Host → Agent DLL の初期化受け渡し構造（共有定義）
//! - `runtime`: Detour が共有する記録ランタイム
//! - `fls`: OS スレッド終了の通知と、Loader Lock 外での遅延回収
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

/// API 定義表は `shirusu-api-catalog` に置く（Host と共有する契約）。
/// 既存の `shirusu_hook::api` の経路は互換のために残す。
pub use shirusu_api_catalog::api;
/// このバイナリの API Catalog Fingerprint（Bootstrap v13 の照合に使う）。
pub use shirusu_api_catalog::fingerprint::catalog_fingerprint as api_catalog_fingerprint;
pub mod alloc_reserve;
pub mod bootstrap;
pub mod callback;
pub mod caller;
mod callsite;
pub mod capture;
pub mod com;
pub mod fls;
mod hazard;
pub mod inline;
#[cfg(windows)]
pub mod last_error;
pub mod pe;
pub mod plan;
pub mod runtime;
#[cfg(windows)]
pub mod thread_id;
pub mod winrt;

#[cfg(windows)]
pub mod engine;
#[cfg(windows)]
mod seh;
#[cfg(windows)]
pub mod shared_com;
#[cfg(windows)]
mod thread_snapshot;

// Windows native tests count allocator activity in the actual suspended interval.
// No panic/assertion runs until every suspended thread has been resumed.
#[cfg(all(test, windows))]
pub(crate) mod heap_watch {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! {
        static WATCH: Cell<bool> = const { Cell::new(false) };
        static HITS: Cell<usize> = const { Cell::new(0) };
    }
    pub struct Allocator;
    fn hit() {
        if WATCH.try_with(Cell::get).unwrap_or(false) {
            let _ = HITS.try_with(|h| h.set(h.get() + 1));
        }
    }
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            hit();
            unsafe { System.alloc(l) }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            hit();
            unsafe { System.dealloc(p, l) }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            hit();
            unsafe { System.realloc(p, l, n) }
        }
    }
    pub fn begin() {
        HITS.with(|h| h.set(0));
        WATCH.with(|w| w.set(true));
    }
    pub fn end() {
        WATCH.with(|w| w.set(false));
        assert_eq!(
            HITS.with(Cell::get),
            0,
            "heap activity while threads suspended"
        );
    }
}
#[cfg(all(test, windows))]
#[global_allocator]
static TEST_ALLOCATOR: heap_watch::Allocator = heap_watch::Allocator;
