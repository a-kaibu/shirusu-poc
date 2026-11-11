//! スレッド終了の検出 (レビュー #6 P1-4)。
//!
//! Agent DLL は `DisableThreadLibraryCalls` を使うため、
//! DLL_THREAD_DETACH は届かず、スレッド終了を契機に Slot を
//! DRAINING へ移す手段が無かった。FLS (Fiber Local Storage) の
//! デストラクタは、値をセットしたスレッドの終了時に OS から
//! 呼ばれることが保証されており、`DisableThreadLibraryCalls` の
//! 影響を受けない。ここではその結線だけを担う:
//!
//! - 初期化時に [`install_thread_exit_handler`] でハンドラを登録し、
//!   FLS インデックスを 1 つ確保する (プロセス全体で 1 回だけ)。
//! - 記録を始めたスレッドは [`arm_current_thread`] で自分の
//!   スレッド ID を値としてセットする (武装)。終了時にデストラクタ
//!   が値 (= スレッド ID) を受け取り、ハンドラへ渡す。
//!
//! ハンドラは agent-dll が登録し、現在のランタイムへ
//! `HookRuntime::thread_exit` を伝える。非 Windows では何もしない
//! スタブであり、呼び出し側のコードはプラットフォームで分岐しない。

use std::sync::Arc;

/// スレッド終了ハンドラ。引数は終了するスレッドの ID。
pub type ThreadExitHandler = Arc<dyn Fn(u64) + Send + Sync>;

#[cfg(windows)]
mod imp {
    use super::ThreadExitHandler;
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Threading::{FlsAlloc, FlsSetValue};

    static HANDLER: OnceLock<ThreadExitHandler> = OnceLock::new();
    static FLS_INDEX: OnceLock<u32> = OnceLock::new();
    const FLS_OUT_OF_INDEXES: u32 = u32::MAX;

    /// FLS デストラクタ。値をセットしたスレッドの終了時に OS から
    /// 呼ばれる。値は武装時に格納したスレッド ID そのものである。
    unsafe extern "system" fn on_thread_exit(value: *const c_void) {
        if value.is_null() {
            return;
        }
        let thread_id = value as usize as u64;
        if let Some(handler) = HANDLER.get() {
            handler(thread_id);
        }
    }

    /// 終了ハンドラを登録し、FLS インデックスを確保する。
    /// プロセス全体で初回だけが有効で、以降の呼び出しは現在の
    /// 状態 (確保済みなら true) を返す。
    pub fn install_thread_exit_handler(handler: ThreadExitHandler) -> bool {
        if HANDLER.set(handler).is_err() {
            return FLS_INDEX.get().is_some();
        }
        // SAFETY: デストラクタはスレッド終了時に OS から呼ばれる。
        // 値の所有権は移らない (スレッド ID をポインタ幅に載せる)。
        let index = unsafe { FlsAlloc(Some(on_thread_exit)) };
        if index == FLS_OUT_OF_INDEXES {
            return false;
        }
        let _ = FLS_INDEX.set(index);
        true
    }

    /// 現在のスレッドの終了通知を武装する。記録を始めたスレッドが
    /// 自分自身に対して呼ぶこと (FLS の値はスレッドごとの格納域)。
    /// ハンドラ未登録なら何もしない。
    pub fn arm_current_thread(thread_id: u64) {
        if thread_id == 0 {
            return; // 0 は NULL 値になり、デストラクタが呼ばれない
        }
        if let Some(&index) = FLS_INDEX.get() {
            // SAFETY: index は確保済みの FLS インデックス。値は
            // スレッド ID をそのままポインタとして保持する。
            unsafe { FlsSetValue(index, thread_id as usize as *mut c_void) };
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::ThreadExitHandler;

    /// 非 Windows では FLS は存在しない。検出できないことを
    /// 呼び出し側が区別できるよう false を返す (スタブ)。
    pub fn install_thread_exit_handler(_handler: ThreadExitHandler) -> bool {
        false
    }

    /// 非 Windows では何もしない。
    pub fn arm_current_thread(_thread_id: u64) {}
}

pub use imp::{arm_current_thread, install_thread_exit_handler};
