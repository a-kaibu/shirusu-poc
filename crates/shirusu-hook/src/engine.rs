//! Windows 実装： IAT パッチと Detour 本体、および Inline Hook（L01）。
//!
//! 透明性（overview「Hookの透明性」）の要点:
//! - 元の API から戻った直後に GetLastError を読み取り、Wrapper の処理が
//!   終わって呼び出し側へ戻る直前に同じ値を書き戻す。取得処理の中で
//!   Win32 API を呼んでも、呼び出し側から見た LastError は変わらない。
//! - 取得は全て「元の呼び出しの外側」で行い、元の呼び出し自体の
//!   引数・戻り値には一切触れない。
//! - 例外 (L08)：元の API が例外で中断したら、例外はそのまま伝え、
//!   中断した呼び出しを `CallAborted` として記録する（`CallGuard` の
//!   Drop。例外は捕捉しない）。
//! - Reentrance (G15)： Detour の記録経路の実行中にフック対象 API が
//!   呼ばれたら、Agent 自身の呼び出しとして記録せず素通しする
//!   （TLS の `ReentrancyGuard`。`prepare` が入口で判定する）。
//!   元の API 呼び出しの間だけガードを外すため、アプリ由来の入れ子
//!   呼び出しは親子として記録される（A43）。旧実装は記録経路がフック
//!   対象 API を呼ばないことに暗黙に依存していた。

use crate::api::{
    api_by_id, api_table, ApiDef, API_CLOSE_HANDLE, API_CREATE_FILE_W, API_GET_OVERLAPPED_RESULT,
    API_GET_QUEUED_COMPLETION_STATUS, API_NT_CLOSE, API_NT_CREATE_FILE, API_NT_OPEN_FILE,
    API_NT_QUERY_INFORMATION_FILE, API_NT_READ_FILE, API_NT_SET_INFORMATION_FILE,
    API_NT_WRITE_FILE, API_READ_FILE, API_WRITE_FILE,
};
use crate::callback::{
    callback_procs, resolve_prev_proc, should_wrap_set_window_long, wrap_wndproc_in_class,
    CallbackKind, CALLBACK_API_ID, CALLBACK_HOOKS, CALLBACK_HOOK_COUNT,
    CALLBACK_HOOK_GET_CLASS_LONG_PTR_A, CALLBACK_HOOK_GET_CLASS_LONG_PTR_W,
    CALLBACK_HOOK_GET_WINDOW_LONG_PTR_A, CALLBACK_HOOK_GET_WINDOW_LONG_PTR_W,
    CALLBACK_HOOK_REGISTER_CLASS_EX_A, CALLBACK_HOOK_REGISTER_CLASS_EX_W,
    CALLBACK_HOOK_REPORT_ID_BASE, CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A,
    CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W, CALLBACK_LEAVE_SCHEMA_ID, CALLBACK_PROC_SLOTS,
    MAX_WNDCLASSEX_BYTES, WNDPROC_FIELD_OFFSET,
};
use crate::capture::{self, MemoryReader};
use crate::com::{
    build_cloned_vtable, interface_by_iid, ComCloneRegistry, Guid, COM_FACTORY_COUNT,
    COM_FACTORY_CO_CREATE_INSTANCE, COM_FACTORY_CO_GET_CLASS_OBJECT, COM_FACTORY_REPORT_ID_BASE,
    IID_IUNKNOWN, KNOWN_FACTORIES,
};
use crate::inline::{build_patch, build_trampoline, plan_with_near_relay, StolenPlan};
use crate::pe;
use crate::plan::{build_plan, HookPlan};
use crate::runtime::{pop_call, push_call, ComCallGuard, HookRuntime, ReentrancyGuard};
use crate::winrt::{
    winrt_method_return, IID_IINSPECTABLE, WINRT_ACTIVATIONS, WINRT_ACTIVATION_API_ID,
    WINRT_ACTIVATION_COUNT, WINRT_ACTIVATION_LEAVE_SCHEMA_ID, WINRT_ACTIVATION_REPORT_ID_BASE,
    WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE, WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
};
use std::ffi::c_void;
use std::sync::Arc;
#[cfg(test)]
use windows_sys::Win32::Foundation::SetLastError;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
/// スレッドコンテキストの制御レジスタだけを取得するフラグ。
/// x64: CONTEXT_CONTROL_AMD64 (0x100001) / x86: CONTEXT_CONTROL_X86 (0x10001)。
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64 as CONTEXT_CONTROL;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86 as CONTEXT_CONTROL;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, CONTEXT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessIdOfThread, OpenThread,
    ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};

/// Agent DLL の初期化がランタイムを登録する。以後の Detour はこれを使う。
///
/// 登録はセッション単位（[`crate::runtime::RuntimeSlot`]）。アクティブな
/// セッションがある間は失敗するが、終了手順が IAT 復元後に
/// [`clear_runtime`] で解除すれば、同じプロセスへ再初期化できる
/// （レビュー第5回 #7。旧実装は OnceLock で再アタッチ不能だった）。
pub fn set_runtime(rt: Arc<HookRuntime>) -> Result<(), Arc<HookRuntime>> {
    crate::runtime::runtime_slot().register(rt)
}
pub fn runtime() -> Option<Arc<HookRuntime>> {
    crate::runtime::runtime_slot().current()
}
/// 終了手順の最後（IAT 復元後）に、自分のセッションの登録を解除する。
/// 解除できたら true。Detour が入口で掴んだ Arc には影響しない。
pub fn clear_runtime(rt: &Arc<HookRuntime>) -> bool {
    crate::runtime::runtime_slot().unregister(rt)
}

#[derive(Debug)]
pub enum EngineError {
    /// モジュールイメージが PE として読めない
    NotPe,
    /// 書き換え可能な IAT が無い。静的 import が無い場合に加え、既存
    /// ラッパーを全件保持した場合も含む。計画の missing / preserved を
    /// 区別して報告する。これは**初期化の失敗ではない**ため、呼び出し側は
    /// 「IAT 0 件設置」として Inline の設置と記録を継続してよい
    /// (レビュー #4 の #8)。
    NoTargets(HookPlan),
    /// ポインタ幅のアトミック更新に必要なアラインメントを満たさない
    UnalignedIatSlot,
    IatChanged,
    /// IAT スロットの保護属性変更に失敗した
    ProtectFailed {
        iat_rva: u32,
    },
    /// 設置途中の失敗（レビュー第5回 #8）。既にパッチしたスロットは
    /// 逆順に復元を試みた後で返る。`unrestored` が空でなければ、
    /// 対象プロセスに Detour が残存する重大な状態であり、呼び出し
    /// 側は Host へその件数を伝えなければならない。
    InstallFailed {
        /// パッチに失敗したスロットの IAT RVA。
        failed_iat_rva: u32,
        /// 復元も失敗したスロットの IAT RVA。
        unrestored: Vec<u32>,
        /// Owned recovery state, including post-publication protection failures.
        pending: Box<InstalledHooks>,
    },
}

/// プロセス内メモリの読み取り (レビュー #6 P0-3)。
///
/// 旧実装は VirtualQuery で「コミット済み・読み取り可能」を確認して
/// から生ポインタをコピーしていたが、確認とコピーの間に別スレッドが
/// VirtualFree / VirtualProtect をすると、観測そのものがアクセス
/// 違反になる競合 (TOCTOU) があった。現在は
/// `ReadProcessMemory(GetCurrentProcess(), ...)` で読む: 保護が
/// 変わっていても違反にはならず、読めなければ失敗として返る。
/// 全バイト読めた場合だけ true (部分読みは失敗として扱う)。
///
/// なお同時性の解消ではない: 読みと並行して対象が書き換われば内容は
/// ある一時点の像とは限らないが、その前提は元々なく、取得側は値を
/// Captured 以外 (Truncated / Unreadable) として扱える。ここで守る
/// のは「観測が対象プロセスを落とさない」ことである。
pub struct ProcessMemory;

impl MemoryReader for ProcessMemory {
    fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool {
        if buf.is_empty() {
            return true;
        }
        if addr == 0 {
            return false;
        }
        let mut read: usize = 0;
        // SAFETY: 自プロセスへの失敗可能な読み取り。対象範囲が
        // アクセス不能でも違反にはならず 0 が返る (P0-3)。
        // GetCurrentProcess は疑似ハンドルで、閉じる必要はない。
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                addr as usize as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut read,
            )
        };
        ok != 0 && read == buf.len()
    }
}

// Submodules share this module's imports through `use super::*`.
mod iat;
pub use iat::*;
mod inline_hooks;
pub use inline_hooks::*;
mod com_install;
pub use com_install::*;
mod detours;
use detours::*;
mod com_detours;
use com_detours::*;
mod callbacks;
use callbacks::*;
mod com_methods;
pub(crate) use com_methods::com_method_dispatch_with;
use com_methods::*;
mod file_io;
use file_io::*;

include!("engine_generated.inc");

#[cfg(test)]
mod tests;
