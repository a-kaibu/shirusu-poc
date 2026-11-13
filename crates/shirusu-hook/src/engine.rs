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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// IAT スロットの保護属性変更に失敗した
    ProtectFailed { iat_rva: u32 },
    /// 設置途中の失敗（レビュー第5回 #8）。既にパッチしたスロットは
    /// 逆順に復元を試みた後で返る。`unrestored` が空でなければ、
    /// 対象プロセスに Detour が残存する重大な状態であり、呼び出し
    /// 側は Host へその件数を伝えなければならない。
    InstallFailed {
        /// パッチに失敗したスロットの IAT RVA。
        failed_iat_rva: u32,
        /// 復元も失敗したスロットの IAT RVA。
        unrestored: Vec<u32>,
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

/// 設置済みフック。解除時に IAT を元へ戻すために保持する。
pub struct InstalledHooks {
    pub module_base: usize,
    /// (IAT RVA, 元の関数ポインタ)
    pub slots: Vec<(u32, usize)>,
    pub plan: HookPlan,
}

/// IAT スロットへ保護属性を変えて書き込む。
///
/// # Safety
/// `slot` は対象モジュールの IAT 内の有効なスロットであること。
unsafe fn write_slot(slot: *mut usize, value: usize) -> Result<(), EngineError> {
    // Attach can run while application threads read the IAT. Publish one
    // aligned pointer atomically; never tear a malformed, unaligned slot.
    if (slot as usize) & (std::mem::align_of::<std::sync::atomic::AtomicUsize>() - 1) != 0 {
        return Err(EngineError::UnalignedIatSlot);
    }
    let mut old: u32 = 0;
    // SAFETY: 呼び出し側の契約に従う。
    let ok = unsafe {
        VirtualProtect(
            slot as *const c_void,
            std::mem::size_of::<usize>(),
            PAGE_READWRITE,
            &mut old,
        )
    };
    if ok == 0 {
        return Err(EngineError::ProtectFailed { iat_rva: 0 });
    }
    // SAFETY: 同上。書き込み後は元の保護属性へ戻す。
    unsafe {
        std::sync::atomic::AtomicUsize::from_ptr(slot)
            .store(value, std::sync::atomic::Ordering::Release);
        let mut tmp: u32 = 0;
        VirtualProtect(
            slot as *const c_void,
            std::mem::size_of::<usize>(),
            old,
            &mut tmp,
        );
    }
    Ok(())
}

/// モジュール（ロード済みイメージ）の IAT をパッチし、対象 API を
/// Detour へ向ける。元の値はランタイムと戻り値の両方へ保存する。
///
/// # Safety
/// `module_base` はロード済み PE モジュールのベースアドレスであり、
/// 設置中は対象モジュールのコードが IAT 経由の呼び出しを行っていない
/// こと（初期化は対象のメインスレッド再開前に行う）。
pub unsafe fn install_hooks(
    module_base: *mut u8,
    rt: &HookRuntime,
) -> Result<InstalledHooks, EngineError> {
    // SAFETY: ベースはロード済みモジュール。ヘッダー分だけ先に読む。
    let header = unsafe { std::slice::from_raw_parts(module_base, 0x1000) };
    let size = pe::size_of_image(header).ok_or(EngineError::NotPe)? as usize;
    // SAFETY: SizeOfImage 分がモジュールイメージ。
    let image = unsafe { std::slice::from_raw_parts(module_base, size) };
    let sites = pe::parse_imports(image);
    let mut plan = build_plan(&sites);
    // Inline installation later replaces the per-API original with its export
    // trampoline. Routing a preexisting IAT wrapper through that shared slot
    // would silently bypass the wrapper. Leave such imports untouched.
    plan.preserve_noncanonical(|entry| {
        let Some(export) = resolve_export(&entry.dll_name, entry.api.function) else {
            return false;
        };
        // SAFETY: the import parser bounds-checks the pointer slot in this image.
        let original =
            unsafe { (module_base.add(entry.iat_rva as usize) as *const usize).read_unaligned() };
        follow_import_thunks(original) == Some(export)
    });
    if plan.entries.is_empty() {
        return Err(EngineError::NoTargets(plan));
    }
    // 設置はトランザクションとして実行する (レビュー第5回 #8):
    // 途中の write_slot が失敗したら、既にパッチしたスロットを
    // 逆順に復元してからエラーを返す。アタッチ先のプロセスは
    // 生きたままなので、一部だけ Detour 化した状態を残さない。
    let entries = &plan.entries;
    let originals = crate::plan::patch_transactionally(
        entries.len(),
        |i| {
            let entry = &entries[i];
            // SAFETY: iat_rva はこのモジュールの IAT 内（plan の入力は同イメージの解析結果）。
            let slot = unsafe { module_base.add(entry.iat_rva as usize) } as *mut usize;
            // SAFETY: 同上。
            let original = unsafe { slot.read_unaligned() };
            rt.set_original(entry.api.api_id, original);
            // SAFETY: 同上。
            unsafe { write_slot(slot, detour_for(entry.api.api_id)) }?;
            Ok(original)
        },
        |i, original| {
            let entry = &entries[i];
            // SAFETY: 設置時にパッチしたのと同じスロット。
            let slot = unsafe { module_base.add(entry.iat_rva as usize) } as *mut usize;
            // SAFETY: 同上。
            unsafe { write_slot(slot, original) }
        },
    )
    .map_err(|rb| EngineError::InstallFailed {
        failed_iat_rva: entries[rb.failed_index].iat_rva,
        unrestored: rb.unrestored.iter().map(|&i| entries[i].iat_rva).collect(),
    })?;
    let slots: Vec<(u32, usize)> = entries.iter().map(|e| e.iat_rva).zip(originals).collect();
    Ok(InstalledHooks {
        module_base: module_base as usize,
        slots,
        plan,
    })
}

/// IAT を元の値へ戻す（設置の巻き戻し）。復元できなかったスロットの
/// IAT RVA を返す (レビュー #6 P1-6)。
///
/// 順序制御は設置側と対称な [`crate::plan::restore_all`] に委ねる:
/// 失敗しても残りを全て試みる。戻り値が空でなければ、対象プロセス
/// に Detour が残存する重大な状態であり、呼び出し側は終了状態
/// (SHUTDOWN_INCOMPLETE) へ反映しなければならない。旧実装は
/// 書き戻しの失敗を捨てており、残存があっても「解除できた」ことに
/// なっていた。
///
/// # Safety
/// `installed` は install_hooks が返したものであり、対象モジュールが
/// まだロードされていること。
unsafe fn uninstall_iat_indices(installed: &InstalledHooks) -> Vec<usize> {
    crate::plan::restore_all(installed.slots.len(), |i| {
        let (iat_rva, original) = installed.slots[i];
        // SAFETY: 呼び出し側の契約に従う。
        let slot =
            unsafe { (installed.module_base as *mut u8).add(iat_rva as usize) } as *mut usize;
        // SAFETY: 同上。
        unsafe { write_slot(slot, original) }
    })
}

/// Restore IAT slots and report RVAs that could not be restored.
///
/// # Safety
/// Same installed-module lifetime contract as `uninstall_pending_hooks`.
pub unsafe fn uninstall_hooks(installed: &InstalledHooks) -> Vec<u32> {
    unsafe { uninstall_iat_indices(installed) }
        .into_iter()
        .map(|i| installed.slots[i].0)
        .collect()
}

/// Retain only IAT slots whose restoration failed, so retries never overwrite
/// slots already restored (and possibly changed by the application afterwards).
///
/// # Safety
/// The installed module and remaining slots must still be mapped at their
/// original addresses; only a lifecycle owner may modify this installation.
pub unsafe fn uninstall_pending_hooks(installed: &mut InstalledHooks) -> usize {
    let failed = unsafe { uninstall_iat_indices(installed) };
    retain_failed_indices(&mut installed.slots, &failed);
    installed.slots.len()
}

fn retain_failed_indices<T>(items: &mut Vec<T>, failed: &[usize]) {
    let mut index = 0;
    items.retain(|_| {
        let keep = failed.contains(&index);
        index += 1;
        keep
    });
}

// ---- L01: Inline Hook ----
//
// IAT フックは対象モジュールのインポート経由の呼び出ししか捕捉できない。
// `GetProcAddress` で取得した関数ポインタや間接呼び出しは、対象関数
// 自体の先頭を Detour へのジャンプで置き換えることで捕捉する。置き換えた
// 先頭命令はトランポリン（`crate::inline` で再配置）へ移し、Detour は
// トランポリンを「元の関数」として呼ぶ。
//
// 設置・解除の安全性:
// - パッチ中は対象プロセスの全スレッド（呼び出し元を除く）を停止する。
//   停止中のスレッドの命令ポインタがパッチ範囲内にある API は見送る
//   （復帰後にパッチの途中バイトを実行してしまうため）。
// - トランポリンは対象の近く（±2GB）に確保し、戻りジャンプが rel32 で
//   届くようにする。近くに空きが無ければ全体確保し、絶対ジャンプを使う。
// - 解除時はプロローグを元へ戻し、停止中のスレッドが中にいない
//   トランポリンはプロセス終了まで保持し、未復元を正直に報告する。

/// Inline Hook 1 件分。解除時にプロローグを復元するために保持する。
/// トランポリンはプロセス終了まで保持する。
#[derive(Debug)]
pub struct InlineHook {
    pub api_id: u32,
    pub target: usize,
    pub trampoline: usize,
    pub trampoline_size: usize,
    pub stolen_len: usize,
    /// パッチ前の先頭バイト（stolen_len 分）。
    pub original_bytes: Vec<u8>,
}

/// Inline Hook の設置結果。IAT とは別経路のため、API ごとに設置／
/// 見送りを記録する。呼び出し側は `skipped` を Coverage 欠落へ写す。
#[derive(Debug, Default)]
pub struct InlineInstallOutcome {
    pub installed: Vec<InlineHook>,
    /// (api_id, 見送り理由)
    pub skipped: Vec<(u32, &'static str)>,
}

/// Inline Hook の設置時にトランポリンを指す元関数ポインタの格納先。
/// API 表のものはランタイムの API 別表へ、COM Factory 関数のものは
/// Factory 別表へ、WinRT アクティベーション関数のものは WinRT 別表へ、
/// コールバック検出フック関数のものはコールバック別表へ格納する
/// （L02・L14・L16）。
enum InlineOriginalSlot {
    Api(u32),
    ComFactory(usize),
    WinRtActivation(usize),
    Callback(usize),
}

impl InlineOriginalSlot {
    fn set_original(&self, rt: &HookRuntime, address: usize) {
        match *self {
            Self::Api(id) => rt.set_original(id, address),
            Self::ComFactory(i) => rt.set_com_original(i, address),
            Self::WinRtActivation(i) => rt.set_winrt_original(i, address),
            Self::Callback(i) => rt.set_callback_original(i, address),
        }
    }

    /// 設置結果の報告用 ID。Factory 関数・アクティベーション関数・
    /// コールバック検出フック関数は API 表に無いため、予約値を使う。
    fn report_id(&self) -> u32 {
        match self {
            InlineOriginalSlot::Api(id) => *id,
            InlineOriginalSlot::ComFactory(i) => COM_FACTORY_REPORT_ID_BASE + *i as u32,
            InlineOriginalSlot::WinRtActivation(i) => WINRT_ACTIVATION_REPORT_ID_BASE + *i as u32,
            InlineOriginalSlot::Callback(i) => CALLBACK_HOOK_REPORT_ID_BASE + *i as u32,
        }
    }
}

/// 計画済みの Inline Hook 1 件（スレッド停止前に解決・デコード済み）。
struct PlannedInline {
    slot: InlineOriginalSlot,
    target: usize,
    detour: usize,
    plan: StolenPlan,
    original_bytes: Vec<u8>,
}

/// Snapshot/open thread handles before suspension; no heap activity until resume.
/// Drop 時にも再開するため、途中で失敗しても停止したままにならない。
struct SuspendedThreads {
    handles: Vec<*mut c_void>,
    thread_ids: Vec<u32>,
    snapshot: Option<crate::thread_snapshot::ThreadSnapshot>,
}

// The x64 Windows SDK declares CONTEXT with DECLSPEC_ALIGN(16), but the
// windows-sys 0.59 binding only has repr(C). Preserve the native buffer alignment
// explicitly; otherwise GetThreadContext can fail and every hook is refused as
// thread-in-target by the fail-safe IP check.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

fn thread_instruction_pointer(handle: *mut c_void) -> Result<usize, u32> {
    let mut ctx = AlignedContext(unsafe { std::mem::zeroed() });
    ctx.0.ContextFlags = CONTEXT_CONTROL;
    if unsafe { GetThreadContext(handle, &mut ctx.0) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    #[cfg(target_arch = "x86_64")]
    let ip = ctx.0.Rip as usize;
    #[cfg(target_arch = "x86")]
    let ip = ctx.0.Eip as usize;
    Ok(ip)
}

impl SuspendedThreads {
    /// 全スレッドを停止する。1 つでも停止できなければ、既に停止した
    /// スレッドを再開して Err を返す（パッチ中の実行と競合させない）。
    fn suspend_all() -> Result<Self, &'static str> {
        Self::suspend_all_after_snapshot(|| {})
    }

    fn suspend_all_after_snapshot(before_suspend: impl FnOnce()) -> Result<Self, &'static str> {
        let snapshot_buffer = crate::thread_snapshot::ThreadSnapshot::new()
            .map_err(|_| "thread-snapshot-unavailable")?;
        let current_tid = unsafe { GetCurrentThreadId() };
        let current_pid = unsafe { GetCurrentProcessId() };
        // SAFETY: スレッド一覧のスナップショット。
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("thread-suspend-failed");
        }
        let mut handles: Vec<*mut c_void> = Vec::new();
        let mut thread_ids = Vec::new();
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        let mut failed = false;
        while more {
            if entry.th32OwnerProcessID == current_pid && entry.th32ThreadID != current_tid {
                // SAFETY: 自プロセスのスレッドを開く。
                let handle = unsafe {
                    OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        0,
                        entry.th32ThreadID,
                    )
                };
                if handle.is_null() {
                    failed = true;
                    break;
                }
                // A terminated thread ID may have been reused since Toolhelp.
                // Never suspend a handle belonging to a different process.
                if unsafe { GetProcessIdOfThread(handle) } != current_pid {
                    unsafe { CloseHandle(handle) };
                    failed = true;
                    break;
                }
                handles.push(handle);
                thread_ids.push(entry.th32ThreadID);
            }
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        if failed {
            for h in handles {
                unsafe { CloseHandle(h) };
            }
            return Err("thread-suspend-failed");
        }
        before_suspend();
        #[cfg(test)]
        crate::heap_watch::begin();
        for (suspended, &handle) in handles.iter().enumerate() {
            if unsafe { SuspendThread(handle) } == u32::MAX {
                for &h in &handles[..suspended] {
                    unsafe { ResumeThread(h) };
                }
                #[cfg(test)]
                crate::heap_watch::end();
                for &h in &handles {
                    unsafe { CloseHandle(h) };
                }
                return Err("thread-suspend-failed");
            }
        }
        let mut suspended = Self {
            handles,
            thread_ids,
            snapshot: Some(snapshot_buffer),
        };
        // GetThreadContext establishes readable suspended contexts before the
        // second native snapshot. Refuse rather than resize or suspend new
        // arrivals while application locks may already be held.
        let verified = suspended
            .handles
            .iter()
            .all(|&handle| thread_instruction_pointer(handle).is_ok());
        let result = if verified {
            suspended
                .snapshot
                .as_mut()
                .unwrap()
                .only_known_threads(current_pid, current_tid, &suspended.thread_ids)
                .map_err(|_| "thread-snapshot-unavailable")
                .and_then(|known| {
                    if known {
                        Ok(())
                    } else {
                        Err("thread-set-changed")
                    }
                })
        } else {
            Err("thread-context-unavailable")
        };
        if let Err(reason) = result {
            suspended.resume();
            return Err(reason);
        }
        Ok(suspended)
    }

    /// 停止中のいずれかのスレッドの命令ポインタが [start, end) にあるか。
    /// コンテキスト取得に失敗したスレッドは「範囲内」とみなし、安全側に倒す。
    fn any_ip_in_range(&self, start: usize, end: usize) -> bool {
        for &handle in &self.handles {
            let Ok(ip) = thread_instruction_pointer(handle) else {
                return true;
            };
            if (start..end).contains(&ip) {
                return true;
            }
        }
        false
    }

    /// 全スレッドを再開し、ハンドルを閉じる。
    fn resume(mut self) {
        let handles = std::mem::take(&mut self.handles);
        for &h in &handles {
            unsafe { ResumeThread(h) };
        }
        #[cfg(test)]
        crate::heap_watch::end();
        for h in handles {
            unsafe { CloseHandle(h) };
        }
    }
}

impl Drop for SuspendedThreads {
    fn drop(&mut self) {
        let handles = std::mem::take(&mut self.handles);
        for &h in &handles {
            unsafe { ResumeThread(h) };
        }
        #[cfg(test)]
        crate::heap_watch::end();
        for h in handles {
            unsafe { CloseHandle(h) };
        }
    }
}

/// DLL のエクスポートアドレスを解決する。モジュール未ロード・
/// 関数不在なら None。
fn resolve_export(module: &str, function: &str) -> Option<usize> {
    let wide: Vec<u16> = module.encode_utf16().chain([0]).collect();
    // SAFETY: モジュール名はヌル終端済み。
    let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    let name = std::ffi::CString::new(function).ok()?;
    // SAFETY: handle はロード済みモジュール、name はヌル終端済み。
    let proc = unsafe { GetProcAddress(handle, name.as_ptr() as *const u8) };
    follow_import_thunks(proc? as usize)
}

// kernel32 exports may be six-byte import thunks while CRT/API-set callers
// address kernelbase directly. Patch their common implementation. Never follow
// our own published detour (or an allocation-backed relay) on reattachment.
fn follow_import_thunks(mut address: usize) -> Option<usize> {
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };
    let module_at = |address: usize| {
        let mut module = std::ptr::null_mut();
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                address as *const u16,
                &mut module,
            );
        }
        module
    };
    let agent = module_at(follow_import_thunks as *const () as usize);
    for _ in 0..8 {
        let mut bytes = [0u8; 6];
        if !ProcessMemory.read_exact(address as u64, &mut bytes) || bytes[..2] != [0xff, 0x25] {
            return Some(address);
        }
        let displacement = u32::from_le_bytes(bytes[2..6].try_into().unwrap());
        #[cfg(target_pointer_width = "64")]
        let slot = (address as u64)
            .checked_add(6)?
            .checked_add_signed(displacement as i32 as i64)?;
        #[cfg(target_pointer_width = "32")]
        let slot = displacement as u64;
        let Some(next) = read_usize(slot).filter(|next| *next != 0) else {
            return Some(address);
        };
        let module = module_at(next);
        if module.is_null() || module == agent {
            return Some(address);
        }
        if next == address {
            return None;
        }
        address = next;
    }
    None
}

fn is_existing_detour(target: usize, detour: usize, bitness: u32, bytes: &[u8]) -> bool {
    if bytes.starts_with(&build_patch(target as u64, detour as u64, bitness)) {
        return true;
    }
    if bitness != 64 || bytes.len() < 5 || bytes[0] != 0xe9 {
        return false;
    }
    let displacement = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
    let relay = (target as u64)
        .wrapping_add(5)
        .wrapping_add_signed(displacement as i64);
    let mut relay_bytes = [0; 14];
    ProcessMemory.read_exact(relay, &mut relay_bytes)
        && relay_bytes.starts_with(&build_patch(relay, detour as u64, bitness))
}

/// `target` の近く（±2GB）に実行可能メモリを確保する。近くに空きが
/// 無ければ None（呼び出し側は全体確保＋絶対ジャンプへ切り替える）。
fn alloc_near(target: usize, size: usize) -> Option<usize> {
    const STEP: usize = 0x1_0000; // 64KB 境界
    const MAX_TRIES: usize = 256; // ±16MB まで探す
    let base = target & !(STEP - 1);
    for i in 1..=MAX_TRIES {
        for cand in [base.wrapping_sub(i * STEP), base.wrapping_add(i * STEP)] {
            // SAFETY: ヒント付き確保。失敗したら null が返るだけ。
            let p = unsafe {
                VirtualAlloc(
                    cand as *const c_void,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !p.is_null() {
                return Some(p as usize);
            }
        }
    }
    None
}

/// 対象アドレスへパッチバイト列を書き込む（保護属性を一時変更し、
/// 命令キャッシュを捨てる）。
fn patch_target(target: usize, patch: &[u8]) -> Result<(), ()> {
    patch_target_with(target, patch, || {})
}

fn patch_target_with(target: usize, patch: &[u8], before_write: impl FnOnce()) -> Result<(), ()> {
    let mut old: u32 = 0;
    // SAFETY: 呼び出し側が有効な対象アドレスを渡す。
    let ok = unsafe {
        VirtualProtect(
            target as *const c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
    };
    if ok == 0 {
        return Err(());
    }
    before_write();
    // SAFETY: 同上。書き込み後は元の保護属性へ戻す。
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, patch.len());
        let mut tmp: u32 = 0;
        VirtualProtect(target as *const c_void, patch.len(), old, &mut tmp);
        FlushInstructionCache(GetCurrentProcess(), target as *const c_void, patch.len());
    }
    Ok(())
}

// Published trampolines survive uninstall for late passthrough callers.
// Unpublished reservations are owned and reclaimed, including their budget.
static TRAMPOLINE_ALLOCATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

struct TrampolineAllocation {
    address: usize,
    published: bool,
}

impl TrampolineAllocation {
    fn reserve() -> Result<Self, &'static str> {
        use std::sync::atomic::Ordering::Relaxed;
        let mut count = TRAMPOLINE_ALLOCATIONS.load(Relaxed);
        loop {
            if count >= 4096 {
                return Err("retained-trampoline-limit");
            }
            match TRAMPOLINE_ALLOCATIONS.compare_exchange_weak(count, count + 1, Relaxed, Relaxed) {
                Ok(_) => {
                    return Ok(Self {
                        address: 0,
                        published: false,
                    })
                }
                Err(actual) => count = actual,
            }
        }
    }
}

impl Drop for TrampolineAllocation {
    fn drop(&mut self) {
        if !self.published {
            if self.address != 0 {
                // SAFETY: no original slot or patched entry has exposed this
                // allocation; prepared owners are dropped after thread resume.
                if unsafe { VirtualFree(self.address as *mut c_void, 0, MEM_RELEASE) } == 0 {
                    // Keep the reservation charged if release was not confirmed.
                    return;
                }
            }
            TRAMPOLINE_ALLOCATIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Prepare the trampoline and patch bytes before suspending any thread.
fn prepare_inline(
    p: &PlannedInline,
    bitness: u32,
) -> Result<(InlineHook, Vec<u8>, TrampolineAllocation), &'static str> {
    const TRAMPOLINE_SIZE: usize = 0x1000;
    const RELAY_OFFSET: usize = 0xf00;
    let mut allocation = TrampolineAllocation::reserve()?;
    let trampoline = match alloc_near(p.target, TRAMPOLINE_SIZE) {
        Some(t) => t,
        None => {
            // SAFETY: 全体確保。失敗したら null。
            let t = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    TRAMPOLINE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if t.is_null() {
                return Err("alloc-failed");
            }
            t as usize
        }
    };
    allocation.address = trampoline;
    let code = match build_trampoline(&p.plan, trampoline as u64) {
        Ok(c) => c,
        Err(e) => {
            return Err(e.reason());
        }
    };
    let direct_patch = build_patch(p.target as u64, p.detour as u64, bitness);
    let patch = if direct_patch.len() > p.plan.patch_len {
        let relay = trampoline + RELAY_OFFSET;
        let entry = build_patch(p.target as u64, relay as u64, bitness);
        if bitness != 64 || entry.len() > p.plan.patch_len || code.len() > RELAY_OFFSET {
            return Err("near-relay-unavailable");
        }
        let relay_code = build_patch(relay as u64, p.detour as u64, bitness);
        unsafe {
            std::ptr::copy_nonoverlapping(relay_code.as_ptr(), relay as *mut u8, relay_code.len());
        }
        entry
    } else {
        direct_patch
    };
    if code.len() > RELAY_OFFSET {
        return Err("trampoline-too-large");
    }
    // SAFETY: 確保したての実行可能領域へ書き込む。
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len());
        FlushInstructionCache(
            GetCurrentProcess(),
            trampoline as *const c_void,
            TRAMPOLINE_SIZE,
        );
    }
    Ok((
        InlineHook {
            api_id: p.slot.report_id(),
            target: p.target,
            trampoline,
            trampoline_size: TRAMPOLINE_SIZE,
            stolen_len: p.plan.stolen_len,
            original_bytes: p.original_bytes.clone(),
        },
        patch,
        allocation,
    ))
}

/// Allocate/decode before suspension; the stopped interval only inspects IPs,
/// publishes atomics and copies prepared bytes. Keep plans alive until resume.
fn install_planned(
    rt: &HookRuntime,
    plans: &[PlannedInline],
    bitness: u32,
) -> Vec<Result<InlineHook, &'static str>> {
    if plans.is_empty() {
        return Vec::new();
    }
    let _guard = ReentrancyGuard::try_enter();
    let mut prepared: Vec<_> = plans.iter().map(|p| prepare_inline(p, bitness)).collect();
    let mut status = vec![Ok(()); plans.len()];
    match SuspendedThreads::suspend_all() {
        Ok(suspender) => {
            for ((p, ready), result) in plans.iter().zip(&mut prepared).zip(&mut status) {
                let Ok((hook, patch, allocation)) = ready else {
                    continue;
                };
                if suspender.any_ip_in_range(p.target, p.target + p.plan.patch_len) {
                    *result = Err("thread-in-target");
                    continue;
                }
                if patch_target_with(p.target, patch, || {
                    // VirtualProtect has succeeded, so the only remaining steps
                    // publish the original and copy the patch. Once visible, retain
                    // the trampoline even if a later operation cannot complete.
                    allocation.published = true;
                    p.slot.set_original(rt, hook.trampoline);
                })
                .is_err()
                {
                    *result = Err("protect-failed");
                }
            }
            suspender.resume();
        }
        Err(reason) => status.fill(Err(reason)),
    }
    prepared
        .drain(..)
        .zip(status)
        .map(|(p, status)| {
            let (hook, _, allocation) = p?;
            status?;
            debug_assert!(allocation.published);
            Ok(hook)
        })
        .collect()
}

/// 全 API へ Inline Hook を設置する（L01）。設置の詳細は
/// `install_inline_hooks_for` を参照。
///
/// # Safety
/// `install_inline_hooks_for` と同じ前提。
pub unsafe fn install_inline_hooks(rt: &HookRuntime) -> InlineInstallOutcome {
    // SAFETY: install_inline_hooks_for と同じ前提。
    unsafe {
        install_inline_hooks_for(
            rt,
            api_table().filter(|api| !crate::api::is_internal_api(api.api_id)),
        )
    }
}

/// L15: 内部 API (Nt*) へ Inline Hook を設置する（詳細調査モード専用）。
/// 対象は `INTERNAL_API_TABLE` のみ。IAT フックは行わない（対象プロセスが
/// ntdll を直接インポートしていなくても、Inline Hook で捕捉できる）。
/// 詳細調査モードが無効な場合、Agent DLL はこれを呼ばない（設置自体を
/// しないため、通常モードの Detour オーバーヘッドは増えない）。
/// 設置は API ごとの best-effort であり、見送りがあっても初期化は成功
/// として継続する（L01 と同じ扱い）。
///
/// # Safety
/// `install_inline_hooks` と同じ前提。
pub unsafe fn install_internal_inline_hooks(rt: &HookRuntime) -> InlineInstallOutcome {
    // SAFETY: install_inline_hooks_for と同じ前提。
    unsafe { install_inline_hooks_for(rt, crate::api::INTERNAL_API_TABLE.iter()) }
}

/// Inline Hook の設置本体。`apis` に挙げた API へ Inline Hook を設置する。
///
/// IAT フックの後で呼ぶこと。成功した API の `original` は IAT 値
/// （生の関数アドレス）からトランポリンへ差し替える。Detour は
/// `original` を呼ぶため、IAT 経由・`GetProcAddress` 経由のどちらの
/// 呼び出しもトランポリン経由で元の関数へ届く。
///
/// 設置は API ごとの best-effort: 1 件の見送りは他に影響しない。
/// ただし他スレッドの停止に失敗した場合は全体を見送る（パッチ中の
/// 実行と競合させないため）。呼び出し側は `skipped` を Coverage へ写す。
///
/// # Safety
/// 対象プロセスの全スレッドを一時停止してからパッチするため、
/// 呼び出し元スレッド以外が対象 API の先頭命令を実行中でないことを
/// 確認してから書き換える。Loader Lock 下（DllMain 内）では呼ばないこと。
unsafe fn install_inline_hooks_for(
    rt: &HookRuntime,
    apis: impl Iterator<Item = &'static ApiDef>,
) -> InlineInstallOutcome {
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut outcome = InlineInstallOutcome::default();
    // 計画: 解決・デコードまでを先に行い、パッチ対象だけを残す。
    let mut planned: Vec<PlannedInline> = Vec::new();
    for api in apis {
        let target = match resolve_export(api.module, api.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((api.api_id, "not-exported"));
                continue;
            }
        };
        let detour = detour_for(api.api_id);
        // 先頭 32 バイトを読む（パッチ長＋再配置に要る最大 28 バイト分）。
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((api.api_id, "read-failed"));
            continue;
        }
        // 既に Detour へ向くパッチが入っている場合は二重設置しない。
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((api.api_id, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::Api(api.api_id),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((api.api_id, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((p.slot.report_id(), reason)),
        }
    }
    outcome
}

/// Inline Hook を解除する（L01）。復元できなかった api_id を返す。
/// トランポリンはプロセス終了まで保持する。停止時の IP が領域外でも、
/// Detour / Passthrough が取得済みのアドレスを後から呼ぶ可能性がある。
/// 全利用者の終了を証明する寿命管理が導入されるまでは解放できない。
/// 解除は IAT 復元より先に行うこと。
///
/// # Safety
/// `installed` は install_inline_hooks が返したものであり、対象モジュール
/// がまだロードされていること。
unsafe fn uninstall_inline_indices(installed: &[InlineHook]) -> Vec<usize> {
    if installed.is_empty() {
        return Vec::new();
    }
    let _guard = ReentrancyGuard::try_enter();
    let mut unrestored = Vec::with_capacity(installed.len());
    // スレッドを止められない場合は何も復元しない（全件を未復元として報告）。
    let Ok(suspender) = SuspendedThreads::suspend_all() else {
        return (0..installed.len()).collect();
    };
    for (index, h) in installed.iter().enumerate() {
        if suspender.any_ip_in_range(h.target, h.target + h.original_bytes.len()) {
            unrestored.push(index);
            continue;
        }
        match patch_target(h.target, &h.original_bytes) {
            Ok(()) => {}
            Err(()) => unrestored.push(index),
        }
    }
    suspender.resume();
    unrestored
}

/// Restore Inline hooks and report API IDs that could not be restored.
///
/// # Safety
/// Installed target modules must still be loaded, as for `uninstall_pending_inline_hooks`.
pub unsafe fn uninstall_inline_hooks(installed: &[InlineHook]) -> Vec<u32> {
    unsafe { uninstall_inline_indices(installed) }
        .into_iter()
        .map(|i| installed[i].api_id)
        .collect()
}

/// Retain only failed Inline restores. Published trampolines stay alive; only
/// restoration descriptors for successful hooks are discarded after resuming
/// all stopped threads. Index tracking also handles repeated API IDs correctly.
///
/// # Safety
/// All remaining targets must belong to the original loaded modules and this
/// caller must exclusively own hook installation and restoration.
pub unsafe fn uninstall_pending_inline_hooks(installed: &mut Vec<InlineHook>) -> usize {
    let failed = unsafe { uninstall_inline_indices(installed) };
    retain_failed_indices(installed, &failed);
    installed.len()
}

// ---- L02: COM Interception ----
//
// 方式は「オブジェクト単位の vtable 複製」（com.rs の文書を参照）。
// Factory 関数（CoCreateInstance / CoGetClassObject）には Inline Hook
// を設置し、返されたインターフェイスを起点に追跡する。返された
// オブジェクトの vtable を複製し、複製のスロットを COM メソッド用
// Detour へ向け、オブジェクトの vtable ポインタだけを複製へ向ける。
// 共有 vtable は書き換えないため、同じ実装の別オブジェクトには及ばない。
// Proxy を使わないため、アプリへ返すポインタの同一性は壊れない。
//
// 設置・解除の安全性:
// - Factory 関数の Inline Hook は L01 と同じ手順（全スレッド一時停止＋
//   命令ポインタ検査＋トランポリン近傍確保）で設置し、解除も
//   uninstall_inline_hooks で行う（agent-dll が保持する）。
// - オブジェクトの vtable 複製は、Factory / QueryInterface の Detour
//   の中で、ポインタがアプリへ返される前に行う。アプリの他スレッドが
//   そのポインタを持つことはまだ無いため、パッチ中の呼び出しと競合しない。
// - 複製 vtable とその登録は解放しない（Release で寿命が終わった後も、
//   他スレッドが呼び出し中かもしれないため。プロセス終了時に OS が回収する）。
//   そのためセッション終了後にアプリが COM メソッドを呼んでも、Detour は
//   登録から元のメソッドを引いて素通しで呼べる（記録はしない）。

/// オブジェクトへの vtable 複製による Detour 設置の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComInterceptOutcome {
    /// 複製 vtable を設置した。
    Intercepted,
    /// 既に設置済み（同じポインタへの二重設置はしない）。
    AlreadyIntercepted,
    /// 未知のインターフェイス（追跡対象としては記録するが、メソッドの
    /// Detour は設置しない。カスタムインターフェイスは未対応）。
    UnknownInterface,
    /// Factory / QI does not prove exclusive access to the returned object.
    SharedObjectSafetyUnproven,
    /// Installed only the three typed IUnknown methods in an image-backed table.
    IUnknownIntercepted,
    IUnknownAlreadyIntercepted,
    MethodInterceptionSkipped(&'static str),
    /// オブジェクト／元の vtable の読み取りに失敗した。
    ReadFailed,
    /// 複製 vtable の確保に失敗した。
    AllocFailed,
    /// オブジェクトの vtable ポインタの書き換えに失敗した。
    VtablePatchFailed,
}

/// COM Factory 関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct ComFactoryOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

fn com_factory_name(index: usize) -> &'static str {
    match index {
        COM_FACTORY_CO_CREATE_INSTANCE => "CoCreateInstance",
        COM_FACTORY_CO_GET_CLASS_OBJECT => "CoGetClassObject",
        _ => "?",
    }
}

fn winrt_activation_name(index: usize) -> &'static str {
    match index {
        WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE => "RoActivateInstance",
        WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY => "RoGetActivationFactory",
        _ => "?",
    }
}

fn callback_hook_name(index: usize) -> &'static str {
    CALLBACK_HOOKS
        .get(index)
        .map(|def| def.function)
        .unwrap_or("?")
}

/// 計画済み Inline Hook の表示名（見送り理由の報告用）。
fn planned_inline_name(p: &PlannedInline) -> &'static str {
    match p.slot {
        InlineOriginalSlot::Api(_) => "?",
        InlineOriginalSlot::ComFactory(i) => com_factory_name(i),
        InlineOriginalSlot::WinRtActivation(i) => winrt_activation_name(i),
        InlineOriginalSlot::Callback(i) => callback_hook_name(i),
    }
}

/// 対象プロセスのメモリから usize を 1 個読む。読めなければ None
/// （アクセス違反ではなく失敗として返す。レビュー #6 P0-3 と同じ方針）。
fn read_usize(addr: u64) -> Option<usize> {
    let mut buf = [0u8; std::mem::size_of::<usize>()];
    if ProcessMemory.read_exact(addr, &mut buf) {
        Some(usize::from_le_bytes(buf))
    } else {
        None
    }
}

/// 対象プロセスのメモリから GUID を 1 個読む。読めなければ None。
fn read_guid(addr: u64) -> Option<Guid> {
    if addr == 0 {
        return None;
    }
    let mut bytes = [0u8; 16];
    if ProcessMemory.read_exact(addr, &mut bytes) {
        Some(Guid { bytes })
    } else {
        None
    }
}

/// 対象プロセスのメモリへ usize を 1 個書く。保護属性を一時変更する。
/// 失敗したら Err（書き込み途中の半端な状態は残さない）。
fn write_usize(addr: u64, value: usize) -> Result<(), ()> {
    let mut old: u32 = 0;
    // SAFETY: 呼び出し側が有効な対象アドレスを渡す。
    let ok = unsafe {
        VirtualProtect(
            addr as *const c_void,
            std::mem::size_of::<usize>(),
            PAGE_READWRITE,
            &mut old,
        )
    };
    if ok == 0 {
        return Err(());
    }
    // SAFETY: 同上。
    unsafe {
        std::ptr::write_unaligned(addr as *mut usize, value);
        let mut tmp: u32 = 0;
        VirtualProtect(
            addr as *const c_void,
            std::mem::size_of::<usize>(),
            old,
            &mut tmp,
        );
    }
    Ok(())
}

/// COM Factory 関数（CoCreateInstance / CoGetClassObject）へ Inline Hook
/// を設置する（L02）。`Direct3DCreate9` はメソッド表が無いため設置しない
/// （KNOWN_FACTORIES の `hookable` が false）。
///
/// IAT フックの後・Inline Hook とは別に呼ぶこと。設置は Factory 関数
/// ごとの best-effort: 1 件の見送りは他に影響しない。ただし他スレッドの
/// 停止に失敗した場合は全体を見送る（L01 と同じ理由）。
///
/// # Safety
/// L01 の Inline Hook と同じ前提（Loader Lock 下では呼ばないこと）。
pub unsafe fn install_com_factory_hooks(rt: &HookRuntime) -> ComFactoryOutcome {
    let mut outcome = ComFactoryOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let factories: [(usize, usize); COM_FACTORY_COUNT] = [
        (
            COM_FACTORY_CO_CREATE_INSTANCE,
            detour_co_create_instance as CoCreateInstanceFn as usize,
        ),
        (
            COM_FACTORY_CO_GET_CLASS_OBJECT,
            detour_co_get_class_object as CoGetClassObjectFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in factories {
        let def = &KNOWN_FACTORIES[index];
        debug_assert!(def.hookable, "{} must be hookable", def.function);
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::ComFactory(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

/// WinRT アクティベーション関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct WinRtActivationOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

/// WinRT アクティベーション関数（RoActivateInstance /
/// RoGetActivationFactory）へ Inline Hook を設置する（L14）。
///
/// COM Factory 関数と同じ手順（全スレッド一時停止＋命令ポインタ検査＋
/// トランポリン近傍確保）で、IAT フックの後・Inline Hook とは別に呼ぶ
/// こと。設置は関数ごとの best-effort で、見送りがあっても初期化は
/// 成功として継続する（COM Factory と同じ扱い）。
///
/// # Safety
/// 対象プロセスの全スレッドを一時停止してからパッチするため、呼び出し元
/// スレッド以外が対象 API の先頭命令を実行中でないことを確認してから
/// 書き換える。Loader Lock 下（DllMain 内）では呼ばないこと。
pub unsafe fn install_winrt_activation_hooks(rt: &HookRuntime) -> WinRtActivationOutcome {
    let mut outcome = WinRtActivationOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let activations: [(usize, usize); WINRT_ACTIVATION_COUNT] = [
        (
            WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE,
            detour_ro_activate_instance as RoActivateInstanceFn as usize,
        ),
        (
            WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
            detour_ro_get_activation_factory as RoGetActivationFactoryFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in activations {
        let def = &WINRT_ACTIVATIONS[index];
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::WinRtActivation(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

/// コールバック検出フック関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct CallbackOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

/// コールバック検出フック関数（RegisterClassExW/A /
/// SetWindowLongPtrW/A）へ Inline Hook を設置する（L16）。
///
/// COM Factory 関数・WinRT アクティベーション関数と同じ手順（全スレッド
/// 一時停止＋命令ポインタ検査＋トランポリン近傍確保）で、IAT フックの後・
/// Inline Hook とは別に呼ぶこと。設置は関数ごとの best-effort で、見送りが
/// あっても初期化は成功として継続する（COM Factory と同じ扱い）。
///
/// # Safety
/// 対象プロセスの全スレッドを一時停止してからパッチするため、呼び出し元
/// スレッド以外が対象 API の先頭命令を実行中でないことを確認してから
/// 書き換える。Loader Lock 下（DllMain 内）では呼ばないこと。
pub unsafe fn install_callback_hooks(rt: &HookRuntime) -> CallbackOutcome {
    let mut outcome = CallbackOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let hooks: [(usize, usize); CALLBACK_HOOK_COUNT] = [
        (
            CALLBACK_HOOK_REGISTER_CLASS_EX_W,
            detour_register_class_ex_w as RegisterClassExFn as usize,
        ),
        (
            CALLBACK_HOOK_REGISTER_CLASS_EX_A,
            detour_register_class_ex_a as RegisterClassExFn as usize,
        ),
        (
            CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W,
            detour_set_window_long_ptr_w as SetWindowLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A,
            detour_set_window_long_ptr_a as SetWindowLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_WINDOW_LONG_PTR_W,
            detour_get_window_long_ptr_w as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_WINDOW_LONG_PTR_A,
            detour_get_window_long_ptr_a as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_CLASS_LONG_PTR_W,
            detour_get_class_long_ptr_w as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_CLASS_LONG_PTR_A,
            detour_get_class_long_ptr_a as GetLongPtrFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in hooks {
        let def = &CALLBACK_HOOKS[index];
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::Callback(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

fn retire_unloaded_com_address(tracker: &mut crate::com::ComTracker, ptr: u64) {
    if tracker
        .lookup(ptr)
        .and_then(|o| o.iunknown_slot)
        .is_some_and(crate::shared_com::installation_retired)
    {
        tracker.note_implementation_unloaded(ptr);
    }
}

/// Install typed IUnknown adapters without replacing the object's vptr.
///
/// # Safety
/// `ptr` must hold a valid owned COM reference throughout installation and
/// obey the IUnknown ABI and module lifetime contract of `shared_com::install`.
pub unsafe fn intercept_object(
    rt: &Arc<HookRuntime>,
    ptr: usize,
    iid: Guid,
) -> ComInterceptOutcome {
    if interface_by_iid(&iid).is_none() {
        return ComInterceptOutcome::UnknownInterface;
    }
    if rt.with_com_tracker(|t| t.lookup(ptr as u64).is_some_and(|o| o.intercepted)) {
        return ComInterceptOutcome::AlreadyIntercepted;
    }
    match unsafe { crate::shared_com::install(rt, ptr) } {
        Ok(installed) => {
            rt.with_com_tracker(|t| {
                t.note_iunknown_intercepted(ptr as u64, installed.table as u64, installed.slot)
            });
            if installed.newly_installed {
                ComInterceptOutcome::IUnknownIntercepted
            } else {
                ComInterceptOutcome::IUnknownAlreadyIntercepted
            }
        }
        Err(reason) => {
            rt.with_com_tracker(|t| t.note_interception_skipped_with_reason(ptr as u64, reason));
            ComInterceptOutcome::MethodInterceptionSkipped(reason)
        }
    }
}

/// 追跡対象のインターフェイスへ vtable 複製による Detour を設置する。
///
/// 手順：元の vtable とメソッド列を読み、複製を作って Detour で
/// スロットを置き換え、複製を登録し、オブジェクトの vtable ポインタを
/// 複製へ向ける。呼び出し側は、ポインタがアプリへ返される前（Factory /
/// QueryInterface の Detour の中）で呼ぶこと。
///
/// # Safety
/// `ptr` は有効な COM インターフェイスのポインタであり、呼び出し元が
/// 設置中に他スレッドがこのポインタでメソッドを呼ばないことを保証すること。
pub unsafe fn intercept_exclusive_object(
    rt: &HookRuntime,
    ptr: usize,
    iid: Guid,
) -> ComInterceptOutcome {
    let Some(def) = interface_by_iid(&iid) else {
        return ComInterceptOutcome::UnknownInterface;
    };
    if rt.with_com_tracker(|t| t.lookup(ptr as u64).is_some_and(|o| o.iunknown_intercepted)) {
        return ComInterceptOutcome::IUnknownAlreadyIntercepted;
    }
    let already =
        rt.with_com_tracker(|t| t.lookup(ptr as u64).map(|o| o.intercepted).unwrap_or(false));
    if already {
        return ComInterceptOutcome::AlreadyIntercepted;
    }
    let Some(vtbl) = read_usize(ptr as u64) else {
        return ComInterceptOutcome::ReadFailed;
    };
    if vtbl == 0 {
        return ComInterceptOutcome::ReadFailed;
    }
    // 既に複製 vtable を指している場合は二重設置しない（前セッションで
    // 設置された複製が残っている等）。登録から元の列を引いて追跡表へ
    // 記録し、設置済みとして扱う（元の vtable アドレスは不明のため 0）。
    if let Some(originals) = ComCloneRegistry::originals(vtbl as u64) {
        rt.with_com_tracker(|t| {
            t.note_intercepted(ptr as u64, 0, vtbl as u64, originals);
        });
        return ComInterceptOutcome::AlreadyIntercepted;
    }
    let count = def.methods.len();
    let mut originals = vec![0usize; count];
    for (i, slot) in originals.iter_mut().enumerate() {
        match read_usize(vtbl as u64 + (i * std::mem::size_of::<usize>()) as u64) {
            Some(v) => *slot = v,
            None => return ComInterceptOutcome::ReadFailed,
        }
    }
    let detours: Vec<(u32, usize)> = def
        .methods
        .iter()
        .filter_map(|m| com_detour_for(m.index, m.arity).map(|d| (m.index, d)))
        .collect();
    if detours.len() != count {
        // 既知メソッドに Detour が無い（実装の不整合）。設置しない。
        return ComInterceptOutcome::ReadFailed;
    }
    let cloned = build_cloned_vtable(&originals, &detours);
    let size = cloned.len() * std::mem::size_of::<usize>();
    // SAFETY: 複製 vtable 用の領域を確保する。データであり実行は不要。
    let mem = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if mem.is_null() {
        return ComInterceptOutcome::AllocFailed;
    }
    // SAFETY: 確保したての領域へ複製を書き込む。
    unsafe {
        std::ptr::copy_nonoverlapping(cloned.as_ptr(), mem as *mut usize, cloned.len());
    }
    // Detour が元のメソッドを引けるよう、複製のアドレスで登録する。
    // パッチに失敗しても登録は残る（リークするが安全。Detour は呼ばれない）。
    ComCloneRegistry::register(mem as u64, originals.iter().map(|a| *a as u64).collect());
    if write_usize(ptr as u64, mem as usize).is_err() {
        return ComInterceptOutcome::VtablePatchFailed;
    }
    // 診断用オプション：同一性の確認（標準では行わない）。
    if rt.with_com_tracker(|t| t.diagnostic_query_interface()) {
        diagnostic_confirm_identity(rt, ptr, &originals);
    }
    rt.with_com_tracker(|t| {
        t.note_intercepted(
            ptr as u64,
            vtbl as u64,
            mem as u64,
            originals.iter().map(|a| *a as u64).collect(),
        );
    });
    ComInterceptOutcome::Intercepted
}

/// 診断用オプション：Interceptor 自身が `QueryInterface(IID_IUnknown)`
/// を呼んで同一性を確認する。元の QI（vtable スロット 0 の元の
/// メソッド）を直接呼び、Detour は通さない（アプリの呼び出しとして
/// 記録しない）。成功したら返された IUnknown ポインタで同一性を確定し、
/// 参照カウントを戻すため Release（スロット 2 の元のメソッド）を呼ぶ。
/// 失敗しても追跡には影響しない。
fn diagnostic_confirm_identity(rt: &HookRuntime, ptr: usize, originals: &[usize]) {
    let qi = match originals.first() {
        Some(&f) if f != 0 => f,
        _ => return,
    };
    let release = match originals.get(2) {
        Some(&f) if f != 0 => f,
        _ => return,
    };
    type QueryInterfaceFn =
        unsafe extern "system-unwind" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type ReleaseFn = unsafe extern "system-unwind" fn(*mut c_void) -> u32;
    let mut unk: *mut c_void = std::ptr::null_mut();
    // SAFETY: qi / release は元の vtable から読んだ有効なメソッド。
    let hr = unsafe {
        std::mem::transmute::<usize, QueryInterfaceFn>(qi)(
            ptr as *mut c_void,
            &IID_IUNKNOWN,
            &mut unk,
        )
    };
    if hr != 0 || unk.is_null() {
        return;
    }
    rt.with_com_tracker(|t| t.note_identity_confirmed(ptr as u64, unk as u64));
    // 参照カウントを元へ戻す（QI で +1 された分）。
    unsafe {
        std::mem::transmute::<usize, ReleaseFn>(release)(unk);
    };
}

type Handle = *mut c_void;
type CreateFileWFn =
    unsafe extern "system-unwind" fn(*const u16, u32, u32, *mut c_void, u32, u32, Handle) -> Handle;
type ReadFileFn =
    unsafe extern "system-unwind" fn(Handle, *mut u8, u32, *mut u32, *mut c_void) -> i32;
type WriteFileFn =
    unsafe extern "system-unwind" fn(Handle, *const u8, u32, *mut u32, *mut c_void) -> i32;
type CloseHandleFn = unsafe extern "system-unwind" fn(Handle) -> i32;
type GetOverlappedResultFn =
    unsafe extern "system-unwind" fn(Handle, *mut c_void, *mut u32, i32) -> i32;
type GetQueuedCompletionStatusFn =
    unsafe extern "system-unwind" fn(Handle, *mut u32, *mut u64, *mut *mut c_void, u32) -> i32;

fn detour_for(api_id: u32) -> usize {
    match api_id {
        API_CREATE_FILE_W => (detour_create_file_w as CreateFileWFn) as usize,
        API_READ_FILE => (detour_read_file as ReadFileFn) as usize,
        API_WRITE_FILE => (detour_write_file as WriteFileFn) as usize,
        API_CLOSE_HANDLE => (detour_close_handle as CloseHandleFn) as usize,
        API_GET_OVERLAPPED_RESULT => {
            (detour_get_overlapped_result as GetOverlappedResultFn) as usize
        }
        API_GET_QUEUED_COMPLETION_STATUS => {
            (detour_get_queued_completion_status as GetQueuedCompletionStatusFn) as usize
        }
        // L15: 内部 API (Nt*) は汎用 Detour で中継する（手書きの
        // トランポリン。引数個数は Nt* のシグネチャ通り）。
        API_NT_CREATE_FILE => detour_nt_create_file as *const () as usize,
        API_NT_OPEN_FILE => detour_nt_open_file as *const () as usize,
        API_NT_READ_FILE => detour_nt_read_file as *const () as usize,
        API_NT_WRITE_FILE => detour_nt_write_file as *const () as usize,
        API_NT_CLOSE => detour_nt_close as *const () as usize,
        API_NT_QUERY_INFORMATION_FILE => detour_nt_query_information_file as *const () as usize,
        API_NT_SET_INFORMATION_FILE => detour_nt_set_information_file as *const () as usize,
        _ => detour_for_generated(api_id),
    }
}

// ---- L15: typed NT API detours ----
// Signatures follow windows-sys 0.59 Wdk::Storage::FileSystem definitions.
// Preserve NTSTATUS, access masks, enum widths, and nullable APC callbacks.
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, PIO_APC_ROUTINE};

macro_rules! nt_detour {
    ($name:ident, $api:expr, ($($arg:ident: $ty:ty => $raw:expr),* $(,)?)) => {
        unsafe extern "system-unwind" fn $name($($arg: $ty),*) -> i32 {
            generic_detour_with($api, &[$(($raw) as u64),*], |original| {
                let original: unsafe extern "system-unwind" fn($($ty),*) -> i32 =
                    unsafe { std::mem::transmute(original) };
                (unsafe { original($($arg),*) }) as u64
            }) as i32
        }
    };
}

nt_detour!(detour_nt_create_file, API_NT_CREATE_FILE, (
    a0: *mut Handle => a0 as usize,
    a1: u32 => a1 as usize,
    a2: *const OBJECT_ATTRIBUTES => a2 as usize,
    a3: *mut IO_STATUS_BLOCK => a3 as usize,
    a4: *const i64 => a4 as usize,
    a5: u32 => a5 as usize,
    a6: u32 => a6 as usize,
    a7: u32 => a7 as usize,
    a8: u32 => a8 as usize,
    a9: *const c_void => a9 as usize,
    a10: u32 => a10 as usize,
));
nt_detour!(detour_nt_open_file, API_NT_OPEN_FILE, (
    a0: *mut Handle => a0 as usize,
    a1: u32 => a1 as usize,
    a2: *const OBJECT_ATTRIBUTES => a2 as usize,
    a3: *mut IO_STATUS_BLOCK => a3 as usize,
    a4: u32 => a4 as usize,
    a5: u32 => a5 as usize,
));
nt_detour!(detour_nt_read_file, API_NT_READ_FILE, (
    a0: Handle => a0 as usize,
    a1: Handle => a1 as usize,
    a2: PIO_APC_ROUTINE => a2.map_or(0, |f| f as usize),
    a3: *const c_void => a3 as usize,
    a4: *mut IO_STATUS_BLOCK => a4 as usize,
    a5: *mut c_void => a5 as usize,
    a6: u32 => a6 as usize,
    a7: *const i64 => a7 as usize,
    a8: *const u32 => a8 as usize,
));
nt_detour!(detour_nt_write_file, API_NT_WRITE_FILE, (
    a0: Handle => a0 as usize,
    a1: Handle => a1 as usize,
    a2: PIO_APC_ROUTINE => a2.map_or(0, |f| f as usize),
    a3: *const c_void => a3 as usize,
    a4: *mut IO_STATUS_BLOCK => a4 as usize,
    a5: *const c_void => a5 as usize,
    a6: u32 => a6 as usize,
    a7: *const i64 => a7 as usize,
    a8: *const u32 => a8 as usize,
));
nt_detour!(detour_nt_close, API_NT_CLOSE, (
    a0: Handle => a0 as usize,
));
nt_detour!(detour_nt_query_information_file, API_NT_QUERY_INFORMATION_FILE, (
    a0: Handle => a0 as usize,
    a1: *mut IO_STATUS_BLOCK => a1 as usize,
    a2: *mut c_void => a2 as usize,
    a3: u32 => a3 as usize,
    a4: i32 => a4 as usize,
));
nt_detour!(detour_nt_set_information_file, API_NT_SET_INFORMATION_FILE, (
    a0: Handle => a0 as usize,
    a1: *mut IO_STATUS_BLOCK => a1 as usize,
    a2: *const c_void => a2 as usize,
    a3: u32 => a3 as usize,
    a4: i32 => a4 as usize,
));

// ---- L03: generated APIs share recording, not their function pointer types ----
// engine_generated.inc supplies typed invokers to generic_detour_with. The
// legacy arity helpers below are retained for the exclusive COM prototype.

type GenericFn0 = unsafe extern "system-unwind" fn() -> usize;
type GenericFn1 = unsafe extern "system-unwind" fn(usize) -> usize;
type GenericFn2 = unsafe extern "system-unwind" fn(usize, usize) -> usize;
type GenericFn3 = unsafe extern "system-unwind" fn(usize, usize, usize) -> usize;
type GenericFn4 = unsafe extern "system-unwind" fn(usize, usize, usize, usize) -> usize;
type GenericFn5 = unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize) -> usize;
type GenericFn6 =
    unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize, usize) -> usize;
type GenericFn7 =
    unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize, usize, usize) -> usize;
type GenericFn8 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;
type GenericFn9 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;
type GenericFn10 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;
type GenericFn11 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;
type GenericFn12 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;

/// 元の関数を引数個数 `N` で呼ぶ。`original` は設置時に保存した本物の
/// 関数ポインタであり、N は生成表の引数個数と一致する。
///
/// # Safety
/// 呼び出し側は `original` がこの `N` の `extern "system-unwind" fn` である
/// ことを保証すること（生成表とトランポリンが保証する）。
unsafe fn call_original<const N: usize>(original: usize, args: &[usize; N]) -> usize {
    // SAFETY: 各分岐は N に対応する引数個数の関数型へ transmute し、
    // その個数で呼ぶ。N > 12 は生成表に現れない（生成器の上限）。
    unsafe {
        match N {
            0 => std::mem::transmute::<usize, GenericFn0>(original)(),
            1 => std::mem::transmute::<usize, GenericFn1>(original)(args[0]),
            2 => std::mem::transmute::<usize, GenericFn2>(original)(args[0], args[1]),
            3 => std::mem::transmute::<usize, GenericFn3>(original)(args[0], args[1], args[2]),
            4 => std::mem::transmute::<usize, GenericFn4>(original)(
                args[0], args[1], args[2], args[3],
            ),
            5 => std::mem::transmute::<usize, GenericFn5>(original)(
                args[0], args[1], args[2], args[3], args[4],
            ),
            6 => std::mem::transmute::<usize, GenericFn6>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5],
            ),
            7 => std::mem::transmute::<usize, GenericFn7>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6],
            ),
            8 => std::mem::transmute::<usize, GenericFn8>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
            ),
            9 => std::mem::transmute::<usize, GenericFn9>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
            ),
            10 => std::mem::transmute::<usize, GenericFn10>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                args[9],
            ),
            11 => std::mem::transmute::<usize, GenericFn11>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                args[9], args[10],
            ),
            12 => std::mem::transmute::<usize, GenericFn12>(original)(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                args[9], args[10], args[11],
            ),
            _ => panic!("generic detour arity {N} exceeds 12"),
        }
    }
}

/// 生成 API の Detour 本体。手書き Detour と同じ手順
/// （prepare → enter 取得 → 元の呼び出し → leave 取得 → LastError 復元）
/// を、表駆動の汎用取得（`capture::generic_enter` / `generic_leave`）
/// で行う。失敗時の戻り値は 0（FALSE / NULL 相当。手書きの
/// CreateFileW が INVALID_HANDLE_VALUE を返すのとは異なり、生成 API
/// は全て NULL / FALSE が失敗値であるため 0 で足りる）。
fn generic_detour_with<const N: usize>(
    api_id: u32,
    args: &[u64; N],
    invoke: impl FnOnce(usize) -> u64 + Copy,
) -> u64 {
    let (rt, original, tid, api, _flight, mut guard, mut le) = match prepare(api_id) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, api, flight, guard, last_error),
        Prepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            return invoke(original);
        }
        Prepare::Unavailable => return 0,
    };
    let call_id = rt.alloc_call_id();
    {
        let bytes = capture::encode_generic_enter::<N>(api, args);
        rt.record_enter(tid, api, call_id, bytes.as_bytes());
    }
    if api.module.eq_ignore_ascii_case("kernel32.dll") && api.function == "ExitThread" {
        // ExitThread does not unwind Rust frames. Release recorder ownership
        // before entering the OS; otherwise DetourFlight and Arc references
        // survive forever and shutdown cannot drain. There is no normal Leave.
        // Stop capture before TLS/DllMain teardown starts, not only when this
        // DLL's native thread-detach callback is eventually reached.
        ReentrancyGuard::mark_thread_exiting();
        drop(_flight);
        drop(rt);
        drop(guard);
        le.restore_before_original();
        return invoke(original);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す。元の呼び出しの中で
    // アプリ由来の入れ子呼び出しが起きた場合は記録される (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    // Tuple field order drops CallGuard before the reentrancy/flight guards.
    // Option::take in the native finally prevents a second cleanup if Rust
    // also runs destructors (for example, a Rust panic through C-unwind).
    let (ret, (mut call_guard, rt, _flight, mut guard)) =
        crate::seh::invoke(original, invoke, (call_guard, rt, _flight, guard));
    let last_error = le.capture_after_original();
    call_guard.complete();
    // Loader heap operations may have destroyed the TLS vector in the original
    // call. Leave the call open for integrity reporting rather than touching
    // Rust TLS after teardown or inventing a normal completion.
    if !crate::runtime::native_tls_available() {
        le.restore_for_return();
        return ret;
    }
    guard.resume();
    pop_call(call_id);
    let bytes = capture::encode_generic_leave_with_inputs(api, ret, last_error, args);
    rt.record_leave(tid, api, call_id, bytes.as_bytes());
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

include!("engine_generated.inc");

// ---- L02: COM メソッド・Factory の Detour ----
//
// COM メソッドの Detour は (vtable インデックス, arity) の組ごとに
// 1 個の `extern "system-unwind" fn` である。Detour は `this` から追跡表を
// 引き、インターフェイス名・メソッド名を復元して記録する。同じ
// (index, arity) の組は全インターフェイスで共有できる（例：index 6
// arity 2 は IShellLinkW::GetDescription と IPersistFile::Save の両方）。
// 元のメソッドは複製 vtable のアドレスを鍵に ComCloneRegistry から引く
// ため、ランタイムが無いセッション終了後でも素通しで呼べる。
//
// 記録の手順は Win32 Detour と同じ（prepare 相当 → enter 取得 → 元の
// 呼び出し → leave 取得 → LastError 復元）。例外で中断した場合は
// ComCallGuard が CallAborted を記録する（L08）。

/// COM の失敗値（E_FAIL）。
const COM_E_FAIL: i32 = 0x8000_4005u32 as i32;

/// Factory 関数の Detour 共通の前処理。Win32 の `prepare` と同じ
/// 判定だが、ApiDef を持たないため元関数は Factory 別表から引く。
enum ComPrepare {
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

fn prepare_com(factory_index: usize) -> ComPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return ComPrepare::Unavailable;
        };
        let original = rt.com_original(factory_index);
        if original == 0 {
            return ComPrepare::Unavailable;
        }
        le.restore_before_original();
        return ComPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return ComPrepare::Unavailable;
    };
    let original = rt.com_original(factory_index);
    if original == 0 {
        return ComPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            ComPrepare::Passthrough { original }
        }
    }
}

type CoCreateInstanceFn = unsafe extern "system-unwind" fn(
    *const Guid,
    *mut c_void,
    u32,
    *const Guid,
    *mut *mut c_void,
) -> i32;
type CoGetClassObjectFn = unsafe extern "system-unwind" fn(
    *const Guid,
    u32,
    *mut c_void,
    *const Guid,
    *mut *mut c_void,
) -> i32;

/// Factory 呼び出しが返したインターフェイスを追跡対象に加え、既知
/// インターフェイスなら vtable 複製による Detour を設置する。
/// 設置の成否は呼び出しの成否に影響しない（best-effort）。
fn on_factory_result(rt: &Arc<HookRuntime>, factory: &'static str, iid: Guid, ptr: usize) {
    rt.with_com_tracker(|t| {
        retire_unloaded_com_address(t, ptr as u64);
        t.note_factory_result(ptr as u64, iid, factory);
    });
    if interface_by_iid(&iid).is_some() {
        // SAFETY: successful factory returned an owned live COM reference.
        let _ = unsafe { intercept_object(rt, ptr, iid) };
    }
}

unsafe extern "system-unwind" fn detour_co_create_instance(
    clsid: *const Guid,
    unk_outer: *mut c_void,
    cls_context: u32,
    iid: *const Guid,
    ppv: *mut *mut c_void,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) =
        match prepare_com(COM_FACTORY_CO_CREATE_INSTANCE) {
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, flight, guard, last_error),
            ComPrepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: CoCreateInstanceFn = unsafe { std::mem::transmute(original) };
                return unsafe { orig(clsid, unk_outer, cls_context, iid, ppv) };
            }
            ComPrepare::Unavailable => return COM_E_FAIL,
        };
    // SAFETY: 設置時に保存した本物の CoCreateInstance。
    let orig: CoCreateInstanceFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let requested = read_guid(iid as u64);
    let values = crate::com::com_factory_enter_values(&crate::com::ComFactoryArgs {
        method: "CoCreateInstance",
        clsid: read_guid(clsid as u64),
        iid: requested,
        context: cls_context,
        outer: unk_outer as u64,
        server_info: 0,
        output_address: ppv as u64,
        clsid_address: clsid as u64,
        iid_address: iid as u64,
    });
    if let Ok(bytes) = crate::com::encode_com_factory_enter(&values) {
        rt.record_com_factory_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        crate::com::COM_METHOD_API_ID,
        crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(clsid, unk_outer, cls_context, iid, ppv) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !ppv.is_null() {
        if let Some(ptr) = read_usize(ppv as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(iid_guid) = requested {
                on_factory_result(&rt, "CoCreateInstance", iid_guid, ptr);
            }
        }
    }
    let values = crate::com::com_factory_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_factory_leave(&values) {
        rt.record_com_factory_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

unsafe extern "system-unwind" fn detour_co_get_class_object(
    clsid: *const Guid,
    cls_context: u32,
    server_info: *mut c_void,
    iid: *const Guid,
    ppv: *mut *mut c_void,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) =
        match prepare_com(COM_FACTORY_CO_GET_CLASS_OBJECT) {
            ComPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, flight, guard, last_error),
            ComPrepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: CoGetClassObjectFn = unsafe { std::mem::transmute(original) };
                return unsafe { orig(clsid, cls_context, server_info, iid, ppv) };
            }
            ComPrepare::Unavailable => return COM_E_FAIL,
        };
    // SAFETY: 設置時に保存した本物の CoGetClassObject。
    let orig: CoGetClassObjectFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let requested = read_guid(iid as u64);
    let values = crate::com::com_factory_enter_values(&crate::com::ComFactoryArgs {
        method: "CoGetClassObject",
        clsid: read_guid(clsid as u64),
        iid: requested,
        context: cls_context,
        outer: 0,
        server_info: server_info as u64,
        output_address: ppv as u64,
        clsid_address: clsid as u64,
        iid_address: iid as u64,
    });
    if let Ok(bytes) = crate::com::encode_com_factory_enter(&values) {
        rt.record_com_factory_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        crate::com::COM_METHOD_API_ID,
        crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(clsid, cls_context, server_info, iid, ppv) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !ppv.is_null() {
        if let Some(ptr) = read_usize(ppv as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(iid_guid) = requested {
                on_factory_result(&rt, "CoGetClassObject", iid_guid, ptr);
            }
        }
    }
    let values = crate::com::com_factory_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_factory_leave(&values) {
        rt.record_com_factory_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

type RoActivateInstanceFn = unsafe extern "system-unwind" fn(usize, *mut *mut c_void) -> i32;
type RoGetActivationFactoryFn =
    unsafe extern "system-unwind" fn(usize, *const Guid, *mut *mut c_void) -> i32;

/// WinRT アクティベーション関数の Detour 共通の前処理。COM の
/// `prepare_com` と同じ判定だが、元関数は WinRT 別表から引く。
enum WinRtPrepare {
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

fn prepare_winrt(activation_index: usize) -> WinRtPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return WinRtPrepare::Unavailable;
        };
        let original = rt.winrt_original(activation_index);
        if original == 0 {
            return WinRtPrepare::Unavailable;
        }
        le.restore_before_original();
        return WinRtPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return WinRtPrepare::Unavailable;
    };
    let original = rt.winrt_original(activation_index);
    if original == 0 {
        return WinRtPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            WinRtPrepare::Record {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            WinRtPrepare::Passthrough { original }
        }
    }
}

// Share recording mechanics, but invoke each activation API with its own ABI.
fn detour_winrt_activation(
    activation_index: usize,
    function: &'static str,
    class_id: usize,
    iid: Option<*const Guid>,
    out: *mut *mut c_void,
    invoke: impl FnOnce(usize) -> i32 + Copy,
) -> i32 {
    let (rt, original, tid, _flight, mut guard, mut le) = match prepare_winrt(activation_index) {
        WinRtPrepare::Record {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        WinRtPrepare::Passthrough { original } => {
            return invoke(original);
        }
        WinRtPrepare::Unavailable => return COM_E_FAIL,
    };
    let requested_iid = match iid {
        Some(address) => read_guid(address as u64),
        None => Some(IID_IINSPECTABLE),
    };
    let raw = match iid {
        Some(address) => [class_id, address as usize, out as usize],
        None => [class_id, out as usize, 0],
    };
    let call_id = rt.alloc_call_id();
    // HSTRING からクラス名を読む。読めなければ空のまま記録する
    // （クラス名の読み取り失敗で呼び出し自体を失敗させない）。
    let class_name = crate::winrt::read_hstring_string(class_id).unwrap_or_default();
    let values = crate::winrt::winrt_activation_enter_values(
        0,
        &class_name,
        function,
        &crate::com::raw_arg_slots(&raw[..if iid.is_some() { 3 } else { 2 }]),
    );
    if let Ok(bytes) = crate::winrt::encode_winrt_activation_enter(&values) {
        rt.record_winrt_activation_enter(tid, call_id, &bytes);
    }
    drop(values);
    drop(class_name);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        WINRT_ACTIVATION_API_ID,
        WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (hr, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| invoke(original),
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    let _ = last_error; // WinRT は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !out.is_null() {
        if let Some(ptr) = read_usize(out as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            if let Some(requested_iid) = requested_iid {
                on_factory_result(&rt, function, requested_iid, ptr);
            }
        }
    }
    let values = crate::winrt::winrt_activation_leave_values(hr, returned_object);
    if let Ok(bytes) = crate::winrt::encode_winrt_activation_leave(&values) {
        rt.record_winrt_activation_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

unsafe extern "system-unwind" fn detour_ro_activate_instance(
    class_id: usize,
    out: *mut *mut c_void,
) -> i32 {
    detour_winrt_activation(
        WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE,
        "RoActivateInstance",
        class_id,
        None,
        out,
        |original| {
            let original: RoActivateInstanceFn = unsafe { std::mem::transmute(original) };
            unsafe { original(class_id, out) }
        },
    )
}

unsafe extern "system-unwind" fn detour_ro_get_activation_factory(
    class_id: usize,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    detour_winrt_activation(
        WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
        "RoGetActivationFactory",
        class_id,
        Some(iid),
        out,
        |original| {
            let original: RoGetActivationFactoryFn = unsafe { std::mem::transmute(original) };
            unsafe { original(class_id, iid, out) }
        },
    )
}

// ---- コールバック (L16) ----

/// コールバック検出フックと WndProc ラッパー共通の前処理。
/// `prepare_com` / `prepare_winrt` と同じ判定だが、元関数は呼び出し側が
/// 解決して渡す（検出フック関数はランタイムの別表、WndProc はスロット表から）。
///
/// WndProc の入口では Unavailable を返さない：ランタイムが無くても元の
/// プロシージャはスロット表から判明しているため、記録せず素通しで呼ぶ。
/// WndProc が 0 を返すとウィンドウ作成の失敗（WM_NCCREATE / WM_CREATE）
/// などアプリの挙動が変わるため、元のプロシージャを呼ばずに失敗値を
/// 返す経路は作らない。
enum CallbackPrepare {
    Proceed {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

/// コールバック検出フック関数の Detour 共通の前処理。元関数はランタイムの
/// コールバック別表から引く（`prepare_com` と同じ形）。
fn prepare_callback_hook(hook_index: usize) -> CallbackPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return CallbackPrepare::Unavailable;
        };
        let original = rt.callback_original(hook_index);
        if original == 0 {
            return CallbackPrepare::Unavailable;
        }
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return CallbackPrepare::Unavailable;
    };
    let original = rt.callback_original(hook_index);
    if original == 0 {
        return CallbackPrepare::Unavailable;
    }
    // COM methods are observable even when called through a runtime.
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            CallbackPrepare::Proceed {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            CallbackPrepare::Passthrough { original }
        }
    }
}

/// WndProc ラッパーの前処理。元関数はスロット表から判明済みのため、
/// ランタイムが無くても Passthrough で元のプロシージャを呼ぶ。
fn prepare_callback_dispatch(original: usize) -> CallbackPrepare {
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(guard) = ReentrancyGuard::try_enter() else {
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        // ランタイムが無い（終了手順の後など）：記録せず素通しで呼ぶ。
        le.restore_before_original();
        return CallbackPrepare::Passthrough { original };
    };
    // L23: 呼び出し元は user32.dll の DispatchMessageW（Windows 分類）の
    // ため通常は抑制されない。Runtime 分類の場合は記録しない。
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            CallbackPrepare::Proceed {
                rt,
                original,
                tid,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            CallbackPrepare::Passthrough { original }
        }
    }
}

/// WndProc の型（`extern "system-unwind" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT`）。
type WndProcFn = unsafe extern "system-unwind" fn(*mut c_void, u32, usize, isize) -> isize;
type RegisterClassExFn = unsafe extern "system-unwind" fn(*const c_void) -> u16;
type SetWindowLongPtrFn = unsafe extern "system-unwind" fn(*mut c_void, i32, usize) -> usize;

/// WndProc ラッパー 1 件。スロット番号を固定で持ち、共通の dispatch へ渡す。
macro_rules! wnd_proc_wrapper {
    ($name:ident, $slot:expr) => {
        unsafe extern "system-unwind" fn $name(
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> isize {
            unsafe { wnd_proc_dispatch($slot, hwnd, msg, wparam, lparam) }
        }
    };
}

macro_rules! wnd_proc_wrappers {
    ($($name:ident = $slot:expr),* $(,)?) => {
        $(wnd_proc_wrapper!($name, $slot);)*
        /// スロット番号順の WndProc ラッパー関数列。
        static CALLBACK_WRAPPERS: [WndProcFn; CALLBACK_PROC_SLOTS] = [
            $($name as WndProcFn),*
        ];
    };
}

wnd_proc_wrappers!(
    wnd_proc_wrapper_00 = 0,
    wnd_proc_wrapper_01 = 1,
    wnd_proc_wrapper_02 = 2,
    wnd_proc_wrapper_03 = 3,
    wnd_proc_wrapper_04 = 4,
    wnd_proc_wrapper_05 = 5,
    wnd_proc_wrapper_06 = 6,
    wnd_proc_wrapper_07 = 7,
    wnd_proc_wrapper_08 = 8,
    wnd_proc_wrapper_09 = 9,
    wnd_proc_wrapper_10 = 10,
    wnd_proc_wrapper_11 = 11,
    wnd_proc_wrapper_12 = 12,
    wnd_proc_wrapper_13 = 13,
    wnd_proc_wrapper_14 = 14,
    wnd_proc_wrapper_15 = 15,
    wnd_proc_wrapper_16 = 16,
    wnd_proc_wrapper_17 = 17,
    wnd_proc_wrapper_18 = 18,
    wnd_proc_wrapper_19 = 19,
    wnd_proc_wrapper_20 = 20,
    wnd_proc_wrapper_21 = 21,
    wnd_proc_wrapper_22 = 22,
    wnd_proc_wrapper_23 = 23,
    wnd_proc_wrapper_24 = 24,
    wnd_proc_wrapper_25 = 25,
    wnd_proc_wrapper_26 = 26,
    wnd_proc_wrapper_27 = 27,
    wnd_proc_wrapper_28 = 28,
    wnd_proc_wrapper_29 = 29,
    wnd_proc_wrapper_30 = 30,
    wnd_proc_wrapper_31 = 31,
);

/// スロット番号からラッパー関数のアドレスを引く。
fn wrapper_for_slot(slot: usize) -> Option<usize> {
    CALLBACK_WRAPPERS.get(slot).map(|f| *f as usize)
}

/// ラッパー関数のアドレスからスロット番号を引く。ラッパーでなければ None。
fn slot_for_wrapper(wrapper: usize) -> Option<usize> {
    CALLBACK_WRAPPERS
        .iter()
        .position(|f| *f as usize == wrapper)
}

/// ラッパー関数のアドレスから元の WndProc を引く。ラッパーでなければ None。
fn original_for_wrapper(wrapper: usize) -> Option<usize> {
    slot_for_wrapper(wrapper).and_then(|slot| callback_procs().original(slot))
}

/// ラップされた WndProc の本体。コールバック enter を記録し、呼出スタックへ
/// 積んでから元のプロシージャを呼ぶ。コールバック中の API 呼び出しは
/// このイベントを親として入れ子に記録される（A43 / C18）。
/// 元のプロシージャが例外で中断したら、ComCallGuard が CallAborted を
/// 記録する（L08。例外は捕捉しない）。
unsafe fn wnd_proc_dispatch(
    slot: usize,
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let Some(original) = callback_procs().original(slot) else {
        // 到達しないはずの防御：スロットが空なら元のプロシージャは
        // 呼べない。0 を返す（呼ぶ先が無いため他に手段が無い）。
        return 0;
    };
    // SAFETY: スロット表から引いた元のプロシージャ。
    let orig: WndProcFn = unsafe { std::mem::transmute(original) };
    let (rt, tid, _flight, mut guard, mut le) = match prepare_callback_dispatch(original) {
        CallbackPrepare::Proceed {
            rt,
            original: _,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: スロット表から引いた元のプロシージャ。
            let orig: WndProcFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(hwnd, msg, wparam, lparam) };
        }
        CallbackPrepare::Unavailable => return 0,
    };
    let call_id = rt.alloc_call_id();
    let values = crate::callback::callback_enter_values(
        hwnd as u64,
        CallbackKind::WndProc,
        msg,
        wparam as u64,
        lparam as i64,
        original as u64,
    );
    if let Ok(bytes) = crate::callback::encode_callback_enter(&values) {
        rt.record_callback_enter(tid, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元のプロシージャが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard =
        ComCallGuard::new_for(&rt, tid, call_id, CALLBACK_API_ID, CALLBACK_LEAVE_SCHEMA_ID);
    le.restore_before_original();
    guard.suspend();
    // SAFETY: スロット表から引いた元のプロシージャ。
    let (result, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(hwnd, msg, wparam, lparam) },
        (call_guard, rt, _flight, guard),
    );
    let _ = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let values = crate::callback::callback_leave_values(result as i64);
    if let Ok(bytes) = crate::callback::encode_callback_leave(&values) {
        rt.record_callback_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    result
}

/// `RegisterClassExW/A` の構造体バイト列を読む。`cbSize` が範囲外・
/// 読めない場合は None（素通し）。
fn read_class_bytes(wc: *const c_void) -> Option<Vec<u8>> {
    if wc.is_null() {
        return None;
    }
    let mut size_buf = [0u8; 4];
    if !ProcessMemory.read_exact(wc as u64, &mut size_buf) {
        return None;
    }
    let cb_size = u32::from_le_bytes(size_buf) as usize;
    if !(16..=MAX_WNDCLASSEX_BYTES).contains(&cb_size) {
        return None;
    }
    let mut buf = vec![0u8; cb_size];
    if !ProcessMemory.read_exact(wc as u64, &mut buf) {
        return None;
    }
    Some(buf)
}

/// `RegisterClassExW/A` の Detour 本体。アプリが渡した構造体のコピーを
/// 作り、コピー内の `lpfnWndProc` だけをラッパーへすり替えて元の関数へ
/// 渡す。読めない・`cbSize` が範囲外・ラップできない場合は素通しする
/// （クラス登録自体は成功させ、コールバックの記録だけが無い）。
/// この Detour 自体は API 呼び出しイベントを記録しない（RegisterClassEx
/// は API 表に無い）。記録されるのはラッパー経由のコールバックである。
unsafe fn detour_register_class_ex(hook_index: usize, wc: *const c_void) -> u16 {
    let (_rt, original, _tid, _flight, mut guard, mut le) = match prepare_callback_hook(hook_index)
    {
        CallbackPrepare::Proceed {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: ランタイムの別表から引いた元の関数。
            let orig: RegisterClassExFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(wc) };
        }
        CallbackPrepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した元の RegisterClassEx。
    let orig: RegisterClassExFn = unsafe { std::mem::transmute(original) };
    // 構造体をコピーし、コピー内の lpfnWndProc だけをラッパーへすり替える。
    // 読めない・cbSize が範囲外・ラップできない場合は None（素通し）。
    let replaced: Option<Vec<u8>> = read_class_bytes(wc).and_then(|bytes| {
        let original_proc = read_usize(wc as u64 + WNDPROC_FIELD_OFFSET as u64)?;
        let slot = callback_procs().wrap(original_proc)?;
        let wrapper = wrapper_for_slot(slot)?;
        wrap_wndproc_in_class(&bytes, wrapper).map(|(_, replaced)| replaced)
    });
    let call_with: *const c_void = match &replaced {
        Some(bytes) => bytes.as_ptr() as *const c_void,
        None => wc,
    };
    le.restore_before_original();
    guard.suspend();
    // SAFETY: コピーした構造体（または元の構造体）を渡す。
    let (result, (_rt, _flight, mut guard, replaced)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(call_with) },
        (_rt, _flight, guard, replaced),
    );
    let _ = le.capture_after_original();
    guard.resume();
    drop(replaced);
    le.restore_for_return();
    result
}

unsafe extern "system-unwind" fn detour_register_class_ex_w(wc: *const c_void) -> u16 {
    unsafe { detour_register_class_ex(CALLBACK_HOOK_REGISTER_CLASS_EX_W, wc) }
}

unsafe extern "system-unwind" fn detour_register_class_ex_a(wc: *const c_void) -> u16 {
    unsafe { detour_register_class_ex(CALLBACK_HOOK_REGISTER_CLASS_EX_A, wc) }
}

/// `SetWindowLongPtrW/A` の Detour 本体。`GWLP_WNDPROC` の差し替えだけを
/// ラップする。それ以外（他のインデックス・0 の指定）は素通しする。
/// 戻り値が shirusu のラッパーだった場合は元のプロシージャへ解決して
/// アプリへ返す（アプリはラッパーの存在を観測しない）。
/// この Detour 自体は API 呼び出しイベントを記録しない（SetWindowLongPtr
/// は API 表に無い）。記録されるのはラッパー経由のコールバックである。
unsafe fn detour_set_window_long_ptr(
    hook_index: usize,
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    let (_rt, original, _tid, _flight, mut guard, mut le) = match prepare_callback_hook(hook_index)
    {
        CallbackPrepare::Proceed {
            rt,
            original,
            tid,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, flight, guard, last_error),
        CallbackPrepare::Passthrough { original } => {
            // SAFETY: ランタイムの別表から引いた元の関数。
            let orig: SetWindowLongPtrFn = unsafe { std::mem::transmute(original) };
            let prev = unsafe { orig(hwnd, n_index, new_long) };
            let last_error = crate::last_error::get();
            let prev = resolve_window_long(n_index, prev);
            crate::last_error::set(last_error);
            return prev;
        }
        CallbackPrepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した元の SetWindowLongPtr。
    let orig: SetWindowLongPtrFn = unsafe { std::mem::transmute(original) };
    let mut call_with = new_long;
    if should_wrap_set_window_long(n_index, new_long) {
        // 既にラッパーになっている値（アプリが GetWindowLongPtrW で
        // 読み戻したもの）をそのまま渡した場合は二重ラップしない。
        if slot_for_wrapper(new_long).is_none() {
            if let Some(slot) = callback_procs().wrap(new_long) {
                if let Some(wrapper) = wrapper_for_slot(slot) {
                    call_with = wrapper;
                }
            }
        }
    }
    le.restore_before_original();
    guard.suspend();
    // SAFETY: ラップ済みまたは元の値を渡す。
    let (prev, (_rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(hwnd, n_index, call_with) },
        (_rt, _flight, guard),
    );
    let _ = le.capture_after_original();
    guard.resume();
    // Only GWLP_WNDPROC contains a procedure. User data and other fields must
    // remain bit-for-bit identical even if they happen to equal a wrapper.
    let prev = resolve_window_long(n_index, prev);
    le.restore_for_return();
    prev
}

fn resolve_window_long(field: i32, value: usize) -> usize {
    if field == crate::callback::GWLP_WNDPROC {
        resolve_prev_proc(value, original_for_wrapper)
    } else {
        value
    }
}

type GetLongPtrFn = unsafe extern "system-unwind" fn(*mut c_void, i32) -> usize;

unsafe fn detour_get_long_ptr(
    index: usize,
    hwnd: *mut c_void,
    field: i32,
    proc_field: i32,
) -> usize {
    let (original, state) = match prepare_callback_hook(index) {
        CallbackPrepare::Proceed {
            original,
            rt,
            tid: _,
            flight,
            guard,
            last_error,
        } => (original, Some((rt, flight, guard, last_error))),
        CallbackPrepare::Passthrough { original } => (original, None),
        CallbackPrepare::Unavailable => return 0,
    };
    let original: GetLongPtrFn = unsafe { std::mem::transmute(original) };
    let mut state = state;
    if let Some((_, _, guard, le)) = state.as_mut() {
        le.restore_before_original();
        guard.suspend();
    }
    let (value, mut state) = crate::seh::invoke(0, |_| unsafe { original(hwnd, field) }, state);
    // LastError must be captured before table lookups or synchronization.
    let saved_error = crate::last_error::get();
    if let Some((_, _, guard, _)) = state.as_mut() {
        guard.resume();
    }
    let value = if field == proc_field {
        resolve_prev_proc(value, original_for_wrapper)
    } else {
        value
    };
    crate::last_error::set(saved_error);
    value
}
unsafe extern "system-unwind" fn detour_get_window_long_ptr_w(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_WINDOW_LONG_PTR_W, hwnd, field, -4) }
}
unsafe extern "system-unwind" fn detour_get_window_long_ptr_a(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_WINDOW_LONG_PTR_A, hwnd, field, -4) }
}
unsafe extern "system-unwind" fn detour_get_class_long_ptr_w(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_CLASS_LONG_PTR_W, hwnd, field, -24) }
}
unsafe extern "system-unwind" fn detour_get_class_long_ptr_a(
    hwnd: *mut c_void,
    field: i32,
) -> usize {
    unsafe { detour_get_long_ptr(CALLBACK_HOOK_GET_CLASS_LONG_PTR_A, hwnd, field, -24) }
}

unsafe extern "system-unwind" fn detour_set_window_long_ptr_w(
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    unsafe {
        detour_set_window_long_ptr(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W, hwnd, n_index, new_long)
    }
}

unsafe extern "system-unwind" fn detour_set_window_long_ptr_a(
    hwnd: *mut c_void,
    n_index: i32,
    new_long: usize,
) -> usize {
    unsafe {
        detour_set_window_long_ptr(CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A, hwnd, n_index, new_long)
    }
}

/// 元の COM メソッドを呼ぶ。`args` は `this` を除く引数（最大 4 個）。
///
/// # Safety
/// `original` はこの引数個数の `extern "system-unwind" fn` であること
/// （呼び出し側は追跡表のメソッド定義で arity を確認している）。
unsafe fn call_com_original(original: usize, this: usize, args: &[usize]) -> i32 {
    // SAFETY: 各分岐は引数個数に対応する関数型へ transmute し、その個数で呼ぶ。
    // 戻り値は HRESULT（i32）の下位 32 ビット。
    unsafe {
        match args.len() {
            0 => call_original::<1>(original, &[this]) as i32,
            1 => call_original::<2>(original, &[this, args[0]]) as i32,
            2 => call_original::<3>(original, &[this, args[0], args[1]]) as i32,
            3 => call_original::<4>(original, &[this, args[0], args[1], args[2]]) as i32,
            4 => call_original::<5>(original, &[this, args[0], args[1], args[2], args[3]]) as i32,
            _ => COM_E_FAIL,
        }
    }
}

/// 元の COM メソッド呼び出しの後の追跡更新（QI / AddRef / Release）。
/// 戻り値は (returned_object, refcount) で leave 値列へ載せる。
fn com_method_post_call(
    rt: &Arc<HookRuntime>,
    this: usize,
    instance: &crate::com::ComInstanceToken,
    method_index: u32,
    args: &[usize],
    ret: i32,
) -> (u64, u32) {
    match method_index {
        0 => {
            // QueryInterface: 成功時に返されたポインタを追跡対象に加え、
            // 既知インターフェイスなら Detour を設置する（アプリへ返す前）。
            if ret != 0 || args.len() < 2 {
                return (0, 0);
            }
            let Some(iid) = read_guid(args[0] as u64) else {
                return (0, 0);
            };
            let Some(out) = read_usize(args[1] as u64) else {
                return (0, 0);
            };
            if out == 0 {
                return (0, 0);
            }
            rt.with_com_tracker(|t| {
                retire_unloaded_com_address(t, this as u64);
                retire_unloaded_com_address(t, out as u64);
                if t.instance_matches(this as u64, instance) {
                    t.note_query_interface(this as u64, out as u64, iid, true);
                } else {
                    // A later discovery has replaced this address while the
                    // original call was in progress. Do not merge lifetimes.
                    t.note_discovered(out as u64, iid);
                }
            });
            if interface_by_iid(&iid).is_some() {
                // SAFETY: out は元の QI が返した有効なインターフェイス。
                // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
                let _ = unsafe { intercept_object(rt, out, iid) };
            }
            (out as u64, 0)
        }
        1 => {
            // AddRef: 戻り値が新しい参照カウント。
            let count = ret as u32;
            rt.with_com_tracker(|t| {
                if t.instance_matches(this as u64, instance) {
                    t.note_add_ref(this as u64, count);
                }
            });
            (0, count)
        }
        2 => {
            // Release: 戻り値が新しい参照カウント。0 なら寿命終了。
            let count = ret as u32;
            rt.with_com_tracker(|t| {
                if t.instance_matches(this as u64, instance) {
                    t.note_release(this as u64, count);
                }
            });
            (0, count)
        }
        _ => {
            // L14: WinRT のインターフェイス返却メソッド（ActivateInstance /
            // CreateUri / CreateWithRelativeUri / CombineUri）。成功時に
            // out 引数のインターフェイスを追跡対象に加え、既知なら Detour
            // を設置する（アプリへ返す前）。表に無いメソッドは (0, 0)。
            if ret != 0 {
                return (0, 0);
            }
            let Some((method_name, out_arg, iid)) = rt.with_com_tracker(|t| {
                if !t.instance_matches(this as u64, instance) {
                    return None;
                }
                t.lookup(this as u64).and_then(|o| {
                    interface_by_iid(&o.iid).and_then(|d| {
                        d.method(method_index).and_then(|m| {
                            winrt_method_return(d.name, method_index)
                                .map(|(out_arg, iid)| (m.name, out_arg, iid))
                        })
                    })
                })
            }) else {
                return (0, 0);
            };
            let Some(ptr) = args
                .get(out_arg)
                .and_then(|&a| read_usize(a as u64))
                .filter(|p| *p != 0)
            else {
                return (0, 0);
            };
            rt.with_com_tracker(|t| {
                retire_unloaded_com_address(t, ptr as u64);
                t.note_method_returned(ptr as u64, iid, this as u64, method_name);
            });
            if interface_by_iid(&iid).is_some() {
                // SAFETY: ptr は元のメソッドが返した有効なインターフェイス。
                // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
                let _ = unsafe { intercept_object(rt, ptr, iid) };
            }
            (ptr as u64, 0)
        }
    }
}

/// COM メソッドの Detour 本体。`this` から複製 vtable を引き、元の
/// メソッドを呼ぶ。追跡表に無いオブジェクト（前セッションで設置された
/// 複製 vtable を持つ等）は、元のメソッドを素通しで呼ぶ（記録しない）。
fn com_method_dispatch(this: usize, method_index: u32, args: &[usize]) -> i32 {
    // 複製 vtable から元のメソッドを引く（ランタイムが無くても引ける。
    // セッション終了後にアプリが COM メソッドを呼んだ場合の素通し用）。
    let vtbl = match read_usize(this as u64) {
        Some(v) if v != 0 => v,
        _ => return COM_E_FAIL,
    };
    let original = match ComCloneRegistry::original(vtbl as u64, method_index) {
        Some(o) if o != 0 => o as usize,
        _ => return COM_E_FAIL,
    };
    com_method_dispatch_with(this, method_index, args, original, None, |original| {
        // SAFETY: the exclusive-object adapter supplies this exact ABI.
        unsafe { call_com_original(original, this, args) }
    })
}

/// Shared IUnknown adapters supply typed invokers and their installation's
/// owner. Old cached wrappers never attach themselves to a newer session.
pub(crate) fn com_method_dispatch_with(
    this: usize,
    method_index: u32,
    args: &[usize],
    original: usize,
    owner: Option<&std::sync::Weak<HookRuntime>>,
    invoke: impl FnOnce(usize) -> i32 + Copy,
) -> i32 {
    let mut le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(mut guard) = ReentrancyGuard::try_enter() else {
        le.restore_before_original();
        // SAFETY: original はこの引数個数の COM メソッド。
        return invoke(original);
    };
    let rt = match owner {
        Some(owner) => owner.upgrade(),
        None => crate::runtime::runtime_slot().for_detour(),
    };
    let Some(rt) = rt else {
        le.restore_before_original();
        // SAFETY: 同上。
        return invoke(original);
    };
    // COM methods are observable even when called through a runtime.
    let Some(flight) = crate::runtime::DetourFlight::begin(&rt) else {
        le.restore_before_original();
        // SAFETY: 同上。
        return invoke(original);
    };
    let _flight = flight;
    // 追跡対象の確認：このセッションで追跡していないオブジェクトは
    // 元のメソッドを素通しで呼ぶ（記録しない）。
    let (iid, interface_name, method_name, instance) = match rt.with_com_tracker(|t| {
        retire_unloaded_com_address(t, this as u64);
        let instance = t.instance_token(this as u64)?;
        t.lookup(this as u64).and_then(|o| {
            interface_by_iid(&o.iid).and_then(|d| {
                d.method(method_index)
                    .map(|m| (o.iid, d.name, m.name, instance))
            })
        })
    }) {
        Some(v) => v,
        None => {
            le.restore_before_original();
            // SAFETY: original はこの引数個数の COM メソッド。
            return invoke(original);
        }
    };
    let tid = crate::thread_id::current() as u64;
    rt.ensure_thread(tid);
    let call_id = rt.alloc_call_id();
    // enter: QI では target_iid に要求された IID を読む。
    let target_iid: Vec<u8> = if method_index == 0 && !args.is_empty() {
        read_guid(args[0] as u64)
            .map(|g| g.bytes.to_vec())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let method_display = format!("{interface_name}::{method_name}");
    let values = crate::com::com_method_enter_values(
        this as u64,
        &iid.bytes,
        method_index,
        &method_display,
        &crate::com::raw_arg_slots(args),
        &target_iid,
    );
    if let Ok(bytes) = crate::com::encode_com_enter(&values) {
        rt.record_com_enter(tid, call_id, &bytes);
    }
    drop(values);
    drop(target_iid);
    drop(method_display);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = ComCallGuard::new(&rt, tid, call_id);
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: original はこの引数個数の COM メソッド。
    let (ret, (mut call_guard, rt, _flight, mut guard, instance)) =
        crate::seh::invoke(original, invoke, (call_guard, rt, _flight, guard, instance));
    let last_error = le.capture_after_original();
    call_guard.complete();
    if !crate::runtime::native_tls_available() {
        le.restore_for_return();
        return ret;
    }
    guard.resume();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let (returned_object, refcount) =
        com_method_post_call(&rt, this, &instance, method_index, args, ret);
    let values =
        crate::com::com_method_leave_values_for(method_index, ret, returned_object, refcount);
    if let Ok(bytes) = crate::com::encode_com_leave(&values) {
        rt.record_com_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

macro_rules! com_method_detour {
    ($name:ident, $index:expr, 0) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void) -> i32 {
            com_method_dispatch(this as usize, $index, &[])
        }
    };
    ($name:ident, $index:expr, 1) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void, a0: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0])
        }
    };
    ($name:ident, $index:expr, 2) => {
        unsafe extern "system-unwind" fn $name(this: *mut c_void, a0: usize, a1: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1])
        }
    };
    ($name:ident, $index:expr, 3) => {
        unsafe extern "system-unwind" fn $name(
            this: *mut c_void,
            a0: usize,
            a1: usize,
            a2: usize,
        ) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1, a2])
        }
    };
    ($name:ident, $index:expr, 4) => {
        unsafe extern "system-unwind" fn $name(
            this: *mut c_void,
            a0: usize,
            a1: usize,
            a2: usize,
            a3: usize,
        ) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1, a2, a3])
        }
    };
}

// (vtable インデックス, arity) の組ごとの Detour。同じ組は全
// インターフェイスで共有する（Detour は `this` から追跡表を引くため）。
com_method_detour!(com_d_0_2, 0, 2);
com_method_detour!(com_d_1_0, 1, 0);
com_method_detour!(com_d_2_0, 2, 0);
com_method_detour!(com_d_3_4, 3, 4);
com_method_detour!(com_d_3_1, 3, 1);
com_method_detour!(com_d_3_2, 3, 2);
com_method_detour!(com_d_4_1, 4, 1);
com_method_detour!(com_d_4_0, 4, 0);
com_method_detour!(com_d_5_1, 5, 1);
com_method_detour!(com_d_5_2, 5, 2);
com_method_detour!(com_d_6_2, 6, 2);
com_method_detour!(com_d_6_1, 6, 1);
com_method_detour!(com_d_7_1, 7, 1);
com_method_detour!(com_d_7_2, 7, 2);
com_method_detour!(com_d_7_3, 7, 3);
com_method_detour!(com_d_8_2, 8, 2);
com_method_detour!(com_d_8_1, 8, 1);
com_method_detour!(com_d_9_1, 9, 1);
com_method_detour!(com_d_9_2, 9, 2);
com_method_detour!(com_d_10_2, 10, 2);
com_method_detour!(com_d_10_1, 10, 1);
com_method_detour!(com_d_11_1, 11, 1);
com_method_detour!(com_d_11_2, 11, 2);
com_method_detour!(com_d_12_1, 12, 1);
com_method_detour!(com_d_12_2, 12, 2);
com_method_detour!(com_d_13_1, 13, 1);
com_method_detour!(com_d_14_1, 14, 1);
com_method_detour!(com_d_15_1, 15, 1);
com_method_detour!(com_d_16_3, 16, 3);
com_method_detour!(com_d_16_1, 16, 1);
com_method_detour!(com_d_17_2, 17, 2);
com_method_detour!(com_d_17_1, 17, 1);
com_method_detour!(com_d_18_2, 18, 2);
com_method_detour!(com_d_18_1, 18, 1);
com_method_detour!(com_d_19_2, 19, 2);
com_method_detour!(com_d_19_1, 19, 1);
com_method_detour!(com_d_20_1, 20, 1);
com_method_detour!(com_d_21_2, 21, 2);
com_method_detour!(com_d_22_2, 22, 2);

type ComDetourFn0 = unsafe extern "system-unwind" fn(*mut c_void) -> i32;
type ComDetourFn1 = unsafe extern "system-unwind" fn(*mut c_void, usize) -> i32;
type ComDetourFn2 = unsafe extern "system-unwind" fn(*mut c_void, usize, usize) -> i32;
type ComDetourFn3 = unsafe extern "system-unwind" fn(*mut c_void, usize, usize, usize) -> i32;
type ComDetourFn4 =
    unsafe extern "system-unwind" fn(*mut c_void, usize, usize, usize, usize) -> i32;

/// (vtable インデックス, arity) の組に対応する Detour を引く。
/// 既知インターフェイスの全メソッドに Detour があること。
fn com_detour_for(index: u32, arity: usize) -> Option<usize> {
    Some(match (index, arity) {
        (0, 2) => com_d_0_2 as ComDetourFn2 as usize,
        (1, 0) => com_d_1_0 as ComDetourFn0 as usize,
        (2, 0) => com_d_2_0 as ComDetourFn0 as usize,
        (3, 4) => com_d_3_4 as ComDetourFn4 as usize,
        (3, 1) => com_d_3_1 as ComDetourFn1 as usize,
        (3, 2) => com_d_3_2 as ComDetourFn2 as usize,
        (4, 1) => com_d_4_1 as ComDetourFn1 as usize,
        (4, 0) => com_d_4_0 as ComDetourFn0 as usize,
        (5, 1) => com_d_5_1 as ComDetourFn1 as usize,
        (5, 2) => com_d_5_2 as ComDetourFn2 as usize,
        (6, 2) => com_d_6_2 as ComDetourFn2 as usize,
        (6, 1) => com_d_6_1 as ComDetourFn1 as usize,
        (7, 1) => com_d_7_1 as ComDetourFn1 as usize,
        (7, 2) => com_d_7_2 as ComDetourFn2 as usize,
        (7, 3) => com_d_7_3 as ComDetourFn3 as usize,
        (8, 2) => com_d_8_2 as ComDetourFn2 as usize,
        (8, 1) => com_d_8_1 as ComDetourFn1 as usize,
        (9, 1) => com_d_9_1 as ComDetourFn1 as usize,
        (9, 2) => com_d_9_2 as ComDetourFn2 as usize,
        (10, 2) => com_d_10_2 as ComDetourFn2 as usize,
        (10, 1) => com_d_10_1 as ComDetourFn1 as usize,
        (11, 1) => com_d_11_1 as ComDetourFn1 as usize,
        (11, 2) => com_d_11_2 as ComDetourFn2 as usize,
        (12, 1) => com_d_12_1 as ComDetourFn1 as usize,
        (12, 2) => com_d_12_2 as ComDetourFn2 as usize,
        (13, 1) => com_d_13_1 as ComDetourFn1 as usize,
        (14, 1) => com_d_14_1 as ComDetourFn1 as usize,
        (15, 1) => com_d_15_1 as ComDetourFn1 as usize,
        (16, 3) => com_d_16_3 as ComDetourFn3 as usize,
        (16, 1) => com_d_16_1 as ComDetourFn1 as usize,
        (17, 2) => com_d_17_2 as ComDetourFn2 as usize,
        (17, 1) => com_d_17_1 as ComDetourFn1 as usize,
        (18, 2) => com_d_18_2 as ComDetourFn2 as usize,
        (18, 1) => com_d_18_1 as ComDetourFn1 as usize,
        (19, 2) => com_d_19_2 as ComDetourFn2 as usize,
        (19, 1) => com_d_19_1 as ComDetourFn1 as usize,
        (20, 1) => com_d_20_1 as ComDetourFn1 as usize,
        (21, 2) => com_d_21_2 as ComDetourFn2 as usize,
        (22, 2) => com_d_22_2 as ComDetourFn2 as usize,
        _ => return None,
    })
}

/// 完了した非同期 I/O 操作の CallCompleted を記録する（F27）。
/// `transferred` は完了時点の転送バイト数、`success` は完了の成否、
/// `last_error` は完了観測 API の直後に読んだ GetLastError。値列は
/// 元の API の leave Schema で符号化する。
fn record_overlapped_completion(
    rt: &HookRuntime,
    tid: u64,
    pending: capture::PendingOverlapped,
    transferred: u32,
    success: bool,
    last_error: u32,
) {
    let Some(api) = api_by_id(pending.api_id) else {
        return;
    };
    let values = match pending.direction {
        capture::OverlappedDirection::Read => capture::complete_read_file_leave(
            &ProcessMemory,
            pending.buffer,
            pending.requested_len,
            transferred,
            success,
            last_error,
        ),
        capture::OverlappedDirection::Write => {
            capture::complete_write_file_leave(transferred, success, last_error)
        }
    };
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_completion(tid, api, pending.call_id, &bytes);
    }
}

/// LastError セルの実物 (レビュー #6 P1-5)。保持手順そのものは
/// `crate::runtime::LastErrorGuard` が担う。
#[derive(Debug, Clone, Copy)]
struct WinLastError;
impl crate::runtime::LastErrorCell for WinLastError {
    fn get(&self) -> u32 {
        crate::last_error::get()
    }
    fn set(&self, code: u32) {
        crate::last_error::set(code)
    }
}

/// Detour 共通の前処理： ランタイム取得と元関数の解決。
/// 元関数が無い（設置されていない）場合は None を返し、呼び出し側は
/// API ごとの失敗値を返す（プロセスを落とさないことを優先する）。
/// Detour の入口判定 (レビュー #4 の #9)。
enum Prepare {
    /// 記録する通常経路。`flight` を Detour 全体で保持することで、
    /// 終了手順が進行中 Detour の完了を待てる。`guard` は Detour の
    /// 記録経路全体を覆う再入ガード (G15)。元の API 呼び出しの間だけ
    /// Detour 側が suspend し、呼び出しが終われば resume する。
    /// `last_error` は入口時点で保存済みの LastError 保持ガード
    /// (P1-5)。Detour は元の API の直前で復元し、戻り直後に確定値を
    /// 取得し、返る直前にその値を復元する。
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        api: &'static ApiDef,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    /// 終了手順の進行中、または再入中: 記録せず元関数を素通しで呼ぶ。
    /// IAT 復元と競合させないための経路。再入の場合は Agent 自身の
    /// 呼び出しであり、記録対象ではない (G15)。
    Passthrough { original: usize },
    /// ランタイム未登録 / 元関数なし: 呼び出し側は失敗値を返す。
    Unavailable,
}

fn prepare(api_id: u32) -> Prepare {
    // P1-5: LastError は入口 (ここ) で保存する。素通し経路は元の API
    // を呼ぶ前に保存値へ戻してから返し、記録経路はガードごと Detour
    // へ渡す (Detour が元の API の直前で復元する)。Unavailable 経路は
    // 元の API を呼ばないため復元は不要である。
    let le = crate::runtime::LastErrorGuard::capture(WinLastError);
    // G15: 記録経路の実行中にフック対象 API が呼ばれたら、Agent 自身の
    // 呼び出しとして記録せず元関数を素通しで呼ぶ。ガードはここで立て、
    // Record 経路の Detour が終わりまで保持する（元の API 呼び出しの間
    // だけ Detour 側が suspend する）。再入の判定はこの入口に集約し、
    // 各 Detour は Prepare の結果に従うだけにする。
    let Some(guard) = ReentrancyGuard::try_enter() else {
        let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
            return Prepare::Unavailable;
        };
        let original = rt.original(api_id);
        if original == 0 {
            return Prepare::Unavailable;
        }
        le.restore_before_original();
        return Prepare::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return Prepare::Unavailable;
    };
    let original = rt.original(api_id);
    if original == 0 {
        return Prepare::Unavailable;
    }
    let Some(api) = api_by_id(api_id) else {
        return Prepare::Unavailable;
    };
    // The option controls Runtime's own exported APIs, not Windows API calls
    // made by Runtime. Agent-originated calls are excluded by reentrancy above.
    if rt.should_suppress_api_id(api.api_id) {
        le.restore_before_original();
        return Prepare::Passthrough { original };
    }
    // L15: 内部 API (Nt*) は詳細調査モードでのみ記録する。無効なら
    // 元の API だけ素通しで呼ぶ（Detour が設置されていても記録しない）。
    // 呼び出し元抑制の後に置くことで、詳細調査モードでは Runtime 起源の
    // 内部呼び出しも record_runtime_apis と合わせて記録される。
    if rt.should_suppress_internal(api.api_id) {
        le.restore_before_original();
        return Prepare::Passthrough { original };
    }
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            rt.ensure_thread(tid);
            Prepare::Record {
                rt,
                original,
                tid,
                api,
                flight,
                guard,
                last_error: le,
            }
        }
        None => {
            le.restore_before_original();
            Prepare::Passthrough { original }
        }
    }
}

const INVALID_HANDLE: usize = usize::MAX;

unsafe extern "system-unwind" fn detour_create_file_w(
    file_name: *const u16,
    desired_access: u32,
    share_mode: u32,
    security_attributes: *mut c_void,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template_file: Handle,
) -> Handle {
    let (rt, original, tid, api, _flight, mut guard, mut le) = match prepare(API_CREATE_FILE_W) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, api, flight, guard, last_error),
        Prepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            let orig: CreateFileWFn = unsafe { std::mem::transmute(original) };
            return unsafe {
                orig(
                    file_name,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file,
                )
            };
        }
        Prepare::Unavailable => return INVALID_HANDLE as Handle,
    };
    // SAFETY: original は設置時に保存した本物の CreateFileW。
    let orig: CreateFileWFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let values = capture::create_file_w_enter(
        &ProcessMemory,
        file_name as u64,
        desired_access,
        share_mode,
        security_attributes as u64,
        creation_disposition,
        flags_and_attributes,
        template_file as u64,
    );
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す。元の呼び出しの中で
    // アプリ由来の入れ子呼び出しが起きた場合は記録される (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe {
            orig(
                file_name,
                desired_access,
                share_mode,
                security_attributes,
                creation_disposition,
                flags_and_attributes,
                template_file,
            )
        },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let values = capture::create_file_w_leave(ret as u64, last_error, creation_disposition);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system-unwind" fn detour_read_file(
    file: Handle,
    buffer: *mut u8,
    bytes_to_read: u32,
    bytes_read: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let (rt, original, tid, api, _flight, mut guard, mut le) = match prepare(API_READ_FILE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, api, flight, guard, last_error),
        Prepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            let orig: ReadFileFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(file, buffer, bytes_to_read, bytes_read, overlapped) };
        }
        Prepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した本物の ReadFile。
    let orig: ReadFileFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let values =
        capture::read_file_enter(file as u64, buffer as u64, bytes_to_read, overlapped as u64);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    let pending_submission = rt.begin_pending_overlapped(
        overlapped as u64,
        capture::PendingOverlapped {
            api_id: API_READ_FILE,
            call_id,
            handle: file as u64,
            buffer: buffer as u64,
            requested_len: bytes_to_read,
            direction: capture::OverlappedDirection::Read,
            bytes_addr: bytes_read as u64,
        },
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, pending_submission, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(file, buffer, bytes_to_read, bytes_read, overlapped) },
        (call_guard, pending_submission, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let is_overlapped = !overlapped.is_null();
    // F27: 同期完了した OVERLAPPED 操作は leave 時点で既に完了して
    // いるため、転送バイト数とバッファ内容をここで取る。未完了
    // (ERROR_IO_PENDING) なら完了の観測に備えて登録する。
    let values = if is_overlapped && ret != 0 {
        match capture::read_overlapped_transferred(
            &ProcessMemory,
            bytes_read as u64,
            overlapped as u64,
        ) {
            Some(n) => capture::complete_read_file_leave(
                &ProcessMemory,
                buffer as u64,
                bytes_to_read,
                n,
                true,
                last_error,
            ),
            None => capture::read_file_leave(
                &ProcessMemory,
                ret,
                buffer as u64,
                bytes_to_read,
                bytes_read as u64,
                true,
                last_error,
            ),
        }
    } else {
        capture::read_file_leave(
            &ProcessMemory,
            ret,
            buffer as u64,
            bytes_to_read,
            bytes_read as u64,
            is_overlapped,
            last_error,
        )
    };
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    pending_submission.finish(ret == 0 && last_error == capture::ERROR_IO_PENDING);
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system-unwind" fn detour_write_file(
    file: Handle,
    buffer: *const u8,
    bytes_to_write: u32,
    bytes_written: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let (rt, original, tid, api, _flight, mut guard, mut le) = match prepare(API_WRITE_FILE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, api, flight, guard, last_error),
        Prepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            let orig: WriteFileFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(file, buffer, bytes_to_write, bytes_written, overlapped) };
        }
        Prepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した本物の WriteFile。
    let orig: WriteFileFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    // 入力バッファは呼び出し前に取得する（before）
    let values = capture::write_file_enter(
        &ProcessMemory,
        file as u64,
        buffer as u64,
        bytes_to_write,
        overlapped as u64,
    );
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    let pending_submission = rt.begin_pending_overlapped(
        overlapped as u64,
        capture::PendingOverlapped {
            api_id: API_WRITE_FILE,
            call_id,
            handle: file as u64,
            buffer: buffer as u64,
            requested_len: bytes_to_write,
            direction: capture::OverlappedDirection::Write,
            bytes_addr: bytes_written as u64,
        },
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, pending_submission, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(file, buffer, bytes_to_write, bytes_written, overlapped) },
        (call_guard, pending_submission, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let is_overlapped = !overlapped.is_null();
    // F27: ReadFile と同じく、同期完了は leave 時点で値を取り、未完了
    // (ERROR_IO_PENDING) は完了の観測に備えて登録する。
    let values = if is_overlapped && ret != 0 {
        match capture::read_overlapped_transferred(
            &ProcessMemory,
            bytes_written as u64,
            overlapped as u64,
        ) {
            Some(n) => capture::complete_write_file_leave(n, true, last_error),
            None => capture::write_file_leave(
                &ProcessMemory,
                ret,
                bytes_written as u64,
                true,
                last_error,
            ),
        }
    } else {
        capture::write_file_leave(
            &ProcessMemory,
            ret,
            bytes_written as u64,
            is_overlapped,
            last_error,
        )
    };
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    pending_submission.finish(ret == 0 && last_error == capture::ERROR_IO_PENDING);
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system-unwind" fn detour_close_handle(object: Handle) -> i32 {
    let (rt, original, tid, api, _flight, mut guard, mut le) = match prepare(API_CLOSE_HANDLE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (rt, original, tid, api, flight, guard, last_error),
        Prepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            let orig: CloseHandleFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(object) };
        }
        Prepare::Unavailable => return 0,
    };
    // SAFETY: 設置時に保存した本物の CloseHandle。
    let orig: CloseHandleFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let values = capture::close_handle_enter(object as u64);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(object) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    let values = capture::close_handle_leave(ret, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

/// GetOverlappedResult の Detour（F27）。通常の API 呼び出しとして
/// enter / leave を記録したうえで、成功時は待っていた OVERLAPPED
/// 操作の完了を `CallCompleted` として記録する。FALSE でも
/// ERROR_IO_INCOMPLETE 以外なら操作自体がエラーで終わった完了として
/// 記録する。未完了 (996) の場合は何もしない（操作はまだ保留中）。
unsafe extern "system-unwind" fn detour_get_overlapped_result(
    file: Handle,
    overlapped: *mut c_void,
    bytes_transferred: *mut u32,
    wait: i32,
) -> i32 {
    let (rt, original, tid, api, _flight, mut guard, mut le) =
        match prepare(API_GET_OVERLAPPED_RESULT) {
            Prepare::Record {
                rt,
                original,
                tid,
                api,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, api, flight, guard, last_error),
            Prepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: GetOverlappedResultFn = unsafe { std::mem::transmute(original) };
                return unsafe { orig(file, overlapped, bytes_transferred, wait) };
            }
            Prepare::Unavailable => return 0,
        };
    // SAFETY: 設置時に保存した本物の GetOverlappedResult。
    let orig: GetOverlappedResultFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let values = capture::get_overlapped_result_enter(file as u64, overlapped as u64, wait);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら CallGuard が CallAborted を記録する。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe { orig(file, overlapped, bytes_transferred, wait) },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    // 完了の観測：元の呼び出しが返した後に転送バイト数を読み、
    // 保留中の操作を解決する。読めなければ完了は記録できない。
    let transferred = capture::read_overlapped_transferred(
        &ProcessMemory,
        bytes_transferred as u64,
        overlapped as u64,
    );
    let values = capture::get_overlapped_result_leave(ret, transferred, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    if ret != 0 {
        if let Some(pending) = rt.take_pending_overlapped(overlapped as u64) {
            if let Some(n) = transferred {
                record_overlapped_completion(&rt, tid, pending, n, true, last_error);
            }
        }
    } else if last_error != capture::ERROR_IO_INCOMPLETE {
        if let Some(pending) = rt.take_pending_overlapped(overlapped as u64) {
            record_overlapped_completion(&rt, tid, pending, 0, false, last_error);
        }
    }
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

/// GetQueuedCompletionStatus の Detour（F27）。完了ポートから取り出した
/// OVERLAPPED 操作の完了を `CallCompleted` として記録する。戻り値が
/// FALSE でも lpOverlapped が非 NULL なら完了した I/O の失敗として
/// 記録する。タイムアウト等で lpOverlapped が NULL の場合は何もしない。
unsafe extern "system-unwind" fn detour_get_queued_completion_status(
    port: Handle,
    bytes_transferred: *mut u32,
    completion_key: *mut u64,
    overlapped: *mut *mut c_void,
    milliseconds: u32,
) -> i32 {
    let (rt, original, tid, api, _flight, mut guard, mut le) =
        match prepare(API_GET_QUEUED_COMPLETION_STATUS) {
            Prepare::Record {
                rt,
                original,
                tid,
                api,
                flight,
                guard,
                last_error,
            } => (rt, original, tid, api, flight, guard, last_error),
            Prepare::Passthrough { original } => {
                // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
                let orig: GetQueuedCompletionStatusFn = unsafe { std::mem::transmute(original) };
                return unsafe {
                    orig(
                        port,
                        bytes_transferred,
                        completion_key,
                        overlapped,
                        milliseconds,
                    )
                };
            }
            Prepare::Unavailable => return 0,
        };
    // SAFETY: 設置時に保存した本物の GetQueuedCompletionStatus。
    let orig: GetQueuedCompletionStatusFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    let values = capture::get_queued_completion_status_enter(
        port as u64,
        bytes_transferred as u64,
        completion_key as u64,
        overlapped as u64,
        milliseconds,
    );
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    drop(values);
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら CallGuard が CallAborted を記録する。
    let call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let (ret, (mut call_guard, rt, _flight, mut guard)) = crate::seh::invoke(
        original,
        |_| unsafe {
            orig(
                port,
                bytes_transferred,
                completion_key,
                overlapped,
                milliseconds,
            )
        },
        (call_guard, rt, _flight, guard),
    );
    let last_error = le.capture_after_original();
    call_guard.complete();
    guard.resume();
    pop_call(call_id);
    // 取り出した OVERLAPPED ポインタは元の呼び出しが書いたもの。
    // SAFETY: overlapped が指す領域は元の呼び出しが書き込んだ有効な領域。
    let dequeued = if overlapped.is_null() {
        0u64
    } else {
        (unsafe { *overlapped }) as u64
    };
    let transferred =
        capture::read_overlapped_transferred(&ProcessMemory, bytes_transferred as u64, dequeued);
    let values = capture::get_queued_completion_status_leave(ret, transferred, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    if dequeued != 0 {
        if let Some(pending) = rt.take_pending_overlapped(dequeued) {
            if let Some(n) = transferred {
                record_overlapped_completion(&rt, tid, pending, n, ret != 0, last_error);
            }
        }
    }
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_agent::Agent;
    use shirusu_transport::context::HostMonitor;
    use shirusu_transport::slot::SlotPool;
    use shirusu_transport::RingConfig;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS,
    };

    #[test]
    fn pending_restore_retention_uses_entry_indices_not_api_ids() {
        let mut hooks = vec![(17, "restored"), (17, "failed"), (18, "restored")];
        retain_failed_indices(&mut hooks, &[1]);
        assert_eq!(hooks, vec![(17, "failed")]);
    }

    static TEST_RUNTIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_runtime() -> HookRuntime {
        HookRuntime::new(
            Arc::new(Agent::new(
                Arc::new(SlotPool::new(2)),
                RingConfig::new(64, 4096),
                Arc::new(HostMonitor::always_alive()),
            )),
            Vec::new(),
            None,
        )
    }

    #[test]
    fn delayed_com_completion_does_not_mutate_a_reused_pointer() {
        let rt = Arc::new(test_runtime());
        let instance = rt.with_com_tracker(|t| {
            t.note_factory_result(0x1000, IID_IUNKNOWN, "CoCreateInstance");
            let token = t.instance_token(0x1000).unwrap();
            t.note_release(0x1000, 0);
            t.note_factory_result(0x1000, IID_IUNKNOWN, "CoCreateInstance");
            token
        });
        assert_eq!(
            com_method_post_call(&rt, 0x1000, &instance, 1, &[], 99),
            (0, 99)
        );
        assert_eq!(
            com_method_post_call(&rt, 0x1000, &instance, 2, &[], 0),
            (0, 0)
        );
        rt.with_com_tracker(|t| {
            let current = t.lookup(0x1000).unwrap();
            assert!(!current.destroyed);
            assert_eq!(current.refcount, None);
        });
    }

    #[test]
    fn create_file_success_error_follows_creation_disposition() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system-unwind" fn original(
            _: *const u16,
            _: u32,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: u32,
            _: Handle,
        ) -> Handle {
            crate::last_error::set(183);
            0x1234usize as Handle
        }
        let rt = Arc::new(test_runtime());
        rt.set_original(API_CREATE_FILE_W, original as *const () as usize);
        assert!(set_runtime(rt.clone()).is_ok());
        let tid = unsafe { GetCurrentThreadId() } as u64;
        rt.ensure_thread(tid);
        let path = [b'x' as u16, 0];
        for disposition in 1..=5 {
            assert_eq!(
                unsafe {
                    detour_create_file_w(
                        path.as_ptr(),
                        0,
                        0,
                        std::ptr::null_mut(),
                        disposition,
                        128,
                        std::ptr::null_mut(),
                    )
                } as usize,
                0x1234
            );
            assert_eq!(crate::last_error::get(), 183);
        }
        // SAFETY: this test owns the Agent and exclusively uses the local Ring.
        let base = unsafe { rt.agent().thread_region_base(tid) }.unwrap();
        let mut reader =
            unsafe { shirusu_transport::ring::RingReader::new(base, rt.agent().thread_config()) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 10);
        let api = api_by_id(API_CREATE_FILE_W).unwrap();
        let types: Vec<_> = api.leave_fields.iter().map(|f| f.1).collect();
        for (i, event) in batch.events.iter().skip(1).step_by(2).enumerate() {
            let values = shirusu_trace::compact::decode_values(&types, &event.payload).unwrap();
            assert_eq!(values[1].value, shirusu_trace::schema::TypedValue::U32(183));
            assert_eq!(
                values[1].capture,
                if matches!(i + 1, 2 | 4) {
                    shirusu_trace::schema::ValueCapture::Captured
                } else {
                    shirusu_trace::schema::ValueCapture::Stale
                }
            );
        }
        assert_eq!(reader.loss_counters(), Default::default());
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn create_file_a_success_error_follows_creation_disposition() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system-unwind" fn original(
            _: *mut c_void,
            _: u32,
            _: u32,
            _: *mut c_void,
            _: u32,
            _: u32,
            _: Handle,
        ) -> Handle {
            crate::last_error::set(183);
            0x1234usize as Handle
        }
        let rt = Arc::new(test_runtime());
        rt.set_original(
            crate::api::api_by_import("kernel32.dll", "CreateFileA")
                .unwrap()
                .api_id,
            original as *const () as usize,
        );
        assert!(set_runtime(rt.clone()).is_ok());
        let tid = unsafe { GetCurrentThreadId() } as u64;
        rt.ensure_thread(tid);
        let mut path = [b'x', 0];
        for disposition in 1..=5 {
            assert_eq!(
                unsafe {
                    detour_generated_kernel32_create_file_a(
                        path.as_mut_ptr().cast(),
                        0,
                        0,
                        std::ptr::null_mut(),
                        disposition,
                        128,
                        std::ptr::null_mut(),
                    )
                } as usize,
                0x1234
            );
            assert_eq!(crate::last_error::get(), 183);
        }
        // SAFETY: this test owns the Agent and exclusively uses the local Ring.
        let base = unsafe { rt.agent().thread_region_base(tid) }.unwrap();
        let mut reader =
            unsafe { shirusu_transport::ring::RingReader::new(base, rt.agent().thread_config()) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 10);
        let api = crate::api::api_by_import("kernel32.dll", "CreateFileA").unwrap();
        let types: Vec<_> = api.leave_fields.iter().map(|f| f.1).collect();
        for (i, event) in batch.events.iter().skip(1).step_by(2).enumerate() {
            let values = shirusu_trace::compact::decode_values(&types, &event.payload).unwrap();
            assert_eq!(values[1].value, shirusu_trace::schema::TypedValue::U32(183));
            assert_eq!(
                values[1].capture,
                if matches!(i + 1, 2 | 4) {
                    shirusu_trace::schema::ValueCapture::Captured
                } else {
                    shirusu_trace::schema::ValueCapture::Stale
                }
            );
        }
        assert_eq!(reader.loss_counters(), Default::default());
        assert!(clear_runtime(&rt));
    }

    /// Explicit release-only measurement; normal test runs skip it. This invokes
    /// the actual typed Detour and SEH boundary, but patches no process and has
    /// no concurrent Host, notification event or real heap allocation.
    #[test]
    #[ignore = "run explicitly in release mode for native component measurements"]
    #[allow(clippy::assertions_on_constants)] // Runtime refusal, not a compile-time assertion.
    fn measure_generic_detour() {
        use shirusu_transport::ring::RingReader;
        use std::{hint::black_box, time::Instant};
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        // Compile in debug test builds too, but reject accidentally measuring
        // an unoptimized binary when this ignored test is explicitly selected.
        assert!(!cfg!(debug_assertions), "measurement requires --release");
        #[inline(never)]
        unsafe extern "system-unwind" fn original(
            _: *mut c_void,
            _: u32,
            size: usize,
        ) -> *mut c_void {
            crate::last_error::set(0x1234);
            size as *mut c_void
        }
        const CALLS: usize = 1024;
        const ROUNDS: usize = 7;
        let config = RingConfig::new(4096, 1024 * 1024);
        let agent = Arc::new(
            Agent::new(
                Arc::new(SlotPool::new(2)),
                config,
                Arc::new(HostMonitor::always_alive()),
            )
            .with_timestamp_source(Arc::new(shirusu_transport_win::QpcTimestampSource::new())),
        );
        let rt = Arc::new(HookRuntime::new(agent.clone(), Vec::new(), None));
        let api = crate::api::api_by_import("kernel32.dll", "HeapAlloc").unwrap();
        rt.set_original(api.api_id, original as *const () as usize);
        assert!(set_runtime(rt.clone()).is_ok());
        let tid = unsafe { GetCurrentThreadId() } as u64;
        rt.ensure_thread(tid);
        // SAFETY: Agent owns the local Ring through all samples; this is its
        // only producer and consumer. No hook patches are installed.
        let base = unsafe { agent.thread_region_base(tid) }.unwrap();
        let mut reader = unsafe { RingReader::new(base, config) };
        let direct: unsafe extern "system-unwind" fn(*mut c_void, u32, usize) -> *mut c_void =
            black_box(original);
        let detour: unsafe extern "system-unwind" fn(*mut c_void, u32, usize) -> *mut c_void =
            black_box(detour_generated_kernel32_heap_alloc);
        for _ in 0..512 {
            unsafe {
                black_box(detour(std::ptr::null_mut(), 0, 64));
            }
        }
        assert_eq!(reader.drain_all().events.len(), 1024);
        let mut baseline = Vec::new();
        let mut boundary = Vec::new();
        let mut captured = Vec::new();
        for _ in 0..ROUNDS {
            let started = Instant::now();
            for _ in 0..CALLS {
                unsafe {
                    black_box(direct(std::ptr::null_mut(), 0, black_box(64)));
                }
            }
            baseline.push(started.elapsed().as_nanos() as f64 / CALLS as f64);
            let started = Instant::now();
            for _ in 0..CALLS {
                black_box(crate::seh::invoke(
                    direct as *const () as usize,
                    |address| {
                        let call: unsafe extern "system-unwind" fn(
                            *mut c_void,
                            u32,
                            usize,
                        )
                            -> *mut c_void = unsafe { std::mem::transmute(address) };
                        unsafe { call(std::ptr::null_mut(), 0, 64) }
                    },
                    (),
                ));
            }
            boundary.push(started.elapsed().as_nanos() as f64 / CALLS as f64);
            let started = Instant::now();
            for _ in 0..CALLS {
                unsafe {
                    black_box(detour(std::ptr::null_mut(), 0, black_box(64)));
                }
            }
            let last_error = crate::last_error::get();
            captured.push(started.elapsed().as_nanos() as f64 / CALLS as f64);
            assert_eq!(last_error, 0x1234);
            let events = reader.drain_all().events;
            assert_eq!(events.len(), 2 * CALLS);
            assert!(events
                .iter()
                .all(|e| e.descriptor.api_id == api.api_id && !e.descriptor.payload_dropped()));
            assert_eq!(rt.in_flight(), 0);
        }
        assert_eq!(reader.loss_counters(), Default::default());
        assert!(clear_runtime(&rt));
        println!("scope=typed-detour-with-stub-original; no patch, real heap work, Host, notification or disk; per-call includes two events; components overlap");
        for (name, mut samples) in [
            ("stub_original", baseline),
            ("seh_stub_original", boundary),
            ("typed_detour_two_events", captured),
        ] {
            samples.sort_by(f64::total_cmp);
            println!(
                "phase={name} median_ns_per_call={:.2} min={:.2} max={:.2}",
                samples[ROUNDS / 2],
                samples[0],
                samples[ROUNDS - 1]
            );
        }
    }

    #[test]
    fn exit_thread_releases_detour_ownership_without_unwinding() {
        use windows_sys::Win32::System::Threading::{
            CreateThread, ExitThread, GetExitCodeThread, WaitForSingleObject,
        };
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system" fn worker(_: *mut c_void) -> u32 {
            unsafe { detour_generated_kernel32_exit_thread(37) };
            99 // A real ExitThread never reaches this point.
        }
        let api = api_table()
            .find(|api| api.function == "ExitThread")
            .unwrap();
        let rt = Arc::new(test_runtime());
        rt.set_original(api.api_id, ExitThread as *const () as usize);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let references = Arc::strong_count(&rt);
        let thread = unsafe {
            CreateThread(
                std::ptr::null(),
                0,
                Some(worker),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert!(!thread.is_null());
        assert_eq!(unsafe { WaitForSingleObject(thread, 10_000) }, 0);
        let mut code = 0;
        assert_ne!(unsafe { GetExitCodeThread(thread, &mut code) }, 0);
        assert_ne!(unsafe { CloseHandle(thread) }, 0);
        assert_eq!(code, 37);
        assert_eq!(rt.in_flight(), 0);
        assert_eq!(Arc::strong_count(&rt), references);
        crate::fls::drain_pending_exits();
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn seh_releases_detour_state_and_clears_parent_stack() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        extern "C-unwind" {
            fn shirusu_test_raise_seh() -> u64;
            fn shirusu_test_catch_seh(
                invoke: unsafe extern "C-unwind" fn(*mut c_void) -> u64,
                context: *mut c_void,
            ) -> u32;
        }
        unsafe extern "C-unwind" fn invoke(_: *mut c_void) -> u64 {
            generic_detour_with(72, &[0, 4, u64::MAX], |_| unsafe {
                shirusu_test_raise_seh()
            })
        }
        let rt = Arc::new(test_runtime());
        rt.set_original(72, 1); // callback raises directly; no fabricated pointer is invoked
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let references = Arc::strong_count(&rt);
        assert_eq!(
            unsafe { shirusu_test_catch_seh(invoke, std::ptr::null_mut()) },
            0xe0424242
        );
        assert_eq!(rt.in_flight(), 0);
        assert_eq!(Arc::strong_count(&rt), references);
        assert_eq!(crate::runtime::current_parent_call(), 0);
        assert!(!ReentrancyGuard::is_active());
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn read_file_seh_cancels_provisional_overlapped_and_releases_state() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        extern "C-unwind" {
            fn shirusu_test_raise_seh() -> u64;
            fn shirusu_test_catch_seh(
                invoke: unsafe extern "C-unwind" fn(*mut c_void) -> u64,
                context: *mut c_void,
            ) -> u32;
        }
        unsafe extern "system-unwind" fn fail(
            _: Handle,
            _: *mut u8,
            _: u32,
            _: *mut u32,
            _: *mut c_void,
        ) -> i32 {
            unsafe { shirusu_test_raise_seh() as i32 }
        }
        unsafe extern "C-unwind" fn invoke(_: *mut c_void) -> u64 {
            unsafe {
                detour_read_file(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    1,
                    std::ptr::null_mut(),
                    0x1234usize as *mut c_void,
                ) as u64
            }
        }
        let rt = Arc::new(test_runtime());
        rt.set_original(API_READ_FILE, fail as ReadFileFn as usize);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let references = Arc::strong_count(&rt);
        assert_eq!(
            unsafe { shirusu_test_catch_seh(invoke, std::ptr::null_mut()) },
            0xe0424242
        );
        assert_eq!(rt.pending_overlapped_count(), 0);
        assert_eq!(rt.in_flight(), 0);
        assert_eq!(Arc::strong_count(&rt), references);
        assert_eq!(crate::runtime::current_parent_call(), 0);
        assert!(!ReentrancyGuard::is_active());
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn kernel32_import_thunks_resolve_to_kernelbase_implementations() {
        for name in ["CreateFileW", "WriteFile", "CloseHandle"] {
            let kernel32 = resolve_export("kernel32.dll", name).unwrap();
            let kernelbase = resolve_export("kernelbase.dll", name).unwrap();
            assert_eq!(kernel32, kernelbase, "{name}");
        }
    }

    #[test]
    fn set_window_long_preserves_non_procedure_values() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system-unwind" fn procedure(
            _: *mut c_void,
            _: u32,
            _: usize,
            _: isize,
        ) -> isize {
            0
        }
        unsafe extern "system-unwind" fn setter(hwnd: *mut c_void, _: i32, _: usize) -> usize {
            unsafe {
                SetLastError(0x8000_0002);
            }
            hwnd as usize
        }
        let procedure = procedure as WndProcFn as usize;
        let slot = callback_procs().wrap(procedure).unwrap();
        let wrapper = wrapper_for_slot(slot).unwrap();
        let rt = Arc::new(test_runtime());
        rt.set_callback_original(
            CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W,
            setter as SetWindowLongPtrFn as usize,
        );
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        for recording in [true, false] {
            if !recording {
                rt.shutdown_recording();
            }
            for (field, expected) in [(-21, wrapper), (0, wrapper), (-4, procedure)] {
                assert_eq!(
                    unsafe { detour_set_window_long_ptr_w(wrapper as *mut c_void, field, 0) },
                    expected
                );
                assert_eq!(unsafe { GetLastError() }, 0x8000_0002);
            }
        }
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn activation_factory_preserves_iid_and_output_in_recording_and_passthrough() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        const IID: Guid = Guid { bytes: [0x77; 16] };
        unsafe extern "system-unwind" fn factory(
            class_id: usize,
            iid: *const Guid,
            out: *mut *mut c_void,
        ) -> i32 {
            assert_eq!(class_id, 0);
            assert_eq!(unsafe { *iid }, IID);
            unsafe {
                *out = 0x1234usize as *mut c_void;
                SetLastError(0x8000_0001);
            }
            0
        }
        let rt = Arc::new(test_runtime());
        rt.set_winrt_original(
            WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
            factory as *const () as usize,
        );
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let detour: RoGetActivationFactoryFn = detour_ro_get_activation_factory;
        for recording in [true, false] {
            if !recording {
                rt.shutdown_recording();
            }
            let mut output = std::ptr::null_mut();
            assert_eq!(unsafe { detour(0, &IID, &mut output) }, 0);
            assert_eq!(unsafe { GetLastError() }, 0x8000_0001);
            assert_eq!(output as usize, 0x1234);
        }
        assert_eq!(
            rt.with_com_tracker(|tracker| tracker.lookup(0x1234).unwrap().iid),
            IID
        );
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn completion_can_arrive_inside_original_read_file() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system-unwind" fn original(
            _: Handle,
            _: *mut u8,
            _: u32,
            _: *mut u32,
            overlapped: *mut c_void,
        ) -> i32 {
            let rt = runtime().unwrap();
            let mut completed = rt
                .take_pending_overlapped(overlapped as u64)
                .expect("submission must already be registered before entering the OS");
            completed.call_id += 1000;
            rt.register_pending_overlapped(overlapped as u64, completed);
            unsafe {
                SetLastError(capture::ERROR_IO_PENDING);
            }
            0
        }
        let rt = Arc::new(test_runtime());
        rt.set_original(API_READ_FILE, original as *const () as usize);
        assert!(set_runtime(rt.clone()).is_ok());
        let mut overlapped = [0usize; 8];
        let address = overlapped.as_mut_ptr() as *mut c_void;
        assert_eq!(
            unsafe {
                detour_read_file(
                    1usize as Handle,
                    std::ptr::null_mut(),
                    4,
                    std::ptr::null_mut(),
                    address,
                )
            },
            0
        );
        let pending = rt.take_pending_overlapped(address as u64).unwrap();
        assert!(
            pending.call_id >= 1000,
            "late return must not overwrite reuse"
        );
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn suspended_thread_context_has_native_alignment_and_valid_ip() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        use std::sync::atomic::{AtomicBool, Ordering};
        assert!(std::mem::align_of::<AlignedContext>() >= 16);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(unsafe { GetCurrentThreadId() }).unwrap();
            while !worker_stop.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
        });
        let tid = rx.recv().unwrap();
        let handle = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                0,
                tid,
            )
        };
        if handle.is_null() {
            stop.store(true, Ordering::Release);
            worker.join().unwrap();
            panic!("OpenThread failed: {}", unsafe { GetLastError() });
        }
        let suspended = unsafe { SuspendThread(handle) };
        if suspended == u32::MAX {
            unsafe {
                CloseHandle(handle);
            }
            stop.store(true, Ordering::Release);
            worker.join().unwrap();
            panic!("SuspendThread failed");
        }
        let guard = SuspendedThreads {
            handles: vec![handle],
            thread_ids: Vec::new(),
            snapshot: None,
        };
        let ip = thread_instruction_pointer(handle);
        let outside = !guard.any_ip_in_range(usize::MAX - 1, usize::MAX);
        guard.resume();
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
        assert_ne!(ip.expect("GetThreadContext on suspended worker"), 0);
        assert!(
            outside,
            "a valid context must not refuse every target range"
        );
    }

    #[test]
    fn ntstatus_and_native_arguments_survive_record_and_passthrough() {
        let _global = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system-unwind" fn close(handle: Handle) -> i32 {
            assert_eq!(handle as usize, usize::MAX - 1);
            -0x1234567
        }
        let agent = Arc::new(Agent::new(
            Arc::new(SlotPool::new(2)),
            RingConfig::new(64, 4096),
            Arc::new(HostMonitor::always_alive()),
        ));
        let rt = Arc::new(HookRuntime::new(agent, Vec::new(), None).with_detailed_mode(true));
        rt.set_original(API_NT_CLOSE, close as *const () as usize);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let detour: unsafe extern "system-unwind" fn(Handle) -> i32 = detour_nt_close;
        assert_eq!(unsafe { detour((usize::MAX - 1) as Handle) }, -0x1234567);
        rt.shutdown_recording();
        assert_eq!(unsafe { detour((usize::MAX - 1) as Handle) }, -0x1234567);
        assert!(clear_runtime(&rt));
    }

    #[test]
    fn shared_com_methods_continue_without_vtable_mutation() {
        use crate::com::IID_IUNKNOWN;
        unsafe extern "system-unwind" fn method(_: usize) -> u32 {
            123
        }
        unsafe extern "system-unwind" fn qi(_: usize, _: *const Guid, _: *mut usize) -> i32 {
            COM_E_FAIL
        }
        let vtable = Arc::new([
            qi as *const () as usize,
            method as *const () as usize,
            method as *const () as usize,
        ]);
        let object = Arc::new(vtable.as_ptr() as usize);
        let rt = Arc::new(test_runtime());
        assert!(crate::shared_com::initialize());
        let ptr = Arc::as_ptr(&object) as usize;
        rt.with_com_tracker(|t| {
            t.note_factory_result(ptr as u64, IID_IUNKNOWN, "fixture");
        });
        let other = Arc::clone(&object);
        let reader = std::thread::spawn(move || {
            for _ in 0..10000 {
                let method: unsafe extern "system-unwind" fn(usize) -> u32 =
                    unsafe { std::mem::transmute(*(*other as *const usize).add(1)) };
                assert_eq!(unsafe { method(Arc::as_ptr(&other) as usize) }, 123);
            }
        });
        for _ in 0..1000 {
            assert_eq!(
                unsafe { intercept_object(&rt, ptr, IID_IUNKNOWN) },
                ComInterceptOutcome::MethodInterceptionSkipped("vtable-not-image-data")
            );
        }
        reader.join().unwrap();
        assert_eq!(*object, vtable.as_ptr() as usize);
        assert_eq!(
            rt.with_com_tracker(|t| t.lookup(ptr as u64).unwrap().interception_skip_reason),
            Some("vtable-not-image-data")
        );
    }

    #[test]
    fn installing_process_pseudo_handle_hook_does_not_recurse() {
        const CHILD: &str = "SHIRUSU_INLINE_PUBLICATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::installing_process_pseudo_handle_hook_does_not_recurse",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("inline publication regression timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        let api = api_table()
            .find(|api| api.function == "GetCurrentProcess")
            .unwrap();
        let rt = Arc::new(test_runtime());
        let original = resolve_export(api.module, api.function).unwrap();
        rt.set_original(api.api_id, original); // The state after IAT installation.
        rt.shutdown_recording();
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        let before = unsafe { std::slice::from_raw_parts(original as *const u8, 16) }.to_vec();
        let result = unsafe { install_inline_hooks_for(&rt, std::iter::once(api)) };
        if result.installed.is_empty() {
            // Some Windows builds implement this export in fewer bytes than
            // a jump. Refusing it must preserve both code and the IAT original.
            assert_eq!(result.skipped, vec![(api.api_id, "too-short")]);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(original as *const u8, 16) },
                before
            );
            assert_eq!(rt.original(api.api_id), original);
        } else {
            assert_eq!(result.installed.len(), 1);
            assert!(result.skipped.is_empty());
        }
        assert_eq!(unsafe { GetCurrentProcess() } as usize, usize::MAX);
        assert!(unsafe { uninstall_inline_hooks(&result.installed) }.is_empty());
        assert!(clear_runtime(&rt));
        assert_eq!(unsafe { GetCurrentProcess() } as usize, usize::MAX);
    }

    #[test]
    fn thread_created_after_snapshot_refuses_freeze_and_recovers() {
        // Isolate SuspendThread from the parallel test harness and its locks.
        const CHILD: &str = "SHIRUSU_THREAD_SNAPSHOT_RACE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::thread_created_after_snapshot_refuses_freeze_and_recovers",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("thread snapshot regression timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let mut worker = None;
        let result = SuspendedThreads::suspend_all_after_snapshot(|| {
            let stop = Arc::clone(&stop);
            let started_worker = Arc::clone(&started);
            worker = Some(std::thread::spawn(move || {
                started_worker.store(true, Ordering::Release);
                while !stop.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
            }));
            while !started.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        });
        let reason = match result {
            Ok(guard) => {
                guard.resume();
                None
            }
            Err(reason) => Some(reason),
        };
        stop.store(true, Ordering::Release);
        worker.unwrap().join().unwrap();
        assert_eq!(reason, Some("thread-set-changed"));
        // A rejected freeze must resume all old threads and release its handles.
        SuspendedThreads::suspend_all()
            .expect("stable thread set after recovery")
            .resume();
    }

    #[test]
    fn unpublished_trampolines_release_memory_and_budget() {
        // Isolate SuspendThread from the parallel test harness and its locks.
        const CHILD: &str = "SHIRUSU_UNPUBLISHED_TRAMPOLINE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::unpublished_trampolines_release_memory_and_budget",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("trampoline reclamation regression timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        use windows_sys::Win32::System::Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_FREE,
        };
        let bitness = usize::BITS;
        // More failures than the retained budget must remain recoverable.
        for _ in 0..4100 {
            drop(TrampolineAllocation::reserve().unwrap());
        }
        assert_eq!(
            TRAMPOLINE_ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let target = alloc_filled_page(0x90) as usize;
        let bytes = [0x90u8; 32];
        let plan =
            plan_with_near_relay(&bytes, target as u64, (target + 256) as u64, bitness).unwrap();
        let original_bytes = bytes[..plan.stolen_len].to_vec();
        let planned = PlannedInline {
            slot: InlineOriginalSlot::Api(17),
            target,
            detour: target + 256,
            plan,
            original_bytes,
        };
        for _ in 0..32 {
            let prepared = prepare_inline(&planned, bitness).unwrap();
            let address = prepared.0.trampoline;
            drop(prepared);
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            assert_ne!(
                unsafe {
                    VirtualQuery(
                        address as *const c_void,
                        &mut info,
                        std::mem::size_of_val(&info),
                    )
                },
                0
            );
            assert_eq!(
                info.State, MEM_FREE,
                "unpublished executable allocation was retained"
            );
            assert_eq!(
                TRAMPOLINE_ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
        unsafe { VirtualFree(target as *mut c_void, 0, MEM_RELEASE) };
    }

    #[test]
    fn iat_write_rejects_unaligned_slots_without_touching_memory() {
        let mut storage = [0x55usize; 2];
        let slot = unsafe { storage.as_mut_ptr().cast::<u8>().add(1).cast::<usize>() };
        assert_eq!(
            unsafe { write_slot(slot, 0x1234) },
            Err(EngineError::UnalignedIatSlot)
        );
        assert_eq!(storage, [0x55; 2]);
    }

    #[test]
    fn failed_page_protection_does_not_publish_a_trampoline() {
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        let published = std::cell::Cell::new(false);
        assert!(patch_target_with(0, &[0x90], || published.set(true)).is_err());
        assert!(!published.get());
    }

    #[test]
    fn trampoline_survives_uninstall_for_late_passthrough() {
        // Isolate SuspendThread from the parallel test harness and its locks.
        const CHILD: &str = "SHIRUSU_TRAMPOLINE_LIFETIME_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::trampoline_survives_uninstall_for_late_passthrough",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("uninstall regression timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        // mov eax, 42; ret works on x86 and x64. Simulate an already acquired
        // trampoline held outside its code while shutdown restores the target.
        for _ in 0..2 {
            let target = alloc_filled_page(0x90);
            let trampoline = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            assert!(!trampoline.is_null());
            let code = [0xB8u8, 42, 0, 0, 0, 0xC3];
            unsafe {
                std::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len());
            }
            let hook = InlineHook {
                api_id: 17,
                target: target as usize,
                trampoline: trampoline as usize,
                trampoline_size: 4096,
                stolen_len: code.len(),
                original_bytes: code.to_vec(),
            };
            let address = hook.trampoline;
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel();
            let caller = std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                unsafe { call_original::<0>(address, &[]) }
            });
            ready_rx.recv().unwrap();
            assert!(unsafe { uninstall_inline_hooks(&[hook]) }.is_empty());
            go_tx.send(()).unwrap();
            assert_eq!(caller.join().unwrap() as u32, 42);
            unsafe {
                VirtualFree(target, 0, MEM_RELEASE);
            }
        }
    }

    #[test]
    fn uninstall_refuses_to_rewrite_a_stopped_instruction_pointer() {
        const CHILD: &str = "SHIRUSU_UNINSTALL_RETRY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::uninstall_refuses_to_rewrite_a_stopped_instruction_pointer",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("uninstall retry timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        use std::sync::atomic::{AtomicU8, Ordering};
        // Signal entry through flag[1], then spin until flag[0] is set. Keep
        // the worker inside the restoration range without OS calls or locks.
        #[cfg(target_arch = "x86_64")]
        let code = [0xc6, 0x41, 1, 1, 0x80, 0x39, 0, 0x74, 0xfb, 0xc3];
        #[cfg(target_arch = "x86")]
        let code = [
            0x8b, 0x4c, 0x24, 4, 0xc6, 0x41, 1, 1, 0x80, 0x39, 0, 0x74, 0xfb, 0xc2, 4, 0,
        ];
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!page.is_null());
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
            FlushInstructionCache(GetCurrentProcess(), page, code.len());
        }
        let address = page as usize;
        let flags = Arc::new([AtomicU8::new(0), AtomicU8::new(0)]);
        let worker_flags = Arc::clone(&flags);
        let worker = std::thread::spawn(move || {
            let run: unsafe extern "system" fn(*const AtomicU8) =
                unsafe { std::mem::transmute(address) };
            unsafe { run(worker_flags.as_ptr()) };
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while flags[1].load(Ordering::Acquire) == 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        let entered = flags[1].load(Ordering::Acquire) != 0;
        let hook = InlineHook {
            api_id: 17,
            target: address,
            trampoline: 0,
            trampoline_size: 0,
            stolen_len: code.len(),
            original_bytes: vec![0x90; code.len()],
        };
        let mut pending = vec![hook];
        let unrestored = unsafe { uninstall_pending_inline_hooks(&mut pending) };
        assert_eq!(pending.len(), 1);
        flags[0].store(1, Ordering::Release);
        worker.join().unwrap();
        assert!(entered, "worker did not enter its native loop");
        assert_eq!(unrestored, 1);
        assert_eq!(unsafe { uninstall_pending_inline_hooks(&mut pending) }, 0);
        assert!(pending.is_empty());
        assert!(
            unsafe { std::slice::from_raw_parts(page.cast::<u8>(), code.len()) }
                .iter()
                .all(|&byte| byte == 0x90)
        );
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn near_relay_preserves_short_function_tail_and_detects_repeat_install() {
        // Isolate SuspendThread from the parallel test harness and its locks.
        const CHILD: &str = "SHIRUSU_NEAR_RELAY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::tests::near_relay_preserves_short_function_tail_and_detects_repeat_install",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("near relay regression timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
        unsafe extern "system" fn replacement() -> u32 {
            7
        }
        let detour = replacement as *const () as usize;
        let mut target = 0;
        for hint in [0x1_0000_0000usize, 0x2_0000_0000, 0x3_0000_0000] {
            let page = unsafe {
                VirtualAlloc(
                    hint as *const c_void,
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if page.is_null() {
                continue;
            }
            if build_patch(page as u64, detour as u64, 64).len() > 5 {
                target = page as usize;
                break;
            }
            unsafe { VirtualFree(page, 0, MEM_RELEASE) };
        }
        assert_ne!(target, 0, "no distant test page available");
        let code = [0xb8u8, 42, 0, 0, 0, 0xc3, 0xcc];
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), target as *mut u8, code.len()) };
        let plan = plan_with_near_relay(&code, target as u64, detour as u64, 64).unwrap();
        assert_eq!(plan.patch_len, 5);
        let planned = PlannedInline {
            slot: InlineOriginalSlot::Api(40),
            target,
            detour,
            original_bytes: code[..plan.stolen_len].to_vec(),
            plan,
        };
        let rt = test_runtime();
        let hook = install_planned(&rt, &[planned], 64).pop().unwrap().unwrap();
        let call: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(target) };
        let original: unsafe extern "system" fn() -> u32 =
            unsafe { std::mem::transmute(hook.trampoline) };
        assert_eq!(unsafe { call() }, 7);
        assert_eq!(unsafe { original() }, 42);
        let patched = unsafe { std::slice::from_raw_parts(target as *const u8, code.len()) };
        assert_eq!(&patched[5..], &[0xc3, 0xcc]);
        assert!(is_existing_detour(target, detour, 64, patched));
        assert!(unsafe { uninstall_inline_hooks(&[hook]) }.is_empty());
        assert_eq!(unsafe { call() }, 42);
        assert_eq!(unsafe { original() }, 42);
        unsafe { VirtualFree(target as *mut c_void, 0, MEM_RELEASE) };
    }

    /// テスト用に 1 ページ確保し、同じバイトで埋める。
    fn alloc_filled_page(byte: u8) -> *mut c_void {
        // SAFETY: 自プロセスに 1 ページ確保する。
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!page.is_null());
        // SAFETY: 確保したページ内。
        unsafe { std::ptr::write_bytes(page as *mut u8, byte, 4096) };
        page
    }

    #[test]
    fn process_memory_reads_committed_and_rejects_noaccess() {
        // レビュー #6 P0-3: 読める範囲は読め、保護を外した範囲は
        // アクセス違反ではなく失敗 (false) として返る。
        let page = alloc_filled_page(0x5A);
        let mut buf = [0u8; 64];
        assert!(ProcessMemory.read_exact(page as u64, &mut buf));
        assert!(buf.iter().all(|&b| b == 0x5A));
        let mut old = 0u32;
        // SAFETY: 自分で確保したページの保護を変える。
        let ok = unsafe { VirtualProtect(page, 4096, PAGE_NOACCESS, &mut old) };
        assert_ne!(ok, 0);
        let mut buf2 = [0u8; 64];
        assert!(!ProcessMemory.read_exact(page as u64, &mut buf2));
        // SAFETY: 後始末。
        unsafe {
            VirtualProtect(page, 4096, PAGE_READWRITE, &mut old);
            VirtualFree(page, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn process_memory_survives_concurrent_protection_changes() {
        // レビュー #6 P0-3 の故障注入: 読み取りと並行して別スレッドが
        // 保護属性を切り替えても、アクセス違反でプロセスが落ちず、
        // 読み取りは「全バイト読めた」か「失敗」のどちらかで戻る。
        // 旧実装 (VirtualQuery 確認 → 生ポインタコピー) ではこの競合で
        // AV になり、テストプロセスごと落ちる。
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        let page = alloc_filled_page(0x5A);
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let addr = page as usize;
        let flipper = std::thread::spawn(move || {
            let mut old = 0u32;
            while !stop2.load(AtomicOrdering::Relaxed) {
                // SAFETY: 自分で確保したページの保護を往復させる。
                unsafe {
                    VirtualProtect(addr as *const c_void, 4096, PAGE_NOACCESS, &mut old);
                    VirtualProtect(addr as *const c_void, 4096, PAGE_READWRITE, &mut old);
                }
            }
        });
        let mut buf = [0u8; 64];
        let mut outcomes = 0u32;
        for _ in 0..2000 {
            if ProcessMemory.read_exact(addr as u64, &mut buf) {
                assert!(
                    buf.iter().all(|&b| b == 0x5A),
                    "成功した読みは全バイト揃っていなければならない"
                );
            }
            outcomes += 1;
        }
        stop.store(true, AtomicOrdering::Relaxed);
        flipper.join().unwrap();
        assert_eq!(outcomes, 2000);
        // SAFETY: 後始末。
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };
    }

    #[test]
    fn com_detours_cover_every_known_method() {
        // L02: 既知インターフェイスの全メソッドに (index, arity) の
        // Detour があること。Detour のアドレスは非 0。
        for def in crate::com::KNOWN_INTERFACES {
            for m in def.methods {
                let d = com_detour_for(m.index, m.arity);
                assert!(
                    d.is_some(),
                    "{}::{} (index {}, arity {}) has no detour",
                    def.name,
                    m.name,
                    m.index,
                    m.arity
                );
                assert_ne!(d.unwrap(), 0);
            }
        }
        // 未知の組は None。
        assert!(com_detour_for(21, 0).is_none());
        assert!(com_detour_for(3, 0).is_none());
        assert!(com_detour_for(0, 0).is_none());
        // Factory 関数の Detour も非 0。
        assert_ne!(detour_co_create_instance as CoCreateInstanceFn as usize, 0);
        assert_ne!(detour_co_get_class_object as CoGetClassObjectFn as usize, 0);
    }

    #[test]
    fn detour_for_covers_every_table_api() {
        // F27: 完了観測の 2 API を含め、表の全 API に Detour が割当てられる。
        for api in crate::api::api_table() {
            assert_ne!(detour_for(api.api_id), 0, "{}", api.function);
        }
        assert_eq!(detour_for(999), 0);
    }

    #[test]
    fn prepare_returns_passthrough_while_record_path_active() {
        let _global = TEST_RUNTIME_LOCK.lock().unwrap();
        // G15: 記録経路の実行中に同じスレッドから prepare を呼ぶと、
        // Agent 自身の呼び出しとして記録せず素通しになる。
        // Global runtime tests serialize registration with TEST_RUNTIME_LOCK.
        assert!(runtime().is_none());
        let pool = Arc::new(SlotPool::new(2));
        let agent = Arc::new(Agent::new(
            pool,
            RingConfig::new(64, 4096),
            Arc::new(HostMonitor::always_alive()),
        ));
        let rt = Arc::new(HookRuntime::new(agent, Vec::new(), None));
        rt.set_original(API_CREATE_FILE_W, 0x1234_5678);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());

        // 1 回目: 記録経路に入る（ガードと flight を保持する）。
        let first = prepare(API_CREATE_FILE_W);
        let mut guard = match first {
            Prepare::Record { guard, flight, .. } => {
                let _flight = flight;
                guard
            }
            Prepare::Passthrough { .. } => panic!("expected Record on first prepare"),
            Prepare::Unavailable => panic!("expected Record, runtime/original missing"),
        };
        assert!(ReentrancyGuard::is_active());

        // 記録経路の実行中は 2 回目の prepare が素通しになる
        // （元関数ポインタは引けるが、記録はしない）。
        match prepare(API_CREATE_FILE_W) {
            Prepare::Passthrough { original } => assert_eq!(original, 0x1234_5678),
            Prepare::Record { .. } => panic!("expected Passthrough while record path active"),
            Prepare::Unavailable => panic!("expected Passthrough, runtime/original missing"),
        };

        // 元の API 実行中（suspend 中）は、アプリ由来の入れ子呼び出しとして
        // 再び記録経路に入れる (A43)。
        guard.suspend();
        assert!(!ReentrancyGuard::is_active());
        let nested = prepare(API_CREATE_FILE_W);
        let nested_guard = match nested {
            Prepare::Record { guard, .. } => guard,
            Prepare::Passthrough { .. } => panic!("expected Record while outer guard suspended"),
            Prepare::Unavailable => panic!("expected Record, runtime/original missing"),
        };
        assert!(ReentrancyGuard::is_active());
        drop(nested_guard);
        assert!(!ReentrancyGuard::is_active());
        guard.resume();
        assert!(ReentrancyGuard::is_active());
        drop(guard);
        assert!(!ReentrancyGuard::is_active());

        assert!(clear_runtime(&rt));
        assert!(runtime().is_none());
    }

    #[test]
    fn prepare_suppresses_internal_api_unless_detailed() {
        let _global = TEST_RUNTIME_LOCK.lock().unwrap();
        // L15: 内部 API (Nt*) は詳細調査モードでのみ記録経路に入る。
        // 無効な場合は元の API だけ素通しで呼ぶ。Win32 API は影響を
        // 受けない。グローバルランタイムを使うテスト同士は排他する。
        assert!(runtime().is_none());
        let pool = Arc::new(SlotPool::new(2));
        let agent = Arc::new(Agent::new(
            pool,
            RingConfig::new(64, 4096),
            Arc::new(HostMonitor::always_alive()),
        ));
        let rt = Arc::new(HookRuntime::new(agent, Vec::new(), None));
        rt.set_original(API_NT_CREATE_FILE, 0x1234_5678);
        rt.set_original(API_CREATE_FILE_W, 0x1234_5678);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());

        // 詳細調査モード無効（既定）: NtCreateFile は素通し。
        match prepare(API_NT_CREATE_FILE) {
            Prepare::Passthrough { original } => assert_eq!(original, 0x1234_5678),
            Prepare::Record { .. } => panic!("expected Passthrough for internal API"),
            Prepare::Unavailable => panic!("expected Passthrough, runtime/original missing"),
        }
        // 同じ条件で CreateFileW は記録経路に入る（ガードはすぐ落とす）。
        match prepare(API_CREATE_FILE_W) {
            Prepare::Record { guard, flight, .. } => {
                drop(flight);
                drop(guard);
            }
            Prepare::Passthrough { .. } => panic!("expected Record for Win32 API"),
            Prepare::Unavailable => panic!("expected Record, runtime/original missing"),
        }
        assert!(clear_runtime(&rt));
        assert!(runtime().is_none());

        // 詳細調査モード有効: NtCreateFile も記録経路に入る。
        let pool = Arc::new(SlotPool::new(2));
        let agent = Arc::new(Agent::new(
            pool,
            RingConfig::new(64, 4096),
            Arc::new(HostMonitor::always_alive()),
        ));
        let rt = Arc::new(HookRuntime::new(agent, Vec::new(), None).with_detailed_mode(true));
        rt.set_original(API_NT_CREATE_FILE, 0x1234_5678);
        assert!(set_runtime(Arc::clone(&rt)).is_ok());
        match prepare(API_NT_CREATE_FILE) {
            Prepare::Record { guard, flight, .. } => {
                drop(flight);
                drop(guard);
            }
            Prepare::Passthrough { .. } => {
                panic!("expected Record for internal API in detailed mode")
            }
            Prepare::Unavailable => panic!("expected Record, runtime/original missing"),
        }
        assert!(clear_runtime(&rt));
        assert!(runtime().is_none());
    }
}
