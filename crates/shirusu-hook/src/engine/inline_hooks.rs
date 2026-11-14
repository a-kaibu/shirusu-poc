//! Inline Hook（L01）：スレッド停止、トランポリン確保、設置・解除。

use super::*;

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
    /// Only these bytes were overwritten; stolen instruction tails stay intact.
    pub patched_len: usize,
    /// Exact bytes published by this hook, for ownership checks on removal.
    pub installed_bytes: Vec<u8>,
    pub restoration: InlineRestoration,
    /// L23: the patch enters through a caller-capturing entry stub, so the
    /// Detour can exclude Windows-internal callers. False records every caller.
    pub caller_boundary: bool,
}

#[derive(Debug, Default)]
pub struct InlineRestoration {
    pub(super) protection: std::sync::atomic::AtomicU32,
    pub(super) code_released: std::sync::atomic::AtomicBool,
    pub(super) cache_pending: std::sync::atomic::AtomicBool,
}
impl InlineHook {
    pub fn maintenance_pending(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.restoration.protection.load(Ordering::Acquire) != 0
            || self.restoration.cache_pending.load(Ordering::Acquire)
    }
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
pub(super) enum InlineOriginalSlot {
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
pub(super) struct PlannedInline {
    pub(super) slot: InlineOriginalSlot,
    pub(super) target: usize,
    pub(super) detour: usize,
    pub(super) plan: StolenPlan,
    pub(super) original_bytes: Vec<u8>,
}

/// Snapshot/open thread handles before suspension; no heap activity until resume.
/// Drop 時にも再開するため、途中で失敗しても停止したままにならない。
pub(super) struct SuspendedThreads {
    pub(super) handles: Vec<*mut c_void>,
    pub(super) thread_ids: Vec<u32>,
    pub(super) snapshot: Option<crate::thread_snapshot::ThreadSnapshot>,
}

// The x64 Windows SDK declares CONTEXT with DECLSPEC_ALIGN(16), but the
// windows-sys 0.59 binding only has repr(C). Preserve the native buffer alignment
// explicitly; otherwise GetThreadContext can fail and every hook is refused as
// thread-in-target by the fail-safe IP check.
#[repr(C, align(16))]
pub(super) struct AlignedContext(CONTEXT);

pub(super) fn thread_instruction_pointer(handle: *mut c_void) -> Result<usize, u32> {
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

/// [`SuspendedThreads::suspend_all`] が取り直す回数の上限。
pub(super) const SUSPEND_ATTEMPTS: u32 = 4;

/// OpenThread が存在しないスレッド ID に返すエラー。
const ERROR_INVALID_PARAMETER: u32 = 87;

impl SuspendedThreads {
    /// 全スレッドを停止する。1 つでも停止できなければ、既に停止した
    /// スレッドを再開して Err を返す（パッチ中の実行と競合させない）。
    ///
    /// 一覧の取得から停止までの間にスレッドが生まれたり終わったりすると
    /// 失敗し得るため、[`SUSPEND_ATTEMPTS`] 回まで取り直す（レビュー
    /// 2026-11-14 P2-8: 1 回の失敗でその回の設置や復元が丸ごと抜けていた）。
    pub(super) fn suspend_all() -> Result<Self, &'static str> {
        let mut attempt = 1;
        loop {
            match Self::suspend_all_after_snapshot(|| {}) {
                Ok(suspended) => return Ok(suspended),
                Err(_) if attempt < SUSPEND_ATTEMPTS => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(reason) => return Err(reason),
            }
        }
    }

    pub(super) fn suspend_all_after_snapshot(
        before_suspend: impl FnOnce(),
    ) -> Result<Self, &'static str> {
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
                    // The thread exited after the snapshot (its ID no longer
                    // names a thread). Skipping it is safe: a thread that is
                    // in fact still running appears in the second snapshot
                    // below, which then refuses the set. Any other failure
                    // (access denied) stops the attempt.
                    if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
                        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
                        continue;
                    }
                    failed = true;
                    break;
                }
                // A terminated thread ID may have been reused since Toolhelp.
                // Never suspend a handle belonging to a different process;
                // our thread with that ID has exited, so skip it.
                if unsafe { GetProcessIdOfThread(handle) } != current_pid {
                    unsafe { CloseHandle(handle) };
                    more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
                    continue;
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
    pub(super) fn any_ip_in_range(&self, start: usize, end: usize) -> bool {
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
    pub(super) fn resume(mut self) {
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
pub(super) fn resolve_export(module: &str, function: &str) -> Option<usize> {
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
pub(super) fn follow_import_thunks(mut address: usize) -> Option<usize> {
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

pub(super) fn is_existing_detour(target: usize, detour: usize, bitness: u32, bytes: &[u8]) -> bool {
    if bytes.starts_with(&build_patch(target as u64, detour as u64, bitness)) {
        return true;
    }
    // A relay or caller-capturing entry stub (L23) sits between the patch and
    // the Detour. Follow one jump and compare the bytes we would have written.
    let Some(relay) = crate::inline::jump_destination(target as u64, bytes, bitness, |slot| {
        let mut value = [0u8; 8];
        let width = (bitness / 8) as usize;
        ProcessMemory
            .read_exact(slot, &mut value[..width])
            .then(|| u64::from_le_bytes(value))
    }) else {
        return false;
    };
    let mut relay_bytes = [0; 32];
    if !ProcessMemory.read_exact(relay, &mut relay_bytes) {
        return false;
    }
    if relay_bytes.starts_with(&build_patch(relay, detour as u64, bitness)) {
        return true;
    }
    crate::caller::entry_slot_offset().is_some_and(|slot| {
        relay_bytes.starts_with(&crate::caller::entry_stub_bytes(
            relay,
            detour as u64,
            bitness,
            slot,
        ))
    })
}

/// `target` の近く（±2GB）に実行可能メモリを確保する。近くに空きが
/// 無ければ None（呼び出し側は全体確保＋絶対ジャンプへ切り替える）。
pub(super) fn alloc_near(target: usize, size: usize) -> Option<usize> {
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
pub(super) fn restore_inline(hook: &InlineHook) -> Result<(), ()> {
    restore_inline_with_ops(
        hook,
        |address, size, protection, old| unsafe { VirtualProtect(address, size, protection, old) },
        |address, size| unsafe { FlushInstructionCache(GetCurrentProcess(), address, size) },
    )
}

pub(super) fn restore_inline_with_ops(
    hook: &InlineHook,
    mut protect: impl FnMut(*const c_void, usize, u32, *mut u32) -> i32,
    mut flush: impl FnMut(*const c_void, usize) -> i32,
) -> Result<(), ()> {
    use std::sync::atomic::Ordering;
    let bytes = hook.original_bytes.get(..hook.patched_len).ok_or(())?;
    if !hook.restoration.code_released.load(Ordering::Acquire) {
        // Current x86/x64 jump encodings are at most 14 bytes. A fixed buffer
        // avoids allocation while application threads are suspended.
        let mut observed = [0u8; 32];
        let observed = observed.get_mut(..hook.patched_len).ok_or(())?;
        if hook.installed_bytes.len() != observed.len()
            || !ProcessMemory.read_exact(hook.target as u64, observed)
        {
            return Err(());
        }
        if observed != hook.installed_bytes.as_slice() {
            // A different owner replaced the patch. Retain its bytes and only
            // finish page/cache work still owed by our earlier publication.
            hook.restoration
                .code_released
                .store(true, Ordering::Release);
            finish_inline_write(hook.target, bytes.len(), &hook.restoration, protect, flush);
            return if hook.maintenance_pending() {
                Err(())
            } else {
                Ok(())
            };
        }
        patch_target_with_ops(
            hook.target,
            bytes,
            &hook.restoration,
            || {},
            &mut protect,
            &mut flush,
        )?;
        hook.restoration
            .code_released
            .store(true, Ordering::Release);
    } else {
        finish_inline_write(hook.target, bytes.len(), &hook.restoration, protect, flush);
    }
    if hook.maintenance_pending() {
        Err(())
    } else {
        Ok(())
    }
}

pub(super) fn finish_inline_write(
    target: usize,
    len: usize,
    state: &InlineRestoration,
    mut protect: impl FnMut(*const c_void, usize, u32, *mut u32) -> i32,
    mut flush: impl FnMut(*const c_void, usize) -> i32,
) {
    use std::sync::atomic::Ordering;
    let protection = state.protection.load(Ordering::Acquire);
    if protection != 0 {
        let mut ignored = 0;
        if protect(target as *const c_void, len, protection, &mut ignored) != 0 {
            state.protection.store(0, Ordering::Release);
        }
    }
    if state.cache_pending.load(Ordering::Acquire) && flush(target as *const c_void, len) != 0 {
        state.cache_pending.store(false, Ordering::Release);
    }
}

/// Err means nothing was published. Post-write failures remain owned by state;
/// callers must keep the descriptor even though the pointer is already live.
pub(super) fn patch_target_with(
    target: usize,
    patch: &[u8],
    state: &InlineRestoration,
    before_write: impl FnOnce(),
) -> Result<(), ()> {
    patch_target_with_ops(
        target,
        patch,
        state,
        before_write,
        |address, size, protection, old| unsafe { VirtualProtect(address, size, protection, old) },
        |address, size| unsafe { FlushInstructionCache(GetCurrentProcess(), address, size) },
    )
}

pub(super) fn patch_target_with_ops(
    target: usize,
    patch: &[u8],
    state: &InlineRestoration,
    before_write: impl FnOnce(),
    mut protect: impl FnMut(*const c_void, usize, u32, *mut u32) -> i32,
    flush: impl FnMut(*const c_void, usize) -> i32,
) -> Result<(), ()> {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS,
    };
    let end = target.checked_add(patch.len()).ok_or(())?;
    if patch.is_empty() {
        return Err(());
    }
    let mut region = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    if unsafe {
        VirtualQuery(
            target as *const c_void,
            region.as_mut_ptr(),
            std::mem::size_of_val(&region),
        )
    } == 0
    {
        return Err(());
    }
    let region = unsafe { region.assume_init() };
    // VirtualProtect reports only the first page's protection. Refuse crossing
    // regions rather than flattening different original protections on restore.
    if region.State != MEM_COMMIT
        || region.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
        || (region.BaseAddress as usize)
            .checked_add(region.RegionSize)
            .is_none_or(|limit| end > limit)
    {
        return Err(());
    }
    let mut old = 0;
    if protect(
        target as *const c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old,
    ) == 0
    {
        return Err(());
    }
    let _ = state
        .protection
        .compare_exchange(0, old, Ordering::AcqRel, Ordering::Acquire);
    before_write();
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, patch.len());
    }
    state.cache_pending.store(true, Ordering::Release);
    finish_inline_write(target, patch.len(), state, protect, flush);
    Ok(())
}

// Published trampolines survive uninstall for late passthrough callers.
// Unpublished reservations are owned and reclaimed, including their budget.
pub(super) static TRAMPOLINE_ALLOCATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) struct TrampolineAllocation {
    address: usize,
    published: bool,
}

impl TrampolineAllocation {
    pub(super) fn reserve() -> Result<Self, &'static str> {
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
pub(super) fn prepare_inline(
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
    // L23: API-table hooks enter through a stub that hands the caller's return
    // address to the Detour. It lives in this allocation, so it is retained with
    // the trampoline. Without a reachable stub, fall back to the direct patch
    // and record every caller, as before.
    let stub = match (&p.slot, crate::caller::entry_slot_offset()) {
        (InlineOriginalSlot::Api(_), Some(slot)) => {
            let stub = trampoline + RELAY_OFFSET;
            let entry = build_patch(p.target as u64, stub as u64, bitness);
            let stub_code =
                crate::caller::entry_stub_bytes(stub as u64, p.detour as u64, bitness, slot);
            (entry.len() <= p.plan.patch_len
                && code.len() <= RELAY_OFFSET
                && RELAY_OFFSET + stub_code.len() <= TRAMPOLINE_SIZE)
                .then_some((stub, entry, stub_code))
        }
        _ => None,
    };
    let caller_boundary = stub.is_some();
    let direct_patch = build_patch(p.target as u64, p.detour as u64, bitness);
    let patch = if let Some((stub, entry, stub_code)) = stub {
        // SAFETY: stub lies inside the freshly allocated executable region.
        unsafe {
            std::ptr::copy_nonoverlapping(stub_code.as_ptr(), stub as *mut u8, stub_code.len());
        }
        entry
    } else if direct_patch.len() > p.plan.patch_len {
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
        if FlushInstructionCache(
            GetCurrentProcess(),
            trampoline as *const c_void,
            TRAMPOLINE_SIZE,
        ) == 0
        {
            return Err("flush-failed");
        }
    }
    Ok((
        InlineHook {
            api_id: p.slot.report_id(),
            target: p.target,
            trampoline,
            trampoline_size: TRAMPOLINE_SIZE,
            stolen_len: p.plan.stolen_len,
            original_bytes: p.original_bytes.clone(),
            patched_len: patch.len(),
            installed_bytes: patch.clone(),
            restoration: InlineRestoration::default(),
            caller_boundary,
        },
        patch,
        allocation,
    ))
}

/// Allocate/decode before suspension; the stopped interval only inspects IPs,
/// publishes atomics and copies prepared bytes. Keep plans alive until resume.
pub(super) fn install_planned(
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
                let mut observed = [0u8; 64];
                let unchanged = observed
                    .get_mut(..p.original_bytes.len())
                    .is_some_and(|bytes| {
                        ProcessMemory.read_exact(p.target as u64, bytes)
                            && bytes == p.original_bytes.as_slice()
                    });
                if !unchanged {
                    *result = Err("target-changed");
                    continue;
                }
                if patch_target_with(p.target, patch, &hook.restoration, || {
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
            api_table().filter(|api| {
                !crate::api::is_internal_api(api.api_id) && !crate::api::is_iat_only_api(api.api_id)
            }),
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
pub(super) unsafe fn install_inline_hooks_for(
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
pub(super) unsafe fn uninstall_inline_indices(installed: &[InlineHook]) -> Vec<usize> {
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
        if suspender.any_ip_in_range(h.target, h.target + h.patched_len) {
            unrestored.push(index);
            continue;
        }
        match restore_inline(h) {
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
