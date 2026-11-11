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
    API_GET_QUEUED_COMPLETION_STATUS, API_READ_FILE, API_WRITE_FILE,
};
use crate::capture::{self, MemoryReader};
use crate::com::{
    build_cloned_vtable, interface_by_iid, ComCloneRegistry, Guid, COM_FACTORY_COUNT,
    COM_FACTORY_CO_CREATE_INSTANCE, COM_FACTORY_CO_GET_CLASS_OBJECT, COM_FACTORY_REPORT_ID_BASE,
    FACTORY_METHOD_INDEX, IID_IUNKNOWN, KNOWN_FACTORIES,
};
use crate::inline::{build_patch, build_trampoline, plan_stolen, StolenPlan};
use crate::pe;
use crate::plan::{build_plan, HookPlan};
use crate::runtime::{pop_call, push_call, ComCallGuard, HookRuntime, ReentrancyGuard};
use crate::winrt::{
    default_interface_for_class, winrt_method_return, IID_IACTIVATION_FACTORY, IID_IINSPECTABLE,
    WINRT_ACTIVATIONS, WINRT_ACTIVATION_API_ID, WINRT_ACTIVATION_COUNT,
    WINRT_ACTIVATION_LEAVE_SCHEMA_ID, WINRT_ACTIVATION_REPORT_ID_BASE,
    WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE, WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
};
use std::ffi::c_void;
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, INVALID_HANDLE_VALUE,
};
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
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread,
    SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
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
    /// 対象 API のインポートが 1 件も無い（計画が空）。計画（全 API
    /// が missing）を一緒に返す。これは**初期化の失敗ではない**:
    /// 対象 API を使わない正常なアプリが存在するため、呼び出し側は
    /// 「0 件設置・全件欠落」として記録を継続してよい
    /// (レビュー #4 の #8)。
    NoTargets(HookPlan),
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
        slot.write_unaligned(value);
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
    let plan = build_plan(&sites);
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
pub unsafe fn uninstall_hooks(installed: &InstalledHooks) -> Vec<u32> {
    let failed = crate::plan::restore_all(installed.slots.len(), |i| {
        let (iat_rva, original) = installed.slots[i];
        // SAFETY: 呼び出し側の契約に従う。
        let slot =
            unsafe { (installed.module_base as *mut u8).add(iat_rva as usize) } as *mut usize;
        // SAFETY: 同上。
        unsafe { write_slot(slot, original) }
    });
    failed.iter().map(|&i| installed.slots[i].0).collect()
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
//   トランポリンだけ解放する（P1-6 と同じ「残存は正直に報告」の扱い）。

/// Inline Hook 1 件分。解除時にプロローグを元へ戻し、トランポリンを
/// 解放するために保持する。
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
/// Factory 別表へ、WinRT アクティベーション関数のものは WinRT 別表へ
/// 格納する（L02・L14）。
enum InlineOriginalSlot {
    Api(u32),
    ComFactory(usize),
    WinRtActivation(usize),
}

impl InlineOriginalSlot {
    /// 設置結果の報告用 ID。Factory 関数・アクティベーション関数は
    /// API 表に無いため、予約値を使う。
    fn report_id(&self) -> u32 {
        match self {
            InlineOriginalSlot::Api(id) => *id,
            InlineOriginalSlot::ComFactory(i) => COM_FACTORY_REPORT_ID_BASE + *i as u32,
            InlineOriginalSlot::WinRtActivation(i) => WINRT_ACTIVATION_REPORT_ID_BASE + *i as u32,
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

/// 対象プロセスの全スレッド（呼び出し元を除く）を一時停止するガード。
/// Drop 時にも再開するため、途中で失敗しても停止したままにならない。
struct SuspendedThreads {
    handles: Vec<*mut c_void>,
}

impl SuspendedThreads {
    /// 全スレッドを停止する。1 つでも停止できなければ、既に停止した
    /// スレッドを再開して Err を返す（パッチ中の実行と競合させない）。
    fn suspend_all() -> Result<Self, ()> {
        let current_tid = unsafe { GetCurrentThreadId() };
        let current_pid = unsafe { GetCurrentProcessId() };
        // SAFETY: スレッド一覧のスナップショット。
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let mut handles: Vec<*mut c_void> = Vec::new();
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
                // SAFETY: 自プロセスのスレッド。
                if unsafe { SuspendThread(handle) } == u32::MAX {
                    unsafe { CloseHandle(handle) };
                    failed = true;
                    break;
                }
                handles.push(handle);
            }
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        if failed {
            for h in handles {
                unsafe { ResumeThread(h) };
                unsafe { CloseHandle(h) };
            }
            return Err(());
        }
        Ok(Self { handles })
    }

    /// 停止中のいずれかのスレッドの命令ポインタが [start, end) にあるか。
    /// コンテキスト取得に失敗したスレッドは「範囲内」とみなし、安全側に倒す。
    fn any_ip_in_range(&self, start: usize, end: usize) -> bool {
        for &handle in &self.handles {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            ctx.ContextFlags = CONTEXT_CONTROL;
            // SAFETY: 停止中の自プロセスのスレッド。
            if unsafe { GetThreadContext(handle, &mut ctx) } == 0 {
                return true;
            }
            #[cfg(target_arch = "x86_64")]
            let ip = ctx.Rip as usize;
            #[cfg(target_arch = "x86")]
            let ip = ctx.Eip as usize;
            if (start..end).contains(&ip) {
                return true;
            }
        }
        false
    }

    /// 全スレッドを再開し、ハンドルを閉じる。
    fn resume(mut self) {
        let handles = std::mem::take(&mut self.handles);
        for h in handles {
            unsafe { ResumeThread(h) };
            unsafe { CloseHandle(h) };
        }
    }
}

impl Drop for SuspendedThreads {
    fn drop(&mut self) {
        let handles = std::mem::take(&mut self.handles);
        for h in handles {
            unsafe { ResumeThread(h) };
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
    proc.map(|f| f as usize)
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
    // SAFETY: 同上。書き込み後は元の保護属性へ戻す。
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, patch.len());
        let mut tmp: u32 = 0;
        VirtualProtect(target as *const c_void, patch.len(), old, &mut tmp);
        FlushInstructionCache(GetCurrentProcess(), target as *const c_void, patch.len());
    }
    Ok(())
}

/// 計画済み 1 件の Inline Hook を設置する（スレッド停止中に呼ぶこと）。
/// トランポリンを確保・書き込み、対象の先頭をパッチし、ランタイムの
/// `original` をトランポリンへ差し替える。
fn install_one_inline(
    rt: &HookRuntime,
    p: &PlannedInline,
    bitness: u32,
) -> Result<InlineHook, &'static str> {
    const TRAMPOLINE_SIZE: usize = 0x1000;
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
    let code = match build_trampoline(&p.plan, trampoline as u64) {
        Ok(c) => c,
        Err(e) => {
            unsafe { VirtualFree(trampoline as *mut c_void, 0, MEM_RELEASE) };
            return Err(e.reason());
        }
    };
    // SAFETY: 確保したての実行可能領域へ書き込む。
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len());
        FlushInstructionCache(GetCurrentProcess(), trampoline as *const c_void, code.len());
    }
    if patch_target(
        p.target,
        &build_patch(p.target as u64, p.detour as u64, bitness),
    )
    .is_err()
    {
        unsafe { VirtualFree(trampoline as *mut c_void, 0, MEM_RELEASE) };
        return Err("protect-failed");
    }
    match p.slot {
        InlineOriginalSlot::Api(api_id) => rt.set_original(api_id, trampoline),
        InlineOriginalSlot::ComFactory(index) => rt.set_com_original(index, trampoline),
        InlineOriginalSlot::WinRtActivation(index) => rt.set_winrt_original(index, trampoline),
    }
    Ok(InlineHook {
        api_id: p.slot.report_id(),
        target: p.target,
        trampoline,
        trampoline_size: TRAMPOLINE_SIZE,
        stolen_len: p.plan.stolen_len,
        original_bytes: p.original_bytes.clone(),
    })
}

/// 全 API へ Inline Hook を設置する（L01）。
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
pub unsafe fn install_inline_hooks(rt: &HookRuntime) -> InlineInstallOutcome {
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut outcome = InlineInstallOutcome::default();
    // 計画: 解決・デコードまでを先に行い、パッチ対象だけを残す。
    let mut planned: Vec<PlannedInline> = Vec::new();
    for api in api_table() {
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
        if bytes.starts_with(&build_patch(target as u64, detour as u64, bitness)) {
            outcome.skipped.push((api.api_id, "already-hooked"));
            continue;
        }
        match plan_stolen(&bytes, target as u64, detour as u64, bitness) {
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
    if planned.is_empty() {
        return outcome;
    }
    // 他スレッドを止められない場合は全体を見送る。
    let Ok(suspender) = SuspendedThreads::suspend_all() else {
        for p in planned {
            outcome
                .skipped
                .push((p.slot.report_id(), "thread-suspend-failed"));
        }
        return outcome;
    };
    for p in planned {
        // 停止中のスレッドがパッチ範囲内で止まっていたら見送る
        // （復帰後にパッチの途中バイトを実行してしまうため）。
        if suspender.any_ip_in_range(p.target, p.target + p.plan.patch_len) {
            outcome
                .skipped
                .push((p.slot.report_id(), "thread-in-target"));
            continue;
        }
        match install_one_inline(rt, &p, bitness) {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((p.slot.report_id(), reason)),
        }
    }
    suspender.resume();
    outcome
}

/// Inline Hook を解除する（L01）。プロローグを元のバイトへ戻し、
/// 復元できたトランポリンだけ解放する。復元できなかった api_id を返す
/// (P1-6 と同じ扱い。戻り値が空でなければ Detour が残存する)。
///
/// 解除は IAT 復元より先に行うこと。トランポリン内に停止中のスレッドが
/// あれば、その API のプロローグは復元してもトランポリンは解放しない
/// （実行中のスレッドが解放済み領域へ戻ると落ちる）。プロローグ復元
/// 自体は安全：トランポリンの戻りジャンプは `target + stolen_len` を
/// 指し、復元後の元命令へ続くためである。
///
/// # Safety
/// `installed` は install_inline_hooks が返したものであり、対象モジュール
/// がまだロードされていること。
pub unsafe fn uninstall_inline_hooks(installed: &[InlineHook]) -> Vec<u32> {
    if installed.is_empty() {
        return Vec::new();
    }
    // スレッドを止められない場合は何も復元しない（全件を未復元として報告）。
    let Ok(suspender) = SuspendedThreads::suspend_all() else {
        return installed.iter().map(|h| h.api_id).collect();
    };
    let mut unrestored = Vec::new();
    let mut to_free: Vec<usize> = Vec::new();
    for h in installed {
        let in_trampoline =
            suspender.any_ip_in_range(h.trampoline, h.trampoline + h.trampoline_size);
        match patch_target(h.target, &h.original_bytes) {
            Ok(()) => {
                if !in_trampoline {
                    to_free.push(h.trampoline);
                }
                // トランポリン内にスレッドがいれば解放しない（リークするが
                // 安全。プロセス終了時に OS が回収する）。
            }
            Err(()) => unrestored.push(h.api_id),
        }
    }
    suspender.resume();
    for t in to_free {
        // SAFETY: 復元済みで、停止中のスレッドが中にいないトランポリン。
        unsafe { VirtualFree(t as *mut c_void, 0, MEM_RELEASE) };
    }
    unrestored
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

/// 計画済み Inline Hook の表示名（見送り理由の報告用）。
fn planned_inline_name(p: &PlannedInline) -> &'static str {
    match p.slot {
        InlineOriginalSlot::Api(_) => "?",
        InlineOriginalSlot::ComFactory(i) => com_factory_name(i),
        InlineOriginalSlot::WinRtActivation(i) => winrt_activation_name(i),
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
        if bytes.starts_with(&build_patch(target as u64, detour as u64, bitness)) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_stolen(&bytes, target as u64, detour as u64, bitness) {
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
    if planned.is_empty() {
        return outcome;
    }
    let Ok(suspender) = SuspendedThreads::suspend_all() else {
        for p in planned {
            outcome
                .skipped
                .push((planned_inline_name(&p), "thread-suspend-failed"));
        }
        return outcome;
    };
    for p in planned {
        let name = planned_inline_name(&p);
        if suspender.any_ip_in_range(p.target, p.target + p.plan.patch_len) {
            outcome.skipped.push((name, "thread-in-target"));
            continue;
        }
        match install_one_inline(rt, &p, bitness) {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((name, reason)),
        }
    }
    suspender.resume();
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
        if bytes.starts_with(&build_patch(target as u64, detour as u64, bitness)) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_stolen(&bytes, target as u64, detour as u64, bitness) {
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
    if planned.is_empty() {
        return outcome;
    }
    let Ok(suspender) = SuspendedThreads::suspend_all() else {
        for p in planned {
            outcome
                .skipped
                .push((planned_inline_name(&p), "thread-suspend-failed"));
        }
        return outcome;
    };
    for p in planned {
        let name = planned_inline_name(&p);
        if suspender.any_ip_in_range(p.target, p.target + p.plan.patch_len) {
            outcome.skipped.push((name, "thread-in-target"));
            continue;
        }
        match install_one_inline(rt, &p, bitness) {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((name, reason)),
        }
    }
    suspender.resume();
    outcome
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
pub unsafe fn intercept_object(rt: &HookRuntime, ptr: usize, iid: Guid) -> ComInterceptOutcome {
    let Some(def) = interface_by_iid(&iid) else {
        return ComInterceptOutcome::UnknownInterface;
    };
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
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
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
    unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, Handle) -> Handle;
type ReadFileFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut c_void) -> i32;
type WriteFileFn = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *mut c_void) -> i32;
type CloseHandleFn = unsafe extern "system" fn(Handle) -> i32;
type GetOverlappedResultFn = unsafe extern "system" fn(Handle, *mut c_void, *mut u32, i32) -> i32;
type GetQueuedCompletionStatusFn =
    unsafe extern "system" fn(Handle, *mut u32, *mut u64, *mut *mut c_void, u32) -> i32;

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
        _ => detour_for_generated(api_id),
    }
}

// ---- L03: 生成 API 用の汎用 Detour ----
//
// 生成 API は全て整数・ポインタ引数だけを持つ（L1）。x64 / x86 の
// 呼び出し規約では、そのような引数は 1 スロット（usize 1 個）に収まる
// ため、引数個数ごとの汎用トランポリンで中継できる。浮動小数点引数・
// 値渡し構造体・可変長引数を持つ API は生成対象外（生成器が弾く）。
// 64bit 固定型（I64 / U64）は x86 で 2 スロットを占めるため同様に
// 対象外。生成器の 1 スロット制約と api.rs のテストがこれを保証する。
//
// 各生成 API には `engine_generated.inc` の専用トランポリンがあり、
// そこから `generic_detour::<N>` を呼ぶ。トランポリンは API ごとの
// 正しい引数個数の `extern "system" fn` であるため、元の関数が見る
// レジスタ・スタック配置は手書き Detour と同じになる。

type GenericFn0 = unsafe extern "system" fn() -> usize;
type GenericFn1 = unsafe extern "system" fn(usize) -> usize;
type GenericFn2 = unsafe extern "system" fn(usize, usize) -> usize;
type GenericFn3 = unsafe extern "system" fn(usize, usize, usize) -> usize;
type GenericFn4 = unsafe extern "system" fn(usize, usize, usize, usize) -> usize;
type GenericFn5 = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> usize;
type GenericFn6 = unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> usize;
type GenericFn7 =
    unsafe extern "system" fn(usize, usize, usize, usize, usize, usize, usize) -> usize;
type GenericFn8 =
    unsafe extern "system" fn(usize, usize, usize, usize, usize, usize, usize, usize) -> usize;
type GenericFn9 = unsafe extern "system" fn(
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
type GenericFn10 = unsafe extern "system" fn(
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
type GenericFn11 = unsafe extern "system" fn(
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
type GenericFn12 = unsafe extern "system" fn(
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
/// 呼び出し側は `original` がこの `N` の `extern "system" fn` である
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
fn generic_detour<const N: usize>(api_id: u32, args: &[usize; N]) -> usize {
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
            return unsafe { call_original::<N>(original, args) };
        }
        Prepare::Unavailable => return 0,
    };
    let call_id = rt.alloc_call_id();
    let raw: Vec<u64> = args.iter().map(|a| *a as u64).collect();
    let values = capture::generic_enter(api, &raw);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す。元の呼び出しの中で
    // アプリ由来の入れ子呼び出しが起きた場合は記録される (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { call_original::<N>(original, args) };
    guard.resume();
    call_guard.complete();
    // 透明性: 他の処理より先に LastError を確定させる（overview）。
    let last_error = le.capture_after_original();
    pop_call(call_id);
    let values = capture::generic_leave(api, ret as u64, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

include!("engine_generated.inc");

// ---- L02: COM メソッド・Factory の Detour ----
//
// COM メソッドの Detour は (vtable インデックス, arity) の組ごとに
// 1 個の `extern "system" fn` である。Detour は `this` から追跡表を
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
        let Some(rt) = runtime() else {
            return ComPrepare::Unavailable;
        };
        let original = rt.com_original(factory_index);
        if original == 0 {
            return ComPrepare::Unavailable;
        }
        le.restore_before_original();
        return ComPrepare::Passthrough { original };
    };
    let Some(rt) = runtime() else {
        return ComPrepare::Unavailable;
    };
    let original = rt.com_original(factory_index);
    if original == 0 {
        return ComPrepare::Unavailable;
    }
    // L23: 呼び出し元が Runtime なら記録しない（元の呼び出しだけ素通し）。
    if rt.should_suppress_caller() {
        le.restore_before_original();
        return ComPrepare::Passthrough { original };
    }
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = unsafe { GetCurrentThreadId() } as u64;
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

type CoCreateInstanceFn =
    unsafe extern "system" fn(*const Guid, *mut c_void, u32, *const Guid, *mut *mut c_void) -> i32;
type CoGetClassObjectFn =
    unsafe extern "system" fn(*const Guid, u32, *mut c_void, *const Guid, *mut *mut c_void) -> i32;

/// Factory 呼び出しが返したインターフェイスを追跡対象に加え、既知
/// インターフェイスなら vtable 複製による Detour を設置する。
/// 設置の成否は呼び出しの成否に影響しない（best-effort）。
fn on_factory_result(rt: &Arc<HookRuntime>, factory: &'static str, iid: Guid, ptr: usize) {
    rt.with_com_tracker(|t| {
        t.note_factory_result(ptr as u64, iid, factory);
    });
    if interface_by_iid(&iid).is_some() {
        // SAFETY: ptr は Factory が返した有効なインターフェイス。
        // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
        let _ = unsafe { intercept_object(rt, ptr, iid) };
    }
}

/// WinRT アクティベーション呼び出しが返したインターフェイスを追跡対象に
/// 加え、既知インターフェイスなら vtable 複製による Detour を設置する
/// （L14）。設置の成否は呼び出しの成否に影響しない（best-effort）。
///
/// - `RoActivateInstance` が返すのはクラスの既定インターフェイス
///   （表に無いクラスは `IInspectable`）。
/// - `RoGetActivationFactory` が返すのは `IActivationFactory` そのもの。
fn on_activation_result(
    rt: &Arc<HookRuntime>,
    activation_index: usize,
    function: &'static str,
    class_name: &str,
    ptr: usize,
) {
    let iid = match activation_index {
        WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY => IID_IACTIVATION_FACTORY,
        _ => default_interface_for_class(class_name)
            .map(|d| d.iid)
            .unwrap_or(IID_IINSPECTABLE),
    };
    rt.with_com_tracker(|t| {
        t.note_factory_result(ptr as u64, iid, function);
    });
    if interface_by_iid(&iid).is_some() {
        // SAFETY: ptr はアクティベーション関数が返した有効なインターフェイス。
        // Detour の中で、ポインタがアプリへ返される前に呼ぶ。
        let _ = unsafe { intercept_object(rt, ptr, iid) };
    }
}

unsafe extern "system" fn detour_co_create_instance(
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
    let iid_bytes: Vec<u8> = requested.map(|g| g.bytes.to_vec()).unwrap_or_default();
    let clsid_bytes: Vec<u8> = read_guid(clsid as u64)
        .map(|g| g.bytes.to_vec())
        .unwrap_or_default();
    let values = crate::com::com_method_enter_values(
        0,
        &iid_bytes,
        FACTORY_METHOD_INDEX,
        "CoCreateInstance",
        &crate::com::raw_arg_slots(&[
            clsid as usize,
            unk_outer as usize,
            cls_context as usize,
            iid as usize,
            ppv as usize,
        ]),
        &clsid_bytes,
    );
    if let Ok(bytes) = crate::com::encode_com_enter(&values) {
        rt.record_com_enter(tid, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = ComCallGuard::new(&rt, tid, call_id);
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let hr = unsafe { orig(clsid, unk_outer, cls_context, iid, ppv) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
    let values = crate::com::com_method_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_leave(&values) {
        rt.record_com_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

unsafe extern "system" fn detour_co_get_class_object(
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
    let iid_bytes: Vec<u8> = requested.map(|g| g.bytes.to_vec()).unwrap_or_default();
    let clsid_bytes: Vec<u8> = read_guid(clsid as u64)
        .map(|g| g.bytes.to_vec())
        .unwrap_or_default();
    let values = crate::com::com_method_enter_values(
        0,
        &iid_bytes,
        FACTORY_METHOD_INDEX,
        "CoGetClassObject",
        &crate::com::raw_arg_slots(&[
            clsid as usize,
            cls_context as usize,
            server_info as usize,
            iid as usize,
            ppv as usize,
        ]),
        &clsid_bytes,
    );
    if let Ok(bytes) = crate::com::encode_com_enter(&values) {
        rt.record_com_enter(tid, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = ComCallGuard::new(&rt, tid, call_id);
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let hr = unsafe { orig(clsid, cls_context, server_info, iid, ppv) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
    let values = crate::com::com_method_leave_values(hr, returned_object, 0);
    if let Ok(bytes) = crate::com::encode_com_leave(&values) {
        rt.record_com_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    hr
}

type RoActivateInstanceFn = unsafe extern "system" fn(usize, *mut *mut c_void) -> i32;
type RoGetActivationFactoryFn = unsafe extern "system" fn(usize, *mut *mut c_void) -> i32;

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
        let Some(rt) = runtime() else {
            return WinRtPrepare::Unavailable;
        };
        let original = rt.winrt_original(activation_index);
        if original == 0 {
            return WinRtPrepare::Unavailable;
        }
        le.restore_before_original();
        return WinRtPrepare::Passthrough { original };
    };
    let Some(rt) = runtime() else {
        return WinRtPrepare::Unavailable;
    };
    let original = rt.winrt_original(activation_index);
    if original == 0 {
        return WinRtPrepare::Unavailable;
    }
    // L23: 呼び出し元が Runtime なら記録しない（元の呼び出しだけ素通し）。
    if rt.should_suppress_caller() {
        le.restore_before_original();
        return WinRtPrepare::Passthrough { original };
    }
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = unsafe { GetCurrentThreadId() } as u64;
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

/// WinRT アクティベーション関数の Detour 本体。`RoActivateInstance` と
/// `RoGetActivationFactory` は引数の形が同じ（HSTRING のクラス名と out
/// ポインタ）のため、1 個の本体を共有する。HSTRING からクラス名を読み、
/// アクティベーションイベントとして記録し、成功時は返された
/// インターフェイスを追跡対象に加える。
unsafe fn detour_winrt_activation(
    activation_index: usize,
    function: &'static str,
    class_id: usize,
    out: *mut *mut c_void,
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
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            let orig: RoActivateInstanceFn = unsafe { std::mem::transmute(original) };
            return unsafe { orig(class_id, out) };
        }
        WinRtPrepare::Unavailable => return COM_E_FAIL,
    };
    // SAFETY: 設置時に保存した本物のアクティベーション関数。
    let orig: RoActivateInstanceFn = unsafe { std::mem::transmute(original) };
    let call_id = rt.alloc_call_id();
    // HSTRING からクラス名を読む。読めなければ空のまま記録する
    // （クラス名の読み取り失敗で呼び出し自体を失敗させない）。
    let class_name = crate::winrt::read_hstring_string(class_id).unwrap_or_default();
    let values = crate::winrt::winrt_activation_enter_values(
        0,
        &class_name,
        function,
        &crate::com::raw_arg_slots(&[class_id, out as usize]),
    );
    if let Ok(bytes) = crate::winrt::encode_winrt_activation_enter(&values) {
        rt.record_winrt_activation_enter(tid, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = ComCallGuard::new_for(
        &rt,
        tid,
        call_id,
        WINRT_ACTIVATION_API_ID,
        WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
    );
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let hr = unsafe { orig(class_id, out) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
    let _ = last_error; // WinRT は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let mut returned_object = 0u64;
    if hr == 0 && !out.is_null() {
        if let Some(ptr) = read_usize(out as u64).filter(|p| *p != 0) {
            returned_object = ptr as u64;
            on_activation_result(&rt, activation_index, function, &class_name, ptr);
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

unsafe extern "system" fn detour_ro_activate_instance(
    class_id: usize,
    out: *mut *mut c_void,
) -> i32 {
    unsafe {
        detour_winrt_activation(
            WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE,
            "RoActivateInstance",
            class_id,
            out,
        )
    }
}

unsafe extern "system" fn detour_ro_get_activation_factory(
    class_id: usize,
    out: *mut *mut c_void,
) -> i32 {
    unsafe {
        detour_winrt_activation(
            WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
            "RoGetActivationFactory",
            class_id,
            out,
        )
    }
}

/// 元の COM メソッドを呼ぶ。`args` は `this` を除く引数（最大 4 個）。
///
/// # Safety
/// `original` はこの引数個数の `extern "system" fn` であること
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
                t.note_query_interface(this as u64, out as u64, iid, true);
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
            rt.with_com_tracker(|t| t.note_add_ref(this as u64, count));
            (0, count)
        }
        2 => {
            // Release: 戻り値が新しい参照カウント。0 なら寿命終了。
            let count = ret as u32;
            rt.with_com_tracker(|t| t.note_release(this as u64, count));
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
    let mut le = crate::runtime::LastErrorGuard::capture(WinLastError);
    let Some(mut guard) = ReentrancyGuard::try_enter() else {
        le.restore_before_original();
        // SAFETY: original はこの引数個数の COM メソッド。
        return unsafe { call_com_original(original, this, args) };
    };
    let Some(rt) = runtime() else {
        le.restore_before_original();
        // SAFETY: 同上。
        return unsafe { call_com_original(original, this, args) };
    };
    // L23: 呼び出し元が Runtime なら記録しない（元の呼び出しだけ素通し）。
    if rt.should_suppress_caller() {
        le.restore_before_original();
        // SAFETY: 同上。
        return unsafe { call_com_original(original, this, args) };
    }
    let Some(flight) = crate::runtime::DetourFlight::begin(&rt) else {
        le.restore_before_original();
        // SAFETY: 同上。
        return unsafe { call_com_original(original, this, args) };
    };
    let _flight = flight;
    // 追跡対象の確認：このセッションで追跡していないオブジェクトは
    // 元のメソッドを素通しで呼ぶ（記録しない）。
    let (iid, interface_name, method_name) = match rt.with_com_tracker(|t| {
        t.lookup(this as u64).and_then(|o| {
            interface_by_iid(&o.iid)
                .and_then(|d| d.method(method_index).map(|m| (o.iid, d.name, m.name)))
        })
    }) {
        Some(v) => v,
        None => {
            le.restore_before_original();
            // SAFETY: original はこの引数個数の COM メソッド。
            return unsafe { call_com_original(original, this, args) };
        }
    };
    let tid = unsafe { GetCurrentThreadId() } as u64;
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
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで ComCallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = ComCallGuard::new(&rt, tid, call_id);
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: original はこの引数個数の COM メソッド。
    let ret = unsafe { call_com_original(original, this, args) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
    let _ = last_error; // COM は HRESULT が誤りの経路。LastError は復元だけ行う。
    pop_call(call_id);
    let (returned_object, refcount) = com_method_post_call(&rt, this, method_index, args, ret);
    let values = crate::com::com_method_leave_values(ret, returned_object, refcount);
    if let Ok(bytes) = crate::com::encode_com_leave(&values) {
        rt.record_com_leave(tid, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

macro_rules! com_method_detour {
    ($name:ident, $index:expr, 0) => {
        unsafe extern "system" fn $name(this: *mut c_void) -> i32 {
            com_method_dispatch(this as usize, $index, &[])
        }
    };
    ($name:ident, $index:expr, 1) => {
        unsafe extern "system" fn $name(this: *mut c_void, a0: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0])
        }
    };
    ($name:ident, $index:expr, 2) => {
        unsafe extern "system" fn $name(this: *mut c_void, a0: usize, a1: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1])
        }
    };
    ($name:ident, $index:expr, 3) => {
        unsafe extern "system" fn $name(this: *mut c_void, a0: usize, a1: usize, a2: usize) -> i32 {
            com_method_dispatch(this as usize, $index, &[a0, a1, a2])
        }
    };
    ($name:ident, $index:expr, 4) => {
        unsafe extern "system" fn $name(
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

type ComDetourFn0 = unsafe extern "system" fn(*mut c_void) -> i32;
type ComDetourFn1 = unsafe extern "system" fn(*mut c_void, usize) -> i32;
type ComDetourFn2 = unsafe extern "system" fn(*mut c_void, usize, usize) -> i32;
type ComDetourFn3 = unsafe extern "system" fn(*mut c_void, usize, usize, usize) -> i32;
type ComDetourFn4 = unsafe extern "system" fn(*mut c_void, usize, usize, usize, usize) -> i32;

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
        // SAFETY: スレッドローカルな値の読み取り。
        unsafe { GetLastError() }
    }
    fn set(&self, code: u32) {
        // SAFETY: 同上。
        unsafe { SetLastError(code) }
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
        let Some(rt) = runtime() else {
            return Prepare::Unavailable;
        };
        let original = rt.original(api_id);
        if original == 0 {
            return Prepare::Unavailable;
        }
        le.restore_before_original();
        return Prepare::Passthrough { original };
    };
    let Some(rt) = runtime() else {
        return Prepare::Unavailable;
    };
    let original = rt.original(api_id);
    if original == 0 {
        return Prepare::Unavailable;
    }
    let Some(api) = api_by_id(api_id) else {
        return Prepare::Unavailable;
    };
    // L23: 呼び出し元が Runtime で record_runtime_apis が無効なら記録
    // しない（元の API だけ素通しで呼ぶ）。呼び出し元が特定できない
    // 場合は記録する（fail-open）。再入ゲートや終了ゲートの後に判定
    // することで、Agent 自身の呼び出しはそちらで素通しになる。
    if rt.should_suppress_caller() {
        le.restore_before_original();
        return Prepare::Passthrough { original };
    }
    match crate::runtime::DetourFlight::begin(&rt) {
        Some(flight) => {
            let tid = unsafe { GetCurrentThreadId() } as u64;
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

unsafe extern "system" fn detour_create_file_w(
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
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す。元の呼び出しの中で
    // アプリ由来の入れ子呼び出しが起きた場合は記録される (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe {
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
    guard.resume();
    call_guard.complete();
    // 透明性: 他の処理より先に LastError を確定させる（overview）。
    let last_error = le.capture_after_original();
    pop_call(call_id);
    let values = capture::create_file_w_leave(ret as u64, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system" fn detour_read_file(
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
    let values = capture::read_file_enter(file as u64, buffer as u64, bytes_to_read);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(file, buffer, bytes_to_read, bytes_read, overlapped) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
                n,
                true,
                last_error,
            ),
            None => capture::read_file_leave(
                &ProcessMemory,
                ret,
                buffer as u64,
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
            bytes_read as u64,
            is_overlapped,
            last_error,
        )
    };
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    if is_overlapped && ret == 0 && last_error == capture::ERROR_IO_PENDING {
        rt.register_pending_overlapped(
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
    }
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system" fn detour_write_file(
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
    let values =
        capture::write_file_enter(&ProcessMemory, file as u64, buffer as u64, bytes_to_write);
    if let Ok(bytes) = capture::encode_enter(api, &values) {
        rt.record_enter(tid, api, call_id, &bytes);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(file, buffer, bytes_to_write, bytes_written, overlapped) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
    if is_overlapped && ret == 0 && last_error == capture::ERROR_IO_PENDING {
        rt.register_pending_overlapped(
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
    }
    // SAFETY: LastError を復元する。
    le.restore_for_return();
    ret
}

unsafe extern "system" fn detour_close_handle(object: Handle) -> i32 {
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
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで CallGuard が
    // CallAborted を記録する（例外は捕捉しない）。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(object) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
unsafe extern "system" fn detour_get_overlapped_result(
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
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら CallGuard が CallAborted を記録する。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(file, overlapped, bytes_transferred, wait) };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
unsafe extern "system" fn detour_get_queued_completion_status(
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
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら CallGuard が CallAborted を記録する。
    let mut call_guard = crate::runtime::CallGuard::new(&rt, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe {
        orig(
            port,
            bytes_transferred,
            completion_key,
            overlapped,
            milliseconds,
        )
    };
    guard.resume();
    call_guard.complete();
    let last_error = le.capture_after_original();
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
        // G15: 記録経路の実行中に同じスレッドから prepare を呼ぶと、
        // Agent 自身の呼び出しとして記録せず素通しになる。
        // グローバルスロットはこのテストだけが使う（他のテストは触らない）。
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
}
