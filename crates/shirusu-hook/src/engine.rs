//! Windows 実装： IAT パッチと Detour 本体。
//!
//! 透明性（overview「Hookの透明性」）の要点:
//! - 元の API から戻った直後に GetLastError を読み取り、Wrapper の処理が
//!   終わって呼び出し側へ戻る直前に同じ値を書き戻す。取得処理の中で
//!   Win32 API を呼んでも、呼び出し側から見た LastError は変わらない。
//! - 取得は全て「元の呼び出しの外側」で行い、元の呼び出し自体の
//!   引数・戻り値には一切触れない。
//! - Reentrance： Agent の記録経路がフック対象 API を呼ぶことはない
//!   （メモリ読み取りは VirtualQuery + 直接コピーのみ）。対象アプリ
//!   自身の入れ子呼び出しは呼出スタックで親子として記録される。

use crate::api::{
    api_by_id, ApiDef, API_CLOSE_HANDLE, API_CREATE_FILE_W, API_READ_FILE, API_WRITE_FILE,
};
use crate::capture::{self, MemoryReader};
use crate::pe;
use crate::plan::{build_plan, HookPlan};
use crate::runtime::{pop_call, push_call, HookRuntime};
use std::ffi::c_void;
use std::sync::{Arc, OnceLock};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

static RUNTIME: OnceLock<Arc<HookRuntime>> = OnceLock::new();

/// Agent DLL の初期化がランタイムを登録する。以後の Detour はこれを使う。
pub fn set_runtime(rt: Arc<HookRuntime>) -> Result<(), Arc<HookRuntime>> {
    RUNTIME.set(rt)
}
pub fn runtime() -> Option<Arc<HookRuntime>> {
    RUNTIME.get().cloned()
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
}

/// プロセス内メモリの読み取り。VirtualQuery で「コミット済みかつ
/// 読取り可能」を確認してから直接コピーする（対象は自プロセス）。
pub struct ProcessMemory;

fn protect_is_readable(state: u32, protect: u32) -> bool {
    if state != MEM_COMMIT {
        return false;
    }
    if protect & PAGE_NOACCESS != 0 || protect & PAGE_GUARD != 0 {
        return false;
    }
    matches!(
        protect & 0xFF,
        0x02 // PAGE_READONLY
        | 0x04 // PAGE_READWRITE
        | 0x08 // PAGE_WRITECOPY
        | 0x20 // PAGE_EXECUTE_READ
        | 0x40 // PAGE_EXECUTE_READWRITE
        | 0x80 // PAGE_EXECUTE_WRITECOPY
    )
}

impl MemoryReader for ProcessMemory {
    fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool {
        if buf.is_empty() {
            return true;
        }
        if addr == 0 {
            return false;
        }
        let start = addr as usize;
        let Some(end) = start.checked_add(buf.len()) else {
            return false;
        };
        let mut cur = start;
        while cur < end {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let n = unsafe {
                VirtualQuery(
                    cur as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 || !protect_is_readable(mbi.State, mbi.Protect) {
                return false;
            }
            let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if region_end <= cur {
                return false;
            }
            cur = region_end;
        }
        // SAFETY: 範囲全体がコミット済み・読取り可能であることを確認した。
        unsafe {
            std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
        true
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
    let mut slots = Vec::new();
    for entry in &plan.entries {
        // SAFETY: iat_rva はこのモジュールの IAT 内（plan の入力は同イメージの解析結果）。
        let slot = unsafe { module_base.add(entry.iat_rva as usize) } as *mut usize;
        // SAFETY: 同上。
        let original = unsafe { slot.read_unaligned() };
        rt.set_original(entry.api.api_id, original);
        // SAFETY: 同上。
        unsafe { write_slot(slot, detour_for(entry.api.api_id))? };
        slots.push((entry.iat_rva, original));
    }
    Ok(InstalledHooks {
        module_base: module_base as usize,
        slots,
        plan,
    })
}

/// IAT を元の値へ戻す（設置の巻き戻し）。
///
/// # Safety
/// `installed` は install_hooks が返したものであり、対象モジュールが
/// まだロードされていること。
pub unsafe fn uninstall_hooks(installed: &InstalledHooks) {
    for (iat_rva, original) in &installed.slots {
        // SAFETY: 呼び出し側の契約に従う。
        let slot =
            unsafe { (installed.module_base as *mut u8).add(*iat_rva as usize) } as *mut usize;
        // SAFETY: 同上。失敗しても巻き戻しは続ける。
        let _ = unsafe { write_slot(slot, *original) };
    }
}

type Handle = *mut c_void;
type CreateFileWFn =
    unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, Handle) -> Handle;
type ReadFileFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut c_void) -> i32;
type WriteFileFn = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *mut c_void) -> i32;
type CloseHandleFn = unsafe extern "system" fn(Handle) -> i32;

fn detour_for(api_id: u32) -> usize {
    match api_id {
        API_CREATE_FILE_W => (detour_create_file_w as CreateFileWFn) as usize,
        API_READ_FILE => (detour_read_file as ReadFileFn) as usize,
        API_WRITE_FILE => (detour_write_file as WriteFileFn) as usize,
        API_CLOSE_HANDLE => (detour_close_handle as CloseHandleFn) as usize,
        _ => 0,
    }
}

/// Detour 共通の前処理： ランタイム取得と元関数の解決。
/// 元関数が無い（設置されていない）場合は None を返し、呼び出し側は
/// API ごとの失敗値を返す（プロセスを落とさないことを優先する）。
/// Detour の入口判定 (レビュー #4 の #9)。
enum Prepare {
    /// 記録する通常経路。`flight` を Detour 全体で保持することで、
    /// 終了手順が進行中 Detour の完了を待てる。
    Record {
        rt: Arc<HookRuntime>,
        original: usize,
        tid: u64,
        api: &'static ApiDef,
        flight: crate::runtime::DetourFlight,
    },
    /// 終了手順の進行中: 記録せず元関数を素通しで呼ぶ。IAT 復元と
    /// 競合させないための経路。
    Passthrough { original: usize },
    /// ランタイム未登録 / 元関数なし: 呼び出し側は失敗値を返す。
    Unavailable,
}

fn prepare(api_id: u32) -> Prepare {
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
            }
        }
        None => Prepare::Passthrough { original },
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
    let (rt, original, tid, api, _flight) = match prepare(API_CREATE_FILE_W) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
        } => (rt, original, tid, api, flight),
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
    // 透明性: 他の処理より先に LastError を確定させる（overview）。
    let last_error = unsafe { GetLastError() };
    pop_call(call_id);
    let values = capture::create_file_w_leave(ret as u64, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    unsafe { SetLastError(last_error) };
    ret
}

unsafe extern "system" fn detour_read_file(
    file: Handle,
    buffer: *mut u8,
    bytes_to_read: u32,
    bytes_read: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let (rt, original, tid, api, _flight) = match prepare(API_READ_FILE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
        } => (rt, original, tid, api, flight),
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
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(file, buffer, bytes_to_read, bytes_read, overlapped) };
    let last_error = unsafe { GetLastError() };
    pop_call(call_id);
    let values = capture::read_file_leave(
        &ProcessMemory,
        ret,
        buffer as u64,
        bytes_read as u64,
        !overlapped.is_null(),
        last_error,
    );
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: LastError を復元する。
    unsafe { SetLastError(last_error) };
    ret
}

unsafe extern "system" fn detour_write_file(
    file: Handle,
    buffer: *const u8,
    bytes_to_write: u32,
    bytes_written: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let (rt, original, tid, api, _flight) = match prepare(API_WRITE_FILE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
        } => (rt, original, tid, api, flight),
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
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(file, buffer, bytes_to_write, bytes_written, overlapped) };
    let last_error = unsafe { GetLastError() };
    pop_call(call_id);
    let values = capture::write_file_leave(
        &ProcessMemory,
        ret,
        bytes_written as u64,
        !overlapped.is_null(),
        last_error,
    );
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: LastError を復元する。
    unsafe { SetLastError(last_error) };
    ret
}

unsafe extern "system" fn detour_close_handle(object: Handle) -> i32 {
    let (rt, original, tid, api, _flight) = match prepare(API_CLOSE_HANDLE) {
        Prepare::Record {
            rt,
            original,
            tid,
            api,
            flight,
        } => (rt, original, tid, api, flight),
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
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    let ret = unsafe { orig(object) };
    let last_error = unsafe { GetLastError() };
    pop_call(call_id);
    let values = capture::close_handle_leave(ret, last_error);
    if let Ok(bytes) = capture::encode_leave(api, &values) {
        rt.record_leave(tid, api, call_id, &bytes);
    }
    // SAFETY: LastError を復元する。
    unsafe { SetLastError(last_error) };
    ret
}
