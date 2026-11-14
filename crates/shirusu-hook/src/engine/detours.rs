//! Win32 / Nt の型付き Detour 表と、生成 API 向けの汎用 Detour（L03 / L15）。

use super::*;

pub(super) type Handle = *mut c_void;
pub(super) type CreateFileWFn =
    unsafe extern "system-unwind" fn(*const u16, u32, u32, *mut c_void, u32, u32, Handle) -> Handle;
pub(super) type ReadFileFn =
    unsafe extern "system-unwind" fn(Handle, *mut u8, u32, *mut u32, *mut c_void) -> i32;
pub(super) type WriteFileFn =
    unsafe extern "system-unwind" fn(Handle, *const u8, u32, *mut u32, *mut c_void) -> i32;
pub(super) type CloseHandleFn = unsafe extern "system-unwind" fn(Handle) -> i32;
pub(super) type GetOverlappedResultFn =
    unsafe extern "system-unwind" fn(Handle, *mut c_void, *mut u32, i32) -> i32;
pub(super) type GetQueuedCompletionStatusFn =
    unsafe extern "system-unwind" fn(Handle, *mut u32, *mut u64, *mut *mut c_void, u32) -> i32;

pub(super) fn detour_for(api_id: u32) -> usize {
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
        pub(super) unsafe extern "system-unwind" fn $name($($arg: $ty),*) -> i32 {
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

pub(super) type GenericFn0 = unsafe extern "system-unwind" fn() -> usize;
pub(super) type GenericFn1 = unsafe extern "system-unwind" fn(usize) -> usize;
pub(super) type GenericFn2 = unsafe extern "system-unwind" fn(usize, usize) -> usize;
pub(super) type GenericFn3 = unsafe extern "system-unwind" fn(usize, usize, usize) -> usize;
pub(super) type GenericFn4 = unsafe extern "system-unwind" fn(usize, usize, usize, usize) -> usize;
pub(super) type GenericFn5 =
    unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize) -> usize;
pub(super) type GenericFn6 =
    unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize, usize) -> usize;
pub(super) type GenericFn7 =
    unsafe extern "system-unwind" fn(usize, usize, usize, usize, usize, usize, usize) -> usize;
pub(super) type GenericFn8 = unsafe extern "system-unwind" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> usize;
pub(super) type GenericFn9 = unsafe extern "system-unwind" fn(
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
pub(super) type GenericFn10 = unsafe extern "system-unwind" fn(
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
pub(super) type GenericFn11 = unsafe extern "system-unwind" fn(
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
pub(super) type GenericFn12 = unsafe extern "system-unwind" fn(
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
pub(super) unsafe fn call_original<const N: usize>(original: usize, args: &[usize; N]) -> usize {
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
pub(super) fn generic_detour_with<const N: usize>(
    api_id: u32,
    args: &[u64; N],
    invoke: impl FnOnce(usize) -> u64 + Copy,
) -> u64 {
    let (original, tid, api, flight, mut guard, mut le) = match prepare_generic(api_id) {
        GenericPrepare::Record {
            original,
            tid,
            api,
            flight,
            guard,
            last_error,
        } => (original, tid, api, flight, guard, last_error),
        GenericPrepare::Passthrough { original } => {
            // SAFETY: 終了手順の進行中は記録せず本物を素通しで呼ぶ。
            return invoke(original);
        }
        GenericPrepare::Unavailable => return 0,
    };
    let call_id = flight.runtime().alloc_call_id();
    {
        let bytes = capture::encode_generic_enter::<N>(api, args);
        flight
            .runtime()
            .record_enter(tid, api, call_id, bytes.as_bytes());
    }
    if crate::api::is_conditional_no_return_api(api.api_id) && terminates_caller(api.api_id, args) {
        // Self-termination (review N1): release recorder ownership before the
        // OS ends this thread or process, as for ExitThread. TerminateThread
        // skips TLS teardown, so the thread is not marked exiting: if the
        // original fails and returns (for example without THREAD_TERMINATE
        // access), capture continues and the call gets its Leave.
        drop(flight);
        drop(guard);
        le.restore_before_original();
        let ret = invoke(original);
        let last_error = le.capture_after_original();
        if let GenericPrepare::Record {
            tid,
            api,
            flight,
            guard,
            ..
        } = prepare_generic(api_id)
        {
            let bytes = capture::encode_generic_leave_with_inputs(api, ret, last_error, args);
            flight
                .runtime()
                .record_leave(tid, api, call_id, bytes.as_bytes());
            drop(flight);
            drop(guard);
        }
        le.restore_for_return();
        return ret;
    }
    if crate::api::is_no_return_api(api.api_id) {
        // ExitThread (the generated no-return API) does not unwind Rust
        // frames. Release recorder ownership before entering the OS;
        // otherwise DetourFlight and Arc references survive forever and
        // shutdown cannot drain. There is no normal Leave. Stop capture
        // before TLS/DllMain teardown starts, not only when this DLL's
        // native thread-detach callback is eventually reached.
        ReentrancyGuard::mark_thread_exiting();
        drop(flight);
        drop(guard);
        le.restore_before_original();
        return invoke(original);
    }
    push_call(call_id);
    // L08: 元の呼び出しが例外で中断したら、巻き戻しで呼び出しガードが
    // CallAborted を記録してから進行中区間を抜ける（例外は捕捉しない）。
    let call_guard = crate::runtime::FlightCallGuard::new(flight, tid, api, call_id);
    // G15: 元の API 呼び出しの間だけ再入ガードを外す。元の呼び出しの中で
    // アプリ由来の入れ子呼び出しが起きた場合は記録される (A43)。
    le.restore_before_original(); // P1-5: 元の API が入口時点の値を観測する
    guard.suspend();
    // SAFETY: 元の呼び出しは引数をそのまま渡す。
    // Tuple field order drops the call guard (abort record, then flight)
    // before the reentrancy guard. Option::take in the native finally prevents
    // a second cleanup if Rust also runs destructors (for example, a Rust
    // panic through C-unwind).
    let (ret, (mut call_guard, mut guard)) =
        crate::seh::invoke(original, invoke, (call_guard, guard));
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
    call_guard
        .runtime()
        .record_leave(tid, api, call_id, bytes.as_bytes());
    drop(call_guard);
    drop(guard);
    // SAFETY: 呼び出し側へ戻る直前に LastError を復元する。
    le.restore_for_return();
    ret
}

/// Whether a conditionally non-returning API terminates the calling thread
/// with these arguments (review N1). TerminateThread on the calling thread
/// (its pseudo handle or a real handle to it) and TerminateJobObject on a job
/// that contains this process do not return; the Detour then releases its
/// flight like ExitThread instead of leaving it in flight forever. An invalid
/// handle is treated as returning (the original fails normally).
#[cold]
fn terminates_caller(api_id: u32, args: &[u64]) -> bool {
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThreadId, GetThreadId,
    };
    let Some(&handle) = args.first() else {
        return false;
    };
    let handle = handle as usize as windows_sys::Win32::Foundation::HANDLE;
    if api_id == crate::api::TERMINATE_THREAD_API_ID {
        // SAFETY: GetThreadId only queries the handle; an invalid one yields 0.
        let target = unsafe { GetThreadId(handle) };
        return target != 0 && target == unsafe { GetCurrentThreadId() };
    }
    if api_id == crate::api::TERMINATE_JOB_OBJECT_API_ID {
        if handle.is_null() {
            return false;
        }
        let mut in_job = 0;
        // SAFETY: queries membership of the current process; an invalid job
        // handle makes the call fail, which is treated as not terminating.
        let ok = unsafe { IsProcessInJob(GetCurrentProcess(), handle, &mut in_job) };
        return ok != 0 && in_job != 0;
    }
    false
}

/// Typed invoker emitted for one generated API: restores the native argument
/// types from their raw slots and calls the original with its exact ABI.
pub(super) type GeneratedInvoke = unsafe fn(usize, &[u64]) -> u64;

/// Shared body of every generated Detour. Thousands of broad-tier Detours
/// would otherwise each instantiate the full recording path; this function is
/// instantiated once per arity, and only the typed invoker is per API.
#[inline(never)]
pub(super) fn generated_detour(api_id: u32, args: &[u64], invoke: GeneratedInvoke) -> u64 {
    macro_rules! by_arity {
        ($($n:literal)*) => {
            match args.len() {
                $($n => {
                    let fixed: &[u64; $n] = args.try_into().expect("matched arity");
                    // SAFETY: the generator pairs this invoker with this
                    // API's original function type and argument count.
                    generic_detour_with(api_id, fixed, move |original| unsafe {
                        invoke(original, args)
                    })
                })*
                n => panic!("generated detour arity {n} exceeds 12"),
            }
        };
    }
    by_arity!(0 1 2 3 4 5 6 7 8 9 10 11 12)
}
