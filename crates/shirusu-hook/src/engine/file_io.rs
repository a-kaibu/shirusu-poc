//! 同期・非同期ファイル I/O の手書き Detour と共通の入口判定。

use super::*;

/// 完了した非同期 I/O 操作の CallCompleted を記録する（F27）。
/// `transferred` は完了時点の転送バイト数、`success` は完了の成否、
/// `last_error` は完了観測 API の直後に読んだ GetLastError。値列は
/// 元の API の leave Schema で符号化する。
pub(super) fn record_overlapped_completion(
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
pub(super) struct WinLastError;
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
pub(super) enum Prepare {
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

/// `prepare` up to (not including) the in-flight section: shared by the
/// hand-written detours (`prepare`) and the generated ones (`prepare_generic`).
pub(super) enum PrepareInner {
    Ready {
        rt: Arc<HookRuntime>,
        original: usize,
        api: &'static ApiDef,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

#[inline(always)]
pub(super) fn prepare_inner(api_id: u32) -> PrepareInner {
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
            return PrepareInner::Unavailable;
        };
        let original = rt.original(api_id);
        if original == 0 {
            return PrepareInner::Unavailable;
        }
        le.restore_before_original();
        return PrepareInner::Passthrough { original };
    };
    let Some(rt) = crate::runtime::runtime_slot().for_detour() else {
        return PrepareInner::Unavailable;
    };
    let original = rt.original(api_id);
    if original == 0 {
        return PrepareInner::Unavailable;
    }
    let Some(api) = api_by_id(api_id) else {
        return PrepareInner::Unavailable;
    };
    // The option controls Runtime's own exported APIs, not Windows API calls
    // made by Runtime. Agent-originated calls are excluded by reentrancy above.
    if rt.should_suppress_api_id(api.api_id) {
        le.restore_before_original();
        return PrepareInner::Passthrough { original };
    }
    // L15: 内部 API (Nt*) は詳細調査モードでのみ記録する。無効なら
    // 元の API だけ素通しで呼ぶ（Detour が設置されていても記録しない）。
    // 呼び出し元抑制の後に置くことで、詳細調査モードでは Runtime 起源の
    // 内部呼び出しも record_runtime_apis と合わせて記録される。
    if rt.should_suppress_internal(api.api_id) {
        le.restore_before_original();
        return PrepareInner::Passthrough { original };
    }
    PrepareInner::Ready {
        rt,
        original,
        api,
        guard,
        last_error: le,
    }
}

pub(super) fn prepare(api_id: u32) -> Prepare {
    let (rt, original, api, guard, le) = match prepare_inner(api_id) {
        PrepareInner::Ready {
            rt,
            original,
            api,
            guard,
            last_error,
        } => (rt, original, api, guard, last_error),
        PrepareInner::Passthrough { original } => return Prepare::Passthrough { original },
        PrepareInner::Unavailable => return Prepare::Unavailable,
    };
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

/// Generated detours: the flight owns the only runtime reference.
pub(super) enum GenericPrepare {
    Record {
        original: usize,
        tid: u64,
        api: &'static ApiDef,
        flight: crate::runtime::DetourFlight,
        guard: ReentrancyGuard,
        last_error: crate::runtime::LastErrorGuard<WinLastError>,
    },
    Passthrough {
        original: usize,
    },
    Unavailable,
}

#[inline(always)]
pub(super) fn prepare_generic(api_id: u32) -> GenericPrepare {
    let (rt, original, api, guard, le) = match prepare_inner(api_id) {
        PrepareInner::Ready {
            rt,
            original,
            api,
            guard,
            last_error,
        } => (rt, original, api, guard, last_error),
        PrepareInner::Passthrough { original } => return GenericPrepare::Passthrough { original },
        PrepareInner::Unavailable => return GenericPrepare::Unavailable,
    };
    match crate::runtime::DetourFlight::begin_owned(rt) {
        Some(flight) => {
            let tid = crate::thread_id::current() as u64;
            flight.runtime().ensure_thread(tid);
            GenericPrepare::Record {
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
            GenericPrepare::Passthrough { original }
        }
    }
}

pub(super) const INVALID_HANDLE: usize = usize::MAX;

pub(super) unsafe extern "system-unwind" fn detour_create_file_w(
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

pub(super) unsafe extern "system-unwind" fn detour_read_file(
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

pub(super) unsafe extern "system-unwind" fn detour_write_file(
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

pub(super) unsafe extern "system-unwind" fn detour_close_handle(object: Handle) -> i32 {
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
pub(super) unsafe extern "system-unwind" fn detour_get_overlapped_result(
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
pub(super) unsafe extern "system-unwind" fn detour_get_queued_completion_status(
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
