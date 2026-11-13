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
    unsafe extern "system-unwind" fn original(_: *mut c_void, _: u32, size: usize) -> *mut c_void {
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
                    ) -> *mut c_void = unsafe { std::mem::transmute(address) };
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
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_FREE};
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
    let plan = plan_with_near_relay(&bytes, target as u64, (target + 256) as u64, bitness).unwrap();
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
    // A hook installed after planning must not be overwritten or leave a
    // stale trampoline published as this session's original.
    unsafe {
        (target as *mut u8).write(0xcc);
    }
    let rt = test_runtime();
    let result = install_planned(&rt, &[planned], bitness).pop().unwrap();
    assert!(matches!(result, Err("target-changed")));
    assert_eq!(unsafe { (target as *const u8).read() }, 0xcc);
    assert_eq!(rt.original(17), 0);
    assert_eq!(
        TRAMPOLINE_ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    unsafe { VirtualFree(target as *mut c_void, 0, MEM_RELEASE) };
}

#[test]
fn iat_write_rejects_unaligned_slots_without_touching_memory() {
    let mut storage = [0x55usize; 2];
    let slot = unsafe { storage.as_mut_ptr().cast::<u8>().add(1).cast::<usize>() };
    let state = IatSlot::installed(0, 0x55, 0x1234);
    assert!(matches!(
        unsafe { exchange_iat(slot, &state, true) },
        Err(EngineError::UnalignedIatSlot)
    ));
    assert_eq!(storage, [0x55; 2]);
}

#[test]
fn iat_protection_failure_retains_recovery_and_preserves_foreign_pointer() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Memory::{VirtualQuery, PAGE_READONLY};
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!page.is_null());
    let slot = page.cast::<usize>();
    unsafe {
        slot.write(0x1111);
    }
    let mut old = 0;
    assert_ne!(
        unsafe { VirtualProtect(page, 4096, PAGE_READONLY, &mut old) },
        0
    );
    let state = IatSlot::installed(0, 0x1111, 0x2222);
    state.owned.store(false, Ordering::Release);
    let mut calls = 0;
    let result = unsafe {
        exchange_iat_with(slot, &state, true, |address, size, protection, old| {
            calls += 1;
            if calls == 2 {
                0
            } else {
                VirtualProtect(address, size, protection, old)
            }
        })
    };
    assert!(matches!(result, Err(EngineError::ProtectFailed { .. })));
    assert_eq!(unsafe { slot.read() }, 0x2222);
    assert!(state.owned.load(Ordering::Acquire));
    assert_eq!(state.protection.load(Ordering::Acquire), PAGE_READONLY);
    // A foreign owner replaces our pointer while restoration is pending.
    unsafe { AtomicUsize::from_ptr(slot) }.store(0x3333, Ordering::Release);
    assert!(unsafe { exchange_iat(slot, &state, false) }.is_ok());
    assert_eq!(unsafe { slot.read() }, 0x3333);
    assert!(!state.owned.load(Ordering::Acquire));
    assert_eq!(state.protection.load(Ordering::Acquire), 0);
    let mut info = std::mem::MaybeUninit::<
        windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
    >::uninit();
    assert_ne!(
        unsafe { VirtualQuery(page, info.as_mut_ptr(), std::mem::size_of_val(&info)) },
        0
    );
    assert_eq!(unsafe { info.assume_init() }.Protect, PAGE_READONLY);

    // A different installation restores its pointer but fails to restore
    // protection. The retry must not write that pointer for a second time.
    let state = IatSlot::installed(0, 0x3333, 0x4444);
    state.owned.store(false, Ordering::Release);
    assert!(unsafe { exchange_iat(slot, &state, true) }.is_ok());
    let mut calls = 0;
    assert!(unsafe {
        exchange_iat_with(slot, &state, false, |address, size, protection, old| {
            calls += 1;
            if calls == 2 {
                0
            } else {
                VirtualProtect(address, size, protection, old)
            }
        })
    }
    .is_err());
    assert_eq!(unsafe { slot.read() }, 0x3333);
    assert!(!state.owned.load(Ordering::Acquire));
    unsafe { AtomicUsize::from_ptr(slot) }.store(0x5555, Ordering::Release);
    assert!(unsafe { exchange_iat(slot, &state, false) }.is_ok());
    assert_eq!(unsafe { slot.read() }, 0x5555);
    let conflict = IatSlot::installed(0, 0x3333, 0x6666);
    conflict.owned.store(false, Ordering::Release);
    assert!(matches!(
        unsafe { exchange_iat(slot, &conflict, true) },
        Err(EngineError::IatChanged)
    ));
    assert_eq!(unsafe { slot.read() }, 0x5555);
    assert!(!conflict.owned.load(Ordering::Acquire));
    assert_eq!(conflict.protection.load(Ordering::Acquire), 0);
    let mut info = std::mem::MaybeUninit::<
        windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
    >::uninit();
    assert_ne!(
        unsafe { VirtualQuery(page, info.as_mut_ptr(), std::mem::size_of_val(&info)) },
        0
    );
    assert_eq!(unsafe { info.assume_init() }.Protect, PAGE_READONLY);
    assert_ne!(unsafe { VirtualFree(page, 0, MEM_RELEASE) }, 0);
}

#[test]
fn inline_post_write_failures_retain_protection_and_cache_retry_state() {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
    };
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!page.is_null());
    unsafe {
        std::ptr::write_bytes(page, 0x90, 4096);
    }
    let mut old = 0;
    assert_ne!(
        unsafe { VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &mut old) },
        0
    );
    let hook = InlineHook {
        api_id: 17,
        target: page as usize,
        trampoline: 0,
        trampoline_size: 0,
        stolen_len: 8,
        original_bytes: vec![0x90; 8],
        patched_len: 5,
        installed_bytes: vec![0xcc; 5],
        restoration: InlineRestoration::default(),
    };
    let published = std::cell::Cell::new(false);
    let mut calls = 0;
    assert!(patch_target_with_ops(
        hook.target,
        &[0xcc; 5],
        &hook.restoration,
        || published.set(true),
        |address, size, protection, old| {
            calls += 1;
            if calls == 2 {
                0
            } else {
                unsafe { VirtualProtect(address, size, protection, old) }
            }
        },
        |_, _| 0
    )
    .is_ok());
    assert!(published.get());
    assert!(hook.maintenance_pending());
    assert_eq!(
        hook.restoration.protection.load(Ordering::Acquire),
        PAGE_EXECUTE_READ
    );
    assert!(hook.restoration.cache_pending.load(Ordering::Acquire));
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.cast::<u8>(), 5) },
        &[0xcc; 5]
    );
    // Bytes beyond the actual patch may have a different owner.
    unsafe {
        page.cast::<u8>().add(7).write(0x77);
    }
    let mut calls = 0;
    assert!(restore_inline_with_ops(
        &hook,
        |address, size, protection, old| {
            calls += 1;
            if calls == 2 {
                0
            } else {
                unsafe { VirtualProtect(address, size, protection, old) }
            }
        },
        |_, _| 0
    )
    .is_err());
    assert!(hook.restoration.code_released.load(Ordering::Acquire));
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.cast::<u8>(), 5) },
        &[0x90; 5]
    );
    assert_eq!(unsafe { page.cast::<u8>().add(7).read() }, 0x77);
    // Retry protection/cache only; never write restored bytes again.
    unsafe {
        page.cast::<u8>().write(0xab);
    }
    assert!(restore_inline(&hook).is_ok());
    assert!(!hook.maintenance_pending());
    assert_eq!(unsafe { page.cast::<u8>().read() }, 0xab);
    let mut info = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    assert_ne!(
        unsafe { VirtualQuery(page, info.as_mut_ptr(), std::mem::size_of_val(&info)) },
        0
    );
    assert_eq!(unsafe { info.assume_init() }.Protect, PAGE_EXECUTE_READ);
    assert_ne!(unsafe { VirtualFree(page, 0, MEM_RELEASE) }, 0);
}

#[test]
fn inline_restore_preserves_a_foreign_patch_without_changing_protection() {
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!page.is_null());
    unsafe {
        std::ptr::write_bytes(page, 0xdd, 4096);
    }
    let hook = InlineHook {
        api_id: 17,
        target: page as usize,
        trampoline: 0,
        trampoline_size: 0,
        stolen_len: 5,
        original_bytes: vec![0x90; 5],
        patched_len: 5,
        installed_bytes: vec![0xcc; 5],
        restoration: InlineRestoration::default(),
    };
    assert!(restore_inline_with_ops(
        &hook,
        |_, _, _, _| panic!("foreign code protection changed"),
        |_, _| panic!("no cache update owed")
    )
    .is_ok());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.cast::<u8>(), 5) },
        &[0xdd; 5]
    );
    assert!(hook
        .restoration
        .code_released
        .load(std::sync::atomic::Ordering::Acquire));
    assert_ne!(unsafe { VirtualFree(page, 0, MEM_RELEASE) }, 0);
}

#[test]
fn inline_patch_refuses_different_page_protections_before_publication() {
    use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            8192,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!page.is_null());
    unsafe {
        std::ptr::write_bytes(page, 0x90, 8192);
    }
    let mut old = 0;
    assert_ne!(
        unsafe { VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &mut old) },
        0
    );
    let target = page as usize + 4094;
    let published = std::cell::Cell::new(false);
    let mut protect_calls = 0;
    assert!(patch_target_with_ops(
        target,
        &[0xcc; 4],
        &InlineRestoration::default(),
        || published.set(true),
        |_, _, _, _| {
            protect_calls += 1;
            0
        },
        |_, _| 0
    )
    .is_err());
    assert!(!published.get());
    assert_eq!(protect_calls, 0);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(target as *const u8, 4) },
        &[0x90; 4]
    );
    assert_ne!(unsafe { VirtualFree(page, 0, MEM_RELEASE) }, 0);
}

#[test]
fn failed_page_protection_does_not_publish_a_trampoline() {
    let _lock = TEST_RUNTIME_LOCK.lock().unwrap();
    let published = std::cell::Cell::new(false);
    assert!(
        patch_target_with(0, &[0x90], &InlineRestoration::default(), || published
            .set(true))
        .is_err()
    );
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
            patched_len: code.len(),
            installed_bytes: vec![0x90; code.len()],
            restoration: InlineRestoration::default(),
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
        patched_len: code.len(),
        installed_bytes: code.to_vec(),
        restoration: InlineRestoration::default(),
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
