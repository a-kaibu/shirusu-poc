//! フック＋レコーダの Windows E2E シナリオ。
//!
//! shirusu-hook-target.exe を Agent DLL 付きで起動し、生成された Trace を
//! 読み戻して「対象が呼んだ API が、引数（L2）付きで記録されていること」を
//! 検証する。windows-x64 CI ジョブで実行される。Windows 以外は SKIP。

#[cfg(windows)]
mod win {
    use shirusu_hook::api::{API_CLOSE_HANDLE, API_CREATE_FILE_W, API_READ_FILE, API_WRITE_FILE};
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture};
    use shirusu_host::IntegrityLevel;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
    use shirusu_trace::schema::TypedValue;
    use shirusu_trace::TraceEvent;
    use shirusu_transport::RingConfig;
    use std::time::Duration;

    #[link(name = "kernel32")]
    extern "system" {
        fn QueryPerformanceFrequency(out: *mut i64) -> i32;
    }

    fn qpc_frequency() -> u64 {
        let mut f: i64 = 0;
        // SAFETY: out は有効なローカルを指す。
        let ok = unsafe { QueryPerformanceFrequency(&mut f) };
        if ok != 0 && f > 0 {
            f as u64
        } else {
            10_000_000
        }
    }

    struct Checker {
        failures: Vec<String>,
    }
    impl Checker {
        fn check(&mut self, cond: bool, what: &str) {
            if cond {
                println!("  ok: {what}");
            } else {
                println!("  FAIL: {what}");
                self.failures.push(what.to_string());
            }
        }
    }

    fn find<'a>(events: &[&'a TraceEvent], schema_id: u32) -> Option<&'a TraceEvent> {
        events.iter().copied().find(|e| e.schema_id == schema_id)
    }

    fn arg(trace: &shirusu_trace::reader::ReadTrace, e: &TraceEvent, idx: usize) -> TypedValue {
        let types = trace
            .registry
            .types(e.schema_id)
            .expect("schema registered");
        let args = e.args.as_ref().expect("args attached (L2)");
        let values = decode_values(&types, args).expect("args decode");
        values[idx].value.clone()
    }

    pub fn run() -> i32 {
        let exe = std::env::current_exe().expect("current exe");
        let dir = exe.parent().expect("exe dir").to_path_buf();
        let dll = dir.join("shirusu_agent_dll.dll");
        let target = dir.join("shirusu-hook-target.exe");
        if !dll.exists() || !target.exists() {
            println!(
                "FAIL: dll/target missing next to capture e2e (dll={dll:?} target={target:?})"
            );
            return 1;
        }
        let trace_path =
            std::env::temp_dir().join(format!("shirusu-capture-e2e-{}.trace", std::process::id()));
        let _ = std::fs::remove_file(&trace_path);
        let freq = qpc_frequency();
        let session_cfg = CaptureSessionConfig {
            session_id: 4242,
            ring_config: RingConfig::PRODUCTION,
            environment: CaptureEnvironment {
                session: SessionMetadata {
                    session_id: 4242,
                    created_by: "shirusu-capture-e2e".into(),
                    qpc_frequency: freq,
                },
                ..Default::default()
            },
            qpc_frequency: freq,
        };
        let cfg = LaunchConfig::new(session_cfg, dll);
        let cmdline = format!("\"{}\"", target.display());
        println!("launching {cmdline}");
        let capture = match LaunchedCapture::launch(&cmdline, &trace_path, cfg) {
            Ok(c) => c,
            Err(e) => {
                println!("FAIL: launch: {e}");
                return 1;
            }
        };
        let summary = match capture.run_to_completion(Duration::from_millis(2)) {
            Ok(s) => s,
            Err(e) => {
                println!("FAIL: run: {e}");
                return 1;
            }
        };
        println!(
            "summary: events={} losses={} rings={}/{} args={} fallback={} integrity={:?}",
            summary.total_events,
            summary.total_loss_records,
            summary.rings_active,
            summary.rings_total,
            summary.args_attached,
            summary.args_fallback_blob,
            summary.integrity.event_integrity
        );
        let bytes = std::fs::read(&trace_path).expect("trace file");
        let trace = shirusu_trace::read_trace(&bytes).expect("trace parses");
        let events: Vec<&TraceEvent> = trace.batches.iter().flat_map(|b| &b.events).collect();
        let cf = shirusu_hook::api::api_by_id(API_CREATE_FILE_W).unwrap();
        let rf = shirusu_hook::api::api_by_id(API_READ_FILE).unwrap();
        let wf = shirusu_hook::api::api_by_id(API_WRITE_FILE).unwrap();
        let ch = shirusu_hook::api::api_by_id(API_CLOSE_HANDLE).unwrap();

        let mut c = Checker { failures: vec![] };
        c.check(trace.finalization.is_some(), "trace finalized");
        c.check(
            summary.integrity.event_integrity != IntegrityLevel::Lost,
            "event integrity not lost",
        );
        c.check(events.len() >= 8, "at least the 8 file-io events");

        // CreateFileW: パス（L2）と戻りハンドル
        let mut created_handle: Option<u64> = None;
        if let Some(e) = find(&events, cf.enter_schema_id()) {
            if let TypedValue::Str16(u) = arg(&trace, e, 0) {
                let s = String::from_utf16_lossy(&u);
                c.check(
                    s.contains("shirusu-hook-target-"),
                    "createfile path captured",
                );
            } else {
                c.check(false, "createfile path is Str16");
            }
        } else {
            c.check(false, "CreateFileW enter present");
        }
        if let Some(e) = find(&events, cf.leave_schema_id()) {
            if let TypedValue::U64(h) = arg(&trace, e, 0) {
                c.check(h != 0 && h != u64::MAX, "created handle valid");
                created_handle = Some(h);
            }
        } else {
            c.check(false, "CreateFileW leave present");
        }
        // WriteFile: 書いた内容そのもの
        if let Some(e) = find(&events, wf.enter_schema_id()) {
            let v = arg(&trace, e, 1);
            c.check(
                v == TypedValue::Bytes(b"shirusu-hook-e2e-content".to_vec()),
                "writefile buffer captured",
            );
        } else {
            c.check(false, "WriteFile enter present");
        }
        // ReadFile: 読み戻した内容とバイト数
        if let Some(e) = find(&events, rf.leave_schema_id()) {
            let n = arg(&trace, e, 1);
            let data = arg(&trace, e, 2);
            // lpNumberOfBytesRead は Schema 上 DWORD = U32 (レビュー
            // #4 の #4: 以前は U64 を期待しており型不一致で必ず失敗した)。
            c.check(
                n == TypedValue::U32(24)
                    && data == TypedValue::Bytes(b"shirusu-hook-e2e-content".to_vec()),
                "readfile data captured",
            );
        } else {
            c.check(false, "ReadFile leave present");
        }
        // CloseHandle: 対象ハンドルが CreateFileW の戻りと一致（相関）
        if let (Some(e), Some(h)) = (find(&events, ch.enter_schema_id()), created_handle) {
            let v = arg(&trace, e, 0);
            c.check(
                v == TypedValue::U64(h),
                "closehandle correlates to created handle",
            );
        } else {
            c.check(false, "CloseHandle enter present with known handle");
        }
        let _ = std::fs::remove_file(&trace_path);
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e: {} checks failed",
                c.failures.len()
            );
            1
        }
    }
}

fn main() {
    #[cfg(windows)]
    std::process::exit(win::run());
    #[cfg(not(windows))]
    println!("SKIP shirusu-capture-e2e (windows only)");
}
