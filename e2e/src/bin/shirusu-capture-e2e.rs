//! フック＋レコーダの Windows E2E シナリオ。
//!
//! shirusu-hook-target.exe を Agent DLL 付きで起動し、生成された Trace を
//! 読み戻して「対象が呼んだ API が、引数（L2）付きで記録されていること」を
//! 検証する。windows-x64 CI ジョブで実行される。Windows 以外は SKIP。

#[cfg(windows)]
mod win {
    use shirusu_hook::api::{API_CLOSE_HANDLE, API_CREATE_FILE_W, API_READ_FILE, API_WRITE_FILE};
    use shirusu_host::child_tree::child_trace_path;
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture, TreeCapture};
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

    fn session_config() -> CaptureSessionConfig {
        let freq = qpc_frequency();
        CaptureSessionConfig {
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
            // F21 で CaptureSessionConfig に追加された永続化設定。
            // E2E は既定の Buffered（flush のみ）でよい。
            durability: shirusu_trace::writer::Durability::Buffered,
            // L11: 全体順序は E2E では使わない（既定の無効）。
            order_global: false,
            // L07: Runtime 独自の API は既定で記録しない。
            record_runtime_apis: false,
            // L09: E2E は既定の `full`（間引きなし）。
            record_mode: shirusu_host::trace_convert::RecordMode::Full,
        }
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
        let cfg = LaunchConfig::new(session_config(), dll);
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

    /// L05 の子プロセス追跡シナリオ。`--spawn-child` 付きの対象を
    /// TreeCapture で起動し、子プロセスの Trace が別ファイルに
    /// 記録されることを検証する。
    pub fn run_child_tree() -> i32 {
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
        let trace_path = std::env::temp_dir().join(format!(
            "shirusu-capture-e2e-child-tree-{}.trace",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&trace_path);
        let cfg = LaunchConfig::new(session_config(), dll);
        let cmdline = format!("\"{}\" --spawn-child", target.display());
        println!("launching {cmdline} (child tree)");
        let tree = match TreeCapture::launch(&cmdline, &trace_path, cfg) {
            Ok(t) => t,
            Err(e) => {
                println!("FAIL: launch: {e}");
                return 1;
            }
        };
        let summary = match tree.run_tree_to_completion(Duration::from_millis(2)) {
            Ok(s) => s,
            Err(e) => {
                println!("FAIL: run: {e}");
                return 1;
            }
        };
        let mut c = Checker { failures: vec![] };
        c.check(
            summary.root.total_events >= 8,
            "root has at least the 8 file-io events",
        );
        c.check(summary.children.len() == 1, "exactly one child captured");
        c.check(summary.uninjectable.is_empty(), "no uninjectable children");
        c.check(
            summary.root.integrity.event_integrity != IntegrityLevel::Lost,
            "root event integrity not lost",
        );
        let root_bytes = std::fs::read(&trace_path).expect("root trace file");
        let root_trace = shirusu_trace::read_trace(&root_bytes).expect("root trace parses");
        c.check(root_trace.finalization.is_some(), "root trace finalized");
        if let Some((pid, child)) = summary.children.first() {
            c.check(
                child.total_events >= 8,
                "child has at least the 8 file-io events",
            );
            let child_path = child_trace_path(&trace_path, *pid);
            c.check(child_path.exists(), "child trace file exists");
            match std::fs::read(&child_path) {
                Ok(bytes) => match shirusu_trace::read_trace(&bytes) {
                    Ok(t) => {
                        let events: Vec<&TraceEvent> =
                            t.batches.iter().flat_map(|b| &b.events).collect();
                        c.check(events.len() >= 8, "child trace has at least 8 events");
                        c.check(t.finalization.is_some(), "child trace finalized");
                        c.check(
                            t.header.session_id != root_trace.header.session_id,
                            "child session_id differs from root",
                        );
                    }
                    Err(e) => c.check(false, &format!("child trace parses ({e})")),
                },
                Err(e) => c.check(false, &format!("child trace readable ({e})")),
            }
            let _ = std::fs::remove_file(child_path);
        } else {
            c.check(false, "child summary present");
        }
        let _ = std::fs::remove_file(&trace_path);
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e --child-tree");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e --child-tree: {} checks failed",
                c.failures.len()
            );
            1
        }
    }

    /// L06 の ABI 適合性テスト。hook-target --abi-probe を Hook なしで
    /// 直接実行した baseline と、Agent DLL 付きで起動した Hook あり実行の
    /// Probe 出力を比べ、Hook ありとなしで観測できる結果が同じことを
    /// 検証する。あわせて Hook あり実行の Trace に Probe のファイル I/O が
    /// 記録され、コールバックの別スレッド分も含まれることを確認する。
    pub fn run_abi() -> i32 {
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
        let pid = std::process::id();
        let base_out = std::env::temp_dir().join(format!("shirusu-abi-base-{pid}.txt"));
        let hooked_out = std::env::temp_dir().join(format!("shirusu-abi-hooked-{pid}.txt"));
        let trace_path = std::env::temp_dir().join(format!("shirusu-abi-{pid}.trace"));
        let _ = std::fs::remove_file(&base_out);
        let _ = std::fs::remove_file(&hooked_out);
        let _ = std::fs::remove_file(&trace_path);
        let mut c = Checker { failures: vec![] };

        // 1. Hook なし（baseline）：対象を直接実行する。
        let base_status = std::process::Command::new(&target)
            .args(["--abi-probe", "--abi-out"])
            .arg(&base_out)
            .status();
        let base_ok = match base_status {
            Ok(s) => {
                c.check(s.success(), "baseline abi-probe exits 0");
                s.success()
            }
            Err(e) => {
                c.check(false, &format!("baseline abi-probe runs ({e})"));
                false
            }
        };

        // 2. Hook あり：Agent DLL 付きで起動する。対象の終了コードは
        // LaunchedCapture から取れないため、Hook あり実行の成否は
        // --abi-out の ABI_PROBE_DONE 行で見る（比較器が判定する）。
        let cfg = LaunchConfig::new(session_config(), dll);
        let cmdline = format!(
            "\"{}\" --abi-probe --abi-out \"{}\"",
            target.display(),
            hooked_out.display()
        );
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
            "summary: events={} losses={} integrity={:?}",
            summary.total_events, summary.total_loss_records, summary.integrity.event_integrity
        );

        // 3. Probe 出力の比較（Hook ありとなしで結果が同じこと）。
        let base_text = std::fs::read_to_string(&base_out).unwrap_or_default();
        let hooked_text = std::fs::read_to_string(&hooked_out).unwrap_or_default();
        c.check(!base_text.is_empty(), "baseline abi output written");
        c.check(!hooked_text.is_empty(), "hooked abi output written");
        if base_ok && !base_text.is_empty() && !hooked_text.is_empty() {
            let diffs = shirusu_e2e::compare_abi_probe_outputs(&base_text, &hooked_text);
            for d in &diffs {
                println!("  FAIL: abi diff: {d}");
                c.failures.push(format!("abi diff: {d}"));
            }
            if diffs.is_empty() {
                println!("  ok: abi probe outputs identical (hook vs no-hook)");
            }
        }

        // 4. Trace の確認：Probe のファイル I/O が記録され、コールバックの
        // 別スレッド分も含めて 2 スレッド以上が現れること。
        match std::fs::read(&trace_path) {
            Ok(bytes) => match shirusu_trace::read_trace(&bytes) {
                Ok(trace) => {
                    let events: Vec<&TraceEvent> =
                        trace.batches.iter().flat_map(|b| &b.events).collect();
                    c.check(trace.finalization.is_some(), "trace finalized");
                    c.check(
                        summary.integrity.event_integrity != IntegrityLevel::Lost,
                        "event integrity not lost",
                    );
                    // Probe のフック対象呼び出し回数：float 3・struct 3・
                    // callback（fnptr 4・thread 4）・exception（4＋4）・
                    // lasterror（2＋1）＝ 25 呼び出し → 50 イベント。
                    // 余裕を見て 20 を下限にする。
                    c.check(events.len() >= 20, "at least 20 abi probe events");
                    let threads: std::collections::BTreeSet<u64> =
                        trace.batches.iter().map(|b| b.thread_id).collect();
                    c.check(threads.len() >= 2, "callback thread recorded (2+ threads)");
                    for (id, name) in [
                        (API_CREATE_FILE_W, "CreateFileW"),
                        (API_READ_FILE, "ReadFile"),
                        (API_WRITE_FILE, "WriteFile"),
                        (API_CLOSE_HANDLE, "CloseHandle"),
                    ] {
                        let api = shirusu_hook::api::api_by_id(id).unwrap();
                        c.check(
                            find(&events, api.enter_schema_id()).is_some(),
                            &format!("{name} enter present in abi trace"),
                        );
                    }
                }
                Err(e) => c.check(false, &format!("abi trace parses ({e})")),
            },
            Err(e) => c.check(false, &format!("abi trace readable ({e})")),
        }
        let _ = std::fs::remove_file(&base_out);
        let _ = std::fs::remove_file(&hooked_out);
        let _ = std::fs::remove_file(&trace_path);
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e --abi");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e --abi: {} checks failed",
                c.failures.len()
            );
            1
        }
    }
}

fn main() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--abi") {
            std::process::exit(win::run_abi());
        }
        if args.iter().any(|a| a == "--child-tree") {
            std::process::exit(win::run_child_tree());
        }
        std::process::exit(win::run());
    }
    #[cfg(not(windows))]
    println!("SKIP shirusu-capture-e2e (windows only)");
}
