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

    /// COM メソッドイベントの enter から method_name を読む。args が
    /// 無い（Schema 未登録で Blob へ逃げた等）場合は None。
    fn com_method_name(trace: &shirusu_trace::reader::ReadTrace, e: &TraceEvent) -> Option<String> {
        let types = trace.registry.types(e.schema_id)?;
        let args = e.args.as_ref()?;
        let values = decode_values(&types, args).ok()?;
        match &values.get(3)?.value {
            TypedValue::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// COM メソッドイベントの enter から object ポインタを読む。
    fn com_enter_object(trace: &shirusu_trace::reader::ReadTrace, e: &TraceEvent) -> Option<u64> {
        let types = trace.registry.types(e.schema_id)?;
        let args = e.args.as_ref()?;
        let values = decode_values(&types, args).ok()?;
        match &values.first()?.value {
            TypedValue::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// WinRT アクティベーションイベントの enter から method_name を読む。
    /// COM メソッドイベントとはフィールド位置が違う（method_name は 2 番目）。
    fn winrt_activation_method_name(
        trace: &shirusu_trace::reader::ReadTrace,
        e: &TraceEvent,
    ) -> Option<String> {
        let types = trace.registry.types(e.schema_id)?;
        let args = e.args.as_ref()?;
        let values = decode_values(&types, args).ok()?;
        match &values.get(2)?.value {
            TypedValue::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// WinRT アクティベーションイベントの enter から class_name を読む。
    fn winrt_enter_class_name(
        trace: &shirusu_trace::reader::ReadTrace,
        e: &TraceEvent,
    ) -> Option<String> {
        let types = trace.registry.types(e.schema_id)?;
        let args = e.args.as_ref()?;
        let values = decode_values(&types, args).ok()?;
        match &values.get(1)?.value {
            TypedValue::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// COM メソッドイベントの leave から (hresult, returned_object,
    /// refcount) を読む。
    fn com_leave_values(
        trace: &shirusu_trace::reader::ReadTrace,
        e: &TraceEvent,
    ) -> Option<(i32, u64, u32)> {
        let types = trace.registry.types(e.schema_id)?;
        let args = e.args.as_ref()?;
        let values = decode_values(&types, args).ok()?;
        let hresult = match &values.first()?.value {
            TypedValue::I32(v) => *v,
            _ => return None,
        };
        let returned = match &values.get(1)?.value {
            TypedValue::U64(v) => *v,
            _ => return None,
        };
        let refcount = match &values.get(2)?.value {
            TypedValue::U32(v) => *v,
            _ => return None,
        };
        Some((hresult, returned, refcount))
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
            diagnostic_query_interface: false,
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
        let mut cfg = LaunchConfig::new(session_config(), dll);
        // L13: 起動対象の exe の PE インポートテーブルから静的依存を
        // 読み、Environment に載せる（CLI の capture と同じ経路）。
        cfg.session.environment.static_dependencies =
            shirusu_host::static_dep::static_dependencies_for_exe(&target);
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
        // L13: 静的依存情報が Trace の Environment に残ること。
        // hook-target は Rust 製 exe で kernel32.dll を直接インポートする。
        let deps = trace.environment.as_ref().map(|e| &e.static_dependencies);
        c.check(
            deps.is_some_and(|d| !d.is_empty()),
            "static dependencies recorded",
        );
        c.check(
            deps.is_some_and(|d| {
                d.iter().any(|dep| {
                    dep.module.eq_ignore_ascii_case("kernel32.dll") && !dep.imports.is_empty()
                })
            }),
            "kernel32.dll static dependency present",
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

    /// L17 の検証用アプリ 3 種シナリオ。各アプリを Hook なし（baseline）と
    /// Agent DLL 付き（hooked）で実行し、VERIFY 出力が同じことと、Trace に
    /// ファイル I/O（4 API × enter/leave ＝ 8 イベント以上）が記録されることを
    /// 検証する。あわせてカバレッジ評価を報告する：レジストリ・USER32・GDI・
    /// DIB・COM の API は現行フック表に無く（L03 待ち）、Trace には現れない
    /// ことをフック表の照合で確認する（未記録は失敗にしない）。
    pub fn run_verify_apps() -> i32 {
        let exe = std::env::current_exe().expect("current exe");
        let dir = exe.parent().expect("exe dir").to_path_buf();
        let dll = dir.join("shirusu_agent_dll.dll");
        let mut c = Checker { failures: vec![] };
        if !dll.exists() {
            println!("FAIL: dll missing next to capture e2e (dll={dll:?})");
            return 1;
        }
        let pid = std::process::id();
        for app in shirusu_e2e::VERIFY_APP_NAMES {
            let target = dir.join(format!("shirusu-verify-{app}.exe"));
            if !target.exists() {
                c.check(false, &format!("shirusu-verify-{app}.exe present"));
                continue;
            }
            let base_out =
                std::env::temp_dir().join(format!("shirusu-verify-{app}-base-{pid}.txt"));
            let hooked_out =
                std::env::temp_dir().join(format!("shirusu-verify-{app}-hooked-{pid}.txt"));
            let trace_path = std::env::temp_dir().join(format!("shirusu-verify-{app}-{pid}.trace"));
            let _ = std::fs::remove_file(&base_out);
            let _ = std::fs::remove_file(&hooked_out);
            let _ = std::fs::remove_file(&trace_path);

            // 1. Hook なし（baseline）：対象を直接実行する。
            let base_ok = match std::process::Command::new(&target)
                .args(["--verify-out"])
                .arg(&base_out)
                .status()
            {
                Ok(s) => {
                    c.check(s.success(), &format!("{app} baseline exits 0"));
                    s.success()
                }
                Err(e) => {
                    c.check(false, &format!("{app} baseline runs ({e})"));
                    false
                }
            };

            // 2. Hook あり：Agent DLL 付きで起動する。対象の終了コードは
            // LaunchedCapture から取れないため、Hook あり実行の成否は
            // --verify-out の VERIFY_DONE 行で見る（比較器が判定する）。
            let cfg = LaunchConfig::new(session_config(), dll.clone());
            let cmdline = format!(
                "\"{}\" --verify-out \"{}\"",
                target.display(),
                hooked_out.display()
            );
            println!("launching {cmdline}");
            let capture = match LaunchedCapture::launch(&cmdline, &trace_path, cfg) {
                Ok(c) => c,
                Err(e) => {
                    println!("FAIL: {app} launch: {e}");
                    c.failures.push(format!("{app} launch: {e}"));
                    continue;
                }
            };
            let summary = match capture.run_to_completion(Duration::from_millis(2)) {
                Ok(s) => s,
                Err(e) => {
                    println!("FAIL: {app} run: {e}");
                    c.failures.push(format!("{app} run: {e}"));
                    continue;
                }
            };
            println!(
                "{app} summary: events={} losses={} integrity={:?}",
                summary.total_events, summary.total_loss_records, summary.integrity.event_integrity
            );

            // 3. VERIFY 出力の比較（Hook ありとなしで結果が同じこと）。
            let base_text = std::fs::read_to_string(&base_out).unwrap_or_default();
            let hooked_text = std::fs::read_to_string(&hooked_out).unwrap_or_default();
            c.check(
                !base_text.is_empty(),
                &format!("{app} baseline verify output written"),
            );
            c.check(
                !hooked_text.is_empty(),
                &format!("{app} hooked verify output written"),
            );
            if base_ok && !base_text.is_empty() && !hooked_text.is_empty() {
                let diffs = shirusu_e2e::compare_verify_outputs(&base_text, &hooked_text);
                for d in &diffs {
                    println!("  FAIL: {app} verify diff: {d}");
                    c.failures.push(format!("{app} verify diff: {d}"));
                }
                if diffs.is_empty() {
                    println!("  ok: {app} verify outputs identical (hook vs no-hook)");
                }
            }

            // 4. Trace の確認：file ステップのファイル I/O が記録されること。
            match std::fs::read(&trace_path) {
                Ok(bytes) => match shirusu_trace::read_trace(&bytes) {
                    Ok(trace) => {
                        let events: Vec<&TraceEvent> =
                            trace.batches.iter().flat_map(|b| &b.events).collect();
                        c.check(
                            trace.finalization.is_some(),
                            &format!("{app} trace finalized"),
                        );
                        c.check(
                            summary.integrity.event_integrity != IntegrityLevel::Lost,
                            &format!("{app} event integrity not lost"),
                        );
                        // file ステップは 4 API × enter/leave ＝ 8 イベント。
                        c.check(
                            events.len() >= 8,
                            &format!("{app} at least 8 file-io events"),
                        );
                        // レジストリ (L03): console アプリは 6 回の Reg* 呼び出し
                        // (enter/leave で 12 イベント) を行う。生成 Detour が
                        // 実動していなければ 0 件になる。
                        if *app == "console" {
                            let reg_ids: Vec<u32> = [
                                "RegCreateKeyExW",
                                "RegSetValueExW",
                                "RegQueryValueExW",
                                "RegDeleteValueW",
                                "RegCloseKey",
                                "RegDeleteKeyW",
                            ]
                            .iter()
                            .filter_map(|n| shirusu_hook::api::api_by_name(n).map(|a| a.api_id))
                            .collect();
                            let reg_events = events
                                .iter()
                                .filter(|e| reg_ids.contains(&e.api_id))
                                .count();
                            c.check(
                                reg_events >= 12,
                                &format!("{app} at least 12 registry events (got {reg_events})"),
                            );
                        }
                        // COM (L02): com アプリは CoCreateInstance、IShellLinkW
                        // の SetPath/GetPath、IPersistFile への QueryInterface
                        // と Release を COM メソッドイベントとして記録する。
                        // Factory 関数が 1 つも設置できていなければ、COM
                        // メソッドの記録はそもそも始まらない。
                        if *app == "com" {
                            c.check(
                                summary.com_factory_count.unwrap_or(0) >= 1,
                                &format!(
                                    "{app} at least 1 COM factory hooked (got {:?})",
                                    summary.com_factory_count
                                ),
                            );
                            let com_enters: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id == shirusu_hook::com::COM_METHOD_ENTER_SCHEMA_ID
                                })
                                .collect();
                            let com_leaves: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id == shirusu_hook::com::COM_METHOD_LEAVE_SCHEMA_ID
                                })
                                .collect();
                            let names: Vec<String> = com_enters
                                .iter()
                                .filter_map(|e| com_method_name(&trace, e))
                                .collect();
                            let count =
                                |name: &str| names.iter().filter(|n| n.as_str() == name).count();
                            c.check(
                                count("CoCreateInstance") >= 1,
                                &format!(
                                    "{app} CoCreateInstance recorded (got {})",
                                    count("CoCreateInstance")
                                ),
                            );
                            c.check(
                                count("IShellLinkW::SetPath") >= 1,
                                &format!("{app} IShellLinkW::SetPath recorded"),
                            );
                            c.check(
                                count("IShellLinkW::GetPath") >= 1,
                                &format!("{app} IShellLinkW::GetPath recorded"),
                            );
                            c.check(
                                count("IShellLinkW::QueryInterface") >= 1,
                                &format!("{app} IShellLinkW::QueryInterface recorded"),
                            );
                            let releases =
                                names.iter().filter(|n| n.ends_with("::Release")).count();
                            c.check(
                                releases >= 2,
                                &format!(
                                    "{app} at least 2 Release calls recorded (got {releases})"
                                ),
                            );
                            c.check(
                                com_enters.len() >= 6,
                                &format!(
                                    "{app} at least 6 COM method enters (got {})",
                                    com_enters.len()
                                ),
                            );
                            c.check(
                                com_leaves.len() == com_enters.len(),
                                &format!(
                                    "{app} COM enters/leaves pair up ({} enters, {} leaves)",
                                    com_enters.len(),
                                    com_leaves.len()
                                ),
                            );
                            // 同一性：QueryInterface の leave が返す別ポインタ
                            // が、IPersistFile として追跡され、その Release が
                            // 返されたポインタで記録されていること（L02 の
                            // 同一性・寿命の実動確認）。
                            let mut qi_returned: Option<u64> = None;
                            for enter in &com_enters {
                                if com_method_name(&trace, enter).as_deref()
                                    != Some("IShellLinkW::QueryInterface")
                                {
                                    continue;
                                }
                                let Some(leave) =
                                    com_leaves.iter().find(|l| l.call_id == enter.call_id)
                                else {
                                    continue;
                                };
                                if let Some((hr, returned, _)) = com_leave_values(&trace, leave) {
                                    if hr == 0 && returned != 0 {
                                        if let Some(obj) = com_enter_object(&trace, enter) {
                                            if returned != obj {
                                                qi_returned = Some(returned);
                                            }
                                        }
                                    }
                                }
                            }
                            c.check(
                                qi_returned.is_some(),
                                &format!(
                                    "{app} QueryInterface returns a different interface pointer"
                                ),
                            );
                            if let Some(returned) = qi_returned {
                                let released = com_enters.iter().any(|e| {
                                    com_method_name(&trace, e)
                                        .is_some_and(|n| n.ends_with("::Release"))
                                        && com_enter_object(&trace, e) == Some(returned)
                                });
                                c.check(
                                    released,
                                    &format!("{app} Release recorded on the QueryInterface-returned pointer"),
                                );
                            }
                        }
                        // WinRT (L14): winrt アプリは RoActivateInstance、
                        // RoGetActivationFactory、IInspectable の
                        // GetRuntimeClassName、IActivationFactory の
                        // ActivateInstance、IUriRuntimeClassFactory の
                        // CreateUri、IUriRuntimeClass の AbsoluteUri を
                        // 記録する。アクティベーション関数が 1 つも設置
                        // できていなければ、WinRT の記録はそもそも始まらない。
                        if *app == "winrt" {
                            c.check(
                                summary.winrt_activation_count.unwrap_or(0) >= 1,
                                &format!(
                                    "{app} at least 1 WinRT activation hooked (got {:?})",
                                    summary.winrt_activation_count
                                ),
                            );
                            let winrt_enters: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id
                                        == shirusu_hook::winrt::WINRT_ACTIVATION_ENTER_SCHEMA_ID
                                })
                                .collect();
                            let winrt_leaves: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id
                                        == shirusu_hook::winrt::WINRT_ACTIVATION_LEAVE_SCHEMA_ID
                                })
                                .collect();
                            let winrt_names: Vec<String> = winrt_enters
                                .iter()
                                .filter_map(|e| winrt_activation_method_name(&trace, e))
                                .collect();
                            let wcount = |name: &str| {
                                winrt_names.iter().filter(|n| n.as_str() == name).count()
                            };
                            c.check(
                                wcount("RoActivateInstance") >= 1,
                                &format!(
                                    "{app} RoActivateInstance recorded (got {})",
                                    wcount("RoActivateInstance")
                                ),
                            );
                            c.check(
                                wcount("RoGetActivationFactory") >= 2,
                                &format!(
                                    "{app} RoGetActivationFactory recorded (got {})",
                                    wcount("RoGetActivationFactory")
                                ),
                            );
                            let classes: Vec<String> = winrt_enters
                                .iter()
                                .filter_map(|e| winrt_enter_class_name(&trace, e))
                                .collect();
                            c.check(
                                classes.iter().any(|c| c == "Windows.Foundation.Uri"),
                                &format!("{app} Uri class name recorded"),
                            );
                            c.check(
                                classes.iter().any(|c| c == "Windows.Data.Json.JsonObject"),
                                &format!("{app} JsonObject class name recorded"),
                            );
                            c.check(
                                winrt_enters.len() >= 3,
                                &format!(
                                    "{app} at least 3 WinRT activation enters (got {})",
                                    winrt_enters.len()
                                ),
                            );
                            c.check(
                                winrt_leaves.len() == winrt_enters.len(),
                                &format!(
                                    "{app} WinRT activation enters/leaves pair up ({} enters, {} leaves)",
                                    winrt_enters.len(),
                                    winrt_leaves.len()
                                ),
                            );
                            let com_enters: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id == shirusu_hook::com::COM_METHOD_ENTER_SCHEMA_ID
                                })
                                .collect();
                            let com_leaves: Vec<&&TraceEvent> = events
                                .iter()
                                .filter(|e| {
                                    e.schema_id == shirusu_hook::com::COM_METHOD_LEAVE_SCHEMA_ID
                                })
                                .collect();
                            let names: Vec<String> = com_enters
                                .iter()
                                .filter_map(|e| com_method_name(&trace, e))
                                .collect();
                            let ccount =
                                |name: &str| names.iter().filter(|n| n.as_str() == name).count();
                            c.check(
                                ccount("IInspectable::GetRuntimeClassName") >= 2,
                                &format!(
                                    "{app} GetRuntimeClassName recorded (got {})",
                                    ccount("IInspectable::GetRuntimeClassName")
                                ),
                            );
                            c.check(
                                ccount("IActivationFactory::ActivateInstance") >= 1,
                                &format!("{app} IActivationFactory::ActivateInstance recorded"),
                            );
                            c.check(
                                ccount("IActivationFactory::QueryInterface") >= 1,
                                &format!("{app} IActivationFactory::QueryInterface recorded"),
                            );
                            c.check(
                                ccount("IUriRuntimeClassFactory::CreateUri") >= 1,
                                &format!("{app} IUriRuntimeClassFactory::CreateUri recorded"),
                            );
                            c.check(
                                ccount("IUriRuntimeClass::AbsoluteUri") >= 1,
                                &format!("{app} IUriRuntimeClass::AbsoluteUri recorded"),
                            );
                            let releases =
                                names.iter().filter(|n| n.ends_with("::Release")).count();
                            c.check(
                                releases >= 2,
                                &format!(
                                    "{app} at least 2 Release calls recorded (got {releases})"
                                ),
                            );
                            c.check(
                                com_enters.len() >= 10,
                                &format!(
                                    "{app} at least 10 COM method enters (got {})",
                                    com_enters.len()
                                ),
                            );
                            c.check(
                                com_leaves.len() == com_enters.len(),
                                &format!(
                                    "{app} COM enters/leaves pair up ({} enters, {} leaves)",
                                    com_enters.len(),
                                    com_leaves.len()
                                ),
                            );
                        }
                    }
                    Err(e) => c.check(false, &format!("{app} trace parses ({e})")),
                },
                Err(e) => c.check(false, &format!("{app} trace readable ({e})")),
            }
            let _ = std::fs::remove_file(&base_out);
            let _ = std::fs::remove_file(&hooked_out);
            let _ = std::fs::remove_file(&trace_path);
        }

        // 5. カバレッジ評価（INFO。未記録は将来の L 項目待ちのため失敗にしない）。
        // フック表に載っている API は記録され、載っていない API は記録されない
        // ことを、表の照合で確認する。レジストリは L03 の生成表で記録される。
        // COM は L02 で Factory 関数（Inline Hook）と vtable メソッドを記録する。
        // WinRT は L14 でアクティベーション関数（Inline Hook）と vtable メソッドを記録する。
        println!("coverage evaluation (L17):");
        println!("  recorded: file I/O (CreateFileW/WriteFile/ReadFile/CloseHandle)");
        println!("  recorded: COM (CoCreateInstance factory + IShellLinkW/IPersistFile vtable methods, L02)");
        println!("  recorded: WinRT (RoActivateInstance/RoGetActivationFactory + IInspectable/IUriRuntimeClass vtable methods, L14)");
        for (group, names, note) in [
            (
                "registry",
                ["RegCreateKeyExW", "RegSetValueExW", "RegQueryValueExW"].as_slice(),
                "L03 generated",
            ),
            (
                "user32",
                ["RegisterClassExW", "CreateWindowExW"].as_slice(),
                "pending",
            ),
            (
                "gdi",
                ["CreateCompatibleDC", "BitBlt"].as_slice(),
                "pending",
            ),
            ("dib", ["CreateDIBSection"].as_slice(), "pending"),
        ] {
            let hooked: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| shirusu_hook::api::api_by_name(n).is_some())
                .collect();
            let unhooked: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| shirusu_hook::api::api_by_name(n).is_none())
                .collect();
            println!("  {group}: hooked={hooked:?} not-in-hook-table={unhooked:?} ({note})");
        }
        // COM (L02): Factory 関数は API 表には無い（Inline Hook で設置する）。
        // フック可否は COM の Factory 表で確認する。
        let com_hooked: Vec<&str> = ["CoCreateInstance", "CoGetClassObject"]
            .iter()
            .copied()
            .filter(|n| {
                shirusu_hook::com::factory_by_name("ole32.dll", n).is_some_and(|f| f.hookable)
            })
            .collect();
        println!("  com: factory-hooked={com_hooked:?} (L02; Direct3DCreate9 is known but not hooked: no IDirect3D9 method table yet)");
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e --verify-apps");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e --verify-apps: {} checks failed",
                c.failures.len()
            );
            1
        }
    }
    /// L23 のモジュール列挙・署名検証・API Set 解決・フック時呼び出し元
    /// 分類の E2E。`hook-target --runtime-caller` を Agent DLL 付きで
    /// 起動し、Trace の Environment.modules に列挙・分類されたモジュール
    /// が載ることと、直接呼び出しのファイル I/O が記録されることを検証
    /// する。`record_runtime_apis` の on/off 両方で実行する。
    /// CRT 経由の呼び出しは現行のメインモジュール限定 IAT では Detour
    /// に届かないため、Trace に現れないことを INFO として報告する
    /// （失敗にしない。L01 後に抑制の検証対象になる）。
    pub fn run_modules() -> i32 {
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
        let mut c = Checker { failures: vec![] };

        // API Set 契約の解決を in-process で直接確認する（列挙とは別経路）。
        let resolved = shirusu_transport_win::modules::resolve_api_set_contract(
            "api-ms-win-core-file-l1-1-0.dll",
        );
        c.check(
            resolved.is_some(),
            "api-set contract resolves to an implementation module",
        );
        if let Some(path) = &resolved {
            let lower = path.to_ascii_lowercase();
            c.check(
                lower.ends_with("kernel32.dll") || lower.ends_with("kernelbase.dll"),
                &format!("api-set contract resolves to kernel32/kernelbase ({path})"),
            );
            c.check(
                std::path::Path::new(path).exists(),
                &format!("api-set implementation path exists ({path})"),
            );
        }
        // 未ロードの名前は解決できない。
        c.check(
            shirusu_transport_win::modules::resolve_api_set_contract(
                "shirusu-definitely-not-loaded-xyz.dll",
            )
            .is_none(),
            "unloaded module name does not resolve",
        );

        let pid = std::process::id();
        let workdir = std::env::temp_dir().join(format!("shirusu-modules-{pid}"));
        let _ = std::fs::create_dir_all(&workdir);
        for record_runtime in [false, true] {
            let tag = if record_runtime {
                "runtime-on"
            } else {
                "default"
            };
            let trace_path =
                std::env::temp_dir().join(format!("shirusu-modules-{tag}-{pid}.trace"));
            let _ = std::fs::remove_file(&trace_path);
            let mut launch_cfg = LaunchConfig::new(session_config(), dll.clone());
            launch_cfg.session.record_runtime_apis = record_runtime;
            let cmdline = format!(
                "\"{}\" --runtime-caller \"{}\"",
                target.display(),
                workdir.display()
            );
            println!("launching ({tag}) {cmdline}");
            let capture = match LaunchedCapture::launch(&cmdline, &trace_path, launch_cfg) {
                Ok(c) => c,
                Err(e) => {
                    println!("FAIL: {tag} launch: {e}");
                    c.failures.push(format!("{tag} launch: {e}"));
                    continue;
                }
            };
            let summary = match capture.run_to_completion(Duration::from_millis(2)) {
                Ok(s) => s,
                Err(e) => {
                    println!("FAIL: {tag} run: {e}");
                    c.failures.push(format!("{tag} run: {e}"));
                    continue;
                }
            };
            println!(
                "{tag} summary: events={} losses={} integrity={:?}",
                summary.total_events, summary.total_loss_records, summary.integrity.event_integrity
            );
            match std::fs::read(&trace_path) {
                Ok(bytes) => match shirusu_trace::read_trace(&bytes) {
                    Ok(trace) => {
                        check_modules_trace(&mut c, &trace, tag, &summary, &workdir, pid);
                    }
                    Err(e) => c.check(false, &format!("{tag} trace parses ({e})")),
                },
                Err(e) => c.check(false, &format!("{tag} trace readable ({e})")),
            }
            let _ = std::fs::remove_file(&trace_path);
        }
        let _ = std::fs::remove_dir_all(&workdir);
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e --modules");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e --modules: {} checks failed",
                c.failures.len()
            );
            1
        }
    }

    /// --modules シナリオの Trace 1 件分の検査。`tag` は実行区分
    /// （"default" / "runtime-on"）。
    fn check_modules_trace(
        c: &mut Checker,
        trace: &shirusu_trace::reader::ReadTrace,
        tag: &str,
        summary: &shirusu_host::recorder::SessionSummary,
        workdir: &std::path::Path,
        pid: u32,
    ) {
        use shirusu_trace::module::ModuleClass;
        c.check(
            trace.finalization.is_some(),
            &format!("{tag} trace finalized"),
        );
        c.check(
            summary.integrity.event_integrity != IntegrityLevel::Lost,
            &format!("{tag} event integrity not lost"),
        );
        let Some(env) = trace.environment.as_ref() else {
            c.check(false, &format!("{tag} environment present"));
            return;
        };
        // capture_config に列挙結果の注記があること。
        c.check(
            env.capture_config.contains("modules="),
            &format!("{tag} capture_config notes module enumeration"),
        );
        // モジュール一覧：最低でも exe・ntdll・kernel32 が載ること。
        c.check(!env.modules.is_empty(), &format!("{tag} modules listed"));
        let by_file = |name: &str| {
            env.modules.iter().find(|m| {
                m.module_name
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case(name)
            })
        };
        // kernel32.dll は Windows（署名確認済み）。
        match by_file("kernel32.dll") {
            Some(m) => {
                c.check(
                    m.class == ModuleClass::Windows,
                    &format!("{tag} kernel32 is windows"),
                );
                c.check(!m.uncertain, &format!("{tag} kernel32 certain"));
                c.check(
                    m.reason.contains("Microsoft"),
                    &format!("{tag} kernel32 reason mentions Microsoft"),
                );
            }
            None => c.check(false, &format!("{tag} kernel32 listed")),
        }
        // 対象 exe は Application。
        match by_file("shirusu-hook-target.exe") {
            Some(m) => c.check(
                m.class == ModuleClass::Application,
                &format!("{tag} hook-target is application"),
            ),
            None => c.check(false, &format!("{tag} hook-target listed")),
        }
        // ucrtbase.dll が載っていれば Runtime。
        if let Some(m) = by_file("ucrtbase.dll") {
            c.check(
                m.class == ModuleClass::Runtime,
                &format!("{tag} ucrtbase is runtime"),
            );
        } else {
            println!("  INFO: {tag} ucrtbase.dll not in module list (not loaded?)");
        }
        // イベント：直接呼び出しの CreateFileW が記録されること。
        let events: Vec<&TraceEvent> = trace.batches.iter().flat_map(|b| &b.events).collect();
        let cf = shirusu_hook::api::api_by_id(API_CREATE_FILE_W).unwrap();
        let direct = workdir
            .join(format!("shirusu-runtime-caller-direct-{pid}.tmp"))
            .to_string_lossy()
            .to_ascii_lowercase();
        let crt = workdir
            .join(format!("shirusu-runtime-caller-crt-{pid}.tmp"))
            .to_string_lossy()
            .to_ascii_lowercase();
        let mut direct_events = 0;
        let mut crt_events = 0;
        for e in &events {
            if e.schema_id != cf.enter_schema_id() {
                continue;
            }
            let types = trace
                .registry
                .types(e.schema_id)
                .expect("schema registered");
            let args = e.args.as_ref().expect("args attached (L2)");
            let values = decode_values(&types, args).expect("args decode");
            if let TypedValue::Str16(u) = &values[0].value {
                let path = String::from_utf16_lossy(u).to_ascii_lowercase();
                if path == direct {
                    direct_events += 1;
                } else if path == crt {
                    crt_events += 1;
                }
            }
        }
        c.check(
            direct_events >= 1,
            &format!("{tag} direct CreateFileW recorded"),
        );
        // L01: CRT 経由の呼び出しも Inline Hook で Detour に届く。
        // record_runtime_apis が無効（default）の場合は L23 の呼び出し元
        // 分類で抑制され、Trace に現れない。有効（runtime-on）の場合は記録される。
        if tag == "default" {
            c.check(
                crt_events == 0,
                &format!("{tag} crt-mediated CreateFileW suppressed (got {crt_events})"),
            );
        } else {
            c.check(
                crt_events >= 1,
                &format!("{tag} crt-mediated CreateFileW recorded (got {crt_events})"),
            );
        }
    }
    /// L01: Inline Hook の E2E。hook-target `--getprocaddress` は
    /// ファイル 4 API と RegCreateKeyExW / RegCloseKey を
    /// `GetProcAddress` で取得したポインタ経由で呼ぶため、IAT 経由では
    /// 記録されない。Trace に 8 件のファイル I/O イベントとレジストリ
    /// 2 API の enter が残ることを検証する。
    pub fn run_inline() -> i32 {
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
            "shirusu-capture-e2e-inline-{}.trace",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&trace_path);
        let cfg = LaunchConfig::new(session_config(), dll);
        let cmdline = format!("\"{}\" --getprocaddress", target.display());
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
        let bytes = std::fs::read(&trace_path).expect("trace file");
        let trace = shirusu_trace::read_trace(&bytes).expect("trace parses");
        let events: Vec<&TraceEvent> = trace.batches.iter().flat_map(|b| &b.events).collect();
        let cf = shirusu_hook::api::api_by_id(API_CREATE_FILE_W).unwrap();
        let rf = shirusu_hook::api::api_by_id(API_READ_FILE).unwrap();
        let wf = shirusu_hook::api::api_by_id(API_WRITE_FILE).unwrap();
        let ch = shirusu_hook::api::api_by_id(API_CLOSE_HANDLE).unwrap();
        let reg_create = shirusu_hook::api::api_table()
            .find(|a| a.function == "RegCreateKeyExW")
            .expect("RegCreateKeyExW in table");
        let reg_close = shirusu_hook::api::api_table()
            .find(|a| a.function == "RegCloseKey")
            .expect("RegCloseKey in table");

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
                    s.contains("shirusu-hook-target-gpa-"),
                    "getprocaddress createfile path captured",
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
        // 生成 API（L03 表）の Inline Hook：RegCreateKeyExW は L1 のため
        // 文字列は取らない。hKey が HKEY_CURRENT_USER であることで
        // 対象の呼び出しであることを確認する。RegCloseKey も同様。
        if let Some(e) = find(&events, reg_create.enter_schema_id()) {
            let v = arg(&trace, e, 0);
            c.check(
                v == TypedValue::U64(0x8000_0001),
                "regcreatekeyexw enter present (HKCU)",
            );
        } else {
            c.check(false, "RegCreateKeyExW enter present");
        }
        c.check(
            find(&events, reg_close.enter_schema_id()).is_some(),
            "regclosekey enter present",
        );
        let _ = std::fs::remove_file(&trace_path);
        if c.failures.is_empty() {
            println!("PASS shirusu-capture-e2e --inline");
            0
        } else {
            println!(
                "FAIL shirusu-capture-e2e --inline: {} checks failed",
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
        if args.iter().any(|a| a == "--inline") {
            std::process::exit(win::run_inline());
        }
        if args.iter().any(|a| a == "--abi") {
            std::process::exit(win::run_abi());
        }
        if args.iter().any(|a| a == "--modules") {
            std::process::exit(win::run_modules());
        }
        if args.iter().any(|a| a == "--verify-apps") {
            std::process::exit(win::run_verify_apps());
        }
        if args.iter().any(|a| a == "--child-tree") {
            std::process::exit(win::run_child_tree());
        }
        std::process::exit(win::run());
    }
    #[cfg(not(windows))]
    println!("SKIP shirusu-capture-e2e (windows only)");
}
