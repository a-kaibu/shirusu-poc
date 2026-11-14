//! `shirusu capture` / `shirusu attach`（L22）。

use super::*;

// ---------------------------------------------------------------------------
// L22: `shirusu capture` / `shirusu attach`
//
// 記録コマンドは Windows 専用（overview のコマンド表）。実働は
// `LaunchedCapture`（host/recorder_launch.rs、L04 でライブラリ層は
// 検証済み）に委ね、CLI は引数の検証・設定の組み立て・要約の表示だけを
// 担う。引数の検証はプラットフォームゲートの前に行うため、Windows 以外
// でも使い方の誤りは終了 2 で、制限そのものは終了 1 で返す。
//
// 来歴不明の記録（overview「プロセスの起動・アタッチ」節）:
// attach は動作中のプロセスへ途中から入るため、アタッチ前の呼び出しや
// その時点で既に存在するオブジェクトの来歴は分からない。これを
// CaptureEnvironment.capture_config に明記する（`shirusu inspect` が
// そのまま表示する）。capture は CREATE_SUSPENDED で起動し、アプリの
// コードが動く前に Agent を準備するため、来歴は起動時から完全である。
// 形式の変更は無い（既存の文字列欄を使う）。
// ---------------------------------------------------------------------------

/// capture / attach の記録方法。Linux では単体テスト以外に読む場所が
/// 無いため（実働は Windows の `run_capture` のみ）、未使用警告を抑える。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum CaptureMode {
    /// 起動して最初から記録する。`cmdline` は Windows のコマンドライン
    /// 文字列（`build_cmdline` で組み立てたもの）。
    Launch { cmdline: String, exe: String },
    /// 動作中のプロセスへ途中から記録する。
    Attach { pid: u32 },
}

/// 検証済みの引数をひとまとめにした記録要求。プラットフォーム非依存。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct CaptureRequest {
    pub(crate) mode: CaptureMode,
    pub(crate) output: PathBuf,
    pub(crate) dll: Option<PathBuf>,
    pub(crate) timeout: Duration,
    pub(crate) order_global: bool,
    /// L07: モジュール単位の分類の上書き（`--module-class` の指定順）。
    pub(crate) module_classes: Vec<ModuleOverride>,
    /// L07: Runtime 独自の API も記録するか（既定は false）。
    pub(crate) record_runtime_apis: bool,
    /// L02: 診断用の追加 QueryInterface を有効にするか（既定は false）。
    pub(crate) diagnostic_query_interface: bool,
    /// L09: 記録モード（`--mode`。既定は `full`）。
    pub(crate) record_mode: RecordMode,
    /// L09: `--api` で指定された通りの名前列（`filtered` のときだけ
    /// 使い、Environment の capture_config に載せる）。
    pub(crate) api_names: Vec<String>,
    /// L05: 起動した対象の子プロセスも追跡するか
    /// （`--follow-children`。capture 専用）。
    pub(crate) follow_children: bool,
    pub(crate) ring_config: shirusu_transport::RingConfig,
    /// P1-1: `--rings`（同時に記録できるスレッド数）。None は既定値。
    pub(crate) rings: Option<usize>,
}

/// capture / attach の共通オプション（`--output` / `--dll` /
/// `--timeout` / `--order=global` / `--module-class` /
/// `--record-runtime-apis` / `--diagnostic-query-interface` /
/// `--mode` / `--api` / `--follow-children` / `--buffer`）。
pub(crate) struct CaptureOptions {
    pub(crate) output: Option<String>,
    pub(crate) dll: Option<PathBuf>,
    pub(crate) timeout_secs: u64,
    pub(crate) order_global: bool,
    pub(crate) module_classes: Vec<ModuleOverride>,
    pub(crate) record_runtime_apis: bool,
    /// L02: 診断用の追加 QueryInterface を有効にするか（既定は false）。
    pub(crate) diagnostic_query_interface: bool,
    /// L09: 記録モード（`--mode`。既定は `full`）。
    pub(crate) record_mode: RecordMode,
    /// L09: `--api` で指定された通りの名前列。
    pub(crate) api_names: Vec<String>,
    /// L05: 子プロセスも追跡するか（`--follow-children`）。
    pub(crate) follow_children: bool,
    pub(crate) ring_config: shirusu_transport::RingConfig,
    /// P1-1: `--rings`（同時に記録できるスレッド数）。None は既定値。
    pub(crate) rings: Option<usize>,
}

impl CaptureOptions {
    pub(crate) fn parse(parsed: &Parsed) -> Result<Self, ToolError> {
        parsed.validate_options(&[
            "output",
            "dll",
            "timeout",
            "order",
            "module-class",
            "record-runtime-apis",
            "diagnostic-query-interface",
            "mode",
            "api",
            "follow-children",
            "buffer",
            "rings",
        ])?;
        // P1-1: 同時に記録できるスレッドの数。足りない分は Capture
        // Coverage の欠落として Trace に残る。
        let rings = match parsed.opt("rings") {
            None => None,
            Some(v) => match v.parse::<usize>() {
                Ok(n) if (1..=shirusu_host::MAX_RING_COUNT).contains(&n) => Some(n),
                _ => {
                    return Err(ToolError::Usage(format!(
                        "bad --rings: {v} (expected 1..={})",
                        shirusu_host::MAX_RING_COUNT
                    )))
                }
            },
        };
        let ring_config = match parsed.opt("buffer") {
            None | Some("standard") => shirusu_transport::RingConfig::PRODUCTION,
            Some("burst") => shirusu_transport::RingConfig::BURST,
            Some(other) => {
                return Err(ToolError::Usage(format!(
                    "unknown --buffer value: {other} (expected standard or burst)"
                )))
            }
        };
        let timeout_secs = match parsed.opt("timeout") {
            Some(v) => v
                .parse()
                .map_err(|_| ToolError::Usage(format!("bad --timeout: {v}")))?,
            None => 30,
        };
        // dump と同じ `--order=global` の表記。値が global 以外なら
        // 使い方エラーにする。
        let order_global = match parsed.opt("order") {
            None => false,
            Some("global") => true,
            Some(other) => {
                return Err(ToolError::Usage(format!(
                    "unknown --order value: {other} (expected global)"
                )))
            }
        };
        // L07: 繰り返し指定できる `--module-class <module>=<class>`。
        // 1 件でも不正なら使い方エラーにする。
        let mut module_classes = Vec::new();
        for v in parsed.opts_all("module-class") {
            module_classes.push(
                ModuleOverride::parse(v)
                    .map_err(|e| ToolError::Usage(format!("bad --module-class: {e}")))?,
            );
        }
        // L09: `--mode` と `--api`。`--api` は `--mode filtered` の
        // ときだけ意味があり、`filtered` には 1 件以上の `--api` が要る。
        // 未知の API 名も使い方エラーにする。
        let api_names: Vec<String> = parsed
            .opts_all("api")
            .iter()
            .map(|s| s.to_string())
            .collect();
        let record_mode = match parsed.opt("mode") {
            None | Some("full") => RecordMode::Full,
            Some("profile") => RecordMode::Profile,
            // L15: 詳細調査モード。Windows 内部の呼び出し (Nt*) も記録する。
            Some("detailed") => RecordMode::Detailed,
            Some("filtered") => {
                if api_names.is_empty() {
                    return Err(ToolError::Usage(
                        "--mode filtered requires at least one --api".into(),
                    ));
                }
                RecordMode::Filtered {
                    apis: resolve_api_names(&api_names).map_err(ToolError::Usage)?,
                }
            }
            Some(other) => {
                return Err(ToolError::Usage(format!(
                    "unknown --mode value: {other} (expected full, profile, filtered, or detailed)"
                )))
            }
        };
        if !matches!(record_mode, RecordMode::Filtered { .. }) && !api_names.is_empty() {
            return Err(ToolError::Usage("--api requires --mode filtered".into()));
        }
        Ok(Self {
            output: parsed.opt("output").map(str::to_string),
            dll: parsed.opt("dll").map(PathBuf::from),
            timeout_secs,
            ring_config,
            rings,
            order_global,
            module_classes,
            // L07: Runtime 独自の API を記録するか（既定は記録しない）。
            // L15: 詳細調査モードでは Runtime 起源の内部呼び出しも記録
            // するため、ここで強制的に有効にする。
            record_runtime_apis: parsed.has("record-runtime-apis")
                || matches!(record_mode, RecordMode::Detailed),
            // L02: 診断用の追加 QueryInterface を有効にするか
            // （既定は無効。標準では Interceptor 自身は QI を呼ばない）。
            diagnostic_query_interface: parsed.has("diagnostic-query-interface"),
            record_mode,
            api_names,
            // L05: 子プロセスも追跡するか（既定はしない）。
            follow_children: parsed.has("follow-children"),
        })
    }
}

/// 引数列を `--` の前後で分ける。`--` が無ければ後半は空。
pub(crate) fn split_dashdash(args: &[String]) -> (&[String], &[String]) {
    match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    }
}

/// Windows のコマンドライン文字列へ組み立てる。MSVC CRT /
/// `CommandLineToArgvW` の規則で各要素がそのまま復元されるように引用する:
/// 空文字列は `""`、空白・タブ・引用符を含む要素は二重引用符で囲み、
/// 引用符の直前と閉じ引用符の直前にある `\` の連続は倍にする。
pub(crate) fn build_cmdline(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| quote_windows_arg(p))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"'))
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// capture の既定の出力パス：exe のファイル stem に `.trace` を付けたもの。
pub(crate) fn default_capture_output(exe: &str) -> String {
    let stem = Path::new(exe)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| exe.to_string());
    format!("{stem}.trace")
}

/// attach の既定の出力パス。
pub(crate) fn default_attach_output(pid: u32) -> String {
    format!("shirusu-attach-{pid}.trace")
}

/// 記録セッションの CaptureEnvironment を作る。`session_id` は
/// config.session_id と同じ値にすること（recorder が一致を検証する）。
/// attach では来歴不明の旨を capture_config に明記する（L22 の要求）。
///
/// L07: 起動対象の exe をモジュールとして分類して `modules` に載せる。
/// `--module-class` の上書きは、既知のモジュールに当たれば分類を置き換え、
/// 当たらなければ（capture 開始時に未ロードのモジュールへの上書きは
/// 黙って消えないよう）上書きエントリとして残す。署名の確認は Windows
/// 側の仕事のため、ここでは `microsoft_signed: None` の証拠で分類する
/// （対象 exe はシステム配置でない限り Application になる）。
/// L23: Host が capture 開始時に全モジュールを列挙・署名検証して
/// `modules` を置き換えるため、ここのエントリは暫定のものである
/// （列挙に失敗した場合はこちらが残る。CLI の上書きは置き換え時にも
/// 温存される）。
/// L13: 起動対象の exe の PE インポートテーブルから静的依存を読み、
/// `static_dependencies` に載せる（読めなければ空のまま）。
/// Linux では単体テスト以外に呼ぶ場所が無いため、未使用警告を抑える。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn capture_environment(
    mode: &CaptureMode,
    session_id: u64,
    qpc_frequency: u64,
    overrides: &[ModuleOverride],
    record_mode: &RecordMode,
    api_names: &[String],
) -> CaptureEnvironment {
    let (created_by, target_description, base_config) = match mode {
        CaptureMode::Launch { exe, .. } => (
            "shirusu capture".to_string(),
            exe.clone(),
            "launched".to_string(),
        ),
        CaptureMode::Attach { pid } => (
            "shirusu attach".to_string(),
            format!("pid {pid}"),
            format!(
                "attached pid={pid}; pre-attach calls and pre-existing objects have unknown provenance"
            ),
        ),
    };
    // L09: 記録モードも capture_config に明記する（`mode=full` /
    // `mode=profile` / `mode=filtered apis=...`）。`full` でも明記する
    // のは、後から Trace を見たときに「間引き無しで記録された」ことが
    // 分かるようにするため。
    let capture_config = format!("{base_config}; {}", record_mode.config_text(api_names));
    let mut modules = Vec::new();
    let mut static_dependencies = Vec::new();
    if let CaptureMode::Launch { exe, .. } = mode {
        modules.push(classify_module(&ModuleEvidence::new(exe)));
        // L13: 起動対象の exe の PE インポートテーブルから静的依存を
        // 読む。読めなければ空のまま（capture を失敗させない）。
        static_dependencies = shirusu_host::static_dep::static_dependencies_for_exe(Path::new(exe));
    }
    let unused = apply_overrides(&mut modules, overrides);
    for ov in unused {
        modules.push(ModuleClassification {
            module_name: ov.module.clone(),
            class: ov.class,
            reason: "CLI override (module not loaded at capture start)".to_string(),
            uncertain: false,
            implementation_module: None,
            overridden: true,
        });
    }
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by,
            qpc_frequency,
        },
        target_description,
        capture_config,
        modules,
        static_dependencies,
        ..Default::default()
    }
}

pub(crate) fn cmd_capture(args: &[String]) -> Result<(), ToolError> {
    let (opts_args, cmdline_parts) = split_dashdash(args);
    let parsed = parse_args(
        opts_args,
        &[
            "record-runtime-apis",
            "diagnostic-query-interface",
            "follow-children",
        ],
    )?;
    if !parsed.positional.is_empty() {
        return Err(ToolError::Usage(format!(
            "unexpected argument: {} (put the command line after --)",
            parsed.positional[0]
        )));
    }
    let opts = CaptureOptions::parse(&parsed)?;
    if cmdline_parts.is_empty() {
        return Err(ToolError::Usage(
            "capture needs a command line after -- (shirusu capture -- <exe> [args...])".into(),
        ));
    }
    let exe = cmdline_parts[0].clone();
    let cmdline = build_cmdline(cmdline_parts);
    let output = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_capture_output(&exe)));
    run_capture(&CaptureRequest {
        mode: CaptureMode::Launch { cmdline, exe },
        output,
        dll: opts.dll,
        timeout: Duration::from_secs(opts.timeout_secs),
        ring_config: opts.ring_config,
        rings: opts.rings,
        order_global: opts.order_global,
        module_classes: opts.module_classes,
        record_runtime_apis: opts.record_runtime_apis,
        diagnostic_query_interface: opts.diagnostic_query_interface,
        record_mode: opts.record_mode,
        api_names: opts.api_names,
        follow_children: opts.follow_children,
    })
}

pub(crate) fn cmd_attach(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(
        args,
        &[
            "record-runtime-apis",
            "diagnostic-query-interface",
            "follow-children",
        ],
    )?;
    let pid_s = parsed
        .positional
        .first()
        .ok_or_else(|| ToolError::Usage("attach needs a <PID>".into()))?;
    if parsed.positional.len() > 1 {
        return Err(ToolError::Usage(format!(
            "unexpected argument: {}",
            parsed.positional[1]
        )));
    }
    let pid: u32 = pid_s
        .parse()
        .map_err(|_| ToolError::Usage(format!("bad pid: {pid_s}")))?;
    let opts = CaptureOptions::parse(&parsed)?;
    // L05: --follow-children は起動（capture）専用。
    if opts.follow_children {
        return Err(ToolError::Usage(
            "--follow-children requires capture (launch)".into(),
        ));
    }
    let output = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_attach_output(pid)));
    run_capture(&CaptureRequest {
        mode: CaptureMode::Attach { pid },
        output,
        dll: opts.dll,
        timeout: Duration::from_secs(opts.timeout_secs),
        ring_config: opts.ring_config,
        rings: opts.rings,
        order_global: opts.order_global,
        module_classes: opts.module_classes,
        record_runtime_apis: opts.record_runtime_apis,
        diagnostic_query_interface: opts.diagnostic_query_interface,
        record_mode: opts.record_mode,
        api_names: opts.api_names,
        follow_children: false,
    })
}

/// capture / attach の実働（Windows）。対象の終了まで回収を続け、終了
/// したら最終回収して Trace を閉じる（`LaunchedCapture::run_to_completion`）。
/// 対象を生かしたまま終える場合は `finish` が Agent の終了手順を呼ぶ。
#[cfg(windows)]
pub(crate) fn run_capture(req: &CaptureRequest) -> Result<(), ToolError> {
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture};
    use shirusu_trace::writer::Durability;

    let dll = resolve_dll(req.dll.as_deref())?;
    let session_id = new_session_id();
    let freq = qpc_frequency();
    let session_cfg = CaptureSessionConfig {
        session_id,
        // Keep default capture costs unchanged; burst buffering is explicit.
        ring_config: req.ring_config,
        environment: capture_environment(
            &req.mode,
            session_id,
            freq,
            &req.module_classes,
            &req.record_mode,
            &req.api_names,
        ),
        qpc_frequency: freq,
        // F21: 永続化は既定の Buffered（flush のみ）。
        durability: Durability::Buffered,
        order_global: req.order_global,
        // L07: Runtime 独自の API を記録するか（既定は記録しない）。
        // Bootstrap v5 で Agent DLL へ伝え、Runtime 自身の API を
        // 呼び出し先で判定する。Runtime から Windows API への呼び出しは記録する。
        record_runtime_apis: req.record_runtime_apis,
        // L02: 診断用の追加 QueryInterface を有効にするか
        // （既定は無効。Bootstrap v6 で Agent DLL へ伝える）。
        diagnostic_query_interface: req.diagnostic_query_interface,
        // L09: 記録モード。
        record_mode: req.record_mode.clone(),
    };
    let mut launch_cfg = LaunchConfig::new(session_cfg, dll);
    launch_cfg.init_timeout = req.timeout;
    // P1-5: Ctrl-C は記録を止めて Trace を確定する (2 回目は強制終了)。
    if shirusu_host::recorder_launch::install_console_stop_handler() {
        eprintln!("shirusu: press Ctrl-C to stop recording and finalize the trace");
    }
    if let Some(n) = req.rings {
        launch_cfg.ring_count = n;
    }
    // L05: --follow-children のときは TreeCapture で子プロセスも追跡する。
    if req.follow_children {
        use shirusu_host::child_tree::child_trace_path;
        use shirusu_host::recorder_launch::TreeCapture;
        let cmdline = match &req.mode {
            CaptureMode::Launch { cmdline, .. } => cmdline,
            // attach での指定は cmd_attach で使い方エラーにしている。
            CaptureMode::Attach { .. } => {
                return Err(ToolError::Runtime(
                    "--follow-children requires capture (launch)".into(),
                ))
            }
        };
        let tree = TreeCapture::launch(cmdline, &req.output, launch_cfg)
            .map_err(|e| ToolError::Runtime(format!("failed to start capture: {e}")))?;
        let summary = tree
            .run_tree_to_completion(Duration::from_millis(2))
            .map_err(|e| ToolError::Runtime(format!("capture failed: {e}")));
        shirusu_host::recorder_launch::notify_stop_finished();
        let summary = summary?;
        print_summary(&req.output, &summary.root);
        for (pid, child) in &summary.children {
            println!("child {pid}:");
            print_summary(&child_trace_path(&req.output, *pid), child);
        }
        for (pid, reason) in &summary.uninjectable {
            println!("child {pid} not recorded: {reason}");
        }
        return Ok(());
    }
    let capture = match &req.mode {
        CaptureMode::Launch { cmdline, .. } => {
            LaunchedCapture::launch(cmdline, &req.output, launch_cfg)
        }
        CaptureMode::Attach { pid } => LaunchedCapture::attach(*pid, &req.output, launch_cfg),
    }
    .map_err(|e| ToolError::Runtime(format!("failed to start capture: {e}")))?;
    let summary = capture
        .run_to_completion(Duration::from_millis(2))
        .map_err(|e| ToolError::Runtime(format!("capture failed: {e}")));
    shirusu_host::recorder_launch::notify_stop_finished();
    print_summary(&req.output, &summary?);
    Ok(())
}

/// Windows 以外では記録はできない。引数の検証は済ませてあるため、ここ
/// ではプラットフォーム制限を明言する（終了 1）。
#[cfg(not(windows))]
pub(crate) fn run_capture(_req: &CaptureRequest) -> Result<(), ToolError> {
    Err(ToolError::Runtime(
        "capture and attach are only available on Windows".into(),
    ))
}

#[cfg(windows)]
pub(crate) fn resolve_dll(explicit: Option<&Path>) -> Result<PathBuf, ToolError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    // e2e と同じ既定値：shirusu 実行ファイルの隣の shirusu_agent_dll.dll。
    let exe = std::env::current_exe()
        .map_err(|e| ToolError::Runtime(format!("cannot locate shirusu executable: {e}")))?;
    let dll = exe
        .parent()
        .map(|d| d.join("shirusu_agent_dll.dll"))
        .unwrap_or_else(|| PathBuf::from("shirusu_agent_dll.dll"));
    if dll.exists() {
        Ok(dll)
    } else {
        Err(ToolError::Runtime(format!(
            "agent dll not found next to shirusu ({}); pass --dll <path>",
            dll.display()
        )))
    }
}

/// セッション ID は起動時刻のナノ秒（UNIX エポック起点）から作る。
/// 時刻が取れない環境では 0 とする（environment と config で同じ値を
/// 使うため、一致検証には通る）。
#[cfg(windows)]
pub(crate) fn new_session_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// QueryPerformanceFrequency（e2e と同じ読み方。失敗時は 10MHz の保険値）。
#[cfg(windows)]
pub(crate) fn qpc_frequency() -> u64 {
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryPerformanceFrequency(out: *mut i64) -> i32;
    }
    let mut f: i64 = 0;
    // SAFETY: out は有効なローカルを指す。
    let ok = unsafe { QueryPerformanceFrequency(&mut f) };
    if ok != 0 && f > 0 {
        f as u64
    } else {
        10_000_000
    }
}

#[cfg(windows)]
pub(crate) fn print_summary(trace: &Path, summary: &shirusu_host::recorder::SessionSummary) {
    use shirusu_host::trace_convert::integrity_level_code;
    println!("captured: {}", trace.display());
    if let Some(code) = summary.target_exit_code {
        println!("target exit code: {code} (0x{code:08X})");
    }
    println!(
        "events: {} (loss records: {})",
        summary.total_events, summary.total_loss_records
    );
    // L09: `profile` モードでは個別イベントが保存されないため、集計を
    // ここで表示する（API 名の解決には Schema が要るため、ここでは
    // api_id のまま出す。名前付きの表示は `shirusu inspect` が担う）。
    if let Some(profile) = &summary.profile_summary {
        println!(
            "profile: {} events seen (individual events not saved)",
            profile.total_events_seen
        );
        for api in &profile.apis {
            println!(
                "  api {}: {} calls, {} enters, {} leaves, total {}",
                api.api_id,
                api.calls,
                api.enters,
                api.leaves,
                qpc_ms(profile.qpc_frequency, api.total_duration_qpc)
            );
        }
    }
    println!(
        "rings: {}/{} active ({} never initialized, {} stopped)",
        summary.rings_active,
        summary.rings_total,
        summary.rings_never_initialized,
        summary.rings_stopped
    );
    println!(
        "args: {} attached, {} fallback to blob",
        summary.args_attached, summary.args_fallback_blob
    );
    let pipeline = &summary.host_pipeline;
    println!(
        "host pipeline: {} commands ({} merged), compression bypasses {}, queue full {}, drain wait {:.3}ms, conversion wall {:.3}ms, queue peak {} bytes",
        pipeline.commands_processed,
        pipeline.merged_event_commands,
        pipeline.compression_bypass_requests,
        pipeline.queue_full_count,
        pipeline.drain_wait_ns as f64 / 1_000_000.0,
        pipeline.conversion_wall_ns as f64 / 1_000_000.0,
        pipeline.peak_queued_bytes,
    );
    if let Some((hooked, missing)) = summary.hook_coverage {
        println!("hook coverage: {hooked} hooked, {missing} missing");
    }
    let i = &summary.integrity;
    println!(
        "integrity: capture_coverage={} event_integrity={} semantic_completeness={}",
        integrity_level_name(integrity_level_code(i.capture_coverage)),
        integrity_level_name(integrity_level_code(i.event_integrity)),
        integrity_level_name(integrity_level_code(i.semantic_completeness)),
    );
    for note in &i.notes {
        println!("note: {note}");
    }
}
