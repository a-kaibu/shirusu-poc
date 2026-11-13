//! Probe 実行の中核（`std` のみ）。生成する Probe exe にそのまま
//! 埋め込むため、このファイルは他のクレートに依存しない。
//!
//! `shirusu-test` の JSON Runner（`runner.rs`）と生成 exe は、どちらも
//! このモジュールの計画・実行・報告を使う。実行の意味論が二か所で
//! ずれないことが、L20 の要点である。
//!
//! 呼び出し表（`CALL_TABLE`）は Probe が実行できる API の最小集合で、
//! 手書きの厳選表である。フック定義表（`shirusu-hook` の `API_TABLE`）
//! は記録用の Schema であり、呼び出しに必要な引数の並び・型（特に
//! out 引数や `lpOverlapped` のような記録しない引数）を持たないため、
//! 呼び出し表としては使えない。WinMD からの生成は将来の拡張。
//! 表に載る API はすべてフック定義表にも載る（＝記録される）ものだけ
//! に絞ってある。表に無い API を呼ぶ仕様は計画時に誤りになる。
//!
//! 実行は Windows でのみ行う。Windows 以外では計画（dry-run）までで、
//! 実行しようとすると誤りになる。生成 exe は Windows 向けにだけ
//! ビルドされるため、実行経路は `cfg(windows)` の内側にある。
//!
//! バッファ引数の読み戻しは上限付き（`MAX_CAPTURED_BUFFER`）。期待値
//! との照合は、バッファについては期待する 16 進文字列との
//! 前方一致で行う（読み戻しバッファは指定サイズ全体で、書き込まれた
//! 部分だけが意味を持つことが多いため）。out スロットは値の完全一致。

#[cfg(windows)]
use std::collections::HashMap;

/// 読み戻すバッファ内容の上限（バイト）。これを超えた分は切り捨て、
/// `outputs_truncated` に引数名を載せる。
pub const MAX_CAPTURED_BUFFER: usize = 4096;

/// 1 引数の種類。呼び出し表が持つ、実行に必要な最小の型情報。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// 32 ビット整数。
    U32,
    /// 64 ビット整数。
    U64,
    /// 真理値（0 / 1）。
    Bool,
    /// UTF-16 文字列（NUL 終端）。
    WideStr,
    /// ANSI 文字列（NUL 終端）。将来の A 系 API 用。v1 の表では使わない。
    AnsiStr,
    /// ハンドル（`usize` 値）。
    Handle,
    /// 生ポインタ（NULL・生アドレス・バッファ・out スロットのいずれか）。
    Ptr,
    /// 入出力バッファ（ポインタを渡し、内容を読み戻す）。
    Bytes,
}

/// 呼び出し表の 1 引数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamDef {
    pub name: &'static str,
    pub kind: ParamKind,
}

/// 呼び出せる API 1 件の署名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSig {
    pub dll: &'static str,
    pub function: &'static str,
    pub params: &'static [ParamDef],
}

const P_U32: ParamKind = ParamKind::U32;
const P_HANDLE: ParamKind = ParamKind::Handle;
const P_PTR: ParamKind = ParamKind::Ptr;
const P_WSTR: ParamKind = ParamKind::WideStr;
const P_BYTES: ParamKind = ParamKind::Bytes;

/// Probe が実行できる API の呼び出し表（v1）。すべてフック定義表にも
/// 載る（＝記録される）API だけを載せる。引数の並びは Win32 の署名通り。
pub const CALL_TABLE: &[CallSig] = &[
    CallSig {
        dll: "kernel32.dll",
        function: "CreateFileW",
        params: &[
            ParamDef {
                name: "lpFileName",
                kind: P_WSTR,
            },
            ParamDef {
                name: "dwDesiredAccess",
                kind: P_U32,
            },
            ParamDef {
                name: "dwShareMode",
                kind: P_U32,
            },
            ParamDef {
                name: "lpSecurityAttributes",
                kind: P_PTR,
            },
            ParamDef {
                name: "dwCreationDisposition",
                kind: P_U32,
            },
            ParamDef {
                name: "dwFlagsAndAttributes",
                kind: P_U32,
            },
            ParamDef {
                name: "hTemplateFile",
                kind: P_HANDLE,
            },
        ],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "ReadFile",
        params: &[
            ParamDef {
                name: "hFile",
                kind: P_HANDLE,
            },
            ParamDef {
                name: "lpBuffer",
                kind: P_BYTES,
            },
            ParamDef {
                name: "nNumberOfBytesToRead",
                kind: P_U32,
            },
            ParamDef {
                name: "lpNumberOfBytesRead",
                kind: P_PTR,
            },
            ParamDef {
                name: "lpOverlapped",
                kind: P_PTR,
            },
        ],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "WriteFile",
        params: &[
            ParamDef {
                name: "hFile",
                kind: P_HANDLE,
            },
            ParamDef {
                name: "lpBuffer",
                kind: P_BYTES,
            },
            ParamDef {
                name: "nNumberOfBytesToWrite",
                kind: P_U32,
            },
            ParamDef {
                name: "lpNumberOfBytesWritten",
                kind: P_PTR,
            },
            ParamDef {
                name: "lpOverlapped",
                kind: P_PTR,
            },
        ],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "CloseHandle",
        params: &[ParamDef {
            name: "hObject",
            kind: P_HANDLE,
        }],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "GetFileSize",
        params: &[
            ParamDef {
                name: "hFile",
                kind: P_HANDLE,
            },
            ParamDef {
                name: "lpFileSizeHigh",
                kind: P_PTR,
            },
        ],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "DeleteFileW",
        params: &[ParamDef {
            name: "lpFileName",
            kind: P_WSTR,
        }],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "CreateDirectoryW",
        params: &[
            ParamDef {
                name: "lpPathName",
                kind: P_WSTR,
            },
            ParamDef {
                name: "lpSecurityAttributes",
                kind: P_PTR,
            },
        ],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "RemoveDirectoryW",
        params: &[ParamDef {
            name: "lpPathName",
            kind: P_WSTR,
        }],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "Sleep",
        params: &[ParamDef {
            name: "dwMilliseconds",
            kind: P_U32,
        }],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "FlushFileBuffers",
        params: &[ParamDef {
            name: "hFile",
            kind: P_HANDLE,
        }],
    },
    CallSig {
        dll: "kernel32.dll",
        function: "MoveFileW",
        params: &[
            ParamDef {
                name: "lpExistingFileName",
                kind: P_WSTR,
            },
            ParamDef {
                name: "lpNewFileName",
                kind: P_WSTR,
            },
        ],
    },
];

/// `"dll!Function"` 形式の呼び出し名を表から引く。DLL 名は
/// 大文字小文字と `.dll` の有無を吸収する（フック定義表と同じ規則）。
/// 関数名は `GetProcAddress` と同じく大文字小文字を区別する。
pub fn lookup_call(call: &str) -> Option<&'static CallSig> {
    let (dll, function) = call.split_once('!')?;
    CALL_TABLE
        .iter()
        .find(|sig| sig.function == function && dll_matches(sig.dll, dll))
}

fn dll_matches(table_dll: &str, spec_dll: &str) -> bool {
    strip_dll_suffix(table_dll).eq_ignore_ascii_case(strip_dll_suffix(spec_dll))
}

fn strip_dll_suffix(d: &str) -> &str {
    d.strip_suffix(".dll").unwrap_or(d)
}

/// 仕様の 1 引数の値。
#[derive(Debug, Clone, PartialEq)]
pub enum ArgValue {
    /// 整数リテラル。
    Int(u64),
    /// 先行ステップの `store` への参照（`"$name"`）。
    Ref(String),
    /// 文字列リテラル（WideStr / AnsiStr へ渡すか、Bytes の中身になる）。
    Text(String),
    /// NULL（0）。
    Null,
    /// 真理値。
    Bool(bool),
    /// サイズ指定のバッファ。`fill` は先頭に置く内容（残りは 0）。
    Buffer { size: usize, fill: Vec<u8> },
    /// u32 の out スロットへのポインタ。
    OutU32,
    /// u64 の out スロットへのポインタ。
    OutU64,
}

/// 戻り値への期待。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetExpect {
    /// A Win32 handle other than NULL or INVALID_HANDLE_VALUE.
    ValidHandle,
    NonZero,
    Zero,
    Equals(u64),
}

/// 1 つの出力（out スロット / バッファ）への期待。
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedOutput {
    /// out スロットの値の完全一致。
    U64(u64),
    /// バッファ内容の 16 進文字列との前方一致。
    HexPrefix(String),
}

/// 1 ステップへの期待（戻り値と出力の両方・片方）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Expect {
    pub ret: Option<RetExpect>,
    pub outputs: Vec<(String, ExpectedOutput)>,
}

/// Probe が実行する 1 ステップ（1 回の API 呼び出し）。
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    /// `"dll!Function"` 形式。
    pub call: String,
    /// 引数名 → 値（並びは仕様の記述順だが、呼び出し順は表が決める）。
    pub args: Vec<(String, ArgValue)>,
    /// 戻り値を保存する名前（後続ステップが `"$name"` で参照する）。
    pub store: Option<String>,
    /// 戻り値・出力への期待（無ければ実行だけして成否を見ない）。
    pub expect: Option<Expect>,
}

/// 計画済みの 1 呼び出し（引数は表の並びに整列済み）。
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedCall {
    pub dll: &'static str,
    pub function: &'static str,
    pub args: Vec<PlannedArg>,
    pub store: Option<String>,
    pub expect: Option<Expect>,
}

/// 計画済みの 1 引数。
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedArg {
    pub name: String,
    pub kind: ParamKind,
    pub value: ArgValue,
}

/// バッファ引数のサイズ上限。異常な確保を計画時に弾く。
pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// 名前（`store` / `$ref`）として許す形。ASCII の識別子。
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// ステップ列を計画する。呼び出し名・引数名・型の適合・`$ref` の解決・
/// `store` の重複・期待値の対象をすべてここで検証する。計画が通れば
/// 実行時に仕様の誤りで止まることはない（DLL/関数の不在と実行時の
/// 失敗だけが残る）。
pub fn plan_steps(steps: &[Step]) -> Result<Vec<PlannedCall>, String> {
    let mut planned = Vec::with_capacity(steps.len());
    let mut stored: Vec<String> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let sig = lookup_call(&step.call).ok_or_else(|| {
            format!(
                "step {i}: unknown call {:?} (not in the probe call table)",
                step.call
            )
        })?;
        if sig.function == "Sleep"
            && (step.store.is_some() || step.expect.as_ref().is_some_and(|e| e.ret.is_some()))
        {
            return Err(format!(
                "step {i}: Sleep returns void; store and return expectations are invalid"
            ));
        }
        if let Some(name) = &step.store {
            if !valid_name(name) {
                return Err(format!("step {i}: invalid store name {name:?}"));
            }
            if stored.iter().any(|n| n == name) {
                return Err(format!("step {i}: duplicate store name {name:?}"));
            }
        }
        // 引数の重複と未知の引数名を弾く。
        for (name, _) in &step.args {
            if step.args.iter().filter(|(n, _)| n == name).count() > 1 {
                return Err(format!("step {i}: duplicate argument {name:?}"));
            }
            if !sig.params.iter().any(|p| p.name == name) {
                return Err(format!(
                    "step {i}: unknown argument {name:?} for {}",
                    step.call
                ));
            }
        }
        let mut args = Vec::with_capacity(sig.params.len());
        for param in sig.params {
            let value = step
                .args
                .iter()
                .find(|(n, _)| n == param.name)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    format!(
                        "step {i}: missing argument {:?} for {}",
                        param.name, step.call
                    )
                })?;
            check_value_kind(i, param, &value, &stored)?;
            args.push(PlannedArg {
                name: param.name.to_string(),
                kind: param.kind,
                value,
            });
        }
        check_io_storage(sig.function, &args, None)?;
        if let Some(expect) = &step.expect {
            check_expect(i, expect, &args)?;
        }
        if let Some(name) = &step.store {
            stored.push(name.clone());
        }
        planned.push(PlannedCall {
            dll: sig.dll,
            function: sig.function,
            args,
            store: step.store.clone(),
            expect: step.expect.clone(),
        });
    }
    Ok(planned)
}

// Managed buffers live only for this call. The runner has no async completion
// owner, so it cannot safely lend them to an OVERLAPPED operation.
fn check_io_storage(
    function: &str,
    args: &[PlannedArg],
    resolved: Option<&[usize]>,
) -> Result<(), String> {
    if !matches!(function, "ReadFile" | "WriteFile") {
        return Ok(());
    }
    if !matches!(args[4].value, ArgValue::Null | ArgValue::Int(0)) {
        return Err("runner does not support asynchronous I/O: lpOverlapped must be null".into());
    }
    let capacity = match &args[1].value {
        ArgValue::Buffer { size, .. } => Some(*size as u64),
        ArgValue::Text(text) => Some(text.len() as u64),
        _ => None,
    };
    let requested = resolved
        .map(|values| values[2] as u64)
        .or(match args[2].value {
            ArgValue::Int(value) => Some(value),
            ArgValue::Null => Some(0),
            _ => None,
        });
    if let (Some(capacity), Some(requested)) = (capacity, requested) {
        if requested > capacity {
            return Err(format!(
                "{function} requests {requested} bytes from a {capacity}-byte buffer"
            ));
        }
    }
    if matches!(args[3].value, ArgValue::Buffer { size, .. } if size < 4) {
        return Err(format!(
            "{function} byte-count output needs at least 4 bytes"
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn checked_slot(value: u64, kind: ParamKind) -> Result<usize, String> {
    let maximum = match kind {
        ParamKind::U32 => u32::MAX as u64,
        ParamKind::Bool => 1,
        _ => usize::MAX as u64,
    };
    if value > maximum {
        return Err(format!(
            "value {value} does not fit {kind:?} on this target"
        ));
    }
    Ok(value as usize)
}

fn check_value_kind(
    i: usize,
    param: &ParamDef,
    value: &ArgValue,
    stored: &[String],
) -> Result<(), String> {
    let err = |why: &str| {
        format!(
            "step {i}: argument {:?} ({:?}) cannot be {why}",
            param.name, value
        )
    };
    match (param.kind, value) {
        (ParamKind::U32, ArgValue::Int(v)) if *v <= u32::MAX as u64 => Ok(()),
        (ParamKind::U64, ArgValue::Int(_)) => Ok(()),
        (ParamKind::Bool, ArgValue::Bool(_)) => Ok(()),
        (ParamKind::Bool, ArgValue::Int(v)) if *v <= 1 => Ok(()),
        (ParamKind::Handle, ArgValue::Int(_)) => Ok(()),
        (ParamKind::WideStr, ArgValue::Text(_)) => Ok(()),
        (ParamKind::AnsiStr, ArgValue::Text(_)) => Ok(()),
        (ParamKind::Ptr, ArgValue::Int(_)) => Ok(()),
        (ParamKind::Ptr, ArgValue::Buffer { size, fill }) => {
            check_buffer(i, param.name, *size, fill)?;
            Ok(())
        }
        (ParamKind::Ptr, ArgValue::OutU32) => Ok(()),
        (ParamKind::Ptr, ArgValue::OutU64) => Ok(()),
        (ParamKind::Bytes, ArgValue::Buffer { size, fill }) => {
            check_buffer(i, param.name, *size, fill)?;
            Ok(())
        }
        (ParamKind::Bytes, ArgValue::Text(_)) => Ok(()),
        (_, ArgValue::Null) => Ok(()),
        (_, ArgValue::Ref(name)) => {
            if !valid_name(name) {
                return Err(format!("step {i}: invalid reference ${name:?}"));
            }
            if !stored.iter().any(|n| n == name) {
                return Err(format!(
                    "step {i}: reference ${name:?} is not stored by an earlier step"
                ));
            }
            match param.kind {
                ParamKind::WideStr | ParamKind::AnsiStr | ParamKind::Bytes => {
                    Err(err("a stored value (a number, not a string)"))
                }
                _ => Ok(()),
            }
        }
        _ => Err(err("this kind of value")),
    }
}

fn check_buffer(i: usize, name: &str, size: usize, fill: &[u8]) -> Result<(), String> {
    if size > MAX_BUFFER_SIZE {
        return Err(format!(
            "step {i}: argument {name:?} buffer size {size} exceeds {MAX_BUFFER_SIZE}"
        ));
    }
    if fill.len() > size {
        return Err(format!(
            "step {i}: argument {name:?} fill ({} bytes) exceeds buffer size {size}",
            fill.len()
        ));
    }
    Ok(())
}

fn check_expect(i: usize, expect: &Expect, args: &[PlannedArg]) -> Result<(), String> {
    for (name, expected) in &expect.outputs {
        let arg = args
            .iter()
            .find(|a| &a.name == name)
            .ok_or_else(|| format!("step {i}: expect.outputs has unknown argument {name:?}"))?;
        match (&arg.value, expected) {
            (ArgValue::Buffer { .. }, ExpectedOutput::HexPrefix(_)) => {}
            (ArgValue::OutU32, ExpectedOutput::U64(_)) => {}
            (ArgValue::OutU64, ExpectedOutput::U64(_)) => {}
            (ArgValue::Buffer { .. }, ExpectedOutput::U64(_)) => {
                return Err(format!(
                    "step {i}: expect.outputs {name:?} is a buffer; expected value must be a hex string"
                ));
            }
            _ => {
                return Err(format!(
                    "step {i}: expect.outputs {name:?} is not a buffer/out argument"
                ));
            }
        }
    }
    Ok(())
}

/// 1 ステップの実行結果。
#[derive(Debug, Clone, PartialEq)]
pub struct StepOutcome {
    pub index: usize,
    pub call: String,
    /// 期待も含めて成功したか。dry-run では常に true。
    pub ok: bool,
    /// 実際に呼び出したか（dry-run では false）。
    pub executed: bool,
    /// 戻り値（実行時のみ）。
    pub returned: Option<u64>,
    /// 呼び出し直後の `GetLastError`（実行時のみ）。
    pub last_error: Option<u32>,
    /// 読み戻した出力（out スロット / バッファ）。
    pub outputs: Vec<(String, OutputValue)>,
    /// 上限で切り捨てたバッファ引数の名前。
    pub outputs_truncated: Vec<String>,
    /// 失敗・中断の理由（成功時は None）。
    pub error: Option<String>,
}

/// 読み戻した出力値。
#[derive(Debug, Clone, PartialEq)]
pub enum OutputValue {
    U64(u64),
    /// バッファ内容の 16 進文字列（上限で切った場合は先頭部分）。
    Hex(String),
}

/// Identity reported by the running executable/API, not OS attestation. A
/// compatibility implementation can report a Windows version too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEnvironment {
    pub target_os: String,
    pub process_arch: String,
    pub pointer_width: u32,
    pub windows_version: Option<String>,
    pub windows_build: Option<u32>,
    pub version_source: Option<String>,
}

pub fn environment_to_json(env: &RunEnvironment) -> String {
    format!("{{\"target_os\":{},\"process_arch\":{},\"pointer_width\":{},\"windows_version\":{},\"windows_build\":{},\"version_source\":{}}}",
        json_string(&env.target_os), json_string(&env.process_arch), env.pointer_width,
        env.windows_version.as_ref().map(|v| json_string(v)).unwrap_or_else(|| "null".into()),
        env.windows_build.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
        env.version_source.as_ref().map(|v| json_string(v)).unwrap_or_else(|| "null".into()))
}

#[cfg(windows)]
fn execution_environment() -> RunEnvironment {
    #[repr(C)]
    struct OsVersion {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }
    let mut env = RunEnvironment {
        target_os: std::env::consts::OS.into(),
        process_arch: std::env::consts::ARCH.into(),
        pointer_width: usize::BITS,
        windows_version: None,
        windows_build: None,
        version_source: None,
    };
    let name: Vec<u16> = "ntdll.dll".encode_utf16().chain([0]).collect();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module != 0 {
        let address = unsafe { GetProcAddress(module, c"RtlGetVersion".as_ptr().cast()) };
        if address != 0 {
            let query: unsafe extern "system" fn(*mut OsVersion) -> i32 =
                unsafe { std::mem::transmute(address) };
            let mut version = OsVersion {
                size: std::mem::size_of::<OsVersion>() as u32,
                major: 0,
                minor: 0,
                build: 0,
                platform: 0,
                service_pack: [0; 128],
            };
            if unsafe { query(&mut version) } == 0 {
                env.windows_version = Some(format!(
                    "{}.{}.{}",
                    version.major, version.minor, version.build
                ));
                env.windows_build = Some(version.build);
                env.version_source = Some("RtlGetVersion".into());
            }
        }
    }
    env
}

/// 実行（または dry-run）の報告全体。
#[derive(Debug, Clone, PartialEq)]
pub struct RunReportData {
    pub environment: Option<RunEnvironment>,
    pub spec_name: String,
    pub executed: bool,
    pub all_ok: bool,
    pub steps: Vec<StepOutcome>,
}

/// 計画だけを行い、実行しない dry-run の報告を作る。
pub fn dry_run_report(spec_name: &str, planned: &[PlannedCall]) -> RunReportData {
    RunReportData {
        spec_name: spec_name.to_string(),
        executed: false,
        environment: None,
        all_ok: true,
        steps: planned
            .iter()
            .enumerate()
            .map(|(index, call)| StepOutcome {
                index,
                call: format!("{}!{}", call.dll.trim_end_matches(".dll"), call.function),
                ok: true,
                executed: false,
                returned: None,
                last_error: None,
                outputs: Vec::new(),
                outputs_truncated: Vec::new(),
                error: None,
            })
            .collect(),
    }
}

/// 報告を JSON 文字列にする（生成 exe 用の `std` のみの描画）。
/// `runner.rs` の `JsonValue` による描画と形を一致させること。
/// 両者の一致は `runner` のテストで確かめる。
pub fn report_to_json(report: &RunReportData) -> String {
    let mut out = String::new();
    out.push_str("{\"spec\":");
    out.push_str(&json_string(&report.spec_name));
    out.push_str(",\"executed\":");
    out.push_str(if report.executed { "true" } else { "false" });
    out.push_str(",\"all_ok\":");
    out.push_str(if report.all_ok { "true" } else { "false" });
    out.push_str(",\"steps\":[");
    for (i, step) in report.steps.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"index\":");
        out.push_str(&step.index.to_string());
        out.push_str(",\"call\":");
        out.push_str(&json_string(&step.call));
        out.push_str(",\"ok\":");
        out.push_str(if step.ok { "true" } else { "false" });
        out.push_str(",\"executed\":");
        out.push_str(if step.executed { "true" } else { "false" });
        out.push_str(",\"returned\":");
        match step.returned {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"last_error\":");
        match step.last_error {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"outputs\":{");
        for (j, (name, value)) in step.outputs.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&json_string(name));
            out.push(':');
            match value {
                OutputValue::U64(v) => out.push_str(&v.to_string()),
                OutputValue::Hex(h) => out.push_str(&json_string(h)),
            }
        }
        out.push_str("},\"outputs_truncated\":[");
        for (j, name) in step.outputs_truncated.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&json_string(name));
        }
        out.push_str("],\"error\":");
        match &step.error {
            Some(e) => out.push_str(&json_string(e)),
            None => out.push_str("null"),
        }
        out.push('}');
    }
    out.push(']');
    if let Some(env) = &report.environment {
        out.push_str(",\"environment\":");
        out.push_str(&environment_to_json(env));
    }
    out.push('}');
    out
}

/// 報告を人間向けの 1 行ごとの表示にする。
pub fn report_to_text(report: &RunReportData) -> String {
    let mut out = String::new();
    let mode = if report.executed {
        "実行済み"
    } else {
        "dry-run（実行しない）"
    };
    let verdict = if report.all_ok {
        "すべて成功"
    } else {
        "失敗あり"
    };
    out.push_str(&format!(
        "probe {:?}: 全 {} 件・{}・{}\n",
        report.spec_name,
        report.steps.len(),
        mode,
        verdict
    ));
    for step in &report.steps {
        let status = if !step.executed {
            "計画のみ".to_string()
        } else if step.ok {
            "OK".to_string()
        } else {
            "FAIL".to_string()
        };
        let mut line = format!("  [{}] {} {}", step.index, step.call, status);
        if let Some(v) = step.returned {
            line.push_str(&format!(" 返り値 {v}"));
        }
        if let Some(e) = step.last_error {
            line.push_str(&format!(" last_error={e}"));
        }
        if let Some(e) = &step.error {
            line.push_str(&format!(" {e}"));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// 計画を人間向けの 1 行ごとの表示にする（dry-run の詳細）。
pub fn plan_to_text(spec_name: &str, planned: &[PlannedCall]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "probe {:?}: 全 {} 件・dry-run（実行しない）\n",
        spec_name,
        planned.len()
    ));
    for (i, call) in planned.iter().enumerate() {
        let args: Vec<String> = call
            .args
            .iter()
            .map(|a| format!("{}: {:?}", a.name, a.kind))
            .collect();
        let mut line = format!(
            "  [{}] {}!{}({})",
            i,
            call.dll.trim_end_matches(".dll"),
            call.function,
            args.join(", ")
        );
        if let Some(name) = &call.store {
            line.push_str(&format!(" → 保存 {name}"));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// Windows でのみ使う（`execute_one` の読み戻し）。Linux ビルドでは
// テストだけが使うため、未使用警告を抑える。
#[cfg_attr(not(windows), allow(dead_code))]
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub(crate) fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Windows での実行
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(lp_lib_file_name: *const u16) -> usize;
    fn GetModuleHandleW(lp_module_name: *const u16) -> usize;
    fn GetProcAddress(h_module: usize, lp_proc_name: *const u8) -> usize;
    fn GetLastError() -> u32;
}

/// Invoke only the supported signatures, preserving pointer widths, DWORD,
/// BOOL and void returns. None means an unsupported signature; Some(None)
/// is a successful void call, with no invented return value.
#[cfg(any(windows, test))]
unsafe fn call_raw(addr: usize, function: &str, args: &[usize]) -> Option<Option<u64>> {
    match (function, args) {
        ("CreateFileW", [a0, a1, a2, a3, a4, a5, a6]) => {
            let f: unsafe extern "system" fn(
                *const u16,
                u32,
                u32,
                *mut std::ffi::c_void,
                u32,
                u32,
                *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void = unsafe { std::mem::transmute(addr) };
            let value = unsafe {
                f(
                    *a0 as *const u16,
                    *a1 as u32,
                    *a2 as u32,
                    *a3 as *mut std::ffi::c_void,
                    *a4 as u32,
                    *a5 as u32,
                    *a6 as *mut std::ffi::c_void,
                )
            };
            Some(Some(value as usize as u64))
        }
        ("ReadFile", [a0, a1, a2, a3, a4]) => {
            let f: unsafe extern "system" fn(
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                u32,
                *mut u32,
                *mut std::ffi::c_void,
            ) -> i32 = unsafe { std::mem::transmute(addr) };
            let value = unsafe {
                f(
                    *a0 as *mut std::ffi::c_void,
                    *a1 as *mut std::ffi::c_void,
                    *a2 as u32,
                    *a3 as *mut u32,
                    *a4 as *mut std::ffi::c_void,
                )
            };
            Some(Some(value as u32 as u64))
        }
        ("WriteFile", [a0, a1, a2, a3, a4]) => {
            let f: unsafe extern "system" fn(
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
                u32,
                *mut u32,
                *mut std::ffi::c_void,
            ) -> i32 = unsafe { std::mem::transmute(addr) };
            let value = unsafe {
                f(
                    *a0 as *mut std::ffi::c_void,
                    *a1 as *const std::ffi::c_void,
                    *a2 as u32,
                    *a3 as *mut u32,
                    *a4 as *mut std::ffi::c_void,
                )
            };
            Some(Some(value as u32 as u64))
        }
        ("CloseHandle", [a0]) => {
            let f: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *mut std::ffi::c_void) };
            Some(Some(value as u32 as u64))
        }
        ("GetFileSize", [a0, a1]) => {
            let f: unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> u32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *mut std::ffi::c_void, *a1 as *mut u32) };
            Some(Some(value as u64))
        }
        ("DeleteFileW", [a0]) => {
            let f: unsafe extern "system" fn(*const u16) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *const u16) };
            Some(Some(value as u32 as u64))
        }
        ("CreateDirectoryW", [a0, a1]) => {
            let f: unsafe extern "system" fn(*const u16, *mut std::ffi::c_void) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *const u16, *a1 as *mut std::ffi::c_void) };
            Some(Some(value as u32 as u64))
        }
        ("RemoveDirectoryW", [a0]) => {
            let f: unsafe extern "system" fn(*const u16) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *const u16) };
            Some(Some(value as u32 as u64))
        }
        ("Sleep", [a0]) => {
            let f: unsafe extern "system" fn(u32) -> () = unsafe { std::mem::transmute(addr) };
            unsafe { f(*a0 as u32) };
            Some(None)
        }
        ("FlushFileBuffers", [a0]) => {
            let f: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *mut std::ffi::c_void) };
            Some(Some(value as u32 as u64))
        }
        ("MoveFileW", [a0, a1]) => {
            let f: unsafe extern "system" fn(*const u16, *const u16) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let value = unsafe { f(*a0 as *const u16, *a1 as *const u16) };
            Some(Some(value as u32 as u64))
        }
        _ => None,
    }
}

/// 呼び出し中に生きていなければならない実体（文字列・バッファ・
/// out スロット）をまとめて保持する。
#[cfg(windows)]
struct LiveStorage {
    wide: Vec<Vec<u16>>,
    narrow: Vec<Vec<u8>>,
    bufs: Vec<Vec<u8>>,
    out32: Vec<u32>,
    out64: Vec<u64>,
}

#[cfg(windows)]
enum ReadBack {
    OutU32(usize),
    OutU64(usize),
    Buffer(usize),
}

/// 呼び出しに渡す値。out スロットのポインタは、実体（`Vec<u32>` 等）の
/// 再配置が終わった後でないと決められないため、スロット番号だけを
/// 持っておき、呼び出し直前に解決する。
#[cfg(windows)]
enum ArgSlot {
    Immediate(usize),
    OutU32(usize),
    OutU64(usize),
}

#[cfg(windows)]
struct LiveArg {
    name: String,
    slot: ArgSlot,
    read_back: Option<ReadBack>,
}

/// 計画済みの呼び出し列を Windows で実際に実行する。最初の失敗で
/// 止まり、残りのステップは `executed: false`・`error` 付きで報告する
/// （後続は先行の `store` に依存することが多いため）。
#[cfg(windows)]
pub fn execute_planned(spec_name: &str, planned: &[PlannedCall]) -> RunReportData {
    let mut outcomes = Vec::with_capacity(planned.len());
    let mut stored: HashMap<String, u64> = HashMap::new();
    let mut modules: HashMap<&'static str, usize> = HashMap::new();
    let mut all_ok = true;
    let mut stopped = false;
    for (index, call) in planned.iter().enumerate() {
        if stopped {
            outcomes.push(StepOutcome {
                index,
                call: format!("{}!{}", call.dll.trim_end_matches(".dll"), call.function),
                ok: false,
                executed: false,
                returned: None,
                last_error: None,
                outputs: Vec::new(),
                outputs_truncated: Vec::new(),
                error: Some("skipped: an earlier step failed".to_string()),
            });
            continue;
        }
        let outcome = execute_one(index, call, &mut modules, &mut stored);
        if !outcome.ok {
            all_ok = false;
            stopped = true;
        }
        outcomes.push(outcome);
    }
    RunReportData {
        spec_name: spec_name.to_string(),
        executed: true,
        environment: Some(execution_environment()),
        all_ok,
        steps: outcomes,
    }
}

#[cfg(windows)]
fn execute_one(
    index: usize,
    call: &PlannedCall,
    modules: &mut HashMap<&'static str, usize>,
    stored: &mut HashMap<String, u64>,
) -> StepOutcome {
    let call_name = format!("{}!{}", call.dll.trim_end_matches(".dll"), call.function);
    let fail = |error: String| StepOutcome {
        index,
        call: call_name.clone(),
        ok: false,
        executed: false,
        returned: None,
        last_error: None,
        outputs: Vec::new(),
        outputs_truncated: Vec::new(),
        error: Some(error),
    };
    let module = match load_module(call.dll, modules) {
        Ok(h) => h,
        Err(e) => return fail(e),
    };
    let addr = unsafe {
        let mut name = call.function.as_bytes().to_vec();
        name.push(0);
        GetProcAddress(module, name.as_ptr())
    };
    if addr == 0 {
        return fail(format!("GetProcAddress failed for {}", call.function));
    }
    let mut storage = LiveStorage {
        wide: Vec::new(),
        narrow: Vec::new(),
        bufs: Vec::new(),
        out32: Vec::new(),
        out64: Vec::new(),
    };
    let mut live: Vec<LiveArg> = Vec::with_capacity(call.args.len());
    for arg in &call.args {
        match materialize(arg, stored, &mut storage) {
            Ok(a) => live.push(a),
            Err(e) => return fail(e),
        }
    }
    // out スロットのポインタは、実体の再配置が終わった今決める。
    let values: Vec<usize> = live
        .iter()
        .map(|a| match a.slot {
            ArgSlot::Immediate(v) => v,
            ArgSlot::OutU32(slot) => storage.out32.as_ptr() as usize + slot * 4,
            ArgSlot::OutU64(slot) => storage.out64.as_ptr() as usize + slot * 8,
        })
        .collect();
    if let Err(error) = check_io_storage(call.function, &call.args, Some(&values)) {
        return fail(error);
    }
    let Some(returned) = (unsafe { call_raw(addr, call.function, &values) }) else {
        return fail(format!("unsupported call signature: {}", call.function));
    };
    let last_error = unsafe { GetLastError() };
    let mut outputs = Vec::new();
    let mut outputs_truncated = Vec::new();
    for arg in &live {
        match &arg.read_back {
            Some(ReadBack::OutU32(slot)) => {
                outputs.push((
                    arg.name.clone(),
                    OutputValue::U64(storage.out32[*slot] as u64),
                ));
            }
            Some(ReadBack::OutU64(slot)) => {
                outputs.push((arg.name.clone(), OutputValue::U64(storage.out64[*slot])));
            }
            Some(ReadBack::Buffer(slot)) => {
                let buf = &storage.bufs[*slot];
                if buf.len() > MAX_CAPTURED_BUFFER {
                    outputs_truncated.push(arg.name.clone());
                }
                let shown = &buf[..buf.len().min(MAX_CAPTURED_BUFFER)];
                outputs.push((arg.name.clone(), OutputValue::Hex(to_hex(shown))));
            }
            None => {}
        }
    }
    if let (Some(name), Some(value)) = (&call.store, returned) {
        stored.insert(name.clone(), value);
    }
    let mut error = None;
    if let Some(expect) = &call.expect {
        if let Some(ret) = expect.ret {
            let ok = match ret {
                RetExpect::ValidHandle => {
                    returned.is_some_and(|v| v != 0 && v != usize::MAX as u64)
                }
                RetExpect::NonZero => returned.is_some_and(|v| v != 0),
                RetExpect::Zero => returned == Some(0),
                RetExpect::Equals(v) => returned == Some(v),
            };
            if !ok {
                error = Some(format!(
                    "return value {returned:?} does not satisfy expect {ret:?}"
                ));
            }
        }
        if error.is_none() {
            for (name, expected) in &expect.outputs {
                let got = outputs.iter().find(|(n, _)| n == name);
                let ok = match (got, expected) {
                    (Some((_, OutputValue::U64(v))), ExpectedOutput::U64(w)) => v == w,
                    (Some((_, OutputValue::Hex(h))), ExpectedOutput::HexPrefix(prefix)) => {
                        h.starts_with(&prefix.to_ascii_lowercase())
                    }
                    _ => false,
                };
                if !ok {
                    error = Some(format!(
                        "output {name:?} does not satisfy expect {expected:?}"
                    ));
                    break;
                }
            }
        }
    }
    StepOutcome {
        index,
        call: call_name,
        ok: error.is_none(),
        executed: true,
        returned,
        last_error: Some(last_error),
        outputs,
        outputs_truncated,
        error,
    }
}

#[cfg(windows)]
fn load_module(
    dll: &'static str,
    cache: &mut HashMap<&'static str, usize>,
) -> Result<usize, String> {
    if let Some(&h) = cache.get(dll) {
        return Ok(h);
    }
    let wide: Vec<u16> = dll.encode_utf16().chain([0]).collect();
    let h = unsafe { LoadLibraryW(wide.as_ptr()) };
    if h == 0 {
        return Err(format!("LoadLibraryW failed for {dll}"));
    }
    cache.insert(dll, h);
    Ok(h)
}

#[cfg(windows)]
fn materialize(
    arg: &PlannedArg,
    stored: &HashMap<String, u64>,
    storage: &mut LiveStorage,
) -> Result<LiveArg, String> {
    let name = arg.name.clone();
    let immediate = |value| LiveArg {
        name: name.clone(),
        slot: ArgSlot::Immediate(value),
        read_back: None,
    };
    match (&arg.kind, &arg.value) {
        (ParamKind::WideStr, ArgValue::Text(s)) => {
            let wide: Vec<u16> = s.encode_utf16().chain([0]).collect();
            let value = wide.as_ptr() as usize;
            storage.wide.push(wide);
            Ok(immediate(value))
        }
        (ParamKind::AnsiStr, ArgValue::Text(s)) => {
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            let value = bytes.as_ptr() as usize;
            storage.narrow.push(bytes);
            Ok(immediate(value))
        }
        (ParamKind::Bytes, ArgValue::Buffer { size, fill }) => {
            let mut buf = vec![0u8; *size];
            buf[..fill.len()].copy_from_slice(fill);
            let value = buf.as_ptr() as usize;
            storage.bufs.push(buf);
            let slot = storage.bufs.len() - 1;
            Ok(LiveArg {
                name,
                slot: ArgSlot::Immediate(value),
                read_back: Some(ReadBack::Buffer(slot)),
            })
        }
        (ParamKind::Bytes, ArgValue::Text(s)) => {
            let buf = s.as_bytes().to_vec();
            let value = buf.as_ptr() as usize;
            storage.bufs.push(buf);
            let slot = storage.bufs.len() - 1;
            Ok(LiveArg {
                name,
                slot: ArgSlot::Immediate(value),
                read_back: Some(ReadBack::Buffer(slot)),
            })
        }
        (ParamKind::Ptr, ArgValue::Buffer { size, fill }) => {
            let mut buf = vec![0u8; *size];
            buf[..fill.len()].copy_from_slice(fill);
            let value = buf.as_ptr() as usize;
            storage.bufs.push(buf);
            let slot = storage.bufs.len() - 1;
            Ok(LiveArg {
                name,
                slot: ArgSlot::Immediate(value),
                read_back: Some(ReadBack::Buffer(slot)),
            })
        }
        (ParamKind::Ptr, ArgValue::OutU32) => {
            storage.out32.push(0);
            let slot = storage.out32.len() - 1;
            Ok(LiveArg {
                name,
                slot: ArgSlot::OutU32(slot),
                read_back: Some(ReadBack::OutU32(slot)),
            })
        }
        (ParamKind::Ptr, ArgValue::OutU64) => {
            storage.out64.push(0);
            let slot = storage.out64.len() - 1;
            Ok(LiveArg {
                name,
                slot: ArgSlot::OutU64(slot),
                read_back: Some(ReadBack::OutU64(slot)),
            })
        }
        (_, ArgValue::Null) => Ok(immediate(0)),
        (_, ArgValue::Int(v)) => Ok(immediate(checked_slot(*v, arg.kind)?)),
        (_, ArgValue::Bool(b)) => Ok(immediate(if *b { 1 } else { 0 })),
        (_, ArgValue::Ref(r)) => match stored.get(r) {
            Some(v) => Ok(immediate(checked_slot(*v, arg.kind)?)),
            None => Err(format!(
                "reference ${r:?} is not stored (plan should have caught this)"
            )),
        },
        _ => Err(format!(
            "argument {:?} cannot be materialized from {:?}",
            arg.name, arg.value
        )),
    }
}

/// Windows 以外での実行。生成 exe は Windows 向けにだけビルドされるが、
/// 関数としては全体を返す（呼び出し側が先に誤りを返すのが本筋）。
#[cfg(not(windows))]
pub fn execute_planned(spec_name: &str, planned: &[PlannedCall]) -> RunReportData {
    RunReportData {
        spec_name: spec_name.to_string(),
        executed: false,
        environment: None,
        all_ok: false,
        steps: planned
            .iter()
            .enumerate()
            .map(|(index, call)| StepOutcome {
                index,
                call: format!("{}!{}", call.dll.trim_end_matches(".dll"), call.function),
                ok: false,
                executed: false,
                returned: None,
                last_error: None,
                outputs: Vec::new(),
                outputs_truncated: Vec::new(),
                error: Some("executing steps requires Windows".to_string()),
            })
            .collect(),
    }
}

/// 生成 exe の `main` から呼ぶ。仕様名とステップ列を受け取り、計画・
/// 実行・報告（stdout に JSON、stderr に人間向け表示）を行って
/// 終了コードを返す。0 = すべて成功、1 = 失敗あり、2 = 計画の誤り。
pub fn run_embedded(spec_name: &str, steps: &[Step]) -> i32 {
    match plan_steps(steps) {
        Err(e) => {
            eprintln!("probe error: {e}");
            2
        }
        Ok(planned) => {
            let report = execute_planned(spec_name, &planned);
            println!("{}", report_to_json(&report));
            eprint!("{}", report_to_text(&report));
            if report.all_ok {
                0
            } else {
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_dispatch_preserves_void_and_32_bit_results() {
        unsafe extern "system" fn sleep(_: u32) {}
        unsafe extern "system" fn close(_: *mut std::ffi::c_void) -> i32 {
            -1
        }
        unsafe {
            assert_eq!(
                call_raw(sleep as *const () as usize, "Sleep", &[0]),
                Some(None)
            );
            assert_eq!(
                call_raw(close as *const () as usize, "CloseHandle", &[0]),
                Some(Some(u32::MAX as u64))
            );
            assert_eq!(call_raw(0, "Sleep", &[]), None);
            assert_eq!(call_raw(0, "Unsupported", &[]), None);
        }
    }

    fn file_flow() -> Vec<Step> {
        vec![
            Step {
                call: "kernel32!CreateFileW".to_string(),
                args: vec![
                    (
                        "lpFileName".to_string(),
                        ArgValue::Text("probe.txt".to_string()),
                    ),
                    ("dwDesiredAccess".to_string(), ArgValue::Int(0xC0000000)),
                    ("dwShareMode".to_string(), ArgValue::Int(0)),
                    ("lpSecurityAttributes".to_string(), ArgValue::Null),
                    ("dwCreationDisposition".to_string(), ArgValue::Int(2)),
                    ("dwFlagsAndAttributes".to_string(), ArgValue::Int(128)),
                    ("hTemplateFile".to_string(), ArgValue::Null),
                ],
                store: Some("hFile".to_string()),
                expect: Some(Expect {
                    ret: Some(RetExpect::NonZero),
                    outputs: vec![],
                }),
            },
            Step {
                call: "kernel32!WriteFile".to_string(),
                args: vec![
                    ("hFile".to_string(), ArgValue::Ref("hFile".to_string())),
                    (
                        "lpBuffer".to_string(),
                        ArgValue::Buffer {
                            size: 5,
                            fill: b"hello".to_vec(),
                        },
                    ),
                    ("nNumberOfBytesToWrite".to_string(), ArgValue::Int(5)),
                    ("lpNumberOfBytesWritten".to_string(), ArgValue::OutU32),
                    ("lpOverlapped".to_string(), ArgValue::Null),
                ],
                store: None,
                expect: Some(Expect {
                    ret: Some(RetExpect::NonZero),
                    outputs: vec![("lpNumberOfBytesWritten".to_string(), ExpectedOutput::U64(5))],
                }),
            },
            Step {
                call: "kernel32!CloseHandle".to_string(),
                args: vec![("hObject".to_string(), ArgValue::Ref("hFile".to_string()))],
                store: None,
                expect: None,
            },
        ]
    }

    #[test]
    fn lookup_is_case_insensitive_on_dll() {
        assert!(lookup_call("kernel32!CreateFileW").is_some());
        assert!(lookup_call("KERNEL32!CreateFileW").is_some());
        assert!(lookup_call("kernel32.dll!CreateFileW").is_some());
        assert!(lookup_call("kernel32!createfilew").is_none());
        assert!(lookup_call("kernel32!NoSuchApi").is_none());
        assert!(lookup_call("CreateFileW").is_none());
    }

    #[test]
    fn plans_file_flow() {
        let planned = plan_steps(&file_flow()).unwrap();
        assert_eq!(planned.len(), 3);
        assert_eq!(planned[0].args.len(), 7);
        assert_eq!(planned[0].args[0].name, "lpFileName");
        assert_eq!(planned[0].args[0].kind, ParamKind::WideStr);
        assert_eq!(planned[0].store.as_deref(), Some("hFile"));
        assert_eq!(planned[1].args[1].kind, ParamKind::Bytes);
        assert_eq!(planned[2].args[0].kind, ParamKind::Handle);
    }

    #[test]
    fn rejects_io_that_outlives_or_exceeds_managed_storage() {
        let mut steps = file_flow();
        steps[1].args[2].1 = ArgValue::Int(MAX_BUFFER_SIZE as u64);
        assert!(plan_steps(&steps).unwrap_err().contains("buffer"));
        let mut steps = file_flow();
        steps[1].args[4].1 = ArgValue::Buffer {
            size: 32,
            fill: vec![],
        };
        assert!(plan_steps(&steps).unwrap_err().contains("asynchronous"));
        let mut calls = plan_steps(&file_flow()).unwrap();
        calls[1].args[2].value = ArgValue::Ref("hFile".into());
        assert!(check_io_storage(
            calls[1].function,
            &calls[1].args,
            Some(&[0, 0, MAX_BUFFER_SIZE, 0, 0])
        )
        .is_err());
        assert!(checked_slot(u32::MAX as u64 + 1, ParamKind::U32).is_err());
        assert!(checked_slot(2, ParamKind::Bool).is_err());
        assert_eq!(
            checked_slot(u32::MAX as u64, ParamKind::U32).unwrap(),
            u32::MAX as usize
        );
    }

    #[test]
    fn plan_rejects_unknown_call_arg_and_ref() {
        let mut bad = file_flow();
        bad[0].call = "kernel32!NoSuchApi".to_string();
        assert!(plan_steps(&bad).is_err());
        let mut bad = file_flow();
        bad[0].args.push(("nope".to_string(), ArgValue::Int(0)));
        assert!(plan_steps(&bad).is_err());
        let mut bad = file_flow();
        bad[0].args.retain(|(n, _)| n != "dwShareMode");
        assert!(plan_steps(&bad).is_err());
        let mut bad = file_flow();
        bad[1].args[0].1 = ArgValue::Ref("missing".to_string());
        assert!(plan_steps(&bad).is_err());
        let mut bad = file_flow();
        bad[2].store = Some("hFile".to_string());
        assert!(plan_steps(&bad).is_err());
    }

    #[test]
    fn plan_rejects_wrong_value_kinds() {
        // 整数引数に文字列は渡せない。
        let mut bad = file_flow();
        bad[0].args[1].1 = ArgValue::Text("x".to_string());
        assert!(plan_steps(&bad).is_err());
        // U32 に収まらない整数。
        let mut bad = file_flow();
        bad[0].args[1].1 = ArgValue::Int(u32::MAX as u64 + 1);
        assert!(plan_steps(&bad).is_err());
        // 文字列引数に $ref は渡せない（保存されるのは数値のため）。
        let mut bad = file_flow();
        bad[0].args[0].1 = ArgValue::Ref("hFile".to_string());
        assert!(plan_steps(&bad).is_err());
        // バッファの fill が size を超える。
        let mut bad = file_flow();
        bad[1].args[1].1 = ArgValue::Buffer {
            size: 2,
            fill: b"hello".to_vec(),
        };
        assert!(plan_steps(&bad).is_err());
        // expect.outputs がバッファ/out 以外の引数を指す。
        let mut bad = file_flow();
        bad[1].expect = Some(Expect {
            ret: None,
            outputs: vec![("hFile".to_string(), ExpectedOutput::U64(1))],
        });
        assert!(plan_steps(&bad).is_err());
        // expect.outputs の値の形が引数と合わない。
        let mut bad = file_flow();
        bad[1].expect = Some(Expect {
            ret: None,
            outputs: vec![(
                "lpNumberOfBytesWritten".to_string(),
                ExpectedOutput::HexPrefix("00".to_string()),
            )],
        });
        assert!(plan_steps(&bad).is_err());
    }

    #[test]
    fn dry_run_report_renders() {
        let planned = plan_steps(&file_flow()).unwrap();
        let report = dry_run_report("sample", &planned);
        assert!(!report.executed);
        assert!(report.all_ok);
        assert_eq!(report.steps.len(), 3);
        assert!(report.steps.iter().all(|s| !s.executed && s.ok));
        let json = report_to_json(&report);
        assert!(json.contains("\"spec\":\"sample\""));
        assert!(json.contains("\"executed\":false"));
        assert!(json.contains("kernel32!CreateFileW"));
        let text = report_to_text(&report);
        assert!(text.contains("dry-run"));
        let plan = plan_to_text("sample", &planned);
        assert!(plan.contains("lpFileName: WideStr"));
        assert!(plan.contains("保存 hFile"));
    }

    #[test]
    fn json_string_escapes() {
        assert_eq!(json_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(to_hex(b"hello"), "68656c6c6f");
        assert_eq!(hex_to_bytes("68656c6c6f"), Some(b"hello".to_vec()));
        assert_eq!(hex_to_bytes("zz"), None);
        assert_eq!(hex_to_bytes("abc"), None);
    }

    #[test]
    fn valid_name_rules() {
        assert!(valid_name("hFile"));
        assert!(valid_name("_x1"));
        assert!(!valid_name(""));
        assert!(!valid_name("1x"));
        assert!(!valid_name("a-b"));
        assert!(!valid_name("a b"));
    }
}
