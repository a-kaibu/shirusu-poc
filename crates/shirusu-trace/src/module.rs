//! モジュール分類（L07、overview「記録境界とモジュール分類」節）。
//!
//! モジュールを名前ではなく 4 分類（Windows / Runtime / Application /
//! Unknown）で扱う。判定理由を Trace に残し、CLI からモジュール単位で
//! 分類を上書きできる。API Set は契約名のため、論理名と実際に実行された
//! 実装モジュールの両方を記録する。出所を確定できないものは Unknown と
//! し、Application として観測したうえで分類が不確実であることを残す。
//!
//! 分類の優先順位（上から先に当たったものを採用する）：
//! 1. パスが空・特定できない → Unknown。
//! 2. API Set 契約名（`api-ms-win-*` / `ext-ms-win-*`）→ 実装モジュール
//!    が解決できればその分類、解決できなければ Unknown。
//! 3. 既知の実行基盤モジュール（VC++ Runtime / CLR / UCRT 等）→ Runtime。
//!    実行基盤であることはモジュール固有の性質のため、配置＋署名の
//!    Windows 判定より先に見る（これらは通常 System32 にあり Microsoft
//!    署名付きだが、Runtime としての扱いが先。`fopen` 経由の
//!    `CreateFileW` が記録されるのはこのため）。
//! 4. System32 / SysWOW64 / WinSxS にあり Microsoft 署名を確認できる
//!    → Windows。KnownDLLs は System32 への解決、SxS は WinSxS への
//!    配置として同じ扱い。
//! 5. システム配置だが署名が未確認 → Unknown（不確実として残す）。
//! 6. それ以外（EXE、同梱 DLL、サードパーティ製 DLL）→ Application。
//!
//! 署名の確認そのものは Windows 側の仕事（WinVerifyTrust 等）で、ここ
//! では `microsoft_signed: Some(true)` という証拠を受け取るだけである。
//! ロード済みモジュールの列挙と署名検証、フック時の呼び出し元分類は
//! Windows 側の残作業として L23 で扱う。

use crate::error::ProtoError;
use crate::proto::{ProtoReader, ProtoWriter, WIRE_LEN, WIRE_VARINT};

/// モジュールの 4 分類（overview「記録境界とモジュール分類」節）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ModuleClass {
    Windows = 1,
    Runtime = 2,
    Application = 3,
    #[default]
    Unknown = 4,
}

impl ModuleClass {
    /// Protobuf へ書く数値（1=windows 2=runtime 3=application 4=unknown）。
    pub fn code(self) -> u32 {
        self as u32
    }

    /// 未知の数値は Unknown として読む（前方互換）。
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => ModuleClass::Windows,
            2 => ModuleClass::Runtime,
            3 => ModuleClass::Application,
            _ => ModuleClass::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ModuleClass::Windows => "windows",
            ModuleClass::Runtime => "runtime",
            ModuleClass::Application => "application",
            ModuleClass::Unknown => "unknown",
        }
    }

    /// 大文字小文字を区別せずに読む。CLI の `--module-class` 用。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" => Some(ModuleClass::Windows),
            "runtime" => Some(ModuleClass::Runtime),
            "application" => Some(ModuleClass::Application),
            "unknown" => Some(ModuleClass::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for ModuleClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 分類の入力となる証拠。`microsoft_signed` が `None` のときは署名を
/// 確認していない（非 Windows での分類や、確認前の状態）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleEvidence {
    /// ロードされたままのモジュール名・パス。API Set 契約名の場合もある。
    pub path: String,
    /// Microsoft 製であることを埋め込み署名またはカタログ署名で確認済みか。
    pub microsoft_signed: Option<bool>,
    /// KnownDLLs として System32 へ解決されたか。
    pub known_dll: bool,
    /// SxS マニフェスト経由で WinSxS からロードされたか。
    pub sxs: bool,
    /// API Set 契約名の解決先の実装モジュール（解決できた場合のみ）。
    pub implementation_module: Option<String>,
}

impl ModuleEvidence {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            ..Default::default()
        }
    }

    pub fn signed(mut self, v: bool) -> Self {
        self.microsoft_signed = Some(v);
        self
    }

    pub fn known_dll(mut self) -> Self {
        self.known_dll = true;
        self
    }

    pub fn sxs(mut self) -> Self {
        self.sxs = true;
        self
    }

    pub fn implementation(mut self, path: &str) -> Self {
        self.implementation_module = Some(path.to_string());
        self
    }
}

/// 1 モジュールの分類結果。`reason` は判定理由（Trace に残す）。
/// `uncertain` が真のとき分類は不確実で、Application として観測する。
/// `overridden` が真のとき CLI の上書きによる分類である。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModuleClassification {
    /// ロードされたままのモジュール名・パス（API Set 契約名の場合もある）。
    pub module_name: String,
    pub class: ModuleClass,
    pub reason: String,
    pub uncertain: bool,
    /// API Set 契約名の解決先の実装モジュール（解決できた場合のみ）。
    pub implementation_module: Option<String>,
    pub overridden: bool,
}

impl ModuleClassification {
    /// `CaptureEnvironment` の field 9 に埋めるメッセージ。
    /// field 1: module_name, 2: class, 3: reason, 4: uncertain,
    /// 5: implementation_module, 6: overridden。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string_field(1, &self.module_name);
        w.u32_field(2, self.class.code());
        w.string_field(3, &self.reason);
        w.bool_field(4, self.uncertain);
        if let Some(m) = &self.implementation_module {
            w.string_field(5, m);
        }
        w.bool_field(6, self.overridden);
        w.into_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.module_name = r.value_string()?,
                (2, WIRE_VARINT) => m.class = ModuleClass::from_code(r.value_u64()? as u32),
                (3, WIRE_LEN) => m.reason = r.value_string()?,
                (4, WIRE_VARINT) => m.uncertain = r.value_bool()?,
                (5, WIRE_LEN) => m.implementation_module = Some(r.value_string()?),
                (6, WIRE_VARINT) => m.overridden = r.value_bool()?,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// API Set 契約名か（`api-ms-win-*` / `ext-ms-win-*` の DLL）。
pub fn is_api_set_contract(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-win-"))
        && lower.ends_with(".dll")
}

/// 既知の実行基盤モジュールか。実行基盤であることはモジュール固有の
/// 性質のため、ファイル名の一覧で識別する（overview の「VC++ Runtime、
/// CLRなどの実行基盤」に対応する実務的な識別規則）。
fn is_runtime_module(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    if !lower.ends_with(".dll") {
        return false;
    }
    matches!(
        lower.as_str(),
        "clr.dll"
            | "coreclr.dll"
            | "clrjit.dll"
            | "mscorlib.dll"
            | "mscorwks.dll"
            | "mscoree.dll"
            | "ucrtbase.dll"
    ) || lower.starts_with("msvcp")
        || lower.starts_with("msvcr")
        || lower.starts_with("vcruntime")
        || lower.starts_with("concrt")
}

/// `evidence` からモジュールを 1 分類する。判定理由は `reason` に残す。
pub fn classify_module(evidence: &ModuleEvidence) -> ModuleClassification {
    classify_with_depth(evidence, 2)
}

fn classify_with_depth(evidence: &ModuleEvidence, depth: u32) -> ModuleClassification {
    let path = evidence.path.trim();
    let file = file_name_of(path);
    let mk = |class: ModuleClass, reason: String, uncertain: bool| ModuleClassification {
        module_name: evidence.path.clone(),
        class,
        reason,
        uncertain,
        implementation_module: evidence.implementation_module.clone(),
        overridden: false,
    };
    if path.is_empty() {
        return mk(
            ModuleClass::Unknown,
            "module path is empty or could not be determined".into(),
            true,
        );
    }
    if is_api_set_contract(file) {
        return match (&evidence.implementation_module, depth) {
            (Some(impl_path), d) if d > 0 => {
                let inner_ev = ModuleEvidence {
                    path: impl_path.clone(),
                    microsoft_signed: evidence.microsoft_signed,
                    known_dll: evidence.known_dll,
                    sxs: evidence.sxs,
                    implementation_module: None,
                };
                let inner = classify_with_depth(&inner_ev, d - 1);
                let mut c = mk(
                    inner.class,
                    format!(
                        "API Set contract {file} resolved to {impl_path}: {}",
                        inner.reason
                    ),
                    inner.uncertain,
                );
                c.implementation_module = Some(impl_path.clone());
                c
            }
            _ => mk(
                ModuleClass::Unknown,
                format!(
                    "API Set contract {file} could not be resolved to an implementation module"
                ),
                true,
            ),
        };
    }
    if is_runtime_module(file) {
        return mk(
            ModuleClass::Runtime,
            format!("known runtime module {file} (VC++ Runtime / CLR / UCRT)"),
            false,
        );
    }
    let norm = path.replace('/', "\\").to_ascii_lowercase();
    let in_system = evidence.known_dll
        || evidence.sxs
        || norm
            .split('\\')
            .any(|seg| seg == "system32" || seg == "syswow64" || seg == "winsxs");
    if in_system {
        let via = if evidence.known_dll {
            "KnownDLLs"
        } else if evidence.sxs {
            "SxS (WinSxS)"
        } else {
            "system directory"
        };
        return match evidence.microsoft_signed {
            Some(true) => mk(
                ModuleClass::Windows,
                format!("{via} + Microsoft signature confirmed ({file})"),
                false,
            ),
            _ => mk(
                ModuleClass::Unknown,
                format!("{via} but Microsoft signature is unconfirmed ({file})"),
                true,
            ),
        };
    }
    mk(
        ModuleClass::Application,
        format!("not in a system directory; application-bundled or third-party module ({file})"),
        false,
    )
}

/// CLI の `--module-class <module>=<class>` 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleOverride {
    pub module: String,
    pub class: ModuleClass,
}

impl ModuleOverride {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (module, class) = s
            .split_once('=')
            .ok_or_else(|| format!("expected <module>=<class>, got {s:?}"))?;
        let module = module.trim();
        let class = ModuleClass::parse(class.trim()).ok_or_else(|| {
            format!("unknown module class {class:?} (expected windows/runtime/application/unknown)")
        })?;
        if module.is_empty() {
            return Err("module name is empty".into());
        }
        Ok(Self {
            module: module.to_string(),
            class,
        })
    }
}

/// `overrides` を `list` へ適用する。モジュール名はファイル名部分で
/// 大文字小文字を区別せず突き合わせる。一致しなかった上書きは返り値
/// として返し、呼び出し側が Trace へ上書きエントリとして記録する
/// （capture 開始時に未ロードのモジュールへの上書きが黙って消えない
/// ようにする）。
pub fn apply_overrides(
    list: &mut [ModuleClassification],
    overrides: &[ModuleOverride],
) -> Vec<ModuleOverride> {
    let mut unused = Vec::new();
    for ov in overrides {
        let ov_file = file_name_of(&ov.module).to_ascii_lowercase();
        match list
            .iter_mut()
            .find(|m| file_name_of(&m.module_name).to_ascii_lowercase() == ov_file)
        {
            Some(m) => {
                let old = m.class;
                let old_reason = std::mem::take(&mut m.reason);
                m.class = ov.class;
                m.overridden = true;
                m.reason = format!("CLI override to {} (was {old}: {old_reason})", ov.class);
            }
            None => unused.push(ov.clone()),
        }
    }
    unused
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_system(path: &str) -> ModuleEvidence {
        ModuleEvidence::new(path).signed(true)
    }

    #[test]
    fn windows_system32_signed_is_windows() {
        let c = classify_module(&signed_system(r"C:\Windows\System32\kernel32.dll"));
        assert_eq!(c.class, ModuleClass::Windows);
        assert!(!c.uncertain);
        assert!(!c.reason.is_empty());
        assert_eq!(c.module_name, r"C:\Windows\System32\kernel32.dll");
    }

    #[test]
    fn system32_without_signature_is_unknown() {
        let c = classify_module(&ModuleEvidence::new(r"C:\Windows\System32\kernel32.dll"));
        assert_eq!(c.class, ModuleClass::Unknown);
        assert!(c.uncertain, "signature unconfirmed must stay uncertain");
    }

    #[test]
    fn system32_signature_denied_is_unknown() {
        let c = classify_module(
            &ModuleEvidence::new(r"C:\Windows\System32\kernel32.dll").signed(false),
        );
        assert_eq!(c.class, ModuleClass::Unknown);
        assert!(c.uncertain);
    }

    #[test]
    fn runtime_modules_are_runtime_even_when_signed_in_system32() {
        for name in [
            r"C:\Windows\System32\msvcp140.dll",
            r"C:\Windows\System32\vcruntime140.dll",
            r"C:\Windows\System32\vcruntime140_1.dll",
            r"C:\Windows\System32\clr.dll",
            r"C:\Windows\System32\coreclr.dll",
            r"C:\Windows\System32\mscorlib.dll",
        ] {
            let c = classify_module(&signed_system(name));
            assert_eq!(c.class, ModuleClass::Runtime, "{name}");
            assert!(!c.uncertain, "{name}");
        }
    }

    #[test]
    fn application_exe_and_bundled_dll() {
        let exe = classify_module(&ModuleEvidence::new(r"C:\tools\app\game.exe"));
        assert_eq!(exe.class, ModuleClass::Application);
        assert!(!exe.uncertain);
        let dll = classify_module(&ModuleEvidence::new(r"C:\tools\app\plugins\foo.dll"));
        assert_eq!(dll.class, ModuleClass::Application);
    }

    #[test]
    fn empty_path_is_unknown() {
        let c = classify_module(&ModuleEvidence::new(""));
        assert_eq!(c.class, ModuleClass::Unknown);
        assert!(c.uncertain);
    }

    #[test]
    fn api_set_contract_unresolved_is_unknown() {
        let c = classify_module(&ModuleEvidence::new("api-ms-win-core-file-l1-1-0.dll"));
        assert_eq!(c.class, ModuleClass::Unknown);
        assert!(c.uncertain);
        assert!(c.reason.contains("API Set"), "{}", c.reason);
    }

    #[test]
    fn api_set_contract_resolves_to_implementation() {
        let c = classify_module(
            &ModuleEvidence::new("api-ms-win-core-file-l1-1-0.dll")
                .implementation(r"C:\Windows\System32\kernel32.dll")
                .signed(true),
        );
        assert_eq!(c.class, ModuleClass::Windows);
        assert!(!c.uncertain);
        assert_eq!(
            c.implementation_module.as_deref(),
            Some(r"C:\Windows\System32\kernel32.dll")
        );
        assert!(c.reason.contains("API Set"), "{}", c.reason);
    }

    #[test]
    fn known_dll_resolves_to_system32() {
        let c = classify_module(&ModuleEvidence::new("kernel32.dll").known_dll().signed(true));
        assert_eq!(c.class, ModuleClass::Windows);
        assert!(c.reason.contains("KnownDLL"), "{}", c.reason);
    }

    #[test]
    fn sxs_module_in_winsxs_is_windows() {
        let c = classify_module(
            &signed_system(r"C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60bdcf4b5d3e7f33\comctl32.dll")
                .sxs(),
        );
        assert_eq!(c.class, ModuleClass::Windows);
    }

    #[test]
    fn paths_are_case_insensitive_and_slash_tolerant() {
        let c = classify_module(&signed_system("c:/windows/SYSTEM32/KERNEL32.DLL"));
        assert_eq!(c.class, ModuleClass::Windows);
        let c = classify_module(&signed_system(r"C:\WINDOWS\SysWOW64\kernel32.dll"));
        assert_eq!(c.class, ModuleClass::Windows);
    }

    #[test]
    fn module_class_parse_is_case_insensitive() {
        assert_eq!(ModuleClass::parse("windows"), Some(ModuleClass::Windows));
        assert_eq!(ModuleClass::parse("RUNTIME"), Some(ModuleClass::Runtime));
        assert_eq!(
            ModuleClass::parse("Application"),
            Some(ModuleClass::Application)
        );
        assert_eq!(ModuleClass::parse("unknown"), Some(ModuleClass::Unknown));
        assert_eq!(ModuleClass::parse("banana"), None);
        assert_eq!(ModuleClass::parse(""), None);
    }

    #[test]
    fn override_parse_ok_and_errors() {
        let o = ModuleOverride::parse("kernel32.dll=windows").unwrap();
        assert_eq!(o.module, "kernel32.dll");
        assert_eq!(o.class, ModuleClass::Windows);
        assert!(ModuleOverride::parse("foo=banana").is_err());
        assert!(ModuleOverride::parse("noequals").is_err());
        assert!(ModuleOverride::parse("=windows").is_err());
        assert!(ModuleOverride::parse("foo=").is_err());
    }

    #[test]
    fn apply_overrides_replaces_and_reports_unused() {
        let mut list = vec![classify_module(&signed_system(
            r"C:\Windows\System32\kernel32.dll",
        ))];
        let unused = apply_overrides(
            &mut list,
            &[
                ModuleOverride::parse("kernel32.dll=application").unwrap(),
                ModuleOverride::parse("not-loaded.dll=runtime").unwrap(),
            ],
        );
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].class, ModuleClass::Application);
        assert!(list[0].overridden);
        assert!(list[0].reason.contains("override"), "{}", list[0].reason);
        assert_eq!(
            unused,
            vec![ModuleOverride::parse("not-loaded.dll=runtime").unwrap()]
        );
    }

    #[test]
    fn module_classification_proto_round_trip() {
        let c = classify_module(&signed_system(r"C:\Windows\System32\kernel32.dll"));
        let back = ModuleClassification::decode(&c.encode()).unwrap();
        assert_eq!(back, c);
        // 上書き済み・不確実・API Set 解決済みの往復も保つ。
        let mut u = classify_module(&ModuleEvidence::new("api-ms-win-core-file-l1-1-0.dll"));
        u.class = ModuleClass::Runtime;
        u.overridden = true;
        u.reason = "CLI override".to_string();
        let back = ModuleClassification::decode(&u.encode()).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn environment_with_modules_round_trips_and_old_bytes_decode_empty() {
        use crate::proto::{CaptureEnvironment, SessionMetadata};
        let mut env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 7,
                created_by: "test".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        };
        env.modules.push(classify_module(&signed_system(
            r"C:\Windows\System32\kernel32.dll",
        )));
        let back = CaptureEnvironment::decode(&env.encode()).unwrap();
        assert_eq!(back.modules, env.modules);
        // フィールド 9 が無い旧バイト列は modules 空として読める。
        let old = CaptureEnvironment {
            modules: vec![],
            ..env.clone()
        };
        let back = CaptureEnvironment::decode(&old.encode()).unwrap();
        assert!(back.modules.is_empty());
        assert_eq!(back.session.session_id, 7);
    }
}
