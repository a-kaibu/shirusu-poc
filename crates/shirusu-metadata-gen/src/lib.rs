//! Win32 Metadata Generator (L03) のライブラリ部分。
//!
//! Win32 Metadata (Windows.Win32.winmd) から、幅広い API の L1 定義
//! （`shirusu-hook` の `ApiDef`）と汎用 Detour を生成するための変換を
//! 置く。生成物はチェックインする Rust ソースであり、このクレートは
//! 開発時ツールとしてだけ使う（フック DLL には含まれない）。
//!
//! 対応の範囲（overview「観測レベル」）:
//! - L1（型付き引数・戻り値・GetLastError の取得）までを生成する。
//!   整数・浮動小数点・ポインタ型を扱い、文字列・バッファ・構造体の
//!   中身は取得しない（ポインタ値だけを記録する）。
//! - L2 以上は SAL アノテーションと手書きの記録仕様で API ごとに拡張
//!   する。生成表の API を手書き表へ昇格させる場合は、生成表から外し
//!   （末尾への追加のみという ID 安定性の規則に注意）、手書きの
//!   `ApiDef` と専用 Detour / 専用取得へ置き換える。
//! - x64 / x86 の元の引数・戻り値型で Detour を生成する。記録用の
//!   u64 は転送だけに使い、浮動小数点はビット列を保存する。複合構造体の
//!   値渡し・可変長引数は生成対象外（スキップ理由を報告する）。
//!
//! 型対応の要点:
//! - WinMD のプリミティブは `Ty` へ写す（8/16bit 整数は 32bit へ拡大）。
//! - 名前付き型は解決する：enum は基底整数型、デリゲート（コールバック）
//!   はポインタ値、単一フィールド構造体はそのフィールドの型
//!   （`HANDLE` / `HKEY` 等の `*mut c_void` 1 個だけの構造体はハンドル、
//!   `PWSTR` 等の `*mut u16` はポインタ、`BOOL` は I32）。
//! - COM インターフェイス型はネイティブのポインタとして記録する。
//!   これは COM メソッドの設置や参照先の取得を意味しない。

use serde::Deserialize;
use shirusu_trace::schema::{LastErrorMeaning, Ty, ValueKind};
use windows_metadata::reader::{TypeCategory, TypeIndex};
use windows_metadata::{MethodCallAttributes, Type};

/// 生成の設定ファイル (`apis.toml`)。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// 生成 API に割り当てる最初の api_id。手書き表の件数 + 1。
    /// 手書き表が増えたらこの値も上げる（ID 安定性のため）。
    pub first_api_id: u32,
    /// IDs owned by handwritten API families; never renumber them.
    #[serde(default)]
    pub reserved_api_ids: Vec<u32>,
    /// 汎用 Detour が中継できる最大引数個数（既定 12）。
    #[serde(default = "default_max_params")]
    pub max_params: usize,
    /// 使った Win32 Metadata の版
    /// （`Microsoft.Windows.SDK.Win32Metadata` の NuGet 版）。
    /// 生成物のヘッダに記録する。
    pub winmd_version: String,
    /// 生成対象の API（記載順に api_id を割り当てる。末尾への追加のみ）。
    #[serde(default, rename = "api")]
    pub apis: Vec<ApiConfig>,
    /// 意図的に生成しない API（決定を記録するための一覧）。
    #[serde(default, rename = "skip")]
    pub skips: Vec<SkipConfig>,
}

fn default_max_params() -> usize {
    12
}

/// Audit every WinMD Apis method, including entries absent from the selection
/// file. "generatable" describes the ABI mapper, not native capture coverage.
pub fn emit_api_inventory(index: &TypeIndex, config: &Config) -> String {
    let mut rows = Vec::new();
    for (namespace, name, def) in index.iter() {
        if name != "Apis" {
            continue;
        }
        for method in def.methods() {
            let module = method
                .impl_map()
                .map(|m| m.import_scope().name().to_string())
                .unwrap_or_default();
            let function = method.name().to_string();
            let selected = config.apis.iter().find(|a| {
                a.namespace == namespace
                    && a.module.eq_ignore_ascii_case(&module)
                    && a.function == function
            });
            let skipped = config.skips.iter().find(|a| {
                a.namespace == namespace
                    && a.module.eq_ignore_ascii_case(&module)
                    && a.function == function
            });
            let candidate = ApiConfig {
                namespace: namespace.to_string(),
                module: module.clone(),
                function: function.clone(),
                last_error: selected.and_then(|a| a.last_error.clone()),
            };
            let (status, reason) = match skipped {
                Some(skip) => ("excluded", skip.reason.clone()),
                None => match map_api(index, &candidate, 1, config.max_params) {
                    Ok(EntryOutcome::Emitted(_)) => (
                        if selected.is_some() {
                            "selected"
                        } else {
                            "generatable"
                        },
                        String::new(),
                    ),
                    Ok(EntryOutcome::Skipped { reason, .. }) | Err(reason) => {
                        ("unsupported", reason)
                    }
                },
            };
            rows.push((namespace.to_string(), module, function, status, reason));
        }
    }
    rows.sort();
    let mut out = String::from("namespace\tmodule\tfunction\tstatus\treason\n");
    for (namespace, module, function, status, reason) in rows {
        let fields = [namespace, module, function, status.to_string(), reason];
        out.push_str(
            &fields
                .iter()
                .map(|v| {
                    v.replace('\\', "\\\\")
                        .replace('\t', "\\t")
                        .replace('\r', "\\r")
                        .replace('\n', "\\n")
                })
                .collect::<Vec<_>>()
                .join("\t"),
        );
        out.push('\n');
    }
    out
}

/// 生成対象の API 1 件。
#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    /// WinMD の名前空間（例 `Windows.Win32.System.Registry`）。
    pub namespace: String,
    /// インポート元 DLL（例 `advapi32.dll`）。ImplMap の DLL と一致
    /// しなければ生成は失敗する（設定の誤りを早期に検出するため）。
    pub module: String,
    /// 関数名（例 `RegCloseKey`）。
    pub function: String,
    /// GetLastError の意味条件の上書き。省略時は戻り値の種類から決める。
    /// `false` / `null` / `invalid-handle` / `minus-one` /
    /// `never` / `always` / `unspecified`。
    #[serde(default)]
    pub last_error: Option<String>,
}

/// 意図的に生成しない API 1 件（理由付き）。
#[derive(Debug, Clone, Deserialize)]
pub struct SkipConfig {
    pub namespace: String,
    pub module: String,
    pub function: String,
    pub reason: String,
}

/// WinMD の型を shirusu の Schema 型へ写したもの。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedTy {
    /// Native ABI type, independent of the serialized schema width.
    pub abi: &'static str,
    pub ty: Ty,
    pub kind: ValueKind,
    /// 戻り値の GetLastError 意味条件の既定を決めるための分類。
    pub flavor: Flavor,
    /// x86 / x64 の両方で呼び出し規約上の 1 スロット（4 / 8 バイト）
    /// に収まるか。固定 64bit 型（I64 / U64）は x86 で 2 スロットを
    /// 占める。ABI 型を保存した生成器はこの区別によらず中継できる。
    /// ポインタ幅の型（ISize / USize / ポインタ / ハンドル）
    /// は両ターゲットで 1 スロットである。
    pub one_slot: bool,
}

/// 戻り値の種類による分類（`LastErrorMeaning` の既定用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// `BOOL`。失敗は FALSE (0)。
    Bool,
    /// `HANDLE` 等のハンドル。失敗は NULL (0)。
    Handle,
    /// `WIN32_ERROR` / `HRESULT` / `NTSTATUS`。戻り値自体がエラー。
    ErrorCode,
    /// ポインタ戻り。失敗は NULL (0)。
    Pointer,
    /// その他の整数（カウント・状態値等）。失敗条件は型だけでは不明。
    Integer,
    /// `void`。戻り値なし。
    Void,
}

/// 生成した API 1 件（`ApiDef` と Detour 生成の入力）。
#[derive(Debug, Clone)]
pub struct MappedApi {
    pub calling_convention: &'static str,
    pub abi_params: Vec<&'static str>,
    pub abi_return: &'static str,
    pub api_id: u32,
    pub module: String,
    pub function: String,
    /// enter フィールド（引数順）: (名前, 型, 種別)。
    pub enter_fields: Vec<(String, Ty, ValueKind)>,
    /// 戻り値（void なら None）: (型, 種別)。
    pub return_ty: Option<(Ty, ValueKind)>,
    pub last_error_meaning: LastErrorMeaning,
}

/// 生成 1 件の結果（出すもの・出さないもの）。
#[derive(Debug, Clone)]
pub enum EntryOutcome {
    Emitted(MappedApi),
    Skipped {
        module: String,
        function: String,
        reason: String,
    },
}

/// 生成の出力一式。
#[derive(Debug, Default)]
pub struct Generated {
    pub entries: Vec<EntryOutcome>,
    /// 意図的なスキップ（設定の `skips`）。
    pub intentional_skips: Vec<SkipConfig>,
}

impl Generated {
    pub fn emitted(&self) -> Vec<&MappedApi> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                EntryOutcome::Emitted(a) => Some(a),
                EntryOutcome::Skipped { .. } => None,
            })
            .collect()
    }

    pub fn skipped(&self) -> Vec<(&str, &str, &str)> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                EntryOutcome::Skipped {
                    module,
                    function,
                    reason,
                } => Some((module.as_str(), function.as_str(), reason.as_str())),
                EntryOutcome::Emitted(_) => None,
            })
            .collect()
    }
}

/// 設定ファイル (`apis.toml`) を読む。
pub fn load_config(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path} を読めない: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("{path} の解析に失敗: {e}"))
}

/// 設定に従って Metadata から API を生成する。対応外の API は
/// `EntryOutcome::Skipped` として残し、生成全体は止めない。設定の
/// 誤り（重複・存在しない関数・DLL 不一致・不明な意味条件）は
/// `Err` で止める。
pub fn generate(index: &TypeIndex, config: &Config) -> Result<Generated, String> {
    if config.apis.is_empty() {
        return Err("生成対象 API が 0 件（apis.toml の [[api]] を確認する）".into());
    }
    let mut out = Generated {
        entries: Vec::new(),
        intentional_skips: config.skips.clone(),
    };
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut next_id = config.first_api_id;
    for api in &config.apis {
        let key = (api.module.to_ascii_lowercase(), api.function.clone());
        if seen.contains(&key) {
            return Err(format!(
                "{}!{} が設定に重複している",
                api.module, api.function
            ));
        }
        seen.push(key);
        while config.reserved_api_ids.contains(&next_id) {
            next_id = next_id.checked_add(1).ok_or("API ID overflow")?;
        }
        match map_api(index, api, next_id, config.max_params)? {
            EntryOutcome::Emitted(mapped) => {
                next_id += 1;
                out.entries.push(EntryOutcome::Emitted(mapped));
            }
            skipped @ EntryOutcome::Skipped { .. } => out.entries.push(skipped),
        }
    }
    Ok(out)
}

/// 1 API を Metadata から写す。
fn map_api(
    index: &TypeIndex,
    api: &ApiConfig,
    api_id: u32,
    max_params: usize,
) -> Result<EntryOutcome, String> {
    let skipped = |reason: String| EntryOutcome::Skipped {
        module: api.module.clone(),
        function: api.function.clone(),
        reason,
    };
    let apis = index
        .get(&api.namespace, "Apis")
        .next()
        .ok_or_else(|| format!("{} に Apis クラスが無い", api.namespace))?;
    let mut methods = apis.methods().filter(|m| m.name() == api.function);
    let method = match methods.next() {
        None => {
            return Err(format!(
                "{}!{} が {} に存在しない",
                api.module, api.function, api.namespace
            ))
        }
        Some(m) => m,
    };
    if methods.next().is_some() {
        return Err(format!(
            "{}!{} は同名の重載が複数あり、どれか決められない",
            api.module, api.function
        ));
    }
    let sig = method.signature(&[]);
    if sig.flags.contains(MethodCallAttributes::VARARG) {
        return Ok(skipped(
            "可変長引数 (VARARG) は汎用 Detour で中継できない".into(),
        ));
    }
    if sig.flags.contains(MethodCallAttributes::HASTHIS) {
        return Ok(skipped("インスタンスメソッド (HASTHIS) は対象外".into()));
    }
    let calling_convention = match method.calling_convention() {
        "system" => "system-unwind",
        "C" => "C-unwind",
        other => return Ok(skipped(format!("unsupported calling convention: {other}"))),
    };
    let Some(map) = method.impl_map() else {
        return Ok(skipped("ImplMap が無い (P/Invoke ではない)".into()));
    };
    if map.import_name() != api.function {
        return Ok(skipped(format!(
            "エクスポート名が {} と異なる",
            map.import_name()
        )));
    }
    let impl_module = map.import_scope().name().to_string();
    if !impl_module.eq_ignore_ascii_case(&api.module) {
        return Err(format!(
            "{}!{} の ImplMap DLL は {} であり、設定の {} と一致しない",
            api.module, api.function, impl_module, api.module
        ));
    }
    // MethodParam の sequence 0 は戻り値の擬似パラメータ。実引数は
    // sequence >= 1 で、sig.types と順に並ぶ。
    let names: Vec<String> = method
        .params()
        .filter(|p| p.sequence() >= 1)
        .map(|p| p.name().to_string())
        .collect();
    if names.len() != sig.types.len() {
        return Err(format!(
            "{}!{} の引数名 ({} 個) と引数型 ({} 個) の個数が合わない",
            api.module,
            api.function,
            names.len(),
            sig.types.len()
        ));
    }
    if sig.types.len() > max_params {
        return Ok(skipped(format!(
            "引数が {} 個で上限 {} を超える",
            sig.types.len(),
            max_params
        )));
    }
    let mut enter_fields = Vec::with_capacity(sig.types.len());
    let mut abi_params = Vec::with_capacity(sig.types.len());
    for (name, ty) in names.iter().zip(sig.types.iter()) {
        match map_type(index, ty) {
            Ok(m) => {
                abi_params.push(m.abi);
                enter_fields.push((name.to_string(), m.ty, m.kind));
            }
            Err(reason) => {
                return Ok(skipped(format!("引数 {name}: {reason}")));
            }
        }
    }
    let (return_ty, flavor, abi_return) = match &sig.return_type {
        Type::Void => (None, Flavor::Void, "()"),
        ty => match map_type(index, ty) {
            Ok(m) => (Some((m.ty, m.kind)), m.flavor, m.abi),
            Err(reason) => return Ok(skipped(format!("戻り値: {reason}"))),
        },
    };
    let last_error_meaning = match &api.last_error {
        Some(s) => parse_last_error(s)
            .map_err(|e| format!("{}!{} の last_error が不正: {e}", api.module, api.function))?,
        None => default_meaning(flavor),
    };
    Ok(EntryOutcome::Emitted(MappedApi {
        calling_convention,
        abi_params,
        abi_return,
        api_id,
        module: api.module.clone(),
        function: api.function.clone(),
        enter_fields,
        return_ty,
        last_error_meaning,
    }))
}

/// WinMD の型を shirusu の Schema 型へ写す。対応外の型は理由付きで
/// `Err` を返す。
pub fn map_type(index: &TypeIndex, ty: &Type) -> Result<MappedTy, String> {
    let scalar = |ty: Ty, one_slot: bool, abi| MappedTy {
        abi,
        ty,
        kind: ValueKind::Scalar,
        flavor: Flavor::Integer,
        one_slot,
    };
    let pointer = || MappedTy {
        abi: "*mut core::ffi::c_void",
        ty: Ty::U64,
        kind: ValueKind::Pointer,
        flavor: Flavor::Pointer,
        one_slot: true,
    };
    Ok(match ty {
        Type::Void => return Err("void 型は引数・戻り値以外では扱えない".into()),
        Type::Bool => scalar(Ty::Bool, true, "u8"),
        Type::Char | Type::U16 => scalar(Ty::U32, true, "u16"),
        Type::I8 => scalar(Ty::I32, true, "i8"),
        Type::U8 => scalar(Ty::U32, true, "u8"),
        Type::I16 => scalar(Ty::I32, true, "i16"),
        Type::I32 => scalar(Ty::I32, true, "i32"),
        Type::U32 => scalar(Ty::U32, true, "u32"),
        Type::I64 => scalar(Ty::I64, false, "i64"),
        Type::U64 => scalar(Ty::U64, false, "u64"),
        Type::ISize => scalar(Ty::I64, true, "isize"),
        Type::USize => scalar(Ty::U64, true, "usize"),
        Type::F32 => scalar(Ty::F32, true, "f32"),
        Type::F64 => scalar(Ty::F64, false, "f64"),
        Type::String => return Err("HSTRING/String 型は対象外".into()),
        Type::Object => return Err("Object 型は対象外".into()),
        Type::Array(_) => return Err("配列の値渡しは対象外".into()),
        Type::ArrayFixed(_, _) => return Err("固定長配列の値渡しは対象外".into()),
        Type::ArrayRef(_) => pointer(),
        Type::Generic(_) => return Err("ジェネリック型は対象外".into()),
        Type::RefMut(_) | Type::RefConst(_) => pointer(),
        Type::PtrMut(_, _) | Type::PtrConst(_, _) => pointer(),
        Type::AttributeEnum => return Err("属性用 enum は対象外".into()),
        Type::Name(tn) => map_named_type(index, tn)?,
    })
}

/// 名前付き型を解決して写す。
fn map_named_type(index: &TypeIndex, tn: &windows_metadata::TypeName) -> Result<MappedTy, String> {
    if !tn.generics.is_empty() {
        return Err(format!(
            "ジェネリックな名前付き型 {}::{} は対象外",
            tn.namespace, tn.name
        ));
    }
    let Some(def) = index.get(&tn.namespace, &tn.name).next() else {
        return Err(format!("未知の名前付き型 {}::{}", tn.namespace, tn.name));
    };
    match def.category() {
        TypeCategory::Enum => {
            let Some(value_field) = def.fields().find(|f| f.name() == "value__") else {
                return Err(format!(
                    "enum {}::{} に value__ が無い",
                    tn.namespace, tn.name
                ));
            };
            let inner = map_type(index, &value_field.ty())?;
            if !matches!(inner.ty, Ty::I32 | Ty::U32 | Ty::I64 | Ty::U64) {
                return Err(format!(
                    "enum {}::{} の基底型 {:?} は整数ではない",
                    tn.namespace, tn.name, inner.ty
                ));
            }
            let flavor = if (tn.namespace.as_str(), tn.name.as_str())
                == ("Windows.Win32.Foundation", "WIN32_ERROR")
                || (tn.namespace.as_str(), tn.name.as_str())
                    == ("Windows.Win32.Foundation", "HRESULT")
                || (tn.namespace.as_str(), tn.name.as_str())
                    == ("Windows.Win32.Foundation", "NTSTATUS")
            {
                Flavor::ErrorCode
            } else {
                Flavor::Integer
            };
            Ok(MappedTy {
                ty: inner.ty,
                kind: ValueKind::Scalar,
                flavor,
                one_slot: inner.one_slot,
                abi: inner.abi,
            })
        }
        TypeCategory::Delegate => Ok(MappedTy {
            abi: "*mut core::ffi::c_void",
            ty: Ty::U64,
            kind: ValueKind::Pointer,
            flavor: Flavor::Pointer,
            one_slot: true,
        }),
        TypeCategory::Struct => {
            let fields: Vec<_> = def.fields().collect();
            if fields.len() != 1 {
                return Err(format!(
                    "値渡し構造体 {}::{} は {} フィールドあり、汎用 Detour で中継できない",
                    tn.namespace,
                    tn.name,
                    fields.len()
                ));
            }
            let field = &fields[0];
            // `*mut c_void` 1 個だけの構造体はハンドル (HANDLE / HKEY 等)。
            if matches!(field.ty(), Type::PtrMut(inner, _) if *inner == Type::Void) {
                return Ok(MappedTy {
                    abi: "*mut core::ffi::c_void",
                    ty: Ty::U64,
                    kind: ValueKind::Handle,
                    flavor: Flavor::Handle,
                    one_slot: true,
                });
            }
            // BOOL は I32 1 個の構造体。戻り値の失敗条件 (FALSE) のため
            // Flavor::Bool として区別する。
            if (tn.namespace.as_str(), tn.name.as_str()) == ("Windows.Win32.Foundation", "BOOL") {
                return Ok(MappedTy {
                    abi: "i32",
                    ty: Ty::I32,
                    kind: ValueKind::Scalar,
                    flavor: Flavor::Bool,
                    one_slot: true,
                });
            }
            map_type(index, &field.ty())
        }
        TypeCategory::Interface => Ok(MappedTy {
            abi: "*mut core::ffi::c_void",
            ty: Ty::U64,
            kind: ValueKind::Pointer,
            flavor: Flavor::Pointer,
            one_slot: true,
        }),
        TypeCategory::Class | TypeCategory::Attribute => Err(format!(
            "COM/クラス/インターフェイス型 {}::{} は対象外 (L02 対象)",
            tn.namespace, tn.name
        )),
    }
}

/// 戻り値の種類から決める `LastErrorMeaning` の既定。
pub fn default_meaning(flavor: Flavor) -> LastErrorMeaning {
    match flavor {
        Flavor::Bool => LastErrorMeaning::WhenReturnIsFalse,
        Flavor::Handle | Flavor::Pointer => LastErrorMeaning::WhenReturnIsNull,
        Flavor::ErrorCode | Flavor::Integer | Flavor::Void => LastErrorMeaning::Never,
    }
}

/// 設定の `last_error` 文字列を `LastErrorMeaning` へ写す。
pub fn parse_last_error(s: &str) -> Result<LastErrorMeaning, String> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "false" => LastErrorMeaning::WhenReturnIsFalse,
        "null" => LastErrorMeaning::WhenReturnIsNull,
        "not-null" => LastErrorMeaning::WhenReturnIsNotNull,
        "invalid-handle" => LastErrorMeaning::WhenReturnIsInvalidHandle,
        "minus-one" => LastErrorMeaning::WhenReturnIsMinusOne,
        "never" => LastErrorMeaning::Never,
        "always" => LastErrorMeaning::Always,
        "unspecified" => LastErrorMeaning::Unspecified,
        other => return Err(format!("不明な last_error 指定: {other}")),
    })
}

/// `PascalCase` の Win32 名を `snake_case` へ写す
/// （生成 Detour の関数名用）。
pub fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// 生成 Detour の関数名（モジュール付きで一意にする）。
pub fn detour_fn_name(api: &MappedApi) -> String {
    let stem = api
        .module
        .strip_suffix(".dll")
        .unwrap_or(&api.module)
        .to_ascii_lowercase();
    format!("detour_generated_{}_{}", stem, snake_case(&api.function))
}

fn rust_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `api_generated.inc`（生成 API の `&[ApiDef]` 1 個の式）を出す。
/// `api.rs` で `pub const GENERATED_API_TABLE: &[ApiDef] =
/// include!("api_generated.inc");` として取り込む。`BEFORE` / `AFTER` /
/// `Ty` 等は取り込み側のスコープで解決する。
pub fn emit_api_inc(generated: &Generated, winmd_version: &str) -> String {
    let mut out = String::new();
    out.push_str("// @generated by win32-metadata-gen — DO NOT EDIT.\n");
    out.push_str(&format!(
        "// Source: Windows.Win32.winmd (Microsoft.Windows.SDK.Win32Metadata {winmd_version}).\n"
    ));
    out.push_str("// Regenerate: cargo run -p shirusu-metadata-gen -- --winmd <path> --config crates/shirusu-metadata-gen/apis.toml\n");
    out.push_str("&[\n");
    for api in generated.emitted() {
        out.push_str("ApiDef {\n");
        out.push_str(&format!("    api_id: {},\n", api.api_id));
        out.push_str(&format!("    module: {},\n", rust_str(&api.module)));
        out.push_str(&format!("    function: {},\n", rust_str(&api.function)));
        out.push_str("    level: 1,\n");
        out.push_str(
            "    level_note: \"L1（Win32 Metadata から生成）：型付き引数・戻り値のみ。文字列・バッファ・構造体の中身は取得しない（ポインタ値のみ）\",\n",
        );
        out.push_str("    enter_fields: &[");
        for (i, (name, ty, kind)) in api.enter_fields.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!(
                "({}, Ty::{:?}, ValueKind::{:?}, BEFORE)",
                rust_str(name),
                ty,
                kind
            ));
        }
        out.push_str("],\n");
        out.push_str("    leave_fields: &[");
        let mut first = true;
        if let Some((ty, kind)) = &api.return_ty {
            out.push_str(&format!(
                "(\"return\", Ty::{ty:?}, ValueKind::{kind:?}, AFTER)"
            ));
            first = false;
        }
        if !first {
            out.push_str(", ");
        }
        out.push_str("(\"last_error\", Ty::U32, ValueKind::Scalar, AFTER)");
        out.push_str("],\n");
        out.push_str(&format!(
            "    last_error_meaning: LastErrorMeaning::{:?},\n",
            api.last_error_meaning
        ));
        out.push_str("},\n");
    }
    out.push_str("]\n");
    out
}

/// `engine_generated.inc`（生成 Detour と `detour_for_generated`）
/// を出す。`engine.rs`（Windows のみ）で `include!` される断片。
pub fn emit_engine_inc(generated: &Generated, winmd_version: &str) -> String {
    let mut out = String::new();
    out.push_str("// @generated by win32-metadata-gen — DO NOT EDIT.\n");
    out.push_str(&format!(
        "// Source: Windows.Win32.winmd (Microsoft.Windows.SDK.Win32Metadata {winmd_version}).\n"
    ));
    out.push_str("// Regenerate: cargo run -p shirusu-metadata-gen -- --winmd <path> --config crates/shirusu-metadata-gen/apis.toml\n");
    for api in generated.emitted() {
        let fname = detour_fn_name(api);
        let abi = api.calling_convention;
        let types = &api.abi_params;
        let params: Vec<_> = types
            .iter()
            .enumerate()
            .map(|(i, ty)| format!("a{i}: {ty}"))
            .collect();
        let args: Vec<_> = (0..types.len()).map(|i| format!("a{i}")).collect();
        let raw: Vec<_> = types
            .iter()
            .enumerate()
            .map(|(i, ty)| match *ty {
                "f32" => format!("a{i}.to_bits() as u64"),
                "f64" => format!("a{i}.to_bits()"),
                "u64" => format!("a{i}"),
                _ => format!("a{i} as u64"),
            })
            .collect();
        let ret = api.abi_return;
        let declaration_ret = if api.return_ty.is_some() {
            format!(" -> {ret}")
        } else {
            String::new()
        };
        out.push_str(&format!(
            "unsafe extern \"{abi}\" fn {fname}({}){declaration_ret} {{\n",
            params.join(", ")
        ));
        let binding = if api.return_ty.is_some() && ret != "u64" {
            "let result = "
        } else {
            ""
        };
        out.push_str(&format!(
            "    {binding}generic_detour_with({}, &[{}], |original| {{\n        let original: unsafe extern \"{abi}\" fn({}) -> {ret} = unsafe {{ std::mem::transmute(original) }};\n",
            api.api_id, raw.join(", "), types.join(", ")
        ));
        let call = format!("unsafe {{ original({}) }}", args.join(", "));
        let raw_return = match ret {
            "()" => format!("{call};\n        0"),
            "f32" => format!("({call}).to_bits() as u64"),
            "f64" => format!("({call}).to_bits()"),
            "u64" => call,
            _ => format!("({call}) as u64"),
        };
        out.push_str(&format!(
            "        {raw_return}\n    }}){}\n",
            if ret == "u64" { "" } else { ";" }
        ));
        if api.return_ty.is_some() && ret != "u64" {
            let returned = match ret {
                "f32" => "f32::from_bits(result as u32)".into(),
                "f64" => "f64::from_bits(result)".into(),
                "u64" => "result".into(),
                _ => format!("result as {ret}"),
            };
            out.push_str(&format!("    {returned}\n"));
        }
        out.push_str("}\n");
    }
    out.push_str("\nfn detour_for_generated(api_id: u32) -> usize {\n");
    out.push_str("    match api_id {\n");
    for api in generated.emitted() {
        let fname = detour_fn_name(api);
        out.push_str(&format!(
            "        {} => {fname} as *const () as usize,\n",
            api.api_id
        ));
    }
    out.push_str("        _ => 0,\n");
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// Generate IID identification metadata for all COM interfaces in WinMD.
/// Names are descriptive only: this table does not license vtable mutation.
pub fn emit_com_catalog(index: &TypeIndex, version: &str) -> Result<String, String> {
    use std::collections::{BTreeMap, BTreeSet};
    use windows_metadata::{reader::HasAttributes, Value};
    let mut catalog: BTreeMap<[u8; 16], BTreeSet<String>> = BTreeMap::new();
    for (namespace, name, def) in index.iter() {
        if def.category() != TypeCategory::Interface {
            continue;
        }
        let Some(attr) = def.find_attribute("GuidAttribute") else {
            continue;
        };
        let values: Vec<u32> = attr
            .value()
            .iter()
            .map(|(_, value)| match value {
                Value::U32(v) => Ok(*v),
                Value::U16(v) => Ok(u32::from(*v)),
                Value::U8(v) => Ok(u32::from(*v)),
                _ => Err(format!(
                    "{namespace}.{name}: unsupported GUID attribute value"
                )),
            })
            .collect::<Result<_, _>>()?;
        if values.len() != 11 {
            return Err(format!("{namespace}.{name}: GUID needs 11 values"));
        }
        let mut iid = [0; 16];
        iid[..4].copy_from_slice(&values[0].to_le_bytes());
        for (n, offset) in [(1, 4), (2, 6)] {
            let value = u16::try_from(values[n]).map_err(|_| "GUID component out of range")?;
            iid[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (n, value) in values[3..].iter().enumerate() {
            iid[n + 8] = u8::try_from(*value).map_err(|_| "GUID byte out of range")?;
        }
        catalog
            .entry(iid)
            .or_default()
            .insert(format!("{namespace}.{name}"));
    }
    let mut out = format!("// @generated from Windows.Win32.winmd {version}; DO NOT EDIT.\n&[\n");
    for (iid, names) in catalog {
        let names = names
            .iter()
            .map(|s| rust_str(s))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "    ComInterfaceInfo {{ iid: {iid:?}, names: &[{names}] }},\n"
        ));
    }
    out.push_str("]\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_index() -> TypeIndex {
        TypeIndex::new(vec![])
    }

    #[test]
    fn snake_case_converts_win32_names() {
        assert_eq!(snake_case("RegCloseKey"), "reg_close_key");
        assert_eq!(snake_case("CreateFileW"), "create_file_w");
        assert_eq!(snake_case("RegOpenKeyExW"), "reg_open_key_ex_w");
        assert_eq!(
            snake_case("GetQueuedCompletionStatus"),
            "get_queued_completion_status"
        );
        assert_eq!(snake_case("Sleep"), "sleep");
    }

    #[test]
    fn parse_last_error_accepts_all_spellings() {
        assert_eq!(
            parse_last_error("not-null").unwrap(),
            LastErrorMeaning::WhenReturnIsNotNull
        );
        assert_eq!(
            parse_last_error("false").unwrap(),
            LastErrorMeaning::WhenReturnIsFalse
        );
        assert_eq!(
            parse_last_error("null").unwrap(),
            LastErrorMeaning::WhenReturnIsNull
        );
        assert_eq!(
            parse_last_error("invalid-handle").unwrap(),
            LastErrorMeaning::WhenReturnIsInvalidHandle
        );
        assert_eq!(
            parse_last_error("minus-one").unwrap(),
            LastErrorMeaning::WhenReturnIsMinusOne
        );
        assert_eq!(parse_last_error("never").unwrap(), LastErrorMeaning::Never);
        assert_eq!(
            parse_last_error("always").unwrap(),
            LastErrorMeaning::Always
        );
        assert_eq!(
            parse_last_error("unspecified").unwrap(),
            LastErrorMeaning::Unspecified
        );
        assert!(parse_last_error("bogus").is_err());
    }

    #[test]
    fn default_meaning_follows_return_flavor() {
        assert_eq!(
            default_meaning(Flavor::Bool),
            LastErrorMeaning::WhenReturnIsFalse
        );
        assert_eq!(
            default_meaning(Flavor::Handle),
            LastErrorMeaning::WhenReturnIsNull
        );
        assert_eq!(
            default_meaning(Flavor::Pointer),
            LastErrorMeaning::WhenReturnIsNull
        );
        assert_eq!(default_meaning(Flavor::ErrorCode), LastErrorMeaning::Never);
        assert_eq!(default_meaning(Flavor::Integer), LastErrorMeaning::Never);
        assert_eq!(default_meaning(Flavor::Void), LastErrorMeaning::Never);
    }

    #[test]
    fn map_type_maps_primitives_without_index() {
        // L03: プリミティブの写像は Metadata の解決を要しない。
        let idx = empty_index();
        let cases = [
            (Type::I32, Ty::I32, true),
            (Type::U32, Ty::U32, true),
            (Type::I64, Ty::I64, false),
            (Type::U64, Ty::U64, false),
            (Type::ISize, Ty::I64, true),
            (Type::USize, Ty::U64, true),
        ];
        for (input, expected, one_slot) in cases {
            let m = map_type(&idx, &input).expect("primitive maps");
            assert_eq!(m.ty, expected, "{input:?}");
            assert_eq!(m.kind, ValueKind::Scalar);
            // 固定 64bit 型だけが 1 スロットに収まらない (x86 で 2 スロット)。
            assert_eq!(m.one_slot, one_slot, "{input:?}");
        }
        // ポインタは中身によらず U64/Pointer。
        let m = map_type(&idx, &Type::PtrMut(Box::new(Type::Void), 1)).unwrap();
        assert_eq!(m.ty, Ty::U64);
        assert_eq!(m.kind, ValueKind::Pointer);
        assert_eq!(m.flavor, Flavor::Pointer);
        let m = map_type(&idx, &Type::RefMut(Box::new(Type::U32))).unwrap();
        assert_eq!(m.kind, ValueKind::Pointer);
    }

    #[test]
    fn map_type_rejects_unsupported_types() {
        let idx = empty_index();
        for ty in [
            Type::Bool,
            Type::Char,
            Type::I8,
            Type::U8,
            Type::I16,
            Type::U16,
        ] {
            assert!(map_type(&idx, &ty).is_ok(), "{ty:?}");
        }
        assert!(map_type(&idx, &Type::F32).is_ok());
        assert!(map_type(&idx, &Type::F64).is_ok());
        assert!(map_type(&idx, &Type::String).is_err());
        assert!(map_type(&idx, &Type::Object).is_err());
        assert!(map_type(&idx, &Type::Array(Box::new(Type::U8))).is_err());
        assert!(map_type(&idx, &Type::ArrayFixed(Box::new(Type::U8), 4)).is_err());
        assert!(map_type(&idx, &Type::Generic(0)).is_err());
        assert!(map_type(&idx, &Type::Void).is_err());
        // 未知の名前付き型も解決できず拒否される。
        assert!(map_type(
            &idx,
            &Type::Name(windows_metadata::TypeName::named(
                "Windows.Win32.Foundation",
                "HANDLE"
            ))
        )
        .is_err());
    }

    #[test]
    fn emit_api_inc_renders_api_def() {
        let api = MappedApi {
            calling_convention: "system-unwind",
            api_id: 7,
            module: "advapi32.dll".into(),
            function: "RegCloseKey".into(),
            abi_params: vec!["*mut core::ffi::c_void"],
            abi_return: "u32",
            enter_fields: vec![("hKey".into(), Ty::U64, ValueKind::Handle)],
            return_ty: Some((Ty::U32, ValueKind::Scalar)),
            last_error_meaning: LastErrorMeaning::Never,
        };
        let generated = Generated {
            entries: vec![EntryOutcome::Emitted(api)],
            intentional_skips: vec![],
        };
        let text = emit_api_inc(&generated, "71.0.45-preview");
        assert!(text.starts_with("// @generated"));
        assert!(
            text.contains("&[\n"),
            "generated table is a single &[ApiDef] expression"
        );
        assert!(text.contains("api_id: 7,"));
        assert!(text.contains("module: \"advapi32.dll\","));
        assert!(text.contains("function: \"RegCloseKey\","));
        assert!(text.contains("level: 1,"));
        assert!(text.contains("(\"hKey\", Ty::U64, ValueKind::Handle, BEFORE)"));
        assert!(text.contains("(\"return\", Ty::U32, ValueKind::Scalar, AFTER)"));
        assert!(text.contains("(\"last_error\", Ty::U32, ValueKind::Scalar, AFTER)"));
        assert!(text.contains("last_error_meaning: LastErrorMeaning::Never,"));
        assert!(text.contains("71.0.45-preview"));
        // void 戻りの API は return フィールドを持たない。
        let api = MappedApi {
            calling_convention: "system-unwind",
            api_id: 8,
            module: "kernel32.dll".into(),
            function: "Sleep".into(),
            abi_params: vec!["u32"],
            abi_return: "()",
            enter_fields: vec![("dwMilliseconds".into(), Ty::U32, ValueKind::Scalar)],
            return_ty: None,
            last_error_meaning: LastErrorMeaning::Never,
        };
        let generated = Generated {
            entries: vec![EntryOutcome::Emitted(api)],
            intentional_skips: vec![],
        };
        let text = emit_api_inc(&generated, "71.0.45-preview");
        assert!(!text.contains("\"return\""));
        assert!(text.contains("\"last_error\""));
    }

    #[test]
    fn emit_engine_inc_renders_detours_and_dispatch() {
        let api = MappedApi {
            calling_convention: "system-unwind",
            api_id: 7,
            module: "advapi32.dll".into(),
            function: "RegCloseKey".into(),
            abi_params: vec!["*mut core::ffi::c_void"],
            abi_return: "u32",
            enter_fields: vec![("hKey".into(), Ty::U64, ValueKind::Handle)],
            return_ty: Some((Ty::U32, ValueKind::Scalar)),
            last_error_meaning: LastErrorMeaning::Never,
        };
        let zero = MappedApi {
            calling_convention: "system-unwind",
            api_id: 8,
            module: "kernel32.dll".into(),
            function: "GetCurrentProcessId".into(),
            abi_params: vec![],
            abi_return: "u32",
            enter_fields: vec![],
            return_ty: Some((Ty::U32, ValueKind::Scalar)),
            last_error_meaning: LastErrorMeaning::Never,
        };
        let generated = Generated {
            entries: vec![EntryOutcome::Emitted(api), EntryOutcome::Emitted(zero)],
            intentional_skips: vec![],
        };
        let text = emit_engine_inc(&generated, "71.0.45-preview");
        assert!(text.contains(
            "unsafe extern \"system-unwind\" fn detour_generated_advapi32_reg_close_key(a0: *mut core::ffi::c_void) -> u32"
        ));
        assert!(text.contains("generic_detour_with(7, &[a0 as u64]"));
        assert!(text.contains(
            "unsafe extern \"system-unwind\" fn detour_generated_kernel32_get_current_process_id() -> u32"
        ));
        assert!(text.contains("generic_detour_with(8, &[]"));
        assert!(
            text.contains("7 => detour_generated_advapi32_reg_close_key as *const () as usize,")
        );
        assert!(text.contains("fn detour_for_generated(api_id: u32) -> usize"));
    }

    /// 実際の winmd があればシード設定全体を生成し、件数と代表例を
    /// 検査する。winmd が無い環境（ローカルで未取得の場合）では
    /// 何もせず通す（CI では fetch-winmd.sh が先に取得するため、
    /// そちらでは必ず検査される）。
    #[test]
    fn generate_seed_from_real_winmd() {
        let winmd = std::env::var("SHIRUSU_WINMD").ok().or_else(|| {
            let p = format!(
                "{}/../../target/winmd/Windows.Win32.winmd",
                env!("CARGO_MANIFEST_DIR")
            );
            if std::path::Path::new(&p).exists() {
                Some(p)
            } else {
                None
            }
        });
        let Some(winmd) = winmd else {
            eprintln!("winmd が無いため generate_seed_from_real_winmd をスキップする");
            return;
        };
        let config_path = format!("{}/apis.toml", env!("CARGO_MANIFEST_DIR"));
        let config = load_config(&config_path).expect("apis.toml を読める");
        let index = TypeIndex::read(&winmd).expect("winmd を読める");
        let generated = generate(&index, &config).expect("シード設定を生成できる");
        let skipped = generated.skipped();
        assert!(skipped.is_empty(), "unexpected skip: {skipped:?}");
        assert_eq!(generated.emitted().len(), config.apis.len());
        let emitted = generated.emitted();
        let reg_close = emitted
            .iter()
            .find(|a| a.function == "RegCloseKey")
            .expect("RegCloseKey が生成される");
        assert_eq!(reg_close.api_id, config.first_api_id);
        assert_eq!(reg_close.enter_fields.len(), 1);
        assert_eq!(reg_close.enter_fields[0].1, Ty::U64);
        assert_eq!(reg_close.enter_fields[0].2, ValueKind::Handle);
        assert_eq!(reg_close.return_ty, Some((Ty::U32, ValueKind::Scalar)));
        assert_eq!(reg_close.last_error_meaning, LastErrorMeaning::Never);
        let create_process = emitted
            .iter()
            .find(|a| a.function == "CreateProcessW")
            .expect("CreateProcessW が生成される");
        assert_eq!(create_process.enter_fields.len(), 10);
        let sleep = emitted
            .iter()
            .find(|a| a.function == "Sleep")
            .expect("Sleep が生成される");
        assert!(sleep.return_ty.is_none(), "Sleep は void 戻り");
        let get_pid = emitted
            .iter()
            .find(|a| a.function == "GetCurrentProcessId")
            .expect("GetCurrentProcessId が生成される");
        assert!(get_pid.enter_fields.is_empty(), "引数 0 個");
    }
}
