//! Golden 期待値（L18、overview「比較とテスト生成」）。
//!
//! 期待値の取り方は二つある。
//!
//! * **毎回取り直す方式（fresh）**: Windows で参照 Trace をその場で
//!   記録し、そこから期待ルールを導出して候補 Trace を評価する。
//!   `fresh_check` がこれを行う。ファイルは残らない。
//! * **保存済み Golden を使う方式**: `derive_from_trace` で参照 Trace
//!   から Golden ファイルを作り、`check` で候補 Trace を評価する。
//!   Golden は言語非依存の JSON（v1）で、H12 のルール形式をそのまま
//!   `rules` に載せる。`TestSpec::parse` は Golden も読める
//!   （Golden は仕様のスーパーセット）。
//!
//! Golden ファイルの形:
//!
//! ```json
//! {
//!   "version": 1,
//!   "kind": "golden",
//!   "name": "save-file-flow",
//!   "environment": {
//!     "os_version": "Windows 11",
//!     "os_build": 26100,
//!     "cpu": "AMD Ryzen 9 7950X",
//!     "cpu_arch": "x86_64",
//!     "locale": "ja-JP",
//!     "gpu": "NVIDIA GeForce RTX 4070"
//!   },
//!   "rules": [
//!     {"type": "api-called", "api": "kernel32!CreateFileW"},
//!     {"type": "no-integrity-loss"},
//!     {"type": "object-closed", "created_by": "kernel32!CreateFileW"}
//!   ]
//! }
//! ```
//!
//! 導出の規則（`derive_from_trace`）:
//!
//! * 参照 Trace に出た API ごとに `api-called`（field 条件なし）を
//!   1 件ずつ。API 名順で決定的に並べる。
//! * `no-integrity-loss` は、参照 Trace に対してそのルールが pass
//!   する場合だけ含める（`evaluate` で probe する）。参照自体に損失が
//!   あれば含めず、理由を注記に残す。
//! * `object-closed` は、参照 Trace でオブジェクトを生成した API
//!   ごとに、生成したものがすべて閉じられている場合だけ含める
//!   （同じく probe）。閉じていないものがあれば含めず注記に残す。
//! * `event-count` は導出しない。呼び出し回数は実行ごとのタイミング
//!   で変わりうるため、Golden の期待としては脆すぎる。回数の期待が
//!   要る場合は、保存済み Golden の `rules` に手で追加する。
//!
//! 導出ルールは定義上、参照 Trace 自身に対してすべて pass する
//! （自己矛盾が無いことがテストで保証される）。
//!
//! 環境情報の扱い:
//!
//! * `os_version` / `os_build` / `cpu_arch` は参照 Trace の
//!   `CaptureEnvironment` から取る。`--os-version` / `--os-build` の
//!   指定があればそちらが勝つ（環境を持たない古い Trace から作る場合用）。
//! * `cpu` / `locale` / `gpu` は Trace 形式が持たないため、記録時の
//!   指定（`GoldenOverrides`）からのみ入る。指定が無ければ unknown
//!   （JSON ではキーを省略）。Host がこれらを自動収集して
//!   `CaptureEnvironment` へ載せるのは将来の拡張であり、L18 の範囲外
//!   とする。
//! * 環境の照合（`check_environment`）は警告どまりである。Golden の
//!   環境と候補 Trace の環境が違っても、ルールが通れば pass する。
//!   環境が違えば同じ期待が当てはまらない可能性がある、という文脈を
//!   人間に示すのが目的であり、fail の判定には使わない。
//!   `cpu` / `locale` / `gpu` は候補 Trace が持たないため照合せず、
//!   報告書の環境欄に表示するだけである。

use crate::eval::{evaluate, TestReport};
use crate::json_parse::{as_str, as_u64, get, parse_json};
use crate::spec::{Rule, TestSpec};
use shirusu_analysis::{JsonValue, TraceView};
use shirusu_compare::NormTrace;
use shirusu_trace::reader::ReadTrace;
use std::collections::BTreeSet;

/// Golden に付ける環境情報。すべて任意で、欠けたものは unknown。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GoldenEnvironment {
    /// Windows のバージョン表示（例 `"Windows 11"`）。
    pub os_version: Option<String>,
    /// Windows のビルド番号（例 `26100`）。
    pub os_build: Option<u64>,
    /// CPU の機種名（例 `"AMD Ryzen 9 7950X"`）。
    pub cpu: Option<String>,
    /// CPU アーキテクチャ（例 `"x86_64"`。Trace の環境から取る）。
    pub cpu_arch: Option<String>,
    /// ロケール（例 `"ja-JP"`）。
    pub locale: Option<String>,
    /// GPU の機種名。
    pub gpu: Option<String>,
}

impl GoldenEnvironment {
    /// 何も決まっていないか。
    pub fn is_empty(&self) -> bool {
        self.os_version.is_none()
            && self.os_build.is_none()
            && self.cpu.is_none()
            && self.cpu_arch.is_none()
            && self.locale.is_none()
            && self.gpu.is_none()
    }

    /// 人間向けの 1 行表示。欠けた項目は `unknown`。
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!(
            "os_version={}",
            self.os_version.as_deref().unwrap_or("unknown")
        ));
        parts.push(format!(
            "os_build={}",
            self.os_build
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
        parts.push(format!("cpu={}", self.cpu.as_deref().unwrap_or("unknown")));
        parts.push(format!(
            "cpu_arch={}",
            self.cpu_arch.as_deref().unwrap_or("unknown")
        ));
        parts.push(format!(
            "locale={}",
            self.locale.as_deref().unwrap_or("unknown")
        ));
        parts.push(format!("gpu={}", self.gpu.as_deref().unwrap_or("unknown")));
        parts.join(" ")
    }

    fn to_json(&self) -> JsonValue {
        let mut pairs: Vec<(&str, JsonValue)> = Vec::new();
        if let Some(v) = &self.os_version {
            pairs.push(("os_version", JsonValue::Str(v.clone())));
        }
        if let Some(v) = self.os_build {
            pairs.push(("os_build", JsonValue::U64(v)));
        }
        if let Some(v) = &self.cpu {
            pairs.push(("cpu", JsonValue::Str(v.clone())));
        }
        if let Some(v) = &self.cpu_arch {
            pairs.push(("cpu_arch", JsonValue::Str(v.clone())));
        }
        if let Some(v) = &self.locale {
            pairs.push(("locale", JsonValue::Str(v.clone())));
        }
        if let Some(v) = &self.gpu {
            pairs.push(("gpu", JsonValue::Str(v.clone())));
        }
        JsonValue::obj(pairs)
    }

    fn from_json(root: &JsonValue) -> Result<GoldenEnvironment, String> {
        let mut env = GoldenEnvironment::default();
        if let Some(v) = get(root, "os_version") {
            env.os_version = Some(
                as_str(v)
                    .ok_or_else(|| "\"os_version\" must be a string".to_string())?
                    .to_string(),
            );
        }
        if let Some(v) = get(root, "os_build") {
            env.os_build =
                Some(as_u64(v).ok_or_else(|| "\"os_build\" must be an integer".to_string())?);
        }
        if let Some(v) = get(root, "cpu") {
            env.cpu = Some(
                as_str(v)
                    .ok_or_else(|| "\"cpu\" must be a string".to_string())?
                    .to_string(),
            );
        }
        if let Some(v) = get(root, "cpu_arch") {
            env.cpu_arch = Some(
                as_str(v)
                    .ok_or_else(|| "\"cpu_arch\" must be a string".to_string())?
                    .to_string(),
            );
        }
        if let Some(v) = get(root, "locale") {
            env.locale = Some(
                as_str(v)
                    .ok_or_else(|| "\"locale\" must be a string".to_string())?
                    .to_string(),
            );
        }
        if let Some(v) = get(root, "gpu") {
            env.gpu = Some(
                as_str(v)
                    .ok_or_else(|| "\"gpu\" must be a string".to_string())?
                    .to_string(),
            );
        }
        Ok(env)
    }
}

/// Golden ファイル全体。
#[derive(Debug, Clone, PartialEq)]
pub struct Golden {
    pub name: String,
    pub environment: GoldenEnvironment,
    pub spec: TestSpec,
}

impl Golden {
    pub fn parse(input: &str) -> Result<Golden, String> {
        let root = parse_json(input)?;
        Self::from_json(&root)
    }

    pub fn from_json(root: &JsonValue) -> Result<Golden, String> {
        if let Some(version) = get(root, "version") {
            match as_u64(version) {
                Some(1) => {}
                _ => return Err("unsupported golden version (only 1)".to_string()),
            }
        }
        match get(root, "kind").and_then(as_str) {
            Some("golden") => {}
            _ => return Err("not a golden file (\"kind\": \"golden\" is required)".to_string()),
        }
        let spec = TestSpec::from_json(root)?;
        let environment = match get(root, "environment") {
            Some(env_json) => GoldenEnvironment::from_json(env_json)?,
            None => GoldenEnvironment::default(),
        };
        Ok(Golden {
            name: spec.name.clone(),
            environment,
            spec,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut pairs: Vec<(&str, JsonValue)> = vec![
            ("version", JsonValue::U64(1)),
            ("kind", JsonValue::Str("golden".into())),
            ("name", JsonValue::Str(self.name.clone())),
        ];
        if !self.environment.is_empty() {
            pairs.push(("environment", self.environment.to_json()));
        }
        pairs.push((
            "rules",
            JsonValue::Array(self.spec.rules.iter().map(|r| r.to_json()).collect()),
        ));
        JsonValue::obj(pairs)
    }

    /// 人間向けの整形 JSON（ファイルへの書き出し用）。
    pub fn to_pretty_json(&self) -> String {
        self.to_json().render_pretty()
    }
}

/// 導出時に環境へ補う指定。Trace が持たない項目（cpu / locale /
/// gpu）と、環境を持たない古い Trace 用の上書き（os_version / os_build）。
#[derive(Debug, Clone, Default)]
pub struct GoldenOverrides {
    pub os_version: Option<String>,
    pub os_build: Option<u64>,
    pub cpu: Option<String>,
    pub locale: Option<String>,
    pub gpu: Option<String>,
}

fn environment_from_trace(trace: &ReadTrace, overrides: &GoldenOverrides) -> GoldenEnvironment {
    let mut env = GoldenEnvironment::default();
    if let Some(capture) = &trace.environment {
        if !capture.os_version.is_empty() {
            env.os_version = Some(capture.os_version.clone());
        }
        if capture.os_build != 0 {
            env.os_build = Some(u64::from(capture.os_build));
        }
        if !capture.cpu_arch.is_empty() {
            env.cpu_arch = Some(capture.cpu_arch.clone());
        }
    }
    if let Some(v) = &overrides.os_version {
        env.os_version = Some(v.clone());
    }
    if let Some(v) = overrides.os_build {
        env.os_build = Some(v);
    }
    if let Some(v) = &overrides.cpu {
        env.cpu = Some(v.clone());
    }
    if let Some(v) = &overrides.locale {
        env.locale = Some(v.clone());
    }
    if let Some(v) = &overrides.gpu {
        env.gpu = Some(v.clone());
    }
    env
}

/// 単一ルールを参照 Trace に対して probe する。pass したかと根拠を返す。
fn probe(rule: Rule, name: &str, trace: &ReadTrace) -> (bool, String) {
    let spec = TestSpec {
        name: name.to_string(),
        steps: Vec::new(),
        rules: vec![rule],
    };
    let report = evaluate(&spec, trace);
    let r = &report.results[0];
    (r.passed, r.detail.clone())
}

/// 参照 Trace から Golden を導出する。戻り値は Golden と、含めなかった
/// ルールの理由を並べた注記。導出ルールは参照自身にすべて pass する。
pub fn derive_from_trace(
    trace: &ReadTrace,
    name: &str,
    overrides: GoldenOverrides,
) -> (Golden, Vec<String>) {
    let view = TraceView::build(trace);
    let mut rules: Vec<Rule> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // 参照に出た API ごとに api-called。存在自体が根拠なので probe 不要。
    let apis: BTreeSet<String> = view
        .events
        .iter()
        .filter_map(|e| e.api_name.clone())
        .collect();
    for api in apis {
        rules.push(Rule::ApiCalled {
            api,
            field: None,
            equals: None,
            contains: None,
        });
    }

    // no-integrity-loss は参照が pass する場合だけ。
    let (passed, detail) = probe(Rule::NoIntegrityLoss, name, trace);
    if passed {
        rules.push(Rule::NoIntegrityLoss);
    } else {
        notes.push(format!("no-integrity-loss を含めない: {detail}"));
    }

    // object-closed は、参照で生成した API ごとに、すべて閉じている場合だけ。
    let norm = NormTrace::build(trace);
    let creators: BTreeSet<String> = norm
        .objects
        .iter()
        .map(|o| o.key.creator_api.clone())
        .collect();
    for creator in creators {
        let rule = Rule::ObjectClosed {
            created_by: creator.clone(),
        };
        let (passed, detail) = probe(rule.clone(), name, trace);
        if passed {
            rules.push(rule);
        } else {
            notes.push(format!(
                "object-closed created_by={creator} を含めない: {detail}"
            ));
        }
    }

    let golden = Golden {
        name: name.to_string(),
        environment: environment_from_trace(trace, &overrides),
        spec: TestSpec {
            name: name.to_string(),
            steps: Vec::new(),
            rules,
        },
    };
    (golden, notes)
}

/// Golden の環境と候補 Trace の環境を比べ、違いを注記として返す。
/// 不一致は警告であり、評価の pass/fail には影響しない。
/// `cpu` / `locale` / `gpu` は候補 Trace が持たないため照合しない。
pub fn check_environment(golden: &Golden, trace: &ReadTrace) -> Vec<String> {
    if golden.environment.is_empty() {
        return Vec::new();
    }
    let Some(capture) = &trace.environment else {
        return vec![
            "candidate trace carries no environment; golden environment cannot be compared"
                .to_string(),
        ];
    };
    let mut notes = Vec::new();
    let golden_env = &golden.environment;
    if let Some(want) = &golden_env.os_version {
        if !capture.os_version.is_empty() && &capture.os_version != want {
            notes.push(format!(
                "environment differs: os_version golden={want:?} candidate={:?}",
                capture.os_version
            ));
        }
    }
    if let Some(want) = golden_env.os_build {
        if capture.os_build != 0 && u64::from(capture.os_build) != want {
            notes.push(format!(
                "environment differs: os_build golden={want} candidate={}",
                capture.os_build
            ));
        }
    }
    if let Some(want) = &golden_env.cpu_arch {
        if !capture.cpu_arch.is_empty() && &capture.cpu_arch != want {
            notes.push(format!(
                "environment differs: cpu_arch golden={want:?} candidate={:?}",
                capture.cpu_arch
            ));
        }
    }
    notes
}

/// Golden による評価の報告書。環境の注記とルールの結果を持つ。
#[derive(Debug, Clone)]
pub struct GoldenReport {
    pub golden_name: String,
    pub environment: GoldenEnvironment,
    pub environment_notes: Vec<String>,
    /// fresh 方式での導出時の注記（check 方式では空）。
    pub derivation_notes: Vec<String>,
    pub report: TestReport,
}

impl GoldenReport {
    pub fn all_passed(&self) -> bool {
        self.report.all_passed()
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::obj(vec![
            ("tool", JsonValue::Str("shirusu-test".into())),
            ("mode", JsonValue::Str("golden".into())),
            ("golden", JsonValue::Str(self.golden_name.clone())),
            ("environment", self.environment.to_json()),
            (
                "environment_notes",
                JsonValue::Array(
                    self.environment_notes
                        .iter()
                        .map(|n| JsonValue::Str(n.clone()))
                        .collect(),
                ),
            ),
            (
                "derivation_notes",
                JsonValue::Array(
                    self.derivation_notes
                        .iter()
                        .map(|n| JsonValue::Str(n.clone()))
                        .collect(),
                ),
            ),
            ("passed", JsonValue::Bool(self.all_passed())),
            (
                "results",
                JsonValue::Array(
                    self.report
                        .results
                        .iter()
                        .map(|r| {
                            JsonValue::obj(vec![
                                ("rule", JsonValue::Str(r.rule.clone())),
                                ("passed", JsonValue::Bool(r.passed)),
                                ("detail", JsonValue::Str(r.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("shirusu-test golden: {:?}\n", self.golden_name));
        out.push_str(&format!("environment: {}\n", self.environment.describe()));
        for n in &self.environment_notes {
            out.push_str(&format!("note: {n}\n"));
        }
        for n in &self.derivation_notes {
            out.push_str(&format!("note: {n}\n"));
        }
        for r in &self.report.results {
            out.push_str(&format!(
                "{} {} — {}\n",
                if r.passed { "PASS" } else { "FAIL" },
                r.rule,
                r.detail
            ));
        }
        out.push_str(&format!(
            "result: {}\n",
            if self.all_passed() {
                "all rules passed"
            } else {
                "some rules failed"
            }
        ));
        out
    }
}

/// 保存済み Golden で候補 Trace を評価する。
pub fn check(golden: &Golden, trace: &ReadTrace) -> GoldenReport {
    GoldenReport {
        golden_name: golden.name.clone(),
        environment: golden.environment.clone(),
        environment_notes: check_environment(golden, trace),
        derivation_notes: Vec::new(),
        report: evaluate(&golden.spec, trace),
    }
}

/// 毎回取り直す方式：参照 Trace からその場で Golden を導出し、
/// 候補 Trace を評価する。ファイルは作らない。
pub fn fresh_check(
    reference: &ReadTrace,
    candidate: &ReadTrace,
    name: &str,
    overrides: GoldenOverrides,
) -> GoldenReport {
    let (golden, derivation_notes) = derive_from_trace(reference, name, overrides);
    GoldenReport {
        golden_name: golden.name.clone(),
        environment: golden.environment.clone(),
        environment_notes: check_environment(&golden, candidate),
        derivation_notes,
        report: evaluate(&golden.spec, candidate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_json() -> &'static str {
        r#"{"version":1,"kind":"golden","name":"save-flow",
            "environment":{"os_version":"Windows 11","os_build":26100,
                "cpu":"Test CPU","cpu_arch":"x86_64","locale":"ja-JP","gpu":"Test GPU"},
            "rules":[
                {"type":"api-called","api":"kernel32!CreateFileW"},
                {"type":"no-integrity-loss"},
                {"type":"object-closed","created_by":"kernel32!CreateFileW"}
            ]}"#
    }

    #[test]
    fn parses_and_roundtrips() {
        let golden = Golden::parse(golden_json()).unwrap();
        assert_eq!(golden.name, "save-flow");
        assert_eq!(golden.environment.os_version.as_deref(), Some("Windows 11"));
        assert_eq!(golden.environment.os_build, Some(26100));
        assert_eq!(golden.environment.cpu.as_deref(), Some("Test CPU"));
        assert_eq!(golden.environment.cpu_arch.as_deref(), Some("x86_64"));
        assert_eq!(golden.environment.locale.as_deref(), Some("ja-JP"));
        assert_eq!(golden.environment.gpu.as_deref(), Some("Test GPU"));
        assert_eq!(golden.spec.rules.len(), 3);
        // 書き出して読み直すと同一。
        let reparsed = Golden::parse(&golden.to_pretty_json()).unwrap();
        assert_eq!(reparsed, golden);
    }

    #[test]
    fn rejects_non_golden_and_bad_versions() {
        assert!(Golden::parse(r#"{"version":1,"rules":[]}"#).is_err());
        assert!(Golden::parse(r#"{"version":1,"kind":"spec","rules":[]}"#).is_err());
        assert!(Golden::parse(r#"{"version":2,"kind":"golden","rules":[]}"#).is_err());
        assert!(Golden::parse(r#"{"version":1,"kind":"golden"}"#).is_err());
        assert!(
            Golden::parse(r#"{"version":1,"kind":"golden","rules":[{"type":"nope"}]}"#).is_err()
        );
        assert!(Golden::parse(
            r#"{"version":1,"kind":"golden","environment":{"os_build":"x"},"rules":[]}"#
        )
        .is_err());
    }

    #[test]
    fn environment_defaults_to_unknown() {
        let golden =
            Golden::parse(r#"{"version":1,"kind":"golden","name":"n","rules":[]}"#).unwrap();
        assert!(golden.environment.is_empty());
        assert!(golden.environment.describe().contains("unknown"));
        // 環境が空の Golden は environment キーを書かない。
        assert!(!golden.to_pretty_json().contains("environment"));
        // 部分的な環境は、ある項目だけ残る。
        let golden = Golden::parse(
            r#"{"version":1,"kind":"golden","name":"n",
                "environment":{"locale":"ja-JP"},"rules":[]}"#,
        )
        .unwrap();
        assert_eq!(golden.environment.locale.as_deref(), Some("ja-JP"));
        assert_eq!(golden.environment.os_version, None);
        let reparsed = Golden::parse(&golden.to_pretty_json()).unwrap();
        assert_eq!(reparsed, golden);
    }

    #[test]
    fn report_renders_environment_and_notes() {
        let golden = Golden::parse(golden_json()).unwrap();
        let report = GoldenReport {
            golden_name: golden.name.clone(),
            environment: golden.environment.clone(),
            environment_notes: vec![
                "environment differs: os_build golden=26100 candidate=22000".to_string()
            ],
            derivation_notes: vec!["no-integrity-loss を含めない: x".to_string()],
            report: TestReport {
                spec_name: golden.name.clone(),
                results: vec![],
            },
        };
        let human = report.render_human();
        assert!(human.contains("shirusu-test golden"), "{human}");
        assert!(human.contains("Windows 11"), "{human}");
        assert!(human.contains("os_build golden=26100"), "{human}");
        assert!(human.contains("no-integrity-loss を含めない"), "{human}");
        let json = report.to_json().render();
        assert!(json.contains("\"mode\":\"golden\""), "{json}");
        assert!(json.contains("\"os_build\":26100"), "{json}");
    }
}
