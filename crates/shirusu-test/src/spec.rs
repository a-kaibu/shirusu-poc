//! 期待ルールの仕様（JSON が正規形式。overview「比較とテスト生成」）。
//!
//! 仕様ファイルの形（v1）:
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "save-file-flow",
//!   "rules": [
//!     {"type": "api-called", "api": "kernel32!CreateFileW"},
//!     {"type": "api-called", "api": "kernel32!ReadFile",
//!      "field": "nNumberOfBytesToRead", "equals": 4},
//!     {"type": "api-called", "api": "kernel32!CreateFileW",
//!      "field": "lpFileName", "contains": "save.dat"},
//!     {"type": "no-integrity-loss"},
//!     {"type": "object-closed", "created_by": "kernel32!CreateFileW"},
//!     {"type": "event-count", "min": 6, "max": 100}
//!   ]
//! }
//! ```
//!
//! ルールは「Trace に対する期待」の表明であり、API 契約そのものの
//! 判定ではない（compare の候補と同じ線引き）。Phase 5 では、差分
//! 候補からこの形式の最小仕様（Probe）を生成する想定であり、
//! そのため形式は言語非依存の JSON に固定する。

use crate::json_parse::{as_str, as_u64, get};
use shirusu_analysis::JsonValue;

/// ルール 1 件。
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// 指定 API が呼ばれていること。`field` を付けると、その
    /// フィールド値への条件（equals / contains のどちらか）も課す。
    ApiCalled {
        api: String,
        field: Option<String>,
        equals: Option<JsonValue>,
        contains: Option<String>,
    },
    /// Event Integrity（および、指定されれば三指標すべて）に
    /// 損失が無いこと。判定の内訳は eval 側に明記する。
    NoIntegrityLoss,
    /// `created_by` が生成したオブジェクトがすべて Close 系 API で
    /// 閉じられていること。生成が 1 件も無い場合は失敗とする
    /// （空虚な真は、記録自体が欠けている可能性を隠すため）。
    ObjectClosed { created_by: String },
    /// 総イベント数の範囲。
    EventCount { min: Option<u64>, max: Option<u64> },
}

impl Rule {
    /// 人間向けの 1 行表現（結果表示と対応づけるため）。
    pub fn describe(&self) -> String {
        match self {
            Rule::ApiCalled {
                api,
                field,
                equals,
                contains,
            } => {
                let mut s = format!("api-called {api}");
                if let Some(field) = field {
                    s.push_str(&format!(" field {field}"));
                    if let Some(e) = equals {
                        s.push_str(&format!(" equals {}", e.render()));
                    }
                    if let Some(c) = contains {
                        s.push_str(&format!(" contains {c:?}"));
                    }
                }
                s
            }
            Rule::NoIntegrityLoss => "no-integrity-loss".to_string(),
            Rule::ObjectClosed { created_by } => format!("object-closed created_by={created_by}"),
            Rule::EventCount { min, max } => {
                format!("event-count min={:?} max={:?}", min, max)
            }
        }
    }
}

/// 仕様ファイル全体。
#[derive(Debug, Clone, PartialEq)]
pub struct TestSpec {
    pub name: String,
    pub rules: Vec<Rule>,
}

impl TestSpec {
    pub fn parse(input: &str) -> Result<TestSpec, String> {
        let root = crate::json_parse::parse_json(input)?;
        Self::from_json(&root)
    }

    pub fn from_json(root: &JsonValue) -> Result<TestSpec, String> {
        if let Some(version) = get(root, "version") {
            match as_u64(version) {
                Some(1) => {}
                _ => return Err("unsupported spec version (only 1)".to_string()),
            }
        }
        let name = get(root, "name")
            .and_then(as_str)
            .unwrap_or("(unnamed)")
            .to_string();
        let rules_json =
            get(root, "rules").ok_or_else(|| "spec has no \"rules\" array".to_string())?;
        let JsonValue::Array(items) = rules_json else {
            return Err("\"rules\" must be an array".to_string());
        };
        let mut rules = Vec::new();
        for (i, item) in items.iter().enumerate() {
            rules.push(parse_rule(item).map_err(|e| format!("rules[{i}]: {e}"))?);
        }
        Ok(TestSpec { name, rules })
    }
}

fn parse_rule(item: &JsonValue) -> Result<Rule, String> {
    let ty = get(item, "type")
        .and_then(as_str)
        .ok_or_else(|| "rule has no \"type\"".to_string())?;
    match ty {
        "api-called" => {
            let api = get(item, "api")
                .and_then(as_str)
                .ok_or_else(|| "api-called needs \"api\"".to_string())?
                .to_string();
            let field = get(item, "field").and_then(as_str).map(str::to_string);
            let equals = get(item, "equals").cloned();
            let contains = get(item, "contains").and_then(as_str).map(str::to_string);
            if field.is_none() && (equals.is_some() || contains.is_some()) {
                return Err("equals/contains need \"field\"".to_string());
            }
            if equals.is_some() && contains.is_some() {
                return Err("equals and contains are exclusive".to_string());
            }
            Ok(Rule::ApiCalled {
                api,
                field,
                equals,
                contains,
            })
        }
        "no-integrity-loss" => Ok(Rule::NoIntegrityLoss),
        "object-closed" => {
            let created_by = get(item, "created_by")
                .and_then(as_str)
                .ok_or_else(|| "object-closed needs \"created_by\"".to_string())?
                .to_string();
            Ok(Rule::ObjectClosed { created_by })
        }
        "event-count" => {
            let min = get(item, "min").and_then(as_u64);
            let max = get(item, "max").and_then(as_u64);
            if min.is_none() && max.is_none() {
                return Err("event-count needs \"min\" and/or \"max\"".to_string());
            }
            Ok(Rule::EventCount { min, max })
        }
        other => Err(format!("unknown rule type: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_spec() {
        let spec = TestSpec::parse(
            r#"{"version":1,"name":"t","rules":[
                {"type":"api-called","api":"kernel32!ReadFile","field":"n","equals":4},
                {"type":"no-integrity-loss"},
                {"type":"object-closed","created_by":"kernel32!CreateFileW"},
                {"type":"event-count","min":1}
            ]}"#,
        )
        .unwrap();
        assert_eq!(spec.name, "t");
        assert_eq!(spec.rules.len(), 4);
        assert_eq!(
            spec.rules[0].describe(),
            "api-called kernel32!ReadFile field n equals 4"
        );
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(TestSpec::parse(r#"{"version":2,"rules":[]}"#).is_err());
        assert!(TestSpec::parse(r#"{"rules":[{"type":"nope"}]}"#).is_err());
        assert!(TestSpec::parse(r#"{"rules":[{"type":"api-called"}]}"#).is_err());
        assert!(
            TestSpec::parse(r#"{"rules":[{"type":"api-called","api":"x","equals":1}]}"#).is_err()
        );
        assert!(TestSpec::parse(r#"{"rules":[{"type":"event-count"}]}"#).is_err());
        assert!(TestSpec::parse("not json").is_err());
    }
}
