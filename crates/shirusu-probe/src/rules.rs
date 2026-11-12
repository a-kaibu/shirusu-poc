//! 差分候補 → shirusu-test ルール（v1）の生成。
//!
//! 生成の方針は「候補の主張を、左（基準側）で pass し右（被検側）
//! で fail する最小のルールとして言い直す」こと。種別ごとに
//! 戦略（言い直しの候補）を用意し、**実際に両 Trace で評価して**
//! 言い直しが成立したものだけを採用する。評価で裏付けられない
//! 戦略は理由つきで棄却され、どの戦略も成立しなければ「ルール化
//! できない候補」として正直に返す（ブリーフのみのバンドルになる）。
//!
//! v1 ルール形式で表現できない差異は実在する：Payload の内容差分、
//! 取得状態の差分には対応するルールが無い。その場合はブリーフが
//! 人間の調査開始点になる、というのが現状の正直な限界である。

use crate::select::locate_call;
use shirusu_analysis::JsonValue;
use shirusu_compare::{Candidate, CandidateKind, NormTrace, NormValue};
use shirusu_test::{evaluate, Rule, TestSpec};
use shirusu_trace::reader::ReadTrace;

/// ルール生成の結果。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleGeneration {
    /// 採用された仕様（識別ルール 1 件のみを含む＝最小形）。
    pub spec: Option<TestSpec>,
    /// 試した戦略と、その結果（採用/棄却理由）の記録。
    pub tried: Vec<(String, String)>,
}

impl RuleGeneration {
    pub fn discriminating(&self) -> bool {
        self.spec.is_some()
    }
}

/// 正規化済みの値を、ルールの `equals` に使える JSON 値へ写す。
/// バイト列と不正な UTF-16 はタグ付き配列で保存する。オブジェクト
/// 参照・ポインタ・Blob・浮動小数点ビット列・未取得は None。
fn norm_to_json(v: &NormValue) -> Option<JsonValue> {
    match v {
        NormValue::Int(i) if *i >= 0 => u64::try_from(*i).ok().map(JsonValue::U64),
        NormValue::Int(i) => i64::try_from(*i).ok().map(JsonValue::I64),
        NormValue::Bool(b) => Some(JsonValue::Bool(*b)),
        NormValue::Text(s) => Some(JsonValue::Str(s.clone())),
        NormValue::Utf16(units) => Some(JsonValue::obj(vec![(
            "utf16",
            JsonValue::Array(
                units
                    .iter()
                    .map(|&v| JsonValue::U64(u64::from(v)))
                    .collect(),
            ),
        )])),
        NormValue::Bytes(bytes) => Some(JsonValue::obj(vec![(
            "bytes",
            JsonValue::Array(
                bytes
                    .iter()
                    .map(|&v| JsonValue::U64(u64::from(v)))
                    .collect(),
            ),
        )])),
        _ => None,
    }
}

/// 戦略 1 件＝ルール 1 件と、その説明。
struct Strategy {
    description: String,
    rule: Rule,
}

fn push(out: &mut Vec<Strategy>, description: String, rule: Rule) {
    out.push(Strategy { description, rule });
}

fn strategies(left: &ReadTrace, right: &ReadTrace, cand: &Candidate) -> Vec<Strategy> {
    let mut out: Vec<Strategy> = Vec::new();
    match cand.kind {
        CandidateKind::MissingCall => {
            if let Some(api) = &cand.api {
                push(
                    &mut out,
                    format!("missing call itself: {api} must be called"),
                    Rule::ApiCalled {
                        api: api.clone(),
                        field: None,
                        equals: None,
                        contains: None,
                    },
                );
            }
        }
        CandidateKind::ArgumentDifference | CandidateKind::ReturnDifference => {
            // 左側の関与呼び出しから、候補が指すフィールドの実際の
            // 値を引き、equals ルールにする。
            if let (Some(api), Some(field), Some(ev)) = (&cand.api, &cand.field, &cand.left_event) {
                let norm = NormTrace::build(left);
                if let Some(idx) = locate_call(&norm, ev) {
                    let call = &norm.calls[idx];
                    for phase_ev in [
                        &call.enter,
                        &call.leave,
                        &call.completed,
                        &call.aborted,
                        &call.solo,
                    ] {
                        let Some(nev) = phase_ev else { continue };
                        for f in &nev.fields {
                            if f.name == *field {
                                if let Some(json) = norm_to_json(&f.value) {
                                    push(&mut out,
                                        format!(
                                            "field equality: {api}.{field} must equal the left value"
                                        ),
                                        Rule::ApiCalled {
                                            api: api.clone(),
                                            field: Some(field.clone()),
                                            equals: Some(json),
                                            contains: None,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        CandidateKind::IntegrityDifference => {
            push(
                &mut out,
                "integrity: the left side's no-loss expectation".into(),
                Rule::NoIntegrityLoss,
            );
        }
        CandidateKind::ObjectStateDifference | CandidateKind::CallShapeDifference => {
            if let Some(obj) = &cand.object {
                push(
                    &mut out,
                    format!(
                        "object lifecycle: objects created by {} must be closed",
                        obj.creator_api
                    ),
                    Rule::ObjectClosed {
                        created_by: obj.creator_api.clone(),
                    },
                );
            }
        }
        CandidateKind::ExtraCall
        | CandidateKind::PayloadDifference
        | CandidateKind::CaptureDifference => {}
    }
    // 汎用フォールバック（種別固有の戦略が識別に失敗したときに試す）。
    if let Some(obj) = &cand.object {
        push(
            &mut out,
            format!("object presence: {} must be called", obj.creator_api),
            Rule::ApiCalled {
                api: obj.creator_api.clone(),
                field: None,
                equals: None,
                contains: None,
            },
        );
    }
    if let Some(api) = &cand.api {
        let already = out
            .iter()
            .any(|s| matches!(&s.rule, Rule::ApiCalled { api: a, field: None, .. } if a == api));
        if !already {
            push(
                &mut out,
                format!("call presence: {api} must be called"),
                Rule::ApiCalled {
                    api: api.clone(),
                    field: None,
                    equals: None,
                    contains: None,
                },
            );
        }
    }
    let (lt, rt) = (left.total_events(), right.total_events());
    if rt > lt {
        push(
            &mut out,
            format!("event budget: at most the left side's {lt} events"),
            Rule::EventCount {
                min: None,
                max: Some(lt),
            },
        );
    } else if rt < lt {
        push(
            &mut out,
            format!("event budget: at least the left side's {lt} events"),
            Rule::EventCount {
                min: Some(lt),
                max: None,
            },
        );
    }
    out
}

/// 候補から識別ルールを生成する。各戦略を両 Trace で実際に評価し、
/// 「左で pass、右で fail」になる最初の 1 件を採用する。
pub fn generate_rules(left: &ReadTrace, right: &ReadTrace, cand: &Candidate) -> RuleGeneration {
    let mut tried: Vec<(String, String)> = Vec::new();
    for strat in strategies(left, right, cand) {
        let spec = TestSpec {
            name: spec_name(cand),
            steps: Vec::new(),
            rules: vec![strat.rule.clone()],
        };
        let l = evaluate(&spec, left);
        let r = evaluate(&spec, right);
        if l.all_passed() && !r.all_passed() {
            tried.push((strat.description, "adopted".to_string()));
            return RuleGeneration {
                spec: Some(spec),
                tried,
            };
        }
        let why = if !l.all_passed() {
            format!(
                "does not pass on the left side: {}",
                l.results
                    .iter()
                    .filter(|x| !x.passed)
                    .map(|x| x.detail.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        } else {
            format!(
                "does not fail on the right side: {}",
                r.results
                    .iter()
                    .map(|x| x.detail.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        };
        tried.push((strat.description, format!("rejected: {why}")));
    }
    RuleGeneration { spec: None, tried }
}

/// バンドル名・仕様名の素になる識別子。
pub fn spec_name(cand: &Candidate) -> String {
    let api_part = cand
        .api
        .as_deref()
        .map(|a| a.rsplit('!').next().unwrap_or(a).to_ascii_lowercase())
        .unwrap_or_else(|| "integrity".to_string());
    format!("probe-{}-{}", cand.kind.name(), api_part)
}

/// TestSpec を v1 JSON 形式のテキストへ書き出す（shirusu-test の
/// パーサがそのまま読み戻せることが前提。往復はテストで固定）。
pub fn spec_to_json(spec: &TestSpec) -> String {
    spec.to_json().render_pretty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_json_roundtrips_through_the_v1_parser() {
        let spec = TestSpec {
            name: "probe-return-difference-readfile".into(),
            steps: Vec::new(),
            rules: vec![
                Rule::ApiCalled {
                    api: "kernel32!ReadFile".into(),
                    field: Some("return".into()),
                    equals: Some(JsonValue::I64(1)),
                    contains: None,
                },
                Rule::NoIntegrityLoss,
                Rule::ObjectClosed {
                    created_by: "kernel32!CreateFileW".into(),
                },
                Rule::EventCount {
                    min: Some(2),
                    max: None,
                },
            ],
        };
        let text = spec_to_json(&spec);
        let parsed = TestSpec::parse(&text).expect("generated spec must parse");
        // JSON パーサは整数を U64/I64 に正規化するため、比較は
        // 正規化後の形で行う（評価上の意味は json_equals_typed が担保）。
        assert_eq!(parsed.name, spec.name);
        assert_eq!(parsed.rules.len(), spec.rules.len());
        assert_eq!(
            parsed.rules[0],
            Rule::ApiCalled {
                api: "kernel32!ReadFile".into(),
                field: Some("return".into()),
                equals: Some(JsonValue::U64(1)),
                contains: None,
            },
            "positive integers canonicalize to U64"
        );
        assert_eq!(parsed.rules[1..], spec.rules[1..]);
    }

    #[test]
    fn norm_value_conversion_limits() {
        assert_eq!(norm_to_json(&NormValue::Int(42)), Some(JsonValue::U64(42)));
        assert_eq!(norm_to_json(&NormValue::Int(-3)), Some(JsonValue::I64(-3)));
        assert_eq!(
            norm_to_json(&NormValue::Bool(true)),
            Some(JsonValue::Bool(true))
        );
        assert_eq!(
            norm_to_json(&NormValue::Text("x".into())),
            Some(JsonValue::Str("x".into()))
        );
        assert_eq!(norm_to_json(&NormValue::Pointer), None);
        assert_eq!(norm_to_json(&NormValue::Null), None);
        assert!(norm_to_json(&NormValue::Bytes(vec![1])).is_some());
    }
}
