//! Probe ブリーフ：候補の内容と関与呼び出し列を、人間が調査を
//! 始められる最小限の形で提示する文書（Markdown）。
//!
//! 提示する値は compare と同じ正規化済みの値である（ハンドルは
//! ObjectKey、ポインタは中身を消した表現）。生のハンドル値を
//! 載せても環境が変われば意味を持たないためであり、「最小限」と
//! はこの意味でもある。候補が「違反の断定ではない」ことは
//! CANDIDATE_NOTICE を転記して明示する。

use crate::rules::RuleGeneration;
use crate::select::involved_calls;
use shirusu_analysis::IntegritySummary;
use shirusu_compare::{Candidate, NormCall, NormTrace, CANDIDATE_NOTICE};
use shirusu_trace::reader::ReadTrace;

/// ブリーフ生成に必要な文脈。
pub struct BriefContext<'a> {
    pub bundle_name: &'a str,
    pub left_label: &'a str,
    pub right_label: &'a str,
    pub candidate_index: usize,
    pub rule_generation: &'a RuleGeneration,
    /// (左の保持/総数, 右の保持/総数, 再現したか)。トリムしなかった
    /// 場合は None。
    pub trim_outcome: Option<(usize, usize, usize, usize, bool)>,
}

fn render_call(call: &NormCall, out: &mut String) {
    out.push_str(&format!("- thread {}: {}", call.thread, call.api));
    for (label, nev) in [
        ("enter", &call.enter),
        ("leave", &call.leave),
        ("event", &call.solo),
    ] {
        let Some(nev) = nev else { continue };
        let fields: Vec<String> = nev
            .fields
            .iter()
            .map(|f| format!("{}={}", f.name, f.value.describe()))
            .collect();
        out.push_str(&format!("\n  - {label}: {}", fields.join(", ")));
        if nev.payload != shirusu_compare::NormPayload::None {
            out.push_str(&format!(
                "\n  - {label} payload: {}",
                nev.payload.describe()
            ));
        }
    }
    out.push('\n');
}

fn integrity_line(name: &str, s: &IntegritySummary) -> String {
    let level = |v: Option<u32>| match v {
        Some(v) => {
            format!("{} ({v})", shirusu_analysis::integrity_level_name(v))
        }
        None => "Unknown (no finalization)".to_string(),
    };
    format!(
        "- {name}: capture_coverage={}, event_integrity={}, semantic_completeness={}, \
         loss_records={}, dropped_payloads={}, missing_blob_refs={}",
        level(s.capture_coverage),
        level(s.event_integrity),
        level(s.semantic_completeness),
        s.loss_records_by_kind.values().sum::<u64>(),
        s.dropped_payload_events,
        s.missing_blob_refs
    )
}

pub fn render_brief(
    left: &ReadTrace,
    right: &ReadTrace,
    cand: &Candidate,
    ctx: &BriefContext,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Probe ブリーフ: {}\n\n", ctx.bundle_name));
    out.push_str(&format!(
        "shirusu-compare の差分候補 #{} から生成（基準側 = {}, 被検側 = {}）。\n\n",
        ctx.candidate_index, ctx.left_label, ctx.right_label
    ));
    out.push_str(&format!("> {CANDIDATE_NOTICE}\n\n"));

    out.push_str("## 候補\n\n");
    out.push_str(&format!(
        "- 種別: {}（重要度: {}）\n",
        cand.kind.name(),
        cand.severity.name()
    ));
    out.push_str(&format!("- 内容: {}\n", cand.message));
    if let Some(api) = &cand.api {
        out.push_str(&format!("- API: {api}\n"));
    }
    if let Some(obj) = &cand.object {
        out.push_str(&format!("- 関与オブジェクト: {}\n", obj.describe()));
    }
    if let Some(field) = &cand.field {
        out.push_str(&format!(
            "- フィールド: {field}（左 = {}, 右 = {}）\n",
            cand.left_value.as_deref().unwrap_or("-"),
            cand.right_value.as_deref().unwrap_or("-")
        ));
    }
    out.push('\n');

    out.push_str("## 関与呼び出し列（正規化済み）\n\n");
    let nl = NormTrace::build(left);
    let nr = NormTrace::build(right);
    out.push_str(&format!("### {}（基準側）\n\n", ctx.left_label));
    let li = involved_calls(&nl, cand, "left");
    if li.is_empty() {
        out.push_str("- （なし）\n");
    }
    for &i in &li {
        render_call(&nl.calls[i], &mut out);
    }
    out.push_str(&format!("\n### {}（被検側）\n\n", ctx.right_label));
    let ri = involved_calls(&nr, cand, "right");
    if ri.is_empty() {
        out.push_str("- （なし）\n");
    }
    for &i in &ri {
        render_call(&nr.calls[i], &mut out);
    }
    out.push('\n');

    out.push_str("## 完全性（両側の記録がどこまで信用できるか）\n\n");
    out.push_str(&integrity_line(ctx.left_label, &IntegritySummary::of(left)));
    out.push('\n');
    out.push_str(&integrity_line(
        ctx.right_label,
        &IntegritySummary::of(right),
    ));
    out.push_str("\n\n");

    out.push_str("## ルール化の結果\n\n");
    match &ctx.rule_generation.spec {
        Some(spec) => {
            out.push_str(&format!(
                "`rules.json`（仕様名: {}）は、この候補を「基準側で pass・被検側で fail」\
                 として再現する識別ルールを含む。\n\n",
                spec.name
            ));
        }
        None => {
            out.push_str(
                "この候補は現行の shirusu-test ルール形式（v1）では識別ルール化できなかった。\
                 試した戦略と棄却理由は manifest.json の rule_generation.tried を参照。\
                 ブリーフとトリム済み Trace が調査の開始点になる。\n\n",
            );
        }
    }
    if !ctx.rule_generation.tried.is_empty() {
        out.push_str("試した戦略:\n\n");
        for (desc, outcome) in &ctx.rule_generation.tried {
            out.push_str(&format!("- {desc}: {outcome}\n"));
        }
        out.push('\n');
    }

    if let Some((lk, lt, rk, rt, reproduced)) = ctx.trim_outcome {
        out.push_str("## トリム済み Trace\n\n");
        out.push_str(&format!(
            "- left.trimmed.trace: {lk} / {lt} イベントを保持\n\
             - right.trimmed.trace: {rk} / {rt} イベントを保持\n\
             - トリム後も同じ候補が再現するか: {}\n\n",
            if reproduced {
                "再現した"
            } else {
                "再現しなかった（全 Trace で調査すること）"
            }
        ));
    }

    out.push_str("## 使い方（ippai 側）\n\n");
    out.push_str(
        "1. 新しい記録ペア（Windows 実機と sake）に対して `shirusu-test <trace> rules.json` \
         を両側で実行し、基準側 pass・被検側 fail が保たれるかを確認する。\n\
         2. 保たれる場合、このバンドルを回帰テストとして取り込む。取り込み先の\
         テストスイートでの配置・実行方法は ippai 側の規約に従う（本バンドルは\
         形式だけを定める）。\n\
         3. 候補が本当に API 契約違反かどうかは Probe / 実装側の調査で判定する。\
         本ブリーフは判定を含まない。\n",
    );
    out
}
