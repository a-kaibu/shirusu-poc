//! 差分エンジン：正規化済み Trace 同士を対応づけ、相違を「候補」
//! として列挙する。
//!
//! 対応づけの方針（overview「比較とテスト生成」の指定どおり、呼び出し
//! 列の単純な並列照合はしない）:
//!
//! 1. まずオブジェクトを対応づける（生成 API と生成序数）。各
//!    オブジェクトについて「そのオブジェクトへの操作列」を両側で
//!    並べ、操作の欠落・追加・順序違いと、対応操作間の引数/戻り値の
//!    相違を検出する（状態遷移の比較）。
//! 2. オブジェクトに関与しない呼び出しは、スレッド（出現順で対応）
//!    ごとに API 列を整列して比べる。
//! 3. 完全性メタデータ（Finalization の三指標、Loss Record、落ちた
//!    Payload）は別枠で比べる。片側にだけ損失がある場合、それ自体が
//!    「そもそも観測できていない」可能性を示す候補になる。
//!
//! **線引き**: ここで出すのは契約違反の「候補」であって断定では
//! ない。呼び出し順や回数が違っても両実装が契約を満たすことは
//! ありうるし、逆に記録が一致しても後続のオブジェクト状態が
//! 違うことはありうる。最終判定は Probe / 回帰テストの仕事である
//! （レビュー第3回 §4）。この留保は出力にも `CANDIDATE_NOTICE`
//! として常に付ける。

use crate::normalize::{NormCall, NormEvent, NormTrace, ObjectKey};
use shirusu_analysis::IntegritySummary;
use shirusu_trace::reader::ReadTrace;
use std::collections::{BTreeMap, HashMap, HashSet};

/// 出力に必ず付ける留保文。
pub const CANDIDATE_NOTICE: &str = "これらの差分は、記録された振る舞いの相違を正規化して提示した「契約違反の候補」であり、違反の断定ではない。呼び出し順・回数の相違は両実装とも API 契約を満たす範囲で起こりうる。最終判定は Probe / 回帰テストで行うこと。";

/// 候補の重要度（候補の並び替えと集計のため。判定ではない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// 候補の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// 左（基準側）にある呼び出しが右に無い。
    MissingCall,
    /// 右にだけある呼び出し。
    ExtraCall,
    /// 対応する呼び出しの引数（Enter 値列、または Leave の出力値）が違う。
    ArgumentDifference,
    /// 戻り値 / last_error が違う。
    ReturnDifference,
    /// Payload の内容が違う（片側だけ落ちている場合を含む）。
    PayloadDifference,
    /// オブジェクトの生成有無や操作列の構成が違う（状態遷移の相違）。
    ObjectStateDifference,
    /// 完全性メタデータの相違（損失の有無など）。
    IntegrityDifference,
    /// 取得状態（Captured か否か）が違う＝意味の復元度が違う。
    CaptureDifference,
    /// Enter/Leave の揃い方が違う（片側だけ未終了など）。
    CallShapeDifference,
}

impl CandidateKind {
    pub fn name(self) -> &'static str {
        match self {
            CandidateKind::MissingCall => "missing-call",
            CandidateKind::ExtraCall => "extra-call",
            CandidateKind::ArgumentDifference => "argument-difference",
            CandidateKind::ReturnDifference => "return-difference",
            CandidateKind::PayloadDifference => "payload-difference",
            CandidateKind::ObjectStateDifference => "object-state-difference",
            CandidateKind::IntegrityDifference => "integrity-difference",
            CandidateKind::CaptureDifference => "capture-difference",
            CandidateKind::CallShapeDifference => "call-shape-difference",
        }
    }
}

/// 根拠イベントへの参照（生の sequence は証跡として残すが、比較には
/// 使っていない。正規化後の位置で示す）。
#[derive(Debug, Clone, PartialEq)]
pub struct EventEvidence {
    /// "left" / "right"。
    pub side: &'static str,
    pub thread: usize,
    pub sequence: u64,
    pub api: String,
}

/// 差分候補 1 件。
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub severity: Severity,
    pub message: String,
    pub api: Option<String>,
    pub object: Option<ObjectKey>,
    pub field: Option<String>,
    pub left_value: Option<String>,
    pub right_value: Option<String>,
    pub left_event: Option<EventEvidence>,
    pub right_event: Option<EventEvidence>,
}

impl Candidate {
    fn new(kind: CandidateKind, severity: Severity, message: String) -> Self {
        Candidate {
            kind,
            severity,
            message,
            api: None,
            object: None,
            field: None,
            left_value: None,
            right_value: None,
            left_event: None,
            right_event: None,
        }
    }
}

/// 比較結果。
#[derive(Debug, Default)]
pub struct DiffReport {
    pub candidates: Vec<Candidate>,
    pub left_events: usize,
    pub right_events: usize,
    pub left_calls: usize,
    pub right_calls: usize,
    pub left_objects: usize,
    pub right_objects: usize,
    pub paired_objects: usize,
    /// API 別の呼び出し数（左, 右）。文脈情報であり候補ではない。
    pub api_counts: BTreeMap<String, (usize, usize)>,
}

impl DiffReport {
    pub fn is_identical(&self) -> bool {
        self.candidates.is_empty()
    }

    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.severity == severity)
            .count()
    }
}

/// 2 つの Trace を比較する。`left` が基準側（想定: Windows 実機）、
/// `right` が被検側（想定: sake）。
pub fn compare_traces(left: &ReadTrace, right: &ReadTrace) -> DiffReport {
    let nl = NormTrace::build(left);
    let nr = NormTrace::build(right);
    let mut report = DiffReport {
        left_events: nl.total_events,
        right_events: nr.total_events,
        left_calls: nl.calls.len(),
        right_calls: nr.calls.len(),
        left_objects: nl.objects.len(),
        right_objects: nr.objects.len(),
        ..Default::default()
    };
    for call in &nl.calls {
        report.api_counts.entry(call.api.clone()).or_default().0 += 1;
    }
    for call in &nr.calls {
        report.api_counts.entry(call.api.clone()).or_default().1 += 1;
    }

    compare_integrity(
        &IntegritySummary::of(left),
        &IntegritySummary::of(right),
        &mut report.candidates,
    );

    // --- オブジェクト対応と操作列の比較 ---
    let left_keys: HashSet<&ObjectKey> = nl.objects.iter().map(|o| &o.key).collect();
    let right_keys: HashSet<&ObjectKey> = nr.objects.iter().map(|o| &o.key).collect();
    let mut compared_pairs: HashSet<(usize, usize)> = HashSet::new();
    for info in &nl.objects {
        if right_keys.contains(&info.key) {
            report.paired_objects += 1;
            compare_object_ops(
                &nl,
                &nr,
                &info.key,
                &mut report.candidates,
                &mut compared_pairs,
            );
        } else {
            let mut c = Candidate::new(
                CandidateKind::ObjectStateDifference,
                Severity::Medium,
                format!(
                    "object {} is created in left but never created in right",
                    info.key.describe()
                ),
            );
            c.object = Some(info.key.clone());
            report.candidates.push(c);
        }
    }
    for info in &nr.objects {
        if !left_keys.contains(&info.key) {
            let mut c = Candidate::new(
                CandidateKind::ObjectStateDifference,
                Severity::Medium,
                format!(
                    "object {} is created in right but never created in left",
                    info.key.describe()
                ),
            );
            c.object = Some(info.key.clone());
            report.candidates.push(c);
        }
    }

    // Unpaired successful creators must also align with failed creation calls:
    // a failed call has no produced object to join through object_calls.
    // Keep creators already compared through an object out of this pass, so
    // cross-thread object matching does not gain duplicate missing/extra calls.
    let compared_left: HashSet<_> = compared_pairs.iter().map(|(l, _)| *l).collect();
    let compared_right: HashSet<_> = compared_pairs.iter().map(|(_, r)| *r).collect();
    // --- オブジェクト非関与と未対応の生成呼び出し: スレッドごとの整列比較 ---
    let plain_left: Vec<Vec<usize>> = nl
        .threads
        .iter()
        .map(|t| {
            t.iter()
                .copied()
                .filter(|&i| {
                    !nl.calls[i].involves_object()
                        || (nl.calls[i].created.is_some() && !compared_left.contains(&i))
                })
                .collect()
        })
        .collect();
    let plain_right: Vec<Vec<usize>> = nr
        .threads
        .iter()
        .map(|t| {
            t.iter()
                .copied()
                .filter(|&i| {
                    !nr.calls[i].involves_object()
                        || (nr.calls[i].created.is_some() && !compared_right.contains(&i))
                })
                .collect()
        })
        .collect();
    for t in 0..plain_left.len().max(plain_right.len()) {
        let empty = Vec::new();
        let a = plain_left.get(t).unwrap_or(&empty);
        let b = plain_right.get(t).unwrap_or(&empty);
        let steps = align(
            &a.iter()
                .map(|&i| nl.calls[i].api.as_str())
                .collect::<Vec<_>>(),
            &b.iter()
                .map(|&i| nr.calls[i].api.as_str())
                .collect::<Vec<_>>(),
        );
        for step in steps {
            match step {
                AlignStep::Pair(i, j) => {
                    let pair = (a[i], b[j]);
                    if compared_pairs.insert(pair) {
                        compare_calls(
                            &nl.calls[pair.0],
                            &nr.calls[pair.1],
                            "left",
                            "right",
                            None,
                            &mut report.candidates,
                        );
                    }
                }
                AlignStep::OnlyLeft(i) => {
                    report.candidates.push(missing_call(&nl.calls[a[i]], None));
                }
                AlignStep::OnlyRight(j) => {
                    report.candidates.push(extra_call(&nr.calls[b[j]], None));
                }
            }
        }
    }

    report.candidates.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.name().cmp(b.kind.name()))
            .then_with(|| a.message.cmp(&b.message))
    });
    report
}

fn missing_call(call: &NormCall, object: Option<ObjectKey>) -> Candidate {
    let mut c = Candidate::new(
        CandidateKind::MissingCall,
        Severity::High,
        format!("call to {} present in left is missing in right", call.api),
    );
    c.api = Some(call.api.clone());
    c.object = object;
    c.left_event = Some(evidence("left", call));
    c
}

fn extra_call(call: &NormCall, object: Option<ObjectKey>) -> Candidate {
    let mut c = Candidate::new(
        CandidateKind::ExtraCall,
        Severity::Medium,
        format!(
            "call to {} present in right has no counterpart in left",
            call.api
        ),
    );
    c.api = Some(call.api.clone());
    c.object = object;
    c.right_event = Some(evidence("right", call));
    c
}

fn evidence(side: &'static str, call: &NormCall) -> EventEvidence {
    EventEvidence {
        side,
        thread: call.thread,
        sequence: call.first_sequence,
        api: call.api.clone(),
    }
}

/// 1 オブジェクトへの操作列の比較。
fn compare_object_ops(
    nl: &NormTrace,
    nr: &NormTrace,
    key: &ObjectKey,
    out: &mut Vec<Candidate>,
    compared_pairs: &mut HashSet<(usize, usize)>,
) {
    let empty = Vec::new();
    let a_idx = nl.object_calls.get(key).unwrap_or(&empty);
    let b_idx = nr.object_calls.get(key).unwrap_or(&empty);
    let a: Vec<&NormCall> = a_idx.iter().map(|&i| &nl.calls[i]).collect();
    let b: Vec<&NormCall> = b_idx.iter().map(|&i| &nr.calls[i]).collect();
    let steps = align(
        &a.iter().map(|c| c.api.as_str()).collect::<Vec<_>>(),
        &b.iter().map(|c| c.api.as_str()).collect::<Vec<_>>(),
    );
    let mut only_left: Vec<usize> = Vec::new();
    let mut only_right: Vec<usize> = Vec::new();
    for step in steps {
        match step {
            AlignStep::Pair(i, j) => {
                let pair = (a_idx[i], b_idx[j]);
                if compared_pairs.insert(pair) {
                    compare_calls(
                        &nl.calls[pair.0],
                        &nr.calls[pair.1],
                        "left",
                        "right",
                        Some(key.clone()),
                        out,
                    );
                }
            }
            AlignStep::OnlyLeft(i) => only_left.push(i),
            AlignStep::OnlyRight(j) => only_right.push(j),
        }
    }
    // 両側に同じ API の操作が同じ個数だけ残った場合は「欠落+追加」
    // ではなく順序の相違として 1 件にまとめる。
    fn api_multiset(calls: &[&NormCall], idxs: &[usize]) -> BTreeMap<String, usize> {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for &i in idxs {
            *m.entry(calls[i].api.clone()).or_default() += 1;
        }
        m
    }
    if !only_left.is_empty()
        && !only_right.is_empty()
        && api_multiset(&a, &only_left) == api_multiset(&b, &only_right)
    {
        let mut c = Candidate::new(
            CandidateKind::ObjectStateDifference,
            Severity::Low,
            format!(
                "operations on {} occur in a different order (same multiset of calls)",
                key.describe()
            ),
        );
        c.object = Some(key.clone());
        out.push(c);
        return;
    }
    for i in only_left {
        out.push(missing_call(a[i], Some(key.clone())));
    }
    for j in only_right {
        out.push(extra_call(b[j], Some(key.clone())));
    }
}

/// 対応づいた 2 呼び出しの値比較。
fn compare_calls(
    l: &NormCall,
    r: &NormCall,
    _left_name: &'static str,
    _right_name: &'static str,
    object: Option<ObjectKey>,
    out: &mut Vec<Candidate>,
) {
    // F27: 実効 leave は completed があればそれ、無ければ leave。
    // 非同期の呼び出しは leave の値列が Unsupported のままだが、完了で
    // 実値が届く。同期の呼び出しと比べるときは、完了の値を leave の値
    // として比べる（完了の有無自体は形の相違にしない）。
    let l_leave = l.completed.as_ref().or(l.leave.as_ref());
    let r_leave = r.completed.as_ref().or(r.leave.as_ref());
    // 形の相違（未終了・中断など）。Leave と Aborted は別の終了の形
    // として区別する（L08：中断と正常終了の取り違えは差分候補）。
    if (l.enter.is_some() != r.enter.is_some())
        || (l_leave.is_some() != r_leave.is_some())
        || (l.aborted.is_some() != r.aborted.is_some())
    {
        let mut c = Candidate::new(
            CandidateKind::CallShapeDifference,
            Severity::Medium,
            format!(
                "call to {} has different shape: left enter={} leave={} aborted={}, right enter={} leave={} aborted={}",
                l.api,
                l.enter.is_some(),
                l_leave.is_some(),
                l.aborted.is_some(),
                r.enter.is_some(),
                r_leave.is_some(),
                r.aborted.is_some()
            ),
        );
        c.api = Some(l.api.clone());
        c.object = object.clone();
        c.left_event = Some(evidence("left", l));
        c.right_event = Some(evidence("right", r));
        out.push(c);
    }
    for (phase, le, re) in [
        ("enter", l.enter.as_ref(), r.enter.as_ref()),
        ("leave", l_leave, r_leave),
        ("aborted", l.aborted.as_ref(), r.aborted.as_ref()),
        ("event", l.solo.as_ref(), r.solo.as_ref()),
    ] {
        let (Some(le), Some(re)) = (le, re) else {
            continue;
        };
        compare_events(l, r, phase, le, re, &object, out);
    }
}

fn compare_events(
    l: &NormCall,
    r: &NormCall,
    phase: &str,
    le: &NormEvent,
    re: &NormEvent,
    object: &Option<ObjectKey>,
    out: &mut Vec<Candidate>,
) {
    if le.fully_captured != re.fully_captured {
        let mut c = Candidate::new(
            CandidateKind::CaptureDifference,
            Severity::Low,
            format!(
                "{} {} event capture state differs (left fully_captured={}, right={})",
                l.api, phase, le.fully_captured, re.fully_captured
            ),
        );
        c.api = Some(l.api.clone());
        c.object = object.clone();
        c.left_event = Some(evidence("left", l));
        c.right_event = Some(evidence("right", r));
        out.push(c);
    }
    let rfields: HashMap<&str, &crate::normalize::NormField> =
        re.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let mut seen: HashSet<&str> = HashSet::new();
    for lf in &le.fields {
        seen.insert(lf.name.as_str());
        match rfields.get(lf.name.as_str()) {
            Some(rf) if rf.value != lf.value => {
                let is_return =
                    phase == "leave" && (lf.name == "return" || lf.name == "last_error");
                let (kind, severity) = if is_return {
                    (CandidateKind::ReturnDifference, Severity::High)
                } else {
                    (CandidateKind::ArgumentDifference, Severity::Medium)
                };
                let mut c = Candidate::new(
                    kind,
                    severity,
                    format!(
                        "{} {} field {} differs: left={} right={}",
                        l.api,
                        phase,
                        lf.name,
                        lf.value.describe(),
                        rf.value.describe()
                    ),
                );
                c.api = Some(l.api.clone());
                c.object = object.clone();
                c.field = Some(lf.name.clone());
                c.left_value = Some(lf.value.describe());
                c.right_value = Some(rf.value.describe());
                c.left_event = Some(evidence("left", l));
                c.right_event = Some(evidence("right", r));
                out.push(c);
            }
            Some(_) => {}
            None => {
                let mut c = Candidate::new(
                    CandidateKind::ArgumentDifference,
                    Severity::Medium,
                    format!(
                        "{} {} field {} present in left is absent in right",
                        l.api, phase, lf.name
                    ),
                );
                c.api = Some(l.api.clone());
                c.object = object.clone();
                c.field = Some(lf.name.clone());
                c.left_value = Some(lf.value.describe());
                c.left_event = Some(evidence("left", l));
                c.right_event = Some(evidence("right", r));
                out.push(c);
            }
        }
    }
    for rf in &re.fields {
        if !seen.contains(rf.name.as_str()) {
            let mut c = Candidate::new(
                CandidateKind::ArgumentDifference,
                Severity::Medium,
                format!(
                    "{} {} field {} present in right is absent in left",
                    l.api, phase, rf.name
                ),
            );
            c.api = Some(l.api.clone());
            c.object = object.clone();
            c.field = Some(rf.name.clone());
            c.right_value = Some(rf.value.describe());
            c.left_event = Some(evidence("left", l));
            c.right_event = Some(evidence("right", r));
            out.push(c);
        }
    }
    if le.payload != re.payload {
        let mut c = Candidate::new(
            CandidateKind::PayloadDifference,
            Severity::Medium,
            format!(
                "{} {} payload differs: left={} right={}",
                l.api,
                phase,
                le.payload.describe(),
                re.payload.describe()
            ),
        );
        c.api = Some(l.api.clone());
        c.object = object.clone();
        c.left_value = Some(le.payload.describe());
        c.right_value = Some(re.payload.describe());
        c.left_event = Some(evidence("left", l));
        c.right_event = Some(evidence("right", r));
        out.push(c);
    }
}

/// 完全性メタデータの比較。片側にだけ損失があることは、それ自体が
/// 「比較以前の問題（観測できていない）」を示す候補になる。
fn compare_integrity(l: &IntegritySummary, r: &IntegritySummary, out: &mut Vec<Candidate>) {
    let mut push = |aspect: &str, lv: String, rv: String, severity: Severity| {
        let mut c = Candidate::new(
            CandidateKind::IntegrityDifference,
            severity,
            format!("integrity {aspect} differs: left={lv} right={rv}"),
        );
        c.field = Some(aspect.to_string());
        c.left_value = Some(lv);
        c.right_value = Some(rv);
        out.push(c);
    };
    let level = |v: Option<u32>| match v {
        Some(v) => format!("{} ({v})", shirusu_analysis::integrity_level_name(v)),
        None => "Unknown (no finalization)".to_string(),
    };
    for (aspect, lv, rv) in [
        ("capture_coverage", l.capture_coverage, r.capture_coverage),
        ("event_integrity", l.event_integrity, r.event_integrity),
        (
            "semantic_completeness",
            l.semantic_completeness,
            r.semantic_completeness,
        ),
    ] {
        if lv != rv {
            let severity = if lv == Some(0) || rv == Some(0) {
                Severity::High
            } else {
                Severity::Medium
            };
            push(aspect, level(lv), level(rv), severity);
        }
    }
    if l.loss_records_by_kind != r.loss_records_by_kind {
        push(
            "loss_records",
            format!("{:?}", l.loss_records_by_kind),
            format!("{:?}", r.loss_records_by_kind),
            Severity::Medium,
        );
    }
    if l.dropped_payload_events != r.dropped_payload_events {
        push(
            "dropped_payload_events",
            l.dropped_payload_events.to_string(),
            r.dropped_payload_events.to_string(),
            Severity::Medium,
        );
    }
    if l.missing_blob_refs != r.missing_blob_refs {
        push(
            "missing_blob_refs",
            l.missing_blob_refs.to_string(),
            r.missing_blob_refs.to_string(),
            Severity::Medium,
        );
    }
}

/// 整列ステップ。
#[derive(Debug, PartialEq)]
enum AlignStep {
    Pair(usize, usize),
    OnlyLeft(usize),
    OnlyRight(usize),
}

/// 2 列の整列（LCS）。積が上限を超える場合は貪欲な前方一致に
/// 切り替える（巨大 Trace でのメモリ爆発を避けるための劣化経路。
/// 結果が変わりうることは traceability に明記する）。
fn align(a: &[&str], b: &[&str]) -> Vec<AlignStep> {
    const MAX_CELLS: usize = 4_000_000;
    if a.len().saturating_mul(b.len()) > MAX_CELLS {
        return align_greedy(a, b);
    }
    let (n, m) = (a.len(), b.len());
    // dp[i][j] = LCS 長（a[i..], b[j..]）
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut steps = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            steps.push(AlignStep::Pair(i, j));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            steps.push(AlignStep::OnlyLeft(i));
            i += 1;
        } else {
            steps.push(AlignStep::OnlyRight(j));
            j += 1;
        }
    }
    while i < n {
        steps.push(AlignStep::OnlyLeft(i));
        i += 1;
    }
    while j < m {
        steps.push(AlignStep::OnlyRight(j));
        j += 1;
    }
    steps
}

fn align_greedy(a: &[&str], b: &[&str]) -> Vec<AlignStep> {
    let mut steps = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            steps.push(AlignStep::Pair(i, j));
            i += 1;
            j += 1;
        } else if b[j..].contains(&a[i]) {
            steps.push(AlignStep::OnlyRight(j));
            j += 1;
        } else {
            steps.push(AlignStep::OnlyLeft(i));
            i += 1;
        }
    }
    while i < a.len() {
        steps.push(AlignStep::OnlyLeft(i));
        i += 1;
    }
    while j < b.len() {
        steps.push(AlignStep::OnlyRight(j));
        j += 1;
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_basic() {
        let steps = align(&["a", "b", "c"], &["a", "c"]);
        assert_eq!(
            steps,
            vec![
                AlignStep::Pair(0, 0),
                AlignStep::OnlyLeft(1),
                AlignStep::Pair(2, 1)
            ]
        );
    }

    #[test]
    fn align_empty_sides() {
        assert_eq!(align(&[], &["x"]), vec![AlignStep::OnlyRight(0)]);
        assert_eq!(align(&["x"], &[]), vec![AlignStep::OnlyLeft(0)]);
        assert!(align(&[], &[]).is_empty());
    }

    #[test]
    fn severity_names_cover_all_variants() {
        // カバレッジ gap: Severity::name の Info/Low は候補の重要度
        // としては未使用だが、表示層の網羅として固定する。
        assert_eq!(Severity::Info.name(), "info");
        assert_eq!(Severity::Low.name(), "low");
        assert_eq!(Severity::Medium.name(), "medium");
        assert_eq!(Severity::High.name(), "high");
    }

    #[test]
    fn candidate_kind_names_cover_all_variants() {
        // カバレッジ gap: report の描画で呼ばれない種別の名前も固定。
        assert_eq!(CandidateKind::MissingCall.name(), "missing-call");
        assert_eq!(CandidateKind::ExtraCall.name(), "extra-call");
        assert_eq!(
            CandidateKind::ArgumentDifference.name(),
            "argument-difference"
        );
        assert_eq!(CandidateKind::ReturnDifference.name(), "return-difference");
        assert_eq!(
            CandidateKind::PayloadDifference.name(),
            "payload-difference"
        );
        assert_eq!(
            CandidateKind::ObjectStateDifference.name(),
            "object-state-difference"
        );
        assert_eq!(
            CandidateKind::IntegrityDifference.name(),
            "integrity-difference"
        );
        assert_eq!(
            CandidateKind::CaptureDifference.name(),
            "capture-difference"
        );
        assert_eq!(
            CandidateKind::CallShapeDifference.name(),
            "call-shape-difference"
        );
    }

    #[test]
    fn align_greedy_falls_back_for_huge_inputs() {
        // カバレッジ gap: 積が MAX_CELLS (4,000,000) を超えると
        // align_greedy へ切り替わる。2500×2500 でその経路に入る。
        let mk = |prefix: &str, n: usize| -> Vec<String> {
            (0..n).map(|i| format!("{prefix}{i}")).collect()
        };
        let a = mk("a", 2500);
        let b = mk("b", 2500);
        let a_refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let b_refs: Vec<&str> = b.iter().map(|s| s.as_str()).collect();
        let steps = align(&a_refs, &b_refs);
        // 共通要素が無いので、a 側が全て OnlyLeft の後に b 側が全て
        // OnlyRight になる（貪欲経路の contains 偽・両末尾ループ）。
        assert_eq!(steps.len(), 5000);
        assert!(steps[..2500]
            .iter()
            .all(|s| matches!(s, AlignStep::OnlyLeft(_))));
        assert!(steps[2500..]
            .iter()
            .all(|s| matches!(s, AlignStep::OnlyRight(_))));
        // 全て一致する場合は Pair だけになる。
        let steps = align(&a_refs, &a_refs);
        assert_eq!(steps.len(), 2500);
        assert!(steps.iter().all(|s| matches!(s, AlignStep::Pair(_, _))));
    }

    /// LCS の長さ（素朴な再帰＋メモ）。`align` の対応数と比べる。
    fn lcs_len(a: &[&str], b: &[&str]) -> usize {
        fn go(
            a: &[&str],
            b: &[&str],
            i: usize,
            j: usize,
            memo: &mut HashMap<(usize, usize), usize>,
        ) -> usize {
            if i == a.len() || j == b.len() {
                return 0;
            }
            if let Some(&v) = memo.get(&(i, j)) {
                return v;
            }
            let v = if a[i] == b[j] {
                go(a, b, i + 1, j + 1, memo) + 1
            } else {
                go(a, b, i + 1, j, memo).max(go(a, b, i, j + 1, memo))
            };
            memo.insert((i, j), v);
            v
        }
        go(a, b, 0, 0, &mut HashMap::new())
    }

    proptest::proptest! {
        /// 小さな入力では LCS（最長の対応）を返し、各要素をちょうど 1 回、
        /// 順に使う。貪欲経路は最長にならない入力があるため、これで区別できる。
        #[test]
        fn align_is_a_longest_common_subsequence(
            a in proptest::collection::vec(0u8..4, 0..12),
            b in proptest::collection::vec(0u8..4, 0..12),
        ) {
            let names = ["w", "x", "y", "z"];
            let a: Vec<&str> = a.iter().map(|&v| names[v as usize]).collect();
            let b: Vec<&str> = b.iter().map(|&v| names[v as usize]).collect();
            let steps = align(&a, &b);
            let (mut i, mut j, mut pairs) = (0, 0, 0);
            for s in &steps {
                match *s {
                    AlignStep::Pair(x, y) => {
                        proptest::prop_assert_eq!((x, y), (i, j));
                        proptest::prop_assert_eq!(a[x], b[y]);
                        i += 1;
                        j += 1;
                        pairs += 1;
                    }
                    AlignStep::OnlyLeft(x) => {
                        proptest::prop_assert_eq!(x, i);
                        i += 1;
                    }
                    AlignStep::OnlyRight(y) => {
                        proptest::prop_assert_eq!(y, j);
                        j += 1;
                    }
                }
            }
            proptest::prop_assert_eq!((i, j), (a.len(), b.len()));
            proptest::prop_assert_eq!(pairs, lcs_len(&a, &b));
        }
    }

    #[test]
    fn align_greedy_skips_unmatched_right_items() {
        // カバレッジ gap: 貪欲経路で b 側の先行要素を飛ばす分岐
        // （a[i] != b[j] だが a[i] が b[j..] にあるときの OnlyRight）。
        let a: Vec<String> = (0..2500).map(|i| format!("k{i}")).collect();
        let mut b: Vec<String> = Vec::with_capacity(2500);
        b.push("zz".to_string());
        b.extend((0..2499).map(|i| format!("k{i}")));
        assert_eq!(b.len(), 2500);
        let a_refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        let b_refs: Vec<&str> = b.iter().map(|s| s.as_str()).collect();
        let steps = align(&a_refs, &b_refs);
        // 最初は b の "zz" を飛ばし (OnlyRight)、その後は k0..k2498
        // が Pair になり、a の末尾 1 件 (k2499) だけ OnlyLeft になる。
        assert_eq!(steps[0], AlignStep::OnlyRight(0));
        assert_eq!(steps[1], AlignStep::Pair(0, 1));
        assert_eq!(steps[2498], AlignStep::Pair(2497, 2498));
        assert_eq!(steps[2499], AlignStep::Pair(2498, 2499));
        assert_eq!(steps[2500], AlignStep::OnlyLeft(2499));
        assert_eq!(steps.len(), 2501);
    }
}
