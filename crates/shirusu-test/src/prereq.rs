//! 前提条件の検査（L19、overview「比較とテスト生成」）。
//!
//! Trace からテスト（Probe）を生成する前に、再実行に必要なものが
//! Trace に足りているかを調べ、不足を報告する。判定は「生成できるか」
//! ではなく「不足があるか」であり、不足があっても生成そのものを禁止
//! しない。不足は生成側が補うか、運用者が与えるかの判断材料になる。
//!
//! 検査する不足（`PrereqKind`）:
//!
//! * **環境情報**：環境ブロックが無い、または OS・ビルド・
//!   アーキテクチャがすべて空だと、再実行する環境が分からない。
//! * **未完了の Trace**：Finalization が無い・正常終了でない・Loss
//!   Record や Reader の回復 issue があると、記録が途中で切れて
//!   いるかもしれず、再実行の入力が欠けている可能性がある。
//! * **呼び出し無し**：イベントが 0 件では生成するものが無い。
//! * **モジュール一覧**：モジュール分類（L07）も静的依存（L13）も
//!   無いと、どの DLL が読み込まれていたか分からない。
//! * **結び付かないハンドル**：Schema が `Handle` と宣言した引数で
//!   使われたハンドル値に、Trace 内の生成記録（`CreatedObject` の
//!   戻り値）が結び付かないもの。再実行では、どの生成呼び出しの
//!   結果を渡せばよいか分からない。L1 の生成 API は out 引数の
//!   値を記録しないため、L1 で作られたハンドルもここに現れる。
//!   そのため「記録開始前から存在した」とは断定せず、「結び付か
//!   ない」とだけ報告する。定義済み定数（HKEY_CURRENT_USER 等）は
//!   生成が不要なため除外する。
//! * **入力値の欠落**：再実行する呼び出し（トップレベルの呼び出し
//!   だけ。L15 の `top_level_events` と同じ考え方）の引数・Payload
//!   が取得できていないもの。下位呼び出しは親の実行の一部として
//!   起きるため、検査の対象外とする。
//! * **コールバックの正体不明**：コールバックイベントは元の
//!   WndProc の生アドレス（`proc`）だけを記録する。モジュール
//!   分類はベースアドレスを持たず、登録呼び出し
//!   （RegisterClassExW / SetWindowLongPtrW）は検出専用フックで
//!   記録イベントではないため、Trace だけではどの関数・どのモジュー
//!   ルルールのコールバックか特定できない。再実行では UI 操作で
//!   呼び出させるか、運用者が対応付けを与える必要がある。
//!
//! 既知の限界：
//!
//! * ハンドルの結び付けは値の一致だけで行う。Close 後に同じ生値が
//!   再利用された場合、古い生成に結び付くことがある（正規化の
//!   `resolve` と同じ近似）。
//! * `Unspecified` の U64 フィールドは推定に頼るため検査しない
//!   （レビュー #4 の #7 と同じ理由）。生成・参照の判定は Schema
//!   の意味種別（`Handle` / `CreatedObject`）だけを使う。
//! * ウィンドウの生成呼び出し（CreateWindowExW 等）は API 表に無い
//!   ため、コールバックの `hwnd` の生成元は検査しない。

use shirusu_analysis::{
    capture_name, integrity_level_name, loss_kind_name, reason_name, value_capture_name, JsonValue,
    PayloadView, Phase, TraceView,
};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{EventCapture, TypedValue, ValueCapture, ValueKind};
use std::collections::{BTreeMap, HashMap};

/// コールバックイベントの api_id。`crates/shirusu-hook/src/callback.rs`
/// の `CALLBACK_API_ID` と同じ値。shirusu-test は hook に依存しない
/// ためここで定義する。変わったら両方を直すこと。Schema 名
/// （`callback!enter` → API 名 `callback`）でも判定するため、片方
/// だけが変わっても検出は続く。
pub const CALLBACK_API_ID: u32 = 1002;

/// 定義済み HKEY 定数の範囲（HKEY_CLASSES_ROOT 0x80000000 〜
/// HKEY_DYN_DATA 0x80000006）。生成が不要な定数のため、結び付かない
/// ハンドルの検査から除外する。
const PREDEFINED_HKEY_MIN: u64 = 0x8000_0000;
const PREDEFINED_HKEY_MAX: u64 = 0x8000_0006;

/// 不足の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrereqKind {
    /// 環境ブロックが無い／環境の素性が分からない。
    MissingEnvironment,
    /// Finalization・Loss・回復 issue による未完了。
    IncompleteTrace,
    /// イベントが 0 件。
    NoCalls,
    /// モジュール分類も静的依存も無い。
    MissingModuleList,
    /// 使われたハンドルに生成記録が結び付かない。
    UnlinkedHandle,
    /// トップレベル呼び出しの入力値が欠けている。
    MissingInputValue,
    /// コールバックの関数・モジュールが特定できない。
    CallbackWithoutIdentity,
}

impl PrereqKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::MissingEnvironment => "missing-environment",
            Self::IncompleteTrace => "incomplete-trace",
            Self::NoCalls => "no-calls",
            Self::MissingModuleList => "missing-module-list",
            Self::UnlinkedHandle => "unlinked-handle",
            Self::MissingInputValue => "missing-input-value",
            Self::CallbackWithoutIdentity => "callback-without-identity",
        }
    }
}

/// 不足 1 件。種別と、人間が判断できる根拠（何が・どこで・なぜ）。
#[derive(Debug, Clone, PartialEq)]
pub struct PrereqItem {
    pub kind: PrereqKind,
    pub detail: String,
}

/// 前提条件の検査結果。
#[derive(Debug, Clone)]
pub struct PrereqReport {
    pub total_events: u64,
    pub items: Vec<PrereqItem>,
}

impl PrereqReport {
    /// 不足が無いか（テスト生成の前提が揃っているか）。
    pub fn is_ready(&self) -> bool {
        self.items.is_empty()
    }

    /// 指定した種別の不足だけを抜き出す。
    pub fn missing(&self, kind: PrereqKind) -> Vec<&PrereqItem> {
        self.items.iter().filter(|i| i.kind == kind).collect()
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::obj(vec![
            ("tool", JsonValue::Str("shirusu-test".into())),
            ("mode", JsonValue::Str("prereq".into())),
            ("ready", JsonValue::Bool(self.is_ready())),
            ("events", JsonValue::U64(self.total_events)),
            (
                "missing",
                JsonValue::Array(
                    self.items
                        .iter()
                        .map(|i| {
                            JsonValue::obj(vec![
                                ("kind", JsonValue::Str(i.kind.name().into())),
                                ("detail", JsonValue::Str(i.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "shirusu-test prereq: {} event(s)\n",
            self.total_events
        ));
        if self.items.is_empty() {
            out.push_str("result: ready — no missing prerequisites\n");
        } else {
            for i in &self.items {
                out.push_str(&format!("MISSING {} — {}\n", i.kind.name(), i.detail));
            }
            out.push_str(&format!(
                "result: {} missing prerequisite(s)\n",
                self.items.len()
            ));
        }
        out
    }
}

fn item(kind: PrereqKind, detail: String) -> PrereqItem {
    PrereqItem { kind, detail }
}

/// Trace の前提条件を検査する。項目の並びは決定的（検査の順序と、
/// 各検査内での初出順）。
pub fn check_prerequisites(trace: &ReadTrace) -> PrereqReport {
    let view = TraceView::build(trace);
    let mut items = Vec::new();
    check_environment(trace, &mut items);
    check_finalization(&view, &mut items);
    if view.events.is_empty() {
        items.push(item(
            PrereqKind::NoCalls,
            "trace contains no events; there is nothing to generate a test from".into(),
        ));
    }
    check_modules(trace, &view, &mut items);
    check_handles(trace, &view, &mut items);
    check_inputs(trace, &view, &mut items);
    check_callbacks(&view, &mut items);
    PrereqReport {
        total_events: trace.total_events(),
        items,
    }
}

fn check_environment(trace: &ReadTrace, items: &mut Vec<PrereqItem>) {
    match &trace.environment {
        None => items.push(item(
            PrereqKind::MissingEnvironment,
            "no environment block; OS version, build and CPU architecture are unknown".into(),
        )),
        Some(env) => {
            if env.os_version.is_empty()
                && env.os_build == 0
                && env.cpu_arch.is_empty()
                && env.pointer_width == 0
            {
                items.push(item(
                    PrereqKind::MissingEnvironment,
                    "environment block carries no usable identity (os_version, os_build, cpu_arch and pointer_width are all empty/zero)".into(),
                ));
            }
        }
    }
}

fn check_finalization(view: &TraceView, items: &mut Vec<PrereqItem>) {
    let s = &view.integrity;
    if !s.has_finalization {
        items.push(item(
            PrereqKind::IncompleteTrace,
            "no finalization block; completeness cannot be confirmed".into(),
        ));
    } else {
        if !s.finalized_cleanly {
            items.push(item(
                PrereqKind::IncompleteTrace,
                "trace was not finalized cleanly; recording may have ended abruptly".into(),
            ));
        }
        let mut bad: Vec<String> = Vec::new();
        for (name, level) in [
            ("capture_coverage", s.capture_coverage),
            ("event_integrity", s.event_integrity),
            ("semantic_completeness", s.semantic_completeness),
        ] {
            if let Some(level) = level {
                if level != 0 {
                    bad.push(format!("{name}={}", integrity_level_name(level)));
                }
            }
        }
        if !bad.is_empty() {
            items.push(item(
                PrereqKind::IncompleteTrace,
                format!("finalization levels are not Complete: {}", bad.join(", ")),
            ));
        }
    }
    if !s.loss_records_by_kind.is_empty() {
        let parts: Vec<String> = s
            .loss_records_by_kind
            .iter()
            .map(|(kind, count)| format!("{}×{count}", loss_kind_name(*kind)))
            .collect();
        items.push(item(
            PrereqKind::IncompleteTrace,
            format!(
                "loss records present: {} ({} lost event(s) in total)",
                parts.join(", "),
                s.total_loss_count
            ),
        ));
    }
    if !s.recovery_issues.is_empty() {
        // 種別ごとに数える（`truncated_tail(offset=42)` → `truncated_tail`）。
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for issue in &s.recovery_issues {
            let kind = issue.split('(').next().unwrap_or(issue).to_string();
            *counts.entry(kind).or_default() += 1;
        }
        let parts: Vec<String> = counts
            .iter()
            .map(|(kind, count)| format!("{kind}×{count}"))
            .collect();
        items.push(item(
            PrereqKind::IncompleteTrace,
            format!(
                "reader recovery issues: {} ({} total)",
                parts.join(", "),
                s.recovery_issues.len()
            ),
        ));
    }
}

fn check_modules(trace: &ReadTrace, view: &TraceView, items: &mut Vec<PrereqItem>) {
    if view.events.is_empty() {
        return;
    }
    let Some(env) = &trace.environment else {
        return;
    };
    if env.modules.is_empty() && env.static_dependencies.is_empty() {
        items.push(item(
            PrereqKind::MissingModuleList,
            "neither module classification (L07) nor static dependencies (L13) were recorded; test generation cannot tell which DLLs were loaded".into(),
        ));
    }
}

/// INVALID_HANDLE_VALUE の番兵値（正規化と同じ規則。ポインタ幅依存）。
/// 幅が 32 以外・不明の場合は 64bit とみなす。
fn invalid_handle_sentinel(pointer_width: u32) -> u64 {
    if pointer_width == 32 {
        0x0000_0000_FFFF_FFFF
    } else {
        u64::MAX
    }
}

fn is_predefined_hkey(raw: u64) -> bool {
    (PREDEFINED_HKEY_MIN..=PREDEFINED_HKEY_MAX).contains(&raw)
}

/// ハンドル値の生成記録と、結び付かない参照を調べる。
fn check_handles(trace: &ReadTrace, view: &TraceView, items: &mut Vec<PrereqItem>) {
    let pointer_width = trace.environment.as_ref().map_or(0, |e| e.pointer_width);
    let invalid = invalid_handle_sentinel(pointer_width);

    // 生成：Leave / Completed の `CreatedObject` フィールド。
    let mut productions: HashMap<u64, Vec<usize>> = HashMap::new();
    for ev in &view.events {
        if !matches!(ev.phase(), Phase::Leave | Phase::Completed) {
            continue;
        }
        for f in &ev.fields {
            if f.kind != ValueKind::CreatedObject || f.capture != ValueCapture::Captured {
                continue;
            }
            if let TypedValue::U64(raw) = f.value {
                if raw == 0 || raw == invalid {
                    continue;
                }
                productions.entry(raw).or_default().push(ev.index);
            }
        }
    }

    // 参照：`Handle` フィールドと、Enter 側の `CreatedObject`
    // フィールド（入力として渡されたオブジェクト）。
    struct Use {
        first_index: usize,
        api: String,
        field: String,
        count: u64,
    }
    let mut uses: HashMap<u64, Use> = HashMap::new();
    let mut order: Vec<u64> = Vec::new();
    for ev in &view.events {
        for f in &ev.fields {
            let is_ref = f.kind == ValueKind::Handle
                || (f.kind == ValueKind::CreatedObject && ev.phase() == Phase::Enter);
            if !is_ref || f.capture != ValueCapture::Captured {
                continue;
            }
            let TypedValue::U64(raw) = f.value else {
                continue;
            };
            if raw == 0 || raw == invalid || is_predefined_hkey(raw) {
                continue;
            }
            let linked = productions
                .get(&raw)
                .is_some_and(|idxs| idxs.iter().any(|&i| i <= ev.index));
            if linked {
                continue;
            }
            match uses.get_mut(&raw) {
                Some(u) => u.count += 1,
                None => {
                    order.push(raw);
                    uses.insert(
                        raw,
                        Use {
                            first_index: ev.index,
                            api: ev
                                .api_name
                                .clone()
                                .unwrap_or_else(|| format!("api#{}", ev.api_id)),
                            field: f.name.clone(),
                            count: 1,
                        },
                    );
                }
            }
        }
    }
    // 初出順に並べる（決定的）。
    order.sort_by_key(|raw| uses[raw].first_index);
    for raw in order {
        let u = &uses[&raw];
        items.push(item(
            PrereqKind::UnlinkedHandle,
            format!(
                "handle 0x{raw:x} used by {} field {} (first event #{}, {} reference(s)) is not linked to any recorded creation; the trace cannot tell which earlier call produced it (L1 out-parameter creations are not value-recorded, so handles created by L1 calls appear here too)",
                u.api, u.field, u.first_index, u.count
            ),
        ));
    }
}

/// トップレベル呼び出しの入力値の欠落を調べる。同じ API・同じ項目の
/// 欠落は 1 件にまとめ、初出イベントと件数を残す。
fn check_inputs(trace: &ReadTrace, view: &TraceView, items: &mut Vec<PrereqItem>) {
    struct Gap {
        first_index: usize,
        reason: String,
        count: u64,
    }
    let mut gaps: HashMap<(String, String), Gap> = HashMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    let mut add = |key: (String, String), reason: String, index: usize| match gaps.get_mut(&key) {
        Some(g) => g.count += 1,
        None => {
            order.push(key.clone());
            gaps.insert(
                key,
                Gap {
                    first_index: index,
                    reason,
                    count: 1,
                },
            );
        }
    };
    for ev in &view.events {
        // 再実行するのはトップレベルの呼び出しだけ（L15）。
        if ev.parent_call_id != 0 {
            continue;
        }
        let api = ev
            .api_name
            .clone()
            .unwrap_or_else(|| format!("api#{}", ev.api_id));
        if ev.capture != EventCapture::Captured {
            add(
                (api.clone(), "event capture".into()),
                format!("event capture is {}", capture_name(ev.capture)),
                ev.index,
            );
        }
        if let Some(err) = &ev.args_error {
            add(
                (api.clone(), "args".into()),
                format!("arguments undecodable: {err}"),
                ev.index,
            );
        }
        for f in &ev.fields {
            if f.capture != ValueCapture::Captured {
                add(
                    (api.clone(), f.name.clone()),
                    format!("field {} is <{}>", f.name, value_capture_name(f.capture)),
                    ev.index,
                );
            }
        }
        match &ev.payload {
            PayloadView::Dropped {
                original_len,
                reason,
            } => {
                add(
                    (api.clone(), "payload".into()),
                    format!(
                        "payload dropped (len={original_len}, reason={})",
                        reason_name(*reason)
                    ),
                    ev.index,
                );
            }
            PayloadView::Blob(id) if !trace.blobs.contains_key(id) => {
                add(
                    (api.clone(), "payload".into()),
                    format!("payload blob {id} is missing from the file"),
                    ev.index,
                );
            }
            _ => {}
        }
    }
    order.sort_by_key(|key| gaps[key].first_index);
    for key in order {
        let g = &gaps[&key];
        items.push(item(
            PrereqKind::MissingInputValue,
            format!(
                "{} {} (first event #{}, {} occurrence(s))",
                key.0, g.reason, g.first_index, g.count
            ),
        ));
    }
}

fn is_callback_event(api_id: u32, api_name: Option<&str>) -> bool {
    api_id == CALLBACK_API_ID || api_name == Some("callback")
}

/// コールバックの正体不明を調べる。同じ proc の呼び出しは 1 件にまとめる。
fn check_callbacks(view: &TraceView, items: &mut Vec<PrereqItem>) {
    struct ProcUse {
        first_index: usize,
        count: u64,
        messages: Vec<u32>,
    }
    let mut procs: HashMap<u64, ProcUse> = HashMap::new();
    let mut order: Vec<u64> = Vec::new();
    let mut no_proc: u64 = 0;
    for ev in &view.events {
        if ev.phase() != Phase::Enter {
            continue;
        }
        if !is_callback_event(ev.api_id, ev.api_name.as_deref()) {
            continue;
        }
        let proc = match ev.field("proc") {
            Some(f) if f.capture == ValueCapture::Captured => match f.value {
                TypedValue::U64(raw) if raw != 0 => Some(raw),
                _ => None,
            },
            _ => None,
        };
        let Some(proc) = proc else {
            no_proc += 1;
            continue;
        };
        let message = match ev.field("message") {
            Some(f) if f.capture == ValueCapture::Captured => match f.value {
                TypedValue::U32(m) => Some(m),
                _ => None,
            },
            _ => None,
        };
        match procs.get_mut(&proc) {
            Some(u) => {
                u.count += 1;
                if let Some(m) = message {
                    if !u.messages.contains(&m) {
                        u.messages.push(m);
                    }
                }
            }
            None => {
                order.push(proc);
                procs.insert(
                    proc,
                    ProcUse {
                        first_index: ev.index,
                        count: 1,
                        messages: message.into_iter().collect(),
                    },
                );
            }
        }
    }
    order.sort_by_key(|proc| procs[proc].first_index);
    for proc in order {
        let u = &procs[&proc];
        let messages = if u.messages.is_empty() {
            "unknown".to_string()
        } else {
            let parts: Vec<String> = u.messages.iter().map(|m| format!("0x{m:x}")).collect();
            parts.join(", ")
        };
        items.push(item(
            PrereqKind::CallbackWithoutIdentity,
            format!(
                "callback proc 0x{proc:x} was invoked {} time(s) (messages [{}], first event #{}) but its identity cannot be determined from this trace: module base addresses are not recorded, and the registration call (RegisterClassExW / SetWindowLongPtrW) is not a recorded event",
                u.count, messages, u.first_index
            ),
        ));
    }
    if no_proc > 0 {
        items.push(item(
            PrereqKind::CallbackWithoutIdentity,
            format!(
                "{no_proc} callback invocation(s) carry no recorded proc address; the callback cannot be identified at all"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(PrereqKind::MissingEnvironment.name(), "missing-environment");
        assert_eq!(PrereqKind::IncompleteTrace.name(), "incomplete-trace");
        assert_eq!(PrereqKind::NoCalls.name(), "no-calls");
        assert_eq!(PrereqKind::MissingModuleList.name(), "missing-module-list");
        assert_eq!(PrereqKind::UnlinkedHandle.name(), "unlinked-handle");
        assert_eq!(PrereqKind::MissingInputValue.name(), "missing-input-value");
        assert_eq!(
            PrereqKind::CallbackWithoutIdentity.name(),
            "callback-without-identity"
        );
    }

    #[test]
    fn report_renders_ready_and_missing() {
        let ready = PrereqReport {
            total_events: 3,
            items: vec![],
        };
        assert!(ready.is_ready());
        assert!(ready.render_human().contains("ready"));
        let json = ready.to_json().render();
        assert!(json.contains("\"mode\":\"prereq\""), "{json}");
        assert!(json.contains("\"ready\":true"), "{json}");

        let missing = PrereqReport {
            total_events: 3,
            items: vec![item(PrereqKind::NoCalls, "trace contains no events".into())],
        };
        assert!(!missing.is_ready());
        assert_eq!(missing.missing(PrereqKind::NoCalls).len(), 1);
        assert!(missing.missing(PrereqKind::UnlinkedHandle).is_empty());
        let human = missing.render_human();
        assert!(human.contains("MISSING no-calls"), "{human}");
        assert!(human.contains("1 missing prerequisite(s)"), "{human}");
        let json = missing.to_json().render();
        assert!(json.contains("\"kind\":\"no-calls\""), "{json}");
    }

    #[test]
    fn predefined_hkey_range_is_exact() {
        assert!(is_predefined_hkey(0x8000_0000));
        assert!(is_predefined_hkey(0x8000_0006));
        assert!(!is_predefined_hkey(0x8000_0007));
        assert!(!is_predefined_hkey(0x100));
    }

    #[test]
    fn invalid_handle_sentinel_follows_pointer_width() {
        assert_eq!(invalid_handle_sentinel(32), 0x0000_0000_FFFF_FFFF);
        assert_eq!(invalid_handle_sentinel(64), u64::MAX);
        assert_eq!(invalid_handle_sentinel(0), u64::MAX);
    }
}
