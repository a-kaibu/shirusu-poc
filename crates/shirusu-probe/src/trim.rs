//! Trace のトリミング：候補が関与する呼び出しだけを残した Trace
//! ペアを再構成する。
//!
//! 再構成の方針：
//! - イベントの選択は正規化側の関与呼び出し（select）から決め、
//!   ビュー上の位置（平坦化インデックス）で元の TraceEvent を引く。
//! - Batch 文脈（セッション/プロセス/スレッド/QPC 周波数）、
//!   sequence、タイムスタンプ、引数バイト列、Payload は元のまま
//!   保つ（＝切り詰めは「抜き出し」であって「再解釈」ではない）。
//! - 参照される Blob は内容アドレスのまま先に登録するので、
//!   Blob ID も元のまま一致する。
//! - Schema は残したイベントが使うものだけを、元の登録順で登録
//!   する。Loss Record はセッションの文脈として全て残す。
//! - Finalization の総数は Writer が再計算する。完全性 3 指標は
//!   元 Trace の申告を引き継ぎ、トリムであることを notes に残す
//!   （トリム済み Trace は「セッション全体の記録」ではなく、
//!   差分の再現用スライスである、という位置づけを明記する）。
//!
//! 切り詰めても同じ候補が再現するかは、生成後に compare を
//! 再実行して確認する（`verify_trimmed`）。再現しない場合は
//! 呼び出し側がその旨をバンドルへ正直に記録する。

use crate::select::involved_calls;
use shirusu_analysis::TraceView;
use shirusu_compare::{compare_traces, Candidate, NormTrace};
use shirusu_trace::compact::decode_values;
use shirusu_trace::error::TraceError;
use shirusu_trace::model::{EventBatch, PayloadRef};
use shirusu_trace::proto::{integrity_level, CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::TypedValue;
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};
use shirusu_trace::BlobId;
use std::collections::{HashMap, HashSet};

/// トリム結果。
#[derive(Debug)]
pub struct TrimmedTrace {
    pub bytes: Vec<u8>,
    pub kept_events: usize,
    pub total_events: usize,
}

/// 片側の Trace を、関与呼び出しのイベントだけに切り詰める。
pub fn trim_trace(
    source: &ReadTrace,
    cand: &Candidate,
    side: &'static str,
    source_label: &str,
) -> Result<TrimmedTrace, TraceError> {
    let norm = NormTrace::build(source);
    let call_indices = involved_calls(&norm, cand, side);
    // 関与呼び出しのイベントを (正準スレッド序数, sequence) で特定する。
    let view = TraceView::build(source);
    let mut ordinal_of: HashMap<(u64, u64, u64), usize> = HashMap::new();
    let mut view_index_of: HashMap<(usize, u64), usize> = HashMap::new();
    for ev in &view.events {
        let key = (ev.session_id, ev.process_id, ev.thread_id);
        let next = ordinal_of.len();
        let ordinal = *ordinal_of.entry(key).or_insert(next);
        view_index_of.insert((ordinal, ev.sequence), ev.index);
    }
    let mut keep: HashSet<usize> = HashSet::new();
    for &ci in &call_indices {
        let call = &norm.calls[ci];
        for nev in [&call.enter, &call.leave, &call.solo].into_iter().flatten() {
            if let Some(&vi) = view_index_of.get(&(call.thread, nev.sequence)) {
                keep.insert(vi);
            }
        }
    }

    // 元の Batch 列を走査し、残すイベントだけを元の文脈で保つ。
    let mut batches: Vec<EventBatch> = Vec::new();
    let mut global = 0usize;
    let mut kept_events = 0usize;
    let mut used_schemas: Vec<u32> = Vec::new();
    let mut blob_ids: Vec<BlobId> = Vec::new();
    let mut seen_blob: HashSet<BlobId> = HashSet::new();
    for batch in &source.batches {
        let mut events = Vec::new();
        for e in &batch.events {
            if keep.contains(&global) {
                events.push(e.clone());
                kept_events += 1;
                if e.schema_id != 0 && !used_schemas.contains(&e.schema_id) {
                    used_schemas.push(e.schema_id);
                }
                if let PayloadRef::Blob(id) = &e.payload {
                    if seen_blob.insert(*id) {
                        blob_ids.push(*id);
                    }
                }
                // 引数値列の中の BlobRef も解決可能な状態で残す。
                if let (Some(types), Some(args)) =
                    (source.registry.types(e.schema_id), e.args.as_deref())
                {
                    if let Ok(values) = decode_values(&types, args) {
                        for v in values {
                            if let TypedValue::BlobRef(id) = v.value {
                                if seen_blob.insert(id) {
                                    blob_ids.push(id);
                                }
                            }
                        }
                    }
                }
            }
            global += 1;
        }
        if !events.is_empty() {
            batches.push(EventBatch {
                session_id: batch.session_id,
                process_id: batch.process_id,
                raw_pid: batch.raw_pid,
                thread_id: batch.thread_id,
                qpc_frequency: batch.qpc_frequency,
                events,
            });
        }
    }

    // Writer で再構成する。環境は元を引き継ぐ（無い場合は理由を
    // 明記した最小環境を作る）。
    let environment = source
        .environment
        .clone()
        .unwrap_or_else(|| CaptureEnvironment {
            session: SessionMetadata {
                session_id: source.header.session_id,
                created_by: "shirusu-probe (trimmed; source environment was missing)".into(),
                qpc_frequency: 0,
            },
            ..Default::default()
        });
    let mut writer = TraceWriter::new(Vec::new(), environment)?;
    // Schema は元の登録順を保って、使うものだけ登録する。
    for id in source.registry.ids() {
        if used_schemas.contains(id) {
            if let Some(def) = source.registry.get(*id) {
                writer.register_schema(def.clone())?;
            }
        }
    }
    for id in &blob_ids {
        if let Some(content) = source.blobs.get(id) {
            let assigned = writer.add_payload(content)?;
            debug_assert_eq!(&assigned, id, "blob ids are content addressed");
        }
    }
    for batch in &batches {
        writer.write_batch(batch)?;
    }
    writer.write_loss_records(&source.loss_records)?;
    let (cc, ei, sc) = match &source.finalization {
        Some(fin) => (
            fin.capture_coverage,
            fin.event_integrity,
            fin.semantic_completeness,
        ),
        None => (
            integrity_level::UNKNOWN,
            integrity_level::UNKNOWN,
            integrity_level::UNKNOWN,
        ),
    };
    let mut notes = source
        .finalization
        .as_ref()
        .map(|f| f.notes.clone())
        .unwrap_or_default();
    notes.push(format!(
        "trimmed by shirusu-probe from {source_label}: {kept_events} of {} events kept; \
         this is a partial slice for diff reproduction, not a complete session record; \
         integrity levels are inherited from the source trace",
        source.total_events()
    ));
    let bytes = writer.finish(FinalizationInfo {
        capture_coverage: cc,
        event_integrity: ei,
        semantic_completeness: sc,
        notes,
    })?;
    Ok(TrimmedTrace {
        bytes,
        kept_events,
        total_events: source.total_events() as usize,
    })
}

/// トリム済みペアで同じ候補が再現するかを確認する。再現の基準は
/// 「同じ種別で、API が一致し（候補が API を持つ場合）、関与
/// オブジェクトの生成 API が一致する（持つ場合）」こと。序数は
/// トリムでずれうるため同一性の判定には使わない。
pub fn verify_trimmed(left: &ReadTrace, right: &ReadTrace, original: &Candidate) -> bool {
    let report = compare_traces(left, right);
    report.candidates.iter().any(|c| {
        c.kind == original.kind
            && (original.api.is_none() || c.api == original.api)
            && (original.object.is_none()
                || c.object.as_ref().map(|o| &o.creator_api)
                    == original.object.as_ref().map(|o| &o.creator_api))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::container::FileHeader;
    use shirusu_trace::model::TraceEvent;
    use shirusu_trace::proto::Finalization;
    use shirusu_trace::schema::{make_schema, EventCapture, SchemaRegistry, Ty};

    fn ev(kind: u16, sequence: u64, call_id: u64, schema_id: u32) -> TraceEvent {
        TraceEvent {
            kind,
            sequence,
            timestamp_qpc: sequence * 10,
            call_id,
            parent_call_id: 0,
            api_id: 1,
            schema_id,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
        }
    }

    fn two_call_trace() -> ReadTrace {
        let mut registry = SchemaRegistry::new();
        for (id, name) in [
            (1, "x!A/enter"),
            (2, "x!A/leave"),
            (3, "x!B/enter"),
            (4, "x!B/leave"),
        ] {
            let fields = if name.ends_with("/leave") {
                vec![
                    ("return".into(), Ty::U64, 0),
                    ("last_error".into(), Ty::U32, 0),
                ]
            } else {
                vec![("h".into(), Ty::U64, 0)]
            };
            registry.register(make_schema(id, name, fields)).unwrap();
        }
        let schemas: Vec<_> = registry
            .ids()
            .iter()
            .map(|id| registry.get(*id).unwrap().clone())
            .collect();
        ReadTrace {
            header: FileHeader::new(1),
            environment: Some(CaptureEnvironment {
                session: SessionMetadata {
                    session_id: 1,
                    created_by: "trim-test".into(),
                    qpc_frequency: 10_000_000,
                },
                ..Default::default()
            }),
            schemas,
            registry,
            batches: vec![EventBatch {
                session_id: 1,
                process_id: 1,
                raw_pid: 1,
                thread_id: 1,
                qpc_frequency: 10_000_000,
                events: vec![
                    ev(1, 1, 1, 1),
                    ev(2, 2, 1, 2),
                    ev(1, 3, 2, 3),
                    ev(2, 4, 2, 4),
                ],
            }],
            blobs: Default::default(),
            loss_records: Vec::new(),
            stored_index: None,
            index_matches_scan: false,
            finalization: Some(Finalization {
                total_events: 4,
                ..Default::default()
            }),
            finalized_cleanly: true,
            blocks: Vec::new(),
            issues: Vec::new(),
        }
    }

    #[test]
    fn trim_keeps_only_involved_call_events() {
        // 左は A の後に B、右は A だけ → B が MissingCall 候補になる。
        let left = two_call_trace();
        let mut right = two_call_trace();
        right.batches[0].events.truncate(2);
        right.finalization.as_mut().unwrap().total_events = 2;
        let report = compare_traces(&left, &right);
        let cand = report
            .candidates
            .iter()
            .find(|c| c.kind == shirusu_compare::CandidateKind::MissingCall)
            .expect("missing call candidate")
            .clone();

        let tl = trim_trace(&left, &cand, "left", "left.trace").unwrap();
        assert_eq!(tl.kept_events, 2);
        assert_eq!(tl.total_events, 4);
        let tr = trim_trace(&right, &cand, "right", "right.trace").unwrap();
        assert_eq!(tr.kept_events, 0);

        let tl_read = shirusu_trace::read_trace(&tl.bytes).unwrap();
        let tr_read = shirusu_trace::read_trace(&tr.bytes).unwrap();
        assert!(verify_trimmed(&tl_read, &tr_read, &cand));
    }
}
