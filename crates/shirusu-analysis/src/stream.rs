//! Trace を 1 Block ずつ読み、イベントを保持せずに集計する経路
//! （2026-11-14 レビュー P1-4）。
//!
//! 全体読み込み（`read_trace` + [`crate::TraceView::build`]）はファイル全体、
//! 全イベントの `TraceEvent`、全イベントの [`crate::EventView`] を同時に
//! メモリへ載せる。約 3,355 万イベントで `EventView` の Vec が 16GB の
//! 確保を要求し、`shirusu inspect` が失敗していた。ここではイベントを
//! 呼び出し側の関数へ 1 件ずつ渡し、メタデータと完全性の集計だけを残す。

use crate::view::{IntegrityCounts, IntegritySummary};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::schema::SchemaRegistry;
use shirusu_trace::stream::{StreamItem, StreamOptions, TraceStream};
use shirusu_trace::{BlobId, ReaderLimits, Result};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

/// ストリーミングで読んだ Trace の集計。
pub struct StreamedTrace {
    /// メタデータ。`batches` と `blobs` は空（イベントと Blob の内容は
    /// 保持しない）。それ以外は全体読み込みと同じ値を持つ。
    pub meta: ReadTrace,
    pub total_events: u64,
    pub batch_count: u64,
    /// 格納された Blob と、更新で生まれた版の数。
    pub blob_count: u64,
    pub blob_bytes: u64,
    pub integrity: IntegritySummary,
}

/// `inner` を先頭から読み、各イベントを `visit` へ渡す。
/// `visit` には、そのイベントの時点の Schema 登録表と Batch の文脈を渡す。
pub fn stream_trace<R: Read + Seek>(
    mut inner: R,
    mut visit: impl FnMut(&SchemaRegistry, &EventBatch, &TraceEvent),
) -> Result<StreamedTrace> {
    let len = inner.seek(SeekFrom::End(0))?;
    let mut stream = TraceStream::with_options(
        inner,
        StreamOptions {
            decode_events: true,
            yield_blobs: true,
            limits: ReaderLimits::for_input_len(len),
        },
    )?;
    let mut meta = ReadTrace {
        header: *stream.header(),
        environment: None,
        schemas: Vec::new(),
        registry: SchemaRegistry::new(),
        batches: Vec::new(),
        blobs: HashMap::new(),
        blob_updates: Vec::new(),
        resource_versions: HashMap::new(),
        loss_records: Vec::new(),
        stored_index: None,
        index_matches_scan: false,
        finalization: None,
        finalized_cleanly: false,
        profile_summary: None,
        blocks: Vec::new(),
        issues: Vec::new(),
    };
    let mut counts = IntegrityCounts::default();
    let mut blob_refs: HashMap<BlobId, u64> = HashMap::new();
    let mut blob_lens: HashMap<BlobId, u64> = HashMap::new();
    let mut total_events = 0u64;
    let mut batch_count = 0u64;
    let mut blob_bytes = 0u64;
    while let Some(item) = stream.next_item()? {
        match item {
            StreamItem::Environment(env) => meta.environment = Some(env),
            StreamItem::Schemas(defs) => meta.schemas.extend(defs),
            StreamItem::Events(batch) => {
                batch_count += 1;
                for e in &batch.events {
                    total_events += 1;
                    // 欠落 Blob は読み終えてから決まる (前方参照がある)。
                    counts.note(e, |_| true);
                    if let PayloadRef::Blob(id) = &e.payload {
                        *blob_refs.entry(*id).or_default() += 1;
                    }
                    visit(stream.registry(), &batch, e);
                }
            }
            StreamItem::SkippedEvents { .. } => {}
            StreamItem::Blobs(blobs) => {
                for (id, data) in blobs {
                    if blob_lens.insert(id, data.len() as u64).is_none() {
                        blob_bytes = blob_bytes.saturating_add(data.len() as u64);
                    }
                }
            }
            StreamItem::BlobUpdate(update) => {
                meta.blob_updates.push(update);
            }
            StreamItem::Loss(records) => meta.loss_records.extend(records),
            StreamItem::Index(index) => meta.stored_index = Some(index),
            StreamItem::Finalization {
                finalization,
                cleanly,
            } => {
                meta.finalization = Some(finalization);
                meta.finalized_cleanly = cleanly;
            }
            StreamItem::ProfileSummary(summary) => meta.profile_summary = Some(summary),
        }
    }
    let summary = stream.finish()?;
    for def in &meta.schemas {
        let _ = meta.registry.register(def.clone());
    }
    // 派生版の長さは基底と同じ (更新は長さを変えない)。
    for update in &meta.blob_updates {
        if !blob_lens.contains_key(&update.new_version_id) {
            if let Some(&base) = blob_lens.get(&update.resource_id) {
                blob_lens.insert(update.new_version_id, base);
                blob_bytes = blob_bytes.saturating_add(base);
            }
        }
    }
    counts.missing_blob_refs = summary
        .issues
        .iter()
        .filter_map(|i| match i {
            RecoveryIssue::MissingBlob { id } => blob_refs.get(id).copied(),
            _ => None,
        })
        .sum();
    meta.header = summary.header;
    meta.blocks = summary.blocks;
    meta.issues = summary.issues;
    meta.index_matches_scan = summary.index_matches_scan;
    let integrity = IntegritySummary::assemble(&meta, &counts);
    Ok(StreamedTrace {
        meta,
        total_events,
        batch_count,
        blob_count: blob_lens.len() as u64,
        blob_bytes,
        integrity,
    })
}
