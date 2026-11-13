//! Host 変換：検証済み回収イベントを公開 Trace へ変換する（A72 の適用）。
//!
//! A72 の不変条件（docs/trace-format.md「Host 変換」節）:
//! - 公開 Trace に載るのは Blob ID のみ。`TemporaryPayloadKey` は
//!   Host 内部の突き合わせ専用であり、公開形式のモデルにも変換の
//!   入出力にも現れない（このモジュールはキーを一切受け取らない）。
//! - 欠落した Payload（`payload_dropped`）にはキーを生成せず、
//!   Trace には `Dropped { original_len, reason }` として理由だけ残す。
//! - Loss 情報は Loss Block の LossRecord へ、IntegrityReport の
//!   3 指標は Finalization へ写す。
//!
//! `record_batch` は Payload を Blob として保持し、args は付与しない。
//! Schema 駆動の引数取得はフック層が担い、以下の args 対応経路で検証する。
//!
//! Phase 3 のフック由来イベントについては
//! [`TraceRecorder::record_batch_with_args`] を使う： Payload が
//! Compact Binary の引数値列そのものであるため、Blob 化せず
//! TraceEvent.args へ写す。

use crate::{IntegrityLevel, IntegrityReport, LossEvent};
use shirusu_api_catalog::api as hook_api;
use shirusu_trace::compact::validate_values_completeness;
use shirusu_trace::error::Result as TraceResult;
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::proto::{
    loss_kind, ApiProfile, CaptureEnvironment, LossRecord, ProfileSummary, SchemaDef,
};
use shirusu_trace::schema::EventCapture;
use shirusu_trace::writer::{DurableWrite, FinalizationInfo, TraceWriter, WriterOptions};
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::ring::ReceivedEvent;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Batch 変換の文脈。転送 Descriptor が持たない Session / Process /
/// Thread の情報は Host がここで補う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceBatchContext {
    pub session_id: u64,
    /// Trace 内 Process ID。
    pub process_id: u64,
    /// OS の PID 生値。
    pub raw_pid: u32,
    /// Trace 内 Thread / Writer ID。
    pub thread_id: u64,
    pub qpc_frequency: u64,
}

/// 転送 CaptureState → 公開形式のイベント取得状態。
pub fn convert_capture(state: CaptureState) -> EventCapture {
    match state {
        CaptureState::Captured => EventCapture::Captured,
        CaptureState::MemoryUnreadable => EventCapture::MemoryUnreadable,
        CaptureState::CaptureLimitExceeded => EventCapture::CaptureLimitExceeded,
        CaptureState::DroppedByBackpressure => EventCapture::DroppedByBackpressure,
        CaptureState::Truncated => EventCapture::Truncated,
        CaptureState::Unsupported => EventCapture::Unsupported,
    }
}

/// 欠落 Payload の理由。Descriptor の取得状態から決める。
/// Overflow で落ちたイベントは Descriptor 自体が届かないため、
/// ここに来るのは「Descriptor は残ったが Payload を落とした」分だけ。
pub fn payload_loss_reason(event: &ReceivedEvent) -> PayloadLossReason {
    match event.capture_state() {
        CaptureState::DroppedByBackpressure => PayloadLossReason::Backpressure,
        CaptureState::CaptureLimitExceeded => PayloadLossReason::TooLarge,
        _ => PayloadLossReason::Other,
    }
}

/// Host の LossEvent → 公開形式の LossRecord。
pub fn convert_loss_record(event: &LossEvent, process_id: u64, thread_id: u64) -> LossRecord {
    let mut record = LossRecord {
        process_id,
        thread_id,
        ..Default::default()
    };
    match event {
        LossEvent::SequenceGap { count } => {
            record.kind = loss_kind::SEQUENCE_GAP;
            record.count = *count;
        }
        LossEvent::Counters {
            dropped_events,
            dropped_payload_bytes,
            degraded_events,
        } => {
            record.kind = loss_kind::COUNTERS;
            record.count = *dropped_events;
            record.dropped_payload_bytes = *dropped_payload_bytes;
            record.degraded_events = *degraded_events;
        }
        LossEvent::UnknownTermination { call_id } => {
            record.kind = loss_kind::UNKNOWN_TERMINATION;
            record.call_id = *call_id;
        }
        LossEvent::IntegrityLost { reason } => {
            record.kind = loss_kind::INTEGRITY_LOST;
            record.reason = reason.clone();
        }
    }
    record
}

/// IntegrityLevel → 公開形式の数値（proto の integrity_level）。
pub fn integrity_level_code(level: IntegrityLevel) -> u32 {
    match level {
        IntegrityLevel::Complete => shirusu_trace::proto::integrity_level::COMPLETE,
        IntegrityLevel::Degraded => shirusu_trace::proto::integrity_level::DEGRADED,
        IntegrityLevel::Lost => shirusu_trace::proto::integrity_level::LOST,
        IntegrityLevel::Unknown => shirusu_trace::proto::integrity_level::UNKNOWN,
    }
}

/// IntegrityReport → Finalization に書く完全性情報。
pub fn finalization_info(report: &IntegrityReport) -> FinalizationInfo {
    FinalizationInfo {
        capture_coverage: integrity_level_code(report.capture_coverage),
        event_integrity: integrity_level_code(report.event_integrity),
        semantic_completeness: integrity_level_code(report.semantic_completeness),
        notes: report.notes.clone(),
    }
}

/// 引数変換の集計（[`TraceRecorder::record_batch_with_args`] の戻り値）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ArgsConversionStats {
    /// Payload を引数値列として args へ写した件数。
    pub args_attached: usize,
    /// Valid payloads containing unavailable or partial field values.
    pub args_incomplete: usize,
    /// 引数値列として復号できず Blob として保持した件数。
    pub args_fallback_blob: usize,
}

/// 記録モード（L09、overview「記録モードと性能目標」節）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RecordMode {
    /// 標準。対象境界の呼び出しを意図的に間引かず全て保存する。
    /// 欠落が起きたら Trace は `incomplete` として扱う（H03 の
    /// Finalization の三指標と連動。間引きはしないが、負荷による
    /// 欠落を防ぐ保証までは無い）。
    #[default]
    Full,
    /// 個別イベントは保存せず、API ごとに呼び出し回数・分布・所要
    /// 時間を集計して ProfileSummary Block として書く。
    Profile,
    /// 指定した API 群のイベントだけを保存する。Loss Record と
    /// Schema は API によらず残る。Agent 側での間引きはしない
    ///（Host 側で落とす。Agent 側の間引きは将来の最適化）。
    Filtered { apis: BTreeSet<u32> },
    /// 詳細調査モード（L15、overview「記録境界とモジュール分類」節）。
    /// `Full` と同じく個別イベントを全て保存するが、Agent 側で
    /// Windows 内部の呼び出し（Nt*。CreateFileW → NtCreateFile など）
    /// も記録する（Bootstrap の detailed_mode 経由）。内部呼び出しは
    /// 親子関係付きの別の呼び出しとして保存される（parent_call_id）。
    /// 再実行では下位呼び出しを重ねて実行しない（trace-format.md 参照）。
    /// 詳細調査モードでは Runtime 起源の呼び出しも記録する（CLI が
    /// `--record-runtime-apis` を強制する）。
    Detailed,
}

impl RecordMode {
    /// `CaptureEnvironment.capture_config` に載せる表示（L22 の来歴
    /// 記録と同じ欄）。`api_names` は CLI で指定された通りの名前列
    ///（`filtered` のときだけ使う）。
    pub fn config_text(&self, api_names: &[String]) -> String {
        match self {
            RecordMode::Full => "mode=full".to_string(),
            RecordMode::Profile => "mode=profile".to_string(),
            RecordMode::Detailed => "mode=detailed".to_string(),
            RecordMode::Filtered { .. } => {
                format!("mode=filtered apis={}", api_names.join(","))
            }
        }
    }
}

/// CLI の `--api` で指定された API 名を api_id の集合へ解決する
/// （L09）。素の関数名（`CreateFileW`）と `module!関数` 形式の両方を
/// 受け付ける。未知の名前が 1 つでもあれば、その名前を入れてエラーに
/// する（呼び出し側が使い方エラーとして表示する）。
pub fn resolve_api_names(names: &[String]) -> Result<BTreeSet<u32>, String> {
    let mut ids = BTreeSet::new();
    for name in names {
        match hook_api::api_by_name(name) {
            Some(api) => {
                ids.insert(api.api_id);
            }
            None => return Err(format!("unknown API: {name}")),
        }
    }
    Ok(ids)
}

/// `profile` モードの集計器（L09）。enter / leave の対応付けは
/// (thread, call_id) で行う（DrainWorker の `track_call` と同じ鍵）。
/// 対応の無い enter / leave は calls に数えず enters / leaves だけに
/// 数える。CallEnter / CallLeave 以外の種別は集計の対象外だが
/// `total_events_seen` には数える。
#[derive(Debug, Clone, Default)]
struct ProfileAggregator {
    total_seen: u64,
    pending: HashMap<(u64, u64), (u32, u64)>,
    apis: BTreeMap<u32, ApiProfile>,
}

impl ProfileAggregator {
    fn observe(&mut self, thread_id: u64, event: &ReceivedEvent) {
        self.total_seen += 1;
        let d = &event.descriptor;
        match d.kind_enum() {
            Some(EventKind::CallEnter) => {
                let row = self.apis.entry(d.api_id).or_default();
                row.api_id = d.api_id;
                row.enters += 1;
                self.pending
                    .insert((thread_id, d.call_id), (d.api_id, d.timestamp_qpc));
            }
            Some(EventKind::CallLeave) => {
                let row = self.apis.entry(d.api_id).or_default();
                row.api_id = d.api_id;
                row.leaves += 1;
                if let Some((enter_api, enter_ts)) = self.pending.remove(&(thread_id, d.call_id)) {
                    let duration = d.timestamp_qpc.saturating_sub(enter_ts);
                    let row = self.apis.entry(enter_api).or_default();
                    row.api_id = enter_api;
                    row.calls += 1;
                    row.total_duration_qpc += duration;
                    if row.calls == 1 {
                        row.min_duration_qpc = duration;
                        row.max_duration_qpc = duration;
                    } else {
                        row.min_duration_qpc = row.min_duration_qpc.min(duration);
                        row.max_duration_qpc = row.max_duration_qpc.max(duration);
                    }
                }
            }
            // L08: 中断した呼び出しは所要時間なしで終わる。対応付け待ち
            // から外すだけにし、calls には数えない（leaves にも数えない）。
            Some(EventKind::CallAborted) => {
                self.pending.remove(&(thread_id, d.call_id));
            }
            // F27: 完了した非同期 I/O。leave が既に対応付けを済ませて
            // いるため、集計には何もしない（所要時間は leave 時点で
            // 計測済み。完了イベントの値列は集計対象外）。
            Some(EventKind::CallCompleted) => {}
            _ => {}
        }
    }

    fn finish(self, qpc_frequency: u64) -> ProfileSummary {
        ProfileSummary {
            qpc_frequency,
            total_events_seen: self.total_seen,
            apis: self.apis.into_values().collect(),
        }
    }
}

/// TraceWriter を所有し、回収イベントをそのまま記録できる形にした
/// レコーダ。Payload の Blob 化と重複排除は Writer が担い、ここでは
/// 「落とした Payload は Blob 化しない」ことだけを守る。
pub struct TraceRecorder<W: DurableWrite> {
    writer: TraceWriter<W>,
    /// 記録モード（L09）。既定は `Full`。
    mode: RecordMode,
    /// `Profile` モードの集計状態。
    profile: ProfileAggregator,
    /// 集計の所要時間換算に使う QPC 周波数（Environment 由来）。
    qpc_frequency: u64,
    /// Schemas registered on first use instead of at session start (the
    /// IAT-only broad tier would otherwise add megabytes to every Trace).
    lazy_schemas: Option<LazySchemas>,
}

/// Provider of a Schema definition for an ID not registered up front.
pub type LazySchemas = fn(u32) -> Option<shirusu_trace::proto::SchemaDef>;

impl<W: DurableWrite> TraceRecorder<W> {
    pub fn new(writer: TraceWriter<W>) -> Self {
        Self {
            qpc_frequency: writer.qpc_frequency(),
            writer,
            mode: RecordMode::Full,
            profile: ProfileAggregator::default(),
            lazy_schemas: None,
        }
    }

    pub fn from_environment(inner: W, environment: CaptureEnvironment) -> TraceResult<Self> {
        Ok(Self {
            qpc_frequency: environment.session.qpc_frequency,
            writer: TraceWriter::new(inner, environment)?,
            mode: RecordMode::Full,
            profile: ProfileAggregator::default(),
            lazy_schemas: None,
        })
    }

    /// 永続化設定を指定して作る（F21）。`CaptureSession::create_file`
    /// 経由で `CaptureSessionConfig::durability` がここへ渡る。
    pub fn from_environment_with_options(
        inner: W,
        environment: CaptureEnvironment,
        options: WriterOptions,
    ) -> TraceResult<Self> {
        Ok(Self {
            qpc_frequency: environment.session.qpc_frequency,
            writer: TraceWriter::with_options(inner, environment, options)?,
            mode: RecordMode::Full,
            profile: ProfileAggregator::default(),
            lazy_schemas: None,
        })
    }

    pub fn update_environment(&mut self, environment: &CaptureEnvironment) -> TraceResult<()> {
        self.writer.update_environment(environment)
    }

    /// 記録モードを指定する（L09）。`CaptureSession::create_file` が
    /// `CaptureSessionConfig::record_mode` から渡す。既定は `Full`。
    pub fn set_record_mode(&mut self, mode: RecordMode) {
        self.mode = mode;
    }

    /// `Profile` モードの現時点までの集計（`finish` 前でも読める）。
    /// `Profile` 以外のモードでは None。`CaptureSession::stop` が
    /// 要約へ載せるために使う。
    pub fn profile_summary(&self) -> Option<ProfileSummary> {
        if matches!(self.mode, RecordMode::Profile) {
            Some(self.profile.clone().finish(self.qpc_frequency))
        } else {
            None
        }
    }

    pub fn register_schema(&mut self, def: SchemaDef) -> TraceResult<()> {
        self.writer.register_schema(def)
    }

    /// Register Schemas from `provider` the first time an event refers to
    /// them. The Writer emits them before the Event Chunk that uses them, so
    /// a Trace carries only the Schemas of APIs it actually observed.
    pub fn set_lazy_schemas(&mut self, provider: LazySchemas) {
        self.lazy_schemas = Some(provider);
    }

    fn ensure_schema(&mut self, schema_id: u32) -> TraceResult<()> {
        if schema_id == 0 || self.writer.schema_types_ref(schema_id).is_some() {
            return Ok(());
        }
        match self.lazy_schemas.and_then(|provider| provider(schema_id)) {
            Some(def) => self.writer.register_schema(def),
            None => Ok(()),
        }
    }

    pub fn write_schema_checkpoint(&mut self) -> TraceResult<()> {
        self.writer.write_schema_checkpoint()
    }

    /// 検証済みイベント列を 1 Batch として記録する。空の列は何もしない。
    pub fn record_batch(
        &mut self,
        ctx: &TraceBatchContext,
        events: &[ReceivedEvent],
    ) -> TraceResult<()> {
        self.record_batch_inner(ctx, events.iter().map(Cow::Borrowed), false, true)
            .map(|_| ())
    }

    /// フック由来のイベント列を記録する。Writer に登録済みの Schema を
    /// 持つイベントは、Payload を Compact Binary の引数値列として
    /// 検証し、TraceEvent.args へ写す（Blob 化しない）。復号検証に
    /// 失敗した Payload はデータを失わないよう Blob として保持し、
    /// その件数を戻り値で知らせる（Semantic Completeness の劣化として
    /// 呼び出し側が数える）。欠落 Payload の扱いは record_batch と同じ。
    pub fn record_batch_with_args(
        &mut self,
        ctx: &TraceBatchContext,
        events: &[ReceivedEvent],
    ) -> TraceResult<ArgsConversionStats> {
        self.record_batch_inner(ctx, events.iter().map(Cow::Borrowed), true, true)
    }

    /// Consume a drained batch, transferring validated argument buffers into
    /// the Trace batch instead of allocating and copying them again.
    pub fn record_owned_batch_with_args(
        &mut self,
        ctx: &TraceBatchContext,
        events: Vec<ReceivedEvent>,
    ) -> TraceResult<ArgsConversionStats> {
        self.record_batch_inner(ctx, events.into_iter().map(Cow::Owned), true, true)
    }

    pub(crate) fn record_owned_batch_uncompressed(
        &mut self,
        ctx: &TraceBatchContext,
        events: Vec<ReceivedEvent>,
    ) -> TraceResult<ArgsConversionStats> {
        self.record_batch_inner(ctx, events.into_iter().map(Cow::Owned), true, false)
    }

    fn record_batch_inner<'a>(
        &mut self,
        ctx: &TraceBatchContext,
        events: impl ExactSizeIterator<Item = Cow<'a, ReceivedEvent>>,
        args_mode: bool,
        compress_events: bool,
    ) -> TraceResult<ArgsConversionStats> {
        let mut stats = ArgsConversionStats::default();
        if events.len() == 0 {
            return Ok(stats);
        }
        if matches!(self.mode, RecordMode::Profile) {
            for event in events {
                self.profile.observe(ctx.thread_id, &event);
            }
            return Ok(stats);
        }
        let mut converted = Vec::with_capacity(events.len());
        for event in events {
            let d = event.descriptor;
            if let RecordMode::Filtered { apis } = &self.mode {
                if !apis.contains(&d.api_id) {
                    continue;
                }
            }
            if self.lazy_schemas.is_some() {
                self.ensure_schema(d.schema_id)?;
            }
            let mut args = None;
            let payload = if d.payload_dropped() {
                // A72：欠落 Payload にはキーを作らず、理由だけを残す。
                PayloadRef::Dropped {
                    original_len: d.payload_len as u64,
                    reason: payload_loss_reason(&event),
                }
            } else if event.payload.is_empty() {
                PayloadRef::None
            } else if args_mode && d.schema_id != 0 {
                match self
                    .writer
                    .schema_types_ref(d.schema_id)
                    .and_then(|types| validate_values_completeness(types, &event.payload).ok())
                {
                    Some(complete) => {
                        stats.args_incomplete += usize::from(!complete);
                        args = Some(match event {
                            Cow::Borrowed(event) => event.payload.clone(),
                            Cow::Owned(event) => event.payload,
                        });
                        stats.args_attached += 1;
                        PayloadRef::None
                    }
                    _ => {
                        // 未登録 Schema、または値列として復号できない
                        // Payload は Blob として保持する（データを失わない）。
                        stats.args_fallback_blob += 1;
                        PayloadRef::Blob(self.writer.add_payload(&event.payload)?)
                    }
                }
            } else {
                // 格納済み Payload は Blob 化し、ID だけを Trace に残す。
                // 一時キーはここでも使わない（突き合わせは DrainWorker 側）。
                PayloadRef::Blob(self.writer.add_payload(&event.payload)?)
            };
            converted.push(TraceEvent {
                kind: d.kind,
                sequence: d.sequence,
                timestamp_qpc: d.timestamp_qpc,
                call_id: d.call_id,
                parent_call_id: d.parent_call_id,
                api_id: d.api_id,
                schema_id: d.schema_id,
                capture: convert_capture(d.capture_state()),
                payload,
                args,
                // L11: 0 は未割当として None にする（--order=global 無効時）。
                global_order: if d.global_order == 0 {
                    None
                } else {
                    Some(d.global_order)
                },
            });
        }
        if converted.is_empty() {
            return Ok(stats);
        }
        let batch = EventBatch {
            session_id: ctx.session_id,
            process_id: ctx.process_id,
            raw_pid: ctx.raw_pid,
            thread_id: ctx.thread_id,
            qpc_frequency: ctx.qpc_frequency,
            events: converted,
        };
        if compress_events {
            self.writer.write_batch(&batch)?;
        } else {
            self.writer.write_batch_uncompressed(&batch)?;
        }
        Ok(stats)
    }

    /// DrainWorker が集めた LossEvent をまとめて記録する。
    pub fn record_losses(
        &mut self,
        losses: &[LossEvent],
        process_id: u64,
        thread_id: u64,
    ) -> TraceResult<()> {
        let records: Vec<LossRecord> = losses
            .iter()
            .map(|l| convert_loss_record(l, process_id, thread_id))
            .collect();
        self.writer.write_loss_records(&records)
    }

    /// IntegrityReport を Finalization へ写して Trace を閉じる。
    /// `Profile` モードでは、先に集計を ProfileSummary Block として
    /// 書く（L09。Index の前に置くため、集計も Index に載る）。
    pub fn finish(mut self, report: &IntegrityReport) -> TraceResult<W> {
        if matches!(self.mode, RecordMode::Profile) {
            let summary = self.profile.finish(self.qpc_frequency);
            self.writer.write_profile_summary(&summary)?;
        }
        self.writer.finish(finalization_info(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_transport::descriptor::EventDescriptor;

    fn received(kind: EventKind, call_id: u64, timestamp_qpc: u64) -> ReceivedEvent {
        let mut d = EventDescriptor::new(kind, call_id);
        d.call_id = call_id;
        d.api_id = 3;
        d.timestamp_qpc = timestamp_qpc;
        ReceivedEvent {
            descriptor: d,
            payload: Vec::new(),
        }
    }

    #[test]
    fn profile_aggregator_completed_does_not_change_counts() {
        // F27: CallCompleted は leave が対応付け済みのため集計を変えない。
        // total_events_seen にだけ数える。
        let mut agg = ProfileAggregator::default();
        agg.observe(5, &received(EventKind::CallEnter, 1, 100));
        agg.observe(5, &received(EventKind::CallLeave, 1, 160));
        agg.observe(5, &received(EventKind::CallCompleted, 1, 200));
        let summary = agg.finish(10_000_000);
        assert_eq!(summary.total_events_seen, 3);
        assert_eq!(summary.apis.len(), 1);
        let row = &summary.apis[0];
        assert_eq!(row.enters, 1);
        assert_eq!(row.leaves, 1);
        assert_eq!(row.calls, 1);
        assert_eq!(row.total_duration_qpc, 60);
    }

    #[test]
    fn profile_aggregator_aborted_clears_pending_without_a_call() {
        // L08: 中断した呼び出しは所要時間なしで終わる。対応付け待ちから
        // 外れ、calls には数えない（enter は enters に数えたまま）。
        let mut agg = ProfileAggregator::default();
        agg.observe(5, &received(EventKind::CallEnter, 1, 100));
        agg.observe(5, &received(EventKind::CallAborted, 1, 150));
        assert!(agg.pending.is_empty(), "aborted clears the pending enter");
        // 同じ call_id の再利用が古い enter と対応付かないこと。
        agg.observe(5, &received(EventKind::CallEnter, 1, 200));
        agg.observe(5, &received(EventKind::CallLeave, 1, 260));
        let summary = agg.finish(10_000_000);
        assert_eq!(summary.total_events_seen, 4);
        assert_eq!(summary.apis.len(), 1);
        let row = &summary.apis[0];
        assert_eq!(row.enters, 2);
        assert_eq!(row.leaves, 1);
        assert_eq!(row.calls, 1, "only the completed call counts");
        assert_eq!(row.total_duration_qpc, 60);
    }
}
