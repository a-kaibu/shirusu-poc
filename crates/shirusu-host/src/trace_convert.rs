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
//! 引数値列（args）は現段階の転送に存在しないため変換では常に None
//! とする。Schema 駆動の引数取得はフック層（Phase 3）が担う。
//!
//! Phase 3 のフック由来イベントについては
//! [`TraceRecorder::record_batch_with_args`] を使う： Payload が
//! Compact Binary の引数値列そのものであるため、Blob 化せず
//! TraceEvent.args へ写す。

use crate::{IntegrityLevel, IntegrityReport, LossEvent};
use shirusu_trace::compact::decode_values;
use shirusu_trace::error::Result as TraceResult;
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::proto::{loss_kind, CaptureEnvironment, LossRecord, SchemaDef};
use shirusu_trace::schema::EventCapture;
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};
use shirusu_transport::descriptor::CaptureState;
use shirusu_transport::ring::ReceivedEvent;
use std::io::Write;

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
    /// 引数値列として復号できず Blob として保持した件数。
    pub args_fallback_blob: usize,
}

/// TraceWriter を所有し、回収イベントをそのまま記録できる形にした
/// レコーダ。Payload の Blob 化と重複排除は Writer が担い、ここでは
/// 「落とした Payload は Blob 化しない」ことだけを守る。
pub struct TraceRecorder<W: Write> {
    writer: TraceWriter<W>,
}

impl<W: Write> TraceRecorder<W> {
    pub fn new(writer: TraceWriter<W>) -> Self {
        Self { writer }
    }

    pub fn from_environment(inner: W, environment: CaptureEnvironment) -> TraceResult<Self> {
        Ok(Self {
            writer: TraceWriter::new(inner, environment)?,
        })
    }

    pub fn register_schema(&mut self, def: SchemaDef) -> TraceResult<()> {
        self.writer.register_schema(def)
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
        self.record_batch_inner(ctx, events, false).map(|_| ())
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
        self.record_batch_inner(ctx, events, true)
    }

    fn record_batch_inner(
        &mut self,
        ctx: &TraceBatchContext,
        events: &[ReceivedEvent],
        args_mode: bool,
    ) -> TraceResult<ArgsConversionStats> {
        let mut stats = ArgsConversionStats::default();
        if events.is_empty() {
            return Ok(stats);
        }
        let mut converted = Vec::with_capacity(events.len());
        for event in events {
            let d = &event.descriptor;
            let mut args = None;
            let payload = if d.payload_dropped() {
                // A72：欠落 Payload にはキーを作らず、理由だけを残す。
                PayloadRef::Dropped {
                    original_len: d.payload_len as u64,
                    reason: payload_loss_reason(event),
                }
            } else if event.payload.is_empty() {
                PayloadRef::None
            } else if args_mode && d.schema_id != 0 {
                match self.writer.schema_types(d.schema_id) {
                    Some(types) if decode_values(&types, &event.payload).is_ok() => {
                        args = Some(event.payload.clone());
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
                capture: convert_capture(event.capture_state()),
                payload,
                args,
            });
        }
        let batch = EventBatch {
            session_id: ctx.session_id,
            process_id: ctx.process_id,
            raw_pid: ctx.raw_pid,
            thread_id: ctx.thread_id,
            qpc_frequency: ctx.qpc_frequency,
            events: converted,
        };
        self.writer.write_batch(&batch)?;
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
    pub fn finish(self, report: &IntegrityReport) -> TraceResult<W> {
        self.writer.finish(finalization_info(report))
    }
}
