//! Trace の「ビュー」：`ReadTrace` を平坦化し、Schema レジストリで
//! 引数値列を復号して、表示・検索・比較ができる形にする。
//!
//! ここでの責務は「読めたものを正直に見せる」ことだけであり、値の
//! 解釈（正規化や同一性判定）は shirusu-compare 側の仕事とする。

use crate::json::JsonValue;
use shirusu_trace::compact::decode_values;
use shirusu_trace::model::{PayloadLossReason, PayloadRef};
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::schema::{EventCapture, Ty, TypedValue, ValueCapture, ValueKind};
use shirusu_trace::BlobId;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// 転送 Descriptor の kind と同じ番号（1 = CallEnter、2 = CallLeave）。
pub const KIND_ENTER: u16 = 1;
pub const KIND_LEAVE: u16 = 2;

/// イベントの相（Enter / Leave / その他）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Enter,
    Leave,
    Other(u16),
}

impl Phase {
    pub fn of_kind(kind: u16) -> Self {
        match kind {
            KIND_ENTER => Phase::Enter,
            KIND_LEAVE => Phase::Leave,
            other => Phase::Other(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Phase::Enter => "enter",
            Phase::Leave => "leave",
            Phase::Other(_) => "event",
        }
    }
}

/// Schema 名（例 `kernel32!CreateFileW/enter`）から API 名
/// （`kernel32!CreateFileW`）を取り出す。`/enter` `/leave` 接尾辞が
/// 無い名前はそのまま API 名とみなす。
pub fn api_name_of_schema(schema_name: &str) -> &str {
    for suffix in ["/enter", "/leave"] {
        if let Some(stem) = schema_name.strip_suffix(suffix) {
            return stem;
        }
    }
    schema_name
}

/// 復号済みの 1 フィールド。
#[derive(Debug, Clone, PartialEq)]
pub struct FieldView {
    pub name: String,
    pub ty: Ty,
    /// Schema が宣言した意味種別。Schema が引けない場合は
    /// Unspecified (利用側は型からの推定にフォールバックする)。
    pub kind: ValueKind,
    pub capture: ValueCapture,
    pub value: TypedValue,
}

/// Payload の要約（実体バイト列は持たない。解決は `ReadTrace` 側）。
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadView {
    None,
    Blob(BlobId),
    Inline(Vec<u8>),
    Dropped {
        original_len: u64,
        reason: PayloadLossReason,
    },
}

impl PayloadView {
    fn of(payload: &PayloadRef) -> Self {
        match payload {
            PayloadRef::None => PayloadView::None,
            PayloadRef::Blob(id) => PayloadView::Blob(*id),
            PayloadRef::Inline(b) => PayloadView::Inline(b.clone()),
            PayloadRef::Dropped {
                original_len,
                reason,
            } => PayloadView::Dropped {
                original_len: *original_len,
                reason: *reason,
            },
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PayloadView::None => "none".to_string(),
            PayloadView::Blob(id) => format!("blob:{id}"),
            PayloadView::Inline(b) => format!("inline[{}]", b.len()),
            PayloadView::Dropped {
                original_len,
                reason,
            } => format!(
                "dropped(len={}, reason={})",
                original_len,
                reason_name(*reason)
            ),
        }
    }
}

pub fn reason_name(reason: PayloadLossReason) -> &'static str {
    match reason {
        PayloadLossReason::Backpressure => "backpressure",
        PayloadLossReason::TooLarge => "too_large",
        PayloadLossReason::Overflow => "overflow",
        PayloadLossReason::HostStopped => "host_stopped",
        PayloadLossReason::Other => "other",
    }
}

pub fn capture_name(capture: EventCapture) -> String {
    match capture {
        EventCapture::Captured => "captured".to_string(),
        EventCapture::MemoryUnreadable => "memory_unreadable".to_string(),
        EventCapture::CaptureLimitExceeded => "capture_limit_exceeded".to_string(),
        EventCapture::DroppedByBackpressure => "dropped_by_backpressure".to_string(),
        EventCapture::Truncated => "truncated".to_string(),
        EventCapture::Unsupported => "unsupported".to_string(),
        EventCapture::Other(code) => format!("other({code})"),
    }
}

pub fn value_capture_name(capture: ValueCapture) -> &'static str {
    match capture {
        ValueCapture::Captured => "captured",
        ValueCapture::Unreadable => "unreadable",
        ValueCapture::Truncated => "truncated",
        ValueCapture::Unsupported => "unsupported",
        ValueCapture::LimitExceeded => "limit_exceeded",
    }
}

/// 平坦化した 1 イベント。バッチ文脈（セッション/プロセス/スレッド）を
/// 保持し、引数は Schema で復号済み。
#[derive(Debug, Clone)]
pub struct EventView {
    /// ファイル順の通し番号（0 始まり）。
    pub index: usize,
    pub session_id: u64,
    pub process_id: u64,
    pub raw_pid: u32,
    pub thread_id: u64,
    pub qpc_frequency: u64,
    pub kind: u16,
    pub sequence: u64,
    pub timestamp_qpc: u64,
    pub call_id: u64,
    pub parent_call_id: u64,
    pub api_id: u32,
    pub schema_id: u32,
    /// Schema 名から導いた API 名。Schema が無い/未登録なら None。
    pub api_name: Option<String>,
    pub schema_name: Option<String>,
    pub capture: EventCapture,
    pub fields: Vec<FieldView>,
    /// 引数の復号に失敗した理由（値列が壊れている等）。隠さず残す。
    pub args_error: Option<String>,
    pub payload: PayloadView,
}

impl EventView {
    pub fn phase(&self) -> Phase {
        Phase::of_kind(self.kind)
    }

    pub fn field(&self, name: &str) -> Option<&FieldView> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// 1 行形式（ダンプの人間可読出力）：
    /// `#<index> seq=<sequence> thread=<tid> <api> <phase> call=<id> \
    /// <name>=<value> ... payload=<要約> capture=<状態>`
    pub fn line(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "#{} seq={} thread={} ",
            self.index, self.sequence, self.thread_id
        );
        match &self.api_name {
            Some(api) => {
                let _ = write!(s, "{} {}", api, self.phase().name());
            }
            None => {
                let _ = write!(s, "api#{} kind={}", self.api_id, self.kind);
            }
        }
        let _ = write!(s, " call={}", self.call_id);
        for f in &self.fields {
            let _ = write!(s, " {}", format_field(f));
        }
        if let Some(err) = &self.args_error {
            let _ = write!(s, " args_error={err:?}");
        }
        let _ = write!(
            s,
            " payload={} capture={}",
            self.payload.describe(),
            capture_name(self.capture)
        );
        s
    }

    pub fn to_json(&self) -> JsonValue {
        let fields = self
            .fields
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    JsonValue::obj(vec![
                        ("ty", JsonValue::Str(format!("{:?}", f.ty))),
                        (
                            "capture",
                            JsonValue::Str(value_capture_name(f.capture).into()),
                        ),
                        ("value", value_to_json(&f.value)),
                    ]),
                )
            })
            .collect::<Vec<_>>();
        let payload = match &self.payload {
            PayloadView::None => JsonValue::obj(vec![("kind", JsonValue::Str("none".into()))]),
            PayloadView::Blob(id) => JsonValue::obj(vec![
                ("kind", JsonValue::Str("blob".into())),
                ("id", JsonValue::Str(id.to_hex())),
            ]),
            PayloadView::Inline(b) => JsonValue::obj(vec![
                ("kind", JsonValue::Str("inline".into())),
                ("len", JsonValue::U64(b.len() as u64)),
                ("hex", JsonValue::Str(hex_prefix(b, usize::MAX))),
            ]),
            PayloadView::Dropped {
                original_len,
                reason,
            } => JsonValue::obj(vec![
                ("kind", JsonValue::Str("dropped".into())),
                ("original_len", JsonValue::U64(*original_len)),
                ("reason", JsonValue::Str(reason_name(*reason).into())),
            ]),
        };
        JsonValue::obj(vec![
            ("index", JsonValue::U64(self.index as u64)),
            ("session_id", JsonValue::U64(self.session_id)),
            ("process_id", JsonValue::U64(self.process_id)),
            ("raw_pid", JsonValue::U64(self.raw_pid as u64)),
            ("thread_id", JsonValue::U64(self.thread_id)),
            ("sequence", JsonValue::U64(self.sequence)),
            ("timestamp_qpc", JsonValue::U64(self.timestamp_qpc)),
            ("kind", JsonValue::U64(self.kind as u64)),
            ("phase", JsonValue::Str(self.phase().name().into())),
            (
                "api",
                self.api_name
                    .clone()
                    .map(JsonValue::Str)
                    .unwrap_or(JsonValue::Null),
            ),
            ("api_id", JsonValue::U64(self.api_id as u64)),
            ("schema_id", JsonValue::U64(self.schema_id as u64)),
            ("call_id", JsonValue::U64(self.call_id)),
            ("parent_call_id", JsonValue::U64(self.parent_call_id)),
            ("capture", JsonValue::Str(capture_name(self.capture))),
            ("fields", JsonValue::Object(fields)),
            (
                "args_error",
                self.args_error
                    .clone()
                    .map(JsonValue::Str)
                    .unwrap_or(JsonValue::Null),
            ),
            ("payload", payload),
        ])
    }
}

/// `name=value` 形式。取得できなかった値は値本体（ダミー）ではなく
/// 取得状態で表す（Semantic Completeness の区別を出力でも保つ）。
pub fn format_field(f: &FieldView) -> String {
    if f.capture != ValueCapture::Captured {
        return format!("{}=<{}>", f.name, value_capture_name(f.capture));
    }
    format!("{}={}", f.name, format_value(&f.value))
}

/// 型付き値の人間可読表記。浮動小数点は形式の方針どおりビット表現。
pub fn format_value(v: &TypedValue) -> String {
    match v {
        TypedValue::I32(x) => x.to_string(),
        TypedValue::I64(x) => x.to_string(),
        TypedValue::U32(x) => x.to_string(),
        TypedValue::U64(x) => format!("0x{x:x}"),
        TypedValue::F32Bits(bits) => format!("f32(0x{bits:08x})"),
        TypedValue::F64Bits(bits) => format!("f64(0x{bits:016x})"),
        TypedValue::Bool(b) => b.to_string(),
        TypedValue::Str(s) => format!("{s:?}"),
        TypedValue::Str16(units) => format!("{:?}", String::from_utf16_lossy(units)),
        TypedValue::Bytes(b) => format!("bytes[{}]={}", b.len(), hex_prefix(b, 16)),
        TypedValue::BlobRef(id) => format!("blob:{id}"),
        TypedValue::Ptr32(x) => format!("0x{x:08x}"),
        TypedValue::Ptr64(x) => format!("0x{x:016x}"),
    }
}

/// 型付き値の JSON 表現。U64 は 2^53 を超えると JSON 数値として
/// 精度が落ちるため、16 進文字列で出す（ハンドル/ポインタの可読性も
/// そちらが上）。それ以外の整数は数値。
pub fn value_to_json(v: &TypedValue) -> JsonValue {
    match v {
        TypedValue::I32(x) => JsonValue::I64(*x as i64),
        TypedValue::I64(x) => JsonValue::I64(*x),
        TypedValue::U32(x) => JsonValue::U64(*x as u64),
        TypedValue::U64(x) => JsonValue::Str(format!("0x{x:x}")),
        TypedValue::F32Bits(bits) => JsonValue::Str(format!("f32(0x{bits:08x})")),
        TypedValue::F64Bits(bits) => JsonValue::Str(format!("f64(0x{bits:016x})")),
        TypedValue::Bool(b) => JsonValue::Bool(*b),
        TypedValue::Str(s) => JsonValue::Str(s.clone()),
        TypedValue::Str16(units) => JsonValue::Str(String::from_utf16_lossy(units)),
        TypedValue::Bytes(b) => JsonValue::Str(hex_prefix(b, usize::MAX)),
        TypedValue::BlobRef(id) => JsonValue::Str(format!("blob:{}", id.to_hex())),
        TypedValue::Ptr32(x) => JsonValue::Str(format!("0x{x:08x}")),
        TypedValue::Ptr64(x) => JsonValue::Str(format!("0x{x:016x}")),
    }
}

/// 先頭 `max` バイトまでの 16 進文字列。切り捨て時は末尾に `..`。
pub fn hex_prefix(b: &[u8], max: usize) -> String {
    let mut s = String::new();
    for byte in b.iter().take(max) {
        let _ = write!(s, "{byte:02x}");
    }
    if b.len() > max {
        s.push_str("..");
    }
    s
}

/// ダンプ/検索のフィルタ（overview の方針どおり、独自クエリ言語は
/// 作らず CLI オプションの組で表す）。
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// API 名の部分一致（例 `CreateFile`）。数値だけの文字列は api_id。
    pub api: Option<String>,
    pub kind: Option<u16>,
    pub seq_min: Option<u64>,
    pub seq_max: Option<u64>,
    pub thread_id: Option<u64>,
    /// 整形済み 1 行（フィールド値を含む）への部分一致。
    pub text: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, ev: &EventView) -> bool {
        if let Some(api) = &self.api {
            if let Ok(id) = api.parse::<u32>() {
                if ev.api_id != id {
                    return false;
                }
            } else {
                match &ev.api_name {
                    Some(name) if name.contains(api.as_str()) => {}
                    _ => return false,
                }
            }
        }
        if let Some(kind) = self.kind {
            if ev.kind != kind {
                return false;
            }
        }
        if let Some(min) = self.seq_min {
            if ev.sequence < min {
                return false;
            }
        }
        if let Some(max) = self.seq_max {
            if ev.sequence > max {
                return false;
            }
        }
        if let Some(tid) = self.thread_id {
            if ev.thread_id != tid {
                return false;
            }
        }
        if let Some(text) = &self.text {
            if !ev.line().contains(text.as_str()) {
                return false;
            }
        }
        true
    }
}

/// 完全性レベルの名前（proto の IntegrityLevel: 0..=3）。
pub fn integrity_level_name(level: u32) -> &'static str {
    match level {
        0 => "Complete",
        1 => "Degraded",
        2 => "Lost",
        3 => "Unknown",
        _ => "Invalid",
    }
}

/// Loss Record の種別名（trace-format.md: 1=SequenceGap 2=Counters
/// 3=UnknownTermination 4=IntegrityLost）。
pub fn loss_kind_name(kind: u32) -> &'static str {
    match kind {
        1 => "sequence_gap",
        2 => "counters",
        3 => "unknown_termination",
        4 => "integrity_lost",
        _ => "other",
    }
}

/// 三つの完全性指標と、その裏付けとなる損失の内訳。
/// Finalization が権威だが、欠けている場合は「確定できない」と
/// 明示する（overview の三指標の区別を出力でも保つ）。
#[derive(Debug, Clone, PartialEq)]
pub struct IntegritySummary {
    /// Finalization Block があり正常終了が宣言されているか。
    pub finalized_cleanly: bool,
    /// Finalization 自体の有無（無い Trace は完全性を確定できない）。
    pub has_finalization: bool,
    pub capture_coverage: Option<u32>,
    pub event_integrity: Option<u32>,
    pub semantic_completeness: Option<u32>,
    pub finalization_notes: Vec<String>,
    /// Loss Record の種別ごとの件数。
    pub loss_records_by_kind: BTreeMap<u32, u64>,
    pub total_loss_count: u64,
    /// Dropped な Payload を持つイベント数と、その元バイト数合計。
    pub dropped_payload_events: u64,
    pub dropped_payload_bytes: u64,
    /// 取得状態が Captured でないイベント数（Semantic の劣化の目安）。
    pub degraded_events: u64,
    /// Reader が記録した回復 issue の件数（種別ごとの内訳つき）。
    pub recovery_issues: Vec<String>,
    /// 参照先 Blob がファイル内に無いイベント数。
    pub missing_blob_refs: u64,
    pub index_matches_scan: bool,
    pub has_stored_index: bool,
}

impl IntegritySummary {
    pub fn of(trace: &ReadTrace) -> Self {
        let mut by_kind: BTreeMap<u32, u64> = BTreeMap::new();
        let mut total_loss_count = 0u64;
        for rec in &trace.loss_records {
            *by_kind.entry(rec.kind).or_default() += 1;
            total_loss_count += rec.count;
        }
        let mut dropped_events = 0u64;
        let mut dropped_bytes = 0u64;
        let mut degraded = 0u64;
        let mut missing_blobs = 0u64;
        for batch in &trace.batches {
            for e in &batch.events {
                if let PayloadRef::Dropped { original_len, .. } = &e.payload {
                    dropped_events += 1;
                    dropped_bytes += original_len;
                }
                if e.capture != EventCapture::Captured {
                    degraded += 1;
                }
                if let PayloadRef::Blob(id) = &e.payload {
                    if !trace.blobs.contains_key(id) {
                        missing_blobs += 1;
                    }
                }
            }
        }
        let issues = trace
            .issues
            .iter()
            .map(|i| match i {
                RecoveryIssue::TruncatedTail { offset } => {
                    format!("truncated_tail(offset={offset})")
                }
                RecoveryIssue::CorruptBlock { offset, reason } => {
                    format!("corrupt_block(offset={offset}, reason={reason})")
                }
                RecoveryIssue::Resync { from, to } => format!("resync({from}..{to})"),
                RecoveryIssue::DuplicateBlob { id } => format!("duplicate_blob({id})"),
                RecoveryIssue::BlobHashMismatch { id, computed } => {
                    format!("blob_hash_mismatch(id={id}, computed={computed})")
                }
                RecoveryIssue::MissingBlob { id } => format!("missing_blob({id})"),
                RecoveryIssue::IndexMismatch => "index_mismatch".to_string(),
                RecoveryIssue::LimitExceeded { what } => format!("limit_exceeded({what})"),
            })
            .collect();
        IntegritySummary {
            finalized_cleanly: trace.finalized_cleanly,
            has_finalization: trace.finalization.is_some(),
            capture_coverage: trace.finalization.as_ref().map(|f| f.capture_coverage),
            event_integrity: trace.finalization.as_ref().map(|f| f.event_integrity),
            semantic_completeness: trace.finalization.as_ref().map(|f| f.semantic_completeness),
            finalization_notes: trace
                .finalization
                .as_ref()
                .map(|f| f.notes.clone())
                .unwrap_or_default(),
            loss_records_by_kind: by_kind,
            total_loss_count,
            dropped_payload_events: dropped_events,
            dropped_payload_bytes: dropped_bytes,
            degraded_events: degraded,
            recovery_issues: issues,
            missing_blob_refs: missing_blobs,
            index_matches_scan: trace.index_matches_scan,
            has_stored_index: trace.stored_index.is_some(),
        }
    }

    /// Event Integrity に損失があるか（Loss Record・落ちた Payload・
    /// Finalization の非 Complete 宣言のいずれか）。shirusu-test の
    /// `no-integrity-loss` ルールの判定材料。
    pub fn has_event_loss(&self) -> bool {
        !self.loss_records_by_kind.is_empty()
            || self.dropped_payload_events > 0
            || self.missing_blob_refs > 0
            || matches!(self.event_integrity, Some(level) if level != 0)
    }
}

/// `ReadTrace` の平坦化ビュー。
pub struct TraceView<'a> {
    pub trace: &'a ReadTrace,
    pub events: Vec<EventView>,
    pub integrity: IntegritySummary,
}

impl<'a> TraceView<'a> {
    pub fn build(trace: &'a ReadTrace) -> Self {
        let mut events = Vec::new();
        for batch in &trace.batches {
            for e in &batch.events {
                let schema_name = trace.registry.get(e.schema_id).map(|def| def.name.clone());
                let api_name = schema_name
                    .as_deref()
                    .map(|n| api_name_of_schema(n).to_string());
                let (fields, args_error) = decode_fields(trace, e.schema_id, e.args.as_deref());
                events.push(EventView {
                    index: events.len(),
                    session_id: batch.session_id,
                    process_id: batch.process_id,
                    raw_pid: batch.raw_pid,
                    thread_id: batch.thread_id,
                    qpc_frequency: batch.qpc_frequency,
                    kind: e.kind,
                    sequence: e.sequence,
                    timestamp_qpc: e.timestamp_qpc,
                    call_id: e.call_id,
                    parent_call_id: e.parent_call_id,
                    api_id: e.api_id,
                    schema_id: e.schema_id,
                    api_name,
                    schema_name,
                    capture: e.capture,
                    fields,
                    args_error,
                    payload: PayloadView::of(&e.payload),
                });
            }
        }
        let integrity = IntegritySummary::of(trace);
        TraceView {
            trace,
            events,
            integrity,
        }
    }

    /// API 別の Enter/Leave 件数（名前順）。
    pub fn api_stats(&self) -> Vec<(String, u64, u64)> {
        let mut map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for ev in &self.events {
            let key = ev
                .api_name
                .clone()
                .unwrap_or_else(|| format!("api#{}", ev.api_id));
            let entry = map.entry(key).or_default();
            match ev.phase() {
                Phase::Enter => entry.0 += 1,
                Phase::Leave => entry.1 += 1,
                Phase::Other(_) => {}
            }
        }
        map.into_iter().map(|(k, (a, b))| (k, a, b)).collect()
    }

    /// スレッド数（(session, process, thread) の相異なる組の数）。
    pub fn thread_count(&self) -> usize {
        let mut keys: Vec<(u64, u64, u64)> = self
            .events
            .iter()
            .map(|e| (e.session_id, e.process_id, e.thread_id))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys.len()
    }
}

fn decode_fields(
    trace: &ReadTrace,
    schema_id: u32,
    args: Option<&[u8]>,
) -> (Vec<FieldView>, Option<String>) {
    let Some(bytes) = args else {
        return (Vec::new(), None);
    };
    let Some(def) = trace.registry.get(schema_id) else {
        return (
            Vec::new(),
            Some(format!("schema {schema_id} not registered")),
        );
    };
    let Some(types) = trace.registry.types(schema_id) else {
        return (
            Vec::new(),
            Some(format!("schema {schema_id} has unknown types")),
        );
    };
    match decode_values(&types, bytes) {
        Ok(values) => {
            let fields = values
                .into_iter()
                .enumerate()
                .map(|(i, cv)| FieldView {
                    name: def
                        .fields
                        .get(i)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| format!("field{i}")),
                    ty: cv.value.ty(),
                    kind: def
                        .fields
                        .get(i)
                        .map(|f| ValueKind::from_flags(f.flags))
                        .unwrap_or(ValueKind::Unspecified),
                    capture: cv.capture,
                    value: cv.value,
                })
                .collect();
            (fields, None)
        }
        Err(e) => (Vec::new(), Some(format!("decode failed: {e}"))),
    }
}
