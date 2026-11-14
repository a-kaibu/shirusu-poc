//! Trace の「ビュー」：`ReadTrace` を平坦化し、Schema レジストリで
//! 引数値列を復号して、表示・検索・比較ができる形にする。
//!
//! ここでの責務は「読めたものを正直に見せる」ことだけであり、値の
//! 解釈（正規化や同一性判定）は shirusu-compare 側の仕事とする。

use crate::json::JsonValue;
use shirusu_trace::compact::decode_values;
use shirusu_trace::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use shirusu_trace::reader::{ReadTrace, RecoveryIssue};
use shirusu_trace::schema::{
    EventCapture, SchemaRegistry, Ty, TypedValue, ValueCapture, ValueKind,
};
use shirusu_trace::BlobId;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// 転送 Descriptor の kind と同じ番号（1 = CallEnter、2 = CallLeave、
/// 7 = CallAborted、8 = CallCompleted）。
pub const KIND_ENTER: u16 = 1;
pub const KIND_LEAVE: u16 = 2;
pub const KIND_ABORTED: u16 = 7;
pub const KIND_COMPLETED: u16 = 8;

/// イベントの相（Enter / Leave / Aborted / Completed / その他）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Enter,
    Leave,
    Aborted,
    Completed,
    Other(u16),
}

impl Phase {
    pub fn of_kind(kind: u16) -> Self {
        match kind {
            KIND_ENTER => Phase::Enter,
            KIND_LEAVE => Phase::Leave,
            KIND_ABORTED => Phase::Aborted,
            KIND_COMPLETED => Phase::Completed,
            other => Phase::Other(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Phase::Enter => "enter",
            Phase::Leave => "leave",
            Phase::Aborted => "aborted",
            Phase::Completed => "completed",
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
        // F20: 値は読めたが生値が古い（この呼び出しのエラーではない）。
        // format_field は Captured 以外を `<stale>` と表示する。
        ValueCapture::Stale => "stale",
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
    /// 全スレッド共通の観測順序番号（L11）。None は未割当。
    pub global_order: Option<u64>,
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
    /// 1 件のイベントを、その Batch の文脈と Schema 登録表で復号する。
    /// 全体読み込み（[`TraceView::build`]）とストリーミング読み取りの
    /// 両方が使う。`index` はファイル順の通し番号。
    pub fn of(registry: &SchemaRegistry, batch: &EventBatch, e: &TraceEvent, index: usize) -> Self {
        let schema_name = registry.get(e.schema_id).map(|def| def.name.clone());
        let api_name = schema_name
            .as_deref()
            .map(|n| api_name_of_schema(n).to_string());
        let (fields, args_error) = decode_fields(registry, e.schema_id, e.args.as_deref());
        EventView {
            index,
            session_id: batch.session_id,
            process_id: batch.process_id,
            raw_pid: batch.raw_pid,
            thread_id: batch.thread_id,
            qpc_frequency: batch.qpc_frequency,
            kind: e.kind,
            sequence: e.sequence,
            global_order: e.global_order,
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
        }
    }
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
        // L11: 全体順序がある場合だけ表示する（無い Trace の表示は変わらない）。
        if let Some(g) = self.global_order {
            let _ = write!(s, "g={g} ");
        }
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
        if let Some(names) = self.com_interface_names() {
            let _ = write!(s, " interface={}", names.join("|"));
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

    /// IID identification is descriptive; it says nothing about intercepted methods.
    pub fn com_interface_names(&self) -> Option<&'static [&'static str]> {
        if !matches!(self.api_name.as_deref(), Some("com!method" | "com!factory")) {
            return None;
        }
        let field = self.field("iid")?;
        if field.capture != ValueCapture::Captured {
            return None;
        }
        let TypedValue::Bytes(bytes) = &field.value else {
            return None;
        };
        let iid: &[u8; 16] = bytes.as_slice().try_into().ok()?;
        shirusu_trace::com_catalog::interface_by_iid(iid).map(|entry| entry.names)
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
        JsonValue::obj({
            let mut entries = vec![
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
            ];
            if let Some(names) = self.com_interface_names() {
                entries.push((
                    "com_interfaces",
                    JsonValue::Array(names.iter().map(|n| JsonValue::Str((*n).into())).collect()),
                ));
            }
            // L11: 全体順序がある場合だけ出す（無い Trace の JSON は変わらない）。
            if let Some(g) = self.global_order {
                entries.push(("global_order", JsonValue::U64(g)));
            }
            entries
        })
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
        TypedValue::Str16(units) => match String::from_utf16(units) {
            Ok(s) => JsonValue::Str(s),
            Err(_) => JsonValue::obj(vec![(
                "utf16",
                JsonValue::Array(units.iter().map(|&u| JsonValue::U64(u as u64)).collect()),
            )]),
        },
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

/// イベントごとに数える完全性の材料（全体読み込みとストリーミングで共用）。
#[derive(Debug, Default, Clone)]
pub struct IntegrityCounts {
    pub dropped_payload_events: u64,
    pub dropped_payload_bytes: u64,
    pub degraded_events: u64,
    pub missing_blob_refs: u64,
}

impl IntegrityCounts {
    /// 1 件を数える。`blob_present` は参照先 Blob がファイル内にあるか。
    pub fn note(&mut self, e: &TraceEvent, blob_present: impl FnOnce(&BlobId) -> bool) {
        if let PayloadRef::Dropped { original_len, .. } = &e.payload {
            self.dropped_payload_events += 1;
            self.dropped_payload_bytes = self.dropped_payload_bytes.saturating_add(*original_len);
        }
        if e.capture != EventCapture::Captured {
            self.degraded_events += 1;
        }
        if let PayloadRef::Blob(id) = &e.payload {
            if !blob_present(id) {
                self.missing_blob_refs += 1;
            }
        }
    }
}

impl IntegritySummary {
    pub fn of(trace: &ReadTrace) -> Self {
        let mut counts = IntegrityCounts::default();
        for batch in &trace.batches {
            for e in &batch.events {
                counts.note(e, |id| trace.blobs.contains_key(id));
            }
        }
        Self::assemble(trace, &counts)
    }

    /// `trace` のメタデータ (イベント本体は使わない) とイベントごとの
    /// 集計から作る。ストリーミング読み (`stream_trace`) が使う。
    pub fn assemble(trace: &ReadTrace, counts: &IntegrityCounts) -> Self {
        let mut by_kind: BTreeMap<u32, u64> = BTreeMap::new();
        let mut total_loss_count = 0u64;
        for rec in &trace.loss_records {
            *by_kind.entry(rec.kind).or_default() += 1;
            total_loss_count = total_loss_count.saturating_add(rec.count);
        }
        let dropped_events = counts.dropped_payload_events;
        let dropped_bytes = counts.dropped_payload_bytes;
        let degraded = counts.degraded_events;
        let missing_blobs = counts.missing_blob_refs;
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
                RecoveryIssue::ForwardBlobReference { id } => {
                    format!("forward_blob_reference({id})")
                }
                RecoveryIssue::IndexMismatch => "index_mismatch".to_string(),
                RecoveryIssue::LimitExceeded { what } => format!("limit_exceeded({what})"),
                RecoveryIssue::SessionMismatch {
                    what,
                    expected,
                    found,
                } => {
                    format!("session_mismatch(what={what}, expected={expected}, found={found})")
                }
                RecoveryIssue::BlobUpdateMissingBase { resource_id } => {
                    format!("blob_update_missing_base(resource={resource_id})")
                }
                RecoveryIssue::BlobUpdateOutOfRange {
                    resource_id,
                    offset,
                    size,
                    base_len,
                } => {
                    format!(
                        "blob_update_out_of_range(resource={resource_id}, offset={offset}, size={size}, base_len={base_len})"
                    )
                }
                RecoveryIssue::BlobUpdateHashMismatch {
                    resource_id,
                    expected,
                    computed,
                } => {
                    format!(
                        "blob_update_hash_mismatch(resource={resource_id}, expected={expected}, computed={computed})"
                    )
                }
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
            || self
                .recovery_issues
                .iter()
                .any(|issue| issue != "index_mismatch")
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
                events.push(EventView::of(&trace.registry, batch, e, events.len()));
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
                // 中断した呼び出しは Enter には数え、Leave には数えない。
                Phase::Aborted => {}
                // 完了した非同期 I/O は Leave には数えない（leave は既に
                // 数えてある。完了はその値列の遅れての到着である）。
                Phase::Completed => {}
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
    registry: &SchemaRegistry,
    schema_id: u32,
    args: Option<&[u8]>,
) -> (Vec<FieldView>, Option<String>) {
    let Some(bytes) = args else {
        return (Vec::new(), None);
    };
    let Some(def) = registry.get(schema_id) else {
        return (
            Vec::new(),
            Some(format!("schema {schema_id} not registered")),
        );
    };
    let Some(types) = registry.types(schema_id) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_trace::model::PayloadLossReason;

    #[test]
    fn aborted_phase_has_its_own_name() {
        // L08: CallAborted (kind 7) は enter/leave とは別の相。
        assert_eq!(KIND_ABORTED, 7);
        assert_eq!(Phase::of_kind(KIND_ABORTED), Phase::Aborted);
        assert_eq!(Phase::Aborted.name(), "aborted");
        assert_eq!(Phase::of_kind(KIND_ENTER), Phase::Enter);
        assert_eq!(Phase::of_kind(KIND_LEAVE), Phase::Leave);
        assert_eq!(Phase::of_kind(99), Phase::Other(99));
    }

    #[test]
    fn completed_phase_has_its_own_name() {
        // F27: CallCompleted (kind 8) は leave とは別の相。
        assert_eq!(KIND_COMPLETED, 8);
        assert_eq!(Phase::of_kind(KIND_COMPLETED), Phase::Completed);
        assert_eq!(Phase::Completed.name(), "completed");
    }

    #[test]
    fn other_phase_name_and_schema_name_without_suffix() {
        // カバレッジ gap: Phase::Other の名前と、/enter・/leave 接尾辞
        // の無いスキーマ名の API 名抽出。
        assert_eq!(Phase::Other(5).name(), "event");
        assert_eq!(Phase::Enter.name(), "enter");
        assert_eq!(Phase::Leave.name(), "leave");
        assert_eq!(
            api_name_of_schema("kernel32!CreateFileW/enter"),
            "kernel32!CreateFileW"
        );
        assert_eq!(
            api_name_of_schema("kernel32!CreateFileW/leave"),
            "kernel32!CreateFileW"
        );
        assert_eq!(api_name_of_schema("test!Ping"), "test!Ping");
    }

    #[test]
    fn reason_capture_and_value_capture_names() {
        // カバレッジ gap: 各種の名前関数の全バリアント。
        assert_eq!(reason_name(PayloadLossReason::Backpressure), "backpressure");
        assert_eq!(reason_name(PayloadLossReason::TooLarge), "too_large");
        assert_eq!(reason_name(PayloadLossReason::Overflow), "overflow");
        assert_eq!(reason_name(PayloadLossReason::HostStopped), "host_stopped");
        assert_eq!(reason_name(PayloadLossReason::Other), "other");
        assert_eq!(capture_name(EventCapture::Captured), "captured");
        assert_eq!(
            capture_name(EventCapture::MemoryUnreadable),
            "memory_unreadable"
        );
        assert_eq!(
            capture_name(EventCapture::CaptureLimitExceeded),
            "capture_limit_exceeded"
        );
        assert_eq!(
            capture_name(EventCapture::DroppedByBackpressure),
            "dropped_by_backpressure"
        );
        assert_eq!(capture_name(EventCapture::Truncated), "truncated");
        assert_eq!(capture_name(EventCapture::Unsupported), "unsupported");
        assert_eq!(capture_name(EventCapture::Other(9)), "other(9)");
        assert_eq!(value_capture_name(ValueCapture::Captured), "captured");
        assert_eq!(value_capture_name(ValueCapture::Unreadable), "unreadable");
        assert_eq!(value_capture_name(ValueCapture::Truncated), "truncated");
        assert_eq!(value_capture_name(ValueCapture::Unsupported), "unsupported");
        assert_eq!(
            value_capture_name(ValueCapture::LimitExceeded),
            "limit_exceeded"
        );
        assert_eq!(value_capture_name(ValueCapture::Stale), "stale");
    }

    #[test]
    fn integrity_and_loss_kind_names() {
        // カバレッジ gap: 完全性レベル名と Loss 種別名の全バリアント。
        assert_eq!(integrity_level_name(0), "Complete");
        assert_eq!(integrity_level_name(1), "Degraded");
        assert_eq!(integrity_level_name(2), "Lost");
        assert_eq!(integrity_level_name(3), "Unknown");
        assert_eq!(integrity_level_name(4), "Invalid");
        assert_eq!(integrity_level_name(99), "Invalid");
        assert_eq!(loss_kind_name(1), "sequence_gap");
        assert_eq!(loss_kind_name(2), "counters");
        assert_eq!(loss_kind_name(3), "unknown_termination");
        assert_eq!(loss_kind_name(4), "integrity_lost");
        assert_eq!(loss_kind_name(0), "other");
        assert_eq!(loss_kind_name(99), "other");
    }

    #[test]
    fn payload_view_describe_covers_all_variants() {
        // カバレッジ gap: PayloadView::describe の Inline / Dropped。
        let id = BlobId::of_content(b"payload");
        assert_eq!(PayloadView::None.describe(), "none");
        assert_eq!(
            PayloadView::Blob(id).describe(),
            format!("blob:{}", id.to_hex())
        );
        assert_eq!(PayloadView::Inline(vec![1, 2, 3]).describe(), "inline[3]");
        assert_eq!(
            PayloadView::Dropped {
                original_len: 100,
                reason: PayloadLossReason::Overflow,
            }
            .describe(),
            "dropped(len=100, reason=overflow)"
        );
    }

    #[test]
    fn format_value_covers_all_types() {
        // カバレッジ gap: format_value の I64 / F32 / F64 / Bool /
        // Str / BlobRef / Ptr32 / Ptr64。
        assert_eq!(format_value(&TypedValue::I32(-3)), "-3");
        assert_eq!(format_value(&TypedValue::I64(-4)), "-4");
        assert_eq!(format_value(&TypedValue::U32(5)), "5");
        assert_eq!(format_value(&TypedValue::U64(0x2a4)), "0x2a4");
        assert_eq!(
            format_value(&TypedValue::F32Bits(0x3F80_0000)),
            "f32(0x3f800000)"
        );
        assert_eq!(
            format_value(&TypedValue::F64Bits(0x3FF0_0000_0000_0000)),
            "f64(0x3ff0000000000000)"
        );
        assert_eq!(format_value(&TypedValue::Bool(true)), "true");
        assert_eq!(format_value(&TypedValue::Str("a".into())), "\"a\"");
        assert_eq!(format_value(&TypedValue::Str16(vec![0x61])), "\"a\"");
        assert_eq!(
            format_value(&TypedValue::Bytes(vec![0xde, 0xad])),
            "bytes[2]=dead"
        );
        let id = BlobId::of_content(b"payload");
        assert_eq!(
            format_value(&TypedValue::BlobRef(id)),
            format!("blob:{}", id.to_hex())
        );
        assert_eq!(format_value(&TypedValue::Ptr32(0x1234)), "0x00001234");
        assert_eq!(
            format_value(&TypedValue::Ptr64(0x1234)),
            "0x0000000000001234"
        );
    }

    #[test]
    fn value_to_json_covers_all_types() {
        // カバレッジ gap: value_to_json の I64 / F32 / F64 / Bool /
        // Str / Bytes / BlobRef / Ptr32 / Ptr64。
        assert_eq!(value_to_json(&TypedValue::I32(-3)).render(), "-3");
        assert_eq!(value_to_json(&TypedValue::I64(-4)).render(), "-4");
        assert_eq!(value_to_json(&TypedValue::U32(5)).render(), "5");
        assert_eq!(value_to_json(&TypedValue::U64(0x2a4)).render(), "\"0x2a4\"");
        assert_eq!(
            value_to_json(&TypedValue::F32Bits(0x3F80_0000)).render(),
            "\"f32(0x3f800000)\""
        );
        assert_eq!(
            value_to_json(&TypedValue::F64Bits(0x3FF0_0000_0000_0000)).render(),
            "\"f64(0x3ff0000000000000)\""
        );
        assert_eq!(value_to_json(&TypedValue::Bool(true)).render(), "true");
        assert_eq!(
            value_to_json(&TypedValue::Str("hi".into())).render(),
            "\"hi\""
        );
        assert_eq!(
            value_to_json(&TypedValue::Str16(vec![0x68, 0x69])).render(),
            "\"hi\""
        );
        assert_eq!(
            value_to_json(&TypedValue::Bytes(vec![0xde, 0xad])).render(),
            "\"dead\""
        );
        let id = BlobId::of_content(b"payload");
        assert_eq!(
            value_to_json(&TypedValue::BlobRef(id)).render(),
            format!("\"blob:{}\"", id.to_hex())
        );
        assert_eq!(
            value_to_json(&TypedValue::Ptr32(0x1234)).render(),
            "\"0x00001234\""
        );
        assert_eq!(
            value_to_json(&TypedValue::Ptr64(0x1234)).render(),
            "\"0x0000000000001234\""
        );
    }

    #[test]
    fn hex_prefix_truncates_with_ellipsis() {
        // カバレッジ gap: 上限を超えるバイト列は末尾に `..`。
        assert_eq!(hex_prefix(&[0xde, 0xad, 0xbe, 0xef], 2), "dead..");
        assert_eq!(hex_prefix(&[1, 2], 16), "0102");
        assert_eq!(hex_prefix(&[], 16), "");
    }

    #[test]
    fn format_field_covers_non_captured_states() {
        // カバレッジ gap: Captured 以外の取得状態は値ではなく状態名。
        for (capture, name) in [
            (ValueCapture::Unreadable, "unreadable"),
            (ValueCapture::Truncated, "truncated"),
            (ValueCapture::Unsupported, "unsupported"),
            (ValueCapture::LimitExceeded, "limit_exceeded"),
        ] {
            let f = FieldView {
                name: "x".into(),
                ty: Ty::U32,
                kind: ValueKind::Unspecified,
                capture,
                value: TypedValue::U32(0),
            };
            assert_eq!(format_field(&f), format!("x=<{name}>"));
        }
    }
}
