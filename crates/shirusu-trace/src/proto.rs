//! Protobuf ワイヤ形式の手書き符号化・復号と、Trace メタデータの
//! メッセージ型。形式の正は `docs/trace-format.md` のメッセージ定義。
//!
//! protoc / prost に依存しない判断の理由は trace-format.md の
//! 「依存クレートの判断」を参照。ワイヤ形式自体は標準であり、
//! 未知フィールドは読み飛ばすため、他言語の Protobuf 実装でも読める。

use crate::error::ProtoError;
use crate::module::ModuleClassification;
use crate::static_dep::StaticDependency;

// ---------------------------------------------------------------------------
// ワイヤ形式の基礎
// ---------------------------------------------------------------------------

pub const WIRE_VARINT: u32 = 0;
pub const WIRE_I64: u32 = 1;
pub const WIRE_LEN: u32 = 2;
pub const WIRE_I32: u32 = 5;

#[derive(Default)]
pub struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
    pub fn write_varint(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(b);
                return;
            }
            self.buf.push(b | 0x80);
        }
    }
    fn key(&mut self, field: u32, wire: u32) {
        debug_assert!(field >= 1);
        self.write_varint(((field as u64) << 3) | wire as u64);
    }
    pub fn u64_field(&mut self, field: u32, v: u64) {
        if v == 0 {
            return; // proto3 の既定値は省略する
        }
        self.key(field, WIRE_VARINT);
        self.write_varint(v);
    }
    /// Optional scalar whose presence is meaningful: emitted even when zero.
    pub fn u64_field_present(&mut self, field: u32, v: u64) {
        self.key(field, WIRE_VARINT);
        self.write_varint(v);
    }
    pub fn u32_field(&mut self, field: u32, v: u32) {
        self.u64_field(field, v as u64);
    }
    pub fn bool_field(&mut self, field: u32, v: bool) {
        if !v {
            return;
        }
        self.key(field, WIRE_VARINT);
        self.write_varint(1);
    }
    pub fn bytes_field(&mut self, field: u32, data: &[u8]) {
        self.key(field, WIRE_LEN);
        self.write_varint(data.len() as u64);
        self.buf.extend_from_slice(data);
    }
    pub fn string_field(&mut self, field: u32, s: &str) {
        if s.is_empty() {
            return;
        }
        self.bytes_field(field, s.as_bytes());
    }
    /// 埋め込みメッセージ。`encode` で作ったバイト列を LEN として書く。
    pub fn message_field(&mut self, field: u32, encoded: &[u8]) {
        self.bytes_field(field, encoded);
    }
}

/// フィールド単位で読み進めるリーダー。未知フィールドは `skip` で飛ばす。
pub struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    /// ここまでに読み進めたバイト数。前置メッセージの長さを知るために使う。
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn read_varint(&mut self) -> Result<u64, ProtoError> {
        let mut result: u64 = 0;
        for i in 0..10 {
            let Some(&b) = self.buf.get(self.pos) else {
                return Err(ProtoError::VarintTooLong);
            };
            self.pos += 1;
            if i == 9 && b > 1 {
                // 10 バイト目は 0 か 1 でなければならない (u64 に収まる範囲)。
                return Err(ProtoError::VarintTooLong);
            }
            result |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(ProtoError::VarintTooLong)
    }
    /// 次のフィールドの (番号, wire type) を返す。終わりなら None。
    pub fn next_field(&mut self) -> Result<Option<(u32, u32)>, ProtoError> {
        if self.is_empty() {
            return Ok(None);
        }
        let key = self.read_varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x7) as u32;
        if field == 0 {
            return Err(ProtoError::InvalidFieldNumber);
        }
        match wire {
            WIRE_VARINT | WIRE_I64 | WIRE_LEN | WIRE_I32 => Ok(Some((field, wire))),
            _ => Err(ProtoError::InvalidWireType(wire)),
        }
    }
    pub fn read_len_bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.read_varint()?;
        let len = usize::try_from(len).map_err(|_| ProtoError::LengthOutOfRange {
            len,
            remaining: self.remaining(),
        })?;
        if len > self.remaining() {
            return Err(ProtoError::LengthOutOfRange {
                len: len as u64,
                remaining: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }
    pub fn skip(&mut self, wire: u32) -> Result<(), ProtoError> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_I64 => {
                if self.remaining() < 8 {
                    return Err(ProtoError::TruncatedFixed);
                }
                self.pos += 8;
            }
            WIRE_I32 => {
                if self.remaining() < 4 {
                    return Err(ProtoError::TruncatedFixed);
                }
                self.pos += 4;
            }
            WIRE_LEN => {
                self.read_len_bytes()?;
            }
            _ => return Err(ProtoError::InvalidWireType(wire)),
        }
        Ok(())
    }
    /// 現在位置の値が varint である前提で読む。
    pub fn value_u64(&mut self) -> Result<u64, ProtoError> {
        self.read_varint()
    }
    pub fn value_bool(&mut self) -> Result<bool, ProtoError> {
        Ok(self.read_varint()? != 0)
    }
    pub fn value_bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        self.read_len_bytes()
    }
    pub fn value_string(&mut self) -> Result<String, ProtoError> {
        let b = self.read_len_bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| ProtoError::InvalidUtf8)
    }
}

// ---------------------------------------------------------------------------
// メタデータメッセージ（docs/trace-format.md の定義が正）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionMetadata {
    pub session_id: u64,
    pub created_by: String,
    pub qpc_frequency: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureEnvironment {
    pub session: SessionMetadata,
    pub os_version: String,
    pub os_build: u32,
    pub cpu_arch: String,
    pub pointer_width: u32,
    pub capture_config: String,
    pub feature_flags: u64,
    pub target_description: String,
    /// モジュール分類（L07）。空のときは field 9 を書かないので旧ファイル
    /// と同じバイト列になる。
    pub modules: Vec<ModuleClassification>,
    /// 静的依存情報（L13）。空のときは field 10 を書かないので旧ファイル
    /// と同じバイト列になる。
    pub static_dependencies: Vec<StaticDependency>,
    /// Agent-reported installation evidence; absent in older traces.
    pub hook_evidence: Vec<HookEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldDef {
    pub name: String,
    pub ty: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemaDef {
    pub schema_id: u32,
    pub name: String,
    /// 正規化内容の BLAKE3 先頭 8 バイト（LE u64 として保持）。
    pub content_hash: u64,
    pub fields: Vec<FieldDef>,
    pub annotation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemaSet {
    pub schemas: Vec<SchemaDef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchHeader {
    pub session_id: u64,
    pub process_id: u64,
    pub raw_pid: u32,
    pub thread_id: u64,
    pub base_timestamp_qpc: u64,
    pub qpc_frequency: u64,
    pub first_sequence: u64,
    pub event_count: u32,
    /// この Batch の全イベントが `global_order` を持つ (L11)。
    /// 旧ファイルでは欄が無く false として読む（後方互換）。
    pub has_global_order: bool,
}

/// LossRecord.kind の値。
pub mod loss_kind {
    pub const SEQUENCE_GAP: u32 = 1;
    pub const COUNTERS: u32 = 2;
    pub const UNKNOWN_TERMINATION: u32 = 3;
    pub const INTEGRITY_LOST: u32 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LossRecord {
    pub kind: u32,
    pub count: u64,
    pub dropped_payload_bytes: u64,
    pub degraded_events: u64,
    pub call_id: u64,
    pub reason: String,
    pub process_id: u64,
    pub thread_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndexEntry {
    pub offset: u64,
    pub block_type: u32,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockIndex {
    pub entries: Vec<IndexEntry>,
}

/// 完全性レベル（Finalization の数値表現）。Host の IntegrityLevel と対応する。
pub mod integrity_level {
    pub const COMPLETE: u32 = 0;
    pub const DEGRADED: u32 = 1;
    pub const LOST: u32 = 2;
    pub const UNKNOWN: u32 = 3;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalization {
    pub total_events: u64,
    pub total_blobs: u64,
    pub total_loss_records: u64,
    pub capture_coverage: u32,
    pub event_integrity: u32,
    pub semantic_completeness: u32,
    pub notes: Vec<String>,
}

impl Default for Finalization {
    fn default() -> Self {
        Self {
            total_events: 0,
            total_blobs: 0,
            total_loss_records: 0,
            capture_coverage: integrity_level::COMPLETE,
            event_integrity: integrity_level::COMPLETE,
            semantic_completeness: integrity_level::COMPLETE,
            notes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 各メッセージの encode / decode
// ---------------------------------------------------------------------------

impl SessionMetadata {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u64_field(1, self.session_id);
        w.string_field(2, &self.created_by);
        w.u64_field(3, self.qpc_frequency);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.session_id = r.value_u64()?,
                (2, WIRE_LEN) => m.created_by = r.value_string()?,
                (3, WIRE_VARINT) => m.qpc_frequency = r.value_u64()?,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookEvidence {
    pub api_id: u32,
    pub module: String,
    pub function: String,
    pub method: String,
    pub outcome: String,
    pub reason: String,
    pub scope: String,
    pub semantic_detail: String,
    pub semantic_level: u32,
}

impl HookEvidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string_field(1, &self.module);
        w.string_field(2, &self.function);
        w.string_field(3, &self.method);
        w.string_field(4, &self.outcome);
        w.string_field(5, &self.reason);
        w.string_field(6, &self.scope);
        w.string_field(7, &self.semantic_detail);
        w.u32_field(8, self.semantic_level);
        w.u32_field(9, self.api_id);
        w.into_bytes()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut r = ProtoReader::new(bytes);
        let mut m = Self::default();
        while let Some((field, wire)) = r.next_field()? {
            match (field, wire) {
                (1, WIRE_LEN) => m.module = r.value_string()?,
                (2, WIRE_LEN) => m.function = r.value_string()?,
                (3, WIRE_LEN) => m.method = r.value_string()?,
                (4, WIRE_LEN) => m.outcome = r.value_string()?,
                (5, WIRE_LEN) => m.reason = r.value_string()?,
                (6, WIRE_LEN) => m.scope = r.value_string()?,
                (7, WIRE_LEN) => m.semantic_detail = r.value_string()?,
                (8, WIRE_VARINT) => m.semantic_level = r.value_u64()? as u32,
                (9, WIRE_VARINT) => m.api_id = r.value_u64()? as u32,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl CaptureEnvironment {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.message_field(1, &self.session.encode());
        w.string_field(2, &self.os_version);
        w.u32_field(3, self.os_build);
        w.string_field(4, &self.cpu_arch);
        w.u32_field(5, self.pointer_width);
        w.string_field(6, &self.capture_config);
        w.u64_field(7, self.feature_flags);
        w.string_field(8, &self.target_description);
        for m in &self.modules {
            w.message_field(9, &m.encode());
        }
        for d in &self.static_dependencies {
            w.message_field(10, &d.encode());
        }
        for evidence in &self.hook_evidence {
            w.message_field(11, &evidence.encode());
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.session = SessionMetadata::decode(r.value_bytes()?)?,
                (2, WIRE_LEN) => m.os_version = r.value_string()?,
                (3, WIRE_VARINT) => m.os_build = r.value_u64()? as u32,
                (4, WIRE_LEN) => m.cpu_arch = r.value_string()?,
                (5, WIRE_VARINT) => m.pointer_width = r.value_u64()? as u32,
                (6, WIRE_LEN) => m.capture_config = r.value_string()?,
                (7, WIRE_VARINT) => m.feature_flags = r.value_u64()?,
                (8, WIRE_LEN) => m.target_description = r.value_string()?,
                (9, WIRE_LEN) => m
                    .modules
                    .push(ModuleClassification::decode(r.value_bytes()?)?),
                (10, WIRE_LEN) => m
                    .static_dependencies
                    .push(StaticDependency::decode(r.value_bytes()?)?),
                (11, WIRE_LEN) => m
                    .hook_evidence
                    .push(HookEvidence::decode(r.value_bytes()?)?),
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl FieldDef {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.string_field(1, &self.name);
        w.u32_field(2, self.ty);
        w.u32_field(3, self.flags);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.name = r.value_string()?,
                (2, WIRE_VARINT) => m.ty = r.value_u64()? as u32,
                (3, WIRE_VARINT) => m.flags = r.value_u64()? as u32,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl SchemaDef {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u32_field(1, self.schema_id);
        w.string_field(2, &self.name);
        w.u64_field(3, self.content_hash);
        for fd in &self.fields {
            w.message_field(4, &fd.encode());
        }
        w.string_field(5, &self.annotation);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.schema_id = r.value_u64()? as u32,
                (2, WIRE_LEN) => m.name = r.value_string()?,
                (3, WIRE_VARINT) => m.content_hash = r.value_u64()?,
                (4, WIRE_LEN) => m.fields.push(FieldDef::decode(r.value_bytes()?)?),
                (5, WIRE_LEN) => m.annotation = r.value_string()?,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl SchemaSet {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        for s in &self.schemas {
            w.message_field(1, &s.encode());
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => m.schemas.push(SchemaDef::decode(r.value_bytes()?)?),
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl BatchHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u64_field(1, self.session_id);
        w.u64_field(2, self.process_id);
        w.u32_field(3, self.raw_pid);
        w.u64_field(4, self.thread_id);
        w.u64_field(5, self.base_timestamp_qpc);
        w.u64_field(6, self.qpc_frequency);
        w.u64_field(7, self.first_sequence);
        w.u32_field(8, self.event_count);
        // L11: false は既定値のため書かない（旧ファイルと同じバイト列になる）。
        if self.has_global_order {
            w.u64_field(9, 1);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.session_id = r.value_u64()?,
                (2, WIRE_VARINT) => m.process_id = r.value_u64()?,
                (3, WIRE_VARINT) => m.raw_pid = r.value_u64()? as u32,
                (4, WIRE_VARINT) => m.thread_id = r.value_u64()?,
                (5, WIRE_VARINT) => m.base_timestamp_qpc = r.value_u64()?,
                (6, WIRE_VARINT) => m.qpc_frequency = r.value_u64()?,
                (7, WIRE_VARINT) => m.first_sequence = r.value_u64()?,
                (8, WIRE_VARINT) => m.event_count = r.value_u64()? as u32,
                (9, WIRE_VARINT) => m.has_global_order = r.value_u64()? != 0,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl LossRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u32_field(1, self.kind);
        w.u64_field(2, self.count);
        w.u64_field(3, self.dropped_payload_bytes);
        w.u64_field(4, self.degraded_events);
        w.u64_field(5, self.call_id);
        w.string_field(6, &self.reason);
        w.u64_field(7, self.process_id);
        w.u64_field(8, self.thread_id);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.kind = r.value_u64()? as u32,
                (2, WIRE_VARINT) => m.count = r.value_u64()?,
                (3, WIRE_VARINT) => m.dropped_payload_bytes = r.value_u64()?,
                (4, WIRE_VARINT) => m.degraded_events = r.value_u64()?,
                (5, WIRE_VARINT) => m.call_id = r.value_u64()?,
                (6, WIRE_LEN) => m.reason = r.value_string()?,
                (7, WIRE_VARINT) => m.process_id = r.value_u64()?,
                (8, WIRE_VARINT) => m.thread_id = r.value_u64()?,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

/// Loss Block の payload：`repeated LossRecord records = 1` のメッセージ。
pub fn encode_loss_block(records: &[LossRecord]) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    for r in records {
        w.message_field(1, &r.encode());
    }
    w.into_bytes()
}

pub fn decode_loss_block(buf: &[u8]) -> Result<Vec<LossRecord>, ProtoError> {
    let mut out = Vec::new();
    let mut r = ProtoReader::new(buf);
    while let Some((f, wire)) = r.next_field()? {
        match (f, wire) {
            (1, WIRE_LEN) => out.push(LossRecord::decode(r.value_bytes()?)?),
            _ => r.skip(wire)?,
        }
    }
    Ok(out)
}

impl BlockIndex {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        for e in &self.entries {
            let mut ew = ProtoWriter::new();
            ew.u64_field(1, e.offset);
            ew.u32_field(2, e.block_type);
            ew.u64_field(3, e.sequence);
            w.message_field(1, &ew.into_bytes());
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_LEN) => {
                    let eb = r.value_bytes()?;
                    let mut er = ProtoReader::new(eb);
                    let mut e = IndexEntry::default();
                    while let Some((ef, ewire)) = er.next_field()? {
                        match (ef, ewire) {
                            (1, WIRE_VARINT) => e.offset = er.value_u64()?,
                            (2, WIRE_VARINT) => e.block_type = er.value_u64()? as u32,
                            (3, WIRE_VARINT) => e.sequence = er.value_u64()?,
                            _ => er.skip(ewire)?,
                        }
                    }
                    m.entries.push(e);
                }
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

impl Finalization {
    /// proto 上の `finalized_cleanly` (field 7) は、この Block を書けた
    /// こと自体が正常終了の印であり、符号化時は常に true として出す。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u64_field(1, self.total_events);
        w.u64_field(2, self.total_blobs);
        w.u64_field(3, self.total_loss_records);
        w.u32_field(4, self.capture_coverage);
        w.u32_field(5, self.event_integrity);
        w.u32_field(6, self.semantic_completeness);
        w.bool_field(7, true);
        for n in &self.notes {
            // notes は空文字列も保持したいので string_field の省略規則を使わない
            w.bytes_field(8, n.as_bytes());
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, bool), ProtoError> {
        let mut m = Self::default();
        let mut cleanly = false;
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.total_events = r.value_u64()?,
                (2, WIRE_VARINT) => m.total_blobs = r.value_u64()?,
                (3, WIRE_VARINT) => m.total_loss_records = r.value_u64()?,
                (4, WIRE_VARINT) => m.capture_coverage = r.value_u64()? as u32,
                (5, WIRE_VARINT) => m.event_integrity = r.value_u64()? as u32,
                (6, WIRE_VARINT) => m.semantic_completeness = r.value_u64()? as u32,
                (7, WIRE_VARINT) => cleanly = r.value_bool()?,
                (8, WIRE_LEN) => m.notes.push(r.value_string()?),
                _ => r.skip(wire)?,
            }
        }
        Ok((m, cleanly))
    }
}

/// L09: 記録モード `profile` で API ごとに集計した 1 行。所要時間は
/// QPC ティック（`ProfileSummary.qpc_frequency` で秒へ換算する）。
/// `min_duration_qpc` / `max_duration_qpc` は `calls == 0` のとき 0
///（proto3 の既定値省略と一致し、「呼び出し無し」を表す）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApiProfile {
    pub api_id: u32,
    /// 対応する enter / leave が揃った呼び出しの数。
    pub calls: u64,
    /// 観測した enter の数（対応する leave が無くても数える）。
    pub enters: u64,
    /// 観測した leave の数（対応する enter が無くても数える）。
    pub leaves: u64,
    /// 揃った呼び出しの所要時間の合計（QPC ティック）。
    pub total_duration_qpc: u64,
    pub min_duration_qpc: u64,
    pub max_duration_qpc: u64,
}

impl ApiProfile {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u32_field(1, self.api_id);
        w.u64_field(2, self.calls);
        w.u64_field(3, self.enters);
        w.u64_field(4, self.leaves);
        w.u64_field(5, self.total_duration_qpc);
        w.u64_field(6, self.min_duration_qpc);
        w.u64_field(7, self.max_duration_qpc);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.api_id = r.value_u64()? as u32,
                (2, WIRE_VARINT) => m.calls = r.value_u64()?,
                (3, WIRE_VARINT) => m.enters = r.value_u64()?,
                (4, WIRE_VARINT) => m.leaves = r.value_u64()?,
                (5, WIRE_VARINT) => m.total_duration_qpc = r.value_u64()?,
                (6, WIRE_VARINT) => m.min_duration_qpc = r.value_u64()?,
                (7, WIRE_VARINT) => m.max_duration_qpc = r.value_u64()?,
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}

/// L09: 記録モード `profile` の集計全体。`TraceRecorder::finish` が
/// ProfileSummary Block（種別 11）として Index の前に 1 回だけ書く。
/// `apis` は api_id の昇順。個別イベントは保存されないため、この
/// Block が `profile` モードの記録そのものである。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileSummary {
    pub qpc_frequency: u64,
    /// `record_batch` に渡された全イベント数（種別を問わない）。
    pub total_events_seen: u64,
    pub apis: Vec<ApiProfile>,
}

impl ProfileSummary {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.u64_field(1, self.qpc_frequency);
        w.u64_field(2, self.total_events_seen);
        for api in &self.apis {
            w.message_field(3, &api.encode());
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Self::default();
        let mut r = ProtoReader::new(buf);
        while let Some((f, wire)) = r.next_field()? {
            match (f, wire) {
                (1, WIRE_VARINT) => m.qpc_frequency = r.value_u64()?,
                (2, WIRE_VARINT) => m.total_events_seen = r.value_u64()?,
                (3, WIRE_LEN) => m.apis.push(ApiProfile::decode(r.read_len_bytes()?)?),
                _ => r.skip(wire)?,
            }
        }
        Ok(m)
    }
}
