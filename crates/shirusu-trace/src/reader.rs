//! Trace Reader：回復意味論（docs/trace-format.md の「回復意味論」節）。
//!
//! Reader は入力を信頼しない。先頭が Header Block でなければ Trace
//! ではないとして全体を拒否するが、それ以降の破損は Block 単位で
//! 隔離し、issue として記録したうえで、読める内容を可能な限り返す。
//! 失われたイベントを推測で作ることはしない。
//!
//! v1 はファイル全体をメモリに載せる前提（形式仕様の留保どおり）。

use crate::blob::BlobId;
use crate::compact;
use crate::container::{
    self, BlockType, Compression, FileHeader, HEADER_LEN, MAX_RAW_LEN, MAX_STORED_LEN,
};
use crate::error::{Result, TraceError};
use crate::model::{EventBatch, PayloadRef, TraceEvent};
use crate::proto::{BlockIndex, CaptureEnvironment, Finalization, LossRecord, SchemaSet};
use crate::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet};

/// Reader の上限（DoS 対策の目安値。形式仕様の決定）。
#[derive(Debug, Clone, Copy)]
pub struct ReaderLimits {
    pub max_blocks: usize,
    pub max_events: u64,
    pub max_blobs: usize,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            max_blocks: 1_000_000,
            max_events: 100_000_000,
            max_blobs: 10_000_000,
        }
    }
}

/// 走査中に見つけた問題。破損の種類と位置を値として残す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryIssue {
    /// 末尾で Block ヘッダー / payload が切断していた。ここで走査終了。
    TruncatedTail { offset: u64 },
    /// 単一 Block の破損（CRC 不一致、長さ上限超過、展開失敗、
    /// Protobuf / Compact の復号失敗、重複 Header 等）。
    CorruptBlock { offset: u64, reason: String },
    /// 破損した Block の後、再同期で受理し直した範囲。
    Resync { from: u64, to: u64 },
    /// 同じ Blob ID がファイル内に複数回現れた（内容の同一性によらない）。
    DuplicateBlob { id: BlobId },
    /// イベントが参照する Blob がファイル内に無い。
    MissingBlob { id: BlobId },
    /// 保存されていた Index が走査結果と一致せず、無視した。
    IndexMismatch,
    /// Reader の上限（blocks / events / blobs）に達して走査を止めた。
    LimitExceeded { what: &'static str },
}

/// 走査で受理した Block の位置情報（Index の検証と順序確認用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannedBlock {
    pub offset: u64,
    pub block_type: BlockType,
    pub sequence: u64,
}

/// Payload の解決結果。Reader は Blob の欠落を隠さず明示する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadResolution<'a> {
    None,
    Blob(&'a [u8]),
    Inline(&'a [u8]),
    Dropped {
        original_len: u64,
        reason: crate::model::PayloadLossReason,
    },
    MissingBlob(BlobId),
}

/// 読み取り結果。`finalization` が None のファイルは「途中で終わった
/// 可能性があり、完全性を確定できない」ものとして扱う。
#[derive(Debug)]
pub struct ReadTrace {
    pub header: FileHeader,
    pub environment: Option<CaptureEnvironment>,
    /// ファイル順に新規登録された Schema 定義。
    pub schemas: Vec<crate::proto::SchemaDef>,
    pub registry: SchemaRegistry,
    pub batches: Vec<EventBatch>,
    pub blobs: HashMap<BlobId, Vec<u8>>,
    pub loss_records: Vec<LossRecord>,
    /// ファイルに保存されていた Index（検証前）。最適化であり正ではない。
    pub stored_index: Option<BlockIndex>,
    /// 保存 Index が走査結果（Index Block より前の Block 列）と一致したか。
    pub index_matches_scan: bool,
    pub finalization: Option<Finalization>,
    pub finalized_cleanly: bool,
    pub blocks: Vec<ScannedBlock>,
    pub issues: Vec<RecoveryIssue>,
}

impl ReadTrace {
    /// イベントの Payload を解決する。参照先 Blob がファイル内に
    /// 無ければ `MissingBlob` を返し、イベント自体は失われない。
    pub fn resolve_payload<'a>(&'a self, event: &'a TraceEvent) -> PayloadResolution<'a> {
        match &event.payload {
            PayloadRef::None => PayloadResolution::None,
            PayloadRef::Inline(b) => PayloadResolution::Inline(b),
            PayloadRef::Dropped {
                original_len,
                reason,
            } => PayloadResolution::Dropped {
                original_len: *original_len,
                reason: *reason,
            },
            PayloadRef::Blob(id) => match self.blobs.get(id) {
                Some(data) => PayloadResolution::Blob(data),
                None => PayloadResolution::MissingBlob(*id),
            },
        }
    }

    pub fn total_events(&self) -> u64 {
        self.batches.iter().map(|b| b.events.len() as u64).sum()
    }
}

/// 既定の上限で読む。
pub fn read_trace(data: &[u8]) -> Result<ReadTrace> {
    read_trace_with_limits(data, ReaderLimits::default())
}

pub fn read_trace_with_limits(data: &[u8], limits: ReaderLimits) -> Result<ReadTrace> {
    let mut scan = Scan {
        data,
        limits,
        issues: Vec::new(),
        blocks: Vec::new(),
        environment: None,
        schemas: Vec::new(),
        registry: SchemaRegistry::new(),
        batches: Vec::new(),
        blobs: HashMap::new(),
        loss_records: Vec::new(),
        stored_index: None,
        index_block_offset: None,
        finalization: None,
        finalized_cleanly: false,
        total_events: 0u64,
        stopped_by_limit: false,
        resync_end: 0,
    };
    let header = scan.read_file_header()?;
    scan.run();
    // 参照先 Blob の欠落を、走査後にまとめて明示する（重複は1回だけ）。
    let mut missing: Vec<BlobId> = Vec::new();
    let mut seen_missing: HashSet<BlobId> = HashSet::new();
    for batch in &scan.batches {
        for e in &batch.events {
            if let PayloadRef::Blob(id) = &e.payload {
                if !scan.blobs.contains_key(id) && seen_missing.insert(*id) {
                    missing.push(*id);
                }
            }
        }
    }
    missing.sort();
    for id in missing {
        scan.issues.push(RecoveryIssue::MissingBlob { id });
    }
    // 保存 Index の検証：Index Block より前に走査した Block 列と一致するか。
    let mut index_matches_scan = false;
    if let Some(stored) = &scan.stored_index {
        let cutoff = scan.index_block_offset.unwrap_or(u64::MAX);
        let expected: Vec<(u64, u32, u64)> = scan
            .blocks
            .iter()
            .filter(|b| b.offset < cutoff)
            .map(|b| (b.offset, b.block_type.code() as u32, b.sequence))
            .collect();
        let actual: Vec<(u64, u32, u64)> = stored
            .entries
            .iter()
            .map(|e| (e.offset, e.block_type, e.sequence))
            .collect();
        index_matches_scan = expected == actual;
        if !index_matches_scan {
            scan.issues.push(RecoveryIssue::IndexMismatch);
        }
    }
    Ok(ReadTrace {
        header,
        environment: scan.environment,
        schemas: scan.schemas,
        registry: scan.registry,
        batches: scan.batches,
        blobs: scan.blobs,
        loss_records: scan.loss_records,
        stored_index: scan.stored_index,
        index_matches_scan,
        finalization: scan.finalization,
        finalized_cleanly: scan.finalized_cleanly,
        blocks: scan.blocks,
        issues: scan.issues,
    })
}

struct Scan<'a> {
    data: &'a [u8],
    limits: ReaderLimits,
    issues: Vec<RecoveryIssue>,
    blocks: Vec<ScannedBlock>,
    environment: Option<CaptureEnvironment>,
    schemas: Vec<crate::proto::SchemaDef>,
    registry: SchemaRegistry,
    batches: Vec<EventBatch>,
    blobs: HashMap<BlobId, Vec<u8>>,
    loss_records: Vec<LossRecord>,
    stored_index: Option<BlockIndex>,
    index_block_offset: Option<u64>,
    finalization: Option<Finalization>,
    finalized_cleanly: bool,
    total_events: u64,
    stopped_by_limit: bool,
    /// 直近の再同期で受理した Block の末尾位置（走査再開位置）。
    resync_end: u64,
}

impl<'a> Scan<'a> {
    /// 先頭 Block は厳格に検証する。ここが成立しなければ Trace では
    /// ない（回復の対象外）。
    fn read_file_header(&mut self) -> Result<FileHeader> {
        let data = self.data;
        if data.len() < HEADER_LEN {
            return Err(TraceError::NotATrace);
        }
        let raw = container::parse_raw_header(data).ok_or(TraceError::NotATrace)?;
        if raw.header_len as usize != HEADER_LEN
            || raw.reserved != 0
            || raw.block_type_code != BlockType::Header.code()
            || raw.compression_code != Compression::None.code()
            || raw.stored_len != 24
            || raw.raw_len != 24
        {
            return Err(TraceError::NotATrace);
        }
        let end = HEADER_LEN + 24;
        if data.len() < end {
            return Err(TraceError::NotATrace);
        }
        let payload = &data[HEADER_LEN..end];
        if !container::raw_header_crc_matches(&raw, data, payload) {
            return Err(TraceError::NotATrace);
        }
        let header = FileHeader::decode(payload).ok_or(TraceError::NotATrace)?;
        if header.container_version != container::CONTAINER_VERSION
            || header.schema_version != container::SCHEMA_VERSION
        {
            return Err(TraceError::NotATrace);
        }
        self.blocks.push(ScannedBlock {
            offset: 0,
            block_type: BlockType::Header,
            sequence: raw.sequence,
        });
        Ok(header)
    }

    fn run(&mut self) {
        let mut pos = (HEADER_LEN + 24) as u64;
        loop {
            if self.stopped_by_limit {
                break;
            }
            let remaining = self.data.len() as u64 - pos;
            if remaining == 0 {
                break;
            }
            if self.blocks.len() >= self.limits.max_blocks {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blocks" });
                break;
            }
            if remaining < HEADER_LEN as u64 {
                self.issues
                    .push(RecoveryIssue::TruncatedTail { offset: pos });
                break;
            }
            let start = pos as usize;
            let Some(raw) = container::parse_raw_header(&self.data[start..]) else {
                // Magic が無い = Block として成立しない。破損として記録し再同期。
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset: pos,
                    reason: "block magic not found".into(),
                });
                if !self.resync(pos) {
                    break;
                }
                pos = self.resync_end;
                continue;
            };
            if raw.header_len as usize != HEADER_LEN || raw.reserved != 0 {
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset: pos,
                    reason: "invalid block header fields".into(),
                });
                if !self.resync(pos) {
                    break;
                }
                pos = self.resync_end;
                continue;
            }
            let Some(compression) = Compression::from_code(raw.compression_code) else {
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset: pos,
                    reason: format!("unknown compression {}", raw.compression_code),
                });
                if !self.resync(pos) {
                    break;
                }
                pos = self.resync_end;
                continue;
            };
            if raw.stored_len > MAX_STORED_LEN || raw.raw_len > MAX_RAW_LEN {
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset: pos,
                    reason: "block length exceeds limit".into(),
                });
                if !self.resync(pos) {
                    break;
                }
                pos = self.resync_end;
                continue;
            }
            let payload_start = start + HEADER_LEN;
            let payload_end = payload_start + raw.stored_len as usize;
            if payload_end > self.data.len() {
                // ヘッダーは読めたが payload が切断している = 末尾切断。
                self.issues
                    .push(RecoveryIssue::TruncatedTail { offset: pos });
                break;
            }
            let payload = &self.data[payload_start..payload_end];
            if !container::raw_header_crc_matches(
                &raw,
                &self.data[start..start + HEADER_LEN],
                payload,
            ) {
                // payload 長は信用しない。再同期を試みる。
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset: pos,
                    reason: "crc mismatch".into(),
                });
                if !self.resync(pos) {
                    break;
                }
                pos = self.resync_end;
                continue;
            }
            let block_type = BlockType::from_code(raw.block_type_code);
            self.blocks.push(ScannedBlock {
                offset: pos,
                block_type,
                sequence: raw.sequence,
            });
            self.handle_block(pos, block_type, compression, raw.raw_len, payload);
            pos = payload_end as u64;
        }
    }

    /// 破損した Block の開始位置の次バイトから `SBLK` を探し、完全な
    /// 検証（長さ上限内・payload が収まる・CRC 一致）を満たす候補だけを
    /// Block として受理し直す。受理できたら true（受理 Block は処理済み）。
    fn resync(&mut self, corrupt_from: u64) -> bool {
        let data = self.data;
        let mut q = (corrupt_from + 1) as usize;
        while q + HEADER_LEN <= data.len() {
            if data[q..q + 4] != container::BLOCK_MAGIC {
                q += 1;
                continue;
            }
            let Some(raw) = container::parse_raw_header(&data[q..]) else {
                q += 1;
                continue;
            };
            if raw.header_len as usize != HEADER_LEN || raw.reserved != 0 {
                q += 1;
                continue;
            }
            if Compression::from_code(raw.compression_code).is_none()
                || raw.stored_len > MAX_STORED_LEN
                || raw.raw_len > MAX_RAW_LEN
            {
                q += 1;
                continue;
            }
            let payload_start = q + HEADER_LEN;
            let payload_end = payload_start + raw.stored_len as usize;
            if payload_end > data.len() {
                q += 1;
                continue;
            }
            let payload = &data[payload_start..payload_end];
            if !container::raw_header_crc_matches(&raw, &data[q..q + HEADER_LEN], payload) {
                q += 1;
                continue;
            }
            if self.blocks.len() >= self.limits.max_blocks {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blocks" });
                self.stopped_by_limit = true;
                return false;
            }
            let block_type = BlockType::from_code(raw.block_type_code);
            self.blocks.push(ScannedBlock {
                offset: q as u64,
                block_type,
                sequence: raw.sequence,
            });
            self.issues.push(RecoveryIssue::Resync {
                from: corrupt_from,
                to: q as u64,
            });
            let compression = Compression::from_code(raw.compression_code).expect("checked");
            self.handle_block(q as u64, block_type, compression, raw.raw_len, payload);
            self.resync_end = payload_end as u64;
            return true;
        }
        // 再同期できない場合は末尾切断と同様に扱う。
        self.issues.push(RecoveryIssue::TruncatedTail {
            offset: corrupt_from,
        });
        false
    }

    /// CRC 検証済み Block の中身を種類ごとに取り込む。復号の失敗は
    /// その Block だけを破損として隔離する（走査は続行する）。
    fn handle_block(
        &mut self,
        offset: u64,
        block_type: BlockType,
        compression: Compression,
        raw_len: u32,
        stored_payload: &[u8],
    ) {
        let corrupt = |issues: &mut Vec<RecoveryIssue>, reason: String| {
            issues.push(RecoveryIssue::CorruptBlock { offset, reason });
        };
        let raw_payload: Vec<u8> = match compression {
            Compression::None => {
                if stored_payload.len() as u64 != raw_len as u64 {
                    corrupt(
                        &mut self.issues,
                        "uncompressed block has stored_len != raw_len".into(),
                    );
                    return;
                }
                stored_payload.to_vec()
            }
            Compression::Zstd => match container::decompress_chunk(stored_payload, raw_len) {
                Ok(v) => v,
                Err(e) => {
                    corrupt(&mut self.issues, format!("zstd decode failed: {e}"));
                    return;
                }
            },
        };
        match block_type {
            BlockType::Header => {
                corrupt(&mut self.issues, "duplicate header block".into());
            }
            BlockType::Environment => match CaptureEnvironment::decode(&raw_payload) {
                Ok(env) => self.environment = Some(env),
                Err(e) => corrupt(&mut self.issues, format!("environment proto: {e}")),
            },
            BlockType::Schema | BlockType::SchemaCheckpoint => {
                match SchemaSet::decode(&raw_payload) {
                    Ok(set) => {
                        for def in set.schemas {
                            let before = self.registry.len();
                            match self.registry.register(def.clone()) {
                                Ok(()) => {
                                    if self.registry.len() > before {
                                        self.schemas.push(def);
                                    }
                                }
                                Err(reason) => corrupt(&mut self.issues, reason),
                            }
                        }
                    }
                    Err(e) => corrupt(&mut self.issues, format!("schema proto: {e}")),
                }
            }
            BlockType::EventChunk => match compact::decode_event_chunk(&raw_payload) {
                Ok(batch) => {
                    self.total_events += batch.events.len() as u64;
                    if self.total_events > self.limits.max_events {
                        self.issues
                            .push(RecoveryIssue::LimitExceeded { what: "events" });
                        self.stopped_by_limit = true;
                        return;
                    }
                    self.batches.push(batch);
                }
                Err(e) => corrupt(&mut self.issues, format!("event chunk: {e}")),
            },
            BlockType::BlobChunk => {
                self.handle_blob_chunk(offset, &raw_payload);
            }
            BlockType::Index => match BlockIndex::decode(&raw_payload) {
                Ok(index) => {
                    self.stored_index = Some(index);
                    self.index_block_offset = Some(offset);
                }
                Err(e) => corrupt(&mut self.issues, format!("index proto: {e}")),
            },
            BlockType::Finalization => match Finalization::decode(&raw_payload) {
                Ok((fin, cleanly)) => {
                    self.finalization = Some(fin);
                    self.finalized_cleanly = cleanly;
                }
                Err(e) => corrupt(&mut self.issues, format!("finalization proto: {e}")),
            },
            BlockType::Loss => match crate::proto::decode_loss_block(&raw_payload) {
                Ok(records) => self.loss_records.extend(records),
                Err(e) => corrupt(&mut self.issues, format!("loss proto: {e}")),
            },
            BlockType::Unknown(_) => {
                // 未知の Block は読み飛ばす（破損ではない）。
            }
        }
    }

    fn handle_blob_chunk(&mut self, offset: u64, payload: &[u8]) {
        let mut pos = 0usize;
        while pos < payload.len() {
            if payload.len() - pos < 36 {
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset,
                    reason: "blob entry header truncated".into(),
                });
                return;
            }
            let id = BlobId::from_bytes(payload[pos..pos + 32].try_into().expect("32 bytes"));
            let len = u32::from_le_bytes(payload[pos + 32..pos + 36].try_into().expect("4 bytes"))
                as usize;
            pos += 36;
            if payload.len() - pos < len {
                self.issues.push(RecoveryIssue::CorruptBlock {
                    offset,
                    reason: "blob entry body truncated".into(),
                });
                return;
            }
            let body = payload[pos..pos + len].to_vec();
            pos += len;
            if self.blobs.contains_key(&id) {
                self.issues.push(RecoveryIssue::DuplicateBlob { id });
                continue;
            }
            if self.blobs.len() >= self.limits.max_blobs {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blobs" });
                self.stopped_by_limit = true;
                return;
            }
            self.blobs.insert(id, body);
        }
    }
}
