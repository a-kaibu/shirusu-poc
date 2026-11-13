//! ストリーミング Trace Reader。
//!
//! [`crate::reader::read_trace`] はファイル全体をメモリに載せ、全 Event
//! Batch と Blob を展開する。小さな Trace や Unit Test ではこのモデルが
//! 便利だが、長時間の高頻度記録では入力・復号済みイベント・Blob・解析
//! 情報が同時にメモリへ載る。[`TraceStream`] は同じ回復意味論で Block を
//! 1 つずつ読み、保持するのは次の小さな状態だけにする。
//!
//! - Schema 登録表（Event の復号に必要）、Block 位置の一覧（Index の照合用）
//! - Blob ID → Block 位置の表（内容は保持しない。必要になったら
//!   [`TraceStream::load_blob`] で読み直す）
//! - Blob の部分的な更新（F18）の位置（内容は `load_blob` で畳み込む）
//!
//! Event Batch は [`StreamItem::Events`] として 1 件ずつ渡し、呼び出し側が
//! 処理したら捨てられる。`decode_events` を false にすると Event Chunk は
//! CRC だけ検査して復号しない（`inspect` のように Header・Environment・
//! Finalization・集計だけを読む用途）。
//!
//! 回復意味論は全体読み込みと同じ: 先頭が Header Block でなければ拒否し、
//! 以降の破損は Block 単位で隔離して issue に記録する。全体読み込みとの
//! 違いは次のとおり。
//! - Event の復号に使う Schema は、その Event Chunk より前に現れたもの
//!   だけ（レイアウト規則どおり Schema は先に書かれる）。
//! - Blob の欠落・前方参照（F23）と更新（F18）の畳み込みの issue は
//!   [`TraceStream::finish`] でまとめて記録する（Blob ID ごとに最初の参照
//!   位置だけを覚え、畳み込みは更新されるリソースの内容だけを一時的に持つ）。
//!   走査中の更新は [`StreamItem::BlobUpdate`] として渡す。
//! - `decode_events = false` では Event を復号しないため、Blob の参照に
//!   関する issue（欠落・前方参照）は判定できない。

use crate::blob::{apply_update_to, BlobId, BlobUpdate};
use crate::compact;
use crate::container::{
    self, BlockType, Compression, FileHeader, HEADER_LEN, MAX_RAW_LEN, MAX_STORED_LEN,
};
use crate::error::{Result, TraceError};
use crate::model::{EventBatch, PayloadRef};
use crate::proto::{
    BlockIndex, CaptureEnvironment, Finalization, LossRecord, ProfileSummary, SchemaDef, SchemaSet,
};
use crate::reader::{ReaderLimits, RecoveryIssue, ScannedBlock};
use crate::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

/// ストリーミング読み取りの設定。
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// Event Chunk を復号して [`StreamItem::Events`] として渡すか。false の
    /// 場合は CRC だけ検査し、件数も数えない（[`StreamItem::SkippedEvents`]）。
    pub decode_events: bool,
    /// Blob Chunk の内容を [`StreamItem::Blobs`] として渡すか。false でも
    /// ID と位置は記録し、`load_blob` で後から読める。
    pub yield_blobs: bool,
    pub limits: ReaderLimits,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            decode_events: true,
            yield_blobs: false,
            limits: ReaderLimits::default(),
        }
    }
}

/// 1 Block から取り出した内容。
#[derive(Debug)]
pub enum StreamItem {
    Environment(CaptureEnvironment),
    /// この Block で新たに登録された Schema（既登録と同一の再登録は含まない）。
    Schemas(Vec<SchemaDef>),
    Events(EventBatch),
    /// `decode_events = false` のとき、復号せずに通過した Event Chunk。
    SkippedEvents {
        offset: u64,
        raw_len: u32,
    },
    /// 1 つの Blob Chunk で受理した Blob（ID の照合済み）。
    Blobs(Vec<(BlobId, Vec<u8>)>),
    BlobUpdate(BlobUpdate),
    Loss(Vec<LossRecord>),
    Index(BlockIndex),
    Finalization {
        finalization: Finalization,
        cleanly: bool,
    },
    ProfileSummary(ProfileSummary),
}

/// 走査の終わりにまとめる結果。
#[derive(Debug)]
pub struct StreamSummary {
    pub header: FileHeader,
    pub blocks: Vec<ScannedBlock>,
    pub issues: Vec<RecoveryIssue>,
    pub index_matches_scan: bool,
    /// 復号した Event の総数（`decode_events = false` では 0）。
    pub total_events: u64,
}

struct UpdateRecord {
    offset: u64,
    resource_id: BlobId,
    new_version_id: BlobId,
}

/// Block を 1 つずつ読むストリーミング Reader。
pub struct TraceStream<R: Read + Seek> {
    inner: R,
    len: u64,
    pos: u64,
    options: StreamOptions,
    header: FileHeader,
    registry: SchemaRegistry,
    blocks: Vec<ScannedBlock>,
    issues: Vec<RecoveryIssue>,
    blob_offsets: HashMap<BlobId, u64>,
    blob_count: usize,
    blob_bytes: u64,
    updates: Vec<UpdateRecord>,
    /// Event が参照した Blob ID ごとの、最初に参照した Event Chunk の位置
    /// （欠落と前方参照の判定用。Blob ID の種類数に比例する）。
    first_ref: HashMap<BlobId, u64>,
    reported_sessions: HashSet<u64>,
    stored_index: Option<(u64, BlockIndex)>,
    total_events: u64,
    decoded_bytes: u64,
    done: bool,
}

impl<R: Read + Seek> TraceStream<R> {
    /// 既定の設定で開く。先頭が Header Block でなければ `NotATrace`。
    pub fn open(inner: R) -> Result<Self> {
        Self::with_options(inner, StreamOptions::default())
    }

    pub fn with_options(mut inner: R, options: StreamOptions) -> Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        let mut first = [0u8; HEADER_LEN + 24];
        if len < first.len() as u64 {
            return Err(TraceError::NotATrace);
        }
        inner.read_exact(&mut first)?;
        let raw = container::parse_raw_header(&first).ok_or(TraceError::NotATrace)?;
        if raw.header_len as usize != HEADER_LEN
            || raw.reserved != 0
            || raw.block_type_code != BlockType::Header.code()
            || raw.compression_code != Compression::None.code()
            || raw.stored_len != 24
            || raw.raw_len != 24
        {
            return Err(TraceError::NotATrace);
        }
        let payload = &first[HEADER_LEN..];
        if !container::raw_header_crc_matches(&raw, &first[..HEADER_LEN], payload) {
            return Err(TraceError::NotATrace);
        }
        let header = FileHeader::decode(payload).ok_or(TraceError::NotATrace)?;
        if header.container_version != container::CONTAINER_VERSION
            || header.schema_version != container::SCHEMA_VERSION
        {
            return Err(TraceError::NotATrace);
        }
        Ok(Self {
            inner,
            len,
            pos: first.len() as u64,
            options,
            header,
            registry: SchemaRegistry::new(),
            blocks: vec![ScannedBlock {
                offset: 0,
                block_type: BlockType::Header,
                sequence: raw.sequence,
            }],
            issues: Vec::new(),
            blob_offsets: HashMap::new(),
            blob_count: 0,
            blob_bytes: 0,
            updates: Vec::new(),
            first_ref: HashMap::new(),
            reported_sessions: HashSet::new(),
            stored_index: None,
            total_events: 0,
            decoded_bytes: 0,
            done: false,
        })
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// ここまでに登録された Schema。
    pub fn registry(&self) -> &SchemaRegistry {
        &self.registry
    }

    /// ここまでに記録した issue。
    pub fn issues(&self) -> &[RecoveryIssue] {
        &self.issues
    }

    /// 次の内容を読む。内容を持たない Block（未知の種類、破損で隔離した
    /// Block）は読み飛ばす。終わりに達したら None。I/O エラーは Err。
    pub fn next_item(&mut self) -> Result<Option<StreamItem>> {
        while !self.done {
            let Some((offset, block_type, compression, raw_len, payload)) = self.next_block()?
            else {
                self.done = true;
                break;
            };
            if let Some(item) = self.handle_block(offset, block_type, compression, raw_len, payload)
            {
                return Ok(Some(item));
            }
        }
        Ok(None)
    }

    /// 残りを読み捨てて走査を終え、結果をまとめる。
    pub fn finish(mut self) -> Result<StreamSummary> {
        while self.next_item()?.is_some() {}
        let derived = self.fold_updates()?;
        let mut missing: Vec<BlobId> = self
            .first_ref
            .keys()
            .filter(|id| !self.blob_offsets.contains_key(id) && !derived.contains_key(id))
            .copied()
            .collect();
        missing.sort();
        for id in missing {
            self.issues.push(RecoveryIssue::MissingBlob { id });
        }
        let mut forward: Vec<(u64, BlobId)> = self
            .first_ref
            .iter()
            .filter_map(|(id, &first)| {
                let at = self
                    .blob_offsets
                    .get(id)
                    .or_else(|| derived.get(id))
                    .copied()?;
                (at > first).then_some((first, *id))
            })
            .collect();
        forward.sort();
        for (_, id) in forward {
            self.issues.push(RecoveryIssue::ForwardBlobReference { id });
        }
        let mut index_matches_scan = false;
        if let Some((cutoff, stored)) = &self.stored_index {
            let expected: Vec<(u64, u32, u64)> = self
                .blocks
                .iter()
                .filter(|b| b.offset < *cutoff)
                .map(|b| (b.offset, b.block_type.code() as u32, b.sequence))
                .collect();
            let actual: Vec<(u64, u32, u64)> = stored
                .entries
                .iter()
                .map(|e| (e.offset, e.block_type, e.sequence))
                .collect();
            index_matches_scan = expected == actual;
            if !index_matches_scan {
                self.issues.push(RecoveryIssue::IndexMismatch);
            }
        }
        Ok(StreamSummary {
            header: self.header,
            blocks: self.blocks,
            issues: self.issues,
            index_matches_scan,
            total_events: self.total_events,
        })
    }

    /// F18: 全体読み込みと同じ規則で Blob の更新を畳み込み、issue を記録する。
    /// 戻り値は適用に成功した版の ID → 位置。作業中の内容は更新される
    /// リソースの分だけ一時的に保持する（更新は稀な操作である）。
    fn fold_updates(&mut self) -> Result<HashMap<BlobId, u64>> {
        let mut derived_offsets: HashMap<BlobId, u64> = HashMap::new();
        let mut derived: HashMap<BlobId, Vec<u8>> = HashMap::new();
        let mut current: HashMap<BlobId, Vec<u8>> = HashMap::new();
        let mut missing_base_reported: HashSet<BlobId> = HashSet::new();
        let updates: Vec<(u64, BlobId)> = self
            .updates
            .iter()
            .map(|u| (u.offset, u.resource_id))
            .collect();
        for (offset, resource) in updates {
            let base: Vec<u8> = match derived.get(&resource) {
                Some(content) => content.clone(),
                None => match self.blob_offsets.get(&resource).copied() {
                    Some(at) => match self.read_blob_at(at, &resource)? {
                        Some(content) => content,
                        None => continue,
                    },
                    None => {
                        if missing_base_reported.insert(resource) {
                            self.issues.push(RecoveryIssue::BlobUpdateMissingBase {
                                resource_id: resource,
                            });
                        }
                        continue;
                    }
                },
            };
            let Some(update) = self
                .read_block_payload(offset)?
                .and_then(|raw| BlobUpdate::decode(&raw))
            else {
                continue;
            };
            let base_offset = self
                .blob_offsets
                .get(&resource)
                .or_else(|| derived_offsets.get(&resource))
                .copied()
                .unwrap_or(offset);
            if base_offset > offset {
                self.issues
                    .push(RecoveryIssue::ForwardBlobReference { id: resource });
            }
            let base_len = base.len() as u64;
            let known = self.blob_offsets.contains_key(&update.new_version_id)
                || derived.contains_key(&update.new_version_id);
            if !known {
                let exceeded = if self.blob_count >= self.options.limits.max_blobs {
                    Some("blobs")
                } else if base_len
                    > self
                        .options
                        .limits
                        .max_blob_bytes
                        .saturating_sub(self.blob_bytes)
                {
                    Some("blob bytes")
                } else {
                    None
                };
                if let Some(what) = exceeded {
                    self.issues.push(RecoveryIssue::LimitExceeded { what });
                    break;
                }
            }
            let working = current.entry(resource).or_insert(base);
            match apply_update_to(working, update.offset, &update.data) {
                None => self.issues.push(RecoveryIssue::BlobUpdateOutOfRange {
                    resource_id: resource,
                    offset: update.offset,
                    size: update.data.len() as u64,
                    base_len,
                }),
                Some(folded) => {
                    let computed = BlobId::of_content(&folded);
                    if computed != update.new_version_id {
                        self.issues.push(RecoveryIssue::BlobUpdateHashMismatch {
                            resource_id: resource,
                            expected: update.new_version_id,
                            computed,
                        });
                    } else {
                        *working = folded.clone();
                        if !self.blob_offsets.contains_key(&update.new_version_id) {
                            derived_offsets
                                .entry(update.new_version_id)
                                .or_insert(offset.max(base_offset));
                        }
                        if !known {
                            self.blob_bytes += folded.len() as u64;
                            self.blob_count += 1;
                            derived.insert(update.new_version_id, folded);
                        }
                    }
                }
            }
        }
        Ok(derived_offsets)
    }

    /// Blob の内容を読み直す。Blob の部分的な更新（F18）が作った版は、
    /// 基底からファイル順に更新を畳み込んで作る（全体読み込みと同じ規則で、
    /// 失敗した更新は適用しない）。走査済みの範囲に無い ID は None。
    pub fn load_blob(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        let resume = self.pos;
        let result = self.load_blob_inner(id);
        self.inner.seek(SeekFrom::Start(resume))?;
        result
    }

    fn load_blob_inner(&mut self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        if let Some(&offset) = self.blob_offsets.get(id) {
            return self.read_blob_at(offset, id);
        }
        let Some(target) = self.updates.iter().position(|u| u.new_version_id == *id) else {
            return Ok(None);
        };
        let resource = self.updates[target].resource_id;
        let Some(&base_offset) = self.blob_offsets.get(&resource) else {
            return Ok(None);
        };
        let Some(mut working) = self.read_blob_at(base_offset, &resource)? else {
            return Ok(None);
        };
        let chain: Vec<u64> = self.updates[..=target]
            .iter()
            .filter(|u| u.resource_id == resource)
            .map(|u| u.offset)
            .collect();
        for offset in chain {
            let Some(update) = self
                .read_block_payload(offset)?
                .and_then(|raw| BlobUpdate::decode(&raw))
            else {
                continue;
            };
            if let Some(folded) = apply_update_to(&working, update.offset, &update.data) {
                if BlobId::of_content(&folded) == update.new_version_id {
                    working = folded;
                    if update.new_version_id == *id {
                        return Ok(Some(working));
                    }
                }
            }
        }
        Ok(None)
    }

    fn read_blob_at(&mut self, offset: u64, id: &BlobId) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.read_block_payload(offset)? else {
            return Ok(None);
        };
        let mut pos = 0usize;
        while raw.len() - pos >= 36 {
            let entry = BlobId::from_bytes(raw[pos..pos + 32].try_into().expect("32 bytes"));
            let len =
                u32::from_le_bytes(raw[pos + 32..pos + 36].try_into().expect("4 bytes")) as usize;
            pos += 36;
            if raw.len() - pos < len {
                break;
            }
            if entry == *id && BlobId::of_content(&raw[pos..pos + len]) == *id {
                return Ok(Some(raw[pos..pos + len].to_vec()));
            }
            pos += len;
        }
        Ok(None)
    }

    /// 走査で受理済みの Block を読み直して展開する。
    fn read_block_payload(&mut self, offset: u64) -> Result<Option<Vec<u8>>> {
        let Some((raw, payload)) = self.read_verified(offset)? else {
            return Ok(None);
        };
        let Some(compression) = Compression::from_code(raw.compression_code) else {
            return Ok(None);
        };
        Ok(decode_payload(compression, raw.raw_len, &payload).ok())
    }

    /// `offset` の Block を検証付きで読む（長さ上限・CRC）。成立しなければ None。
    fn read_verified(
        &mut self,
        offset: u64,
    ) -> Result<Option<(container::RawBlockHeader, Vec<u8>)>> {
        if self.len.saturating_sub(offset) < HEADER_LEN as u64 {
            return Ok(None);
        }
        let mut head = [0u8; HEADER_LEN];
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(&mut head)?;
        let Some(raw) = container::parse_raw_header(&head) else {
            return Ok(None);
        };
        if raw.header_len as usize != HEADER_LEN
            || raw.reserved != 0
            || Compression::from_code(raw.compression_code).is_none()
            || raw.stored_len > MAX_STORED_LEN
            || raw.raw_len > MAX_RAW_LEN
            || self.len - offset - (HEADER_LEN as u64) < raw.stored_len as u64
        {
            return Ok(None);
        }
        let mut payload = vec![0u8; raw.stored_len as usize];
        self.inner.read_exact(&mut payload)?;
        if !container::raw_header_crc_matches(&raw, &head, &payload) {
            return Ok(None);
        }
        Ok(Some((raw, payload)))
    }

    /// 次の受理可能な Block を探す。破損は issue に記録して再同期する。
    #[allow(clippy::type_complexity)]
    fn next_block(&mut self) -> Result<Option<(u64, BlockType, Compression, u32, Vec<u8>)>> {
        loop {
            let pos = self.pos;
            let remaining = self.len - pos;
            if remaining == 0 {
                return Ok(None);
            }
            if self.blocks.len() >= self.options.limits.max_blocks {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blocks" });
                return Ok(None);
            }
            if remaining < HEADER_LEN as u64 {
                self.issues
                    .push(RecoveryIssue::TruncatedTail { offset: pos });
                return Ok(None);
            }
            let mut head = [0u8; HEADER_LEN];
            self.inner.seek(SeekFrom::Start(pos))?;
            self.inner.read_exact(&mut head)?;
            let reason = match container::parse_raw_header(&head) {
                None => Some("block magic not found".to_string()),
                Some(raw) if raw.header_len as usize != HEADER_LEN || raw.reserved != 0 => {
                    Some("invalid block header fields".into())
                }
                Some(raw) if Compression::from_code(raw.compression_code).is_none() => {
                    Some(format!("unknown compression {}", raw.compression_code))
                }
                Some(raw) if raw.stored_len > MAX_STORED_LEN || raw.raw_len > MAX_RAW_LEN => {
                    Some("block length exceeds limit".into())
                }
                Some(raw) => {
                    if remaining - (HEADER_LEN as u64) < raw.stored_len as u64 {
                        self.issues
                            .push(RecoveryIssue::TruncatedTail { offset: pos });
                        return Ok(None);
                    }
                    let mut payload = vec![0u8; raw.stored_len as usize];
                    self.inner.read_exact(&mut payload)?;
                    if container::raw_header_crc_matches(&raw, &head, &payload) {
                        let block_type = BlockType::from_code(raw.block_type_code);
                        self.blocks.push(ScannedBlock {
                            offset: pos,
                            block_type,
                            sequence: raw.sequence,
                        });
                        self.pos = pos + HEADER_LEN as u64 + raw.stored_len as u64;
                        let compression =
                            Compression::from_code(raw.compression_code).expect("checked");
                        return Ok(Some((pos, block_type, compression, raw.raw_len, payload)));
                    }
                    Some("crc mismatch".into())
                }
            };
            let reason = reason.expect("every rejected header has a reason");
            self.issues.push(RecoveryIssue::CorruptBlock {
                offset: pos,
                reason,
            });
            match self.resync(pos)? {
                Some(found) => {
                    self.issues.push(RecoveryIssue::Resync {
                        from: pos,
                        to: found,
                    });
                    self.pos = found;
                }
                None => {
                    self.issues
                        .push(RecoveryIssue::TruncatedTail { offset: pos });
                    return Ok(None);
                }
            }
        }
    }

    /// 破損位置の次のバイトから、完全な検証を満たす Block の開始を探す。
    fn resync(&mut self, corrupt_from: u64) -> Result<Option<u64>> {
        const WINDOW: usize = 64 * 1024;
        let mut q = corrupt_from + 1;
        let mut window = vec![0u8; WINDOW];
        while q + HEADER_LEN as u64 <= self.len {
            let n = (self.len - q).min(WINDOW as u64) as usize;
            self.inner.seek(SeekFrom::Start(q))?;
            self.inner.read_exact(&mut window[..n])?;
            let mut i = 0;
            while i + 4 <= n {
                if window[i..i + 4] == container::BLOCK_MAGIC {
                    let candidate = q + i as u64;
                    if self.read_verified(candidate)?.is_some() {
                        return Ok(Some(candidate));
                    }
                }
                i += 1;
            }
            // 窓の末尾 3 バイトにまたがる Magic を取りこぼさない。
            q += (n.saturating_sub(3)).max(1) as u64;
        }
        Ok(None)
    }

    fn handle_block(
        &mut self,
        offset: u64,
        block_type: BlockType,
        compression: Compression,
        raw_len: u32,
        stored: Vec<u8>,
    ) -> Option<StreamItem> {
        if block_type == BlockType::EventChunk && !self.options.decode_events {
            return Some(StreamItem::SkippedEvents { offset, raw_len });
        }
        if raw_len as u64
            > self
                .options
                .limits
                .max_decoded_bytes
                .saturating_sub(self.decoded_bytes)
        {
            self.issues.push(RecoveryIssue::LimitExceeded {
                what: "decoded bytes",
            });
            self.done = true;
            return None;
        }
        self.decoded_bytes += raw_len as u64;
        let raw = match decode_payload(compression, raw_len, &stored) {
            Ok(raw) => raw,
            Err(reason) => {
                self.corrupt(offset, reason);
                return None;
            }
        };
        match block_type {
            BlockType::Header => {
                self.corrupt(offset, "duplicate header block".into());
                None
            }
            BlockType::Environment => match CaptureEnvironment::decode(&raw) {
                Ok(env) => {
                    if env.session.session_id != self.header.session_id {
                        self.issues.push(RecoveryIssue::SessionMismatch {
                            what: "environment",
                            expected: self.header.session_id,
                            found: env.session.session_id,
                        });
                    }
                    Some(StreamItem::Environment(env))
                }
                Err(e) => {
                    self.corrupt(offset, format!("environment proto: {e}"));
                    None
                }
            },
            BlockType::Schema | BlockType::SchemaCheckpoint => match SchemaSet::decode(&raw) {
                Ok(set) => {
                    let mut added = Vec::new();
                    for def in set.schemas {
                        let before = self.registry.len();
                        match self.registry.register(def.clone()) {
                            Ok(()) if self.registry.len() > before => added.push(def),
                            Ok(()) => {}
                            Err(reason) => self.corrupt(offset, reason),
                        }
                    }
                    Some(StreamItem::Schemas(added))
                }
                Err(e) => {
                    self.corrupt(offset, format!("schema proto: {e}"));
                    None
                }
            },
            BlockType::EventChunk => match compact::decode_event_chunk(&raw) {
                Ok(batch) => {
                    let total = self.total_events + batch.events.len() as u64;
                    if total > self.options.limits.max_events {
                        self.issues
                            .push(RecoveryIssue::LimitExceeded { what: "events" });
                        self.done = true;
                        return None;
                    }
                    self.total_events = total;
                    if batch.session_id != self.header.session_id
                        && self.reported_sessions.insert(batch.session_id)
                    {
                        self.issues.push(RecoveryIssue::SessionMismatch {
                            what: "event chunk",
                            expected: self.header.session_id,
                            found: batch.session_id,
                        });
                    }
                    for e in &batch.events {
                        if let PayloadRef::Blob(id) = &e.payload {
                            self.first_ref.entry(*id).or_insert(offset);
                        }
                    }
                    Some(StreamItem::Events(batch))
                }
                Err(e) => {
                    self.corrupt(offset, format!("event chunk: {e}"));
                    None
                }
            },
            BlockType::BlobChunk => self.handle_blob_chunk(offset, raw),
            BlockType::BlobUpdate => match BlobUpdate::decode(&raw) {
                Some(update) => {
                    self.updates.push(UpdateRecord {
                        offset,
                        resource_id: update.resource_id,
                        new_version_id: update.new_version_id,
                    });
                    Some(StreamItem::BlobUpdate(update))
                }
                None => {
                    self.corrupt(
                        offset,
                        "blob update payload malformed: declared size mismatch or truncated".into(),
                    );
                    None
                }
            },
            BlockType::Index => match BlockIndex::decode(&raw) {
                Ok(index) => {
                    self.stored_index = Some((offset, index.clone()));
                    Some(StreamItem::Index(index))
                }
                Err(e) => {
                    self.corrupt(offset, format!("index proto: {e}"));
                    None
                }
            },
            BlockType::Finalization => match Finalization::decode(&raw) {
                Ok((finalization, cleanly)) => Some(StreamItem::Finalization {
                    finalization,
                    cleanly,
                }),
                Err(e) => {
                    self.corrupt(offset, format!("finalization proto: {e}"));
                    None
                }
            },
            BlockType::Loss => match crate::proto::decode_loss_block(&raw) {
                Ok(records) => Some(StreamItem::Loss(records)),
                Err(e) => {
                    self.corrupt(offset, format!("loss proto: {e}"));
                    None
                }
            },
            BlockType::ProfileSummary => match ProfileSummary::decode(&raw) {
                Ok(summary) => Some(StreamItem::ProfileSummary(summary)),
                Err(e) => {
                    self.corrupt(offset, format!("profile summary proto: {e}"));
                    None
                }
            },
            BlockType::Unknown(_) => None,
        }
    }

    fn handle_blob_chunk(&mut self, offset: u64, raw: Vec<u8>) -> Option<StreamItem> {
        let mut pos = 0usize;
        let mut yielded = Vec::new();
        while pos < raw.len() {
            if raw.len() - pos < 36 {
                self.corrupt(offset, "blob entry header truncated".into());
                break;
            }
            let id = BlobId::from_bytes(raw[pos..pos + 32].try_into().expect("32 bytes"));
            let len =
                u32::from_le_bytes(raw[pos + 32..pos + 36].try_into().expect("4 bytes")) as usize;
            pos += 36;
            if raw.len() - pos < len {
                self.corrupt(offset, "blob entry body truncated".into());
                break;
            }
            let body = &raw[pos..pos + len];
            pos += len;
            if self.blob_offsets.contains_key(&id) {
                self.issues.push(RecoveryIssue::DuplicateBlob { id });
                continue;
            }
            if self.blob_count >= self.options.limits.max_blobs {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blobs" });
                self.done = true;
                break;
            }
            let computed = BlobId::of_content(body);
            if computed != id {
                self.issues
                    .push(RecoveryIssue::BlobHashMismatch { id, computed });
                continue;
            }
            if body.len() as u64
                > self
                    .options
                    .limits
                    .max_blob_bytes
                    .saturating_sub(self.blob_bytes)
            {
                self.issues
                    .push(RecoveryIssue::LimitExceeded { what: "blob bytes" });
                self.done = true;
                break;
            }
            self.blob_bytes += body.len() as u64;
            self.blob_count += 1;
            self.blob_offsets.insert(id, offset);
            if self.options.yield_blobs {
                yielded.push((id, body.to_vec()));
            }
        }
        (!yielded.is_empty()).then_some(StreamItem::Blobs(yielded))
    }

    fn corrupt(&mut self, offset: u64, reason: String) {
        self.issues
            .push(RecoveryIssue::CorruptBlock { offset, reason });
    }
}

fn decode_payload(
    compression: Compression,
    raw_len: u32,
    stored: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    match compression {
        Compression::None => {
            if stored.len() as u64 != raw_len as u64 {
                return Err("uncompressed block has stored_len != raw_len".into());
            }
            Ok(stored.to_vec())
        }
        Compression::Zstd => container::decompress_chunk(stored, raw_len)
            .map_err(|e| format!("zstd decode failed: {e}")),
    }
}
