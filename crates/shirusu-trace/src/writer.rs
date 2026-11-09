//! Trace Writer：公開 Trace を Block Container へ順に書き出す。
//!
//! 不変条件（docs/trace-format.md）:
//! - 先頭は Header Block、次に Environment Block。
//! - Blob は、それを参照する Event Chunk より前に Blob Chunk として
//!   書く（前方参照を許さない）。`add_payload` で受けた Payload は
//!   バッファし、次の Event Chunk の直前（と finalize 時）に流す。
//! - 同じ Blob はセッション内で一度だけ書く（重複排除）。
//! - Event Chunk / Blob Chunk は非圧縮サイズが
//!   `DEFAULT_CHUNK_RAW_TARGET` を目安に分割し、チャンク単位で
//!   Zstd 圧縮する（圧縮で膨らむ場合は無圧縮で格納する）。
//! - メタデータ系 Block は無圧縮。
//! - `finish` で Index と Finalization を書く。`finish` せずに
//!   終わったファイルは「途中で終わった Trace」として Reader が読む。

use crate::blob::BlobId;
use crate::compact;
use crate::container::{
    BlockHeader, BlockType, Compression, FileHeader, DEFAULT_CHUNK_RAW_TARGET, HEADER_LEN,
    MAX_RAW_LEN, MAX_STORED_LEN,
};
use crate::error::{Result, TraceError};
use crate::model::{EventBatch, PayloadRef, TraceEvent};
use crate::proto::{
    BlockIndex, CaptureEnvironment, Finalization, IndexEntry, LossRecord, SchemaDef, SchemaSet,
};
use crate::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet};
use std::io::Write;

/// `finish` に渡す完全性情報。Host の IntegrityReport からの写像は
/// Host 側（shirusu-host の変換層）が行い、本クレートは数値で受け取る。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinalizationInfo {
    /// proto の integrity_level 値（0=Complete 1=Degraded 2=Lost 3=Unknown）。
    pub capture_coverage: u32,
    pub event_integrity: u32,
    pub semantic_completeness: u32,
    pub notes: Vec<String>,
}

pub struct TraceWriter<W: Write> {
    inner: W,
    session_id: u64,
    next_sequence: u64,
    offset: u64,
    registry: SchemaRegistry,
    /// 登録済みだがまだ Schema Block に書いていない Schema。
    unwritten_schemas: Vec<SchemaDef>,
    seen_blobs: HashSet<BlobId>,
    pending_blobs: Vec<(BlobId, Vec<u8>)>,
    pending_blob_raw: usize,
    index: Vec<IndexEntry>,
    last_sequence_by_thread: HashMap<u64, u64>,
    total_events: u64,
    total_loss_records: u64,
    finished: bool,
}

impl<W: Write> TraceWriter<W> {
    /// Header Block と Environment Block を書いて Writer を作る。
    /// session_id は Environment の SessionMetadata と一致させる
    /// （形式仕様の決定）。
    pub fn new(inner: W, environment: CaptureEnvironment) -> Result<Self> {
        let session_id = environment.session.session_id;
        let mut w = Self {
            inner,
            session_id,
            next_sequence: 0,
            offset: 0,
            registry: SchemaRegistry::new(),
            unwritten_schemas: Vec::new(),
            seen_blobs: HashSet::new(),
            pending_blobs: Vec::new(),
            pending_blob_raw: 0,
            index: Vec::new(),
            last_sequence_by_thread: HashMap::new(),
            total_events: 0,
            total_loss_records: 0,
            finished: false,
        };
        let header = FileHeader::new(session_id);
        w.write_block(BlockType::Header, &header.encode(), false)?;
        w.write_block(BlockType::Environment, &environment.encode(), false)?;
        Ok(w)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Schema を登録する。content_hash の検証と再定義の禁止は
    /// SchemaRegistry が担う。実際の Schema Block は次の Event Chunk
    /// の直前（または finish 時）にまとめて書く。
    pub fn register_schema(&mut self, def: SchemaDef) -> Result<()> {
        let before = self.registry.len();
        self.registry
            .register(def.clone())
            .map_err(TraceError::WriterInvariant)?;
        if self.registry.len() > before {
            self.unwritten_schemas.push(def);
        }
        Ok(())
    }

    /// 登録済み Schema の型列を引く（Host 変換が Payload を引数値列と
    /// して検証するときに使う）。未知の Schema ID や未知タグを含む
    /// Schema では None。
    pub fn schema_types(&self, schema_id: u32) -> Option<Vec<crate::schema::Ty>> {
        self.registry.types(schema_id)
    }

    /// 登録済み Schema の複製を Schema Checkpoint Block として書く
    /// （途中から読み始める Reader がそれ以前の定義を引けるように）。
    pub fn write_schema_checkpoint(&mut self) -> Result<()> {
        if self.registry.is_empty() {
            return Ok(());
        }
        let mut set = SchemaSet::default();
        for id in self.registry.ids() {
            if let Some(def) = self.registry.get(*id) {
                set.schemas.push(def.clone());
            }
        }
        let payload = set.encode();
        self.write_block(BlockType::SchemaCheckpoint, &payload, false)
    }

    /// Payload 本体を受け取り Blob ID を返す。既出の内容なら格納せず
    /// 同じ ID を返す（重複排除）。新規 Blob はバッファし、参照する
    /// Event Chunk より前に Blob Chunk として書き出す。
    ///
    /// 1 Blob が 1 Block に収まらなければならないため、エントリ全体
    /// (ID 32 + 長さ 4 + 本体) が Reader の上限 `MAX_RAW_LEN` を超える
    /// Payload は明示的に拒否する (レビュー #4 の #6)。大きな Blob の
    /// 分割保存は未仕様であり、黙って書くと Reader が読めない Trace
    /// ができてしまう。
    pub fn add_payload(&mut self, data: &[u8]) -> Result<BlobId> {
        if data.len() + 36 > MAX_RAW_LEN as usize {
            return Err(TraceError::WriterInvariant(format!(
                "payload of {} bytes exceeds the per-block raw limit ({} bytes incl. entry header); \
                 blob splitting is not supported yet",
                data.len(),
                MAX_RAW_LEN
            )));
        }
        let id = BlobId::of_content(data);
        if self.seen_blobs.contains(&id) {
            return Ok(id);
        }
        self.seen_blobs.insert(id);
        self.pending_blob_raw += 36 + data.len();
        self.pending_blobs.push((id, data.to_vec()));
        if self.pending_blob_raw >= DEFAULT_CHUNK_RAW_TARGET {
            self.flush_blobs()?;
        }
        Ok(id)
    }

    /// Event Batch を書く。先に未書出しの Schema と Blob を流し、
    /// 前方参照が起きない順序を保証する。大きな Batch は目安サイズで
    /// 複数の Event Chunk に分割する（各 Chunk が Batch 文脈を持つ）。
    pub fn write_batch(&mut self, batch: &EventBatch) -> Result<()> {
        self.validate_batch(batch)?;
        self.flush_schemas()?;
        self.flush_blobs()?;
        let mut start = 0;
        while start < batch.events.len() {
            let end = self.chunk_end(batch, start);
            let sub = EventBatch {
                session_id: batch.session_id,
                process_id: batch.process_id,
                raw_pid: batch.raw_pid,
                thread_id: batch.thread_id,
                qpc_frequency: batch.qpc_frequency,
                events: batch.events[start..end].to_vec(),
            };
            let payload = compact::encode_event_chunk(&sub);
            self.write_block(BlockType::EventChunk, &payload, true)?;
            start = end;
        }
        if let Some(last) = batch.events.last() {
            self.last_sequence_by_thread
                .insert(batch.thread_id, last.sequence);
        }
        self.total_events += batch.events.len() as u64;
        Ok(())
    }

    /// Loss Record の列を Loss Block として書く。
    pub fn write_loss_records(&mut self, records: &[LossRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let payload = crate::proto::encode_loss_block(records);
        self.write_block(BlockType::Loss, &payload, false)?;
        self.total_loss_records += records.len() as u64;
        Ok(())
    }

    /// 未書出しの Schema / Blob を流し、Index と Finalization を書いて
    /// 内側の Writer を返す。Finalization Block の存在が正常終了の印。
    pub fn finish(mut self, info: FinalizationInfo) -> Result<W> {
        self.flush_schemas()?;
        self.flush_blobs()?;
        let index = BlockIndex {
            entries: self.index.clone(),
        };
        let payload = index.encode();
        self.write_block(BlockType::Index, &payload, false)?;
        let fin = Finalization {
            total_events: self.total_events,
            total_blobs: self.seen_blobs.len() as u64,
            total_loss_records: self.total_loss_records,
            capture_coverage: info.capture_coverage,
            event_integrity: info.event_integrity,
            semantic_completeness: info.semantic_completeness,
            notes: info.notes,
        };
        let payload = fin.encode();
        self.write_block(BlockType::Finalization, &payload, false)?;
        self.finished = true;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn validate_batch(&self, batch: &EventBatch) -> Result<()> {
        if batch.session_id != self.session_id {
            return Err(TraceError::WriterInvariant(format!(
                "batch session_id {} != writer session_id {}",
                batch.session_id, self.session_id
            )));
        }
        if batch.events.is_empty() {
            return Err(TraceError::WriterInvariant("empty batch".into()));
        }
        let mut prev = self.last_sequence_by_thread.get(&batch.thread_id).copied();
        for e in &batch.events {
            if let Some(p) = prev {
                if e.sequence < p {
                    return Err(TraceError::WriterInvariant(format!(
                        "sequence regressed on thread {}: {p} -> {}",
                        batch.thread_id, e.sequence
                    )));
                }
            }
            prev = Some(e.sequence);
            if let PayloadRef::Blob(id) = &e.payload {
                if !self.seen_blobs.contains(id) {
                    return Err(TraceError::WriterInvariant(format!(
                        "event references blob {id} not added via add_payload"
                    )));
                }
            }
        }
        Ok(())
    }

    /// [start..] のうち、符号化サイズの目安が目標以下に収まる範囲。
    /// 少なくとも 1 イベントは含む（巨大な単一イベントでも進む）。
    fn chunk_end(&self, batch: &EventBatch, start: usize) -> usize {
        // Batch Header（Protobuf）の見積もり。実サイズより小さくならない
        // よう余裕を持たせる（目安なので厳密さは要らない）。
        let mut est = 128usize;
        let mut scratch = Vec::new();
        let mut end = start;
        while end < batch.events.len() {
            scratch.clear();
            compact::encode_event_fields(&mut scratch, &batch.events[end], 0, 0);
            if end > start && est + scratch.len() > DEFAULT_CHUNK_RAW_TARGET {
                break;
            }
            est += scratch.len();
            end += 1;
        }
        end
    }

    fn flush_schemas(&mut self) -> Result<()> {
        if self.unwritten_schemas.is_empty() {
            return Ok(());
        }
        let set = SchemaSet {
            schemas: std::mem::take(&mut self.unwritten_schemas),
        };
        let payload = set.encode();
        self.write_block(BlockType::Schema, &payload, false)
    }

    fn flush_blobs(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending_blobs);
        self.pending_blob_raw = 0;
        let mut cur: Vec<u8> = Vec::new();
        for (id, data) in pending {
            let entry_len = 36 + data.len();
            if !cur.is_empty() && cur.len() + entry_len > DEFAULT_CHUNK_RAW_TARGET {
                let payload = std::mem::take(&mut cur);
                self.write_block(BlockType::BlobChunk, &payload, true)?;
            }
            cur.extend_from_slice(id.as_bytes());
            cur.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cur.extend_from_slice(&data);
        }
        if !cur.is_empty() {
            self.write_block(BlockType::BlobChunk, &cur, true)?;
        }
        Ok(())
    }

    fn write_block(
        &mut self,
        block_type: BlockType,
        payload: &[u8],
        compressible: bool,
    ) -> Result<()> {
        // Writer/Reader 契約 (レビュー #4 の #6): Reader は raw_len
        // (展開後サイズ) が MAX_RAW_LEN を超える Block を拒否する。
        // Writer も同じ上限を守らなければ、書けるのに読めない Trace が
        // できてしまう。stored (格納サイズ) の上限も従来どおり併せて守る。
        if payload.len() > MAX_RAW_LEN as usize {
            return Err(TraceError::WriterInvariant(format!(
                "block payload {} exceeds raw_len limit {} (reader would reject it)",
                payload.len(),
                MAX_RAW_LEN
            )));
        }
        if payload.len() > MAX_STORED_LEN as usize {
            return Err(TraceError::WriterInvariant(format!(
                "block payload {} exceeds stored_len limit",
                payload.len()
            )));
        }
        let (compression, stored) = if compressible && !payload.is_empty() {
            let compressed = crate::container::compress_chunk(payload);
            if compressed.len() < payload.len() {
                (Compression::Zstd, compressed)
            } else {
                (Compression::None, payload.to_vec())
            }
        } else {
            (Compression::None, payload.to_vec())
        };
        let header = BlockHeader {
            block_type,
            compression,
            sequence: self.next_sequence,
            stored_len: stored.len() as u32,
            raw_len: payload.len() as u32,
        };
        let header_bytes = crate::container::serialize_header(&header, &stored);
        debug_assert_eq!(header_bytes.len(), HEADER_LEN);
        self.index.push(IndexEntry {
            offset: self.offset,
            block_type: block_type.code() as u32,
            sequence: self.next_sequence,
        });
        self.inner.write_all(&header_bytes)?;
        self.inner.write_all(&stored)?;
        self.offset += (HEADER_LEN + stored.len()) as u64;
        self.next_sequence += 1;
        Ok(())
    }
}

/// チャンク分割の見積もりで使う、イベント 1 件の符号化長。
/// 差分を 0 として見積もるため実長とは数バイトずれる（目安用途）。
pub fn estimate_event_len(e: &TraceEvent) -> usize {
    let mut v = Vec::new();
    compact::encode_event_fields(&mut v, e, 0, 0);
    v.len()
}
