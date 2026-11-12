//! Trace Writer：公開 Trace を Block Container へ順に書き出す。
//!
//! 不変条件（docs/trace-format.md）:
//! - 先頭は Header Block、次に Environment Block。
//! - Blob は、それを参照する Event Chunk より前に Blob Chunk として
//!   書く（前方参照を許さない）。`add_payload` で受けた Payload は
//!   バッファし、次の Event Chunk の直前（と finalize 時）に流す。
//! - 同じ Blob はセッション内で一度だけ書く（重複排除）。
//! - Schema Block を書くときは、直後にその時点までの全定義の複製を
//!   Schema Checkpoint Block として書く（F22: 単一 Block の破損に
//!   対する冗長性。Reader はどちらか一方のコピーが残っていれば
//!   型付き解釈ができる）。
//! - Event Chunk / Blob Chunk は非圧縮サイズが
//!   `WriterOptions::chunk_raw_target`（既定 512 KiB）を目安に分割し、チャンク単位で
//!   Zstd 圧縮する（圧縮で膨らむ場合は無圧縮で格納する）。
//! - メタデータ系 Block は無圧縮。
//! - Blob の部分的な更新は BlobUpdate Block として書く（F18）。
//!   基底の Blob Chunk が先に書かれるよう、更新の書出し前に
//!   `flush_blobs` を行う。更新が宣言する新版 ID は既知として登録し、
//!   後続のイベントが参照できる（Reader は更新を畳み込んで新版の
//!   内容を復元する）。
//! - 記録モード `profile`（L09）の集計は ProfileSummary Block として
//!   `finish` の前に書く。個別イベントは保存されない。
//! - `finish` で Index と Finalization を書く。`finish` せずに
//!   終わったファイルは「途中で終わった Trace」として Reader が読む。
//!
//! 永続化（F21）: 書き出し先の永続化の強さは [`Durability`] で選ぶ。
//! 既定の [`Durability::Buffered`] は `flush` だけを行う（現行挙動）。
//! `SyncOnFinish` は `finish` の成功時に `sync_all` を 1 回行い、
//! `SyncPerBlock` は各 Block の書き込み後に `sync_all` を行う。
//! 保証範囲の詳細は `docs/trace-format.md`「永続化と復旧保証」節を参照。

use crate::blob::{BlobId, BlobUpdate};
use crate::compact;
use crate::container::{
    BlockHeader, BlockType, Compression, FileHeader, DEFAULT_CHUNK_RAW_TARGET, HEADER_LEN,
    MAX_RAW_LEN, MAX_STORED_LEN,
};
use crate::error::{Result, TraceError};
use crate::model::{EventBatch, PayloadRef};
use crate::proto::{
    BlockIndex, CaptureEnvironment, Finalization, IndexEntry, LossRecord, ProfileSummary,
    SchemaDef, SchemaSet,
};
use crate::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet};
use std::io::Write;

/// Writer が書き出し先へ永続化を求める強さ（F21）。
///
/// 保証範囲は設定ごとに異なる（詳細は `docs/trace-format.md`
/// 「永続化と復旧保証」節）:
///
/// - `Buffered`: `flush` のみ。プロセスのクラッシュには強いが、
///   Host や OS のクラッシュでは最後に OS へ渡したチャンクまでしか
///   保証されない（OS のページキャッシュに残った分は失われ得る）。
/// - `SyncOnFinish`: `finish` の成功時に `sync_all` を 1 回行う。
///   正常終了した Trace は OS クラッシュにも耐える。書き込み途中の
///   クラッシュでは `Buffered` と同じ範囲までしか保証されない。
/// - `SyncPerBlock`: 各 Block の書き込み後に `sync_all` を行う。
///   `write_batch` 等が返った時点で、その Block までが OS クラッシュ
///   にも耐える。`sync_all` の回数が増える分、書き込みは遅くなる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    /// `flush` のみ行う。既定（F21 以前の挙動）。
    #[default]
    Buffered,
    /// `finish` の成功時に `sync_all` を 1 回行う。
    SyncOnFinish,
    /// 各 Block の書き込み後に `sync_all` を行う。
    SyncPerBlock,
}

/// 永続化できる書き先。`Write` に `sync_all` を足したもの。
///
/// `std::fs::File` は OS の `sync_all`（fsync 相当）へ委譲し、
/// `Vec<u8>` や `Cursor<Vec<u8>>` などメモリ上の書き先では何もしない。
/// `BufWriter` は flush してから内側を sync する。
pub trait DurableWrite: Write {
    /// 書き出した内容を永続化する。メモリ上の書き先では何もしない。
    fn sync_all(&mut self) -> std::io::Result<()>;
}

impl DurableWrite for std::fs::File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

impl DurableWrite for Vec<u8> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DurableWrite for std::io::Cursor<Vec<u8>> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: DurableWrite> DurableWrite for std::io::BufWriter<W> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        self.flush()?;
        self.get_mut().sync_all()
    }
}

/// [`TraceWriter`] の作成時オプション。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriterOptions {
    /// 書き出し先への永続化の強さ。既定は [`Durability::Buffered`]。
    pub durability: Durability,
    /// Event / Blob Chunk の非圧縮サイズの目安（F25）。
    /// `0` は既定値 [`DEFAULT_CHUNK_RAW_TARGET`]（512 KiB）と等価。
    /// 256 KiB〜1 MiB の範囲は `shirusu-trace-bench` の測定で決めた
    /// （決定と測定値は `docs/trace-format.md`「チャンクサイズの決定」節
    /// 参照）。小さくすると回復の粒度が細かくなる代わりに Block
    /// ヘッダーと Zstd フレームの数が増え、大きくすると圧縮率は上がるが
    /// 1 Block の破損で失われる量が増える。
    pub chunk_raw_target: usize,
}

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

pub struct TraceWriter<W: DurableWrite> {
    inner: W,
    session_id: u64,
    next_sequence: u64,
    offset: u64,
    registry: SchemaRegistry,
    /// 登録済みだがまだ Schema Block に書いていない Schema。
    unwritten_schemas: Vec<SchemaDef>,
    seen_blobs: HashSet<BlobId>,
    /// 既知の Blob ID から内容長への写像（F18: 更新の範囲検証用。
    /// 派生版も含む。長さは更新で変わらない）。
    blob_lens: HashMap<BlobId, usize>,
    pending_blobs: Vec<(BlobId, Vec<u8>)>,
    pending_blob_raw: usize,
    index: Vec<IndexEntry>,
    last_sequence_by_thread: HashMap<(u64, u64), u64>,
    total_events: u64,
    total_loss_records: u64,
    finished: bool,
    durability: Durability,
    /// Environment の SessionMetadata 由来の QPC 周波数（L09:
    /// `profile` 集計の所要時間換算に使う）。
    qpc_frequency: u64,
    /// Event / Blob Chunk の非圧縮サイズの目安（`WriterOptions` 由来。
    /// `0` は既定値に解決済み）。
    chunk_raw_target: usize,
}

impl<W: DurableWrite> TraceWriter<W> {
    /// Header Block と Environment Block を書いて Writer を作る。
    /// session_id は Environment の SessionMetadata と一致させる
    /// （形式仕様の決定）。永続化は既定の [`Durability::Buffered`]
    ///（`flush` のみ）。
    pub fn new(inner: W, environment: CaptureEnvironment) -> Result<Self> {
        Self::with_options(inner, environment, WriterOptions::default())
    }

    /// 永続化設定を指定して Header Block と Environment Block を書く。
    pub fn with_options(
        inner: W,
        environment: CaptureEnvironment,
        options: WriterOptions,
    ) -> Result<Self> {
        let session_id = environment.session.session_id;
        let qpc_frequency = environment.session.qpc_frequency;
        let mut w = Self {
            inner,
            session_id,
            next_sequence: 0,
            offset: 0,
            registry: SchemaRegistry::new(),
            unwritten_schemas: Vec::new(),
            seen_blobs: HashSet::new(),
            blob_lens: HashMap::new(),
            pending_blobs: Vec::new(),
            pending_blob_raw: 0,
            index: Vec::new(),
            last_sequence_by_thread: HashMap::new(),
            total_events: 0,
            total_loss_records: 0,
            finished: false,
            durability: options.durability,
            qpc_frequency,
            chunk_raw_target: if options.chunk_raw_target == 0 {
                DEFAULT_CHUNK_RAW_TARGET
            } else {
                options.chunk_raw_target
            },
        };
        let header = FileHeader::new(session_id);
        w.write_block(BlockType::Header, &header.encode(), false)?;
        w.write_block(BlockType::Environment, &environment.encode(), false)?;
        Ok(w)
    }

    /// この Writer の永続化設定。
    pub fn durability(&self) -> Durability {
        self.durability
    }

    /// Environment の SessionMetadata 由来の QPC 周波数（L09）。
    pub fn qpc_frequency(&self) -> u64 {
        self.qpc_frequency
    }

    /// この Writer のチャンクサイズの目安（非圧縮バイト数）。
    pub fn chunk_raw_target(&self) -> usize {
        self.chunk_raw_target
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
    /// `flush_schemas` からも Schema Block の直後に自動で呼ばれる
    /// （F22: 単一 Block の破損に対する冗長性）。手動で呼ぶと、長時間
    /// 記録の途中で任意の時点に複製を追加で置ける。
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
        self.blob_lens.insert(id, data.len());
        self.pending_blob_raw += 36 + data.len();
        self.pending_blobs.push((id, data.to_vec()));
        if self.pending_blob_raw >= self.chunk_raw_target {
            self.flush_blobs()?;
        }
        Ok(id)
    }

    /// Blob の部分的な更新を BlobUpdate Block として書く（F18）。
    ///
    /// `resource_id` は基底 Blob の ID、`new_version_id` は更新適用後の
    /// 内容全体の BLAKE3（呼び出し側が、更新後の全体内容を観測したうえで
    /// 求める）。Writer は基底の全体内容を保持しないため、新版 ID の
    /// 正しさは検証しない（Reader が畳み込み結果のハッシュと照合する）。
    ///
    /// 検証するのは「リソースがこのセッションで既知であること」と
    /// 「`offset + data.len()` が基底長以内であること」のみ。いずれかに
    /// 反する場合は `WriterInvariant` エラー。更新は基底の Blob Chunk
    /// より後に書く（先に `flush_blobs` を行う）。新版 ID は既知として
    /// 登録するため、後続のイベントが新版を参照できる（`validate_batch`
    /// が通る）。Reader は更新を畳み込んで新版の内容を復元する。
    pub fn write_blob_update(
        &mut self,
        resource_id: BlobId,
        new_version_id: BlobId,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        let Some(&base_len) = self.blob_lens.get(&resource_id) else {
            return Err(TraceError::WriterInvariant(format!(
                "blob update references unknown resource {resource_id} (add_payload first)"
            )));
        };
        let end = offset.checked_add(data.len() as u64).ok_or_else(|| {
            TraceError::WriterInvariant(format!(
                "blob update offset {offset} + size {} overflows",
                data.len()
            ))
        })?;
        if end > base_len as u64 {
            return Err(TraceError::WriterInvariant(format!(
                "blob update out of range: offset {offset} + size {} exceeds base length {base_len}",
                data.len()
            )));
        }
        // 基底の Blob Chunk を先に流し、更新が基底より後に並ぶようにする。
        self.flush_blobs()?;
        let update = BlobUpdate {
            resource_id,
            new_version_id,
            offset,
            data: data.to_vec(),
        };
        let payload = update.encode();
        self.write_block(BlockType::BlobUpdate, &payload, true)?;
        // 新版は「更新で生まれた Blob」として既知にする。長さは更新で
        // 変わらないため、基底長を引き継ぐ。
        self.seen_blobs.insert(new_version_id);
        self.blob_lens.insert(new_version_id, base_len);
        Ok(())
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
                .insert((batch.process_id, batch.thread_id), last.sequence);
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

    /// 記録モード `profile` の集計を ProfileSummary Block として書く
    ///（L09）。メタデータ系 Block のため無圧縮。`finish` の前に呼ぶ
    /// こと（`finish` が Index を書くため、集計は Index に載る）。
    pub fn write_profile_summary(&mut self, summary: &ProfileSummary) -> Result<()> {
        let payload = summary.encode();
        self.write_block(BlockType::ProfileSummary, &payload, false)?;
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
        // `Buffered` 以外は、最後の flush で OS へ渡した分まで永続化する。
        // `SyncPerBlock` でもここで 1 回 sync する（最終 flush が運んだ分
        // が Block 書き込み後の sync の後になるため）。
        if self.durability != Durability::Buffered {
            self.inner.sync_all()?;
        }
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
        let mut prev = self
            .last_sequence_by_thread
            .get(&(batch.process_id, batch.thread_id))
            .copied();
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
        // L11: 全体順序は Batch 内で全件 Some か全件 None のどちらかで、
        // Some の場合は厳密に増加する（Agent が観測点で採番した順序）。
        // 混在・非増加は書き手の不変条件違反として Batch を拒否する。
        let mut prev_global: Option<u64> = None;
        let mut any_global = false;
        let mut any_plain = false;
        for e in &batch.events {
            match e.global_order {
                Some(g) => {
                    if g == 0 {
                        return Err(TraceError::WriterInvariant(
                            "global_order must be nonzero".into(),
                        ));
                    }
                    any_global = true;
                    if let Some(p) = prev_global {
                        if g <= p {
                            return Err(TraceError::WriterInvariant(format!(
                                "global_order not increasing on thread {}: {p} -> {g}",
                                batch.thread_id
                            )));
                        }
                    }
                    prev_global = Some(g);
                }
                None => any_plain = true,
            }
        }
        if any_global && any_plain {
            return Err(TraceError::WriterInvariant(
                "batch mixes events with and without global_order".into(),
            ));
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
        // L11: 全体順序の差分の見積もりも encode と同じ規則で数える。
        let has_global_order = batch.events.iter().any(|e| e.global_order.is_some());
        let mut prev_global: Option<u64> = if start > 0 {
            batch.events[start - 1].global_order
        } else {
            None
        };
        while end < batch.events.len() {
            scratch.clear();
            let global_delta = if has_global_order {
                let g = batch.events[end].global_order.unwrap_or(0);
                let d = match prev_global {
                    None => g,
                    Some(p) => g.wrapping_sub(p),
                };
                prev_global = Some(g);
                Some(d)
            } else {
                None
            };
            compact::encode_event_fields(&mut scratch, &batch.events[end], 0, 0, global_delta);
            if end > start && est + scratch.len() > self.chunk_raw_target {
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
        self.write_block(BlockType::Schema, &payload, false)?;
        // F22: Schema Block の直後に、その時点までの全定義の複製を
        // Schema Checkpoint Block として書く。Reader はファイル全体
        // から 1 つのレジストリを構築するため、Schema Block と
        // Checkpoint のどちらか一方のコピーが残っていれば型付き解釈
        // ができる。単一 Block の破損に対する冗長性であり、Checkpoint
        // 自体は write_schema_checkpoint() でも任意の時点で書ける。
        self.write_schema_checkpoint()?;
        Ok(())
    }

    fn flush_blobs(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending_blobs);
        self.pending_blob_raw = 0;
        let mut cur: Vec<u8> = Vec::new();
        for (id, data) in pending {
            let entry_len = 36 + data.len();
            if !cur.is_empty() && cur.len() + entry_len > self.chunk_raw_target {
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
        if self.durability == Durability::SyncPerBlock {
            self.inner.sync_all()?;
        }
        Ok(())
    }
}
