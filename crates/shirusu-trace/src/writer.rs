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
//!   Zstd 圧縮を試みる（圧縮で膨らむ場合、または write_batch_uncompressed
//!   で要求された Event Chunk は無圧縮で格納する）。
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
use std::borrow::Cow;
use std::collections::HashMap;
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
    /// 書き出し先の長さを `len` に切り詰め、書き位置もそこへ戻す
    /// （2026-11-14 レビュー P2-10: 書き込みに失敗した Block の書きかけを
    /// 捨てる）。できない書き出し先は `Ok(false)`。
    fn truncate_to(&mut self, len: u64) -> std::io::Result<bool> {
        let _ = len;
        Ok(false)
    }
    /// 書き出し先を `len` まで先に確保する（書き位置は変えない）。
    /// Finalization のための空きを残すのに使う。できない書き出し先は
    /// `Ok(false)`。
    fn reserve_to(&mut self, len: u64) -> std::io::Result<bool> {
        let _ = len;
        Ok(false)
    }
}

impl DurableWrite for std::fs::File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        std::fs::File::sync_all(self)
    }
    fn truncate_to(&mut self, len: u64) -> std::io::Result<bool> {
        use std::io::Seek;
        self.set_len(len)?;
        self.seek(std::io::SeekFrom::Start(len))?;
        Ok(true)
    }
    fn reserve_to(&mut self, len: u64) -> std::io::Result<bool> {
        // NTFS allocates the clusters of a non-sparse file extended this
        // way, so later writes inside it cannot fail for lack of space.
        self.set_len(len)?;
        Ok(true)
    }
}

impl DurableWrite for Vec<u8> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn truncate_to(&mut self, len: u64) -> std::io::Result<bool> {
        self.truncate(len as usize);
        Ok(true)
    }
}

impl DurableWrite for std::io::Cursor<Vec<u8>> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn truncate_to(&mut self, len: u64) -> std::io::Result<bool> {
        self.get_mut().truncate(len as usize);
        self.set_position(len);
        Ok(true)
    }
}

impl<W: DurableWrite> DurableWrite for std::io::BufWriter<W> {
    fn sync_all(&mut self) -> std::io::Result<()> {
        self.flush()?;
        self.get_mut().sync_all()
    }
}

/// 書き出し先の空きが尽きた (`StorageFull`) ことによる失敗か (P2-10)。
pub fn is_storage_full(error: &TraceError) -> bool {
    matches!(error, TraceError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull)
}

/// Writer が Index に載せる Block 数の上限 (2026-11-14 レビュー P1-2)。
/// 以前は無制限で、約 1,700 万 Block で Index Block が 256MiB を超え、
/// 何時間分の記録が Finalization なしで終わった。1 件は符号化で約 15
/// バイト、メモリ上で 24 バイトなので、上限で約 15MiB / 24MiB に収まる。
/// 超えたら Index を書かない (Index は省略可能な最適化)。
pub const MAX_INDEX_ENTRIES: usize = 1 << 20;

/// これ以下の Block は、ヘッダーと本体を 1 回の write で出す。
const SMALL_BLOCK_COALESCE: usize = 64 * 1024;

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
    /// Index に載せる Block 数の上限。`0` は [`MAX_INDEX_ENTRIES`]。
    pub max_index_entries: usize,
    /// 書き出し先を先に確保しておく量（P2-10）。`0` は確保しない。
    /// 確保できなくなったら（ディスク満杯）、残りが
    /// [`FINAL_RESERVE_BYTES`] を割る前にデータ Block を
    /// `StorageFull` で拒否し、Finalization を書ける空きを残す。
    /// 確保した末尾は `finish` で切り詰める。異常終了した Trace には
    /// 0 で埋まった末尾が残る（Reader は途中の破損として扱う）。
    pub reserve_bytes: u64,
}

/// [`WriterOptions::reserve_bytes`] を使い切る前に残す量。Finalization と
/// （入るなら）Index を書くための空き。
pub const FINAL_RESERVE_BYTES: u64 = 1024 * 1024;

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
    /// Definitions written since the last full Schema Checkpoint, and how
    /// many that checkpoint held (P3-11: amortized full copies).
    schemas_since_full_checkpoint: usize,
    last_full_checkpoint_len: usize,
    /// 既知の Blob ID から内容長への写像。重複排除、イベントの参照検査、
    /// 更新の範囲検証（F18。派生版も含む。長さは更新で変わらない）を
    /// 1 つの表で賄う（2026-11-14 レビュー P3-10: ID の集合と長さの表を
    /// 二重に持っていた）。長さは Block の上限内なので u32 に収まる。
    blobs: HashMap<BlobId, u32>,
    pending_blobs: Vec<(BlobId, Vec<u8>)>,
    pending_blob_raw: usize,
    index: Vec<IndexEntry>,
    /// Index の上限を超えて記録をやめたか (P1-2)。Index は省略可能な
    /// 最適化なので、超えたら破棄して Finalization だけを書く。
    index_overflowed: bool,
    max_index_entries: usize,
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
    /// 先に確保する量（0 = 確保しない）と、確保済みの末尾 (P2-10)。
    reserve_bytes: u64,
    reserved_end: u64,
    /// 確保を広げられなくなった (ディスク満杯)。
    reserve_failed: bool,
    /// 書きかけの Block を捨てられず、以後の書き込みが位置をずらす。
    torn: bool,
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
            schemas_since_full_checkpoint: 0,
            last_full_checkpoint_len: 0,
            blobs: HashMap::new(),
            pending_blobs: Vec::new(),
            pending_blob_raw: 0,
            index: Vec::new(),
            index_overflowed: false,
            max_index_entries: if options.max_index_entries == 0 {
                MAX_INDEX_ENTRIES
            } else {
                options.max_index_entries
            },
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
            reserve_bytes: options.reserve_bytes,
            reserved_end: 0,
            reserve_failed: false,
            torn: false,
        };
        let header = FileHeader::new(session_id);
        w.write_block(BlockType::Header, &header.encode(), false)?;
        w.write_block(BlockType::Environment, &environment.encode(), false)?;
        Ok(w)
    }

    /// Append a newer environment snapshot. Readers use the last valid snapshot;
    /// event identity and the session clock must remain unchanged.
    pub fn update_environment(&mut self, environment: &CaptureEnvironment) -> Result<()> {
        if environment.session.session_id != self.session_id
            || environment.session.qpc_frequency != self.qpc_frequency
        {
            return Err(TraceError::WriterInvariant(
                "environment update changes session or clock".into(),
            ));
        }
        self.write_block(BlockType::Environment, &environment.encode(), false)
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

    /// Borrow the registered types without allocating on each event.
    pub fn schema_types_ref(&self, schema_id: u32) -> Option<&[crate::schema::Ty]> {
        self.registry.types_ref(schema_id)
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
        self.write_block(BlockType::SchemaCheckpoint, &payload, false)?;
        self.last_full_checkpoint_len = set.schemas.len();
        self.schemas_since_full_checkpoint = 0;
        Ok(())
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
        if self.blobs.contains_key(&id) {
            return Ok(id);
        }
        self.blobs.insert(id, data.len() as u32);
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
        let Some(base_len) = self.blobs.get(&resource_id).map(|&len| len as usize) else {
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
        self.blobs.insert(new_version_id, base_len as u32);
        Ok(())
    }

    /// Event Batch を書く。先に未書出しの Schema と Blob を流し、
    /// 前方参照が起きない順序を保証する。大きな Batch は目安サイズで
    /// 複数の Event Chunk に分割する（各 Chunk が Batch 文脈を持つ）。
    pub fn write_batch(&mut self, batch: &EventBatch) -> Result<()> {
        self.write_batch_inner(batch, true)
    }

    /// Preserve the complete batch using raw Event Chunks. This avoids compression
    /// CPU work when a live recorder is behind; schema, blob and validation rules
    /// are unchanged. The existing container format permits mixed chunk codecs.
    pub fn write_batch_uncompressed(&mut self, batch: &EventBatch) -> Result<()> {
        self.write_batch_inner(batch, false)
    }

    fn write_batch_inner(&mut self, batch: &EventBatch, compress_events: bool) -> Result<()> {
        self.validate_batch(batch)?;
        self.flush_schemas()?;
        self.flush_blobs()?;
        let mut start = 0;
        while start < batch.events.len() {
            let (end, capacity) = self.chunk_end(batch, start);
            let payload =
                compact::encode_event_chunk_slice(batch, &batch.events[start..end], capacity);
            self.write_block(BlockType::EventChunk, &payload, compress_events)?;
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
        let mut notes = info.notes;
        // P2-10: out of space, the pending Schemas and Blobs are given up so
        // that Finalization still fits; their events were refused as well.
        match self.flush_schemas().and_then(|()| self.flush_blobs()) {
            Err(e) if self.reserve_failed && is_storage_full(&e) => {
                notes.push("storage full: pending schemas or blobs not written".into());
                self.unwritten_schemas.clear();
                self.pending_blobs.clear();
            }
            other => other?,
        }
        let index_len = self.index.len() as u64 * 24 + 64;
        if self.reserve_failed
            && !self.index_overflowed
            && self.offset + index_len + FINAL_RESERVE_BYTES / 2 > self.reserved_end
        {
            notes.push("index omitted: storage full; readers scan the file instead".into());
        } else if self.index_overflowed {
            // Index は省略可能 (trace-format)。Reader は走査結果を使う。
            notes.push(format!(
                "index omitted: more than {} blocks; readers scan the file instead",
                self.max_index_entries
            ));
        } else {
            let index = BlockIndex {
                entries: std::mem::take(&mut self.index),
            };
            let payload = index.encode();
            drop(index);
            self.write_block(BlockType::Index, &payload, false)?;
        }
        let fin = Finalization {
            total_events: self.total_events,
            total_blobs: self.blobs.len() as u64,
            total_loss_records: self.total_loss_records,
            capture_coverage: info.capture_coverage,
            event_integrity: info.event_integrity,
            semantic_completeness: info.semantic_completeness,
            notes,
        };
        let payload = fin.encode();
        self.write_block(BlockType::Finalization, &payload, false)?;
        self.finished = true;
        self.inner.flush()?;
        if self.reserved_end > self.offset {
            // Give the unused reservation back.
            self.inner.truncate_to(self.offset)?;
        }
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
                if !self.blobs.contains_key(id) {
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
    fn chunk_end(&self, batch: &EventBatch, start: usize) -> (usize, usize) {
        // Batch Header（Protobuf）の見積もり。実サイズより小さくならない
        // よう余裕を持たせる（目安なので厳密さは要らない）。
        let mut est = 128usize;
        let mut end = start;
        let mut prev_seq = batch.events[start].sequence;
        let mut prev_ts = batch.events[start].timestamp_qpc;
        // Every chunk restarts its delta bases; global order starts absolute.
        let mut prev_global: Option<u64> = None;
        while end < batch.events.len() {
            let event = &batch.events[end];
            let global_delta = event.global_order.map(|g| {
                let delta = prev_global.map_or(g, |previous| g.wrapping_sub(previous));
                prev_global = Some(g);
                delta
            });
            let size = compact::encoded_event_fields_len(
                event,
                event.sequence.wrapping_sub(prev_seq),
                event.timestamp_qpc.wrapping_sub(prev_ts) as i64,
                global_delta,
            );
            if end > start && est.saturating_add(size) > self.chunk_raw_target {
                break;
            }
            est = est.saturating_add(size);
            prev_seq = event.sequence;
            prev_ts = event.timestamp_qpc;
            end += 1;
        }
        (end, est)
    }

    fn flush_schemas(&mut self) -> Result<()> {
        if self.unwritten_schemas.is_empty() {
            return Ok(());
        }
        let set = SchemaSet {
            schemas: std::mem::take(&mut self.unwritten_schemas),
        };
        let payload = set.encode();
        if let Err(e) = self.write_block(BlockType::Schema, &payload, false) {
            // Still unwritten (P2-10): a later flush must write them.
            self.unwritten_schemas = set.schemas;
            return Err(e);
        }
        // F22: Schema Block の直後に、その定義の複製を Schema Checkpoint
        // Block として書く。Reader はファイル全体から 1 つのレジストリを
        // 構築するため、Schema Block と Checkpoint のどちらか一方の
        // コピーが残っていれば型付き解釈ができる（単一 Block の破損に
        // 対する冗長性）。
        //
        // 全定義の複製は、前回の全体複製以降に増えた定義数がその大きさに
        // 達したときだけ書き、それ以外は今回の定義だけを複製する。遅延
        // 登録のたびに全定義を書くと定義数の二乗になる（2026-11-14
        // レビュー P3-11）。全体複製の大きさは毎回 2 倍以上になるため、
        // 複製の総量は定義数の 3 倍以内に収まる（全体複製で 2 倍、差分で 1 倍）。
        self.schemas_since_full_checkpoint += set.schemas.len();
        if self.schemas_since_full_checkpoint >= self.last_full_checkpoint_len {
            self.write_schema_checkpoint()?;
        } else {
            self.write_block(BlockType::SchemaCheckpoint, &payload, false)?;
        }
        Ok(())
    }

    fn flush_blobs(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending_blobs);
        self.pending_blob_raw = 0;
        let mut cur: Vec<u8> = Vec::new();
        // First pending Blob not yet in a written Block.
        let mut first_unwritten = 0;
        let mut result = Ok(());
        for (i, (id, data)) in pending.iter().enumerate() {
            let entry_len = 36 + data.len();
            if !cur.is_empty() && cur.len() + entry_len > self.chunk_raw_target {
                let payload = std::mem::take(&mut cur);
                result = self.write_block(BlockType::BlobChunk, &payload, true);
                if result.is_err() {
                    break;
                }
                first_unwritten = i;
            }
            cur.extend_from_slice(id.as_bytes());
            cur.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cur.extend_from_slice(data);
        }
        if result.is_ok() && !cur.is_empty() {
            result = self.write_block(BlockType::BlobChunk, &cur, true);
            if result.is_ok() {
                first_unwritten = pending.len();
            }
        } else if result.is_ok() {
            first_unwritten = pending.len();
        }
        if result.is_err() {
            // Keep what was not written (P2-10): events referring to these
            // Blobs are already accepted, so a later flush must write them.
            self.pending_blobs = pending.into_iter().skip(first_unwritten).collect();
            self.pending_blob_raw = self
                .pending_blobs
                .iter()
                .fold(0usize, |n, (_, d)| n.saturating_add(36 + d.len()));
        }
        result
    }

    /// Keep [`WriterOptions::reserve_bytes`] allocated ahead of the end
    /// (P2-10). Once it cannot grow, data Blocks are refused before the
    /// last [`FINAL_RESERVE_BYTES`] so Finalization still fits.
    fn ensure_reserve(&mut self, block_type: BlockType, block_len: u64) -> Result<()> {
        if self.reserve_bytes == 0 {
            return Ok(());
        }
        let end = self.offset + block_len;
        if !self.reserve_failed && end + self.reserve_bytes / 2 > self.reserved_end {
            let target = end + self.reserve_bytes;
            match self
                .inner
                .flush()
                .and_then(|()| self.inner.reserve_to(target))
            {
                Ok(true) => self.reserved_end = target,
                Ok(false) => {
                    // The sink cannot reserve: write as if unreserved.
                    self.reserve_bytes = 0;
                    return Ok(());
                }
                Err(_) => self.reserve_failed = true,
            }
        }
        let final_block = matches!(
            block_type,
            BlockType::Header
                | BlockType::Environment
                | BlockType::ProfileSummary
                | BlockType::Index
                | BlockType::Finalization
        );
        let limit = if final_block {
            self.reserved_end
        } else {
            self.reserved_end.saturating_sub(FINAL_RESERVE_BYTES)
        };
        if self.reserve_failed && end > limit {
            return Err(TraceError::Io(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "storage full: the rest is kept for finalization",
            )));
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
                (Compression::Zstd, Cow::Owned(compressed))
            } else {
                (Compression::None, Cow::Borrowed(payload))
            }
        } else {
            (Compression::None, Cow::Borrowed(payload))
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
        if self.torn {
            return Err(TraceError::WriterInvariant(
                "an earlier block write failed and could not be discarded".into(),
            ));
        }
        let block_len = (HEADER_LEN + stored.len()) as u64;
        self.ensure_reserve(block_type, block_len)?;
        let written = if stored.len() <= SMALL_BLOCK_COALESCE {
            // 小さい Block はヘッダーと合わせて 1 回で書く (P1-2: 直接
            // File へ書くため、Block ごとに syscall が 2 回だった)。
            let mut one = Vec::with_capacity(HEADER_LEN + stored.len());
            one.extend_from_slice(&header_bytes);
            one.extend_from_slice(&stored);
            self.inner.write_all(&one)
        } else {
            self.inner
                .write_all(&header_bytes)
                .and_then(|()| self.inner.write_all(&stored))
        };
        if let Err(e) = written {
            // P2-10: drop the partial Block so the Writer stays at a Block
            // boundary (a retry, or Finalization, continues from there).
            let restored = self.inner.flush().is_ok()
                && matches!(self.inner.truncate_to(self.offset), Ok(true));
            if restored && self.reserved_end > self.offset {
                // Truncation released the reservation as well.
                self.reserved_end = self.offset;
            }
            self.torn = !restored;
            return Err(e.into());
        }
        // 書けた Block だけを Index に載せる (P2-10: 書き込みに失敗した
        // Block が Index に残ると、再試行後の位置がずれる)。
        if !self.index_overflowed && block_type != BlockType::Index {
            if self.index.len() >= self.max_index_entries {
                self.index_overflowed = true;
                self.index = Vec::new();
            } else {
                self.index.push(IndexEntry {
                    offset: self.offset,
                    block_type: block_type.code() as u32,
                    sequence: self.next_sequence,
                });
            }
        }
        self.offset += (HEADER_LEN + stored.len()) as u64;
        self.next_sequence += 1;
        if self.durability == Durability::SyncPerBlock {
            self.inner.sync_all()?;
        }
        Ok(())
    }
}
