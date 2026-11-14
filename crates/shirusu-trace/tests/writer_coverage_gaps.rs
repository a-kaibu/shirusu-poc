//! カバレッジ gap のテスト（2026-11-12 の llvm-cov 計測で見つけた
//! `writer.rs` の未実行行を閉じるもの）。
//!
//! 対象は主に次の 3 種：
//! - getter・`write_schema_checkpoint` の両腕・`register_schema` の
//!   拒否・Blob 更新のオーバーフロー／範囲外。
//! - `DurableWrite::sync_all` の各実装（`Vec<u8>` / `Cursor` /
//!   `BufWriter`）と `Durability::SyncOnFinish` / `SyncPerBlock` の
//!   経路（既定の `Buffered` では `sync_all` は呼ばれない）。
//! - 書き込み失敗時の `?` 伝播（`ProbeWriter` で注入する）。
//!   `write_block` は 1 Block あたり `write_all` を 2 回呼ぶため、
//!   失敗させる書き込み回数を数えて狙った `?` を踏む。
//!
//! テストで閉じない行（理由を明記）：
//! - `write_block` の raw_len 上限（585 行）：1 Block で 256 MiB 超の
//!   ペイロードが必要で、単体テストの割に合わない防御チェック。
//! - `write_block` の stored_len 上限（592 行）：到達不能。stored は
//!   圧縮後（圧縮が膨らむ場合は生データ）で raw 以下であり、
//!   stored > 512 MiB なら raw > 512 MiB > 256 MiB で先に 585 行が
//!   発火する。
//! - `write_batch` の `if let Some(last)` の None 腕（380 行）：
//!   空 Batch は `validate_batch` で拒否されるため到達しない。
//! - `write_schema_checkpoint` の `if let Some(def)` の None 腕
//!   （263 行）：`registry.ids()` は存在する id しか返さないため
//!   到達しない。
//! - `register_schema` の `if` の閉じ行（239 行）：llvm-cov の閉じ括弧
//!   への帰属の癖（分岐自体は既存テストで通っている）。

use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, ProfileSummary, SessionMetadata};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::{
    Durability, DurableWrite, FinalizationInfo, TraceWriter, WriterOptions,
};
use std::cell::Cell;
use std::io::{self, Cursor, Write};
use std::rc::Rc;

fn env(session_id: u64) -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id,
            created_by: "shirusu-trace test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        os_build: 26100,
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        capture_config: "L2".into(),
        feature_flags: 3,
        target_description: "game.exe".into(),
        modules: Vec::new(),
        static_dependencies: Vec::new(),
        hook_evidence: Vec::new(),
    }
}

fn event(seq: u64, payload: PayloadRef) -> TraceEvent {
    TraceEvent {
        kind: 1,
        sequence: seq,
        timestamp_qpc: 1000 + seq * 10,
        call_id: seq,
        parent_call_id: 0,
        api_id: 77,
        schema_id: 1,
        capture: EventCapture::Captured,
        payload,
        args: None,
        global_order: None,
    }
}

fn batch(events: Vec<TraceEvent>) -> EventBatch {
    EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 3,
        qpc_frequency: 10_000_000,
        events,
    }
}

fn schema_one() -> shirusu_trace::proto::SchemaDef {
    make_schema(1, "test!Op", vec![("x".into(), Ty::U64, 0)])
}

/// Blob を参照する 1 イベントの Batch（`flush_blobs` を経由させる用）。
fn batch_with_blob(blob: BlobId) -> EventBatch {
    let args = encode_values(&[Ty::U64], &[CapturedValue::captured(TypedValue::U64(1))]).unwrap();
    let mut e = event(1, PayloadRef::Blob(blob));
    e.args = Some(args);
    batch(vec![e])
}

/// 失敗を注入できる writer。`TraceWriter` が所有するため、制御用の
/// フラグは `Rc` でテスト側と共有する。
#[derive(Default)]
struct ProbeState {
    writes: Cell<usize>,
    fail_at_write: Cell<Option<usize>>,
    fail_write: Cell<bool>,
    fail_flush: Cell<bool>,
    fail_sync: Cell<bool>,
}

struct ProbeWriter {
    inner: Vec<u8>,
    state: Rc<ProbeState>,
}

impl ProbeWriter {
    fn new() -> (Self, Rc<ProbeState>) {
        let state = Rc::new(ProbeState::default());
        (
            ProbeWriter {
                inner: Vec::new(),
                state: state.clone(),
            },
            state,
        )
    }
}

impl Write for ProbeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.state.writes.get() + 1;
        self.state.writes.set(n);
        if self.state.fail_write.get() || self.state.fail_at_write.get() == Some(n) {
            return Err(io::Error::other("injected write failure"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.state.fail_flush.get() {
            return Err(io::Error::other("injected flush failure"));
        }
        self.inner.flush()
    }
}

impl DurableWrite for ProbeWriter {
    fn sync_all(&mut self) -> io::Result<()> {
        if self.state.fail_sync.get() {
            return Err(io::Error::other("injected sync failure"));
        }
        Ok(())
    }
}

fn options(durability: Durability, chunk_raw_target: usize) -> WriterOptions {
    WriterOptions {
        durability,
        chunk_raw_target,
        ..Default::default()
    }
}

#[test]
fn getters_expose_writer_options() {
    let w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    assert_eq!(w.session_id(), 42);
    assert_eq!(w.qpc_frequency(), 10_000_000);
    assert_eq!(w.chunk_raw_target(), 512 * 1024, "default is 512 KiB (F25)");
    assert_eq!(w.durability(), Durability::Buffered);

    let w = TraceWriter::with_options(Vec::new(), env(7), options(Durability::SyncOnFinish, 4096))
        .unwrap();
    assert_eq!(w.session_id(), 7);
    assert_eq!(w.chunk_raw_target(), 4096);
    assert_eq!(w.durability(), Durability::SyncOnFinish);
}

#[test]
fn register_schema_rejects_reserved_id_and_redefinition() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    // schema_id 0 は予約済み。
    assert!(w
        .register_schema(make_schema(0, "test!Zero", vec![]))
        .is_err());
    // 同じ id の別内容は再定義として拒否。
    w.register_schema(schema_one()).unwrap();
    let other = make_schema(1, "test!Other", vec![("y".into(), Ty::U32, 0)]);
    assert!(w.register_schema(other).is_err());
    // 同じ定義の再登録は冪等（エラーにならない）。
    assert!(w.register_schema(schema_one()).is_ok());
}

#[test]
fn write_schema_checkpoint_with_empty_and_nonempty_registry() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    // 登録が無ければ何も書かず Ok。
    w.write_schema_checkpoint().unwrap();
    // 登録があれば Checkpoint Block を書く。
    w.register_schema(schema_one()).unwrap();
    w.write_schema_checkpoint().unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.registry.len(), 1);
}

#[test]
fn sync_all_variants_are_called_by_durability() {
    // `Vec<u8>` の sync_all（SyncOnFinish で finish 時に 1 回）。
    let w = TraceWriter::with_options(Vec::new(), env(42), options(Durability::SyncOnFinish, 0))
        .unwrap();
    w.finish(FinalizationInfo::default()).unwrap();

    // `Cursor<Vec<u8>>` の sync_all。
    let w = TraceWriter::with_options(
        Cursor::new(Vec::new()),
        env(42),
        options(Durability::SyncOnFinish, 0),
    )
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap();

    // `BufWriter` の sync_all（flush してから内側へ委譲）。
    let w = TraceWriter::with_options(
        io::BufWriter::new(Vec::new()),
        env(42),
        options(Durability::SyncOnFinish, 0),
    )
    .unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(bytes.get_ref()).unwrap();
    assert!(trace.finalized_cleanly);
}

#[test]
fn blob_update_offset_overflow_is_rejected() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    let base = w.add_payload(b"0123456789").unwrap();
    let err = w
        .write_blob_update(base, BlobId::of_content(b"new version"), u64::MAX, b"x")
        .expect_err("offset + size must overflow");
    assert!(matches!(err, shirusu_trace::TraceError::WriterInvariant(_)));
}

#[test]
fn blob_update_flush_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    let base = w.add_payload(b"0123456789").unwrap();
    state.fail_write.set(true);
    // 未書出しの Blob があるため `flush_blobs` が走って失敗する。
    let err = w
        .write_blob_update(base, BlobId::of_content(b"new version"), 0, b"XX")
        .expect_err("flush_blobs must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn blob_update_block_write_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    w.register_schema(schema_one()).unwrap();
    let base = w.add_payload(b"0123456789").unwrap();
    // Batch を書いて Blob Chunk を流し、pending を空にしておく。
    w.write_batch(&batch_with_blob(base)).unwrap();
    state.fail_write.set(true);
    // `flush_blobs` は no-op になり、BlobUpdate Block の書き込みで失敗する。
    let err = w
        .write_blob_update(base, BlobId::of_content(b"new version"), 0, b"XX")
        .expect_err("BlobUpdate block write must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn write_batch_schema_flush_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    w.register_schema(schema_one()).unwrap();
    state.fail_write.set(true);
    let err = w
        .write_batch(&batch(vec![event(1, PayloadRef::None)]))
        .expect_err("flush_schemas must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn write_batch_event_chunk_write_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    state.fail_write.set(true);
    // Schema・Blob の pending が無いため EventChunk の書き込みで失敗する。
    let err = w
        .write_batch(&batch(vec![event(1, PayloadRef::None)]))
        .expect_err("EventChunk block write must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn write_batch_checkpoint_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    w.register_schema(schema_one()).unwrap();
    // 小さい Block は 1 回の write で書く (P1-2)。構築時に 2 回の
    // 書き込みが済んでいるため、Schema Block は 3 回目、Checkpoint
    // Block は 4 回目で失敗。
    state.fail_at_write.set(Some(4));
    let err = w
        .write_batch(&batch(vec![event(1, PayloadRef::None)]))
        .expect_err("checkpoint write must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn flush_blobs_splits_chunks_over_target() {
    let mut w =
        TraceWriter::with_options(Vec::new(), env(42), options(Durability::Buffered, 200)).unwrap();
    // 1 件目（136 B）は溜まるだけ、2 件目で合計が目標を超えて
    // 途中で Chunk を切り出す（`flush_blobs` の分割腕）。
    w.add_payload(&[0u8; 100]).unwrap();
    w.add_payload(&[1u8; 100]).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.blobs.len(), 2);
}

#[test]
fn flush_blobs_write_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    let blob = w.add_payload(b"pending blob").unwrap();
    state.fail_write.set(true);
    let mut e = event(1, PayloadRef::Blob(blob));
    e.args =
        Some(encode_values(&[Ty::U64], &[CapturedValue::captured(TypedValue::U64(1))]).unwrap());
    let err = w
        .write_batch(&batch(vec![e]))
        .expect_err("flush_blobs must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn write_loss_records_and_profile_write_errors_propagate() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    state.fail_write.set(true);
    let err = w
        .write_loss_records(&[LossRecord {
            kind: 1,
            count: 1,
            ..Default::default()
        }])
        .expect_err("Loss block write must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
    let err = w
        .write_profile_summary(&ProfileSummary {
            qpc_frequency: 10_000_000,
            total_events_seen: 0,
            apis: Vec::new(),
        })
        .expect_err("ProfileSummary block write must fail");
    // The sink accepted none of the Loss Block, so the Writer is still at a
    // Block boundary and tries again (P3-14); only a partial Block that
    // cannot be discarded stops it (P2-10).
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn finish_schema_and_blob_flush_errors_propagate() {
    // Schema の flush で失敗。
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    w.register_schema(schema_one()).unwrap();
    state.fail_write.set(true);
    assert!(w.finish(FinalizationInfo::default()).is_err());

    // Schema が無く Blob の flush で失敗。
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::new(w, env(42)).unwrap();
    w.add_payload(b"pending blob").unwrap();
    state.fail_write.set(true);
    assert!(w.finish(FinalizationInfo::default()).is_err());
}

#[test]
fn finish_index_and_finalization_write_errors_propagate() {
    // 構築時に 2 回の書き込みが済んでいるため、Index Block は
    // write 3 回目、Finalization Block は 4 回目。
    let (w, state) = ProbeWriter::new();
    let w = TraceWriter::new(w, env(42)).unwrap();
    state.fail_at_write.set(Some(3));
    assert!(w.finish(FinalizationInfo::default()).is_err());

    let (w, state) = ProbeWriter::new();
    let w = TraceWriter::new(w, env(42)).unwrap();
    state.fail_at_write.set(Some(4));
    assert!(w.finish(FinalizationInfo::default()).is_err());
}

#[test]
fn finish_flush_and_sync_errors_propagate() {
    // `inner.flush()` の失敗。
    let (w, state) = ProbeWriter::new();
    let w = TraceWriter::new(w, env(42)).unwrap();
    state.fail_flush.set(true);
    assert!(w.finish(FinalizationInfo::default()).is_err());

    // `SyncOnFinish` での `sync_all()` の失敗。
    let (w, state) = ProbeWriter::new();
    let w = TraceWriter::with_options(w, env(42), options(Durability::SyncOnFinish, 0)).unwrap();
    state.fail_sync.set(true);
    assert!(w.finish(FinalizationInfo::default()).is_err());
}

#[test]
fn construction_write_errors_propagate() {
    // Header Block の 1 回目の書き込みで失敗。
    let (w, state) = ProbeWriter::new();
    state.fail_at_write.set(Some(1));
    assert!(TraceWriter::new(w, env(42)).is_err());

    // Environment Block（2 回目。小さい Block はヘッダーと本体を 1 回で
    // 書く）で失敗。
    let (w, state) = ProbeWriter::new();
    state.fail_at_write.set(Some(2));
    assert!(TraceWriter::new(w, env(42)).is_err());
}

#[test]
fn sync_per_block_sync_error_propagates() {
    let (w, state) = ProbeWriter::new();
    state.fail_sync.set(true);
    // Header Block の書き込み直後の `sync_all` で失敗する。
    match TraceWriter::with_options(w, env(42), options(Durability::SyncPerBlock, 0)) {
        Ok(_) => panic!("sync_all must fail"),
        Err(e) => assert!(matches!(e, shirusu_trace::TraceError::Io(_))),
    }
}

#[test]
fn buf_writer_sync_all_flush_error_propagates() {
    // `BufWriter` の `sync_all` は内側への flush から始まる。
    // `SyncPerBlock` では各 Block の書き込み後に `sync_all` が走るため、
    // flush の失敗が `sync_all` 内の `?`（writer.rs:104）へ伝播する。
    let (inner, state) = ProbeWriter::new();
    let mut w = TraceWriter::with_options(
        io::BufWriter::new(inner),
        env(42),
        options(Durability::SyncPerBlock, 0),
    )
    .unwrap();
    state.fail_write.set(true);
    let err = w
        .write_batch(&batch(vec![event(1, PayloadRef::None)]))
        .expect_err("BufWriter sync_all flush must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

#[test]
fn flush_blobs_split_write_error_propagates() {
    let (w, state) = ProbeWriter::new();
    let mut w = TraceWriter::with_options(w, env(42), options(Durability::Buffered, 200)).unwrap();
    w.add_payload(&[0u8; 100]).unwrap();
    state.fail_write.set(true);
    // 2 件目で合計が目標を超え、`flush_blobs` 内で Chunk を切り出す
    // 書き込みが失敗する（writer.rs:562）。
    let err = w
        .add_payload(&[1u8; 100])
        .expect_err("split BlobChunk write must fail");
    assert!(matches!(err, shirusu_trace::TraceError::Io(_)));
}

// ---------------------------------------------------------------------------
// ミューテーションテスト（cargo-mutants）で生き残った分岐を固定する。
// ---------------------------------------------------------------------------

fn blob_chunk_entry_counts(bytes: &[u8]) -> Vec<(u32, usize)> {
    use shirusu_trace::container::{decode_payload, parse_header, BlockType, HEADER_LEN};
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + HEADER_LEN <= bytes.len() {
        let stored = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
        let payload = &bytes[at + HEADER_LEN..at + HEADER_LEN + stored];
        let (header, ok) = parse_header(&bytes[at..], payload).unwrap();
        assert!(ok);
        if header.block_type == BlockType::BlobChunk {
            let raw = decode_payload(&header, payload).unwrap();
            let mut pos = 0;
            let mut n = 0;
            while pos < raw.len() {
                let len = u32::from_le_bytes(raw[pos + 32..pos + 36].try_into().unwrap()) as usize;
                pos += 36 + len;
                n += 1;
            }
            out.push((header.raw_len, n));
        }
        at += HEADER_LEN + stored;
    }
    out
}

/// Blob は貯めた量が目安に達した時点で書き出し、Blob Chunk は目安を
/// 超えないように詰める（1 エントリだけで目安を超える場合を除く）。
/// 目安を超えない範囲で次のエントリを入れられたなら、同じ Chunk に入る。
#[test]
fn blob_chunks_are_greedy_and_bounded_by_the_target() {
    let target = 200;
    let sizes = [10usize, 50, 70, 300, 5, 5, 100, 64, 1, 150, 30];
    let (probe, state) = ProbeWriter::new();
    let mut w =
        TraceWriter::with_options(probe, env(42), options(Durability::Buffered, target)).unwrap();
    let mut pending = 0usize;
    for (i, size) in sizes.iter().enumerate() {
        let before = state.writes.get();
        w.add_payload(&vec![i as u8; *size]).unwrap();
        pending += 36 + size;
        let flushed = state.writes.get() > before;
        assert_eq!(flushed, pending >= target, "payload {i}: pending {pending}");
        if flushed {
            pending = 0;
        }
    }
    let bytes = w.finish(FinalizationInfo::default()).unwrap().inner;
    let chunks = blob_chunk_entry_counts(&bytes);
    assert_eq!(chunks.iter().map(|c| c.1).sum::<usize>(), sizes.len());
    for (raw, entries) in &chunks {
        assert!(*raw as usize <= target || *entries == 1, "{chunks:?}");
    }
    let read = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(read.issues.is_empty(), "{:?}", read.issues);
    assert_eq!(read.blobs.len(), sizes.len());
    // 同じ内容の 2 回目は貯めない（目安の計算に入らない）。
    let (probe, state) = ProbeWriter::new();
    let mut w =
        TraceWriter::with_options(probe, env(42), options(Durability::Buffered, 100)).unwrap();
    w.add_payload(&[1; 40]).unwrap();
    let before = state.writes.get();
    w.add_payload(&[1; 40]).unwrap();
    assert_eq!(
        state.writes.get(),
        before,
        "duplicate must not count toward the target"
    );
}

#[test]
fn schema_types_accessors_return_registered_types() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    assert_eq!(w.schema_types(1), None);
    assert_eq!(w.schema_types_ref(1), None);
    w.register_schema(make_schema(
        1,
        "test!Two",
        vec![("a".into(), Ty::U32, 0), ("b".into(), Ty::Str16, 0)],
    ))
    .unwrap();
    assert_eq!(w.schema_types(1), Some(vec![Ty::U32, Ty::Str16]));
    assert_eq!(w.schema_types_ref(1), Some(&[Ty::U32, Ty::Str16][..]));
}

/// 同じ Schema の再登録は受理するが、Schema Block には 1 回だけ書く。
#[test]
fn identical_schema_registration_is_written_once() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    w.register_schema(schema_one()).unwrap();
    w.register_schema(schema_one()).unwrap();
    w.write_batch(&batch(vec![event(1, PayloadRef::None)]))
        .unwrap();
    w.register_schema(schema_one()).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let read = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(read.schemas.len(), 1, "{:?}", read.schemas);
}

/// 同じスレッドで Sequence が等しいイベントは退行ではない（重複は
/// 適合性検査で Warn にする規約で、Writer は拒否しない）。
#[test]
fn equal_sequence_is_not_a_regression() {
    let mut w = TraceWriter::new(Vec::new(), env(42)).unwrap();
    w.write_batch(&batch(vec![event(5, PayloadRef::None)]))
        .unwrap();
    w.write_batch(&batch(vec![
        event(5, PayloadRef::None),
        event(5, PayloadRef::None),
    ]))
    .unwrap();
    assert!(w
        .write_batch(&batch(vec![event(4, PayloadRef::None)]))
        .is_err());
}

/// 1 イベントだけで目安を超える Batch も、1 イベントずつの Chunk に
/// 分けて書き終える（空の Chunk を作らず、止まらない）。Block の
/// sequence はファイル内で 0 から 1 ずつ増える。
#[test]
fn tiny_chunk_target_still_makes_progress_and_numbers_blocks() {
    let mut w =
        TraceWriter::with_options(Vec::new(), env(42), options(Durability::Buffered, 1)).unwrap();
    w.register_schema(schema_one()).unwrap();
    let events: Vec<_> = (1..=5)
        .map(|s| event(s, PayloadRef::Inline(vec![s as u8; 8])))
        .collect();
    w.write_batch(&batch(events)).unwrap();
    let bytes = w.finish(FinalizationInfo::default()).unwrap();
    let read = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(read.issues.is_empty(), "{:?}", read.issues);
    assert_eq!(read.batches.len(), 5);
    assert!(read.batches.iter().all(|b| b.events.len() == 1));
    let seqs: Vec<u64> = read.blocks.iter().map(|b| b.sequence).collect();
    assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<_>>());
}

/// Accepts `budget` more bytes, then fails. Cannot truncate.
struct PartialSink {
    data: Vec<u8>,
    budget: std::rc::Rc<std::cell::Cell<usize>>,
}

impl io::Write for PartialSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = self.budget.get();
        if room == 0 {
            return Err(io::Error::other("injected failure"));
        }
        let n = room.min(buf.len());
        self.budget.set(room - n);
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl shirusu_trace::writer::DurableWrite for PartialSink {
    fn sync_all(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn only_a_partial_block_that_cannot_be_discarded_stops_the_writer() {
    let budget = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
    let sink = PartialSink {
        data: Vec::new(),
        budget: budget.clone(),
    };
    let mut w = TraceWriter::new(sink, env(42)).unwrap();
    let loss = [LossRecord {
        kind: 1,
        count: 1,
        ..Default::default()
    }];
    // Nothing accepted: still at a Block boundary, a retry works.
    budget.set(0);
    assert!(matches!(
        w.write_loss_records(&loss),
        Err(shirusu_trace::TraceError::Io(_))
    ));
    budget.set(usize::MAX);
    w.write_loss_records(&loss).unwrap();
    // Part of a Block accepted and not removable: the Writer stops.
    budget.set(10);
    assert!(w.write_loss_records(&loss).is_err());
    budget.set(usize::MAX);
    assert!(matches!(
        w.write_loss_records(&loss),
        Err(shirusu_trace::TraceError::WriterInvariant(_))
    ));
}
