//! バイト列レベルの統合テスト：TraceWriter で実際に書いた Trace が
//! 適合し、途中で切断した Trace が finalization 検査で落ちること。

use shirusu_conformance::{check_trace, CheckStatus};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, EventCapture, Ty};
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};

fn env() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: 3,
            created_by: "bytes-test writer".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    }
}

fn build_trace(unregistered_schema_event: bool) -> Vec<u8> {
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    w.register_schema(make_schema(1, "x!Y/enter", vec![("h".into(), Ty::U64, 0)]))
        .unwrap();
    w.register_schema(make_schema(
        2,
        "x!Y/leave",
        vec![
            ("return".into(), Ty::U64, 0),
            ("last_error".into(), Ty::U32, 0),
        ],
    ))
    .unwrap();
    let ev = |kind, sequence, call_id, schema_id| TraceEvent {
        kind,
        sequence,
        timestamp_qpc: sequence * 10,
        call_id,
        parent_call_id: 0,
        api_id: 1,
        schema_id,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: None,
        global_order: None,
    };
    let mut events = vec![ev(1, 1, 1, 1), ev(2, 2, 1, 2)];
    if unregistered_schema_event {
        events.push(ev(1, 3, 2, 77));
        events.push(ev(2, 4, 2, 77));
    }
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events,
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn writer_built_trace_conforms() {
    let bytes = build_trace(false);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let report = check_trace(&trace);
    assert!(report.conformant(), "{}", report.render_human("t"));
}

#[test]
fn writer_built_trace_with_unregistered_schema_fails_schema_check() {
    let bytes = build_trace(true);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let report = check_trace(&trace);
    assert!(!report.conformant());
    let f = report.finding("schemas-registered").unwrap();
    assert_eq!(f.status, CheckStatus::Fail);
    assert!(f.detail.contains("77"), "detail: {}", f.detail);
}

#[test]
fn truncated_trace_fails_finalization() {
    let bytes = build_trace(false);
    // Index + Finalization は末尾にある。末尾を切り落とすと
    // Finalization が消え、Reader は「途中で終わった Trace」として読む。
    let cut = &bytes[..bytes.len() - 40];
    let trace = shirusu_trace::read_trace(cut).unwrap();
    assert!(trace.finalization.is_none());
    let report = check_trace(&trace);
    assert_eq!(
        report.finding("finalization").unwrap().status,
        CheckStatus::Fail
    );
}

// ---- F18: Blob の部分的な更新 ----

/// finish せずに中身を取り出すための共有バッファ Writer。
#[derive(Clone, Default)]
struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl shirusu_trace::writer::DurableWrite for SharedBuf {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl SharedBuf {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// 基底 Blob＋更新 1 件＋更新版を参照するイベントの Trace。
/// 正常に finish したもの（適合するはず）。
fn build_trace_with_blob_update() -> Vec<u8> {
    use shirusu_trace::blob::BlobId;
    let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
    let base_id = w.add_payload(b"0123456789abcdef").unwrap();
    let folded = b"01234XXXXXabcdef".to_vec();
    let new_version = BlobId::of_content(&folded);
    w.write_blob_update(base_id, new_version, 5, b"XXXXX")
        .unwrap();
    let ev = |kind, sequence| TraceEvent {
        kind,
        sequence,
        timestamp_qpc: sequence * 10,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 0,
        capture: EventCapture::Captured,
        payload: PayloadRef::Blob(new_version),
        args: None,
        global_order: None,
    };
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![ev(1, 1), ev(2, 2)],
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn writer_built_trace_with_blob_update_conforms() {
    // F18: 正常な更新を含む Trace は適合する。特に finalization-counts
    // は、派生版を Reader が blobs へ具体化するため一致する。
    let bytes = build_trace_with_blob_update();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    let report = check_trace(&trace);
    assert!(report.conformant(), "{}", report.render_human("t"));
}

#[test]
fn failed_blob_update_fails_clean_scan() {
    // F18: 畳み込み結果のハッシュが宣言と食い違う更新は、clean-scan
    // で damaging として落ちる（内容を復元できないため）。
    use shirusu_trace::blob::{BlobId, BlobUpdate};
    use shirusu_trace::container::{serialize_header, BlockHeader, BlockType, Compression};
    use shirusu_trace::reader::RecoveryIssue;
    let buf = SharedBuf::default();
    let mut w = TraceWriter::new(buf.clone(), env()).unwrap();
    let base_id = w.add_payload(b"0123456789abcdef").unwrap();
    w.write_batch(&EventBatch {
        session_id: 3,
        process_id: 1,
        raw_pid: 10,
        thread_id: 1,
        qpc_frequency: 10_000_000,
        events: vec![TraceEvent {
            kind: 1,
            sequence: 1,
            timestamp_qpc: 10,
            call_id: 1,
            parent_call_id: 0,
            api_id: 1,
            schema_id: 0,
            capture: EventCapture::Captured,
            payload: PayloadRef::Blob(base_id),
            args: None,
            global_order: None,
        }],
    })
    .unwrap();
    let mut bytes = buf.bytes();
    // 手組みの誤った更新（新版 ID が畳み込み結果と一致しない）
    let update = BlobUpdate {
        resource_id: base_id,
        new_version_id: BlobId::of_content(b"not the folded content"),
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    let payload = update.encode();
    let header = BlockHeader {
        block_type: BlockType::BlobUpdate,
        compression: Compression::None,
        sequence: 999,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    bytes.extend_from_slice(&serialize_header(&header, &payload));
    bytes.extend_from_slice(&payload);
    drop(w);
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(
        trace
            .issues
            .iter()
            .any(|i| matches!(i, RecoveryIssue::BlobUpdateHashMismatch { .. })),
        "issues: {:?}",
        trace.issues
    );
    let report = check_trace(&trace);
    let f = report.finding("clean-scan").unwrap();
    assert_eq!(f.status, CheckStatus::Fail);
    assert!(f.detail.contains("blob update"), "detail: {}", f.detail);
}
