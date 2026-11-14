//! カバレッジ gap のテスト（2026-11-12 の llvm-cov 計測で見つけた
//! `emitter.rs` の未実行行を閉じるもの）。
//!
//! 対象は主に次の 3 種：
//! - `EmitError` の Display / From（エラー型の表示経路は通常の
//!   正常系テストでは通らない）。
//! - getter・`write_loss_records`・`flush_thread` の早期 return・
//!   Inline Payload・フィールド無し API（`encode_args` の None 分岐）。
//! - 書き込み失敗時の `?` 伝播（`FailingWriter` で注入する）。
//!   `add_payload` は 512 KiB までバッファするため、Blob 経路の
//!   失敗注入には `chunk_raw_target` を小さくした `with_options` を使う。
//!
//! 到達不能と判断した行はテストで閉じない（`finish` の `if let Some`
//! の None 腕＝`thread_ids` は `threads` のキー由来で常に Some、
//! `register_schema` の `?` エラー腕＝`ApiSet` からは重複 Schema ID
//! を作れない）。これらは README の所感に記録する。

use shirusu_emit::{
    file_io_api_set, ApiSet, ApiSpec, CallToken, EmitError, Emitter, EventMeta, PayloadData,
    SessionConfig,
};
use shirusu_trace::error::{CompactError, TraceError};
use shirusu_trace::proto::LossRecord;
use shirusu_trace::reader::PayloadResolution;
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::writer::{DurableWrite, FinalizationInfo, WriterOptions};
use std::io::{self, Write};

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn close_handle_args(handle: u64) -> Vec<CapturedValue> {
    vec![cv(TypedValue::U64(handle))]
}

fn close_handle_leave() -> Vec<CapturedValue> {
    vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))]
}

fn new_emitter() -> Emitter<Vec<u8>> {
    Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
    )
    .unwrap()
}

#[test]
fn display_covers_all_variants() {
    assert_eq!(
        EmitError::UnknownApi("kernel32!Nope".into()).to_string(),
        "api not in the emitter's ApiSet: kernel32!Nope"
    );
    assert_eq!(
        EmitError::DuplicateApi("kernel32!CloseHandle".into()).to_string(),
        "api already registered: kernel32!CloseHandle"
    );
    assert_eq!(
        EmitError::InvalidSpec("api name is empty".into()).to_string(),
        "invalid api spec: api name is empty"
    );
    assert_eq!(
        EmitError::UnknownCall {
            thread_id: 7,
            call_id: 9
        }
        .to_string(),
        "call 9 on thread 7 is not open (unknown or already ended)"
    );
    assert_eq!(
        EmitError::OpenCallsAtFinish {
            thread_id: 3,
            call_ids: vec![1, 2]
        }
        .to_string(),
        "thread 3 still has 2 open call(s) at finish: [1, 2]"
    );
    assert_eq!(
        EmitError::Trace(TraceError::NotATrace).to_string(),
        "trace error: input does not start with a trace header block"
    );
    assert_eq!(
        EmitError::Compact(CompactError::Truncated).to_string(),
        "argument encoding error: compact input truncated"
    );
}

#[test]
fn from_conversions_wrap_underlying_errors() {
    let e: EmitError = TraceError::NotATrace.into();
    assert!(matches!(e, EmitError::Trace(TraceError::NotATrace)));
    let e: EmitError = CompactError::FieldCountMismatch {
        expected: 1,
        actual: 0,
    }
    .into();
    assert!(matches!(
        e,
        EmitError::Compact(CompactError::FieldCountMismatch { .. })
    ));
    // `std::error::Error` として source を辿れること（Display だけの
    // 検査では落ちない経路）。
    use std::error::Error as _;
    assert!(EmitError::Trace(TraceError::NotATrace).source().is_none());
}

#[test]
fn getters_expose_api_set_and_session_config() {
    let em = new_emitter();
    assert_eq!(em.api_set().len(), 6, "file_io set has 6 apis");
    assert_eq!(em.session_config().session_id, 1);
    assert_eq!(em.session_config().created_by, "emit-test");
}

#[test]
fn end_call_with_unknown_api_id_is_unknown_api() {
    let mut em = new_emitter();
    let bogus = CallToken {
        thread_id: 1,
        call_id: 1,
        api_id: 9999,
    };
    assert!(matches!(
        em.end_call(bogus, &close_handle_leave(), 0, EventMeta::default()),
        Err(EmitError::UnknownApi(_))
    ));
}

#[test]
fn end_call_with_wrong_leave_values_is_compact_error() {
    let mut em = new_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    // leave は 2 フィールド（return, last_error）なのに 0 個渡す。
    assert!(matches!(
        em.end_call(tok, &[], 1, EventMeta::default()),
        Err(EmitError::Compact(_))
    ));
}

#[test]
fn abandon_call_unknown_thread_and_unknown_call() {
    let mut em = new_emitter();
    // スレッド自体が存在しない。
    let bogus_thread = CallToken {
        thread_id: 99,
        call_id: 1,
        api_id: 4,
    };
    assert!(matches!(
        em.abandon_call(bogus_thread),
        Err(EmitError::UnknownCall { .. })
    ));
    // スレッドは存在するが call_id がオープン中でない。
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    let bogus_call = CallToken {
        thread_id: 1,
        call_id: tok.call_id + 100,
        api_id: 4,
    };
    assert!(matches!(
        em.abandon_call(bogus_call),
        Err(EmitError::UnknownCall { .. })
    ));
    // 正常系の abandon は通る（比較用）。
    em.abandon_call(tok).unwrap();
    assert_eq!(em.open_call_count(1), 0);
}

#[test]
fn write_loss_records_roundtrip() {
    let mut em = new_emitter();
    em.write_loss_records(&[LossRecord {
        kind: 1,
        count: 3,
        reason: "test loss".into(),
        process_id: 1,
        thread_id: 5,
        ..Default::default()
    }])
    .unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.loss_records.len(), 1);
    let rec = &trace.loss_records[0];
    assert_eq!(rec.kind, 1);
    assert_eq!(rec.count, 3);
    assert_eq!(rec.reason, "test loss");
    assert_eq!(rec.thread_id, 5);
}

#[test]
fn flush_thread_on_unknown_and_empty_thread_is_ok() {
    let mut em = new_emitter();
    // 存在しないスレッドは素通しで Ok。
    em.flush_thread(999).unwrap();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(tok, &close_handle_leave(), 1, EventMeta::default())
        .unwrap();
    // 1 回目は書き出し、2 回目は pending が空で Ok。
    em.flush_thread(1).unwrap();
    em.flush_thread(1).unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.total_events(), 2);
}

#[test]
fn inline_payload_roundtrips() {
    let mut em = new_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        tok,
        &close_handle_leave(),
        1,
        EventMeta::with_payload(PayloadData::Inline(b"small".to_vec())),
    )
    .unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let leave = &trace.batches[0].events[1];
    match trace.resolve_payload(leave) {
        PayloadResolution::Inline(data) => assert_eq!(data, b"small"),
        other => panic!("unexpected payload resolution: {other:?}"),
    }
}

#[test]
fn empty_field_api_encodes_no_args() {
    let mut set = ApiSet::new();
    set.add(ApiSpec::new("test!NoArgs", &[], &[])).unwrap();
    let mut em = Emitter::new(Vec::new(), set, SessionConfig::new(5, "emit-test")).unwrap();
    let tok = em
        .begin_call(1, "test!NoArgs", &[], 0, EventMeta::default())
        .unwrap();
    em.end_call(tok, &[], 1, EventMeta::default()).unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.total_events(), 2);
    for ev in &trace.batches[0].events {
        assert_eq!(ev.args, None, "field-less schema carries no args");
    }
}

/// 書き込みを注入したタイミングで失敗させる writer。
/// `Emitter::new` 成功後に共有フラグを立てると、その後の書き込みが
/// すべて失敗する（Header / Schema は構築時に書かれるため）。
struct FailingWriter {
    inner: Vec<u8>,
    fail: std::rc::Rc<std::cell::Cell<bool>>,
}

impl FailingWriter {
    fn new() -> (Self, std::rc::Rc<std::cell::Cell<bool>>) {
        let fail = std::rc::Rc::new(std::cell::Cell::new(false));
        (
            FailingWriter {
                inner: Vec::new(),
                fail: fail.clone(),
            },
            fail,
        )
    }
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail.get() {
            return Err(io::Error::other("injected write failure"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail.get() {
            return Err(io::Error::other("injected write failure"));
        }
        self.inner.flush()
    }
}

impl DurableWrite for FailingWriter {
    fn sync_all(&mut self) -> io::Result<()> {
        if self.fail.get() {
            return Err(io::Error::other("injected write failure"));
        }
        Ok(())
    }
}

fn failing_emitter() -> (Emitter<FailingWriter>, std::rc::Rc<std::cell::Cell<bool>>) {
    let (w, fail) = FailingWriter::new();
    let em = Emitter::new(w, file_io_api_set(), SessionConfig::new(1, "emit-test")).unwrap();
    (em, fail)
}

/// `chunk_raw_target` を小さくした emitter。Blob が 2 KiB を超えると
/// `add_payload` 内で `flush_blobs` が走り、書き込み失敗が
/// `resolve_payload` の `?` へ伝播する。
fn small_chunk_emitter() -> (Emitter<FailingWriter>, std::rc::Rc<std::cell::Cell<bool>>) {
    let (w, fail) = FailingWriter::new();
    let em = Emitter::with_options(
        w,
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
        WriterOptions {
            chunk_raw_target: 1024,
            ..Default::default()
        },
    )
    .unwrap();
    (em, fail)
}

#[test]
fn write_loss_records_with_failing_writer_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    fail.set(true);
    assert!(matches!(
        em.write_loss_records(&[LossRecord {
            kind: 1,
            count: 1,
            ..Default::default()
        }]),
        Err(EmitError::Trace(_))
    ));
}

#[test]
fn api_set_accessors_cover_empty_spec_and_lookup_by_name() {
    let empty = ApiSet::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.spec(0), None, "api_id 0 is never valid");
    assert_eq!(empty.spec(1), None, "empty set has no specs");
    assert_eq!(empty.spec_by_name("kernel32!CloseHandle"), None);

    let set = file_io_api_set();
    assert!(!set.is_empty());
    assert_eq!(set.len(), 6);
    let spec = set.spec_by_name("kernel32!CloseHandle").expect("in set");
    assert_eq!(spec.name, "kernel32!CloseHandle");
    assert_eq!(
        set.spec(set.api_id("kernel32!CloseHandle").unwrap()),
        Some(spec)
    );
    assert_eq!(set.spec(999), None, "out-of-range api_id");
    assert_eq!(set.spec_by_name("kernel32!Nope"), None);
}

#[test]
fn writer_failure_at_construction_is_trace_error() {
    let (w, fail) = FailingWriter::new();
    fail.set(true);
    let err = match Emitter::new(w, file_io_api_set(), SessionConfig::new(1, "emit-test")) {
        Ok(_) => panic!("header write must fail"),
        Err(e) => e,
    };
    assert!(matches!(err, EmitError::Trace(TraceError::Io(_))));
    assert!(
        err.to_string()
            .contains("trace error: io error: injected write failure"),
        "unexpected display: {err}"
    );
}

#[test]
fn blob_payload_with_failing_writer_is_trace_error() {
    let (mut em, fail) = small_chunk_emitter();
    fail.set(true);
    let result = em.begin_call(
        1,
        "kernel32!CloseHandle",
        &close_handle_args(0x10),
        0,
        EventMeta::with_payload(PayloadData::Blob(vec![0u8; 2048])),
    );
    assert!(matches!(result, Err(EmitError::Trace(_))));
}

#[test]
fn end_call_blob_payload_with_failing_writer_is_trace_error() {
    let (mut em, fail) = small_chunk_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    fail.set(true);
    let result = em.end_call(
        tok,
        &close_handle_leave(),
        1,
        EventMeta::with_payload(PayloadData::Blob(vec![0u8; 2048])),
    );
    assert!(matches!(result, Err(EmitError::Trace(_))));
}

#[test]
fn flush_with_failing_writer_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(tok, &close_handle_leave(), 1, EventMeta::default())
        .unwrap();
    fail.set(true);
    assert!(matches!(em.flush_thread(1), Err(EmitError::Trace(_))));
}

#[test]
fn auto_flush_on_begin_with_failing_writer_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    fail.set(true);
    // 256 件目で自動 flush が走り、書き込み失敗が返る。
    let mut last = Ok(CallToken {
        thread_id: 1,
        call_id: 0,
        api_id: 4,
    });
    for i in 0..256 {
        last = em.begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x100 + i),
            i,
            EventMeta::default(),
        );
    }
    assert!(matches!(last, Err(EmitError::Trace(_))));
}

#[test]
fn auto_flush_on_end_with_failing_writer_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    let mut toks = Vec::new();
    for i in 0..255 {
        toks.push(
            em.begin_call(
                1,
                "kernel32!CloseHandle",
                &close_handle_args(0x100 + i),
                i,
                EventMeta::default(),
            )
            .unwrap(),
        );
    }
    fail.set(true);
    // 255 件の enter + 1 件の leave で 256 件になり自動 flush が走る。
    let tok = toks.pop().unwrap();
    assert!(matches!(
        em.end_call(tok, &close_handle_leave(), 999, EventMeta::default()),
        Err(EmitError::Trace(_))
    ));
}

#[test]
fn finish_flush_with_failing_writer_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(tok, &close_handle_leave(), 1, EventMeta::default())
        .unwrap();
    fail.set(true);
    // pending の flush で失敗する（`finish` 内の `flush_thread`）。
    assert!(matches!(
        em.finish(FinalizationInfo::default()),
        Err(EmitError::Trace(_))
    ));
}

#[test]
fn finish_writer_error_is_trace_error() {
    let (mut em, fail) = failing_emitter();
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(0x10),
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(tok, &close_handle_leave(), 1, EventMeta::default())
        .unwrap();
    // 先に flush を済ませておく（成功）。この後の `finish` は
    // Index / Finalization の書き込みで失敗する。
    em.flush_thread(1).unwrap();
    fail.set(true);
    assert!(matches!(
        em.finish(FinalizationInfo::default()),
        Err(EmitError::Trace(_))
    ));
}

#[test]
fn calls_on_one_thread_get_distinct_ids_and_nest_by_parent() {
    let mut em = new_emitter();
    let outer = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(1),
            0,
            EventMeta::default(),
        )
        .unwrap();
    let inner = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(2),
            1,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(inner, &close_handle_leave(), 2, EventMeta::default())
        .unwrap();
    em.end_call(outer, &close_handle_leave(), 3, EventMeta::default())
        .unwrap();
    let third = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &close_handle_args(3),
            4,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(third, &close_handle_leave(), 5, EventMeta::default())
        .unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    let enters: Vec<_> = trace
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| e.kind == 1)
        .collect();
    assert_eq!(enters.len(), 3);
    let ids: std::collections::HashSet<_> = enters.iter().map(|e| e.call_id).collect();
    assert_eq!(ids.len(), 3, "call ids repeat: {enters:?}");
    assert_eq!(enters[0].parent_call_id, 0);
    assert_eq!(enters[1].parent_call_id, enters[0].call_id);
    assert_eq!(enters[2].parent_call_id, 0);
}
