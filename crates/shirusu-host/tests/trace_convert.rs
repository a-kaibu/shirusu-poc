//! Host 変換（A72）のテスト：検証済みイベント → 公開 Trace。
//!
//! 確かめること：
//! - 格納済み Payload は Blob 化され、Trace には Blob ID だけが残る。
//! - 欠落 Payload は Blob 化されず、Dropped { 元長, 理由 } だけが残る。
//! - TemporaryPayloadKey（payload_position を含む Host 内部情報）は
//!   公開 Trace のバイト列のどこにも現れない。
//! - Loss / IntegrityReport の写像が全種類そろっている。
//! - 実 Agent → 検証付き Host → TraceRecorder の通し経路で閉じる。

use shirusu_host::trace_convert::{
    convert_capture, convert_loss_record, integrity_level_code, TraceBatchContext, TraceRecorder,
};
use shirusu_host::{IntegrityLevel, IntegrityReport, LossEvent};
use shirusu_trace::blob::BlobId;
use shirusu_trace::model::PayloadRef;
use shirusu_trace::proto::{loss_kind, CaptureEnvironment, SessionMetadata};
use shirusu_trace::reader::PayloadResolution;
use shirusu_trace::schema::EventCapture;
use shirusu_transport::descriptor::{CaptureState, EventDescriptor, EventKind};
use shirusu_transport::ring::ReceivedEvent;

const SESSION: u64 = 42;

fn environment() -> CaptureEnvironment {
    CaptureEnvironment {
        session: SessionMetadata {
            session_id: SESSION,
            created_by: "shirusu-host test".into(),
            qpc_frequency: 10_000_000,
        },
        ..Default::default()
    }
}

fn ctx(thread_id: u64) -> TraceBatchContext {
    TraceBatchContext {
        session_id: SESSION,
        process_id: 7,
        raw_pid: 4242,
        thread_id,
        qpc_frequency: 10_000_000,
    }
}

fn received(
    sequence: u64,
    state: CaptureState,
    payload_len: u32,
    payload: Vec<u8>,
) -> ReceivedEvent {
    let mut d = EventDescriptor::new(EventKind::CallEnter, sequence);
    d.flags = state.to_flags();
    d.payload_len = payload_len;
    d.timestamp_qpc = 5000 + sequence;
    d.call_id = sequence + 100;
    d.parent_call_id = 3;
    d.api_id = 77;
    ReceivedEvent {
        descriptor: d,
        payload,
    }
}

#[test]
fn stored_payload_becomes_blob_reference_only() {
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    let ev = received(1, CaptureState::Captured, 11, b"hello trace".to_vec());
    rec.record_batch(&ctx(3), &[ev]).unwrap();
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    let e = &trace.batches[0].events[0];
    let expected_id = BlobId::of_content(b"hello trace");
    assert_eq!(e.payload, PayloadRef::Blob(expected_id));
    assert_eq!(
        trace.resolve_payload(e),
        PayloadResolution::Blob(b"hello trace")
    );
    // Descriptor の素のフィールドが写っている
    assert_eq!(e.kind, EventKind::CallEnter as u16);
    assert_eq!(e.timestamp_qpc, 5001);
    assert_eq!(e.call_id, 101);
    assert_eq!(e.parent_call_id, 3);
    assert_eq!(e.api_id, 77);
    assert_eq!(trace.batches[0].raw_pid, 4242);
    // Finalization の集計
    let fin = trace.finalization.as_ref().unwrap();
    assert_eq!(fin.total_events, 1);
    assert_eq!(fin.total_blobs, 1);
}

#[test]
fn empty_stored_payload_is_none_not_blob() {
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    let ev = received(1, CaptureState::Captured, 0, Vec::new());
    rec.record_batch(&ctx(3), &[ev]).unwrap();
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.batches[0].events[0].payload, PayloadRef::None);
    assert!(trace.blobs.is_empty());
}

#[test]
fn dropped_payload_keeps_only_reason() {
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    let bp = received(1, CaptureState::DroppedByBackpressure, 5000, Vec::new());
    // 上限超過で Payload を落とした場合は PAYLOAD_DROPPED と
    // CAPTURE_LIMIT_EXCEEDED が併立する（転送契約：落とした印は
    // PAYLOAD_DROPPED が正で、payload_len は元の長さになる）。
    let mut tl = received(2, CaptureState::CaptureLimitExceeded, 999, Vec::new());
    tl.descriptor.flags |= shirusu_transport::descriptor::flags::PAYLOAD_DROPPED;
    rec.record_batch(&ctx(3), &[bp, tl]).unwrap();
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(
        trace.blobs.is_empty(),
        "dropped payloads must not be stored"
    );
    let e0 = &trace.batches[0].events[0];
    assert_eq!(
        e0.payload,
        PayloadRef::Dropped {
            original_len: 5000,
            reason: shirusu_trace::model::PayloadLossReason::Backpressure
        }
    );
    assert_eq!(e0.capture, EventCapture::DroppedByBackpressure);
    let e1 = &trace.batches[0].events[1];
    assert_eq!(
        e1.payload,
        PayloadRef::Dropped {
            original_len: 999,
            reason: shirusu_trace::model::PayloadLossReason::TooLarge
        }
    );
    assert_eq!(e1.capture, EventCapture::CaptureLimitExceeded);
}

#[test]
fn capture_state_mapping_is_total() {
    for (state, expected) in [
        (CaptureState::Captured, EventCapture::Captured),
        (
            CaptureState::MemoryUnreadable,
            EventCapture::MemoryUnreadable,
        ),
        (
            CaptureState::CaptureLimitExceeded,
            EventCapture::CaptureLimitExceeded,
        ),
        (
            CaptureState::DroppedByBackpressure,
            EventCapture::DroppedByBackpressure,
        ),
        (CaptureState::Truncated, EventCapture::Truncated),
        (CaptureState::Unsupported, EventCapture::Unsupported),
    ] {
        assert_eq!(convert_capture(state), expected);
    }
}

#[test]
fn temporary_key_material_never_reaches_trace_bytes() {
    // payload_position は一時キーの材料（Host 内部）。特徴的な値を入れ、
    // 公開 Trace のバイト列にその LE 表現が現れないことを確かめる。
    const POSITION: u64 = 0xA5A5_5A5A_C3C3_3C3C;
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    let mut stored = received(1, CaptureState::Captured, 4, b"data".to_vec());
    stored.descriptor.payload_position = POSITION;
    let mut dropped = received(2, CaptureState::DroppedByBackpressure, 64, Vec::new());
    dropped.descriptor.payload_position = POSITION;
    rec.record_batch(&ctx(3), &[stored, dropped]).unwrap();
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let needle = POSITION.to_le_bytes();
    assert!(
        !bytes.windows(8).any(|w| w == needle),
        "payload_position (temporary key material) leaked into public trace"
    );
    // 対照：Blob ID は載っている（＝検査が無意味でないことの確認）
    let id = BlobId::of_content(b"data");
    assert!(bytes.windows(32).any(|w| w == id.as_bytes()));
}

#[test]
fn loss_mapping_all_kinds() {
    let cases = [
        (
            LossEvent::SequenceGap { count: 5 },
            loss_kind::SEQUENCE_GAP,
            5,
        ),
        (
            LossEvent::Counters {
                dropped_events: 9,
                dropped_payload_bytes: 4096,
                degraded_events: 3,
            },
            loss_kind::COUNTERS,
            9,
        ),
        (
            LossEvent::UnknownTermination { call_id: 123 },
            loss_kind::UNKNOWN_TERMINATION,
            0,
        ),
        (
            LossEvent::IntegrityLost {
                reason: "cursor regressed".into(),
            },
            loss_kind::INTEGRITY_LOST,
            0,
        ),
    ];
    for (event, kind, count) in &cases {
        let r = convert_loss_record(event, 7, 3);
        assert_eq!(r.kind, *kind);
        assert_eq!(r.count, *count);
        assert_eq!(r.process_id, 7);
        assert_eq!(r.thread_id, 3);
    }
    let r = convert_loss_record(
        &LossEvent::Counters {
            dropped_events: 9,
            dropped_payload_bytes: 4096,
            degraded_events: 3,
        },
        7,
        3,
    );
    assert_eq!(r.dropped_payload_bytes, 4096);
    assert_eq!(r.degraded_events, 3);
    let r = convert_loss_record(&LossEvent::UnknownTermination { call_id: 123 }, 7, 3);
    assert_eq!(r.call_id, 123);
    let r = convert_loss_record(
        &LossEvent::IntegrityLost {
            reason: "cursor regressed".into(),
        },
        7,
        3,
    );
    assert_eq!(r.reason, "cursor regressed");
}

#[test]
fn integrity_levels_map_to_proto_codes() {
    assert_eq!(integrity_level_code(IntegrityLevel::Complete), 0);
    assert_eq!(integrity_level_code(IntegrityLevel::Degraded), 1);
    assert_eq!(integrity_level_code(IntegrityLevel::Lost), 2);
    assert_eq!(integrity_level_code(IntegrityLevel::Unknown), 3);
}

#[test]
fn recorder_writes_losses_and_finalization() {
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    rec.record_batch(
        &ctx(3),
        &[received(1, CaptureState::Captured, 0, Vec::new())],
    )
    .unwrap();
    rec.record_losses(
        &[
            LossEvent::SequenceGap { count: 2 },
            LossEvent::UnknownTermination { call_id: 55 },
        ],
        7,
        3,
    )
    .unwrap();
    let report = IntegrityReport {
        capture_coverage: IntegrityLevel::Degraded,
        event_integrity: IntegrityLevel::Lost,
        semantic_completeness: IntegrityLevel::Unknown,
        finalized: true,
        notes: vec!["note".into()],
    };
    let bytes = rec.finish(&report).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert_eq!(trace.loss_records.len(), 2);
    assert_eq!(trace.loss_records[0].kind, loss_kind::SEQUENCE_GAP);
    assert_eq!(trace.loss_records[1].call_id, 55);
    let fin = trace.finalization.as_ref().unwrap();
    assert_eq!(fin.capture_coverage, 1);
    assert_eq!(fin.event_integrity, 2);
    assert_eq!(fin.semantic_completeness, 3);
    assert_eq!(fin.total_loss_records, 2);
    assert_eq!(fin.notes, vec!["note".to_string()]);
}

#[test]
fn agent_to_host_to_trace_end_to_end() {
    use shirusu_agent::{Agent, RecordResult};
    use shirusu_host::{DrainWorker, ProcessInstanceId, RingId, RingIdentity};
    use shirusu_transport::context::HostMonitor;
    use shirusu_transport::ring::WriterPolicy;
    use shirusu_transport::slot::SlotPool;
    use shirusu_transport::RingConfig;
    use std::sync::Arc;
    use std::time::Duration;

    let cfg = RingConfig::new(1024, 65536);
    let agent = Agent::new(
        Arc::new(SlotPool::new(2)),
        cfg,
        Arc::new(HostMonitor::always_alive()),
    )
    .with_policy(WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    });
    let mut rec = TraceRecorder::from_environment(Vec::new(), environment()).unwrap();
    let pairs = 50u64;
    for tid in 1..=2u64 {
        let handle = agent.thread_begin(tid).expect("slot");
        let base = unsafe { agent.thread_region_base(tid) }.expect("base");
        let mut worker = unsafe { DrainWorker::new(base, cfg, handle.generation) };
        worker.set_identity(RingIdentity::new(
            ProcessInstanceId(1),
            RingId(tid),
            handle.generation,
        ));
        for i in 0..pairs {
            assert!(matches!(
                agent.record_enter(tid, 10, 20, i, 0, b"payload"),
                RecordResult::Written(_)
            ));
            assert!(matches!(
                agent.record_leave(tid, 10, 20, i, 0, b"payload"),
                RecordResult::Written(_)
            ));
        }
        let drained = worker.drain_all();
        assert_eq!(drained.events.len() as u64, pairs * 2);
        // Host 内部では一時キーが生成されている（A72 の内部管理）。
        assert_eq!(worker.payload_keys.len() as u64, pairs * 2);
        rec.record_batch(&ctx(tid), &drained.events).unwrap();
        rec.record_losses(&worker.loss_events, 7, tid).unwrap();
    }
    let bytes = rec.finish(&IntegrityReport::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.total_events(), 2 * pairs * 2);
    // 全イベントの Payload は同一内容 → Blob は 1 つに重複排除される。
    assert_eq!(trace.blobs.len(), 1);
    let id = BlobId::of_content(b"payload");
    for b in &trace.batches {
        for e in &b.events {
            assert_eq!(e.payload, PayloadRef::Blob(id));
        }
    }
    let fin = trace.finalization.as_ref().unwrap();
    assert_eq!(fin.total_blobs, 1);
}
