//! エミッタの通しテスト：キットで書いた Trace を Reader で読み戻し、
//! 規約（Schema 登録、sequence 単調性、Enter/Leave 対応、Payload
//! 解決、Finalization の整合）が実際に成立していることを確かめる。

use shirusu_emit::{file_io_api_set, CallToken, Emitter, EventMeta, PayloadData, SessionConfig};
use shirusu_trace::schema::{CapturedValue, TypedValue};
use shirusu_trace::writer::FinalizationInfo;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

/// 1 スレッド分の「ファイルを開いて読み書きして閉じる」流れを
/// 記録した Trace バイト列を作る。handle は呼び出し側が渡す。
fn record_session(handle: u64, read_data: &[u8]) -> Vec<u8> {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(42, "emit-test 0.1"),
    )
    .unwrap();
    let create = em
        .begin_call(
            7,
            "kernel32!CreateFileW",
            &[
                cv(str16("save.dat")),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::U32(3)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
            ],
            1_000,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        create,
        &[cv(TypedValue::U64(handle)), cv(TypedValue::U32(0))],
        2_000,
        EventMeta::default(),
    )
    .unwrap();
    let write = em
        .begin_call(
            7,
            "kernel32!WriteFile",
            &[
                cv(TypedValue::U64(handle)),
                cv(TypedValue::Bytes(b"DATA".to_vec())),
                cv(TypedValue::U32(4)),
                cv(TypedValue::U64(0)),
            ],
            3_000,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        write,
        &[
            cv(TypedValue::I32(1)),
            cv(TypedValue::U32(4)),
            cv(TypedValue::U32(0)),
        ],
        4_000,
        EventMeta::default(),
    )
    .unwrap();
    let read = em
        .begin_call(
            7,
            "kernel32!ReadFile",
            &[
                cv(TypedValue::U64(handle)),
                cv(TypedValue::U64(0x5000)),
                cv(TypedValue::U32(read_data.len() as u32)),
                cv(TypedValue::U64(0)),
            ],
            5_000,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        read,
        &[
            cv(TypedValue::I32(1)),
            cv(TypedValue::U32(read_data.len() as u32)),
            cv(TypedValue::Bytes(read_data.to_vec())),
            cv(TypedValue::U32(0)),
        ],
        6_000,
        EventMeta::with_payload(PayloadData::Blob(read_data.to_vec())),
    )
    .unwrap();
    let close = em
        .begin_call(
            7,
            "kernel32!CloseHandle",
            &[cv(TypedValue::U64(handle))],
            7_000,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        close,
        &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        8_000,
        EventMeta::default(),
    )
    .unwrap();
    em.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn emitted_trace_roundtrips_and_honors_contract() {
    let bytes = record_session(0x100, b"DATA");
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    assert!(trace.issues.is_empty(), "issues: {:?}", trace.issues);
    assert_eq!(trace.registry.len(), 12, "file_io set registers 12 schemas");
    assert_eq!(trace.total_events(), 8);
    let fin = trace.finalization.as_ref().expect("finalization present");
    assert_eq!(fin.total_events, 8);
    assert!(trace.finalized_cleanly);

    // sequence はスレッド内で 1 から単調増加。
    let seqs: Vec<u64> = trace.batches[0].events.iter().map(|e| e.sequence).collect();
    assert_eq!(seqs, (1..=8).collect::<Vec<_>>());

    // Blob Payload が内容で解決できる。
    let read_leave = &trace.batches[0].events[5];
    match trace.resolve_payload(read_leave) {
        shirusu_trace::reader::PayloadResolution::Blob(data) => assert_eq!(data, b"DATA"),
        other => panic!("unexpected payload resolution: {other:?}"),
    }

    // ビュー層で API 名と値が復元できる（compare の前提）。
    let view = shirusu_analysis::TraceView::build(&trace);
    assert_eq!(
        view.events[0].api_name.as_deref(),
        Some("kernel32!CreateFileW")
    );
    assert_eq!(view.events[0].phase(), shirusu_analysis::Phase::Enter);
    assert_eq!(view.events[1].phase(), shirusu_analysis::Phase::Leave);
    let ret = view.events[1].field("return").unwrap();
    assert_eq!(ret.value, TypedValue::U64(0x100));
    assert_eq!(
        view.events[0].session_id, 42,
        "batch context comes from the session config"
    );
}

#[test]
fn unknown_api_and_bad_values_are_errors() {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
    )
    .unwrap();
    assert!(matches!(
        em.begin_call(1, "kernel32!Nope", &[], 0, EventMeta::default()),
        Err(shirusu_emit::EmitError::UnknownApi(_))
    ));
    // フィールド個数の不一致は符号化エラーとして返る。
    assert!(matches!(
        em.begin_call(1, "kernel32!CloseHandle", &[], 0, EventMeta::default()),
        Err(shirusu_emit::EmitError::Compact(_))
    ));
    // 型の不一致も同様。
    assert!(matches!(
        em.begin_call(
            1,
            "kernel32!CloseHandle",
            &[cv(TypedValue::Str("x".into()))],
            0,
            EventMeta::default()
        ),
        Err(shirusu_emit::EmitError::Compact(_))
    ));
}

#[test]
fn call_pairing_is_enforced() {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
    )
    .unwrap();
    let bogus = CallToken {
        thread_id: 1,
        call_id: 99,
        api_id: 4,
    };
    assert!(matches!(
        em.end_call(
            bogus,
            &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            0,
            EventMeta::default()
        ),
        Err(shirusu_emit::EmitError::UnknownCall { .. })
    ));
    // end 済みのトークンの再 end も弾く。
    let tok = em
        .begin_call(
            1,
            "kernel32!CloseHandle",
            &[cv(TypedValue::U64(0x10))],
            0,
            EventMeta::default(),
        )
        .unwrap();
    em.end_call(
        tok,
        &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        1,
        EventMeta::default(),
    )
    .unwrap();
    assert!(matches!(
        em.end_call(
            tok,
            &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
            2,
            EventMeta::default()
        ),
        Err(shirusu_emit::EmitError::UnknownCall { .. })
    ));
}

#[test]
fn finish_rejects_open_calls_but_abandon_allows_finish() {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
    )
    .unwrap();
    let tok = em
        .begin_call(
            3,
            "kernel32!CloseHandle",
            &[cv(TypedValue::U64(0x10))],
            0,
            EventMeta::default(),
        )
        .unwrap();
    assert_eq!(em.open_call_count(3), 1);
    // オープンなままの finish は、トークンを保持したまま検証できない
    // ので、別インスタンスで abandon 経路を確認する。
    em.abandon_call(tok).unwrap();
    assert_eq!(em.open_call_count(3), 0);
    let out = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&out).unwrap();
    assert_eq!(trace.total_events(), 1, "only the enter was recorded");

    // オープンなまま finish すると OpenCallsAtFinish になる。
    let mut em2 = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(1, "emit-test"),
    )
    .unwrap();
    em2.begin_call(
        3,
        "kernel32!CloseHandle",
        &[cv(TypedValue::U64(0x10))],
        0,
        EventMeta::default(),
    )
    .unwrap();
    match em2.finish(FinalizationInfo::default()) {
        Err(shirusu_emit::EmitError::OpenCallsAtFinish { thread_id, .. }) => {
            assert_eq!(thread_id, 3);
        }
        other => panic!("expected OpenCallsAtFinish, got {other:?}"),
    }
}

#[test]
fn nested_calls_get_parent_linkage_and_interleaved_threads_sequence_independently() {
    let mut em = Emitter::new(
        Vec::new(),
        file_io_api_set(),
        SessionConfig::new(9, "emit-test"),
    )
    .unwrap();
    let outer = em
        .begin_call(
            1,
            "kernel32!CreateFileW",
            &[
                cv(str16("a.dat")),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
                cv(TypedValue::U32(3)),
                cv(TypedValue::U32(0)),
                cv(TypedValue::U64(0)),
            ],
            10,
            EventMeta::default(),
        )
        .unwrap();
    // 別スレッドの呼び出し（sequence はスレッドごとに独立）。
    let other = em
        .begin_call(
            2,
            "kernel32!CloseHandle",
            &[cv(TypedValue::U64(0x77))],
            11,
            EventMeta::default(),
        )
        .unwrap();
    // ネストした内側の呼び出し。
    let inner = em
        .begin_call(
            1,
            "kernel32!WriteFile",
            &[
                cv(TypedValue::U64(0x100)),
                cv(TypedValue::Bytes(vec![1])),
                cv(TypedValue::U32(1)),
                cv(TypedValue::U64(0)),
            ],
            12,
            EventMeta::default(),
        )
        .unwrap();
    // 非 LIFO の end（非同期完了の表現）も許す。
    em.end_call(
        outer,
        &[cv(TypedValue::U64(0x100)), cv(TypedValue::U32(0))],
        13,
        EventMeta::default(),
    )
    .unwrap();
    em.end_call(
        inner,
        &[
            cv(TypedValue::I32(1)),
            cv(TypedValue::U32(1)),
            cv(TypedValue::U32(0)),
        ],
        14,
        EventMeta::default(),
    )
    .unwrap();
    em.end_call(
        other,
        &[cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        15,
        EventMeta::default(),
    )
    .unwrap();
    let bytes = em.finish(FinalizationInfo::default()).unwrap();
    let trace = shirusu_trace::read_trace(&bytes).unwrap();
    // スレッド 1 の列：CreateEnter(parent=0), WriteEnter(parent=create), CreateLeave, WriteLeave。
    let t1: Vec<_> = trace
        .batches
        .iter()
        .filter(|b| b.thread_id == 1)
        .flat_map(|b| b.events.iter())
        .collect();
    assert_eq!(t1.len(), 4);
    assert_eq!(t1[0].parent_call_id, 0);
    assert_eq!(
        t1[1].parent_call_id, t1[0].call_id,
        "inner call nests under outer"
    );
    let seqs: Vec<u64> = t1.iter().map(|e| e.sequence).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4]);
    let t2: Vec<_> = trace
        .batches
        .iter()
        .filter(|b| b.thread_id == 2)
        .flat_map(|b| b.events.iter())
        .collect();
    assert_eq!(
        t2.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![1, 2],
        "thread 2 sequences start at 1 independently"
    );
}
