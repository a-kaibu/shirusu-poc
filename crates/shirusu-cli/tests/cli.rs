//! `shirusu` バイナリの統合テスト。合成 Trace を一時ファイルに書き、
//! 実バイナリを起動して inspect / dump / export の出力をゴールデンと
//! 照合する。ゴールデンの更新は UPDATE_GOLDEN=1 で明示的に行う。

use shirusu_trace::blob::BlobId;
use shirusu_trace::compact::encode_event_chunk;
use shirusu_trace::compact::encode_values;
use shirusu_trace::container::{
    parse_raw_header, serialize_header, BlockHeader, BlockType, Compression,
};
use shirusu_trace::model::{EventBatch, PayloadLossReason, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
use shirusu_trace::schema::{make_schema, CapturedValue, EventCapture, Ty, TypedValue};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::PayloadRef;
use shirusu_trace::TraceWriter;
use std::path::PathBuf;
use std::process::Command;

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

fn sample_trace_bytes() -> Vec<u8> {
    trace_bytes_with(FinalizationInfo::default(), false)
}

/// `fin` で Finalization を、`drop_first_payload` で先頭イベントの
/// Payload 欠落を変えた合成 Trace。H14 の incomplete 判定の回帰用。
fn trace_bytes_with(fin: FinalizationInfo, drop_first_payload: bool) -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
                ("hTemplateFile".into(), Ty::U64, 0),
            ],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![
                ("return".into(), Ty::U64, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            7,
            "kernel32!CloseHandle/enter",
            vec![("hObject".into(), Ty::U64, 0)],
        ),
        make_schema(
            8,
            "kernel32!CloseHandle/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
    ] {
        w.register_schema(def).unwrap();
    }
    let ev = |kind: u16,
              sequence: u64,
              api_id: u32,
              schema_id: u32,
              types: &[Ty],
              values: Vec<CapturedValue>| {
        TraceEvent {
            kind,
            sequence,
            timestamp_qpc: 1_000 + sequence * 10,
            call_id: 1,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload: shirusu_trace::PayloadRef::None,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        }
    };
    let mut events = vec![
        ev(
            1,
            1,
            1,
            1,
            &[Ty::Str16, Ty::U32, Ty::U64],
            vec![
                cv(TypedValue::Str16("a.txt".encode_utf16().collect())),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U64(0)),
            ],
        ),
        ev(
            2,
            2,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(0x2a4)), cv(TypedValue::U32(0))],
        ),
        ev(1, 3, 4, 7, &[Ty::U64], vec![cv(TypedValue::U64(0x2a4))]),
        ev(
            2,
            4,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), cv(TypedValue::U32(0))],
        ),
    ];
    if drop_first_payload {
        events[0].payload = PayloadRef::Dropped {
            original_len: 16,
            reason: PayloadLossReason::Overflow,
        };
    }
    w.write_batch(&EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events,
    })
    .unwrap();
    w.finish(fin).unwrap()
}

/// 一意の一時ディレクトリを作る。テストスレッドが並行に同じ
/// sample.trace を書き換え合うと、読んでいる途中の CLI が不完全な
/// Trace を掴んで失敗する競合があったため、呼び出しごとに一意にする。
fn fresh_dir() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("shirusu-cli-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_shirusu"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
        out.status.code(),
    )
}

/// 一時ディレクトリに sample.trace を置き、その中でバイナリを起動する。
/// ディレクトリは呼び出しごとに一意にする: テストスレッドが並行に
/// 同じ sample.trace を書き換え合うと、読んでいる途中の CLI が
/// 不完全な Trace を掴んで失敗する競合があった。
fn run_cli(args: &[&str]) -> (String, String, bool) {
    let (out, err, code) = run_cli_bytes(&sample_trace_bytes(), args);
    (out, err, code == Some(0))
}

/// 任意の Trace バイトでバイナリを起動し、終了コードまで返す。
/// H14: incomplete な Trace の inspect は終了 1 になる。
fn run_cli_bytes(bytes: &[u8], args: &[&str]) -> (String, String, Option<i32>) {
    let dir = fresh_dir();
    std::fs::write(dir.join("sample.trace"), bytes).unwrap();
    run_in(&dir, args)
}

/// 改行コードを LF へ寄せる。golden のチェックアウト (Windows の
/// autocrlf) や実行環境の差で CRLF が混ざっても、内容の比較が改行
/// だけで落ちないようにする (レビュー #4 の隠れ失敗 (a))。
/// .gitattributes でも golden は eol=lf に固定してある。
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn check_golden(name: &str, actual: &str) {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "golden", name]
        .iter()
        .collect();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
    assert_eq!(
        normalize_newlines(actual),
        normalize_newlines(&expected),
        "golden mismatch for {name}; rerun with UPDATE_GOLDEN=1 to refresh"
    );
}

#[test]
fn golden_compare_ignores_newline_style_only() {
    // 改行コードの差は無視するが、内容の差は検出する (正規化で
    // 比較自体が空転していないことの固定)。
    assert_eq!(
        normalize_newlines("a\r\nb\rc\n"),
        normalize_newlines("a\nb\nc\n")
    );
    assert_ne!(normalize_newlines("a\r\nb"), normalize_newlines("a\nc"));
}

#[test]
fn inspect_matches_golden() {
    let (stdout, stderr, ok) = run_cli(&["inspect", "sample.trace"]);
    assert!(ok, "stderr: {stderr}");
    check_golden("inspect.txt", &stdout);
}

#[test]
fn dump_matches_golden() {
    let (stdout, stderr, ok) = run_cli(&["dump", "sample.trace"]);
    assert!(ok, "stderr: {stderr}");
    check_golden("dump.txt", &stdout);
}

#[test]
fn dump_json_and_filters() {
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--json"]);
    assert!(ok);
    assert!(
        stdout.contains("\"api\":\"kernel32!CreateFileW\""),
        "{stdout}"
    );
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--api", "CloseHandle"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--text", "a.txt"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let (stdout, _, ok) = run_cli(&["dump", "sample.trace", "--seq", "2..3", "--kind", "leave"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
}

/// L11: 2 スレッドの Batch に全体順序を振った Trace。
/// ファイル順は thread 11 (g=1, 3) → thread 12 (g=2, 4) で、
/// 全体順序で並べ替えると 1, 2, 3, 4 になる。
fn global_order_trace_bytes() -> Vec<u8> {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![("lpFileName".into(), Ty::Str16, 0)],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![("return".into(), Ty::U64, 0)],
        ),
    ] {
        w.register_schema(def).unwrap();
    }
    let ev = |kind: u16, sequence: u64, global_order: u64| TraceEvent {
        kind,
        sequence,
        timestamp_qpc: 1_000 + sequence * 10,
        call_id: sequence,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 1,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: Some(encode_values(&[Ty::Str16], &[cv(str16("a.txt"))]).unwrap()),
        global_order: Some(global_order),
    };
    for (thread_id, orders) in [(11u64, [1u64, 3u64]), (12u64, [2u64, 4u64])] {
        let events = orders
            .iter()
            .enumerate()
            .map(|(i, g)| ev(if i == 0 { 1 } else { 2 }, (i + 1) as u64, *g))
            .collect();
        w.write_batch(&EventBatch {
            session_id: 42,
            process_id: 7,
            raw_pid: 1234,
            thread_id,
            qpc_frequency: 10_000_000,
            events,
        })
        .unwrap();
    }
    w.finish(FinalizationInfo::default()).unwrap()
}

fn dump_global_orders(stdout: &str) -> Vec<u64> {
    stdout
        .lines()
        .map(|l| {
            let at = l.find(" g=").expect("line has g=<n>");
            l[at + 3..]
                .split(' ')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .collect()
}

#[test]
fn dump_order_global_sorts_across_threads() {
    let bytes = global_order_trace_bytes();
    let (stdout, stderr, code) = run_cli_bytes(&bytes, &["dump", "sample.trace", "--order=global"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(dump_global_orders(&stdout), vec![1, 2, 3, 4]);
    // ファイル順（--order 無し）では thread 11 の 2 件が先に来る。
    let (stdout, _, code) = run_cli_bytes(&bytes, &["dump", "sample.trace"]);
    assert_eq!(code, Some(0));
    assert_eq!(dump_global_orders(&stdout), vec![1, 3, 2, 4]);
}

#[test]
fn dump_order_global_space_form() {
    let bytes = global_order_trace_bytes();
    let (stdout, stderr, code) =
        run_cli_bytes(&bytes, &["dump", "sample.trace", "--order", "global"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(dump_global_orders(&stdout), vec![1, 2, 3, 4]);
}

#[test]
fn dump_order_global_json_includes_global_order() {
    let bytes = global_order_trace_bytes();
    let (stdout, stderr, code) = run_cli_bytes(
        &bytes,
        &["dump", "sample.trace", "--order=global", "--json"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("\"global_order\":1"), "{stdout}");
}

#[test]
fn dump_order_global_rejected_without_global_order() {
    let (_out, stderr, ok) = run_cli(&["dump", "sample.trace", "--order=global"]);
    assert!(!ok);
    assert!(
        stderr.contains("not recorded with --order=global"),
        "{stderr}"
    );
}

#[test]
fn dump_order_unknown_value_rejected() {
    let (_out, stderr, ok) = run_cli(&["dump", "sample.trace", "--order=bogus"]);
    assert!(!ok);
    assert!(stderr.contains("unknown --order value: bogus"), "{stderr}");
}

#[test]
fn inspect_shows_global_order_present() {
    let bytes = global_order_trace_bytes();
    let (stdout, stderr, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("global_order: present (4 of 4 events)"),
        "{stdout}"
    );
}

#[test]
fn export_jsonl_line_count() {
    let (stdout, _, ok) = run_cli(&["export", "sample.trace", "--format", "jsonl"]);
    assert!(ok);
    assert_eq!(stdout.lines().count(), 4);
    assert!(stdout
        .lines()
        .all(|l| l.starts_with('{') && l.ends_with('}')));
}

#[test]
fn inspect_degraded_trace_exits_one() {
    // Finalization が event_integrity=Degraded を宣言した Trace は
    // incomplete なので inspect は終了 1 になる (H14)。
    let bytes = trace_bytes_with(
        FinalizationInfo {
            event_integrity: 1,
            ..Default::default()
        },
        false,
    );
    let (stdout, stderr, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace"]);
    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("status: incomplete"), "{stdout}");
    assert!(stderr.contains("incomplete"), "{stderr}");
}

#[test]
fn inspect_dropped_payload_trace_exits_one() {
    // Finalization が Complete でも、落ちた Payload があれば
    // Event Integrity の損失として incomplete になる (H14)。
    let bytes = trace_bytes_with(FinalizationInfo::default(), true);
    let (stdout, stderr, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace"]);
    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("status: incomplete"), "{stdout}");
    assert!(stderr.contains("incomplete"), "{stderr}");
}

#[test]
fn inspect_degraded_trace_json_exits_one() {
    let bytes = trace_bytes_with(
        FinalizationInfo {
            event_integrity: 2,
            ..Default::default()
        },
        false,
    );
    let (stdout, stderr, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace", "--json"]);
    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("incomplete"), "{stdout}");
    assert!(stderr.contains("incomplete"), "{stderr}");
}

#[test]
fn bad_inputs_exit_nonzero() {
    let (_, stderr, ok) = run_cli(&["inspect", "missing.trace"]);
    assert!(!ok);
    assert!(stderr.contains("cannot read"), "{stderr}");
    let (_, _, ok) = run_cli(&["frobnicate", "sample.trace"]);
    assert!(!ok);
    let (_, _, ok) = run_cli(&["export", "sample.trace", "--format", "parquet"]);
    assert!(!ok);
}

/// F22 用の Trace: Blob を参照する CreateFileW leave イベントを含む
/// enter/leave 1 往復。戻り値は (Trace バイト列, BlobId)。
fn trace_bytes_with_blob() -> (Vec<u8>, BlobId) {
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
                ("hTemplateFile".into(), Ty::U64, 0),
            ],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![
                ("return".into(), Ty::U64, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
    ] {
        w.register_schema(def).unwrap();
    }
    let id = w.add_payload(b"file contents").unwrap();
    let enter = TraceEvent {
        kind: 1,
        sequence: 1,
        timestamp_qpc: 1010,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 1,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: Some(
            encode_values(
                &[Ty::Str16, Ty::U32, Ty::U64],
                &[
                    cv(str16("a.txt")),
                    cv(TypedValue::U32(0x8000_0000)),
                    cv(TypedValue::U64(0)),
                ],
            )
            .unwrap(),
        ),
        global_order: None,
    };
    let leave = TraceEvent {
        kind: 2,
        sequence: 2,
        timestamp_qpc: 1020,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 2,
        capture: EventCapture::Captured,
        payload: PayloadRef::Blob(id),
        args: Some(
            encode_values(
                &[Ty::U64, Ty::U32],
                &[cv(TypedValue::U64(0x2a4)), cv(TypedValue::U32(0))],
            )
            .unwrap(),
        ),
        global_order: None,
    };
    let batch = EventBatch {
        session_id: 42,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events: vec![enter, leave],
    };
    w.write_batch(&batch).unwrap();
    (w.finish(FinalizationInfo::default()).unwrap(), id)
}

/// Blob Chunk の本体 1 バイトを壊し、Block の CRC32C を再計算して
/// 整合させる（Blob ID と内容の BLAKE3 が一致しなくなる）。
fn corrupt_blob_body(bytes: &[u8]) -> Vec<u8> {
    let mut pos = 0usize;
    while pos + 32 <= bytes.len() {
        let raw = parse_raw_header(&bytes[pos..]).expect("valid header");
        if raw.block_type_code == BlockType::BlobChunk.code() {
            let header = BlockHeader {
                block_type: BlockType::BlobChunk,
                compression: Compression::from_code(raw.compression_code).unwrap(),
                sequence: raw.sequence,
                stored_len: raw.stored_len,
                raw_len: raw.raw_len,
            };
            let stored = &bytes[pos + 32..pos + 32 + raw.stored_len as usize];
            let mut payload = shirusu_trace::container::decode_payload(&header, stored).unwrap();
            payload[36] ^= 0xFF;
            let new_header = BlockHeader {
                block_type: BlockType::BlobChunk,
                compression: Compression::None,
                sequence: raw.sequence,
                stored_len: payload.len() as u32,
                raw_len: payload.len() as u32,
            };
            let mut out = bytes[..pos].to_vec();
            out.extend_from_slice(&serialize_header(&new_header, &payload));
            out.extend_from_slice(&payload);
            out.extend_from_slice(&bytes[pos + 32 + raw.stored_len as usize..]);
            return out;
        }
        pos += 32 + raw.stored_len as usize;
    }
    panic!("no blob chunk found");
}

#[test]
fn dump_finds_api_call_with_corrupt_blob() {
    // F22: Blob が壊れても、実バイナリの `dump --api` で API 呼び出し
    // 自体が検索できる（enter/leave の 2 行が残る）。
    let (bytes, _id) = trace_bytes_with_blob();
    let corrupted = corrupt_blob_body(&bytes);
    let (stdout, stderr, code) = run_cli_bytes(
        &corrupted,
        &["dump", "sample.trace", "--api", "CreateFileW"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert!(stdout.contains("kernel32!CreateFileW"), "{stdout}");
}

// ---------------------------------------------------------------------------
// L12: `shirusu repair`
// ---------------------------------------------------------------------------

/// 入力バイトを sample.trace に置き、repair を実行して
/// (stdout, stderr, 終了コード, 作業ディレクトリ) を返す。
fn run_repair(input: &[u8], args: &[&str]) -> (String, String, Option<i32>, PathBuf) {
    let dir = fresh_dir();
    std::fs::write(dir.join("sample.trace"), input).unwrap();
    let (out, err, code) = run_in(&dir, args);
    (out, err, code, dir)
}

/// EventChunk ブロック（無圧縮）を末尾に追記する。Finalization の後でも
/// Reader は走査を続けるため、セッション不一致・シーケンス退行の入力を
/// 合成できる（TraceWriter では書けない、信頼できない入力の形）。
fn append_event_chunk(bytes: &[u8], batch: &EventBatch) -> Vec<u8> {
    let payload = encode_event_chunk(batch);
    let header = BlockHeader {
        block_type: BlockType::EventChunk,
        compression: Compression::None,
        sequence: 999,
        stored_len: payload.len() as u32,
        raw_len: payload.len() as u32,
    };
    let mut out = bytes.to_vec();
    out.extend_from_slice(&serialize_header(&header, &payload));
    out.extend_from_slice(&payload);
    out
}

/// 追記チャンク用の単発イベント（schema 1 = CreateFileW/enter 相当）。
fn single_event(sequence: u64) -> TraceEvent {
    TraceEvent {
        kind: 1,
        sequence,
        timestamp_qpc: 1000 + sequence * 10,
        call_id: 1,
        parent_call_id: 0,
        api_id: 1,
        schema_id: 1,
        capture: EventCapture::Captured,
        payload: PayloadRef::None,
        args: Some(
            encode_values(
                &[Ty::Str16, Ty::U32, Ty::U64],
                &[
                    cv(str16("a.txt")),
                    cv(TypedValue::U32(0x8000_0000)),
                    cv(TypedValue::U64(0)),
                ],
            )
            .unwrap(),
        ),
        global_order: None,
    }
}

fn appended_batch(session_id: u64, sequence: u64) -> EventBatch {
    EventBatch {
        session_id,
        process_id: 7,
        raw_pid: 1234,
        thread_id: 55,
        qpc_frequency: 10_000_000,
        events: vec![single_event(sequence)],
    }
}

#[test]
fn repair_healthy_trace_roundtrips() {
    let (stdout, stderr, code, dir) = run_repair(
        &sample_trace_bytes(),
        &["repair", "sample.trace", "--output", "repaired.trace"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    check_golden("repair.txt", &stdout);
    let repaired = std::fs::read(dir.join("repaired.trace")).unwrap();
    let trace = shirusu_trace::read_trace(&repaired).unwrap();
    assert_eq!(trace.total_events(), 4);
    assert!(trace.issues.is_empty(), "{:?}", trace.issues);
    // 出力も実バイナリの inspect で読める。
    let (out, err, code) = run_in(&dir, &["inspect", "repaired.trace"]);
    assert_eq!(code, Some(0), "stderr: {err}");
    assert!(out.contains("status: complete"), "{out}");
    assert!(out.contains("events: 4 in 1 batches"), "{out}");
}

#[test]
fn repair_corrupt_blob_drops_event() {
    // Blob が壊れると、その Blob を参照する leave だけが失われ、
    // enter は回収される（失われたイベントを推測で作らない）。
    let (bytes, _id) = trace_bytes_with_blob();
    let corrupted = corrupt_blob_body(&bytes);
    let (stdout, stderr, code, dir) = run_repair(
        &corrupted,
        &["repair", "sample.trace", "--output", "repaired.trace"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("events: 1 recovered, 1 lost (scanned 2)"),
        "{stdout}"
    );
    assert!(stdout.contains("blob_hash_mismatch"), "{stdout}");
    assert!(stdout.contains("  - missing_blob: 1"), "{stdout}");
    let repaired = std::fs::read(dir.join("repaired.trace")).unwrap();
    let trace = shirusu_trace::read_trace(&repaired).unwrap();
    assert_eq!(trace.total_events(), 1);
}

#[test]
fn repair_truncated_tail_recovers_events() {
    // 末尾 10 バイトを切ると Finalization の payload が切断するが、
    // それ以前のイベントはすべて回収できる。
    let mut bytes = sample_trace_bytes();
    bytes.truncate(bytes.len() - 10);
    let (stdout, stderr, code, dir) = run_repair(
        &bytes,
        &["repair", "sample.trace", "--output", "repaired.trace"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("truncated_tail"), "{stdout}");
    assert!(
        stdout.contains("events: 4 recovered, 0 lost (scanned 4)"),
        "{stdout}"
    );
    let repaired = std::fs::read(dir.join("repaired.trace")).unwrap();
    assert_eq!(
        shirusu_trace::read_trace(&repaired).unwrap().total_events(),
        4
    );
}

#[test]
fn repair_refuses_same_output() {
    let input = sample_trace_bytes();
    let (_stdout, stderr, code, dir) = run_repair(
        &input,
        &["repair", "sample.trace", "--output", "sample.trace"],
    );
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("refusing"), "{stderr}");
    assert_eq!(std::fs::read(dir.join("sample.trace")).unwrap(), input);
}

#[test]
fn repair_default_output_path() {
    let (stdout, stderr, code, dir) =
        run_repair(&sample_trace_bytes(), &["repair", "sample.trace"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("sample.trace -> sample.trace.repaired"),
        "{stdout}"
    );
    let repaired = std::fs::read(dir.join("sample.trace.repaired")).unwrap();
    assert_eq!(
        shirusu_trace::read_trace(&repaired).unwrap().total_events(),
        4
    );
}

#[test]
fn repair_json_report() {
    let (stdout, stderr, code, _dir) = run_repair(
        &sample_trace_bytes(),
        &[
            "repair",
            "sample.trace",
            "--output",
            "repaired.trace",
            "--json",
        ],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("\"recovered\": 4"), "{stdout}");
    assert!(stdout.contains("\"lost\": 0"), "{stdout}");
    assert!(
        stdout.contains("\"output\": \"repaired.trace\""),
        "{stdout}"
    );
}

#[test]
fn repair_skips_session_mismatch_batch() {
    // Header と異なる session_id の Batch は丸ごと回収しない。
    let bytes = append_event_chunk(&sample_trace_bytes(), &appended_batch(99, 5));
    let (stdout, stderr, code, dir) = run_repair(
        &bytes,
        &["repair", "sample.trace", "--output", "repaired.trace"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("events: 4 recovered, 1 lost (scanned 5)"),
        "{stdout}"
    );
    assert!(stdout.contains("session_mismatch: 1"), "{stdout}");
    let repaired = std::fs::read(dir.join("repaired.trace")).unwrap();
    assert_eq!(
        shirusu_trace::read_trace(&repaired).unwrap().total_events(),
        4
    );
}

#[test]
fn repair_skips_sequence_regression_batch() {
    // 同一スレッドで sequence が退行する Batch は丸ごと回収しない
    //（Writer の不変条件に反するため、無理に書き直さない）。
    let bytes = append_event_chunk(&sample_trace_bytes(), &appended_batch(42, 1));
    let (stdout, stderr, code, dir) = run_repair(
        &bytes,
        &["repair", "sample.trace", "--output", "repaired.trace"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("events: 4 recovered, 1 lost (scanned 5)"),
        "{stdout}"
    );
    assert!(stdout.contains("sequence_regression: 1"), "{stdout}");
    let repaired = std::fs::read(dir.join("repaired.trace")).unwrap();
    assert_eq!(
        shirusu_trace::read_trace(&repaired).unwrap().total_events(),
        4
    );
}

// ---------------------------------------------------------------------------
// L22: `shirusu capture` / `shirusu attach`
// ---------------------------------------------------------------------------

/// Windows 以外では capture / attach は実働できない。引数の検証まで
/// 済ませたうえで、プラットフォーム制限を明言して終了 1 にする。
#[cfg(not(windows))]
#[test]
fn capture_reports_windows_only() {
    let (_out, err, code) = run_in(&fresh_dir(), &["capture", "--", "notepad.exe"]);
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(err.contains("only available on Windows"), "stderr: {err}");
}

#[cfg(not(windows))]
#[test]
fn attach_reports_windows_only() {
    let (_out, err, code) = run_in(&fresh_dir(), &["attach", "1234"]);
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(err.contains("only available on Windows"), "stderr: {err}");
}

/// PID の検証はプラットフォームゲートの前に行う（全 OS で終了 2）。
#[test]
fn attach_rejects_bad_pid() {
    let (_out, err, code) = run_in(&fresh_dir(), &["attach", "abc"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("bad pid: abc"), "stderr: {err}");
}

#[test]
fn attach_needs_pid() {
    let (_out, err, code) = run_in(&fresh_dir(), &["attach"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("attach needs a <PID>"), "stderr: {err}");
}

#[test]
fn capture_needs_command_line() {
    let (_out, err, code) = run_in(&fresh_dir(), &["capture"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(
        err.contains("capture needs a command line after --"),
        "stderr: {err}"
    );
}

#[test]
fn capture_rejects_bad_timeout() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--timeout", "abc", "--", "a.exe"],
    );
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("bad --timeout: abc"), "stderr: {err}");
}

#[test]
fn attach_rejects_bad_timeout() {
    let (_out, err, code) = run_in(&fresh_dir(), &["attach", "1234", "--timeout", "abc"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("bad --timeout: abc"), "stderr: {err}");
}

#[test]
fn capture_rejects_bad_order() {
    let (_out, err, code) = run_in(&fresh_dir(), &["capture", "--order=bogus", "--", "a.exe"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(
        err.contains("unknown --order value: bogus"),
        "stderr: {err}"
    );
}

#[test]
fn capture_rejects_bad_module_class() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--module-class", "foo=banana", "--", "a.exe"],
    );
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("bad --module-class"), "stderr: {err}");
}

/// L07: モジュール分類を Environment に持つ Trace。inspect（人間可読・
/// JSON）で分類と判定理由が見えることの回帰用。
fn modules_trace_bytes() -> Vec<u8> {
    use shirusu_trace::module::{classify_module, ModuleEvidence};
    let mut env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    env.modules.push(classify_module(
        &ModuleEvidence::new(r"C:\Windows\System32\kernel32.dll").signed(true),
    ));
    env.modules
        .push(classify_module(&ModuleEvidence::new(r"C:\tools\game.exe")));
    let w = TraceWriter::new(Vec::new(), env).unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn inspect_shows_module_classifications() {
    let bytes = modules_trace_bytes();
    let (out, err, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace"]);
    assert_eq!(code, Some(0), "stderr: {err}");
    assert!(out.contains("modules:"), "{out}");
    assert!(out.contains("kernel32.dll"), "{out}");
    assert!(out.contains("windows"), "{out}");
    assert!(out.contains("game.exe"), "{out}");
    assert!(out.contains("application"), "{out}");
}

#[test]
fn inspect_json_includes_modules() {
    let bytes = modules_trace_bytes();
    let (out, err, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace", "--json"]);
    assert_eq!(code, Some(0), "stderr: {err}");
    assert!(out.contains("\"modules\""), "{out}");
    assert!(out.contains("kernel32.dll"), "{out}");
}

#[test]
fn usage_lists_capture_and_attach() {
    let (out, _err, code) = run_in(&fresh_dir(), &["help"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("capture"), "{out}");
    assert!(out.contains("attach"), "{out}");
}

/// L09: `--mode` の使い方エラー（全 OS で終了 2）。
#[test]
fn capture_rejects_bad_mode() {
    let (_out, err, code) = run_in(&fresh_dir(), &["capture", "--mode", "bogus", "--", "a.exe"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("unknown --mode value: bogus"), "stderr: {err}");
}

#[test]
fn capture_rejects_api_without_filtered() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--api", "CreateFileW", "--", "a.exe"],
    );
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(
        err.contains("--api requires --mode filtered"),
        "stderr: {err}"
    );
}

#[test]
fn capture_rejects_filtered_without_api() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--mode", "filtered", "--", "a.exe"],
    );
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(
        err.contains("--mode filtered requires at least one --api"),
        "stderr: {err}"
    );
}

#[test]
fn capture_rejects_unknown_api() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &[
            "capture",
            "--mode",
            "filtered",
            "--api",
            "NoSuchApi",
            "--",
            "a.exe",
        ],
    );
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(err.contains("unknown API: NoSuchApi"), "stderr: {err}");
}

/// L09: 有効な `--mode profile` は引数検証を通り、Linux では
/// プラットフォーム制限で終了 1 になる（--mode が未知オプションなら
/// 終了 2 になるため、到達の判別になる）。
#[cfg(not(windows))]
#[test]
fn capture_mode_profile_reports_windows_only() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--mode", "profile", "--", "a.exe"],
    );
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(err.contains("only available on Windows"), "stderr: {err}");
}

/// L05: `--follow-children` は有効なフラグとして引数検証を通り、
/// Linux ではプラットフォーム制限で終了 1 になる。
#[cfg(not(windows))]
#[test]
fn capture_follow_children_reports_windows_only() {
    let (_out, err, code) = run_in(
        &fresh_dir(),
        &["capture", "--follow-children", "--", "a.exe"],
    );
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(err.contains("only available on Windows"), "stderr: {err}");
}

/// L05: `--follow-children` は起動（capture）専用で、attach では
/// 使い方エラーになる（全 OS で終了 2）。
#[test]
fn attach_rejects_follow_children() {
    let (_out, err, code) = run_in(&fresh_dir(), &["attach", "1234", "--follow-children"]);
    assert_eq!(code, Some(2), "stderr: {err}");
    assert!(
        err.contains("--follow-children requires capture (launch)"),
        "stderr: {err}"
    );
}

/// L09: ProfileSummary を持つ Trace。inspect（人間可読・JSON）で
/// 集計が見えることの回帰用。
fn profile_trace_bytes() -> Vec<u8> {
    use shirusu_trace::proto::{ApiProfile, ProfileSummary};
    let env = CaptureEnvironment {
        session: SessionMetadata {
            session_id: 42,
            created_by: "cli-test".into(),
            qpc_frequency: 10_000_000,
        },
        os_version: "Windows 11".into(),
        cpu_arch: "x86_64".into(),
        pointer_width: 64,
        ..Default::default()
    };
    let mut w = TraceWriter::new(Vec::new(), env).unwrap();
    for def in [
        make_schema(1, "kernel32!CreateFileW/enter", vec![]),
        make_schema(2, "kernel32!CreateFileW/leave", vec![]),
    ] {
        w.register_schema(def).unwrap();
    }
    w.write_profile_summary(&ProfileSummary {
        qpc_frequency: 10_000_000,
        total_events_seen: 5,
        apis: vec![ApiProfile {
            api_id: 1,
            calls: 2,
            enters: 3,
            leaves: 2,
            total_duration_qpc: 5000,
            min_duration_qpc: 1000,
            max_duration_qpc: 4000,
        }],
    })
    .unwrap();
    w.finish(FinalizationInfo::default()).unwrap()
}

#[test]
fn inspect_shows_profile_summary() {
    let bytes = profile_trace_bytes();
    let (out, err, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace"]);
    assert_eq!(code, Some(0), "stderr: {err}");
    assert!(out.contains("profile:"), "{out}");
    assert!(out.contains("events seen: 5"), "{out}");
    assert!(out.contains("kernel32!CreateFileW"), "{out}");
    assert!(out.contains("2 calls"), "{out}");
}

#[test]
fn inspect_json_includes_profile_summary() {
    let bytes = profile_trace_bytes();
    let (out, err, code) = run_cli_bytes(&bytes, &["inspect", "sample.trace", "--json"]);
    assert_eq!(code, Some(0), "stderr: {err}");
    assert!(out.contains("\"profile_summary\""), "{out}");
    assert!(out.contains("\"total_events_seen\": 5"), "{out}");
    assert!(out.contains("kernel32!CreateFileW"), "{out}");
}
