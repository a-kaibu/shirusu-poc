//! `shirusu repair`（L12）。

use super::*;

// ---------------------------------------------------------------------------
// L12: `shirusu repair`
//
// 回復読み（F11）で読めたイベントだけを新しい Trace に書き出す。
// 正常なチャンクと参照関係を検証し、読めるイベントを回収する。
// 失われたイベントを推測で作らない（overview「完全性と復旧」）。
//
// 回収できないもの（数えて報告する）：
// - 参照先 Blob がファイル内に無いイベント（MissingBlob）。
//   Blob の内容を推測して補うことはしない。
// - Header と session_id が異なる Batch（SessionMismatch）。
//   session_id を書き換えて取り込むことはしない。
// - 同一スレッドで sequence が退行する Batch。Writer の不変条件に
//   反するため、順序を並べ替えて取り込むことはしない。
// - 空の Batch。
//
// 出力に残すもの：読めたイベント（元の Batch 順・元の内容のまま）、
// 参照された Blob（内容の BLAKE3 から同じ ID を再計算する。重複排除
// 済み）、Schema 定義、Loss Record。Blob の部分的な更新（F18）は
// 再発行しない。派生版の内容は `blobs` へ具体化済みで、イベントが
// 参照する版 ID の内容を `add_payload` で運べば十分なため。更新の
// 履歴そのものは修復出力には残らない。
//
// Finalization は元の Trace の三つの指標を引き継ぐ。ただし修復で
// イベントを失った場合、Complete の宣言は維持できないため
// event_integrity を Degraded（1）へ落とす。Finalization が無い
// 入力は三つとも Unknown（3）とする。修復の来歴は notes に残す。
// ---------------------------------------------------------------------------

/// repair の集計。`lost_by_cause` は初出順。
#[derive(Default)]
pub(crate) struct RepairReport {
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) scanned: u64,
    pub(crate) recovered: u64,
    pub(crate) lost: u64,
    pub(crate) batches_written: usize,
    pub(crate) batches_skipped: usize,
    pub(crate) blobs_carried: usize,
    pub(crate) schemas_registered: usize,
    pub(crate) schemas_skipped: usize,
    pub(crate) loss_records: usize,
    pub(crate) issues: Vec<String>,
    pub(crate) lost_by_cause: Vec<(String, u64)>,
}

pub(crate) fn add_lost(report: &mut RepairReport, cause: &str, n: u64) {
    report.lost += n;
    if let Some(entry) = report.lost_by_cause.iter_mut().find(|(c, _)| c == cause) {
        entry.1 += n;
    } else {
        report.lost_by_cause.push((cause.to_string(), n));
    }
}

/// view.rs の IntegritySummary と同じ文字列で issue を表す。
/// 新しい RecoveryIssue バリアントが増えたらここも非網羅マッチで
/// コンパイルエラーになる（view.rs と同じ方針）。
pub(crate) fn format_issue(issue: &RecoveryIssue) -> String {
    match issue {
        RecoveryIssue::TruncatedTail { offset } => {
            format!("truncated_tail(offset={offset})")
        }
        RecoveryIssue::CorruptBlock { offset, reason } => {
            format!("corrupt_block(offset={offset}, reason={reason})")
        }
        RecoveryIssue::Resync { from, to } => format!("resync({from}..{to})"),
        RecoveryIssue::DuplicateBlob { id } => format!("duplicate_blob({id})"),
        RecoveryIssue::BlobHashMismatch { id, computed } => {
            format!("blob_hash_mismatch(id={id}, computed={computed})")
        }
        RecoveryIssue::MissingBlob { id } => format!("missing_blob({id})"),
        RecoveryIssue::ForwardBlobReference { id } => {
            format!("forward_blob_reference({id})")
        }
        RecoveryIssue::IndexMismatch => "index_mismatch".to_string(),
        RecoveryIssue::LimitExceeded { what } => format!("limit_exceeded({what})"),
        RecoveryIssue::SessionMismatch {
            what,
            expected,
            found,
        } => {
            format!("session_mismatch(what={what}, expected={expected}, found={found})")
        }
        RecoveryIssue::BlobUpdateMissingBase { resource_id } => {
            format!("blob_update_missing_base(resource={resource_id})")
        }
        RecoveryIssue::BlobUpdateOutOfRange {
            resource_id,
            offset,
            size,
            base_len,
        } => {
            format!(
                "blob_update_out_of_range(resource={resource_id}, offset={offset}, size={size}, base_len={base_len})"
            )
        }
        RecoveryIssue::BlobUpdateHashMismatch {
            resource_id,
            expected,
            computed,
        } => {
            format!(
                "blob_update_hash_mismatch(resource={resource_id}, expected={expected}, computed={computed})"
            )
        }
    }
}

/// 回復読み済みの Trace から修復済み Trace のバイト列と報告を作る。
/// 途中で失敗しても部分的な出力ファイルは作らない（呼び出し側が
/// 返されたバイト列を書き出すまでは、ファイルは作られない）。
pub(crate) fn repair_trace(
    input: &str,
    trace: &ReadTrace,
) -> Result<(Vec<u8>, RepairReport), ToolError> {
    let mut report = RepairReport {
        input: input.to_string(),
        scanned: trace.total_events(),
        issues: trace.issues.iter().map(format_issue).collect(),
        ..Default::default()
    };
    // Environment が無い入力でも Header の session_id だけは分かる
    // ため、空の Environment で Writer を作る（元の session_id を保つ）。
    let env = match &trace.environment {
        Some(env) => env.clone(),
        None => CaptureEnvironment {
            session: SessionMetadata {
                session_id: trace.header.session_id,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut writer = TraceWriter::new(Vec::new(), env)
        .map_err(|e| ToolError::Runtime(format!("cannot start repaired trace: {e}")))?;
    // Schema は同一内容の再登録は受理される。内容の違う再定義や
    // content_hash の不一致は Writer が拒否するため、その定義だけ
    // 落として数える（修復全体は止めない）。
    for def in &trace.schemas {
        match writer.register_schema(def.clone()) {
            Ok(()) => report.schemas_registered += 1,
            Err(_) => report.schemas_skipped += 1,
        }
    }
    let mut carried: HashSet<BlobId> = HashSet::new();
    let mut last_sequence_by_thread: HashMap<u64, u64> = HashMap::new();
    for batch in &trace.batches {
        if batch.events.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        if batch.session_id != trace.header.session_id {
            report.batches_skipped += 1;
            add_lost(&mut report, "session_mismatch", batch.events.len() as u64);
            continue;
        }
        // 参照先 Blob が無いイベントは落とす（内容を推測しない）。
        let mut kept: Vec<TraceEvent> = Vec::new();
        for e in &batch.events {
            if let PayloadRef::Blob(id) = &e.payload {
                if !trace.blobs.contains_key(id) {
                    add_lost(&mut report, "missing_blob", 1);
                    continue;
                }
            }
            kept.push(e.clone());
        }
        if kept.is_empty() {
            report.batches_skipped += 1;
            continue;
        }
        // シーケンス退行の事前検査。Writer の validate_batch と同じ
        // 規則（スレッドごとに単調。書けた Batch だけが水位を進める）。
        let mut prev = last_sequence_by_thread.get(&batch.thread_id).copied();
        let mut regressed = false;
        for e in &kept {
            if let Some(p) = prev {
                if e.sequence < p {
                    regressed = true;
                    break;
                }
            }
            prev = Some(e.sequence);
        }
        if regressed {
            report.batches_skipped += 1;
            add_lost(&mut report, "sequence_regression", kept.len() as u64);
            continue;
        }
        for e in &kept {
            if let PayloadRef::Blob(id) = &e.payload {
                let data = &trace.blobs[id];
                writer
                    .add_payload(data)
                    .map_err(|err| ToolError::Runtime(format!("cannot carry blob {id}: {err}")))?;
                carried.insert(*id);
            }
        }
        let filtered = EventBatch {
            session_id: batch.session_id,
            process_id: batch.process_id,
            raw_pid: batch.raw_pid,
            thread_id: batch.thread_id,
            qpc_frequency: batch.qpc_frequency,
            events: kept,
        };
        match writer.write_batch(&filtered) {
            Ok(()) => {
                report.batches_written += 1;
                report.recovered += filtered.events.len() as u64;
                if let Some(last) = filtered.events.last() {
                    last_sequence_by_thread.insert(batch.thread_id, last.sequence);
                }
            }
            Err(err) => {
                // 事前検査をすり抜けた Writer 側の拒否。Batch ごと落とし、
                // 理由を issue として残す（推測で補わない）。
                report.batches_skipped += 1;
                add_lost(&mut report, "write_failed", filtered.events.len() as u64);
                report.issues.push(format!(
                    "write_failed(thread={}, reason={err})",
                    batch.thread_id
                ));
            }
        }
    }
    report.blobs_carried = carried.len();
    writer
        .write_loss_records(&trace.loss_records)
        .map_err(|e| ToolError::Runtime(format!("cannot write loss records: {e}")))?;
    report.loss_records = trace.loss_records.len();
    let (capture_coverage, mut event_integrity, semantic_completeness, mut notes) =
        match &trace.finalization {
            Some(f) => (
                f.capture_coverage,
                f.event_integrity,
                f.semantic_completeness,
                f.notes.clone(),
            ),
            None => (3, 3, 3, Vec::new()),
        };
    if report.lost > 0 && event_integrity == 0 {
        event_integrity = 1;
    }
    notes.push(format!(
        "repaired from {}: {} events recovered, {} lost; {} recovery issues",
        input,
        report.recovered,
        report.lost,
        report.issues.len()
    ));
    let bytes = writer
        .finish(FinalizationInfo {
            capture_coverage,
            event_integrity,
            semantic_completeness,
            notes,
        })
        .map_err(|e| ToolError::Runtime(format!("cannot finish repaired trace: {e}")))?;
    Ok((bytes, report))
}

pub(crate) fn repair_lines(report: &RepairReport) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("repaired: {} -> {}", report.input, report.output));
    out.push(format!(
        "events: {} recovered, {} lost (scanned {})",
        report.recovered, report.lost, report.scanned
    ));
    out.push(format!(
        "batches: {} written, {} skipped",
        report.batches_written, report.batches_skipped
    ));
    out.push(format!("blobs: {} carried over", report.blobs_carried));
    let mut schemas = format!("schemas: {} registered", report.schemas_registered);
    if report.schemas_skipped > 0 {
        schemas.push_str(&format!(", {} skipped", report.schemas_skipped));
    }
    out.push(schemas);
    out.push(format!("loss_records: {} preserved", report.loss_records));
    out.push(format!("recovery_issues: {}", report.issues.len()));
    for issue in &report.issues {
        out.push(format!("  - {issue}"));
    }
    if report.lost > 0 {
        out.push("lost_events:".into());
        for (cause, count) in &report.lost_by_cause {
            out.push(format!("  - {cause}: {count}"));
        }
    }
    out
}

pub(crate) fn repair_json(report: &RepairReport) -> JsonValue {
    JsonValue::obj(vec![
        ("input", JsonValue::Str(report.input.clone())),
        ("output", JsonValue::Str(report.output.clone())),
        (
            "events",
            JsonValue::obj(vec![
                ("recovered", JsonValue::U64(report.recovered)),
                ("lost", JsonValue::U64(report.lost)),
                ("scanned", JsonValue::U64(report.scanned)),
            ]),
        ),
        (
            "batches",
            JsonValue::obj(vec![
                ("written", JsonValue::U64(report.batches_written as u64)),
                ("skipped", JsonValue::U64(report.batches_skipped as u64)),
            ]),
        ),
        ("blobs_carried", JsonValue::U64(report.blobs_carried as u64)),
        (
            "schemas",
            JsonValue::obj(vec![
                (
                    "registered",
                    JsonValue::U64(report.schemas_registered as u64),
                ),
                ("skipped", JsonValue::U64(report.schemas_skipped as u64)),
            ]),
        ),
        (
            "loss_records_preserved",
            JsonValue::U64(report.loss_records as u64),
        ),
        (
            "recovery_issues",
            JsonValue::Array(report.issues.iter().cloned().map(JsonValue::Str).collect()),
        ),
        (
            "lost_by_cause",
            JsonValue::Array(
                report
                    .lost_by_cause
                    .iter()
                    .map(|(cause, count)| {
                        JsonValue::obj(vec![
                            ("cause", JsonValue::Str(cause.clone())),
                            ("count", JsonValue::U64(*count)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn cmd_repair(args: &[String]) -> Result<(), ToolError> {
    let parsed = parse_args(args, &["json"])?;
    parsed.validate_options(&["json", "output"])?;
    let (input, trace) = load_trace(&parsed)?;
    let output = match parsed.opt("output") {
        Some(path) => path.to_string(),
        None => format!("{input}.repaired"),
    };
    let mut file = prepare_output(&input, &output)?;
    let (bytes, mut report) = repair_trace(&input, &trace)?;
    file.write_all(&bytes)
        .map_err(|e| ToolError::Runtime(format!("cannot write {output}: {e}")))?;
    file.persist(&output)
        .map_err(|e| ToolError::Runtime(format!("cannot publish repaired trace {output}: {e}")))?;
    report.output = output;
    if parsed.has("json") {
        println!("{}", repair_json(&report).render_pretty());
    } else {
        for line in repair_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod pbt {
    //! repair の性質検査（PBT）。任意の操作列で書いた Trace に任意の破損を
    //! 加え、回復読みできた入力を修復する。
    //!
    //! - 修復結果は issue なしで読め、きれいに終わっている。
    //! - 会計: 回収数 + 損失数 = 走査数、損失の内訳の合計 = 損失数。
    //! - 修復結果のイベントは入力の（空でない）Batch を順に絞り込んだもの。
    //! - 冪等: 修復結果をもう一度修復しても何も失わず、イベントは変わらない。
    //! - イベントを失ったら Complete を宣言しない。
    use super::*;
    use proptest::prelude::*;
    use shirusu_trace::container::HEADER_LEN;
    use shirusu_trace::reader::read_trace;
    use shirusu_trace::schema::{make_schema, EventCapture, Ty};

    #[derive(Debug, Clone)]
    enum Op {
        Payload(Vec<u8>),
        Batch { thread: u64, refs: Vec<usize> },
        Loss(u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            2 => proptest::collection::vec(any::<u8>(), 0..32).prop_map(Op::Payload),
            4 => (1u64..4, proptest::collection::vec(any::<usize>(), 0..5))
                .prop_map(|(thread, refs)| Op::Batch { thread, refs }),
            1 => (1u64..9).prop_map(Op::Loss),
        ]
    }

    fn env() -> CaptureEnvironment {
        CaptureEnvironment {
            session: SessionMetadata {
                session_id: 9,
                created_by: "repair-pbt".into(),
                qpc_frequency: 1000,
            },
            ..Default::default()
        }
    }

    fn write(ops: &[Op], finish: bool, integrity: u32) -> Vec<u8> {
        let mut w = TraceWriter::new(Vec::new(), env()).unwrap();
        w.register_schema(make_schema(
            1,
            "k32!T/enter",
            vec![("x".into(), Ty::U32, 0)],
        ))
        .unwrap();
        let mut blobs: Vec<BlobId> = Vec::new();
        let mut seq: HashMap<u64, u64> = HashMap::new();
        for op in ops {
            match op {
                Op::Payload(d) => blobs.push(w.add_payload(d).unwrap()),
                Op::Batch { thread, refs } => {
                    let events: Vec<TraceEvent> = refs
                        .iter()
                        .map(|r| {
                            let s = seq.entry(*thread).or_insert(0);
                            *s += 1;
                            TraceEvent {
                                kind: 1,
                                sequence: *s,
                                timestamp_qpc: *s,
                                call_id: *s,
                                parent_call_id: 0,
                                api_id: 1,
                                schema_id: 1,
                                capture: EventCapture::Captured,
                                payload: if blobs.is_empty() || r % 3 == 0 {
                                    PayloadRef::Inline(vec![*r as u8])
                                } else {
                                    PayloadRef::Blob(blobs[r % blobs.len()])
                                },
                                args: None,
                                global_order: None,
                            }
                        })
                        .collect();
                    if events.is_empty() {
                        continue;
                    }
                    w.write_batch(&EventBatch {
                        session_id: 9,
                        process_id: 1,
                        raw_pid: 1,
                        thread_id: *thread,
                        qpc_frequency: 1000,
                        events,
                    })
                    .unwrap();
                }
                Op::Loss(n) => w
                    .write_loss_records(&[shirusu_trace::proto::LossRecord {
                        kind: 1,
                        count: *n,
                        ..Default::default()
                    }])
                    .unwrap(),
            }
        }
        let bytes = w
            .finish(FinalizationInfo {
                capture_coverage: 0,
                event_integrity: integrity,
                semantic_completeness: 0,
                notes: Vec::new(),
            })
            .unwrap();
        if finish {
            bytes
        } else {
            // Index と Finalization の 2 Block を落とす（途中で終わった Trace）。
            let mut at = 0;
            let mut offs = Vec::new();
            while at + HEADER_LEN <= bytes.len() {
                offs.push(at);
                let stored =
                    u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
                at += HEADER_LEN + stored;
            }
            let cut = offs[offs.len().saturating_sub(2).max(1)];
            bytes[..cut].to_vec()
        }
    }

    /// 同じスレッドの Sequence を巻き戻した Batch を Block 単位で複製して
    /// 足す破損（sequence_regression の経路）も含める。
    #[derive(Debug, Clone)]
    enum Damage {
        None,
        Flip(usize, u8),
        Truncate(usize),
        DuplicateTail(usize),
    }

    fn damage() -> impl Strategy<Value = Damage> {
        prop_oneof![
            1 => Just(Damage::None),
            3 => (any::<usize>(), 1u8..=255).prop_map(|(a, m)| Damage::Flip(a, m)),
            1 => any::<usize>().prop_map(Damage::Truncate),
            2 => any::<usize>().prop_map(Damage::DuplicateTail),
        ]
    }

    fn apply(mut b: Vec<u8>, d: &Damage) -> Vec<u8> {
        match *d {
            Damage::None => b,
            Damage::Flip(at, m) => {
                let i = at % b.len();
                b[i] ^= m;
                b
            }
            Damage::Truncate(at) => {
                b.truncate(at % (b.len() + 1));
                b
            }
            Damage::DuplicateTail(at) => {
                // Header の後ろの任意の位置から末尾までを複製して足す。
                // Block 境界に当たれば同じ Batch の再提示になる。
                let from = HEADER_LEN + 24 + at % (b.len() - HEADER_LEN - 24 + 1);
                let tail = b[from..].to_vec();
                b.extend_from_slice(&tail);
                b
            }
        }
    }

    fn events(t: &ReadTrace) -> Vec<(u64, TraceEvent)> {
        t.batches
            .iter()
            .flat_map(|b| b.events.iter().map(move |e| (b.thread_id, e.clone())))
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            std::env::var("SHIRUSU_PBT_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256)
        ))]

        #[test]
        fn repair_is_accounted_clean_and_idempotent(
            ops in proptest::collection::vec(op(), 0..20),
            finish in any::<bool>(),
            integrity in 0u32..4,
            d in damage(),
        ) {
            let data = apply(write(&ops, finish, integrity), &d);
            let Ok(input) = read_trace(&data) else { return Ok(()) };
            let (bytes, report) = repair_trace("in", &input).unwrap();
            prop_assert_eq!(report.recovered + report.lost, report.scanned);
            prop_assert_eq!(
                report.lost_by_cause.iter().map(|(_, n)| n).sum::<u64>(),
                report.lost
            );
            let out = read_trace(&bytes).unwrap();
            prop_assert!(out.issues.is_empty(), "{:?}", out.issues);
            prop_assert!(out.finalized_cleanly);
            prop_assert_eq!(out.total_events(), report.recovered);
            prop_assert_eq!(&out.loss_records, &input.loss_records);
            // 出力イベントは入力イベントの部分列（順序を保つ）。
            let src = events(&input);
            let mut it = src.iter();
            for e in events(&out) {
                prop_assert!(it.any(|s| *s == e), "event not from the input in order: {e:?}");
            }
            // 参照する Blob はすべて運ばれている。
            for (_, e) in events(&out) {
                if let PayloadRef::Blob(id) = e.payload {
                    prop_assert!(out.blobs.contains_key(&id));
                }
            }
            let f = out.finalization.as_ref().unwrap();
            if report.lost > 0 {
                prop_assert_ne!(f.event_integrity, 0, "lost events but still Complete");
            }
            // 冪等性。
            let (again, report2) = repair_trace("out", &out).unwrap();
            prop_assert_eq!(report2.lost, 0);
            let out2 = read_trace(&again).unwrap();
            prop_assert_eq!(events(&out2), events(&out));
            prop_assert_eq!(out2.finalization.unwrap().event_integrity, f.event_integrity);
        }
    }

    /// すべての RecoveryIssue に表記があり、報告の行と JSON に載る。
    #[test]
    fn every_issue_variant_is_formatted_and_reported() {
        let id = BlobId::of_content(b"x");
        let issues = vec![
            RecoveryIssue::TruncatedTail { offset: 1 },
            RecoveryIssue::CorruptBlock {
                offset: 2,
                reason: "r".into(),
            },
            RecoveryIssue::Resync { from: 3, to: 4 },
            RecoveryIssue::DuplicateBlob { id },
            RecoveryIssue::BlobHashMismatch { id, computed: id },
            RecoveryIssue::MissingBlob { id },
            RecoveryIssue::ForwardBlobReference { id },
            RecoveryIssue::IndexMismatch,
            RecoveryIssue::LimitExceeded { what: "blobs" },
            RecoveryIssue::SessionMismatch {
                what: "batch",
                expected: 1,
                found: 2,
            },
            RecoveryIssue::BlobUpdateMissingBase { resource_id: id },
            RecoveryIssue::BlobUpdateOutOfRange {
                resource_id: id,
                offset: 5,
                size: 6,
                base_len: 7,
            },
            RecoveryIssue::BlobUpdateHashMismatch {
                resource_id: id,
                expected: id,
                computed: id,
            },
        ];
        let texts: Vec<String> = issues.iter().map(format_issue).collect();
        let mut prefixes: Vec<&str> = texts.iter().map(|t| t.split('(').next().unwrap()).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), issues.len(), "{texts:?}");
        assert_eq!(texts[2], "resync(3..4)");
        assert_eq!(
            texts[11],
            format!("blob_update_out_of_range(resource={id}, offset=5, size=6, base_len=7)")
        );
        let mut report = RepairReport {
            input: "a".into(),
            output: "b".into(),
            issues: texts.clone(),
            ..Default::default()
        };
        add_lost(&mut report, "missing_blob", 2);
        add_lost(&mut report, "write_failed", 1);
        add_lost(&mut report, "missing_blob", 3);
        assert_eq!(report.lost, 6);
        assert_eq!(
            report.lost_by_cause,
            vec![
                ("missing_blob".to_string(), 5),
                ("write_failed".to_string(), 1)
            ]
        );
        report.schemas_skipped = 1;
        let lines = repair_lines(&report);
        assert!(lines.contains(&"schemas: 0 registered, 1 skipped".to_string()));
        assert!(lines.contains(&"  - missing_blob: 5".to_string()));
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("  - ")).count(),
            texts.len() + 2
        );
        let json = repair_json(&report).render_pretty();
        assert!(json.contains("\"write_failed\""), "{json}");
        assert!(json.contains("resync(3..4)"));
    }
}
