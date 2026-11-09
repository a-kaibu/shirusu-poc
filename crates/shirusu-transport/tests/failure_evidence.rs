//! D53: DST/PBT 失敗時の証跡保存と、縮小ケースの回帰テスト化の実働部分。
//!
//! verification.md の取り決め: 「失敗時には、Seed、コードのリビジョン、
//! テスト構成、実際に選ばれた操作列と注入した故障を保存し、縮小したものを
//! 回帰テストに加える」。
//!
//! 役割分担:
//! - 縮小と Seed の保存は proptest 既定の failure persistence
//!   (`*.proptest-regressions`) が担う。実績として host の recorder PBT で
//!   実際に 1 件保存され、毎回再実行されている。
//! - 証跡の形式・保存・決定的再実行は common/evidence.rs が担い、本ファイル
//!   はその常時検証 (往復・必須フィールド・縮小ケースの回帰) を持つ。
//!   DST 本体 (proptest_ring.rs の dst_fault_mix_invariants) は失敗時に
//!   同じ形式で証跡を evidence_dir() へ保存する。
//! - 縮小済みケースは本ファイルに固定し、回帰テストとして常時実行する
//!   (shrunk_dst_case_replays_clean)。
//! - Fuzz の最小入力は fuzz/seeds/**/*.hex へ書き戻す運用 (fuzz/README.md)
//!   で、検証で実際に踏んだ入力はそちらに残る。例: D57 で validate_control
//!   が見つけた Payload 位置後退の受理は、回帰テスト
//!   (validate.rs の validate_control_rejects_payload_position_regression と
//!   matrix_validate の vc_prev_payload_* ケース) として固定済み。
//! - loom の失敗スケジュールは、旧順序モデルを should_panic で固定する形で
//!   回帰化する (shirusu-loom-tests の loom_slot_reclaim_old_order_is_detected)。

#[path = "common/evidence.rs"]
mod evidence;

use evidence::*;

fn sample_evidence() -> FailureEvidence {
    FailureEvidence {
        test: "dst_fault_mix_invariants".to_string(),
        revision: "0123456789abcdef".to_string(),
        seed_reference: "proptest-regressions (dst_fault_mix_invariants)".to_string(),
        config: "cases=512 desc=8 payload=256 max_wait_ms=1".to_string(),
        ops: vec![
            DstOp::Write(4),
            DstOp::HostStop,
            DstOp::Write(40),
            DstOp::HostResume,
            DstOp::Drain,
            DstOp::AdvanceClock,
            DstOp::DropNotification,
            DstOp::ThreadEnd,
            DstOp::Write(4),
        ],
    }
}

#[test]
fn evidence_json_roundtrip_restores_everything() {
    let ev = sample_evidence();
    let restored = FailureEvidence::from_json(&ev.to_json()).expect("roundtrip parses");
    assert_eq!(restored, ev);
    assert_eq!(restored.faults(), ev.faults());
}

#[test]
fn evidence_faults_extract_only_fault_ops_with_positions() {
    let ev = sample_evidence();
    let faults = ev.faults();
    assert_eq!(
        faults,
        vec![
            (1, DstOp::HostStop),
            (5, DstOp::AdvanceClock),
            (6, DstOp::DropNotification),
            (7, DstOp::ThreadEnd),
        ]
    );
}

#[test]
fn evidence_save_writes_all_required_fields() {
    let dir = std::env::temp_dir().join(format!("shirusu-evidence-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ev = sample_evidence();
    let path = save_evidence(&dir, &ev).expect("save");
    let text = std::fs::read_to_string(&path).expect("read back");
    for field in [
        "\"test\"",
        "\"revision\"",
        "\"seed_reference\"",
        "\"config\"",
        "\"ops\"",
        "\"faults\"",
    ] {
        assert!(
            text.contains(field),
            "evidence is missing field {field}:\n{text}"
        );
    }
    // 保存した証跡はそのまま復元・再実行できる
    let restored = FailureEvidence::from_json(&text).expect("parse saved evidence");
    assert_eq!(restored.ops, ev.ops);
    assert!(replay_dst(&restored.ops).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn revision_resolution_always_returns_nonempty() {
    assert!(!current_revision().is_empty());
}

#[test]
fn evidence_dir_honors_env_override() {
    // 既定先は CARGO_MANIFEST_DIR 基準の target 配下、環境変数があれば
    // そちらが優先される (CI で成果物の置き場所を指定する経路)。
    let default_dir = evidence_dir();
    assert!(default_dir.ends_with("shirusu-failure-evidence"));
    // SAFETY: このテストは evidence_dir を読む唯一のテストであり、
    // 並行する他のテストは環境変数を参照しない。
    unsafe { std::env::set_var("SHIRUSU_FAILURE_EVIDENCE_DIR", "/tmp/shirusu-evidence-x") };
    assert_eq!(
        evidence_dir(),
        std::path::PathBuf::from("/tmp/shirusu-evidence-x")
    );
    unsafe { std::env::remove_var("SHIRUSU_FAILURE_EVIDENCE_DIR") };
}

/// 縮小済み回帰ケース: Host 停止・再開・時計進行・通知欠落・スレッド終了を
/// 含む最小の DST 列。証跡形式で固定し、再実行で不変条件が成り立つことを
/// 常時確認する (D53 の「縮小したものを回帰テストに加える」の実例)。
#[test]
fn shrunk_dst_case_replays_clean() {
    let ops = vec![
        DstOp::Write(4),
        DstOp::Write(40),
        DstOp::HostStop,
        DstOp::Write(4), // Host 停止中は記録されない
        DstOp::HostResume,
        DstOp::AdvanceClock,
        DstOp::DropNotification,
        DstOp::Drain,
        DstOp::ThreadEnd,
        DstOp::Write(4), // スレッド終了後は書かない
    ];
    let received = replay_dst(&ops).expect("shrunk case must satisfy invariants");
    // 書けたのは停止前 2 件分のみ (停止中の書込は記録されず、再開後も
    // HostMonitor の確定した停止判定は戻らない)
    assert_eq!(received, vec![1, 2]);
}

/// もう 1 つの回帰ケース: 小さい Ring での溢れを含む列でも、順序の
/// 不変条件は保たれ、欠落は sequence の欠番として観測できる。
#[test]
fn shrunk_overflow_case_replays_with_gaps_only() {
    let mut ops: Vec<DstOp> = (0..40).map(|_| DstOp::Write(40)).collect();
    ops.push(DstOp::Drain);
    let received = replay_dst(&ops).expect("overflow replay must satisfy invariants");
    assert!(!received.is_empty());
    assert!(
        received.len() < 40,
        "overflow must actually drop some events"
    );
    assert!(
        received.windows(2).all(|w| w[1] > w[0]),
        "received sequences stay strictly increasing"
    );
}
