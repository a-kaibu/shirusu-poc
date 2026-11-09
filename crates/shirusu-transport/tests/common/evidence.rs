// D53: DST/PBT 失敗証跡の共有モジュール (failure_evidence.rs と
// proptest_ring.rs の両方から #[path] で取り込む。テストは持たない)。
//
// 形式と役割分担の正は failure_evidence.rs のモジュール文書を参照。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// DST の 1 操作。proptest_ring.rs の DstOp と同じ意味論を持ち、証跡 JSON
/// では文字列として保持する (例: "write:40", "host_stop")。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstOp {
    Write(u8),
    Drain,
    AdvanceClock,
    HostStop,
    HostResume,
    DropNotification,
    ThreadEnd,
}

impl DstOp {
    pub fn to_token(self) -> String {
        match self {
            DstOp::Write(n) => format!("write:{n}"),
            DstOp::Drain => "drain".to_string(),
            DstOp::AdvanceClock => "advance_clock".to_string(),
            DstOp::HostStop => "host_stop".to_string(),
            DstOp::HostResume => "host_resume".to_string(),
            DstOp::DropNotification => "drop_notification".to_string(),
            DstOp::ThreadEnd => "thread_end".to_string(),
        }
    }
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "drain" => Some(DstOp::Drain),
            "advance_clock" => Some(DstOp::AdvanceClock),
            "host_stop" => Some(DstOp::HostStop),
            "host_resume" => Some(DstOp::HostResume),
            "drop_notification" => Some(DstOp::DropNotification),
            "thread_end" => Some(DstOp::ThreadEnd),
            _ => token
                .strip_prefix("write:")
                .and_then(|n| n.parse::<u8>().ok())
                .map(DstOp::Write),
        }
    }
    /// 注入故障かどうか (証跡の faults 欄に抽出する対象)。
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            DstOp::HostStop | DstOp::DropNotification | DstOp::ThreadEnd | DstOp::AdvanceClock
        )
    }
}

/// 失敗証跡。verification.md が保存を求める 5 要素 (Seed・リビジョン・
/// テスト構成・操作列・注入故障) を全て持つ。Seed は proptest 側の
/// regressions ファイルが正であり、ここにはその参照名を入れる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureEvidence {
    pub test: String,
    pub revision: String,
    pub seed_reference: String,
    pub config: String,
    pub ops: Vec<DstOp>,
}

impl FailureEvidence {
    /// 注入故障だけを (位置, 種別) で抽出する。
    pub fn faults(&self) -> Vec<(usize, DstOp)> {
        self.ops
            .iter()
            .enumerate()
            .filter(|(_, op)| op.is_fault())
            .map(|(i, op)| (i, *op))
            .collect()
    }

    pub fn to_json(&self) -> String {
        let ops = self
            .ops
            .iter()
            .map(|op| format!("\"{}\"", op.to_token()))
            .collect::<Vec<_>>()
            .join(", ");
        let faults = self
            .faults()
            .iter()
            .map(|(i, op)| format!("{{\"at\": {i}, \"kind\": \"{}\"}}", op.to_token()))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{{\n  \"format\": 1,\n  \"test\": \"{}\",\n  \"revision\": \"{}\",\n  \"seed_reference\": \"{}\",\n  \"config\": \"{}\",\n  \"ops\": [{ops}],\n  \"faults\": [{faults}]\n}}\n",
            json_escape(&self.test),
            json_escape(&self.revision),
            json_escape(&self.seed_reference),
            json_escape(&self.config),
        )
    }

    /// 自分が書いた形式を読むための最小復元。ops 列が完全に復元できる
    /// ことが再実行の前提であり、スカラは存在確認つきで取り出す。
    pub fn from_json(text: &str) -> Option<Self> {
        let test = json_string_field(text, "\"test\"")?;
        let revision = json_string_field(text, "\"revision\"")?;
        let seed_reference = json_string_field(text, "\"seed_reference\"")?;
        let config = json_string_field(text, "\"config\"")?;
        let ops_text = json_array_body(text, "\"ops\"")?;
        let mut ops = Vec::new();
        for token in json_string_elements(ops_text) {
            ops.push(DstOp::from_token(&token)?);
        }
        Some(Self {
            test,
            revision,
            seed_reference,
            config,
            ops,
        })
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json_string_field(text: &str, key: &str) -> Option<String> {
    let at = text.find(key)?;
    let rest = &text[at + key.len()..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    Some(rest[start..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn json_array_body<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let at = text.find(key)?;
    let rest = &text[at + key.len()..];
    let open = rest.find('[')?;
    // 自分が書く形式では配列要素に ']' を含む入れ子は無いので、最初の
    // ']' がその配列の閉じ括弧になる。
    let close = rest[open..].find(']')? + open;
    Some(&rest[open + 1..close])
}

fn json_string_elements(array_body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = array_body;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        match after.find('"') {
            Some(end) => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// 証跡の保存先。環境変数が最優先、無ければ workspace の target 配下
/// (git 管理外。CI では成果物として拾える場所に置く運用は文書側に残す)。
pub fn evidence_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("SHIRUSU_FAILURE_EVIDENCE_DIR") {
        if !dir.is_empty() {
            return std::path::PathBuf::from(dir);
        }
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/shirusu-failure-evidence")
}

/// コードのリビジョン。証跡用なので取得手段を複数持ち、どれも駄目なら
/// "unknown" を返す (証跡の欠落理由にはならない)。
pub fn current_revision() -> String {
    for var in ["SHIRUSU_EVIDENCE_REVISION", "GITHUB_SHA"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// 証跡をファイルへ保存する。ファイル名はテスト名と操作列のハッシュで
/// 決定的に決まる (同じ失敗は同じ場所を指す)。
pub fn save_evidence(
    dir: &std::path::Path,
    evidence: &FailureEvidence,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&evidence.to_json(), &mut hasher);
    let digest = std::hash::Hasher::finish(&hasher);
    let safe_test: String = evidence
        .test
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let path = dir.join(format!("{safe_test}-{digest:016x}.json"));
    std::fs::write(&path, evidence.to_json())?;
    Ok(path)
}

/// 決定的再実行器: 証跡の操作列を、proptest_ring.rs の DST と同じ意味論で
/// 実 Ring へ適用し、受信した sequence の列を返す。再実行でも不変条件
/// (sequence の厳密増加) が壊れていれば Err を返す。これにより、保存した
/// 証跡は「読み物」ではなく再現可能な失敗ケースになる。
pub fn replay_dst(ops: &[DstOp]) -> Result<Vec<u64>, String> {
    let alive = Arc::new(AtomicBool::new(true));
    let alive2 = alive.clone();
    let monitor = HostMonitor::new(move || alive2.load(Ordering::Relaxed));
    let clock = Arc::new(ManualClock::new());
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let wc: Arc<dyn Clock> = clock.clone();
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::from_millis(1),
                ..Default::default()
            },
            wc,
        )
    };
    let mut rd = unsafe { region.reader() };
    let mut received: Vec<u64> = Vec::new();
    let mut call = 0u64;
    let mut thread_ended = false;
    let check = |batch: shirusu_transport::ring::DrainBatch,
                 received: &mut Vec<u64>|
     -> Result<(), String> {
        for e in batch.events {
            if let Some(&last) = received.last() {
                if e.descriptor.sequence <= last {
                    return Err(format!(
                        "sequence not strictly increasing: {last} then {}",
                        e.descriptor.sequence
                    ));
                }
            }
            received.push(e.descriptor.sequence);
        }
        Ok(())
    };
    for op in ops {
        match op {
            DstOp::Write(n) => {
                if thread_ended {
                    continue;
                }
                call += 1;
                if monitor.recording_enabled() {
                    let payload = vec![7u8; *n as usize];
                    w.write(EventInput {
                        kind: EventKind::CallEnter,
                        api_id: 1,
                        schema_id: 2,
                        call_id: call,
                        parent_call_id: 0,
                        payload: &payload,
                        capture_state: CaptureState::Captured,
                    });
                }
            }
            DstOp::Drain => check(rd.drain_all(), &mut received)?,
            DstOp::AdvanceClock => clock.advance(Duration::from_millis(3)),
            DstOp::HostStop => {
                alive.store(false, Ordering::Relaxed);
                monitor.check_on_abnormal_path();
            }
            DstOp::HostResume => {
                alive.store(true, Ordering::Relaxed);
            }
            DstOp::DropNotification => {}
            DstOp::ThreadEnd => {
                thread_ended = true;
            }
        }
    }
    check(rd.drain_all(), &mut received)?;
    Ok(received)
}
