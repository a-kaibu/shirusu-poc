//! 回帰バンドルの組み立てと書き出し。
//!
//! バンドル形式 v1（ディレクトリ構成）:
//!
//! ```text
//! <bundle>/
//!   manifest.json        バンドルの素性と生成結果の要約（機械可読）
//!   brief.md             Probe ブリーフ（人間向け）
//!   rules.json           shirusu-test 仕様 v1（識別ルール。生成できなかった場合は存在しない）
//!   left.trimmed.trace   基準側のトリム済み Trace
//!   right.trimmed.trace  被検側のトリム済み Trace
//! ```
//!
//! 形式の正は docs/ippai-integration.md の「回帰バンドル形式」節。
//! ippai 側のテストスイートは、この構成と manifest の形だけに
//! 依存して取り込める。

use crate::brief::{render_brief, BriefContext};
use crate::rules::{generate_rules, spec_to_json, RuleGeneration};
use crate::trim::{trim_trace, verify_trimmed, TrimmedTrace};
use shirusu_analysis::JsonValue;
use shirusu_compare::{Candidate, DiffReport, CANDIDATE_NOTICE};
use shirusu_test::TestSpec;
use shirusu_trace::reader::ReadTrace;
use std::fmt;
use std::path::{Path, PathBuf};

/// バンドル生成のエラー。
#[derive(Debug)]
pub enum ProbeError {
    /// 指定された候補インデックスが比較結果に無い。
    NoSuchCandidate {
        index: usize,
        available: usize,
    },
    /// 生成した rules.json が v1 パーサで読み戻せない（内部不整合）。
    SpecRoundtrip(String),
    Io(std::io::Error),
    Trace(shirusu_trace::error::TraceError),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::NoSuchCandidate { index, available } => {
                write!(
                    f,
                    "candidate index {index} out of range ({available} candidate(s) available)"
                )
            }
            ProbeError::SpecRoundtrip(msg) => {
                write!(f, "generated rules.json does not roundtrip: {msg}")
            }
            ProbeError::Io(e) => write!(f, "io error: {e}"),
            ProbeError::Trace(e) => write!(f, "trace error: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

impl From<std::io::Error> for ProbeError {
    fn from(e: std::io::Error) -> Self {
        ProbeError::Io(e)
    }
}

impl From<shirusu_trace::error::TraceError> for ProbeError {
    fn from(e: shirusu_trace::error::TraceError) -> Self {
        ProbeError::Trace(e)
    }
}

pub type Result<T> = std::result::Result<T, ProbeError>;

/// バンドル生成のオプション。
#[derive(Debug, Clone)]
pub struct BundleOptions {
    /// バンドル名（ディレクトリ名と manifest の name になる）。
    pub name: String,
    /// 基準側（想定: Windows 実機）の表示名。通常はファイル名。
    pub left_label: String,
    /// 被検側（想定: sake）の表示名。
    pub right_label: String,
}

/// 生成済みバンドル（メモリ内表現。書き出しは `write_bundle`）。
#[derive(Debug)]
pub struct ProbeBundle {
    pub name: String,
    pub candidate_index: usize,
    pub brief_md: String,
    pub manifest_json: String,
    /// 識別ルールを含む shirusu-test 仕様。生成できなかった場合は
    /// None で、バンドルは「ブリーフ＋Trace のみ」になる。
    pub rules_json: Option<String>,
    /// Full supported baseline call sequence; Err explains missing prerequisites.
    pub replay: std::result::Result<TestSpec, String>,
    pub rule_generation: RuleGeneration,
    pub left_trimmed: Option<TrimmedTrace>,
    pub right_trimmed: Option<TrimmedTrace>,
    /// トリム後に同じ候補が再現したか。トリムしなかった場合は None。
    pub trim_reproduced: Option<bool>,
}

impl ProbeBundle {
    /// 識別ルールまで揃った完全なバンドルか。
    pub fn has_discriminating_rule(&self) -> bool {
        self.rules_json.is_some()
    }
}

/// 比較結果の 1 候補からバンドルを組み立てる。
pub fn build_bundle(
    left: &ReadTrace,
    right: &ReadTrace,
    report: &DiffReport,
    candidate_index: usize,
    opts: &BundleOptions,
) -> Result<ProbeBundle> {
    let cand: &Candidate =
        report
            .candidates
            .get(candidate_index)
            .ok_or(ProbeError::NoSuchCandidate {
                index: candidate_index,
                available: report.candidates.len(),
            })?;

    // 1. ルール生成（両 Trace で評価して裏付けを取る）。
    let rule_generation = generate_rules(left, right, cand);
    let rules_json = match &rule_generation.spec {
        Some(spec) => {
            let text = spec_to_json(spec);
            // 自分で書いた仕様が v1 パーサで読み戻せ、かつ識別が
            // 保たれることを保証する。なお JSON パーサは正の整数を
            // U64 に正規化するため、構造の完全一致ではなく評価の
            // 一致（左 pass・右 fail）を不変条件とする。
            let parsed = TestSpec::parse(&text).map_err(ProbeError::SpecRoundtrip)?;
            let l = shirusu_test::evaluate(&parsed, left);
            let r = shirusu_test::evaluate(&parsed, right);
            if !l.all_passed() || r.all_passed() {
                return Err(ProbeError::SpecRoundtrip(
                    "roundtripped spec no longer discriminates".into(),
                ));
            }
            Some(text)
        }
        None => None,
    };

    // 2. トリミングと再現確認。
    let left_trimmed = trim_trace(left, cand, "left", &opts.left_label)?;
    let right_trimmed = trim_trace(right, cand, "right", &opts.right_label)?;
    let trim_reproduced = {
        let lt = shirusu_trace::read_trace(&left_trimmed.bytes)?;
        let rt = shirusu_trace::read_trace(&right_trimmed.bytes)?;
        verify_trimmed(&lt, &rt, cand)
    };
    let trim_outcome = (
        left_trimmed.kept_events,
        left_trimmed.total_events,
        right_trimmed.kept_events,
        right_trimmed.total_events,
        trim_reproduced,
    );

    // 3. ブリーフと manifest。
    let brief_md = render_brief(
        left,
        right,
        cand,
        &BriefContext {
            bundle_name: &opts.name,
            left_label: &opts.left_label,
            right_label: &opts.right_label,
            candidate_index,
            rule_generation: &rule_generation,
            trim_outcome: Some(trim_outcome),
        },
    );
    let replay_slice = crate::replay::generate_candidate_replay(left, cand);
    let mut manifest = manifest(opts, cand, &rule_generation, Some(trim_outcome));
    if let JsonValue::Object(ref mut fields) = manifest {
        fields.push((
            "replay_source_capture_coverage".into(),
            left.finalization
                .as_ref()
                .map(|f| JsonValue::U64(u64::from(f.capture_coverage)))
                .unwrap_or(JsonValue::Null),
        ));
        fields.push((
            "replay".into(),
            match &replay_slice {
                Ok(slice) => JsonValue::obj(vec![
                    ("source_steps", JsonValue::U64(slice.source_steps as u64)),
                    ("kept_source_steps", JsonValue::Array(slice.kept_steps.iter().map(|i| JsonValue::U64(*i as u64)).collect())),
                    ("target_source_step", JsonValue::U64(slice.target_source_step as u64)),
                    ("target_replay_step", JsonValue::U64(slice.target_replay_step as u64)),
                    ("execution_verified", JsonValue::Bool(false)),
                    ("minimal", JsonValue::Bool(false)),
                    ("file", JsonValue::Str("replay.json".into())),
                    (
                        "scope",
                        JsonValue::Str(
                            "candidate file dependencies from recorded baseline calls only; all lifetimes retained; run in a fresh scratch directory"
                                .into(),
                        ),
                    ),
                ]),
                Err(reason) => JsonValue::obj(vec![("missing", JsonValue::Str(reason.clone()))]),
            },
        ));
    }
    let replay = replay_slice.map(|slice| slice.spec);
    let manifest_json = manifest.render_pretty();
    Ok(ProbeBundle {
        name: opts.name.clone(),
        candidate_index,
        brief_md,
        manifest_json,
        rules_json,
        replay,
        rule_generation,
        left_trimmed: Some(left_trimmed),
        right_trimmed: Some(right_trimmed),
        trim_reproduced: Some(trim_reproduced),
    })
}

fn manifest(
    opts: &BundleOptions,
    cand: &Candidate,
    rule_generation: &RuleGeneration,
    trim_outcome: Option<(usize, usize, usize, usize, bool)>,
) -> JsonValue {
    let tried: Vec<JsonValue> = rule_generation
        .tried
        .iter()
        .map(|(d, o)| {
            JsonValue::obj(vec![
                ("strategy", JsonValue::Str(d.clone())),
                ("outcome", JsonValue::Str(o.clone())),
            ])
        })
        .collect();
    JsonValue::obj(vec![
        ("format", JsonValue::Str("shirusu-probe-bundle".into())),
        ("version", JsonValue::U64(1)),
        ("name", JsonValue::Str(opts.name.clone())),
        ("generated_by", JsonValue::Str("shirusu-probe".into())),
        ("notice", JsonValue::Str(CANDIDATE_NOTICE.into())),
        (
            "sources",
            JsonValue::obj(vec![
                ("left", JsonValue::Str(opts.left_label.clone())),
                ("right", JsonValue::Str(opts.right_label.clone())),
            ]),
        ),
        (
            "candidate",
            JsonValue::obj(vec![
                ("kind", JsonValue::Str(cand.kind.name().into())),
                ("severity", JsonValue::Str(cand.severity.name().into())),
                ("message", JsonValue::Str(cand.message.clone())),
                (
                    "api",
                    cand.api
                        .clone()
                        .map(JsonValue::Str)
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "object",
                    cand.object
                        .as_ref()
                        .map(|o| JsonValue::Str(o.describe()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "field",
                    cand.field
                        .clone()
                        .map(JsonValue::Str)
                        .unwrap_or(JsonValue::Null),
                ),
            ]),
        ),
        (
            "rules",
            match &rule_generation.spec {
                Some(spec) => JsonValue::obj(vec![
                    ("file", JsonValue::Str("rules.json".into())),
                    ("spec_name", JsonValue::Str(spec.name.clone())),
                    ("discriminating", JsonValue::Bool(true)),
                ]),
                None => JsonValue::Null,
            },
        ),
        (
            "rule_generation",
            JsonValue::obj(vec![("tried", JsonValue::Array(tried))]),
        ),
        (
            "trimmed",
            match trim_outcome {
                Some((lk, lt, rk, rt, reproduced)) => JsonValue::obj(vec![
                    ("left_kept_events", JsonValue::U64(lk as u64)),
                    ("left_total_events", JsonValue::U64(lt as u64)),
                    ("right_kept_events", JsonValue::U64(rk as u64)),
                    ("right_total_events", JsonValue::U64(rt as u64)),
                    ("candidate_reproduced", JsonValue::Bool(reproduced)),
                ]),
                None => JsonValue::Null,
            },
        ),
    ])
}

/// バンドルをディレクトリへ書き出す（無ければ作る）。
/// 戻り値は書き出したファイルのパスの列。
pub fn write_bundle(bundle: &ProbeBundle, dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut written = Vec::new();
    let mut put = |name: &str, bytes: &[u8]| -> Result<()> {
        let path = dir.join(name);
        std::fs::write(&path, bytes)?;
        written.push(path);
        Ok(())
    };
    put("manifest.json", bundle.manifest_json.as_bytes())?;
    put("brief.md", bundle.brief_md.as_bytes())?;
    if let Ok(spec) = &bundle.replay {
        put("replay.json", spec.to_json().render_pretty().as_bytes())?;
    }
    if let Some(rules) = &bundle.rules_json {
        put("rules.json", rules.as_bytes())?;
    }
    if let Some(t) = &bundle.left_trimmed {
        put("left.trimmed.trace", &t.bytes)?;
    }
    if let Some(t) = &bundle.right_trimmed {
        put("right.trimmed.trace", &t.bytes)?;
    }
    // A regenerated bundle must not expose stale optional artifacts.
    for (name, present) in [
        ("replay.json", bundle.replay.is_ok()),
        ("rules.json", bundle.rules_json.is_some()),
        ("left.trimmed.trace", bundle.left_trimmed.is_some()),
        ("right.trimmed.trace", bundle.right_trimmed.is_some()),
    ] {
        if !present {
            match std::fs::remove_file(dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(written)
}
