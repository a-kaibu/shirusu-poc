//! Capture Policy と API Catalog の照合（Bootstrap v15）。
//!
//! Capture Policy は Agent がどの API を記録するかを決め、Trace Output
//! Policy（[`RecordMode`] の保存・集計の仕方）とは分ける。`filtered` では
//! 指定 API 以外を Agent が記録せず素通しにするため、範囲外の API は
//! 「観測していない」ことを Trace の Hook Evidence に明示する。保存件数の
//! 減少を、完全な記録の成功と混同しないためである。
//!
//! `full` / `profile` / `detailed` は従来どおり全 API を Agent で記録する
//! （`full` は意図的な間引きをしない。`profile` は Host での集計）。
//! COM / WinRT / コールバックのイベントは API 表に無いため Agent 側の
//! 選択の対象外で、`filtered` でも Host 側の保存段階で落とす。

use crate::trace_convert::RecordMode;
use shirusu_api_catalog::api::{api_table, is_internal_api};
use shirusu_api_catalog::fingerprint::{fingerprint_hex, CatalogFingerprint};
use shirusu_trace::proto::HookEvidence;
use std::collections::BTreeSet;

/// Hook Evidence の `method`: Capture Policy による記録範囲の宣言。
pub const CAPTURE_POLICY_METHOD: &str = "capture-policy";
/// Hook Evidence の `outcome`: Agent が観測していない。
pub const NOT_OBSERVED: &str = "not-observed";
/// Hook Evidence の `reason`: Capture Policy で記録範囲から外した。
pub const EXCLUDED_BY_CAPTURE_POLICY: &str = "excluded-by-capture-policy";

/// Agent へ渡す選択 API 一覧。None は全 API を記録する。
pub fn selected_api_ids(mode: &RecordMode) -> Option<Vec<u32>> {
    match mode {
        RecordMode::Filtered { apis } => Some(apis.iter().copied().collect()),
        RecordMode::Full | RecordMode::Profile | RecordMode::Detailed => None,
    }
}

/// `capture_config` に追記する来歴。
pub fn config_text(mode: &RecordMode, catalog: &CatalogFingerprint) -> String {
    let policy = match selected_api_ids(mode) {
        Some(ids) => format!("agent-selected({})", ids.len()),
        None => "agent-all".into(),
    };
    format!(
        "; capture_policy={policy}; api_catalog={}",
        fingerprint_hex(catalog)
    )
}

/// 選択外の API を「観測していない」と宣言する Hook Evidence。
/// 内部 API（Nt*）は通常モードの Coverage に数えないため含めない。
pub fn excluded_evidence(selected: &BTreeSet<u32>) -> Vec<HookEvidence> {
    api_table()
        .filter(|api| !is_internal_api(api.api_id) && !selected.contains(&api.api_id))
        .map(|api| HookEvidence {
            api_id: api.api_id,
            module: api.module.into(),
            function: api.function.into(),
            method: CAPTURE_POLICY_METHOD.into(),
            outcome: NOT_OBSERVED.into(),
            reason: EXCLUDED_BY_CAPTURE_POLICY.into(),
            scope: "session".into(),
            semantic_level: api.level.into(),
            semantic_detail: api.level_note.into(),
        })
        .collect()
}

/// Agent が書き戻した Fingerprint と Host の Fingerprint を照合する。
pub fn check_catalog(host: &CatalogFingerprint, agent: &CatalogFingerprint) -> Result<(), String> {
    if host == agent {
        Ok(())
    } else {
        Err(format!(
            "agent API catalog {} does not match host API catalog {}; \
             rebuild the agent DLL and host from the same commit",
            fingerprint_hex(agent),
            fingerprint_hex(host)
        ))
    }
}

/// u32 配列のネイティブ順バイト列（同一ビットネス・同一エンディアンの対象プロセスへ書き込む形）。
pub fn encode_ids(ids: &[u32]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_ne_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_api_catalog::api::{API_CLOSE_HANDLE, API_COUNT, API_CREATE_FILE_W};
    use shirusu_api_catalog::fingerprint::catalog_fingerprint;

    #[test]
    fn only_filtered_mode_selects_apis_in_the_agent() {
        let apis: BTreeSet<u32> = [API_CREATE_FILE_W, API_CLOSE_HANDLE].into_iter().collect();
        assert_eq!(
            selected_api_ids(&RecordMode::Filtered { apis }),
            Some(vec![API_CREATE_FILE_W, API_CLOSE_HANDLE])
        );
        for mode in [RecordMode::Full, RecordMode::Profile, RecordMode::Detailed] {
            assert_eq!(selected_api_ids(&mode), None);
        }
    }

    #[test]
    fn excluded_apis_are_declared_not_observed() {
        let selected: BTreeSet<u32> = [API_CREATE_FILE_W].into_iter().collect();
        let evidence = excluded_evidence(&selected);
        assert!(evidence.iter().all(|e| e.api_id != API_CREATE_FILE_W));
        assert!(evidence.iter().any(|e| e.api_id == API_CLOSE_HANDLE));
        assert!(evidence.iter().all(|e| !is_internal_api(e.api_id)));
        assert!(evidence.iter().all(|e| e.method == CAPTURE_POLICY_METHOD
            && e.outcome == NOT_OBSERVED
            && e.reason == EXCLUDED_BY_CAPTURE_POLICY));
        let public = api_table().filter(|a| !is_internal_api(a.api_id)).count();
        assert_eq!(evidence.len(), public - 1);
        assert!(public <= API_COUNT);
    }

    #[test]
    fn catalog_mismatch_names_both_fingerprints() {
        let host = catalog_fingerprint();
        assert!(check_catalog(&host, &host).is_ok());
        let mut agent = host;
        agent[0] ^= 0xff;
        let message = check_catalog(&host, &agent).unwrap_err();
        assert!(message.contains(&fingerprint_hex(&host)));
        assert!(message.contains(&fingerprint_hex(&agent)));
    }

    #[test]
    fn config_text_records_policy_and_catalog() {
        let fp = catalog_fingerprint();
        let text = config_text(&RecordMode::Full, &fp);
        assert!(text.contains("capture_policy=agent-all"));
        assert!(text.contains(&fingerprint_hex(&fp)));
        let apis: BTreeSet<u32> = [API_CREATE_FILE_W].into_iter().collect();
        assert!(config_text(&RecordMode::Filtered { apis }, &fp)
            .contains("capture_policy=agent-selected(1)"));
        assert_eq!(encode_ids(&[1, 2]).len(), 8);
    }
}
