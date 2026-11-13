//! shirusu API Catalog: Capture（Agent）と Host が共有するデータ契約。
//!
//! API ID、Schema ID、フィールドの型・順序・意味種別・取得タイミング、
//! LastError の意味条件を一か所に置く。`shirusu-hook` はこの表で
//! Capture し、`shirusu-host` は同じ表で Trace の Schema を登録する。
//! `shirusu-metadata-gen` は `api_generated.inc` を生成する。
//!
//! 異なるビルドの Agent と Host が同じ表を使っていることは
//! [`fingerprint::catalog_fingerprint`] で照合する。

pub mod api;
pub mod callback;
pub mod com;
pub mod fingerprint;
pub mod winrt;

use shirusu_trace::proto::SchemaDef;

/// 全 Schema（API 表の全階層・COM・WinRT・コールバック）。登録順は
/// Fingerprint の入力順でもある。
pub fn all_trace_schemas() -> Vec<SchemaDef> {
    let mut schemas = api::all_schemas();
    schemas.extend(com::com_schemas());
    schemas.extend(winrt::winrt_schemas());
    schemas.extend(callback::callback_schemas());
    schemas
}

/// Host がセッション開始時に登録する Schema。IAT のみの broad 階層は
/// イベントが最初に使った時点で [`api::broad_schema`] から登録する。
pub fn eager_trace_schemas() -> Vec<SchemaDef> {
    let mut schemas = api::eager_schemas();
    schemas.extend(com::com_schemas());
    schemas.extend(winrt::winrt_schemas());
    schemas.extend(callback::callback_schemas());
    schemas
}

#[cfg(test)]
mod tests {
    use shirusu_trace::schema::ValueKind;

    /// 共有 Schema の意味契約: 全フィールドが意味種別（CreatedObject /
    /// Handle / Pointer / Scalar）を明示する。型からの推定は旧 Trace の
    /// 互換のためだけに残し、新しい Schema へは持ち込まない。
    #[test]
    fn every_catalog_field_declares_its_value_kind() {
        let mut unspecified = Vec::new();
        for schema in super::all_trace_schemas() {
            for field in &schema.fields {
                if ValueKind::from_flags(field.flags) == ValueKind::Unspecified {
                    unspecified.push(format!("{}.{}", schema.name, field.name));
                }
            }
        }
        assert!(unspecified.is_empty(), "unspecified: {unspecified:?}");
    }
}
