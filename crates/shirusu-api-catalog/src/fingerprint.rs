//! API Catalog Fingerprint: Agent と Host が同じ API 定義表を使っていることの照合。
//!
//! Host は自分のバイナリの表から Trace の Schema を登録し、Agent DLL は
//! 自分のバイナリの表で値を符号化する。`--dll` で別ビルドの Agent を
//! 指定すると、Bootstrap の版が同じでも表の中身が違い得る。同じ
//! `api_id` / `schema_id` で意味の違うフィールドを持つと、型検査を
//! 通ったまま誤った Trace ができる。そのため初期化時に両者の
//! Fingerprint を照合し、一致しなければ対象を再開する前に拒否する。
//!
//! 入力（この順に BLAKE3 へ流す）:
//! - 形式の版 [`FINGERPRINT_FORMAT`]、内部転送 Codec の版
//!   [`CAPTURE_CODEC_VERSION`]、公開 Schema 形式の版
//! - API 表の各行: api_id、module、function、観測レベル、enter / leave の
//!   Schema ID、内部 API か否か
//! - 全 Schema（API 表・COM・WinRT・コールバック）: schema_id、名前、
//!   各フィールドの名前・型タグ・flags（意味種別・取得タイミング・
//!   LastError の意味条件）
//!
//! 注記（`level_note` / `annotation`）は説明文であり、記録の意味を
//! 変えないため入力に含めない。

use crate::api::{api_table, is_internal_api};

/// Fingerprint 入力の並べ方の版。入力の構成を変えたら上げる。
pub const FINGERPRINT_FORMAT: u32 = 1;
/// Agent → Host の Payload 符号化（Compact Binary の値列。
/// docs/trace-format.md「Compact Binary」）の版。符号化規則を変えたら上げる。
pub const CAPTURE_CODEC_VERSION: u32 = 1;
/// Fingerprint のバイト数（BLAKE3 の全長）。
pub const FINGERPRINT_BYTES: usize = 32;

pub type CatalogFingerprint = [u8; FINGERPRINT_BYTES];

fn put_str(h: &mut blake3::Hasher, s: &str) {
    h.update(&(s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

/// このバイナリに組み込まれた API Catalog の Fingerprint。
pub fn catalog_fingerprint() -> CatalogFingerprint {
    let mut h = blake3::Hasher::new();
    h.update(b"shirusu-api-catalog");
    h.update(&FINGERPRINT_FORMAT.to_le_bytes());
    h.update(&CAPTURE_CODEC_VERSION.to_le_bytes());
    h.update(&shirusu_trace::container::SCHEMA_VERSION.to_le_bytes());
    let apis: Vec<_> = api_table().collect();
    h.update(&(apis.len() as u64).to_le_bytes());
    for api in apis {
        h.update(&api.api_id.to_le_bytes());
        put_str(&mut h, api.module);
        put_str(&mut h, api.function);
        h.update(&[api.level, u8::from(is_internal_api(api.api_id))]);
        h.update(&api.enter_schema_id().to_le_bytes());
        h.update(&api.leave_schema_id().to_le_bytes());
    }
    let schemas = crate::all_trace_schemas();
    h.update(&(schemas.len() as u64).to_le_bytes());
    for schema in &schemas {
        h.update(&schema.schema_id.to_le_bytes());
        put_str(&mut h, &schema.name);
        h.update(&(schema.fields.len() as u64).to_le_bytes());
        for field in &schema.fields {
            put_str(&mut h, &field.name);
            h.update(&field.ty.to_le_bytes());
            h.update(&field.flags.to_le_bytes());
        }
    }
    *h.finalize().as_bytes()
}

/// 表示用の 16 進表記（Trace の capture_config やエラー文に載せる）。
pub fn fingerprint_hex(fp: &CatalogFingerprint) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_nonzero() {
        let a = catalog_fingerprint();
        assert_eq!(a, catalog_fingerprint());
        assert_ne!(a, [0; FINGERPRINT_BYTES]);
        assert_eq!(fingerprint_hex(&a).len(), FINGERPRINT_BYTES * 2);
    }

    #[test]
    fn annotations_do_not_change_the_contract_but_flags_do() {
        // 注記は入力に含めず、flags は含める（意味種別の違いを検出する）。
        let schemas = crate::all_trace_schemas();
        let mut changed = schemas.clone();
        changed[0].annotation.push_str(" (edited)");
        let digest = |s: &[shirusu_trace::proto::SchemaDef]| {
            let mut h = blake3::Hasher::new();
            for schema in s {
                for f in &schema.fields {
                    h.update(&f.flags.to_le_bytes());
                }
            }
            *h.finalize().as_bytes()
        };
        assert_eq!(digest(&schemas), digest(&changed));
        changed[0].fields[0].flags ^= 1;
        assert_ne!(digest(&schemas), digest(&changed));
    }
}
