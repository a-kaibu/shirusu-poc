//! Blob ストアと Schema レジストリの単体テスト。

use shirusu_trace::blob::{BlobId, BlobStore};
use shirusu_trace::schema::{make_schema, schema_content_hash, schema_types, SchemaRegistry, Ty};
use std::path::PathBuf;

fn temp_root(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!(
        "shirusu-trace-test-{tag}-{}-{nanos}",
        std::process::id()
    ));
    p
}

#[test]
fn blob_id_hash_and_hex() {
    let id = BlobId::of_content(b"abc");
    // BLAKE3 のテストベクター照合自体は blake3 クレート側の責務。
    // ここでは ID の決定性と hex 往復を確かめる。
    assert_eq!(id.to_hex().len(), 64);
    let parsed = BlobId::parse_hex(&id.to_hex()).unwrap();
    assert_eq!(parsed, id);
    assert!(BlobId::parse_hex("zz").is_none());
    assert!(BlobId::parse_hex(&"a".repeat(63)).is_none());
    assert!(BlobId::parse_hex(&"g".repeat(64)).is_none());
    assert_eq!(BlobId::of_content(b"abc"), id);
    assert_ne!(BlobId::of_content(b"abd"), id);
    assert_eq!(format!("{id}"), id.to_hex());
}

#[test]
fn blob_store_dedup_and_layout() {
    let root = temp_root("dedup");
    let mut store = BlobStore::open(&root).unwrap();
    let (id1, fresh1) = store.put(b"payload-one").unwrap();
    assert!(fresh1);
    let (id1b, fresh2) = store.put(b"payload-one").unwrap();
    assert_eq!(id1, id1b);
    assert!(!fresh2, "同じ内容は再格納しない");
    let (id2, _) = store.put(b"payload-two").unwrap();
    assert_ne!(id1, id2);
    assert_eq!(store.stored_count(), 2);
    assert!(store.contains(&id1));
    // 配置は <root>/<先頭2hex>/<全体hex>
    let hex = id1.to_hex();
    assert!(root.join(&hex[..2]).join(&hex).is_file());
    assert_eq!(store.get(&id1).unwrap().unwrap(), b"payload-one");
    assert_eq!(store.get_verified(&id2).unwrap().unwrap(), b"payload-two");
    assert_eq!(store.get(&BlobId::of_content(b"absent")).unwrap(), None);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn blob_store_reopen_keeps_dedup() {
    let root = temp_root("reopen");
    {
        let mut store = BlobStore::open(&root).unwrap();
        store.put(b"persisted").unwrap();
    }
    // 再オープンで既存ファイルを走査し、重複排除が効く
    let mut store = BlobStore::open(&root).unwrap();
    assert_eq!(store.stored_count(), 1);
    let (_, fresh) = store.put(b"persisted").unwrap();
    assert!(!fresh);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn blob_store_get_verified_detects_corruption() {
    let root = temp_root("verify");
    let mut store = BlobStore::open(&root).unwrap();
    let (id, _) = store.put(b"integrity").unwrap();
    // ファイルを直接書き換える（書込み途中の不完全ファイルや改竄の模擬）
    let hex = id.to_hex();
    let path = root.join(&hex[..2]).join(&hex);
    std::fs::write(&path, b"tampered!").unwrap();
    // 通常の get はそのまま返すが、get_verified はハッシュ不一致を検出する
    assert_eq!(store.get(&id).unwrap().unwrap(), b"tampered!");
    assert!(matches!(
        store.get_verified(&id),
        Err(shirusu_trace::error::TraceError::BlobHashMismatch)
    ));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn blob_store_empty_content() {
    let root = temp_root("empty");
    let mut store = BlobStore::open(&root).unwrap();
    let (id, fresh) = store.put(b"").unwrap();
    assert!(fresh);
    assert_eq!(id, BlobId::of_content(b""));
    assert_eq!(store.get_verified(&id).unwrap().unwrap(), Vec::<u8>::new());
    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------------
// Schema レジストリ
// ---------------------------------------------------------------------------

#[test]
fn schema_hash_is_deterministic_and_sensitive() {
    let a = make_schema(1, "api!F", vec![("x".into(), Ty::U64, 0)]);
    let b = make_schema(2, "api!F", vec![("x".into(), Ty::U64, 0)]);
    // ハッシュは ID に依存しない（別 Trace 間の同一性判定用）
    assert_eq!(a.content_hash, b.content_hash);
    // 名前・型・フラグ・順序のどれが変わってもハッシュが変わる
    let c = make_schema(1, "api!G", vec![("x".into(), Ty::U64, 0)]);
    assert_ne!(a.content_hash, c.content_hash);
    let d = make_schema(1, "api!F", vec![("x".into(), Ty::U32, 0)]);
    assert_ne!(a.content_hash, d.content_hash);
    let e = make_schema(1, "api!F", vec![("x".into(), Ty::U64, 1)]);
    assert_ne!(a.content_hash, e.content_hash);
    let f = make_schema(
        1,
        "api!F",
        vec![("x".into(), Ty::U64, 0), ("y".into(), Ty::U64, 0)],
    );
    let g = make_schema(
        1,
        "api!F",
        vec![("y".into(), Ty::U64, 0), ("x".into(), Ty::U64, 0)],
    );
    assert_ne!(f.content_hash, g.content_hash);
    assert_eq!(schema_content_hash(&a.name, &a.fields), a.content_hash);
}

#[test]
fn registry_rejects_bad_definitions() {
    let mut reg = SchemaRegistry::new();
    // schema_id 0 は予約
    let zero = make_schema(0, "api", vec![]);
    assert!(reg.register(zero).is_err());
    // content_hash が正規化ハッシュと一致しない
    let mut bad = make_schema(1, "api", vec![]);
    bad.content_hash ^= 1;
    assert!(reg.register(bad).is_err());
    assert!(reg.is_empty());
}

#[test]
fn registry_idempotent_and_redefinition() {
    let mut reg = SchemaRegistry::new();
    let def = make_schema(1, "api", vec![("x".into(), Ty::Bool, 0)]);
    reg.register(def.clone()).unwrap();
    // 同一内容の再登録（Checkpoint の複製）は冪等
    reg.register(def.clone()).unwrap();
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.ids(), &[1]);
    // 同じ ID の異なる内容は拒否
    let other = make_schema(1, "api2", vec![]);
    assert!(reg.register(other).is_err());
    assert_eq!(reg.get(1).unwrap().name, "api");
    assert_eq!(reg.types(1).unwrap(), vec![Ty::Bool]);
    assert_eq!(reg.types_ref(1), Some([Ty::Bool].as_slice()));
    assert!(reg.types_ref(99).is_none());
    assert!(reg.get(99).is_none());
}

#[test]
fn schema_types_unknown_tag() {
    let mut def = make_schema(1, "api", vec![("x".into(), Ty::U64, 0)]);
    assert_eq!(schema_types(&def).unwrap(), vec![Ty::U64]);
    def.fields[0].ty = 42;
    // Schema 自体は読めるが、その Schema での復号は拒否される
    assert_eq!(schema_types(&def), None);
    let mut reg = SchemaRegistry::new();
    // ハッシュは ty を含むため、書き換えた定義は再計算しないと登録できない。
    // 登録自体は「未知タグでも可」が形式仕様。ハッシュを正しく付け直す。
    def.content_hash = schema_content_hash(&def.name, &def.fields);
    reg.register(def).unwrap();
    assert_eq!(reg.types(1), None);
    assert_eq!(reg.types_ref(1), None);
}

// ---- F18: Blob の部分的な更新 ----

#[test]
fn blob_update_encode_decode_roundtrip() {
    use shirusu_trace::blob::BlobUpdate;
    let base = BlobId::of_content(b"0123456789abcdef");
    let new_version = BlobId::of_content(b"01234XXXXXabcdef");
    let u = BlobUpdate {
        resource_id: base,
        new_version_id: new_version,
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    let encoded = u.encode();
    // 32 (resource) + 32 (new version) + 8 (offset) + 4 (size) + 5 (data)
    assert_eq!(encoded.len(), 76 + 5);
    let decoded = BlobUpdate::decode(&encoded).expect("roundtrip decodes");
    assert_eq!(decoded, u);
}

#[test]
fn blob_update_decode_rejects_size_mismatch_and_truncation() {
    use shirusu_trace::blob::BlobUpdate;
    let base = BlobId::of_content(b"0123456789abcdef");
    let new_version = BlobId::of_content(b"01234XXXXXabcdef");
    let u = BlobUpdate {
        resource_id: base,
        new_version_id: new_version,
        offset: 5,
        data: b"XXXXX".to_vec(),
    };
    let mut encoded = u.encode();
    // 宣言サイズと実データ長が食い違う（size 欄を +1 する）
    encoded[72..76].copy_from_slice(&6u32.to_le_bytes());
    assert!(
        BlobUpdate::decode(&encoded).is_none(),
        "size mismatch rejected"
    );
    // 76 バイト未満は切り詰め
    assert!(BlobUpdate::decode(&encoded[..40]).is_none());
    assert!(BlobUpdate::decode(&[]).is_none());
}

#[test]
fn apply_update_to_splices_and_rejects_out_of_range() {
    use shirusu_trace::blob::apply_update_to;
    let base = b"0123456789abcdef";
    assert_eq!(
        apply_update_to(base, 5, b"XXXXX").unwrap(),
        b"01234XXXXXabcdef".to_vec()
    );
    // 先頭と末尾ちょうど
    assert_eq!(
        apply_update_to(base, 0, b"AB").unwrap(),
        b"AB23456789abcdef".to_vec()
    );
    assert_eq!(
        apply_update_to(base, 14, b"XY").unwrap(),
        b"0123456789abcdXY".to_vec()
    );
    // 空の更新は無変更
    assert_eq!(apply_update_to(base, 3, b"").unwrap(), base.to_vec());
    // 範囲外は None（末尾を 1 バイトでも超えると不可）
    assert!(apply_update_to(base, 15, b"XY").is_none());
    assert!(
        apply_update_to(base, 16, b"").is_some(),
        "offset == len with empty data is ok"
    );
    assert!(apply_update_to(base, 17, b"").is_none());
    // u64 オーバーフローする offset も範囲外
    assert!(apply_update_to(base, u64::MAX, b"X").is_none());
}

#[test]
fn blob_store_apply_update_folds_and_dedups() {
    use shirusu_trace::blob::BlobStore;
    let root = temp_root("apply-update");
    let mut store = BlobStore::open(&root).unwrap();
    let base = b"0123456789abcdef";
    let (base_id, is_new) = store.put(base).unwrap();
    assert!(is_new);
    // 未知の基底は None（何も書かない）
    let unknown = BlobId::of_content(b"no such blob here");
    assert_eq!(store.apply_update(&unknown, 0, b"X").unwrap(), None);
    assert_eq!(store.stored_count(), 1);
    // 畳み込み：新版が格納され、ID は畳み込み内容のハッシュ
    let folded = b"01234XXXXXabcdef".to_vec();
    let expected_id = BlobId::of_content(&folded);
    let (new_id, is_new) = store
        .apply_update(&base_id, 5, b"XXXXX")
        .unwrap()
        .expect("base exists");
    assert_eq!(new_id, expected_id);
    assert!(is_new);
    assert_eq!(store.get_verified(&new_id).unwrap().unwrap(), folded);
    // 同じ更新の再適用は重複排除で is_new=false
    let (again_id, is_new) = store
        .apply_update(&base_id, 5, b"XXXXX")
        .unwrap()
        .expect("base exists");
    assert_eq!(again_id, expected_id);
    assert!(!is_new);
    assert_eq!(store.stored_count(), 2);
    // 範囲外はエラー
    assert!(store.apply_update(&base_id, 15, b"XY").is_err());
    let _ = std::fs::remove_dir_all(&root);
}

/// 再オープン時の走査は `<2 文字のディレクトリ>/<64 hex>` だけを既出とする。
/// 長い名前のディレクトリの中身や、root 直下のファイルは数えない。
#[test]
fn blob_store_open_ignores_foreign_layout() {
    let root = temp_root("foreign");
    std::fs::create_dir_all(&root).unwrap();
    let a = BlobId::of_content(b"in a long-named dir");
    let b = BlobId::of_content(b"two-char file at root");
    let c = BlobId::of_content(b"not hex");
    std::fs::create_dir_all(root.join("abc")).unwrap();
    std::fs::write(root.join("abc").join(a.to_hex()), b"x").unwrap();
    // root 直下の 2 文字のファイル（ディレクトリではない）。
    std::fs::write(root.join("zz"), b"x").unwrap();
    std::fs::write(root.join(b.to_hex()), b"x").unwrap();
    let hex = c.to_hex();
    std::fs::create_dir_all(root.join(&hex[..2])).unwrap();
    std::fs::write(root.join(&hex[..2]).join("not-a-blob-id"), b"x").unwrap();
    let store = BlobStore::open(&root).unwrap();
    assert_eq!(store.stored_count(), 0);
    for id in [a, b, c] {
        assert!(!store.contains(&id));
        assert_eq!(store.get(&id).unwrap(), None);
    }
    std::fs::remove_dir_all(&root).ok();
}

/// 既出のファイルが外部で消えたら `get` は None、読めない（ディレクトリに
/// なっている）なら Err を返す。NotFound だけを「無い」と扱う。
#[test]
fn blob_store_get_distinguishes_missing_from_unreadable() {
    let root = temp_root("unreadable");
    let mut store = BlobStore::open(&root).unwrap();
    let (gone, _) = store.put(b"deleted behind the store").unwrap();
    let (dir, _) = store.put(b"replaced by a directory").unwrap();
    let path = |id: &BlobId| {
        let hex = id.to_hex();
        root.join(&hex[..2]).join(hex)
    };
    std::fs::remove_file(path(&gone)).unwrap();
    std::fs::remove_file(path(&dir)).unwrap();
    std::fs::create_dir(path(&dir)).unwrap();
    assert!(store.contains(&gone));
    assert_eq!(store.get(&gone).unwrap(), None);
    assert_eq!(store.get_verified(&gone).unwrap(), None);
    assert!(store.get(&dir).is_err());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn container_size_limits_match_the_format_spec() {
    use shirusu_trace::container::{MAX_RAW_LEN, MAX_STORED_LEN};
    // docs/trace-format.md: stored_len ≤ 512 MiB、raw_len ≤ 256 MiB。
    assert_eq!(MAX_STORED_LEN, 512 << 20);
    assert_eq!(MAX_RAW_LEN, 256 << 20);
}
