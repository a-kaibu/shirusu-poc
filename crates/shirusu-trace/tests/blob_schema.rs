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
}
