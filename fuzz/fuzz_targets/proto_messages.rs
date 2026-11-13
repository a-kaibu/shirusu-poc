#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_trace::blob::BlobUpdate;
use shirusu_trace::container::FileHeader;
use shirusu_trace::module::ModuleClassification;
use shirusu_trace::proto::{
    ApiProfile, BatchHeader, BlockIndex, CaptureEnvironment, FieldDef, Finalization, HookEvidence,
    LossRecord, ProfileSummary, SchemaDef, SchemaSet, SessionMetadata,
};
use shirusu_trace::static_dep::{StaticDependency, StaticImport};

// 任意バイト列を Trace メタデータの各メッセージとして復号する。
// どの型でも panic せず、受理した場合は「再符号化 → 再復号」で同じ値に戻る
// (encode は decode の正規形を出す)。未知フィールドの読み飛ばしと、
// 型ごとの既定値省略・切り詰めが往復で値を変えないことを確かめる。
macro_rules! roundtrip {
    ($data:expr, $($ty:ty),+ $(,)?) => {$(
        if let Ok(m) = <$ty>::decode($data) {
            let again = <$ty>::decode(&m.encode()).expect(concat!(stringify!($ty), ": re-decode failed"));
            assert_eq!(again, m, concat!(stringify!($ty), ": not idempotent"));
        }
    )+};
}

fuzz_target!(|data: &[u8]| {
    roundtrip!(
        data,
        SessionMetadata,
        HookEvidence,
        CaptureEnvironment,
        FieldDef,
        SchemaDef,
        SchemaSet,
        BatchHeader,
        LossRecord,
        BlockIndex,
        ApiProfile,
        ProfileSummary,
        ModuleClassification,
        StaticImport,
        StaticDependency,
    );
    if let Ok((m, _)) = Finalization::decode(data) {
        let (again, cleanly) = Finalization::decode(&m.encode()).expect("Finalization re-decode");
        assert_eq!(again, m);
        assert!(cleanly, "encode always marks a clean finalization");
    }
    if let Some(u) = BlobUpdate::decode(data) {
        assert_eq!(BlobUpdate::decode(&u.encode()), Some(u));
    }
    if let Some(h) = FileHeader::decode(data) {
        assert_eq!(FileHeader::decode(&h.encode()), Some(h));
    }
});
