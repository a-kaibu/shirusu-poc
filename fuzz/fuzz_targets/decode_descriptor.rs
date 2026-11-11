#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_transport::descriptor::EventDescriptor;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::validate::{decode_descriptor, KnownConfig};

// 64 バイトの任意 Descriptor で、不明な Kind や異常な長さを安全に扱う。
// D57: 受理した Descriptor が公開 Trace の不変条件（既知の Kind・
// global_order は無効なセッションで 0・
// 長さ上限・64 バイト像への忠実な再符号化）を満たすかも確かめる。
// R6: 長さ上限は格納長に対するもの。PAYLOAD_DROPPED の payload_len は
// 落とした元の長さであり、容量と比較しない (u32 の範囲内なら受理する)。
fuzz_target!(|data: &[u8]| {
    let cfg = RingConfig::new(64, 4096);
    let known = KnownConfig::new(cfg, cfg.required_len());
    // L11: 入力の先頭ビットで --order=global 有効/無効の両モードを fuzz する。
    let allow_global_order = data.first().map_or(false, |b| b & 1 == 1);
    if let Ok(d) = decode_descriptor(data, &known, allow_global_order) {
        assert!(d.payload_dropped() || d.payload_len <= 4096);
        assert!(allow_global_order || d.global_order == 0);
        assert!(d.kind_enum().is_some());
        assert_ne!(d.kind, 0);
        assert_eq!(EventDescriptor::from_bytes(&d.to_bytes()), Some(d));
    }
});
