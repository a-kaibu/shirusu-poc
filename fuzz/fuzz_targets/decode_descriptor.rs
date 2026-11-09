#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_transport::descriptor::EventDescriptor;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::validate::{decode_descriptor, KnownConfig};

// 64 バイトの任意 Descriptor で、不明な Kind や異常な長さを安全に扱う。
// D57: 受理した Descriptor が公開 Trace の不変条件（既知の Kind・reserved 0・
// 長さ上限・64 バイト像への忠実な再符号化）を満たすかも確かめる。
fuzz_target!(|data: &[u8]| {
    let cfg = RingConfig::new(64, 4096);
    let known = KnownConfig::new(cfg, cfg.required_len());
    if let Ok(d) = decode_descriptor(data, &known) {
        assert!(d.payload_len <= 4096);
        assert!(d.reserved == 0);
        assert!(d.kind_enum().is_some());
        assert_ne!(d.kind, 0);
        assert_eq!(EventDescriptor::from_bytes(&d.to_bytes()), Some(d));
    }
});
