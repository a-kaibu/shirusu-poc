#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_transport::descriptor::EventDescriptor;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::validate::{decode_payload, KnownConfig};

// Descriptor + Payload の任意入力で、参照範囲と折り返しを検証し範囲外に触らない。
// D57: 受理した Payload が公開 Trace の不変条件（落とした Payload は空、
// それ以外は Descriptor の長さどおりで、折り返しを考慮した領域コピーと
// バイト単位で一致）を満たすかも確かめる。
fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let cfg = RingConfig::new(16, 256);
    let known = KnownConfig::new(cfg, cfg.required_len());
    let Some(desc) = EventDescriptor::from_bytes(&data[..64]) else {
        return;
    };
    let region = vec![0xABu8; 256];
    if let Ok(out) = decode_payload(&desc, &region, &known) {
        if desc.payload_dropped() || desc.payload_len == 0 {
            assert!(out.is_empty());
        } else {
            assert_eq!(out.len(), desc.payload_len as usize);
            let cap = 256usize;
            let start = (desc.payload_position % 256) as usize;
            let len = desc.payload_len as usize;
            let first = core::cmp::min(len, cap - start);
            let mut expected = Vec::with_capacity(len);
            expected.extend_from_slice(&region[start..start + first]);
            expected.extend_from_slice(&region[..len - first]);
            assert_eq!(out, expected);
        }
    }
});
