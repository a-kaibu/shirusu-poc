#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::validate::{validate_control, KnownConfig};

// Cursor・容量・Generation の任意入力で、受理した占有量が容量を超えないことを確かめる。
// D57: 受理した像が公開 Trace の不変条件（占有量上限・前後像の単調性）を満たすかも確かめる。
// 入力形式: [前像 256 バイト][後像 256 バイト]（256 バイトだけでも単発像として使う）。
fuzz_target!(|data: &[u8]| {
    if data.len() < 256 {
        return;
    }
    let cfg = RingConfig::new(64, 4096);
    let known = KnownConfig::new(cfg, cfg.required_len());
    // 単発像: 受理した占有量は Descriptor・Payload 両 Ring の容量を超えない。
    if let Ok(snap) = validate_control(&data[..256], &known, None) {
        assert!(snap.write_cursor >= snap.read_cursor);
        assert!(snap.write_cursor - snap.read_cursor <= 64);
        assert!(snap.payload_write_position >= snap.payload_read_position);
        assert!(snap.payload_write_position - snap.payload_read_position <= 4096);
    }
    // 2 像: 前像・後像が両方受理され、後像が前像の後継として受理されるなら、
    // Cursor・Payload 位置・Loss カウンタは単調でなければならない。
    if data.len() < 512 {
        return;
    }
    if let Ok(prev) = validate_control(&data[..256], &known, None) {
        if let Ok(cur) = validate_control(&data[256..512], &known, Some(&prev)) {
            assert!(cur.write_cursor >= prev.write_cursor);
            assert!(cur.read_cursor >= prev.read_cursor);
            assert!(cur.payload_write_position >= prev.payload_write_position);
            assert!(cur.payload_read_position >= prev.payload_read_position);
            assert!(cur.loss.diff_since(&prev.loss).is_some());
        }
    }
});
