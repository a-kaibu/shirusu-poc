//! R6 回帰 (レビュー指摘): writer の degrade / 取得失敗経路は PAYLOAD_DROPPED
//! フラグ付きで Descriptor の payload_len に「落とした元の長さ」を格納する。
//! しかし decode_descriptor はフラグ無関係に payload_len > 容量を
//! PayloadTooLarge で拒否していたため、正規の劣化イベント (例: 1MiB Ring
//! で 2MiB Payload を落としたイベント) が破損扱いになっていた。
//! decode_descriptor_checked も decode_descriptor を先に呼ぶため同じ誤拒否
//! をしていた。
//!
//! 修正後の契約: dropped の格納長は 0 として検証し、元の長さは容量と
//! 比較しない。元の長さの受理上限は MAX_DROPPED_ORIGINAL_LEN
//! (= u32 の表現最大値。writer は u32 へ飽和させて格納する)。

use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::{flags, EventDescriptor, EventKind};
use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
use shirusu_transport::validate::{
    decode_descriptor, decode_descriptor_checked, DescriptorExpectation, KnownConfig,
    ValidatingReader,
};
use shirusu_transport::{CaptureState, Clock, RingConfig};
use std::sync::Arc;

fn known(desc: usize, pay: usize) -> KnownConfig {
    let cfg = RingConfig::new(desc, pay);
    KnownConfig::new(cfg, cfg.required_len())
}

#[test]
fn dropped_descriptor_with_original_len_above_capacity_is_accepted() {
    // 1MiB の Ring で 2MiB の Payload を落とした正規の劣化イベント。
    let mut d = EventDescriptor::new(EventKind::CallEnter, 1);
    d.flags = flags::PAYLOAD_DROPPED | flags::DROPPED_BY_BACKPRESSURE;
    d.payload_len = 2 * 1024 * 1024;
    let got = decode_descriptor(&d.to_bytes(), &known(16, 1024 * 1024), false)
        .expect("legit degraded event must be accepted");
    assert_eq!(got.payload_len, 2 * 1024 * 1024);
    assert!(got.payload_dropped());
    // 上限は u32 の表現最大値: それ自体は受理する。
    let mut d2 = EventDescriptor::new(EventKind::CallEnter, 1);
    d2.flags = flags::PAYLOAD_DROPPED;
    d2.payload_len = u32::MAX;
    assert!(decode_descriptor(&d2.to_bytes(), &known(16, 256), false).is_ok());
    // checked でも同じく受理し、格納長 0 として位置を扱う。
    let exp = DescriptorExpectation {
        sequence_at_least: 1,
        payload_position: Some(0),
        payload_write_position: 0,
    };
    assert!(decode_descriptor_checked(&d.to_bytes(), &known(16, 1024 * 1024), &exp, false).is_ok());
}

#[test]
fn writer_degraded_event_above_capacity_passes_validating_reader() {
    // 書き手が実際に作る劣化イベント: 容量 256 の Ring に 512 バイトの
    // Payload を取得失敗 (MemoryUnreadable) として記録すると、Descriptor
    // には元の長さ 512 と PAYLOAD_DROPPED が入る。これが検証を通ること。
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
    let big = vec![7u8; 512];
    w.write(EventInput {
        kind: EventKind::CallEnter,
        api_id: 1,
        schema_id: 1,
        call_id: 1,
        parent_call_id: 0,
        payload: &big,
        capture_state: CaptureState::MemoryUnreadable,
        global_order: 0,
    });
    w.write(EventInput {
        kind: EventKind::CallLeave,
        api_id: 1,
        schema_id: 1,
        call_id: 1,
        parent_call_id: 0,
        payload: b"ok",
        capture_state: CaptureState::Captured,
        global_order: 0,
    });
    let mut vr = ValidatingReader::new(known(8, 256), 1);
    let evs = vr
        .drain_image(region.as_slice())
        .expect("degraded events must validate");
    assert_eq!(evs.len(), 2);
    assert!(evs[0].descriptor.payload_dropped());
    assert_eq!(evs[0].descriptor.payload_len, 512);
    assert!(
        evs[0].payload.is_empty(),
        "dropped payload has no stored bytes"
    );
    assert_eq!(evs[1].payload, b"ok");
    assert!(!vr.is_stopped());
}
