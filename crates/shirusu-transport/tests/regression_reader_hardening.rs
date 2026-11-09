//! レビュー第2回・項目5 (後半) の回帰: `RingReader::drain` の多層防御。
//!
//! 本番経路は検証付き (`ValidatingReader`) に統一済みで `RingReader` は
//! テスト専用/信頼済み内部用に格下げされているが、直接呼ばれた場合でも
//! 破損 Descriptor の `payload_len` / `payload_position` を信頼して範囲外
//! コピーをしてはならない。drain はコピー前に ValidatingReader と同等の
//! 最低限の検証を行い、失敗したらその Ring の破損として報告し、それ以上
//! Cursor を進めない。

use std::sync::Arc;

use shirusu_transport::clock::ManualClock;
use shirusu_transport::descriptor::EventDescriptor;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{EventInput, RingReader, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::validate::IntegrityError;
use shirusu_transport::{CaptureState, Clock, EventKind};

fn setup(desc_cap: usize, pay_cap: usize) -> (SharedRegion, RingWriter, RingReader) {
    let cfg = RingConfig::new(desc_cap, pay_cap);
    let region = SharedRegion::new(cfg, 1, 100);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let w = unsafe { region.writer(WriterPolicy::default(), clock) };
    let r = unsafe { region.reader() };
    (region, w, r)
}

fn input(call: u64, payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 10,
        schema_id: 20,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
    }
}

/// 確定済み Descriptor のバイト列を直接書き換える (破損した共有メモリの再現)。
fn tamper(region: &SharedRegion, cursor: u64, f: impl Fn(&mut EventDescriptor)) {
    let cfg = region.config;
    let slot = (cursor % cfg.descriptor_capacity as u64) as usize;
    let off = cfg.descriptors_offset() + slot * 64;
    let base = region.base();
    let mut bytes = [0u8; 64];
    unsafe { std::ptr::copy_nonoverlapping(base.add(off), bytes.as_mut_ptr(), 64) };
    let mut d = EventDescriptor::from_bytes(&bytes).expect("descriptor bytes");
    f(&mut d);
    let out = d.to_bytes();
    unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), base.add(off), 64) };
}

#[test]
fn drain_rejects_payload_len_above_capacity() {
    let (region, mut w, mut rd) = setup(8, 256);
    w.write(input(1, b"hello"));
    // 容量 256 を超える長さを申告する破損 Descriptor。旧 drain はこの長さで
    // copy_payload_read を呼び、Payload 領域を越えて読む可能性があった。
    tamper(&region, 0, |d| d.payload_len = 300);
    let b = rd.drain_all();
    assert!(b.events.is_empty(), "破損 Descriptor はイベント化しない");
    assert_eq!(
        b.integrity_error,
        Some(IntegrityError::PayloadTooLarge {
            len: 300,
            capacity: 256
        })
    );
    assert_eq!(rd.read_cursor(), 0, "破損した先は Cursor を進めない");
    // Ring は破損として停止したままになる (再試行しても素通りしない)。
    let b2 = rd.drain_all();
    assert!(b2.events.is_empty());
    assert_eq!(b2.integrity_error, b.integrity_error);
}

#[test]
fn drain_rejects_payload_position_out_of_range() {
    let (region, mut w, mut rd) = setup(8, 256);
    w.write(input(1, b"hello"));
    // 書込み済み範囲 (payload_write_position = 5) をはるかに超える位置。
    tamper(&region, 0, |d| d.payload_position = 1_000_000);
    let b = rd.drain_all();
    assert!(b.events.is_empty());
    assert_eq!(
        b.integrity_error,
        Some(IntegrityError::PayloadPositionOutOfRange {
            position: 1_000_000,
            end: 1_000_005,
            write_position: 5
        })
    );
    assert_eq!(rd.read_cursor(), 0);
}

#[test]
fn drain_rejects_noncontiguous_second_position() {
    let (region, mut w, mut rd) = setup(8, 256);
    w.write(input(1, b"hello")); // position 0..5
    w.write(input(2, b"abc")); // position 5..8
                               // 2 件目の位置をずらす: 終端は書込み済み範囲に収まるが、前件の終端 5 と
                               // 連続しない (範囲検査ではなく連続性検査で捕まえるケース)。
    tamper(&region, 1, |d| d.payload_position = 2);
    let b = rd.drain_all();
    assert_eq!(b.events.len(), 1, "検証が通った分だけは取り出す");
    assert_eq!(b.events[0].payload, b"hello");
    assert_eq!(
        b.integrity_error,
        Some(IntegrityError::PayloadPositionNotContiguous {
            expected: 5,
            found: 2
        })
    );
    assert_eq!(rd.read_cursor(), 1, "破損した Descriptor の先は進めない");
}

#[test]
fn well_formed_stream_still_drains_without_error() {
    let (_region, mut w, mut rd) = setup(8, 256);
    w.write(input(1, b"hello"));
    // 落とした Payload (格納長 0 として扱う) を含む正常系。
    let dropped = EventInput {
        capture_state: CaptureState::DroppedByBackpressure,
        ..input(2, b"zzzz")
    };
    w.write(dropped);
    w.write(input(3, b"abc"));
    let b = rd.drain_all();
    assert_eq!(b.integrity_error, None);
    assert_eq!(b.events.len(), 3);
    assert_eq!(b.events[0].payload, b"hello");
    assert!(b.events[1].payload.is_empty());
    assert_eq!(b.events[2].payload, b"abc");
    assert_eq!(rd.read_cursor(), 3);
}
