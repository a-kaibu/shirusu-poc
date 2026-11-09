#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_transport::clock::ManualClock;
use shirusu_transport::layout::RingConfig;
use shirusu_transport::ring::{SharedRegion, WriterPolicy};
use shirusu_transport::snapshot::{reassemble, write_snapshot, FailAfterSource, SliceSource};
use shirusu_transport::{CaptureState, Clock};
use std::sync::Arc;
use std::time::Duration;

// Snapshot Fragment 列: 任意データを任意の断片サイズで書き、再構成する。
// 正常系は完全一致、故障注入と容量不足では接頭辞だけが残ることを確かめる。
// 入力形式: [断片サイズ決定バイト][モードバイト][対象データ...]
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let frag = (data[0] as usize % 64) + 1;
    let mode = data[1] % 3;
    let payload = &data[2..];
    let cfg = RingConfig::new(512, 32768);
    let region = SharedRegion::new(cfg, 1, 1);
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
    let mut w = unsafe {
        region.writer(
            WriterPolicy {
                max_wait: Duration::ZERO,
                ..Default::default()
            },
            clock,
        )
    };
    let mut rd = unsafe { region.reader() };
    let out = match mode {
        0 => write_snapshot(&mut w, &SliceSource(payload), payload.len(), frag, 1, 1, 7),
        f => {
            let fail_at = ((f as usize) * 977) % (payload.len() + 1);
            write_snapshot(
                &mut w,
                &FailAfterSource {
                    inner: payload,
                    fail_at,
                },
                payload.len(),
                frag,
                1,
                1,
                7,
            )
        }
    };
    let batch = rd.drain_all();
    let (joined, state) = reassemble(&batch.events, 7);
    match out.state {
        CaptureState::Captured => {
            assert_eq!(state, CaptureState::Captured);
            assert_eq!(joined, payload);
        }
        CaptureState::MemoryUnreadable => {
            assert!(payload.starts_with(&joined));
            assert_eq!(state, CaptureState::Truncated);
        }
        CaptureState::Truncated => {
            assert!(payload.starts_with(&joined));
        }
        _ => {}
    }
});
