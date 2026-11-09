#![no_main]
use libfuzzer_sys::fuzz_target;

// 任意バイト列を公開 Trace として回復読みする (recover_trace)。
// どんな入力でも panic せず、受理した場合は基本不変条件を満たす:
// Batch 内 sequence は単調非減少、総イベント数は Reader 上限内、
// 全イベントの Payload 解決が安全に行える。
fuzz_target!(|data: &[u8]| {
    if let Ok(trace) = shirusu_trace::recover_trace(data) {
        assert!(trace.total_events() <= 100_000_000);
        assert!(trace.blocks.len() <= 1_000_000);
        for batch in &trace.batches {
            let mut prev: Option<u64> = None;
            for e in &batch.events {
                if let Some(p) = prev {
                    assert!(e.sequence >= p, "sequence must not regress in a batch");
                }
                prev = Some(e.sequence);
                // 欠落 Blob を含め、解決が panic しないこと。
                let _ = trace.resolve_payload(e);
            }
        }
    }
});
