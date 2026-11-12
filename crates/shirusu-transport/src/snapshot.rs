//! 大きなメモリ Snapshot の Fragment 分割。
//! 各 Fragment は個別に公開し、最後に SnapshotComplete を書く。
//! 全部取れたときだけ Captured。途中不足/読取エラーは取得分を残して Truncated / Unreadable。
//! Fragment 取得中に元メモリが書き換わり得るため、同時点性は保証されないことを型で記録する。

use crate::descriptor::{flags, CaptureState, EventKind};
use crate::ring::{EventInput, RingWriter, WriteOutcome};

/// 対象メモリの読み取り源（テストでは故障注入できる）。
pub trait MemorySource {
    fn read_mem(&self, offset: usize, buf: &mut [u8]) -> Result<(), ReadFault>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFault {
    Unreadable,
    LimitExceeded,
}

/// バイト列をそのまま返す源。
pub struct SliceSource<'a>(pub &'a [u8]);
impl MemorySource for SliceSource<'_> {
    fn read_mem(&self, offset: usize, buf: &mut [u8]) -> Result<(), ReadFault> {
        if offset + buf.len() > self.0.len() {
            return Err(ReadFault::Unreadable);
        }
        buf.copy_from_slice(&self.0[offset..offset + buf.len()]);
        Ok(())
    }
}

/// 指定オフセット以降を故障させる源（DST/テスト用）。
pub struct FailAfterSource<'a> {
    pub inner: &'a [u8],
    pub fail_at: usize,
}
impl MemorySource for FailAfterSource<'_> {
    fn read_mem(&self, offset: usize, buf: &mut [u8]) -> Result<(), ReadFault> {
        if offset + buf.len() > self.fail_at {
            return Err(ReadFault::Unreadable);
        }
        SliceSource(self.inner).read_mem(offset, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotOutcome {
    pub state: CaptureState,
    pub fragments_published: usize,
    pub bytes_captured: usize,
    pub total_len: usize,
    /// 常に false: Fragment 取得中の書換えがあり得て、同時点の内容である保証はない。
    pub simultaneity_guaranteed: bool,
    pub complete_marker_published: bool,
}

/// Fragment 数の純粋計算 (Kani の対象)。total_len == 0 または
/// fragment_payload == 0 なら 0。
pub fn fragment_count(total_len: usize, fragment_payload: usize) -> usize {
    if total_len == 0 || fragment_payload == 0 {
        0
    } else {
        total_len.div_ceil(fragment_payload)
    }
}

/// index 番目の Fragment の長さ (Kani の対象)。範囲外 index は 0。
/// 全 Fragment の長さの合計は total_len に一致する。
pub fn fragment_len(total_len: usize, fragment_payload: usize, index: usize) -> usize {
    let offset = index.saturating_mul(fragment_payload);
    if fragment_payload == 0 || offset >= total_len {
        0
    } else {
        core::cmp::min(fragment_payload, total_len - offset)
    }
}

/// Snapshot を Fragment 分割して書く。fragment_payload は Payload Ring 容量以下にする。
pub fn write_snapshot(
    writer: &mut RingWriter,
    source: &dyn MemorySource,
    total_len: usize,
    fragment_payload: usize,
    api_id: u32,
    schema_id: u32,
    call_id: u64,
) -> SnapshotOutcome {
    let mut out = SnapshotOutcome {
        state: CaptureState::Captured,
        fragments_published: 0,
        bytes_captured: 0,
        total_len,
        simultaneity_guaranteed: false,
        complete_marker_published: false,
    };
    if fragment_payload == 0 {
        out.state = CaptureState::Unsupported;
        return out;
    }
    let mut buf = vec![0u8; fragment_payload];
    for index in 0..fragment_count(total_len, fragment_payload) {
        let offset = index * fragment_payload;
        let n = fragment_len(total_len, fragment_payload, index);
        if source.read_mem(offset, &mut buf[..n]).is_err() {
            // 取得済み Fragment は残し、Unreadable で終える（Complete は書かない）
            out.state = CaptureState::MemoryUnreadable;
            return out;
        }
        let input = EventInput {
            kind: EventKind::SnapshotFragment,
            api_id,
            schema_id,
            call_id,
            parent_call_id: 0,
            payload: &buf[..n],
            capture_state: CaptureState::Captured,
            // Snapshot はフックの観測点ではないため全体順序は付かない (L11)。
            global_order: 0,
        };
        match writer.write(input) {
            WriteOutcome::Published { .. } => {
                out.fragments_published += 1;
                out.bytes_captured += n;
            }
            WriteOutcome::PublishedDegraded { .. } | WriteOutcome::Dropped { .. } => {
                // 途中不足: 取得分を残して Truncated で終える
                out.state = CaptureState::Truncated;
                return out;
            }
        }
    }
    let complete = EventInput {
        kind: EventKind::SnapshotComplete,
        api_id,
        schema_id,
        call_id,
        parent_call_id: 0,
        payload: &[],
        capture_state: CaptureState::Captured,
        // Snapshot はフックの観測点ではないため全体順序は付かない (L11)。
        global_order: 0,
    };
    match writer.write(complete) {
        WriteOutcome::Published { .. } => {
            out.complete_marker_published = true;
            out.state = CaptureState::Captured;
        }
        _ => {
            out.state = CaptureState::Truncated;
        }
    }
    out
}

/// Host 側: 受信イベント列から Snapshot を再構成する。
/// Complete が無ければ Truncated として、取得済み Fragment の連結だけを返す。
pub fn reassemble(events: &[crate::ring::ReceivedEvent], call_id: u64) -> (Vec<u8>, CaptureState) {
    let mut data = Vec::new();
    let mut complete = false;
    for e in events {
        if e.descriptor.call_id != call_id {
            continue;
        }
        match e.descriptor.kind_enum() {
            Some(EventKind::SnapshotFragment)
                if e.descriptor.flags & flags::PAYLOAD_DROPPED == 0 =>
            {
                data.extend_from_slice(&e.payload);
            }
            Some(EventKind::SnapshotComplete) => complete = true,
            _ => {}
        }
    }
    (
        data,
        if complete {
            CaptureState::Captured
        } else {
            CaptureState::Truncated
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::layout::RingConfig;
    use crate::ring::{RingReader, SharedRegion, WriterPolicy};
    use std::sync::Arc;

    fn setup(pcap: usize) -> (SharedRegion, RingWriter, RingReader) {
        let cfg = RingConfig::new(64, pcap);
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(ManualClock::new());
        let policy = WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        };
        let w = unsafe { region.writer(policy, clock) };
        let r = unsafe { region.reader() };
        (region, w, r)
    }

    #[test]
    fn large_snapshot_fragments_and_complete() {
        // Payload Ring より大きな Snapshot を Fragment 分割する。Host が並行して回収する
        // 実運用と違い単スレッドのこのテストでは、全 Fragment が入る Payload 容量を使う。
        let (_rg, mut w, mut rd) = setup(8192);
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), 256, 1, 1, 77);
        assert_eq!(out.state, CaptureState::Captured);
        assert!(out.complete_marker_published);
        assert!(!out.simultaneity_guaranteed);
        let batch = rd.drain_all();
        let (joined, state) = reassemble(&batch.events, 77);
        assert_eq!(state, CaptureState::Captured);
        assert_eq!(joined, data);
    }

    #[test]
    fn unreadable_midway_keeps_partial_and_marks_unreadable() {
        let (_rg, mut w, mut rd) = setup(4096);
        let data = vec![7u8; 2000];
        let src = FailAfterSource {
            inner: &data,
            fail_at: 512,
        };
        let out = write_snapshot(&mut w, &src, data.len(), 256, 1, 1, 5);
        assert_eq!(out.state, CaptureState::MemoryUnreadable);
        assert_eq!(out.fragments_published, 2);
        assert!(!out.complete_marker_published);
        let batch = rd.drain_all();
        let (joined, state) = reassemble(&batch.events, 5);
        assert_eq!(state, CaptureState::Truncated);
        assert_eq!(joined.len(), 512);
    }

    #[test]
    fn capacity_shortage_truncates() {
        let (_rg, mut w, _rd) = setup(300); // fragment 256 が 1 つ入る程度
        let data = vec![1u8; 5000];
        let out = write_snapshot(&mut w, &SliceSource(&data), data.len(), 256, 1, 1, 5);
        assert_eq!(out.state, CaptureState::Truncated);
        assert!(out.fragments_published >= 1);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Fragment 分割の境界: count は天井除算で、最後の Fragment は 1..=frag、
    /// 範囲外 index は 0、中間の Fragment は満杯サイズ。
    #[kani::proof]
    fn fragment_partition_properties() {
        let total: usize = kani::any();
        let frag: usize = kani::any();
        kani::assume(total <= 2048);
        kani::assume(frag >= 1 && frag <= 512);
        let count = fragment_count(total, frag);
        if total == 0 {
            assert!(count == 0);
            return;
        }
        assert!(count >= 1);
        assert!((count - 1) * frag < total);
        assert!(count * frag >= total);
        let last = fragment_len(total, frag, count - 1);
        assert!(last >= 1 && last <= frag);
        assert!(fragment_len(total, frag, count) == 0);
        if count >= 2 {
            assert!(fragment_len(total, frag, 0) == frag);
            assert!(fragment_len(total, frag, count - 2) == frag);
        }
    }

    /// fragment_payload = 0 は常に count 0 / len 0。
    #[kani::proof]
    fn fragment_zero_payload_is_empty() {
        let total: usize = kani::any();
        kani::assume(total <= 2048);
        assert!(fragment_count(total, 0) == 0);
        assert!(fragment_len(total, 0, 0) == 0);
    }
}
