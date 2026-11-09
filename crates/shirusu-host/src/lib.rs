//! shirusu-host: 読み手側。Ring 毎に単一 Drain Worker 前提の取出し、検証、Loss Event 生成、
//! Enter/Leave 対応付けと終了不明判定、スレッド終了確認後の Slot 解放、完全性報告。

use shirusu_transport::descriptor::EventKind;
use shirusu_transport::layout::LossCounters;
use shirusu_transport::ring::{DrainBatch, ReceivedEvent, RingReader, SharedRegion};
use shirusu_transport::slot::{SlotHandle, SlotPool};
use shirusu_transport::validate::{IntegrityError, KnownConfig, ValidatingReader};
use shirusu_transport_win::{notify_space_if_writer_waiting, RingNotify};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

/// Host が生成する Loss Event（公開 Trace の Loss Event に対応する transport 表現）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossEvent {
    /// Sequence 欠番で検出した欠落。
    SequenceGap { count: u64 },
    /// Loss カウンタの差分で検出した欠落。
    Counters {
        dropped_events: u64,
        dropped_payload_bytes: u64,
        degraded_events: u64,
    },
    /// Enter はあるが Leave が欠落し、終了不明になった呼出。
    UnknownTermination { call_id: u64 },
    /// 共有メモリの矛盾で Ring を停止した。
    IntegrityLost { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityLevel {
    Complete,
    Degraded,
    Lost,
    /// 完全性を確定できない。Host が Finalization なしに終了した場合など、
    /// 欠落が無かったのか情報が失われたのか区別がつかない状態。
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    pub capture_coverage: IntegrityLevel,
    pub event_integrity: IntegrityLevel,
    pub semantic_completeness: IntegrityLevel,
    /// Host が正常に Finalization して閉じたか。false なら完全性は不確定。
    pub finalized: bool,
    pub notes: Vec<String>,
}
impl Default for IntegrityReport {
    fn default() -> Self {
        Self {
            capture_coverage: IntegrityLevel::Complete,
            event_integrity: IntegrityLevel::Complete,
            semantic_completeness: IntegrityLevel::Complete,
            finalized: true,
            notes: Vec::new(),
        }
    }
}
impl IntegrityReport {
    /// Host が Finalization なしに終了したことを記録する。仕様: Finalization が
    /// 無い Trace は完全性を確定できないものとして扱う。既に判明している
    /// 欠落（Degraded/Lost）はそのまま残し、Complete だった項目だけ Unknown にする。
    pub fn mark_unfinalized(&mut self) {
        self.finalized = false;
        if self.event_integrity == IntegrityLevel::Complete {
            self.event_integrity = IntegrityLevel::Unknown;
        }
        self.notes
            .push("host ended without finalization; completeness cannot be determined".into());
    }
}

/// Ring 1 本分の Drain Worker。単一読み手を前提とし、複数 Worker で同じ Ring を扱わない。
pub struct DrainWorker {
    reader: RingReader,
    prev_loss: LossCounters,
    open_calls: HashMap<u64, u64>, // call_id -> enter sequence
    closed_calls: HashSet<u64>,
    pub loss_events: Vec<LossEvent>,
    pub unknown_terminations: Vec<u64>,
    pub total_events: u64,
    degraded_seen: u64,
}
impl DrainWorker {
    pub fn new(reader: RingReader) -> Self {
        Self {
            reader,
            prev_loss: LossCounters::default(),
            open_calls: HashMap::new(),
            closed_calls: HashSet::new(),
            loss_events: Vec::new(),
            unknown_terminations: Vec::new(),
            total_events: 0,
            degraded_seen: 0,
        }
    }
    pub fn drain_once(&mut self, max: usize) -> DrainBatch {
        self.drain_once_with_space_notify(max, || {})
    }
    pub fn drain_all(&mut self) -> DrainBatch {
        self.drain_all_with_space_notify(|| {})
    }
    /// 回収後に空きができ、書き手が空き待ち中なら `notify_space` を呼ぶ。
    /// 書き手は待機の意思表示＋全順序フェンスの後に空きを再確認しているので、
    /// この通知と再確認の組合せで空き待ちの取りこぼしが起きない。
    pub fn drain_once_with_space_notify(
        &mut self,
        max: usize,
        notify_space: impl Fn(),
    ) -> DrainBatch {
        let batch = self.drain_once_inner(max);
        if !batch.events.is_empty() && self.reader.writer_waiting() {
            notify_space();
        }
        batch
    }
    pub fn drain_all_with_space_notify(&mut self, notify_space: impl Fn()) -> DrainBatch {
        let batch = self.drain_once_inner(usize::MAX);
        if !batch.events.is_empty() && self.reader.writer_waiting() {
            notify_space();
        }
        batch
    }
    fn drain_once_inner(&mut self, max: usize) -> DrainBatch {
        let batch = self.reader.drain(max);
        self.process_batch(&batch);
        batch
    }
    fn process_batch(&mut self, batch: &DrainBatch) {
        if batch.sequence_gaps > 0 {
            self.loss_events.push(LossEvent::SequenceGap {
                count: batch.sequence_gaps,
            });
        }
        for e in &batch.events {
            self.total_events += 1;
            self.track_call(e);
            if e.descriptor.payload_dropped() {
                self.degraded_seen += 1;
            }
        }
        let now = self.reader.loss_counters();
        if let Some(diff) = now.diff_since(&self.prev_loss) {
            if diff.dropped_events > 0 || diff.dropped_payload_bytes > 0 || diff.degraded_events > 0
            {
                self.loss_events.push(LossEvent::Counters {
                    dropped_events: diff.dropped_events,
                    dropped_payload_bytes: diff.dropped_payload_bytes,
                    degraded_events: diff.degraded_events,
                });
            }
            self.prev_loss = now;
        }
    }
    fn track_call(&mut self, e: &ReceivedEvent) {
        match e.descriptor.kind_enum() {
            Some(EventKind::CallEnter) => {
                self.open_calls
                    .insert(e.descriptor.call_id, e.descriptor.sequence);
            }
            Some(EventKind::CallLeave)
                if self.open_calls.remove(&e.descriptor.call_id).is_some() =>
            {
                self.closed_calls.insert(e.descriptor.call_id);
            }
            _ => {}
        }
    }
    /// スレッド終了時点の確定: Enter があって Leave が無い呼出は「欠落により終了不明」。
    pub fn finalize_thread(&mut self) -> Vec<u64> {
        let mut unterminated: Vec<u64> = self.open_calls.keys().copied().collect();
        unterminated.sort_unstable();
        for &call_id in &unterminated {
            self.loss_events
                .push(LossEvent::UnknownTermination { call_id });
            self.unknown_terminations.push(call_id);
        }
        self.open_calls.clear();
        unterminated
    }
    pub fn open_call_count(&self) -> usize {
        self.open_calls.len()
    }
    pub fn integrity_report(
        &self,
        pool_missing_calls: u64,
        integrity_lost: bool,
    ) -> IntegrityReport {
        let mut r = IntegrityReport::default();
        if pool_missing_calls > 0 {
            r.capture_coverage = IntegrityLevel::Degraded;
            r.notes
                .push(format!("slot/coverage missing calls: {pool_missing_calls}"));
        }
        if integrity_lost {
            r.event_integrity = IntegrityLevel::Lost;
            r.notes
                .push("shared memory integrity lost; ring stopped".into());
        } else if !self.loss_events.is_empty() || !self.unknown_terminations.is_empty() {
            r.event_integrity = IntegrityLevel::Degraded;
            r.notes
                .push(format!("loss events: {}", self.loss_events.len()));
        }
        if self.degraded_seen > 0 {
            r.semantic_completeness = IntegrityLevel::Degraded;
            r.notes
                .push(format!("payload-degraded events: {}", self.degraded_seen));
        }
        // イベントを失ったものを完全として扱わない (不変条件 B05)
        if r.event_integrity != IntegrityLevel::Complete
            && r.capture_coverage == IntegrityLevel::Complete
        {
            // notes only; levels already reflect loss
        }
        r
    }
}

/// Host プロセス側の Ring 1 本分の配線: `DrainWorker` + `RingNotify`。
///
/// ライブラリ単位では `DrainWorker::drain_*_with_space_notify` にクロージャを
/// 渡す形だったが、Host プロセスが毎回結線を書くのは取りこぼしの元になる。
/// この型がその結線を 1 か所に集約する: 回収で空きができ、書き手が空き待ち中
/// （Control の writer_waiting フラグ）なら `space_available` を SetEvent する。
/// 書き手は待機の意思表示＋全順序フェンスの後に空きを再確認しているので、
/// この通知と再確認の組合せで空き待ちの取りこぼしが起きない（A61）。
///
/// `region` はこの worker より長く生きること。`RingNotify` は Ring 単位で
/// 1 個作り、書き手側へは DuplicateHandle 等で同じ OS イベントを渡す前提。
/// `notify` は `Arc` で共有する：書き手側の待機（`EventClock`）が同じ
/// `space_available` を待つため。
pub struct NotifyingDrainWorker<'r> {
    pub worker: DrainWorker,
    pub notify: Arc<RingNotify>,
    control_base: *const u8,
    /// 回収で空きができ、書き手待ち中に実際に SetEvent した回数。
    pub space_notifications: u64,
    /// 通知（SetEvent）に失敗した回数。失敗しても回収自体は行われており、
    /// 書き手は待機上限までの遅延で前に進む（通知は最適化であり正しさの前提ではない）。
    pub space_notify_errors: u64,
    _region: PhantomData<&'r SharedRegion>,
}
impl<'r> NotifyingDrainWorker<'r> {
    pub fn new(worker: DrainWorker, notify: Arc<RingNotify>, region: &'r SharedRegion) -> Self {
        Self {
            worker,
            notify,
            control_base: region.base() as *const u8,
            space_notifications: 0,
            space_notify_errors: 0,
            _region: PhantomData,
        }
    }
    /// Host→Agent の受け渡し（A68）: この Ring の `space_available` イベントを
    /// 対象プロセスへ DuplicateHandle で渡す。返した値は対象プロセス側の
    /// ハンドル値で、Agent は `Agent::attach_space_available` で取り込む。
    pub fn duplicate_space_to_process(
        &self,
        target_pid: u32,
    ) -> shirusu_transport_win::Result<shirusu_transport_win::HandleValue> {
        self.notify.duplicate_space_to_process(target_pid)
    }
    pub fn drain_once(&mut self, max: usize) -> DrainBatch {
        let Self {
            worker,
            notify,
            control_base,
            space_notifications,
            space_notify_errors,
            ..
        } = self;
        let notified = Cell::new(false);
        let failed = Cell::new(false);
        let batch = worker.drain_once_with_space_notify(max, || {
            // SAFETY: control_base は `region`（'r の借用）が生きている間だけ
            // 有効であり、この worker は region より先に破棄される。
            match unsafe { notify_space_if_writer_waiting(*control_base, notify.as_ref()) } {
                Ok(true) => notified.set(true),
                Ok(false) => {}
                Err(_) => failed.set(true),
            }
        });
        if notified.get() {
            *space_notifications += 1;
        }
        if failed.get() {
            *space_notify_errors += 1;
        }
        batch
    }
    pub fn drain_all(&mut self) -> DrainBatch {
        let Self {
            worker,
            notify,
            control_base,
            space_notifications,
            space_notify_errors,
            ..
        } = self;
        let notified = Cell::new(false);
        let failed = Cell::new(false);
        let batch = worker.drain_all_with_space_notify(|| {
            // SAFETY: 上記 drain_once と同じ。
            match unsafe { notify_space_if_writer_waiting(*control_base, notify.as_ref()) } {
                Ok(true) => notified.set(true),
                Ok(false) => {}
                Err(_) => failed.set(true),
            }
        });
        if notified.get() {
            *space_notifications += 1;
        }
        if failed.get() {
            *space_notify_errors += 1;
        }
        batch
    }
    pub fn finalize_thread(&mut self) -> Vec<u64> {
        self.worker.finalize_thread()
    }
    pub fn open_call_count(&self) -> usize {
        self.worker.open_call_count()
    }
    pub fn integrity_report(
        &self,
        pool_missing_calls: u64,
        integrity_lost: bool,
    ) -> IntegrityReport {
        self.worker
            .integrity_report(pool_missing_calls, integrity_lost)
    }
}

/// 検証付きで共有メモリ像を読む Host 経路。矛盾したら Ring 停止 + IntegrityLost を記録する。
pub struct ValidatingHost {
    reader: ValidatingReader,
    pub loss_events: Vec<LossEvent>,
    pub integrity_lost: bool,
}
impl ValidatingHost {
    pub fn new(known: KnownConfig, expected_generation: u64) -> Self {
        Self {
            reader: ValidatingReader::new(known, expected_generation),
            loss_events: Vec::new(),
            integrity_lost: false,
        }
    }
    pub fn drain_image(&mut self, image: &[u8]) -> Result<Vec<ReceivedEvent>, IntegrityError> {
        match self.reader.drain_image(image) {
            Ok(events) => Ok(events),
            Err(e) => {
                self.integrity_lost = true;
                self.loss_events.push(LossEvent::IntegrityLost {
                    reason: format!("{e:?}"),
                });
                Err(e)
            }
        }
    }
    pub fn is_stopped(&self) -> bool {
        self.reader.is_stopped()
    }
}

/// Host 主導の Slot 回収: スレッド終了を確認し、回収完了後にだけ再利用可能にする。
pub fn host_release_slot(
    pool: &SlotPool,
    handle: &SlotHandle,
    thread_ended: bool,
    drained: bool,
) -> bool {
    if !pool.host_confirm_ended_and_drained(handle, thread_ended, drained) {
        return false;
    }
    pool.host_reclaim(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_transport::clock::ManualClock;
    use shirusu_transport::ring::{EventInput, SharedRegion, WriterPolicy};
    use shirusu_transport::{CaptureState, Clock, RingConfig};
    use std::sync::Arc;

    /// Vec<u8> はポインタの 8 バイト整列を保証しないため、layout の原子操作を
    /// 適用する画像は u64 バッファで保持する (整列なしは UB、Miri 検出)。
    struct AlignedImage {
        words: Vec<u64>,
        len: usize,
    }
    impl AlignedImage {
        fn copy_of(src: &[u8]) -> Self {
            let mut s = Self {
                words: vec![0; src.len().div_ceil(8)],
                len: src.len(),
            };
            s.as_mut_slice().copy_from_slice(src);
            s
        }
        fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
        }
        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
        }
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.words.as_mut_ptr() as *mut u8
        }
    }

    fn setup() -> (SharedRegion, shirusu_transport::RingWriter, DrainWorker) {
        let cfg = RingConfig::new(16, 512);
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let w = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: std::time::Duration::ZERO,
                    ..Default::default()
                },
                clock,
            )
        };
        let r = unsafe { region.reader() };
        (region, w, DrainWorker::new(r))
    }
    fn ev(kind: EventKind, call: u64, payload: &[u8]) -> EventInput<'_> {
        EventInput {
            kind,
            api_id: 3,
            schema_id: 4,
            call_id: call,
            parent_call_id: 0,
            payload,
            capture_state: CaptureState::Captured,
        }
    }
    #[test]
    fn enter_leave_pairing_and_unknown_termination() {
        let (_rg, mut w, mut host) = setup();
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        w.write(ev(EventKind::CallLeave, 1, b"b"));
        w.write(ev(EventKind::CallEnter, 2, b"c")); // leave missing
        host.drain_all();
        assert_eq!(host.open_call_count(), 1);
        let unterminated = host.finalize_thread();
        assert_eq!(unterminated, vec![2]);
        assert!(host
            .loss_events
            .iter()
            .any(|l| matches!(l, LossEvent::UnknownTermination { call_id: 2 })));
    }
    #[test]
    fn loss_counters_become_loss_events() {
        let (_rg, mut w, mut host) = setup();
        // Ring を溢れさせて欠落を作る
        for i in 0..64u64 {
            w.write(ev(EventKind::CallEnter, i, b"0123456789abcdef"));
        }
        host.drain_all();
        assert!(!host.loss_events.is_empty());
        let report = host.integrity_report(0, false);
        assert_ne!(report.event_integrity, IntegrityLevel::Complete);
    }
    #[test]
    fn space_notify_only_when_writer_waiting_and_space_freed() {
        use std::cell::Cell;
        let (region, mut w, mut host) = setup();
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        // 書き手が空き待ち中のときだけ、回収で空けた分を通知する。
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            1,
            std::sync::atomic::Ordering::Relaxed,
        );
        let notified = Cell::new(false);
        let b = host.drain_once_with_space_notify(16, || notified.set(true));
        assert_eq!(b.events.len(), 1);
        assert!(notified.get());
        // フラグが下りていれば、回収しても通知しない。
        w.write(ev(EventKind::CallEnter, 2, b"b"));
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            0,
            std::sync::atomic::Ordering::Relaxed,
        );
        let notified = Cell::new(false);
        host.drain_once_with_space_notify(16, || notified.set(true));
        assert!(!notified.get());
        // 空きができなければ、フラグが立っていても通知しない。
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            1,
            std::sync::atomic::Ordering::Relaxed,
        );
        let notified = Cell::new(false);
        let b = host.drain_once_with_space_notify(16, || notified.set(true));
        assert_eq!(b.events.len(), 0);
        assert!(!notified.get());
    }
    #[test]
    fn unfinalized_report_is_unknown_not_complete() {
        let (_rg, _w, host) = setup();
        let mut report = host.integrity_report(0, false);
        assert!(report.finalized);
        assert_eq!(report.event_integrity, IntegrityLevel::Complete);
        report.mark_unfinalized();
        assert!(!report.finalized);
        assert_eq!(report.event_integrity, IntegrityLevel::Unknown);
        // 既に判明している Lost は Unknown で上書きしない。
        let mut lost = host.integrity_report(0, true);
        assert_eq!(lost.event_integrity, IntegrityLevel::Lost);
        lost.mark_unfinalized();
        assert!(!lost.finalized);
        assert_eq!(lost.event_integrity, IntegrityLevel::Lost);
    }
    #[test]
    fn validating_host_stops_on_corruption() {
        let cfg = RingConfig::new(8, 256);
        let region = SharedRegion::new(cfg, 5, 1);
        let known = KnownConfig::new(cfg, cfg.required_len());
        let mut host = ValidatingHost::new(known, 5);
        let mut image = AlignedImage::copy_of(region.as_slice());
        assert!(host.drain_image(image.as_slice()).unwrap().is_empty());
        // Cursor を異常値に壊す
        shirusu_transport::layout::store(
            image.as_mut_ptr(),
            shirusu_transport::layout::OFF_WRITE_CURSOR,
            u64::MAX - 3,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(host.drain_image(image.as_slice()).is_err());
        assert!(host.integrity_lost);
        assert!(host.is_stopped());
    }
    #[test]
    fn notifying_worker_sets_space_event_only_when_writer_waiting() {
        use shirusu_transport_win::RingNotify;
        let (region, mut w, worker) = setup();
        let notify = Arc::new(RingNotify::new().unwrap());
        let mut nw = NotifyingDrainWorker::new(worker, notify, &region);
        // 空き待ちでなければ回収しても通知しない。
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        let b = nw.drain_all();
        assert_eq!(b.events.len(), 1);
        assert_eq!(nw.space_notifications, 0);
        assert!(!nw
            .notify
            .space_available
            .wait_timeout(std::time::Duration::from_millis(1)));
        // 書き手が空き待ち中なら、回収で空けた分を 1 回通知する。
        w.write(ev(EventKind::CallEnter, 2, b"b"));
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            1,
            std::sync::atomic::Ordering::Relaxed,
        );
        let b = nw.drain_all();
        assert_eq!(b.events.len(), 1);
        assert_eq!(nw.space_notifications, 1);
        assert!(nw
            .notify
            .space_available
            .wait_timeout(std::time::Duration::from_millis(100)));
        // 空きができなければ、フラグが立っていても通知しない。
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            1,
            std::sync::atomic::Ordering::Relaxed,
        );
        nw.drain_all();
        assert_eq!(nw.space_notifications, 1);
        assert_eq!(nw.space_notify_errors, 0);
    }

    #[test]
    fn integrity_report_branch_matrix() {
        let (_rg, _w, host) = setup();
        // 欠落なし + finalized: 全て Complete
        let r = host.integrity_report(0, false);
        assert_eq!(r.capture_coverage, IntegrityLevel::Complete);
        assert_eq!(r.event_integrity, IntegrityLevel::Complete);
        assert_eq!(r.semantic_completeness, IntegrityLevel::Complete);
        // Pool 欠落だけ: Capture Coverage だけが Degraded
        let r = host.integrity_report(3, false);
        assert_eq!(r.capture_coverage, IntegrityLevel::Degraded);
        assert_eq!(r.event_integrity, IntegrityLevel::Complete);
        assert_eq!(r.semantic_completeness, IntegrityLevel::Complete);
        // Integrity 喪失: Event Integrity が Lost (Coverage の注記とは独立)
        let r = host.integrity_report(0, true);
        assert_eq!(r.event_integrity, IntegrityLevel::Lost);
        assert_eq!(r.capture_coverage, IntegrityLevel::Complete);
    }
    #[test]
    fn degraded_event_degrades_semantic_and_event() {
        let (_rg, mut w, mut host) = setup();
        let mut inp = ev(EventKind::CallEnter, 1, b"lost-value");
        inp.capture_state = CaptureState::DroppedByBackpressure;
        w.write(inp);
        host.drain_all();
        let r = host.integrity_report(0, false);
        assert_eq!(r.semantic_completeness, IntegrityLevel::Degraded);
        // 値が取れなかったことは Descriptor が無事に届いて申告している。
        // イベント自体の欠落ではないので Event Integrity は Complete のまま。
        assert_eq!(r.event_integrity, IntegrityLevel::Complete);
        assert_eq!(r.capture_coverage, IntegrityLevel::Complete);
    }
    #[test]
    fn sequence_gap_becomes_sequence_gap_loss_event() {
        let cfg = RingConfig::new(4, 256);
        let region = SharedRegion::new(cfg, 1, 1);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut w = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: std::time::Duration::ZERO,
                    ..Default::default()
                },
                clock,
            )
        };
        let r = unsafe { region.reader() };
        let mut host = DrainWorker::new(r);
        for i in 0..4u64 {
            w.write(ev(EventKind::CallEnter, i, b"x"));
        }
        // 2 件落とす (seq 5, 6) 後に 1 件書く (seq 7)
        let _ = w.write(ev(EventKind::CallEnter, 90, b"x"));
        let _ = w.write(ev(EventKind::CallEnter, 91, b"x"));
        host.drain_all();
        let _ = w.write(ev(EventKind::CallEnter, 92, b"x"));
        host.drain_all();
        assert!(
            host.loss_events
                .iter()
                .any(|l| matches!(l, LossEvent::SequenceGap { count: 2 })),
            "gap of 2 must be reported: {:?}",
            host.loss_events
        );
    }
    #[test]
    fn finalize_without_open_calls_and_drain_zero() {
        let (_rg, _w, mut host) = setup();
        let b = host.drain_once(0);
        assert!(b.events.is_empty());
        assert_eq!(host.total_events, 0);
        assert!(host.loss_events.is_empty());
        assert!(host.finalize_thread().is_empty());
        assert!(host.loss_events.is_empty(), "no spurious loss events");
        // Enter の無い Leave は対応付けを壊さない
        let (_rg2, mut w2, mut host2) = setup();
        w2.write(ev(EventKind::CallLeave, 777, b"orphan"));
        host2.drain_all();
        assert_eq!(host2.open_call_count(), 0);
        assert!(host2.finalize_thread().is_empty());
    }
    #[test]
    fn validating_host_returns_events_on_success() {
        let cfg = RingConfig::new(8, 256);
        let region = SharedRegion::new(cfg, 3, 1);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut w = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: std::time::Duration::ZERO,
                    ..Default::default()
                },
                clock,
            )
        };
        w.write(ev(EventKind::CallEnter, 1, b"hello"));
        w.write(ev(EventKind::CallLeave, 1, b"world"));
        let mut host = ValidatingHost::new(KnownConfig::new(cfg, cfg.required_len()), 3);
        let evs = host.drain_image(region.as_slice()).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].payload, b"hello");
        assert_eq!(evs[1].payload, b"world");
        assert!(!host.integrity_lost);
        assert!(!host.is_stopped());
    }
    #[test]
    fn notifying_worker_passthrough_methods() {
        use shirusu_transport_win::RingNotify;
        let (region, mut w, worker) = setup();
        let notify = Arc::new(RingNotify::new().unwrap());
        let mut nw = NotifyingDrainWorker::new(worker, notify, &region);
        w.write(ev(EventKind::CallEnter, 9, b"z"));
        let b = nw.drain_once(1);
        assert_eq!(b.events.len(), 1);
        assert_eq!(nw.open_call_count(), 1);
        let report = nw.integrity_report(0, false);
        assert_eq!(report.event_integrity, IntegrityLevel::Complete);
        // 対応する Leave が無いまま finalize すると未確定として返る
        let un = nw.finalize_thread();
        assert_eq!(un, vec![9]);
    }
    #[test]
    fn notifying_worker_duplicate_space_unsupported_on_stub() {
        use shirusu_transport_win::RingNotify;
        let (region, _w, worker) = setup();
        let notify = Arc::new(RingNotify::new().unwrap());
        let nw = NotifyingDrainWorker::new(worker, notify, &region);
        // Linux スタブではプロセス間複製は Unsupported。Windows 実機では
        // duplicate_event_to_self_process_signals_across_handle が担う。
        #[cfg(not(windows))]
        assert!(nw.duplicate_space_to_process(std::process::id()).is_err());
        #[cfg(windows)]
        assert!(nw.duplicate_space_to_process(std::process::id()).is_ok());
    }
    #[test]
    fn slot_release_requires_thread_end_and_drain() {
        let pool = SlotPool::new(1);
        let h = pool.claim(42).unwrap();
        pool.begin_detach(&h);
        assert!(!host_release_slot(&pool, &h, false, true));
        assert!(!host_release_slot(&pool, &h, true, false));
        assert!(host_release_slot(&pool, &h, true, true));
        assert_eq!(
            pool.slot(h.index).state(),
            shirusu_transport::SlotState::Free
        );
    }
}
