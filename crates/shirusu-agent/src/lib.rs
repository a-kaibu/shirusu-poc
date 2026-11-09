//! shirusu-agent: 書き手側。スレッド毎 Ring の取得と書込み、再入ガード、Host 生存確認、DETACH 通知。
//! Hook 自体は実装範囲外（spec のクレート構成表）。ここは転送層への書込みまでを担う。

use shirusu_transport::clock::{system_clock, Clock};
use shirusu_transport::context::{should_record, CallOrigin, HostMonitor, PublishGuard};
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriteOutcome, WriterPolicy};
use shirusu_transport::slot::{SlotHandle, SlotPool};
use shirusu_transport::RingConfig;
use shirusu_transport_win::{EventClock, EventObject, HandleValue, RingNotify};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordResult {
    Written(WriteOutcome),
    /// Slot が無く記録しなかった（Capture Coverage 欠落として数え済み）。
    NoSlot,
    /// DETACH 後で記録しなかった（欠落として数え済み）。
    AfterDetach,
    /// Host 停止が確認され、記録を無効化して素通しにした。
    PassthroughHostStopped,
    /// Agent 自身の呼出なので記録しない。
    SkippedAgentInternal,
}

/// Agent 全体。SlotPool と、Slot ごとの共有領域・書き手を管理する。
pub struct Agent {
    pool: Arc<SlotPool>,
    config: RingConfig,
    policy: WriterPolicy,
    /// 書き手が使う Clock。`attach_space_available_*` で EventClock へ差し替える
    /// ため Mutex 越しに持つ（書き手は thread_begin 時に Arc を複製して保持する）。
    clock: Mutex<Arc<dyn Clock>>,
    /// Host から受け取った space_available 通知（A68）。受け取り後に保持し、
    /// EventClock と同じ OS イベントを指し続ける。
    space_notify: Mutex<Option<Arc<RingNotify>>>,
    host_monitor: Arc<HostMonitor>,
    threads: Mutex<HashMap<u64, ThreadSlotState>>,
}
struct ThreadSlotState {
    handle: SlotHandle,
    // SharedRegion は writer より長生きさせるためここに保持する。
    _region: Box<SharedRegion>,
    writer: RingWriter,
}

impl Agent {
    pub fn new(pool: Arc<SlotPool>, config: RingConfig, host_monitor: Arc<HostMonitor>) -> Self {
        Self {
            pool,
            config,
            policy: WriterPolicy::default(),
            clock: Mutex::new(system_clock()),
            space_notify: Mutex::new(None),
            host_monitor,
            threads: Mutex::new(HashMap::new()),
        }
    }
    pub fn with_policy(mut self, policy: WriterPolicy) -> Self {
        self.policy = policy;
        self
    }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Mutex::new(clock);
        self
    }
    /// Host から `space_available` を受け取る（A68）。`notify` は Host 側の
    /// `RingNotify` と同じ OS イベントを指すもの（プロセス内共有の場合は同じ
    /// `Arc`、プロセス間の場合は Host が `duplicate_space_to_process` で渡した
    /// ハンドルから `attach_space_available` で作ったもの）であること。
    /// 受け取りに成功すると、以後 `thread_begin` で作る書き手は `EventClock`
    /// （Host の SetEvent で即起きる待機）で書く。返した `EventClock` は
    /// `sleep_calls()` で待機の実績を観測できる。
    /// スレッドが既に書き始めている場合は差し替えできない（既存の書き手が
    /// 古い Clock を保持したままになるため）ので `None` を返す。
    pub fn attach_space_available_notify(
        &self,
        notify: Arc<RingNotify>,
    ) -> Option<Arc<EventClock>> {
        if !self.threads.lock().unwrap().is_empty() {
            return None;
        }
        let clock = Arc::new(EventClock::new(Arc::clone(&notify)));
        *self.clock.lock().unwrap() = Arc::clone(&clock) as Arc<dyn Clock>;
        *self.space_notify.lock().unwrap() = Some(notify);
        Some(clock)
    }
    /// Host から `space_available` ハンドルを受け取る（A68、プロセス間経路）。
    /// `handle_value` はこのプロセスで有効な Event ハンドルであること
    /// （Host が `NotifyingDrainWorker::duplicate_space_to_process` で渡した値、
    /// または継承で受け取った値）。`space_available` は auto-reset 前提。
    ///
    /// # Safety
    /// 無効なハンドル値を渡すと、Windows では待機が失敗するか未定義動作に
    /// なる。Linux スタブではハンドル値に実体が無いため、つながっていない
    /// 新しいイベントが作られるだけ（プロセス間受け渡しの実証は Windows
    /// 実機＋GHA の `duplicate_event_to_self_process_signals_across_handle`
    /// が担う）。
    pub unsafe fn attach_space_available(
        &self,
        handle_value: HandleValue,
    ) -> Option<Arc<EventClock>> {
        let notify = Arc::new(RingNotify {
            space_available: EventObject::from_handle_value(handle_value, true),
        });
        self.attach_space_available_notify(notify)
    }
    /// Host から `space_available` を受け取り済みかどうか。
    pub fn space_available_attached(&self) -> bool {
        self.space_notify.lock().unwrap().is_some()
    }
    pub fn pool(&self) -> &Arc<SlotPool> {
        &self.pool
    }
    pub fn host_monitor(&self) -> &Arc<HostMonitor> {
        &self.host_monitor
    }

    /// スレッドが初めて記録するときに Slot と Ring を取得する。
    pub fn thread_begin(&self, thread_id: u64) -> Option<SlotHandle> {
        let mut map = self.threads.lock().unwrap();
        if let Some(s) = map.get(&thread_id) {
            return Some(s.handle);
        }
        let handle = self.pool.claim(thread_id)?;
        let region = Box::new(SharedRegion::new(self.config, handle.generation, thread_id));
        let clock = self.clock.lock().unwrap().clone();
        let writer = unsafe { region.writer(self.policy.clone(), clock) };
        map.insert(
            thread_id,
            ThreadSlotState {
                handle,
                _region: region,
                writer,
            },
        );
        Some(handle)
    }

    /// テスト/Host 連携用: スレッドの共有領域ベースポインタを返す。
    ///
    /// # Safety
    /// 返したポインタは ThreadSlotState が保持する領域を指す。thread_end で解放された後は使えない。
    pub unsafe fn thread_region_base(&self, thread_id: u64) -> Option<*mut u8> {
        let map = self.threads.lock().unwrap();
        map.get(&thread_id).map(|s| s._region.base())
    }
    pub fn thread_config(&self) -> RingConfig {
        self.config
    }

    /// 呼び出しを記録する。再入ガードは公開区間だけに適用される（ring の publish 内相当を
    /// ここでも明示し、元の API 呼出に相当する処理の前には外れていることを型で示す）。
    pub fn record(&self, thread_id: u64, origin: CallOrigin, input: EventInput) -> RecordResult {
        if !should_record(origin) {
            return RecordResult::SkippedAgentInternal;
        }
        if !self.host_monitor.recording_enabled() {
            return RecordResult::PassthroughHostStopped;
        }
        let mut map = self.threads.lock().unwrap();
        let slot_state = match map.get_mut(&thread_id) {
            Some(s) => s,
            None => {
                drop(map);
                if self.thread_begin(thread_id).is_none() {
                    return RecordResult::NoSlot;
                }
                map = self.threads.lock().unwrap();
                map.get_mut(&thread_id).expect("just inserted")
            }
        };
        if slot_state.writer.is_detached() {
            self.pool.note_call_after_detach(&slot_state.handle);
            return RecordResult::AfterDetach;
        }
        let outcome = {
            let _guard = PublishGuard::enter(); // 公開区間だけのガード
            slot_state.writer.write(input)
        };
        // 容量不足などの異常経路でのみ Host 生存確認する。通常経路では確認しない。
        if matches!(
            outcome,
            WriteOutcome::Dropped { .. } | WriteOutcome::PublishedDegraded { .. }
        ) && !self.host_monitor.check_on_abnormal_path()
        {
            return RecordResult::PassthroughHostStopped;
        }
        RecordResult::Written(outcome)
    }

    pub fn record_enter(
        &self,
        thread_id: u64,
        api_id: u32,
        schema_id: u32,
        call_id: u64,
        parent: u64,
        payload: &[u8],
    ) -> RecordResult {
        self.record(
            thread_id,
            CallOrigin::Application,
            EventInput {
                kind: EventKind::CallEnter,
                api_id,
                schema_id,
                call_id,
                parent_call_id: parent,
                payload,
                capture_state: CaptureState::Captured,
            },
        )
    }
    pub fn record_leave(
        &self,
        thread_id: u64,
        api_id: u32,
        schema_id: u32,
        call_id: u64,
        parent: u64,
        payload: &[u8],
    ) -> RecordResult {
        self.record(
            thread_id,
            CallOrigin::Application,
            EventInput {
                kind: EventKind::CallLeave,
                api_id,
                schema_id,
                call_id,
                parent_call_id: parent,
                payload,
                capture_state: CaptureState::Captured,
            },
        )
    }

    /// DLL_THREAD_DETACH 相当: DRAINING へ移行するだけ（待たない）。領域は Host 回収まで保持する。
    pub fn thread_detach(&self, thread_id: u64) -> bool {
        let mut map = self.threads.lock().unwrap();
        if let Some(s) = map.get_mut(&thread_id) {
            s.writer.mark_detached();
            let handle = s.handle;
            drop(map);
            return self.pool.begin_detach(&handle);
        }
        false
    }

    /// Host が回収を終えた後に Agent 側の保持を解く（通常は Host 主導）。
    pub fn thread_forget(&self, thread_id: u64) {
        self.threads.lock().unwrap().remove(&thread_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn agent(pool_size: usize) -> Agent {
        let pool = Arc::new(SlotPool::new(pool_size));
        Agent::new(
            pool,
            RingConfig::new(16, 512),
            Arc::new(HostMonitor::always_alive()),
        )
        .with_policy(WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        })
    }
    #[test]
    fn records_enter_leave_and_agent_internal_skipped() {
        let a = agent(4);
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            a.record_leave(1, 10, 20, 100, 0, b"ret"),
            RecordResult::Written(_)
        ));
        let internal = a.record(
            1,
            CallOrigin::AgentInternal,
            EventInput {
                kind: EventKind::CallEnter,
                api_id: 1,
                schema_id: 1,
                call_id: 1,
                parent_call_id: 0,
                payload: b"",
                capture_state: CaptureState::Captured,
            },
        );
        assert_eq!(internal, RecordResult::SkippedAgentInternal);
    }
    #[test]
    fn no_slot_counts_coverage_loss() {
        let a = agent(1);
        assert!(a.thread_begin(1).is_some());
        assert!(a.thread_begin(2).is_none());
        assert_eq!(a.pool().missing_calls(), 1);
    }
    #[test]
    fn detach_then_calls_are_counted_not_recorded() {
        let a = agent(2);
        a.record_enter(7, 1, 1, 5, 0, b"x");
        assert!(a.thread_detach(7));
        assert_eq!(
            a.record_enter(7, 1, 1, 6, 0, b"x"),
            RecordResult::AfterDetach
        );
        assert!(a.pool().missing_calls() >= 1);
    }
    #[test]
    fn attach_space_available_before_first_write() {
        use shirusu_transport_win::RingNotify;
        let a = agent(2);
        assert!(!a.space_available_attached());
        let notify = Arc::new(RingNotify::new().unwrap());
        let clock = a.attach_space_available_notify(Arc::clone(&notify));
        assert!(clock.is_some());
        assert!(a.space_available_attached());
        assert_eq!(clock.unwrap().sleep_calls(), 0);
        // 受け取り後に書き始めたスレッドは EventClock で書く。
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
        // 書き始め後の差し替えはできない（既存の書き手が古い Clock を持つため）。
        let notify2 = Arc::new(RingNotify::new().unwrap());
        assert!(a.attach_space_available_notify(notify2).is_none());
        assert!(a.space_available_attached());
    }
    #[test]
    fn attach_space_available_after_thread_begin_is_rejected() {
        use shirusu_transport_win::RingNotify;
        let a = agent(2);
        assert!(a.thread_begin(1).is_some());
        let notify = Arc::new(RingNotify::new().unwrap());
        assert!(a.attach_space_available_notify(notify).is_none());
        assert!(!a.space_available_attached());
    }
    #[test]
    fn attach_space_available_from_handle_value_shape() {
        // ハンドル値経路の API 形だけを確認する。Linux スタブではハンドル値に
        // 実体が無く、つながっていない新しいイベントになる（プロセス間受け渡し
        // の実証は Windows 実機の duplicate テストが担う）。それでも Agent は
        // EventClock で書けること。
        let a = agent(2);
        let clock = unsafe { a.attach_space_available(0) };
        assert!(clock.is_some());
        assert!(a.space_available_attached());
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
    }
    #[test]
    fn record_without_slot_returns_no_slot() {
        let a = agent(1);
        assert!(a.thread_begin(1).is_some());
        // record 内の thread_begin でも Slot が取れなければ NoSlot
        assert_eq!(a.record_enter(2, 1, 1, 1, 0, b"x"), RecordResult::NoSlot);
        assert_eq!(a.pool().missing_calls(), 1);
    }
    #[test]
    fn thread_begin_is_idempotent_per_thread() {
        let a = agent(2);
        let h1 = a.thread_begin(9).unwrap();
        let h2 = a.thread_begin(9).unwrap();
        assert_eq!(h1, h2, "same thread reuses its slot and writer");
        assert_eq!(a.pool().free_count(), 1);
    }
    #[test]
    fn detach_unknown_thread_and_forget_reclaims_new_slot() {
        let a = agent(2);
        assert!(
            !a.thread_detach(12345),
            "unknown thread has nothing to detach"
        );
        let h1 = a.thread_begin(3).unwrap();
        a.thread_forget(3);
        // forget は Pool の Slot を解放しない (Host 回収が前提)。再記録では別の Slot を取る。
        assert!(matches!(
            a.record_enter(3, 1, 1, 1, 0, b"x"),
            RecordResult::Written(_)
        ));
        let h2 = a.thread_begin(3).unwrap();
        assert_ne!(h1.index, h2.index);
        assert_eq!(a.pool().free_count(), 0);
    }
    #[test]
    fn record_inside_publish_guard_is_skipped() {
        let a = agent(2);
        let _g = PublishGuard::enter();
        // 公開区間内ではアプリ由来でも記録しない (should_record の契約)
        assert_eq!(
            a.record_enter(1, 1, 1, 1, 0, b"x"),
            RecordResult::SkippedAgentInternal
        );
    }
    #[test]
    fn dead_host_monitor_short_circuits_before_slot_use() {
        let pool = Arc::new(SlotPool::new(2));
        let monitor = Arc::new(HostMonitor::always_alive());
        monitor.force_dead();
        let a = Agent::new(pool.clone(), RingConfig::new(4, 64), monitor);
        assert_eq!(
            a.record_enter(1, 1, 1, 1, 0, b"x"),
            RecordResult::PassthroughHostStopped
        );
        assert_eq!(pool.free_count(), 2, "no slot was claimed");
    }
    #[test]
    fn with_clock_and_region_accessors() {
        use shirusu_transport::clock::ManualClock;
        let a = agent(2).with_clock(Arc::new(ManualClock::new()));
        assert_eq!(a.thread_config(), RingConfig::new(16, 512));
        assert!(unsafe { a.thread_region_base(77) }.is_none());
        a.thread_begin(77).unwrap();
        let base = unsafe { a.thread_region_base(77) }.expect("region exists");
        assert!(!base.is_null());
        assert!(matches!(
            a.record_enter(77, 1, 1, 1, 0, b"x"),
            RecordResult::Written(_)
        ));
    }
    #[test]
    fn host_stopped_passthrough() {
        let pool = Arc::new(SlotPool::new(2));
        let monitor = Arc::new(HostMonitor::new(|| false));
        let a = Agent::new(pool, RingConfig::new(4, 64), monitor).with_policy(WriterPolicy {
            max_wait: std::time::Duration::ZERO,
            ..Default::default()
        });
        // Ring を埋めて異常経路に入れると Host 停止が確認され、以後は素通しになる
        for i in 0..40u64 {
            let _ = a.record_enter(1, 1, 1, i, 0, b"0123456789");
        }
        assert!(!a.host_monitor().recording_enabled());
        assert_eq!(
            a.record_enter(1, 1, 1, 999, 0, b"x"),
            RecordResult::PassthroughHostStopped
        );
    }
}
