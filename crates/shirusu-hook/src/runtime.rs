//! Detour が共有する記録ランタイム。
//!
//! 役割:
//! - 元関数ポインタの表（engine が IAT パッチ時に格納し、Detour が引く）
//! - Call ID の発番と、スレッドローカルな呼出スタックによる親子関係
//! - 記録の入口：スレッド初回時の Slot 取得と、その Ring の
//!   `space_available` 通知の結線（管理パス。以後の記録は通常経路）
//! - 書き込み通知（NotifySignal）に応じた data_ready の SetEvent
//!
//! Loader Lock への配慮: ランタイムの構築とフックの設置は DLL 初期化
//! 専用スレッド（DllMain の外）で行う。記録経路では Agent の
//! WriterPolicy 既定（Loader Lock 保持が不明な書き込みは待機 0、A69）
//! に従い、ここでも待機する操作は行わない（SetEvent は待たない操作）。

use crate::api::{ApiDef, API_TABLE};
use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::notify::NotifySignal;
use shirusu_transport::ring::WriteOutcome;
use shirusu_transport_win::{ProcessNotify, RingNotify};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

thread_local! {
    /// 呼出スタック（Call ID の列）。フックした呼び出しの入れ子を
    /// 親子関係として記録するために使う。元の API がコールバック等で
    /// 再入した場合も、同じスレッドなら自然に入れ子になる。
    static CALL_STACK: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

pub fn current_parent_call() -> u64 {
    CALL_STACK.with(|s| s.borrow().last().copied().unwrap_or(0))
}
pub fn push_call(call_id: u64) {
    CALL_STACK.with(|s| s.borrow_mut().push(call_id));
}
/// スタック最上位が自分の Call ID のときにだけ取り除く（異常な
/// 対応ずれで他人のフレームを壊さない）。
pub fn pop_call(call_id: u64) {
    CALL_STACK.with(|s| {
        let mut s = s.borrow_mut();
        if s.last() == Some(&call_id) {
            s.pop();
        }
    });
}

/// Detour の記録区間への入場証 (レビュー #4 の #9)。
///
/// 保持している間、その Detour は「進行中」として数えられる。
/// 終了手順はこの数が 0 になるまで IAT を復元しないため、復元は
/// 進行中の呼び出しと競合しない。Drop で自動的に退出する。
pub struct DetourFlight {
    rt: Arc<HookRuntime>,
}

impl DetourFlight {
    /// 記録区間に入る。終了手順が始まっていれば None を返し、
    /// 呼び出し側は記録せず元関数を素通しで呼ぶこと。
    ///
    /// 無効化との競合で「数えられていない進行中 Detour」を残さない
    /// ため、加算後に有効フラグを再確認する。shutdown 側は無効化
    /// してから in_flight == 0 を待つので、この再確認と対になって
    /// 次が保証される: begin が Some を返した Detour は、待つ側から
    /// 必ず数えられる (か、無効化を観測して自分で退出する)。
    pub fn begin(rt: &Arc<HookRuntime>) -> Option<Self> {
        if !rt.recording_enabled.load(Ordering::SeqCst) {
            return None;
        }
        rt.in_flight.fetch_add(1, Ordering::SeqCst);
        if !rt.recording_enabled.load(Ordering::SeqCst) {
            rt.in_flight.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self { rt: Arc::clone(rt) })
    }
}

impl Drop for DetourFlight {
    fn drop(&mut self) {
        self.rt.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct HookRuntime {
    agent: Arc<Agent>,
    /// Slot index 順の space_available 通知。スレッドが Slot を取得した
    /// 時点で、そのスレッド（Ring）へ結線する（R7 の Ring 単位結線）。
    space_notifies: Vec<Arc<RingNotify>>,
    data_ready: Option<ProcessNotify>,
    originals: [AtomicUsize; API_TABLE.len() + 1],
    next_call_id: AtomicU64,
    seen_threads: Mutex<HashSet<u64>>,
    /// 記録の有効/無効 (終了手順のゲート。レビュー #4 の #9)。
    /// false になった後に Detour へ入った呼び出しは記録されず、
    /// 元関数を素通しで実行する。
    recording_enabled: AtomicBool,
    /// 記録区間に入っている Detour の数。終了手順は新規記録を
    /// 無効化してから、これが 0 になるのを待って IAT を復元する。
    in_flight: AtomicUsize,
}

impl HookRuntime {
    pub fn new(
        agent: Arc<Agent>,
        space_notifies: Vec<Arc<RingNotify>>,
        data_ready: Option<ProcessNotify>,
    ) -> Self {
        Self {
            agent,
            space_notifies,
            data_ready,
            originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            next_call_id: AtomicU64::new(1),
            seen_threads: Mutex::new(HashSet::new()),
            recording_enabled: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// 記録が有効か。終了手順 (shutdown_recording) が始まると false。
    pub fn recording_active(&self) -> bool {
        self.recording_enabled.load(Ordering::SeqCst)
    }

    /// 現在記録区間に入っている Detour の数。
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// 終了手順の開始 (レビュー #4 の #9): 新規の記録を無効化する。
    /// 既に記録区間に入っている Detour は通常どおり完了する。
    /// 無効化した時点の進行中件数を返す。以後の
    /// [`DetourFlight::begin`] は None を返す。
    pub fn shutdown_recording(&self) -> usize {
        self.recording_enabled.store(false, Ordering::SeqCst);
        self.in_flight()
    }

    /// 記録区間の Detour が全て完了するまで待つ。タイムアウトで false。
    pub fn wait_in_flight_drained(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while self.in_flight() != 0 {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }

    pub fn alloc_call_id(&self) -> u64 {
        self.next_call_id.fetch_add(1, Ordering::Relaxed)
    }

    /// engine が IAT の元値を保存する。Detour はこれを元関数として呼ぶ。
    pub fn set_original(&self, api_id: u32, addr: usize) {
        if let Some(slot) = self.originals.get(api_id as usize) {
            slot.store(addr, Ordering::Release);
        }
    }
    pub fn original(&self, api_id: u32) -> usize {
        self.originals
            .get(api_id as usize)
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(0)
    }
    pub fn originals_installed(&self) -> usize {
        self.originals
            .iter()
            .filter(|s| s.load(Ordering::Relaxed) != 0)
            .count()
    }

    /// スレッド初回記録時の管理パス： Slot を取得し、その Slot の
    /// space_available 通知を Ring へ結線する。2 回目以降は何もしない
    /// （記録の通常経路はここを通らない）。
    pub fn ensure_thread(&self, thread_id: u64) {
        {
            let seen = self.seen_threads.lock().unwrap();
            if seen.contains(&thread_id) {
                return;
            }
        }
        let Some(handle) = self.agent.thread_begin(thread_id) else {
            return; // Slot 不足。記録時に NoSlot として数えられる
        };
        if let Some(notify) = self.space_notifies.get(handle.index) {
            self.agent
                .attach_space_available_notify(thread_id, Arc::clone(notify));
        }
        self.seen_threads.lock().unwrap().insert(thread_id);
    }

    fn signal_if_needed(&self, result: &RecordResult) {
        if let RecordResult::Written(WriteOutcome::Published { notify, .. }) = result {
            if *notify != NotifySignal::None {
                if let Some(n) = &self.data_ready {
                    let _ = n.notify_data_ready();
                }
            }
        }
    }

    pub fn record_enter(
        &self,
        thread_id: u64,
        api: &ApiDef,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_enter(
            thread_id,
            api.api_id,
            api.enter_schema_id(),
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    pub fn record_leave(
        &self,
        thread_id: u64,
        api: &ApiDef,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_leave(
            thread_id,
            api.api_id,
            api.leave_schema_id(),
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::*;
    use shirusu_transport::context::HostMonitor;
    use shirusu_transport::ring::RingReader;
    use shirusu_transport::slot::SlotPool;
    use shirusu_transport::RingConfig;

    fn runtime() -> (Arc<Agent>, HookRuntime) {
        let pool = Arc::new(SlotPool::new(2));
        let agent = Arc::new(Agent::new(
            pool,
            RingConfig::new(64, 4096),
            Arc::new(HostMonitor::always_alive()),
        ));
        let rt = HookRuntime::new(Arc::clone(&agent), Vec::new(), None);
        (agent, rt)
    }

    #[test]
    fn enter_leave_reach_the_ring_with_parent_chain() {
        let (agent, rt) = runtime();
        let tid = 4242u64;
        rt.ensure_thread(tid);
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let outer = rt.alloc_call_id();
        let r = rt.record_enter(tid, create, outer, b"enter-args");
        assert!(matches!(r, RecordResult::Written(_)));
        push_call(outer);
        // 入れ子呼び出しは親を引く
        let inner = rt.alloc_call_id();
        assert_eq!(current_parent_call(), outer);
        rt.record_enter(tid, create, inner, b"inner");
        pop_call(outer);
        rt.record_leave(tid, create, outer, b"leave-args");

        // Ring を読み戻してイベントの対応を確認する
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert!(batch.integrity_error.is_none());
        assert_eq!(batch.events.len(), 3);
        let inner_ev = &batch.events[1];
        assert_eq!(inner_ev.descriptor.call_id, inner);
        assert_eq!(inner_ev.descriptor.parent_call_id, outer);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            create.enter_schema_id()
        );
        assert_eq!(
            batch.events[2].descriptor.schema_id,
            create.leave_schema_id()
        );
    }

    #[test]
    fn originals_table_roundtrip() {
        let (_agent, rt) = runtime();
        assert_eq!(rt.original(API_CREATE_FILE_W), 0);
        rt.set_original(API_CREATE_FILE_W, 0xDEAD_BEEF);
        assert_eq!(rt.original(API_CREATE_FILE_W), 0xDEAD_BEEF);
        assert_eq!(rt.originals_installed(), 1);
        // 範囲外 ID は静かに 0
        rt.set_original(9999, 1);
        assert_eq!(rt.original(9999), 0);
    }

    #[test]
    fn detour_gate_blocks_new_flights_after_shutdown() {
        // レビュー #4 の #9: 終了手順が始まったら新規 Detour は記録
        // 区間に入れない (呼び出し側は素通しする)。
        let (_agent, rt) = runtime();
        let rt = Arc::new(rt);
        assert!(rt.recording_active());
        let flight = DetourFlight::begin(&rt).expect("flight before shutdown");
        assert_eq!(rt.in_flight(), 1);
        assert_eq!(rt.shutdown_recording(), 1, "one flight in progress");
        assert!(!rt.recording_active());
        assert!(DetourFlight::begin(&rt).is_none());
        drop(flight);
        assert_eq!(rt.in_flight(), 0);
        assert!(rt.wait_in_flight_drained(Duration::from_secs(1)));
    }

    #[test]
    fn shutdown_waits_for_in_flight_detours() {
        // 進行中 Detour が完了するまで drained にならない。
        let (_agent, rt) = runtime();
        let rt = Arc::new(rt);
        let rt2 = Arc::clone(&rt);
        let holder = std::thread::spawn(move || {
            let flight = DetourFlight::begin(&rt2).expect("flight");
            std::thread::sleep(Duration::from_millis(150));
            drop(flight);
        });
        // holder が入場するまで少し待つ
        while rt.in_flight() == 0 {
            std::thread::yield_now();
        }
        rt.shutdown_recording();
        assert!(!rt.wait_in_flight_drained(Duration::from_millis(10)));
        assert!(rt.wait_in_flight_drained(Duration::from_secs(5)));
        holder.join().unwrap();
        assert_eq!(rt.in_flight(), 0);
    }

    #[test]
    fn call_stack_pop_only_own_frame() {
        push_call(10);
        push_call(20);
        pop_call(10); // 最上位でないので取り除かない
        assert_eq!(current_parent_call(), 20);
        pop_call(20);
        assert_eq!(current_parent_call(), 10);
        pop_call(10);
        assert_eq!(current_parent_call(), 0);
    }
}
