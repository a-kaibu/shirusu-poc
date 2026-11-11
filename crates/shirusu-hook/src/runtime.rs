//! Detour が共有する記録ランタイム。
//!
//! 役割:
//! - 元関数ポインタの表（engine が IAT パッチ時に格納し、Detour が引く）
//! - Call ID の発番と、スレッドローカルな呼出スタックによる親子関係
//! - 記録の入口：スレッド初回時の Slot 取得と、その Ring の
//!   `space_available` 通知の結線（管理パス。以後の記録は通常経路）
//! - 書き込み通知（NotifySignal）に応じた data_ready の SetEvent
//! - Detour の再入制御 (G15): 記録経路の実行中にフック対象 API が呼ばれたら
//!   TLS ガードで素通しにする（`ReentrancyGuard`）。元の API 呼び出しの間だけ
//!   ガードを外し、アプリ由来の入れ子は記録する。
//!
//! Loader Lock への配慮: ランタイムの構築とフックの設置は DLL 初期化
//! 専用スレッド（DllMain の外）で行う。記録経路では Agent の
//! WriterPolicy 既定（Loader Lock 保持が不明な書き込みは待機 0、A69）
//! に従い、ここでも待機する操作は行わない（SetEvent は待たない操作）。

use crate::api::{ApiDef, API_TABLE};
use crate::capture::{OverlappedRegistry, PendingOverlapped};
use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::notify::NotifySignal;
use shirusu_transport::ring::WriteOutcome;
use shirusu_transport_win::{ProcessNotify, RingNotify};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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

thread_local! {
    /// Detour の再入ガードの深さ (G15)。0 = 記録経路の外、1 = 記録経路の実行中。
    static REENTRANCY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Detour の再入ガード (G15)。
///
/// 記録経路（capture / Agent への記録 / 通知）の実行中にフック対象 API が
/// 呼ばれた場合、その呼び出しは Agent 自身のものであり記録しない。
/// 入口で [`ReentrancyGuard::try_enter`] が `None` を返したら、呼び出し側は
/// 元関数を素通しで呼ぶこと（`engine::prepare` がこの判定を集約する）。
///
/// A42 の `PublishGuard`（転送層・公開区間だけの短いガード）とは別層の
/// ガードである。あちらは Ring への公開区間だけを覆うが、こちらは Detour
/// の記録経路全体（capture・`ensure_thread`・Agent への記録・通知）を覆う。
/// 旧実装は記録経路がフック対象の 4 API を呼ばないことに暗黙に依存して
/// いたが、API 表が増える（L03）とその前提が崩れるため、機構として持つ。
///
/// 元の API 呼び出しの間だけ [`ReentrancyGuard::suspend`] でガードを外す:
/// 元の呼び出しの中でアプリ由来の入れ子呼び出し（コールバック経由を含む）が
/// 起きた場合は、従来どおり親子として記録される (A43)。
/// ガードは同時に 1 つだけ保持できる（suspend 中の入れ子は別のガード）。
/// Drop で必ず外れる（suspend したまま drop しても深さは 0 のまま）。
pub struct ReentrancyGuard {
    suspended: bool,
}

impl ReentrancyGuard {
    /// Detour 入口で呼ぶ。再入中なら `None` を返す。
    pub fn try_enter() -> Option<Self> {
        REENTRANCY_DEPTH.with(|d| {
            if d.get() > 0 {
                None
            } else {
                d.set(1);
                Some(Self { suspended: false })
            }
        })
    }

    /// 記録経路の実行中か。
    pub fn is_active() -> bool {
        REENTRANCY_DEPTH.with(|d| d.get() > 0)
    }

    /// 元の API 呼び出しの直前に呼ぶ: ガードを一時的に外す。
    pub fn suspend(&mut self) {
        if !self.suspended {
            REENTRANCY_DEPTH.with(|d| d.set(0));
            self.suspended = true;
        }
    }

    /// 元の API 呼び出しの直後に呼ぶ: ガードを戻す。
    pub fn resume(&mut self) {
        if self.suspended {
            REENTRANCY_DEPTH.with(|d| d.set(1));
            self.suspended = false;
        }
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        // suspend 中は深さは既に 0。保持中の場合だけ 0 に戻す。
        if !self.suspended {
            REENTRANCY_DEPTH.with(|d| d.set(0));
        }
    }
}

/// 中断した呼び出しの記録ガード (L08)。
///
/// Detour が enter を記録して呼出スタックへ積んだ直後に作り、元の API
/// 呼び出しが正常に戻ったら [`CallGuard::complete`] で武装解除する。
/// 元の呼び出しが例外（C++ 例外 / SEH / Rust パニック）で戻らなかった
/// 場合、巻き戻しでこのガードの Drop が走り、呼出スタックから外して
/// `CallAborted` を記録する。例外自体は一切捕捉しないため、呼び出し側
/// へ伝わる例外は Detour が無い場合と同一である。
///
/// 前提: Windows では Rust のフレームも SEH アンワインド情報を持つため、
/// 外来の例外が Detour フレームを巻き戻すときにこの Drop は走る。
/// 仮に走らなかった場合の失敗モードは「中断の記録漏れ」だけで、例外の
/// 伝播や対象プロセスの挙動は変わらない（記録漏れは Host 側の
/// UnknownTermination として別途扱われる）。
///
/// Drop 中の記録は失敗してもプロセスを落とさないこと: 巻き戻し中の
/// Drop でパニックするとプロセスが abort するため、記録は
/// `catch_unwind` で包んで結果を捨てる。
pub struct CallGuard {
    rt: Arc<HookRuntime>,
    thread_id: u64,
    api: &'static ApiDef,
    call_id: u64,
    armed: bool,
}

impl CallGuard {
    pub fn new(rt: &Arc<HookRuntime>, thread_id: u64, api: &'static ApiDef, call_id: u64) -> Self {
        Self {
            rt: Arc::clone(rt),
            thread_id,
            api,
            call_id,
            armed: true,
        }
    }

    /// 元の呼び出しが正常に戻った: 武装解除し、Drop しても何もしない。
    pub fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        pop_call(self.call_id);
        let rt = Arc::clone(&self.rt);
        let (thread_id, api, call_id) = (self.thread_id, self.api, self.call_id);
        // 巻き戻し中の Drop でパニックすると abort するため、記録の
        // 成否は問わず、パニックもここで吸収する（例外の伝播には触れない）。
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.record_aborted(thread_id, api, call_id);
        }));
    }
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

/// セッション単位のランタイム登録スロット（レビュー第5回 #7）。
///
/// 旧実装は `OnceLock` で、shutdown 後も登録が残るため、同じ対象
/// プロセスへの再アタッチ（init → shutdown → init）が
/// ALREADY_INITIALIZED で失敗していた。このスロットは「アクティブな
/// セッションが 1 つだけ」という不変条件を保ったまま、終了した
/// セッションの登録を解除して次のセッションを受け入れられる。
///
/// 安全性の要点:
/// - Detour は呼び出しの入口で [`RuntimeSlot::current`] から `Arc` を
///   掴み、その呼び出しの間は掴んだランタイムだけを使う。登録が
///   差し替わっても、進行中の Detour は旧ランタイムを安全に
///   使い続けられる（`Arc` が寿命を保証し、元関数ポインタは掴んだ
///   ランタイムの表から引く）。
/// - 登録解除は **IAT 復元の後** にだけ行うこと。復元前に登録が
///   無くなると、その間に到達した Detour が元関数を引けず、
///   対象 API の失敗値を返してしまう。
/// - 2 回目の設置では、復元済み IAT から元関数ポインタを読み直す
///   （install_hooks が毎回スロット実値を読む）ため、旧セッションの
///   ポインタが残ることはない。
pub struct RuntimeSlot {
    current: RwLock<Option<Arc<HookRuntime>>>,
}

impl RuntimeSlot {
    pub const fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// アクティブなセッションが無ければ登録する。ある場合は、
    /// 渡したランタイムをそのまま `Err` で返す。
    pub fn register(&self, rt: Arc<HookRuntime>) -> Result<(), Arc<HookRuntime>> {
        let mut cur = self.current.write().unwrap();
        if cur.is_some() {
            return Err(rt);
        }
        *cur = Some(rt);
        Ok(())
    }

    /// 現在のセッションのランタイム（Detour の入口が掴む）。
    pub fn current(&self) -> Option<Arc<HookRuntime>> {
        self.current.read().unwrap().clone()
    }

    /// 登録解除は「自分が登録したランタイム」に対してだけ行う
    /// （後継セッションの登録を誤って消さない）。解除したら true。
    pub fn unregister(&self, rt: &Arc<HookRuntime>) -> bool {
        let mut cur = self.current.write().unwrap();
        if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, rt)) {
            *cur = None;
            true
        } else {
            false
        }
    }
}

impl Default for RuntimeSlot {
    fn default() -> Self {
        Self::new()
    }
}

static RUNTIME_SLOT: RuntimeSlot = RuntimeSlot::new();

/// プロセス全体のランタイム登録スロット（engine が使う）。
pub fn runtime_slot() -> &'static RuntimeSlot {
    &RUNTIME_SLOT
}

/// Call ID のセッション別シード。セッションごとに 2^32 の範囲を
/// 割り当てることで、終了間際に残ったスレッドローカルの呼出
/// スタックフレーム（旧セッションの Call ID）が、次セッションの
/// ID と衝突して親子関係を誤らせることを防ぐ。
static NEXT_CALL_ID_SEED: AtomicU64 = AtomicU64::new(1);

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
    /// 完了待ちの非同期 I/O 操作の登録表（F27）。完了は別スレッドで
    /// 観測されることがある（IOCP）ため、セッション全体で共有する。
    pending_overlapped: OverlappedRegistry,
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
            next_call_id: AtomicU64::new(NEXT_CALL_ID_SEED.fetch_add(1 << 32, Ordering::Relaxed)),
            seen_threads: Mutex::new(HashSet::new()),
            recording_enabled: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            pending_overlapped: OverlappedRegistry::new(),
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

    /// 中断した呼び出しを記録する（L08）。`CallGuard` の Drop から呼ぶ。
    /// 記録の成否は呼び出し側の例外伝播に影響しない（結果は捨てる）。
    pub fn record_aborted(&self, thread_id: u64, api: &ApiDef, call_id: u64) {
        let parent = current_parent_call();
        let result = self.agent.record_aborted(
            thread_id,
            api.api_id,
            api.leave_schema_id(),
            call_id,
            parent,
        );
        self.signal_if_needed(&result);
    }

    /// 非同期 I/O の完了を記録する（F27）。完了を観測した Detour から
    /// 呼ぶ。`api` は元の呼び出し（ReadFile / WriteFile）の定義で、
    /// payload はその leave Schema の値列。
    pub fn record_completion(
        &self,
        thread_id: u64,
        api: &ApiDef,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_completion(
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

    /// 完了待ちの非同期 I/O 操作を登録する（F27）。鍵は OVERLAPPED
    /// 構造体のアドレス。
    pub fn register_pending_overlapped(&self, overlapped_addr: u64, pending: PendingOverlapped) {
        self.pending_overlapped.register(overlapped_addr, pending);
    }

    /// 完了した非同期 I/O 操作を取り出す（F27）。未登録なら None。
    pub fn take_pending_overlapped(&self, overlapped_addr: u64) -> Option<PendingOverlapped> {
        self.pending_overlapped.take(overlapped_addr)
    }

    /// 完了待ちの操作の数（テスト用）。
    pub fn pending_overlapped_count(&self) -> usize {
        self.pending_overlapped.len()
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
    fn pending_overlapped_register_take_and_record_completion() {
        // F27: 登録した完了待ち操作は OVERLAPPED アドレスで取り出せ、
        // 完了イベントは元の API の leave Schema で Ring へ記録される。
        use crate::capture::{OverlappedDirection, PendingOverlapped};
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let tid = 4244u64;
        rt.ensure_thread(tid);
        let read = api_by_id(API_READ_FILE).unwrap();
        let call_id = rt.alloc_call_id();
        rt.register_pending_overlapped(
            0x8000,
            PendingOverlapped {
                api_id: API_READ_FILE,
                call_id,
                handle: 0x1234,
                buffer: 0x4000,
                requested_len: 100,
                direction: OverlappedDirection::Read,
                bytes_addr: 0x5000,
            },
        );
        assert_eq!(rt.pending_overlapped_count(), 1);
        let pending = rt.take_pending_overlapped(0x8000).expect("registered");
        assert_eq!(pending.call_id, call_id);
        assert_eq!(pending.direction, OverlappedDirection::Read);
        assert_eq!(rt.pending_overlapped_count(), 0);
        assert!(rt.take_pending_overlapped(0x8000).is_none());
        let r = rt.record_completion(tid, read, call_id, b"completed-args");
        assert!(matches!(r, RecordResult::Written(_)));
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallCompleted)
        );
        assert_eq!(batch.events[0].descriptor.schema_id, read.leave_schema_id());
        assert_eq!(batch.events[0].payload, b"completed-args");
    }

    #[test]
    fn call_guard_records_aborted_when_dropped_armed() {
        // L08: 元の呼び出しが戻らずにガードが drop されたら、
        // CallAborted が記録され、呼出スタックから外れる。
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4243u64;
        rt.ensure_thread(tid);
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let call_id = rt.alloc_call_id();
        assert!(matches!(
            rt.record_enter(tid, create, call_id, b"enter-args"),
            RecordResult::Written(_)
        ));
        push_call(call_id);
        {
            let _guard = CallGuard::new(&rt, tid, create, call_id);
            // 完了させずに drop（元の呼び出しが例外で中断したのと同じ）。
        }
        assert_eq!(current_parent_call(), 0, "aborted call pops the stack");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(shirusu_transport::descriptor::EventKind::CallAborted)
        );
        assert_eq!(batch.events[1].descriptor.call_id, call_id);
    }

    #[test]
    fn call_guard_completed_drop_records_nothing() {
        // L08: 正常に戻った呼び出しは complete() で武装解除し、
        // drop しても CallAborted は記録されない。
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4244u64;
        rt.ensure_thread(tid);
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let call_id = rt.alloc_call_id();
        rt.record_enter(tid, create, call_id, b"enter-args");
        push_call(call_id);
        {
            let mut guard = CallGuard::new(&rt, tid, create, call_id);
            guard.complete();
        }
        pop_call(call_id);
        rt.record_leave(tid, create, call_id, b"leave-args");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(shirusu_transport::descriptor::EventKind::CallLeave)
        );
    }

    #[test]
    fn call_guard_records_aborted_on_panic_and_panic_propagates() {
        // L08: 例外は捕捉しない。パニックがガードを巻き戻して抜けるとき
        // CallAborted が記録され、パニック自体はそのまま伝わる。
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4245u64;
        rt.ensure_thread(tid);
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let call_id = rt.alloc_call_id();
        rt.record_enter(tid, create, call_id, b"enter-args");
        push_call(call_id);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CallGuard::new(&rt, tid, create, call_id);
            panic!("simulated original-call exception");
        }));
        assert!(caught.is_err(), "the panic must propagate unchanged");
        assert_eq!(current_parent_call(), 0);
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(shirusu_transport::descriptor::EventKind::CallAborted)
        );
        assert_eq!(batch.events[1].descriptor.call_id, call_id);
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
    fn runtime_slot_allows_reattach_after_unregister() {
        // レビュー第5回 #7: init → shutdown → init の往復。
        let slot = RuntimeSlot::new();
        let (_a1, rt1) = runtime();
        let rt1 = Arc::new(rt1);
        let (_a2, rt2) = runtime();
        let rt2 = Arc::new(rt2);
        assert!(slot.current().is_none());
        assert!(slot.register(Arc::clone(&rt1)).is_ok());
        // アクティブな間は 2 つ目の登録は失敗する
        assert!(slot.register(Arc::clone(&rt2)).is_err());
        assert!(Arc::ptr_eq(&slot.current().unwrap(), &rt1));
        // 他人のランタイムでは解除できない
        assert!(!slot.unregister(&rt2));
        assert!(slot.current().is_some());
        // 自分のランタイムで解除すれば、次のセッションを受け入れる
        assert!(slot.unregister(&rt1));
        assert!(slot.current().is_none());
        assert!(slot.register(Arc::clone(&rt2)).is_ok());
        assert!(Arc::ptr_eq(&slot.current().unwrap(), &rt2));
    }

    #[test]
    fn runtime_slot_in_flight_holder_keeps_its_own_runtime() {
        // 進行中 Detour が掴んだ Arc は、登録が差し替わっても旧
        // セッションのランタイムを指し続ける (寿命と元の表の分離)。
        let slot = RuntimeSlot::new();
        let (_a1, rt1) = runtime();
        let rt1 = Arc::new(rt1);
        rt1.set_original(API_CREATE_FILE_W, 0xAAAA);
        let (_a2, rt2) = runtime();
        let rt2 = Arc::new(rt2);
        rt2.set_original(API_CREATE_FILE_W, 0xBBBB);
        assert!(slot.register(Arc::clone(&rt1)).is_ok());
        let held = slot.current().unwrap(); // Detour 入口で掴む Arc
        assert!(slot.unregister(&rt1));
        assert!(slot.register(Arc::clone(&rt2)).is_ok());
        // 掴んだ側は旧ランタイムの元の表を見続ける
        assert!(Arc::ptr_eq(&held, &rt1));
        assert_eq!(held.original(API_CREATE_FILE_W), 0xAAAA);
        // 新規の Detour は新ランタイムを見る
        assert_eq!(slot.current().unwrap().original(API_CREATE_FILE_W), 0xBBBB);
    }

    #[test]
    fn call_ids_do_not_collide_across_sessions() {
        // セッションをまたいだ Call ID の衝突防止 (シード分離)。
        let (_a1, rt1) = runtime();
        let (_a2, rt2) = runtime();
        let first1 = rt1.alloc_call_id();
        let first2 = rt2.alloc_call_id();
        assert_ne!(first1, first2);
        assert!(first2 >= 1 << 32 || first1 >= 1 << 32);
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

    #[test]
    fn reentrancy_guard_blocks_nested_entry() {
        // G15: 記録経路の実行中は、同じスレッドからの再入を素通しにする。
        assert!(!ReentrancyGuard::is_active());
        let guard = ReentrancyGuard::try_enter().expect("first entry");
        assert!(ReentrancyGuard::is_active());
        assert!(
            ReentrancyGuard::try_enter().is_none(),
            "nested entry is blocked"
        );
        drop(guard);
        assert!(!ReentrancyGuard::is_active());
        assert!(
            ReentrancyGuard::try_enter().is_some(),
            "re-entry after drop"
        );
    }

    #[test]
    fn reentrancy_guard_suspend_resume_allows_nested_entry() {
        // G15: 元の API 呼び出しの間（suspend 中）は、アプリ由来の入れ子
        // 呼び出しとして再び入れる (A43)。
        let mut guard = ReentrancyGuard::try_enter().expect("entry");
        guard.suspend();
        assert!(!ReentrancyGuard::is_active());
        let nested = ReentrancyGuard::try_enter().expect("nested entry while suspended");
        assert!(ReentrancyGuard::is_active());
        drop(nested);
        assert!(!ReentrancyGuard::is_active());
        guard.resume();
        assert!(ReentrancyGuard::is_active());
        assert!(ReentrancyGuard::try_enter().is_none());
        drop(guard);
        assert!(!ReentrancyGuard::is_active());
    }

    #[test]
    fn reentrancy_guard_drop_while_suspended_releases() {
        // suspend したまま drop してもガードは解除される。
        let mut guard = ReentrancyGuard::try_enter().expect("entry");
        guard.suspend();
        drop(guard);
        assert!(!ReentrancyGuard::is_active());
        assert!(ReentrancyGuard::try_enter().is_some());
    }

    #[test]
    fn reentrancy_guard_is_thread_local() {
        // 他スレッドのガードはこのスレッドに影響しない。
        let guard = ReentrancyGuard::try_enter().expect("entry");
        assert!(ReentrancyGuard::is_active());
        let other = std::thread::spawn(|| {
            assert!(!ReentrancyGuard::is_active());
            let g = ReentrancyGuard::try_enter().expect("other thread entry");
            assert!(ReentrancyGuard::is_active());
            drop(g);
            assert!(!ReentrancyGuard::is_active());
        });
        other.join().unwrap();
        assert!(ReentrancyGuard::is_active());
        drop(guard);
        assert!(!ReentrancyGuard::is_active());
    }

    #[test]
    fn reentrancy_guard_detour_flow_keeps_parent_chain() {
        // G15: Detour の一連の流れ（記録→元の呼び出し→記録）で、
        // ガードの suspend/resume が呼出スタックと Ring の内容を壊さない。
        let (agent, rt) = runtime();
        let tid = 5150u64;
        rt.ensure_thread(tid);
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let outer = rt.alloc_call_id();

        let mut guard = ReentrancyGuard::try_enter().expect("entry");
        let r = rt.record_enter(tid, create, outer, b"enter-args");
        assert!(matches!(r, RecordResult::Written(_)));
        push_call(outer);
        // 元の API 呼び出しの間: ガードを外し、アプリ由来の入れ子は入れる
        guard.suspend();
        assert!(!ReentrancyGuard::is_active());
        let nested = ReentrancyGuard::try_enter().expect("app nested call during original");
        assert_eq!(
            current_parent_call(),
            outer,
            "nested call sees outer as parent"
        );
        drop(nested);
        guard.resume();
        assert!(ReentrancyGuard::is_active());
        pop_call(outer);
        rt.record_leave(tid, create, outer, b"leave-args");
        drop(guard);
        assert!(!ReentrancyGuard::is_active());

        // Ring には外側の enter/leave だけが残る（入れ子の素通しは記録しない）
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert!(batch.integrity_error.is_none());
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].descriptor.call_id, outer);
        assert_eq!(batch.events[1].descriptor.call_id, outer);
    }
}
