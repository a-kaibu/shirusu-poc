//! shirusu-agent: 書き手側。スレッド毎 Ring の取得と書込み、再入ガード、Host 生存確認、DETACH 通知。
//! Hook 自体は実装範囲外（spec のクレート構成表）。ここは転送層への書込みまでを担う。
//!
//! 並行性 (R1): 記録の通常経路は全体ロックを取らない。書き手は Ring ごとに
//! 1 つで、各 OS スレッドは直前に使った書き手を TLS にキャッシュする。
//! 同じ論理スレッドの記録同士だけが書き手ごとの Mutex で直列化され
//! (SPSC の単一書き手の保証)、満杯 Ring の待機が他スレッドの記録を
//! 止めることはない。Slot の取得・登録・引退といった管理操作だけが
//! 登録表 (RwLock) を使い、ロックは取得・登録の間だけ保持する。
//!
//! 低水位時の非同期 Mapping 追加 (A70) は [`expansion`] モジュールの
//! 管理スレッドが担う。記録経路は登録も待機もしない。

pub mod expansion;
mod writer_cell;
use writer_cell::{Access, WriterCell};

pub use expansion::{ExpansionManager, ExpansionManagerHandle, ExpansionStats};

use shirusu_transport::clock::{system_clock, system_timestamp_source, Clock, TimestampSource};
use shirusu_transport::context::{should_record, CallOrigin, HostMonitor, PublishGuard};
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::expansion::{ExpansionDelivery, EXPANDED_SLOT_GENERATION};
use shirusu_transport::layout;
use shirusu_transport::notify::NotifySignal;
use shirusu_transport::ring::{
    EventInput, LoaderLockProbe, LoaderLockState, RingWriter, SharedRegion, WriteOutcome,
    WriterPolicy,
};
use shirusu_transport::slot::{SlotHandle, SlotPool};
use shirusu_transport::RingConfig;
use shirusu_transport_win::{EventClock, EventObject, HandleValue, RingNotify, SharedMapping};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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
    /// TLS キャッシュの照合用 ID (Agent インスタンスごとに一意)。
    id: u64,
    pool: Arc<SlotPool>,
    config: RingConfig,
    policy: WriterPolicy,
    loader_lock_state: LoaderLockState,
    loader_lock_probe: Option<LoaderLockProbe>,
    /// 書き手の既定 Clock (Ring ごとの `space_available` が結ばれていない
    /// Ring で使う)。`with_clock` で構築時に設定し、以後は不変。
    default_clock: Arc<dyn Clock>,
    /// イベント時刻専用の時刻源 (レビュー第2回・項目8)。待機用 Clock とは
    /// 分離し、全 Ring の刻印で共有する。既定は transport の
    /// `system_timestamp_source`。Windows の Agent は
    /// `with_timestamp_source` で QPC 実装に差し替える。
    timestamps: Arc<dyn TimestampSource>,
    /// Ring (論理スレッド) ごとに結ばれた `space_available` の EventClock
    /// (R7)。Host から受け取った Ring 単位の通知はここに保持し、その Ring の
    /// 書き手はこの Clock で待つ。他 Ring の書き手とは共有しない (auto-reset
    /// Event の取り違えを防ぐ)。書き手生成前なら保留し、生成時に結び、
    /// 生成後なら即座に書き手の Clock を差し替える。
    space_clocks: RwLock<HashMap<u64, Arc<EventClock>>>,
    host_monitor: Arc<HostMonitor>,
    /// 管理パス専用の登録表。record の通常経路はこのロックを取らない
    /// (TLS キャッシュで完結する)。低速経路でも読みロックは取得の間だけ。
    threads: RwLock<HashMap<u64, Arc<ThreadSlotState>>>,
    /// スレッド終了済みで、Host の drain 完了を待つ Slot の保持
    /// (レビュー #6 P1-4)。状態 (領域と書き手) を生かしたまま保持し、
    /// Ring が drain されたことを共有 Control で確認できたら
    /// [`Agent::poll_reclaims`] が Slot を回収する。ここで保持する間、
    /// 領域は解放されない。
    pending_reclaim: Mutex<Vec<Arc<ThreadSlotState>>>,
    /// 追加 Slot (A70) へ紐付けた Mapping の登録表 (Slot index → Mapping)。
    /// 管理スレッドだけが書き込む。ThreadSlotState が drop されても
    /// (thread_forget / Slot 再利用)、Slot への紐付けは残る。
    /// フィールドの破棄順に注意: `threads` より後に宣言し、書き手状態が
    /// 先に破棄されてから Mapping の保持を解く。
    expanded_regions: Arc<Mutex<HashMap<usize, ExpandedRegion>>>,
    /// 公開済み追加 Slot の Mapping base の追記専用リスト。記録経路
    /// (Slot を持てないスレッドの欠落掲示) はロックを取らずにここを読む。
    /// TerminateThread されたスレッドがロックを握ったまま消えると、そのロックは
    /// 二度と解けないため (外部レビュー S1)。
    published_bases: PublishedBases,
    /// Slot を持てなかったスレッドの Ring の受け渡し口 (外部レビュー S1)。
    /// そのスレッドは記録の途中で自分の Ring を作らない (登録表のロックと
    /// Heap を使い、そこで強制終了されるとロックが残る)。要求をロックなしで
    /// 置き、登録・終了・回収をする別のスレッドが Ring を作って置き、要求した
    /// スレッドがロックなしで受け取る。
    adoptions: Adoptions,
    /// `--order=global` (L11) が有効かどうか。`with_order_global` で
    /// 構築時に設定し、以後は不変。Host は Bootstrap / セッション設定から
    /// 決める。無効な間は Descriptor の `global_order` は 0 のまま。
    order_global: bool,
    /// 全スレッド共通の観測順序カウンタ (L11)。`record` で書き込みが
    /// 確定する直前に 1 つ採番する。1 始まり（0 は未割当）。
    next_global_order: AtomicU64,
    /// [`Agent::reap_due`] の前回時刻 (ms)。
    last_reap_ms: AtomicU64,
}

/// 追加 Slot (A70) へ紐付けた Mapping。Slot の index ごとに Agent が保持する。
enum ExpandedRegion {
    /// プロセス内: Host の Mapping の base を借りる。Mapping 自体は Host の
    /// ExpansionService が保持する間だけ有効。
    Borrowed { base: *mut u8 },
    /// Windows プロセス間: duplicate されたハンドルから作った自分の写像。
    Owned(SharedMapping),
}
// SAFETY: `Borrowed` の base は Host が保持する Mapping の有効なビューで、
// Agent が登録を終えた後も Host のサービスが生存する間は有効。
// `Owned` の SharedMapping は Send である。紐付け表は Mutex の内側でのみ
// 触り、base へのアクセスは SPSC の公開プロトコル経由に限る。
unsafe impl Send for ExpandedRegion {}

/// 追加 Slot の Mapping base を並べた追記専用の連結リスト。管理スレッドが
/// CAS で先頭へ足し、記録経路は Acquire で辿るだけ (ロックなし)。要素は
/// Agent の破棄まで外さない。base は `expanded_regions` (Owned) または Host
/// のサービス (Borrowed) が Agent より長く保持する。
struct PublishedBases {
    head: AtomicPtr<PublishedBase>,
}
struct PublishedBase {
    base: *mut u8,
    next: *mut PublishedBase,
}
impl PublishedBases {
    fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
    /// 管理パス専用 (Heap 確保を伴う)。
    fn push(&self, base: *mut u8) {
        let node = Box::into_raw(Box::new(PublishedBase {
            base,
            next: std::ptr::null_mut(),
        }));
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            // SAFETY: node は直前に確保した未公開の要素で、この関数だけが触る。
            unsafe { (*node).next = head };
            match self
                .head
                .compare_exchange_weak(head, node, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(current) => head = current,
            }
        }
    }
    /// ロックも確保もしない走査。
    fn for_each(&self, mut f: impl FnMut(*mut u8)) {
        let mut cur = self.head.load(Ordering::Acquire);
        while !cur.is_null() {
            // SAFETY: 公開された要素は Agent の破棄まで解放されない。
            let node = unsafe { &*cur };
            f(node.base);
            cur = node.next;
        }
    }
}
impl Drop for PublishedBases {
    fn drop(&mut self) {
        let mut cur = *self.head.get_mut();
        while !cur.is_null() {
            // SAFETY: &mut self により他の参照は無く、各要素は push の Box。
            let node = unsafe { Box::from_raw(cur) };
            cur = node.next;
        }
    }
}
// SAFETY: base は共有 Mapping のビューで、アクセスは layout の原子操作に限る。
unsafe impl Send for PublishedBases {}
unsafe impl Sync for PublishedBases {}

/// 受け渡し口の数。埋まっていれば要求は置けず、そのスレッドは記録されない
/// まま (欠落として数える) 次の機会を待つ。
const ADOPTION_CELLS: usize = 64;

/// Slot を持てなかったスレッドへ、別のスレッドが作った Ring を渡す口。
/// `tid` が 0 なら空き。要求したスレッドだけが `tid` を 0 へ戻す。`state` は
/// `Arc::into_raw` の値で、作る側が null から CAS で置き、要求側が swap で
/// 取り出す。どちらもロックも Heap も使わない。
struct Adoptions {
    cells: [AdoptionCell; ADOPTION_CELLS],
}
struct AdoptionCell {
    tid: AtomicU64,
    state: AtomicPtr<ThreadSlotState>,
}
impl Adoptions {
    fn new() -> Self {
        Self {
            cells: std::array::from_fn(|_| AdoptionCell {
                tid: AtomicU64::new(0),
                state: AtomicPtr::new(std::ptr::null_mut()),
            }),
        }
    }
    /// 要求を置く (既にあれば何もしない)。置けなければ false。
    fn request(&self, thread_id: u64) -> bool {
        if self
            .cells
            .iter()
            .any(|c| c.tid.load(Ordering::Acquire) == thread_id)
        {
            return true;
        }
        self.cells.iter().any(|c| {
            c.tid
                .compare_exchange(0, thread_id, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        })
    }
    /// 自分宛てに置かれた Ring を受け取り、口を空ける。
    fn take(&self, thread_id: u64) -> Option<Arc<ThreadSlotState>> {
        for c in &self.cells {
            if c.tid.load(Ordering::Acquire) != thread_id {
                continue;
            }
            let ptr = c.state.swap(std::ptr::null_mut(), Ordering::AcqRel);
            if ptr.is_null() {
                return None;
            }
            c.tid.store(0, Ordering::Release);
            // SAFETY: ptr は `offer` が Arc::into_raw で置いた値で、swap に
            // より取り出したのはこのスレッドだけ。
            return Some(unsafe { Arc::from_raw(ptr) });
        }
        None
    }
    /// 受け取り手を待つ要求の thread id (管理パス用)。
    fn waiting(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.cells.iter().enumerate().filter_map(|(i, c)| {
            let tid = c.tid.load(Ordering::Acquire);
            (tid != 0 && c.state.load(Ordering::Acquire).is_null()).then_some((i, tid))
        })
    }
    /// 作った Ring を口へ置く。別の作り手が先に置いていれば渡さない。
    fn offer(&self, index: usize, thread_id: u64, state: Arc<ThreadSlotState>) {
        let c = &self.cells[index];
        if c.tid.load(Ordering::Acquire) != thread_id {
            return;
        }
        let ptr = Arc::into_raw(state) as *mut ThreadSlotState;
        if c.state
            .compare_exchange(
                std::ptr::null_mut(),
                ptr,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // SAFETY: 置けなかった ptr はこの関数だけが持つ。
            drop(unsafe { Arc::from_raw(ptr) });
        }
    }
    /// 通常の登録で Ring を得たスレッド (同じ ID の再利用を含む) 宛ての
    /// 要求と、置かれたままの Ring を片付ける。
    fn clear(&self, thread_id: u64) {
        for c in &self.cells {
            if c.tid.load(Ordering::Acquire) != thread_id {
                continue;
            }
            let ptr = c.state.swap(std::ptr::null_mut(), Ordering::AcqRel);
            if !ptr.is_null() {
                // SAFETY: swap で取り出した into_raw の値。
                drop(unsafe { Arc::from_raw(ptr) });
            }
            let _ = c
                .tid
                .compare_exchange(thread_id, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}
impl Drop for Adoptions {
    fn drop(&mut self) {
        for c in &mut self.cells {
            let ptr = *c.state.get_mut();
            if !ptr.is_null() {
                // SAFETY: &mut self により他の参照は無い。
                drop(unsafe { Arc::from_raw(ptr) });
            }
        }
    }
}

/// スレッドの Ring の裏付け。初期 Slot は Agent が作るローカル領域、
/// 追加 Slot は Host から配送された Mapping (A70)。
enum RegionBacking {
    /// Agent が確保したローカル領域 (初期 Slot)。
    Owned(Box<SharedRegion>),
    /// 追加 Slot の Mapping のビュー。実体は Agent の登録表
    /// (`expanded_regions`) または Host のサービスが保持する。
    /// `init_control` は claim 時に済ませてある。
    Mapped { base: *mut u8 },
}
impl RegionBacking {
    fn base(&self) -> *mut u8 {
        match self {
            Self::Owned(r) => r.base(),
            Self::Mapped { base } => *base,
        }
    }
    /// # Safety
    /// `base` は config 分の共有領域を指し、この裏付けの存続期間中有効で
    /// あること (呼び出し側は `begin_thread_state` の契約で保証する)。
    unsafe fn writer(
        &self,
        config: RingConfig,
        policy: WriterPolicy,
        clock: Arc<dyn Clock>,
        timestamps: Arc<dyn TimestampSource>,
    ) -> RingWriter {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe { RingWriter::new_with_timestamps(self.base(), config, policy, clock, timestamps) }
    }
}
// SAFETY: `Mapped` の base が指す共有メモリへのアクセスは、書き手側の
// SPSC 公開プロトコル (単一書き手) と Host 側の検証付き読取りに限る。
// `Owned` の SharedRegion と同格のモデルである。
unsafe impl Send for RegionBacking {}
unsafe impl Sync for RegionBacking {}

/// スレッド (Ring) ごとの書き手状態。`Arc` で共有し、TLS キャッシュと
/// 登録表の両方から指す。
struct ThreadSlotState {
    handle: SlotHandle,
    // SharedRegion は writer より長生きさせるためここに保持する。
    region: RegionBacking,
    /// 書き手は Ring ごとに 1 つだけ。記録する OS スレッドは原子的な
    /// 読み書き更新なしの高速経路で使い、他のスレッド (管理パスや同じ
    /// 論理スレッドを名乗る別スレッド) は排他経路で使う。SPSC の単一
    /// 書き手はこの排他で保証する (`writer_cell`)。
    writer: WriterCell,
    /// thread_forget で引退済みにされたか。TLS キャッシュや取得途中の
    /// 状態が、引退後の領域へ書き続けないための印。
    retired: AtomicBool,
}

static NEXT_AGENT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// OS スレッドごとに「直前に使った書き手」を 1 件だけキャッシュする。
    /// 借用は取得・格納の瞬間と、キャッシュ経由の 1 回の記録の間だけ。
    static TLS_STATE: TlsCache = const { TlsCache(RefCell::new(None)) };
    /// Slot を取れなかったスレッドの否定キャッシュ (P1-1):
    /// (agent id, thread id, 失敗時の free epoch, 以後の欠落数)。
    /// 空きが出る (epoch が進む) まで登録表と Slot の走査を繰り返さない。
    static NO_SLOT: Cell<(u64, u64, u64, u64)> = const { Cell::new((0, 0, 0, 0)) };
}

/// 否定キャッシュ中でも、この回数ごとに 1 回は取得をやり直す。
const NO_SLOT_RETRY_INTERVAL: u64 = 4096;
/// 否定キャッシュ中の欠落を、この回数ごとに共有 Control へ掲示する。
const NO_SLOT_PUBLISH_INTERVAL: u64 = 256;

/// The cached writer state; its destructor tells the hook layer that this
/// thread's capture TLS is going away (see [`set_thread_teardown_hook`]).
struct TlsCache(RefCell<Option<CachedState>>);
impl std::ops::Deref for TlsCache {
    type Target = RefCell<Option<CachedState>>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for TlsCache {
    fn drop(&mut self) {
        let hook = TEARDOWN_HOOK.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: only `set_thread_teardown_hook` stores here, from a `fn()`.
            let hook: fn() = unsafe { std::mem::transmute::<usize, fn()>(hook) };
            hook();
        }
    }
}

static TEARDOWN_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Run `hook` on a thread when its Agent writer cache starts destruction,
/// before [`current_thread_capture_available`] turns false there. The hook
/// layer uses it to drop a per-thread "all capture TLS alive" shortcut.
pub fn set_thread_teardown_hook(hook: fn()) {
    TEARDOWN_HOOK.store(hook as usize, Ordering::Release);
}

/// The thread's last-used writer: (Agent ID, logical thread ID, state), plus
/// this thread's [`PublishGuard`] depth counter, so the record fast path
/// reaches both through one thread-local access in this crate.
struct CachedState {
    agent: u64,
    thread_id: u64,
    state: Arc<ThreadSlotState>,
    publish_depth: *const Cell<u32>,
}

/// The publish section on a cached depth counter; same counting as
/// [`PublishGuard`].
struct PublishSection<'a>(&'a Cell<u32>);
impl<'a> PublishSection<'a> {
    #[inline(always)]
    fn enter(depth: &'a Cell<u32>) -> Self {
        depth.set(depth.get() + 1);
        Self(depth)
    }
}
impl Drop for PublishSection<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// Capture must not re-enter the Agent after its thread-local writer cache has
/// started destruction (for example through an intercepted HeapFree).
pub fn current_thread_capture_available() -> bool {
    TLS_STATE.try_with(|_| ()).is_ok()
}

impl Agent {
    pub fn new(pool: Arc<SlotPool>, config: RingConfig, host_monitor: Arc<HostMonitor>) -> Self {
        Self {
            id: NEXT_AGENT_ID.fetch_add(1, Ordering::Relaxed),
            pool,
            config,
            policy: WriterPolicy::default(),
            loader_lock_state: LoaderLockState::NotHeld,
            loader_lock_probe: None,
            default_clock: system_clock(),
            timestamps: system_timestamp_source(),
            space_clocks: RwLock::new(HashMap::new()),
            host_monitor,
            threads: RwLock::new(HashMap::new()),
            pending_reclaim: Mutex::new(Vec::new()),
            expanded_regions: Arc::new(Mutex::new(HashMap::new())),
            published_bases: PublishedBases::new(),
            adoptions: Adoptions::new(),
            order_global: false,
            next_global_order: AtomicU64::new(1),
            last_reap_ms: AtomicU64::new(0),
        }
    }
    /// `--order=global` (L11) を有効にする。フックの観測点ごとに
    /// 全スレッド共通の番号を振り、Descriptor の `global_order` に刻む。
    /// 番号はアトミックカウンタの更新順であり、API 処理の完了順や
    /// メモリ操作全体の順序を保証しない。
    pub fn with_order_global(mut self, enabled: bool) -> Self {
        self.order_global = enabled;
        self
    }
    pub fn with_policy(mut self, policy: WriterPolicy) -> Self {
        self.policy = policy;
        self
    }
    /// Assumption applied to every writer, including mapped/expanded slots.
    /// API hooks without a per-call proof must use Unknown, so the default
    /// zero-wait-on-unknown policy applies even when the Ring is full.
    pub fn with_loader_lock_state(mut self, state: LoaderLockState) -> Self {
        self.loader_lock_state = state;
        self
    }
    /// With `Unknown`, ask `probe` before a full Ring waits for space, so a
    /// write proven outside Loader Lock can wait instead of dropping.
    pub fn with_loader_lock_probe(mut self, probe: LoaderLockProbe) -> Self {
        self.loader_lock_probe = Some(probe);
        self
    }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.default_clock = clock;
        self
    }
    /// イベント時刻源を設定する (レビュー第2回・項目8)。Windows では
    /// `shirusu_transport_win::QpcTimestampSource` を渡し、刻印を本物の
    /// QPC 値にする。待機用 Clock の設定 (`with_clock`) とは独立。
    pub fn with_timestamp_source(mut self, timestamps: Arc<dyn TimestampSource>) -> Self {
        self.timestamps = timestamps;
        self
    }
    /// Host からその Ring の `space_available` を受け取る（A68 + R7）。
    /// `notify` は Host 側の `RingNotify` と同じ OS イベントを指すもの
    /// （プロセス内共有の場合は同じ `Arc`、プロセス間の場合は Host が
    /// `duplicate_space_to_process` で渡したハンドルから
    /// `attach_space_available` で作ったもの）であること。
    ///
    /// 通知は Ring 単位なので、受け取りも Ring (論理スレッド) ごとに行う。
    /// 返した `EventClock` はその Ring の書き手専用のもので、`sleep_calls()`
    /// で待機の実績を観測できる。書き手が既にあれば即座に Clock を差し替え、
    /// 無ければ保留して生成時に結ぶ。他の Ring には影響しない。
    pub fn attach_space_available_notify(
        &self,
        thread_id: u64,
        notify: Arc<RingNotify>,
    ) -> Option<Arc<EventClock>> {
        let clock = Arc::new(EventClock::new(notify));
        self.space_clocks
            .write()
            .unwrap()
            .insert(thread_id, Arc::clone(&clock));
        let state = self.threads.read().unwrap().get(&thread_id).cloned();
        if let Some(state) = state {
            if !state.retired.load(Ordering::Acquire) {
                let _ = state
                    .writer
                    .exclusive(|w| w.set_clock(Arc::clone(&clock) as Arc<dyn Clock>));
            }
        }
        Some(clock)
    }
    /// Host からその Ring の `space_available` ハンドルを受け取る
    /// （A68、プロセス間経路）。`handle_value` はこのプロセスで有効な
    /// Event ハンドルであること（Host が
    /// `NotifyingDrainWorker::duplicate_space_to_process` で渡した値、
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
        thread_id: u64,
        handle_value: HandleValue,
    ) -> Option<Arc<EventClock>> {
        let notify = Arc::new(RingNotify {
            space_available: EventObject::from_handle_value(handle_value, true),
        });
        self.attach_space_available_notify(thread_id, notify)
    }
    /// その Ring に `space_available` を受け取り済みかどうか。
    pub fn space_available_attached(&self, thread_id: u64) -> bool {
        self.space_clocks.read().unwrap().contains_key(&thread_id)
    }
    pub fn pool(&self) -> &Arc<SlotPool> {
        &self.pool
    }
    pub fn host_monitor(&self) -> &Arc<HostMonitor> {
        &self.host_monitor
    }

    /// スレッドの書き手状態を得る。高速経路は TLS キャッシュ (全体ロック
    /// なし)、低速経路は登録表の読みロック (取得の間だけ)、どちらにも
    /// 無ければ管理パスで Slot と Ring を作る。Slot が取れなければ None。
    fn state_for(&self, thread_id: u64) -> Option<Arc<ThreadSlotState>> {
        let cached = TLS_STATE
            .try_with(|c| {
                let c = c.borrow();
                match &*c {
                    Some(c)
                        if c.agent == self.id
                            && c.thread_id == thread_id
                            && !c.state.retired.load(Ordering::Acquire) =>
                    {
                        Some(Arc::clone(&c.state))
                    }
                    _ => None,
                }
            })
            .ok()?;
        if let Some(s) = cached {
            return Some(s);
        }
        let epoch = self.pool.free_epoch();
        let no_slot = NO_SLOT
            .try_with(Cell::get)
            .ok()
            .filter(|&(agent, tid, _, _)| agent == self.id && tid == thread_id);
        let state = if let Some((agent, tid, failed_epoch, misses)) = no_slot {
            // Slot を持てなかったスレッド: 記録の途中なので、登録表にも Heap
            // にも触れない。別のスレッドが作った Ring を受け取れれば使う。
            let retry = failed_epoch != epoch || misses % NO_SLOT_RETRY_INTERVAL == 0;
            let adopted = if retry {
                let adopted = self.adoptions.take(thread_id);
                if adopted.is_none() {
                    let _ = self.adoptions.request(thread_id);
                }
                adopted
            } else {
                None
            };
            match adopted {
                Some(state) if !state.retired.load(Ordering::Acquire) => state,
                _ => {
                    let total = self.pool.note_missing_call();
                    let misses = misses + 1;
                    let _ = NO_SLOT.try_with(|c| c.set((agent, tid, epoch, misses)));
                    if misses % NO_SLOT_PUBLISH_INTERVAL == 0 {
                        self.publish_missing_calls_total(total);
                    }
                    return None;
                }
            }
        } else {
            // 初回の登録 (管理パス): ついでに Slot を待つ他のスレッドの Ring を
            // 作って渡す。
            let found = self.state_for_slow(thread_id);
            if found.is_some() {
                self.adoptions.clear(thread_id);
            }
            self.serve_adoptions();
            let Some(state) = found else {
                let _ = NO_SLOT.try_with(|c| c.set((self.id, thread_id, epoch, 1)));
                let _ = self.adoptions.request(thread_id);
                self.publish_missing_calls();
                return None;
            };
            state
        };
        let _ = NO_SLOT.try_with(|c| {
            if c.get().0 == self.id && c.get().1 == thread_id {
                c.set((0, 0, 0, 0));
            }
        });
        TLS_STATE
            .try_with(|c| {
                *c.borrow_mut() = Some(CachedState {
                    agent: self.id,
                    thread_id,
                    state: Arc::clone(&state),
                    publish_depth: PublishGuard::depth_cell(),
                });
            })
            .ok()?;
        Some(state)
    }
    /// Whether the calling OS thread already records for `thread_id` through
    /// its own live Ring (its cached state, not retired, owned by it). Reads
    /// only thread-local state and atomics: a recording thread asked to
    /// confirm its registration takes no lock, so being terminated there
    /// cannot leave one held.
    pub fn current_thread_registered(&self, thread_id: u64) -> bool {
        TLS_STATE
            .try_with(|c| {
                c.try_borrow().ok().is_some_and(|c| {
                    c.as_ref().is_some_and(|c| {
                        c.agent == self.id
                            && c.thread_id == thread_id
                            && !c.state.retired.load(Ordering::Acquire)
                            && c.state.writer.owned_by_current_thread()
                    })
                })
            })
            .unwrap_or(false)
    }
    /// 管理パス: Slot を待つスレッドの Ring を作って受け渡し口へ置く
    /// (登録・終了・回収をするスレッドが呼ぶ。記録中のスレッドは呼ばない)。
    /// 作った Ring の書き手は、受け取ったスレッドが最初に書くときに所有する。
    /// 渡した数を返す。
    pub fn serve_adoptions(&self) -> usize {
        let mut served = 0;
        for (index, tid) in self.adoptions.waiting() {
            if self.pool.free_count() == 0 {
                break;
            }
            if let Some(state) = self.begin_thread_state(tid) {
                self.adoptions.offer(index, tid, state);
                served += 1;
            }
        }
        served
    }
    fn state_for_slow(&self, thread_id: u64) -> Option<Arc<ThreadSlotState>> {
        let found = self.threads.read().unwrap().get(&thread_id).cloned();
        if let Some(s) = found {
            if !s.retired.load(Ordering::Acquire) {
                if !s.writer.owner_terminated() {
                    return Some(s);
                }
                // The OS reused the ID of a thread that ended without an exit
                // notice (TerminateThread). Retire its Ring now, while this
                // thread starts, instead of writing through the dead owner's
                // writer and swapping states later in the middle of recording.
                self.reap_thread(thread_id, &s);
            }
        }
        self.begin_thread_state(thread_id)
    }
    /// 管理スレッド専用: Host から配送された Mapping を SlotPool へ登録する
    /// (A70)。記録経路はこのメソッドを呼ばない。
    ///
    /// 手順: まず配送を解決する (base を借りるか、ハンドル値から自分の写像を
    /// 作る)。解決できなければ Slot は追加しない。次に Slot を取得不能
    /// (PREPARING) で追加し (上限を超えれば Err)、Mapping を Slot の
    /// index へ紐付けてから、最後に FREE を公開する。公開前の Slot は
    /// claim できないため、「Mapping 未登録の Slot を別スレッドが取得
    /// してローカル領域で記録を始める」競合は起きない (レビュー #4
    /// の #10)。追加 Slot は generation 0 から始まる。
    pub(crate) fn register_expanded_mapping(
        &self,
        delivery: ExpansionDelivery,
    ) -> Result<usize, ()> {
        if delivery.generation != EXPANDED_SLOT_GENERATION {
            return Err(());
        }
        if delivery.len < self.config.required_len() {
            return Err(());
        }
        let region = match (delivery.base, delivery.handle_value) {
            (Some(base), _) => ExpandedRegion::Borrowed { base },
            (None, Some(handle)) => {
                // Windows プロセス間: duplicate されたハンドルから自分の写像を
                // 作る。スタブでは Unsupported で失敗する。
                // SAFETY: handle は Host が duplicate して渡した有効な
                // File Mapping ハンドルであること (呼び出し側の契約)。
                match unsafe { SharedMapping::from_handle_value(handle, delivery.len) } {
                    Ok(mapping) => ExpandedRegion::Owned(mapping),
                    Err(_) => return Err(()),
                }
            }
            (None, None) => return Err(()),
        };
        let base = match &region {
            ExpandedRegion::Borrowed { base } => *base,
            ExpandedRegion::Owned(mapping) => mapping.as_ptr(),
        };
        let index = self.pool.add_slot().ok_or(())?;
        self.expanded_regions.lock().unwrap().insert(index, region);
        if !self.pool.publish_slot(index) {
            // 公開に失敗したら紐付けを取り消す (Slot は PREPARING のまま
            // 残るため claim はされず、記録が誤って始まることはない)。
            self.expanded_regions.lock().unwrap().remove(&index);
            return Err(());
        }
        self.published_bases.push(base);
        // 管理パス: 新しい Slot を、待っているスレッドへ回す。
        self.serve_adoptions();
        Ok(index)
    }
    /// プロセス全体の欠落呼び出し数を、Host が読める全 Mapping の Control
    /// へ掲示する (P1-1)。Slot を持てないスレッドには自分の Ring が無い
    /// ため、Host はこの掲示から Capture Coverage の欠落を知る。
    /// 記録できなかった呼び出しを 1 件数える（Slot 不足以外の理由。
    /// 例: 確保失敗後の素通し、レビュー 2026-11-14 P2-9）。Host へは
    /// Slot 不足と同じ掲示で届く。
    pub fn note_missing_call(&self) {
        let total = self.pool.note_missing_call();
        if total == 1 || total.is_multiple_of(NO_SLOT_PUBLISH_INTERVAL) {
            self.publish_missing_calls_total(total);
        }
    }
    pub fn publish_missing_calls(&self) {
        self.publish_missing_calls_total(self.pool.missing_calls());
    }
    fn publish_missing_calls_total(&self, total: u64) {
        if total == 0 {
            return;
        }
        // ロックを取らない: このメソッドは Slot を持てない記録スレッドから
        // 呼ばれ、そのスレッドが強制終了されてもロックが残らないようにする。
        self.published_bases
            .for_each(|base| layout::publish_process_missing_calls(base, total));
    }
    /// 管理パス: Host から配送された Mapping を Slot として登録する公開
    /// 入口（本体は A70 の管理スレッド経路と同じ `register_expanded_mapping`）。
    /// Agent DLL の Bootstrap 初期化が使う。記録経路からは呼ばない。
    /// 登録できれば Slot の index、配送が不正なら None を返す。
    pub fn register_slot_mapping(&self, delivery: ExpansionDelivery) -> Option<usize> {
        self.register_expanded_mapping(delivery).ok()
    }
    /// 管理パス: Slot を取得し、共有領域と書き手を作って登録する。
    /// 登録表の書きロックはこの初期化の間だけ保持する (記録経路ではない)。
    fn begin_thread_state(&self, thread_id: u64) -> Option<Arc<ThreadSlotState>> {
        let mut map = self.threads.write().unwrap();
        if let Some(s) = map.get(&thread_id) {
            if !s.retired.load(Ordering::Acquire) {
                return Some(Arc::clone(s));
            }
        }
        let handle = self.pool.claim(thread_id)?;
        // 追加 Slot に Mapping が紐付いていればそれを使い、無ければローカル
        // 領域を作る。Mapping の Control 領域はここで初期化する (生成者は
        // Agent)。紐付けは Slot の index に残るため、再利用時も同じ
        // Mapping を使う。
        let region = {
            let expanded = self.expanded_regions.lock().unwrap();
            match expanded.get(&handle.index) {
                Some(ExpandedRegion::Borrowed { base }) => {
                    let base = *base;
                    layout::init_control(base, self.config, handle.generation, thread_id);
                    RegionBacking::Mapped { base }
                }
                Some(ExpandedRegion::Owned(mapping)) => {
                    let base = mapping.as_ptr();
                    layout::init_control(base, self.config, handle.generation, thread_id);
                    RegionBacking::Mapped { base }
                }
                None => RegionBacking::Owned(Box::new(SharedRegion::new(
                    self.config,
                    handle.generation,
                    thread_id,
                ))),
            }
        };
        // Ring ごとの space_available が結ばれていればその EventClock を、
        // 無ければ既定 Clock を使う (R7)。
        let clock = self
            .space_clocks
            .read()
            .unwrap()
            .get(&thread_id)
            .map(|c| Arc::clone(c) as Arc<dyn Clock>)
            .unwrap_or_else(|| Arc::clone(&self.default_clock));
        // SAFETY: region の base は config 分の共有領域を指し、
        // ThreadSlotState の生存期間中有効である。
        let mut writer = unsafe {
            region.writer(
                self.config,
                self.policy.clone(),
                clock,
                Arc::clone(&self.timestamps),
            )
        };
        writer.set_loader_lock_state(self.loader_lock_state);
        writer.set_loader_lock_probe(self.loader_lock_probe);
        let state = Arc::new(ThreadSlotState {
            handle,
            region,
            writer: WriterCell::new(writer),
            retired: AtomicBool::new(false),
        });
        map.insert(thread_id, Arc::clone(&state));
        Some(state)
    }

    /// スレッドが初めて記録するときに Slot と Ring を取得する。
    pub fn thread_begin(&self, thread_id: u64) -> Option<SlotHandle> {
        self.state_for(thread_id).map(|s| s.handle)
    }

    /// テスト/Host 連携用: スレッドの共有領域ベースポインタを返す。
    ///
    /// # Safety
    /// 返したポインタは ThreadSlotState が保持する領域を指す。thread_end で解放された後は使えない。
    pub unsafe fn thread_region_base(&self, thread_id: u64) -> Option<*mut u8> {
        let map = self.threads.read().unwrap();
        map.get(&thread_id).map(|s| s.region.base())
    }
    pub fn thread_config(&self) -> RingConfig {
        self.config
    }

    /// 呼び出しを記録する。再入ガードは公開区間だけに適用される（ring の publish 内相当を
    /// ここでも明示し、元の API 呼出に相当する処理の前には外れていることを型で示す）。
    ///
    /// 通常経路は全体ロックを取らない (R1): 書き手の取得は TLS キャッシュ
    /// または登録表の短い読みロックで済み、書き込み中はその Ring の書き手
    /// Mutex だけを保持する。満杯 Ring の待機が他スレッドを止めることはない。
    ///
    /// Not `#[inline]`: compiled in this crate, its thread-local accesses
    /// (the writer cache and the writer cell's owner token) are inline. A
    /// copy instantiated in a caller's crate reaches each through a call on
    /// Windows without LTO.
    pub fn record(&self, thread_id: u64, origin: CallOrigin, input: EventInput) -> RecordResult {
        if origin == CallOrigin::AgentInternal {
            return RecordResult::SkippedAgentInternal;
        }
        // Fast path: write through the TLS-cached state without cloning its
        // Arc (no shared reference-count traffic per event). Only nested
        // records could reach TLS_STATE meanwhile, and the publish depth
        // rejects those before they write.
        let cached = TLS_STATE
            .try_with(|c| {
                let c = c.try_borrow().ok()?;
                match &*c {
                    Some(c)
                        if c.agent == self.id
                            && c.thread_id == thread_id
                            && !c.state.retired.load(Ordering::Acquire) =>
                    {
                        // SAFETY: the cache is this thread's, and so is the
                        // counter it stored (valid for the thread's lifetime).
                        let depth = unsafe { &*c.publish_depth };
                        Some(if depth.get() > 0 {
                            RecordResult::SkippedAgentInternal
                        } else if !self.host_monitor.recording_enabled() {
                            RecordResult::PassthroughHostStopped
                        } else {
                            self.write_to(&c.state, depth, input.clone())
                        })
                    }
                    _ => None,
                }
            })
            .ok()
            .flatten();
        if let Some(result) = cached {
            return result;
        }
        self.record_uncached(thread_id, input)
    }

    /// Record one captured Application event and report only whether the
    /// Host should be woken: the hot path of the hook's detours.
    ///
    /// Same semantics as [`Agent::record`] with `CallOrigin::Application` and
    /// `CaptureState::Captured`, without building an [`EventInput`] or
    /// returning a [`RecordResult`] through memory on the common path (cached
    /// writer, owner fast path, room in the Ring). Everything else goes
    /// through `record`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_captured(
        &self,
        thread_id: u64,
        kind: EventKind,
        api_id: u32,
        schema_id: u32,
        call_id: u64,
        parent: u64,
        payload: &[u8],
    ) -> bool {
        let fast = TLS_STATE.try_with(|c| {
            let c = c.try_borrow().ok()?;
            let c = c.as_ref()?;
            if c.agent != self.id
                || c.thread_id != thread_id
                || c.state.retired.load(Ordering::Acquire)
            {
                return None;
            }
            // SAFETY: this thread's counter, stored with its cache.
            let depth = unsafe { &*c.publish_depth };
            if depth.get() > 0 {
                return Some(false); // nested inside a publication: skipped
            }
            if !self.host_monitor.recording_enabled() || self.order_global {
                return None;
            }
            let mut writer = c.state.writer.try_owner()?;
            if writer.is_detached() {
                return None;
            }
            let _guard = PublishSection::enter(depth);
            match writer.write_captured(kind, api_id, schema_id, call_id, parent, 0, payload) {
                WriteOutcome::Published { notify, .. } => Some(notify != NotifySignal::None),
                // Degraded and dropped writes already happened; the Host
                // liveness check that `record` adds for them follows below.
                other => Some(self.after_abnormal_write(&other)),
            }
        });
        match fast {
            Ok(Some(notify)) => notify,
            _ => self
                .record_captured_slow(thread_id, kind, api_id, schema_id, call_id, parent, payload),
        }
    }

    #[cold]
    #[inline(never)]
    fn after_abnormal_write(&self, outcome: &WriteOutcome) -> bool {
        let _ = self.host_monitor.check_on_abnormal_path();
        matches!(
            outcome,
            WriteOutcome::PublishedDegraded { notify, .. } if *notify != NotifySignal::None
        )
    }

    #[cold]
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn record_captured_slow(
        &self,
        thread_id: u64,
        kind: EventKind,
        api_id: u32,
        schema_id: u32,
        call_id: u64,
        parent: u64,
        payload: &[u8],
    ) -> bool {
        let result = self.record(
            thread_id,
            CallOrigin::Application,
            EventInput {
                kind,
                api_id,
                schema_id,
                call_id,
                parent_call_id: parent,
                payload,
                capture_state: CaptureState::Captured,
                global_order: 0,
            },
        );
        matches!(
            result,
            RecordResult::Written(
                WriteOutcome::Published { notify, .. }
                    | WriteOutcome::PublishedDegraded { notify, .. }
            ) if notify != NotifySignal::None
        )
    }

    /// First record of a thread, or one after its cached state retired.
    #[cold]
    #[inline(never)]
    fn record_uncached(&self, thread_id: u64, input: EventInput) -> RecordResult {
        if !should_record(CallOrigin::Application) {
            return RecordResult::SkippedAgentInternal;
        }
        if !self.host_monitor.recording_enabled() {
            return RecordResult::PassthroughHostStopped;
        }
        let Some(state) = self.state_for(thread_id) else {
            return RecordResult::NoSlot;
        };
        // SAFETY: this thread's counter, used on this thread only.
        let depth = unsafe { &*PublishGuard::depth_cell() };
        self.write_to(&state, depth, input)
    }

    /// One publication with the writer held.
    #[inline(always)]
    fn write_locked(
        &self,
        writer: &mut RingWriter,
        depth: &Cell<u32>,
        input: EventInput,
    ) -> Option<WriteOutcome> {
        if writer.is_detached() {
            return None;
        }
        let _guard = PublishSection::enter(depth); // 公開区間だけのガード
                                                   // L11: 書き込みが確定する直前に全体順序を採番する。
                                                   // 採番は観測点（この record 呼び出し）の順序を反映する。
                                                   // 欠落したイベントの分は欠番になる（Sequence の欠番と同じ扱い）。
        let mut input = input;
        if self.order_global {
            input.global_order = self.next_global_order.fetch_add(1, Ordering::Relaxed);
        }
        Some(if input.capture_state == CaptureState::Captured {
            writer.write_captured(
                input.kind,
                input.api_id,
                input.schema_id,
                input.call_id,
                input.parent_call_id,
                input.global_order,
                input.payload,
            )
        } else {
            writer.write(input)
        })
    }

    #[inline(always)]
    fn write_to(
        &self,
        state: &ThreadSlotState,
        depth: &Cell<u32>,
        input: EventInput,
    ) -> RecordResult {
        // The owner fast path inlines the write; the exclusive path is cold.
        let outcome = match state.writer.try_owner() {
            Some(mut writer) => self.write_locked(&mut writer, depth, input),
            None if state.writer.unclaimed() => {
                // The owner's liveness could not be taken, so its Ring is not
                // used (a terminated owner could not be told apart from a
                // long write). Counted as missing (Capture Coverage).
                self.note_missing_call();
                return RecordResult::NoSlot;
            }
            None => state
                .writer
                .exclusive(|writer| self.write_locked(writer, depth, input))
                .done()
                .flatten(),
        };
        let Some(outcome) = outcome else {
            self.pool.note_call_after_detach(&state.handle);
            return RecordResult::AfterDetach;
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

    #[inline]
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
                global_order: 0,
            },
        )
    }
    #[inline]
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
                global_order: 0,
            },
        )
    }

    /// 非同期 I/O の完了を記録する（F27）。OVERLAPPED 指定の呼び出し
    /// の leave は未完了のため Unsupported だが、完了を観測した時点
    /// （GetOverlappedResult / GetQueuedCompletionStatus）で、元の
    /// 呼び出しの leave Schema の値列を改めて記録する。`schema_id`
    /// には元の API の leave Schema の ID を入れる。
    pub fn record_completion(
        &self,
        thread_id: u64,
        api_id: u32,
        leave_schema_id: u32,
        call_id: u64,
        parent: u64,
        payload: &[u8],
    ) -> RecordResult {
        self.record(
            thread_id,
            CallOrigin::Application,
            EventInput {
                kind: EventKind::CallCompleted,
                api_id,
                schema_id: leave_schema_id,
                call_id,
                parent_call_id: parent,
                payload,
                capture_state: CaptureState::Captured,
                global_order: 0,
            },
        )
    }

    /// 中断した呼び出しを記録する（L08）。元の API が例外で戻らなかった
    /// 場合に、CallLeave の代わりに記録する。戻り値が無いため引数値列
    /// は空で、`schema_id` には leave Schema の ID を入れる（どの API
    /// の leave になるはずだったかが読めるようにする）。
    pub fn record_aborted(
        &self,
        thread_id: u64,
        api_id: u32,
        leave_schema_id: u32,
        call_id: u64,
        parent: u64,
    ) -> RecordResult {
        self.record(
            thread_id,
            CallOrigin::Application,
            EventInput {
                kind: EventKind::CallAborted,
                api_id,
                schema_id: leave_schema_id,
                call_id,
                parent_call_id: parent,
                payload: &[],
                capture_state: CaptureState::Captured,
                global_order: 0,
            },
        )
    }

    /// DLL_THREAD_DETACH 相当: DRAINING へ移行するだけ（待たない）。領域は Host 回収まで保持する。
    /// 管理操作であり、対象 Ring の書き手 Mutex だけを短く取る (全体ロックは使わない)。
    pub fn thread_detach(&self, thread_id: u64) -> bool {
        let state = self.threads.read().unwrap().get(&thread_id).map(Arc::clone);
        if let Some(s) = state {
            let _ = s.writer.exclusive(|w| w.mark_detached());
            return self.pool.begin_detach(&s.handle);
        }
        false
    }

    /// Host が回収を終えた後に Agent 側の保持を解く（通常は Host 主導）。
    /// 対象スレッドは終了済みであることが前提。引退印を付けてから登録表を
    /// 外し、進行中の記録があればその Ring の書き手ロックで完了を待つ。
    /// TLS キャッシュは引退印の確認で自動的に無効化される。
    pub fn thread_forget(&self, thread_id: u64) {
        let removed = self.threads.write().unwrap().remove(&thread_id);
        if let Some(state) = removed {
            state.retired.store(true, Ordering::Release);
            // Exclusive access waits for an in-flight record to finish (or
            // reports that its thread was terminated inside it).
            let _ = state.writer.exclusive(|_| ());
        }
    }

    /// スレッド終了の通知 (レビュー #6 P1-4): DETACH 相当の遷移と
    /// 登録表からの引退と、回収待ちへの登録を 1 回で行う。
    ///
    /// `thread_detach` (DRAINING へ移すだけ) と `thread_forget`
    /// (Host 主導の後始末) は、単体では「終了したスレッドの Slot を
    /// 再利用可能にする」経路になっていなかった。実 Capture 経路
    /// (Agent DLL) は `DisableThreadLibraryCalls` のため
    /// DLL_THREAD_DETACH が届かず、この入口は FLS デストラクタ
    /// (shirusu-hook の `fls`) から終了するスレッド自身の文脈で
    /// 呼ばれる。戻り値は対象スレッドの状態があったかどうか。
    ///
    /// 処理: 登録表から外して引退印を付ける (同じ OS スレッド ID が
    /// 再利用されても、新しいスレッドは新しい状態と Generation で
    /// 始まる)。書き手を DETACH 済みにして Slot を DRAINING へ移し、
    /// 状態を回収待ちへ登録する。FREE への回収は
    /// [`Agent::poll_reclaims`] が Host の drain 完了を確認してから
    /// 行う。
    pub fn thread_exit(&self, thread_id: u64) -> bool {
        self.adoptions.clear(thread_id);
        let removed = self.threads.write().unwrap().remove(&thread_id);
        let Some(state) = removed else {
            return false;
        };
        self.retire_to_reclaim(thread_id, state);
        true
    }

    /// 登録表から外した状態を DETACH 済みにして回収待ちへ送る。
    fn retire_to_reclaim(&self, thread_id: u64, state: Arc<ThreadSlotState>) {
        state.retired.store(true, Ordering::Release);
        // 排他取得自体が、進行中の記録の完了待ちになる。記録の途中で
        // 強制終了した書き手は待たずに隔離する (レビュー P0)。
        if state.writer.exclusive(|writer| writer.mark_detached()) == Access::OwnerTerminated {
            abandon_ring(state.region.base());
        }
        // この Ring への space_available 結線はこの incarnation の
        // ものであるため外す (再利用時は ensure 経路が結び直す)。
        self.space_clocks.write().unwrap().remove(&thread_id);
        self.pool.begin_detach(&state.handle);
        self.pending_reclaim.lock().unwrap().push(state);
    }

    /// 強制終了したスレッドの Ring を隔離して回収待ちへ送る (レビュー P0)。
    /// 回収したスレッド ID を返す。
    ///
    /// `TerminateThread` で終了したスレッドには FLS デストラクタも
    /// DLL_THREAD_DETACH も届かず、[`Agent::thread_exit`] は呼ばれない。
    /// ここでは高速経路の所有者が終了したことをカーネルの終了状態
    /// (`ThreadLiveness`) で確かめた Ring だけを扱う。生きているスレッド
    /// (一時停止中を含む) の Ring には触れず、待ちもしない。
    ///
    /// - 記録の外で終了していれば、通常の終了と同じく DETACH して回収を待つ。
    /// - 記録の途中で終了していれば書き手は使えない (イベントの途中かも
    ///   しれない)。書き手には触れず、公開済みのイベントだけを Host に
    ///   残し、書きかけの 1 件を欠落として Control に数える。Trace は
    ///   完全とは確定しない。
    ///
    /// Slot の再利用は終了の確認後に限る: 終了したスレッドは二度と
    /// 書き込まない。管理パスと新しいスレッドの初回記録、Shutdown から
    /// 呼ばれる。
    pub fn reap_terminated_threads(&self) -> Vec<u64> {
        let terminated: Vec<(u64, Arc<ThreadSlotState>)> = self
            .threads
            .read()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.writer.owner_terminated())
            .map(|(tid, s)| (*tid, Arc::clone(s)))
            .collect();
        terminated
            .into_iter()
            .filter(|(tid, state)| self.reap_thread(*tid, state))
            .map(|(tid, _)| tid)
            .collect()
    }

    /// Remove `state` (still registered for `tid`) and retire its Ring.
    /// False when another state replaced it meanwhile.
    fn reap_thread(&self, tid: u64, state: &Arc<ThreadSlotState>) -> bool {
        let removed = {
            let mut map = self.threads.write().unwrap();
            match map.get(&tid) {
                Some(s) if Arc::ptr_eq(s, state) => map.remove(&tid),
                _ => None,
            }
        };
        match removed {
            Some(state) => {
                self.retire_to_reclaim(tid, state);
                true
            }
            None => false,
        }
    }

    /// 前回から [`REAP_INTERVAL`] 以上経っていれば true (呼び出し側が
    /// [`Agent::reap_terminated_threads`] を呼ぶ)。スレッド終了のたびに
    /// 全スレッドの終了状態を問い合わせないための間引き。
    pub fn reap_due(&self) -> bool {
        let now = reap_clock_ms();
        let last = self.last_reap_ms.load(Ordering::Relaxed);
        now.saturating_sub(last) >= REAP_INTERVAL.as_millis() as u64
            && self
                .last_reap_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    /// 回収待ち Slot のうち、Host が読み終えたものを再利用可能へ
    /// 進める (管理パス)。進めた件数を返す。
    ///
    /// drain 完了の判定は共有 Control の読み位置で行う: 読み位置が
    /// 書き込み位置へ到達していれば、公開済みイベントは全て Host が
    /// 取り出したことになる (書き手は終了済みのため以後は増えない)。
    /// 判定が通れば、既存の転送層の仕組み
    /// (`host_confirm_ended_and_drained` → `host_reclaim`) で
    /// DRAINING → RECLAIMABLE → FREE (Generation +1) へ進める。
    /// プロセス間ではこの確認と回収は Agent プロセス内で行い、
    /// Host の寄与は読み位置の前進そのものである。
    pub fn poll_reclaims(&self) -> usize {
        let reclaimed = self.poll_reclaims_locked();
        if reclaimed > 0 {
            self.serve_adoptions();
        }
        reclaimed
    }
    fn poll_reclaims_locked(&self) -> usize {
        let mut pending = self.pending_reclaim.lock().unwrap();
        let mut reclaimed = 0usize;
        let mut i = 0;
        while i < pending.len() {
            let state = &pending[i];
            if !ring_is_drained(state.region.base(), state.writer.is_abandoned()) {
                i += 1;
                continue;
            }
            let _ = self
                .pool
                .host_confirm_ended_and_drained(&state.handle, true, true);
            if self.pool.host_reclaim(&state.handle) {
                reclaimed += 1;
                pending.remove(i);
                continue;
            }
            if self.pool.slot(state.handle.index).generation() != state.handle.generation {
                // 世代が進んでいる = 外部 (Host 主導の回収等) で既に
                // 回収・再利用された。保持を解く。
                pending.remove(i);
                continue;
            }
            i += 1;
        }
        reclaimed
    }

    /// 回収待ちの Slot 数 (観測用)。
    pub fn pending_reclaim_count(&self) -> usize {
        self.pending_reclaim.lock().unwrap().len()
    }
}

/// 強制終了したスレッドの探索を間引く間隔 ([`Agent::reap_due`])。
pub const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

fn reap_clock_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    // +REAP_INTERVAL: the first call is always due.
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
        + REAP_INTERVAL.as_millis() as u64
}

/// Ring が drain 済みか (回収判定。レビュー #6 P1-4)。
/// 書き手は終了済みであることが前提で、読み位置が書き込み位置へ
/// 到達していれば公開済みイベントは全て読み手が取り出した。
///
/// 隔離した Ring (書き手が記録の途中で強制終了) では、Payload の書き込み
/// 位置だけが Descriptor の公開より先に進んでいることがある。その分は
/// 公開されないため、公開済み Descriptor を読み終えたことだけで判定する。
fn ring_is_drained(base: *const u8, abandoned: bool) -> bool {
    let write_cursor = layout::load(base, layout::OFF_WRITE_CURSOR, Ordering::Acquire);
    let read_cursor = layout::load(base, layout::OFF_READ_CURSOR, Ordering::Acquire);
    let write_pos = layout::load(base, layout::OFF_PAYLOAD_WRITE_POSITION, Ordering::Acquire);
    let read_pos = layout::load(base, layout::OFF_PAYLOAD_READ_POSITION, Ordering::Acquire);
    read_cursor >= write_cursor && (abandoned || read_pos >= write_pos)
}

/// 記録の途中で強制終了した書き手の Ring を隔離する (レビュー P0)。
/// 書きかけのイベントは公開されないため、欠落として 1 件数える。
/// 書き手は終了済み (二度と実行されない) なので、書き手行の更新が
/// 競合することはない。
fn abandon_ring(base: *mut u8) {
    layout::fetch_add(base, layout::OFF_DROPPED_EVENTS, 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit release-only measurement of the Agent record path in parts
    /// (CI: scripts/ci/native-performance.ps1). Each part is timed alone on a
    /// Ring that a collector-free reader empties between rounds.
    #[test]
    #[ignore = "run explicitly in release mode for native component measurements"]
    #[allow(clippy::assertions_on_constants)] // Runtime refusal, not a compile-time assertion.
    fn measure_agent_record_parts() {
        use shirusu_transport::ring::RingReader;
        use std::hint::black_box;
        use std::time::Instant;
        assert!(!cfg!(debug_assertions), "measurement requires --release");
        const CALLS: usize = 1536;
        const ROUNDS: usize = 7;
        let cfg = RingConfig::new(4096, 1024 * 1024);
        let a = Agent::new(
            Arc::new(SlotPool::new(2)),
            cfg,
            Arc::new(HostMonitor::always_alive()),
        )
        .with_timestamp_source(Arc::new(shirusu_transport_win::QpcTimestampSource::new()));
        let tid = 1;
        a.thread_begin(tid).unwrap();
        let base = unsafe { a.thread_region_base(tid) }.unwrap();
        let mut reader = unsafe { RingReader::new(base, cfg) };
        let state = a.state_for(tid).unwrap();
        let payload = [7u8; 24];
        let report = |name: &str, mut samples: Vec<f64>| {
            samples.sort_by(f64::total_cmp);
            println!(
                "phase={name} median_ns_per_operation={:.2} min={:.2} max={:.2}",
                samples[ROUNDS / 2],
                samples[0],
                samples[ROUNDS - 1]
            );
        };
        let mut time = |name: &str, f: &mut dyn FnMut(u64)| {
            let mut samples = Vec::new();
            for round in 0..=ROUNDS {
                let start = Instant::now();
                for i in 0..2 * CALLS as u64 {
                    f(i);
                }
                let ns = start.elapsed().as_nanos() as f64 / (2 * CALLS) as f64;
                black_box(reader.drain_all());
                if round > 0 {
                    samples.push(ns);
                }
            }
            report(name, samples);
        };
        time("agent_part_tls_state_lookup", &mut |_| {
            black_box(TLS_STATE.try_with(|c| {
                let c = c.try_borrow().ok()?;
                match &*c {
                    Some(c) if c.agent == a.id && c.thread_id == tid => {
                        Some(c.state.retired.load(Ordering::Acquire))
                    }
                    _ => None,
                }
            }))
            .ok();
        });
        time("agent_part_writer_cell_with", &mut |_| {
            black_box(state.writer.with(|w| w.is_detached()));
        });
        time("agent_part_publish_guard", &mut |_| {
            let depth = unsafe { &*PublishGuard::depth_cell() };
            black_box(depth.get() > 0);
            let _g = black_box(PublishSection::enter(depth));
        });
        time("agent_part_write_captured", &mut |i| {
            black_box(state.writer.with(|w| {
                w.write_captured(EventKind::CallEnter, 1, 1, i, 0, 0, black_box(&payload))
            }));
        });
        // The same captured write on a plain heap region, outside the Agent:
        // separates the Agent's own cost from the Ring writer's.
        let plain = SharedRegion::new(cfg, 1, 9);
        let mut plain_writer = unsafe {
            plain.writer_with_timestamps(
                WriterPolicy::default(),
                system_clock(),
                Arc::new(shirusu_transport_win::QpcTimestampSource::new()),
            )
        };
        let mut plain_reader = unsafe { RingReader::new(plain.base(), cfg) };
        {
            let mut samples = Vec::new();
            for round in 0..=ROUNDS {
                let start = Instant::now();
                for i in 0..2 * CALLS as u64 {
                    black_box(plain_writer.write_captured(
                        EventKind::CallEnter,
                        1,
                        1,
                        i,
                        0,
                        0,
                        black_box(&payload),
                    ));
                }
                let ns = start.elapsed().as_nanos() as f64 / (2 * CALLS) as f64;
                black_box(plain_reader.drain_all());
                if round > 0 {
                    samples.push(ns);
                }
            }
            report("agent_part_plain_region_write_captured", samples);
        }
        time("agent_part_record_enter", &mut |i| {
            black_box(a.record_enter(tid, 1, 1, i, 0, black_box(&payload)));
        });
        time("agent_part_record_captured", &mut |i| {
            black_box(a.record_captured(
                tid,
                EventKind::CallEnter,
                1,
                1,
                i,
                0,
                black_box(&payload),
            ));
        });
    }

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
                global_order: 0,
            },
        );
        assert_eq!(internal, RecordResult::SkippedAgentInternal);
    }
    #[test]
    fn record_completion_writes_call_completed_event() {
        // F27: 非同期 I/O の完了は CallCompleted として、元の呼び出しの
        // leave Schema の値列とともに記録される。
        let a = agent(4);
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            a.record_leave(1, 10, 21, 100, 0, b"leave-args"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            a.record_completion(1, 10, 21, 100, 0, b"completed-args"),
            RecordResult::Written(_)
        ));
        let base = unsafe { a.thread_region_base(1) }.expect("region");
        let mut reader =
            unsafe { shirusu_transport::ring::RingReader::new(base, RingConfig::new(16, 512)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 3);
        assert_eq!(
            batch.events[2].descriptor.kind_enum(),
            Some(EventKind::CallCompleted)
        );
        assert_eq!(batch.events[2].descriptor.call_id, 100);
        assert_eq!(batch.events[2].descriptor.api_id, 10);
        assert_eq!(batch.events[2].descriptor.schema_id, 21);
        assert_eq!(batch.events[2].payload, b"completed-args");
    }
    #[test]
    fn record_aborted_writes_call_aborted_event() {
        // L08: 中断した呼び出しは CallAborted として記録される。
        let a = agent(4);
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            a.record_aborted(1, 10, 21, 100, 0),
            RecordResult::Written(_)
        ));
        let base = unsafe { a.thread_region_base(1) }.expect("region");
        let mut reader =
            unsafe { shirusu_transport::ring::RingReader::new(base, RingConfig::new(16, 512)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallEnter)
        );
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(EventKind::CallAborted)
        );
        assert_eq!(batch.events[1].descriptor.call_id, 100);
        assert_eq!(batch.events[1].descriptor.api_id, 10);
        assert_eq!(batch.events[1].descriptor.schema_id, 21);
        assert_eq!(batch.events[1].payload.len(), 0, "aborted has no args");
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
        assert!(!a.space_available_attached(1));
        let notify = Arc::new(RingNotify::new().unwrap());
        let clock = a.attach_space_available_notify(1, Arc::clone(&notify));
        assert!(clock.is_some());
        assert!(a.space_available_attached(1));
        assert!(!a.space_available_attached(2), "attach is per-ring (R7)");
        assert_eq!(clock.unwrap().sleep_calls(), 0);
        // 受け取り後に書き始めたスレッドは EventClock で書く。
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
        // 別 Ring への受け取りは、他 Ring が書き始めた後でも独立に行える。
        // (R7 以前の全体共有 Clock では、どれか 1 Ring が書き始めると
        // 全体への差し替えができなくなっていた。)
        let notify2 = Arc::new(RingNotify::new().unwrap());
        assert!(a.attach_space_available_notify(2, notify2).is_some());
        assert!(a.space_available_attached(2));
    }
    #[test]
    fn attach_space_available_after_thread_begin_swaps_clock() {
        use shirusu_transport_win::RingNotify;
        let a = agent(2);
        assert!(a.thread_begin(1).is_some());
        // R7: Ring ごとに結ぶため、書き始めた後でもその Ring の書き手の
        // Clock を差し替えられる。他 Ring には影響しない。
        let notify = Arc::new(RingNotify::new().unwrap());
        assert!(a.attach_space_available_notify(1, notify).is_some());
        assert!(a.space_available_attached(1));
        assert!(!a.space_available_attached(2));
        assert!(matches!(
            a.record_enter(1, 10, 20, 100, 0, b"args"),
            RecordResult::Written(_)
        ));
    }
    #[test]
    fn attach_space_available_from_handle_value_shape() {
        // ハンドル値経路の API 形だけを確認する。Linux スタブではハンドル値に
        // 実体が無く、つながっていない新しいイベントになる（プロセス間受け渡し
        // の実証は Windows 実機の duplicate テストが担う）。それでも Agent は
        // EventClock で書けること。
        let a = agent(2);
        let clock = unsafe { a.attach_space_available(1, 0) };
        assert!(clock.is_some());
        assert!(a.space_available_attached(1));
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
    /// Review P0: a thread terminated inside a record (TerminateThread runs
    /// no Drop; modeled by leaking the owner guard and exiting) leaves
    /// `owner_busy` set. Management paths must not wait for it forever, the
    /// Ring keeps only what was published, the cut-off event counts as lost,
    /// and the Slot is reused only after the published events are drained.
    #[test]
    fn registration_is_confirmed_from_thread_local_state() {
        let a = agent(2);
        assert!(!a.current_thread_registered(7), "nothing recorded yet");
        assert!(matches!(
            a.record_enter(7, 10, 20, 1, 0, b"x"),
            RecordResult::Written(_)
        ));
        assert!(a.current_thread_registered(7));
        assert!(!a.current_thread_registered(8), "another thread ID");
        let other = std::thread::scope(|s| s.spawn(|| a.current_thread_registered(7)).join());
        assert!(!other.unwrap(), "another OS thread does not own the Ring");
        assert!(a.thread_exit(7));
        assert!(!a.current_thread_registered(7), "retired Ring");
    }

    #[test]
    fn reused_id_of_a_terminated_thread_gets_a_fresh_ring() {
        let a = Arc::new(agent(2));
        let old = {
            let a = Arc::clone(&a);
            std::thread::spawn(move || {
                assert!(matches!(
                    a.record_enter(7, 10, 20, 1, 0, b"old"),
                    RecordResult::Written(_)
                ));
                let state = a.state_for(7).unwrap();
                std::mem::forget(state.writer.try_owner().unwrap()); // cut off mid-write
                let handle = state.handle;
                std::mem::forget(state);
                handle
            })
            .join()
            .unwrap()
        };
        // A new thread with the same OS thread ID (no exit notice came).
        let a2 = Arc::clone(&a);
        let fresh = std::thread::spawn(move || {
            assert!(matches!(
                a2.record_enter(7, 10, 20, 2, 0, b"new"),
                RecordResult::Written(_)
            ));
            let state = a2.state_for(7).unwrap();
            // Its own Ring, written on the owner fast path from the start.
            assert!(state.writer.try_owner().is_some());
            state.handle
        })
        .join()
        .unwrap();
        assert_ne!(old.index, fresh.index, "the dead owner's Ring is retired");
    }

    #[test]
    fn slot_less_thread_is_handed_a_ring_built_by_another_thread() {
        use shirusu_transport::ring::RingReader;
        let a = Arc::new(agent(1));
        let cfg = RingConfig::new(16, 512);
        assert!(matches!(
            a.record_enter(7, 10, 20, 1, 0, b"first"),
            RecordResult::Written(_)
        ));
        let base = unsafe { a.thread_region_base(7) }.unwrap();
        let (to_waiter, waiter_rx) = std::sync::mpsc::channel::<()>();
        let (to_main, main_rx) = std::sync::mpsc::channel::<RecordResult>();
        let waiter = {
            let a = Arc::clone(&a);
            std::thread::spawn(move || {
                // No Slot: the request is left without building anything.
                to_main.send(a.record_enter(8, 10, 20, 2, 0, b"x")).unwrap();
                waiter_rx.recv().unwrap();
                // Another thread built this thread's Ring; it is taken
                // lock-free and owned by this thread from its first write.
                let r = a.record_enter(8, 10, 20, 3, 0, b"adopted");
                let owned = a.current_thread_registered(8);
                to_main.send(r).unwrap();
                assert!(owned, "the adopted Ring is this thread's own");
            })
        };
        assert_eq!(main_rx.recv().unwrap(), RecordResult::NoSlot);
        assert!(
            unsafe { a.thread_region_base(8) }.is_none(),
            "nothing built yet"
        );
        // The first thread exits; once the Host drained its Ring, reclaiming
        // the Slot builds the waiting thread's Ring on this (management) path.
        assert!(a.thread_exit(7));
        let mut reader = unsafe { RingReader::new(base, cfg) };
        assert_eq!(reader.drain_all().events.len(), 1);
        assert_eq!(a.poll_reclaims(), 1);
        assert!(
            unsafe { a.thread_region_base(8) }.is_some(),
            "built for the waiter"
        );
        to_waiter.send(()).unwrap();
        assert!(matches!(main_rx.recv().unwrap(), RecordResult::Written(_)));
        waiter.join().unwrap();
    }

    #[test]
    fn terminated_writer_is_isolated_and_reclaimed() {
        use shirusu_transport::ring::RingReader;
        let a = Arc::new(agent(2));
        let cfg = RingConfig::new(16, 512);
        let victim = {
            let a = Arc::clone(&a);
            std::thread::spawn(move || {
                assert!(matches!(
                    a.record_enter(7, 10, 20, 1, 0, b"published"),
                    RecordResult::Written(_)
                ));
                let state = a.state_for(7).unwrap();
                let guard = state.writer.try_owner().expect("owner fast path");
                // Half way through the next event: payload reserved, its
                // descriptor never published.
                let base = state.region.base();
                let pos = layout::load(base, layout::OFF_PAYLOAD_WRITE_POSITION, Ordering::Relaxed);
                layout::store(
                    base,
                    layout::OFF_PAYLOAD_WRITE_POSITION,
                    pos + 8,
                    Ordering::Relaxed,
                );
                std::mem::forget(guard);
                // Leak the TLS cache's reference as well: a terminated thread
                // drops nothing.
                std::mem::forget(state);
            })
        };
        victim.join().unwrap();
        let base = unsafe { a.thread_region_base(7) }.unwrap();
        // Another thread keeps capturing meanwhile.
        assert!(matches!(
            a.record_enter(8, 10, 20, 2, 0, b"other"),
            RecordResult::Written(_)
        ));
        // Management paths of the victim's Ring return instead of hanging.
        assert!(a.thread_detach(7));
        assert_eq!(a.reap_terminated_threads(), vec![7]);
        assert_eq!(
            layout::load(base, layout::OFF_DROPPED_EVENTS, Ordering::Acquire),
            1,
            "the cut-off event is counted as lost"
        );
        assert!(a.reap_terminated_threads().is_empty(), "reaped once");
        // Not reusable before the Host drained what was published.
        assert_eq!(a.poll_reclaims(), 0);
        let mut reader = unsafe { RingReader::new(base, cfg) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1, "only published events are read");
        assert_eq!(batch.events[0].descriptor.call_id, 1);
        assert_eq!(a.poll_reclaims(), 1);
        // The live thread is unaffected and the Slot serves a new thread.
        assert!(a.reap_terminated_threads().is_empty());
        assert!(matches!(
            a.record_enter(9, 10, 20, 3, 0, b"new"),
            RecordResult::Written(_)
        ));
    }

    #[test]
    fn thread_exit_reclaim_survives_short_lived_thread_churn() {
        // レビュー #6 P1-4: 短命スレッドを大量に作って捨てても、Host
        // が drain すれば Slot は回収され枯渇しない。OS スレッド ID
        // の再利用 (同じ ID の繰り返し) も含む。Pool は 2 スロット
        // しかないため、回収が無ければ 3 回目で枯渇する。
        use shirusu_transport::ring::RingReader;
        let a = agent(2);
        let cfg = RingConfig::new(16, 512);
        let mut generations = std::collections::HashSet::new();
        for i in 0..30u64 {
            let tid = 100 + (i % 3); // 終了済み TID の再利用を含む
            let handle = a.thread_begin(tid).expect("slot must be recycled");
            generations.insert(handle.generation);
            assert!(matches!(
                a.record_enter(tid, 10, 20, 1000 + i, 0, b"x"),
                RecordResult::Written(_)
            ));
            let base = unsafe { a.thread_region_base(tid) }.expect("region");
            assert!(a.thread_exit(tid), "exit of a begun thread");
            // Host がまだ読んでいない間は回収されない
            assert_eq!(a.poll_reclaims(), 0);
            assert_eq!(a.pending_reclaim_count(), 1);
            // Host 側が drain する (実 Host では DrainWorker が共有
            // 読み位置を進める。ここでは RingReader で同じことをする)
            let mut reader = unsafe { RingReader::new(base, cfg) };
            let batch = reader.drain_all();
            assert_eq!(batch.events.len(), 1);
            assert_eq!(batch.events[0].descriptor.call_id, 1000 + i);
            // drain 済みになれば回収され、Slot は次のスレッドへ回る
            assert_eq!(a.poll_reclaims(), 1);
            assert_eq!(a.pending_reclaim_count(), 0);
        }
        // 世代が進んでいる (同じ Slot が別の世代で再利用された)
        assert!(generations.len() > 1, "generations: {generations:?}");
        // 始まっていないスレッドへの thread_exit は false
        assert!(!a.thread_exit(999_999));
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
    fn record_inside_publish_guard_is_skipped_on_the_cached_path() {
        let a = agent(2);
        assert!(matches!(
            a.record_enter(1, 1, 1, 1, 0, b"x"),
            RecordResult::Written(_)
        ));
        {
            let _g = PublishGuard::enter();
            assert_eq!(
                a.record_enter(1, 1, 1, 2, 0, b"x"),
                RecordResult::SkippedAgentInternal
            );
        }
        assert!(
            !PublishGuard::is_active(),
            "the record left the depth as it was"
        );
        assert!(matches!(
            a.record_enter(1, 1, 1, 3, 0, b"x"),
            RecordResult::Written(_)
        ));
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
    fn unknown_loader_lock_disables_wait_for_each_new_writer() {
        use shirusu_transport::clock::ManualClock;
        for loader_lock in [LoaderLockState::Unknown, LoaderLockState::NotHeld] {
            let clock = Arc::new(ManualClock::default());
            let a = Agent::new(
                Arc::new(SlotPool::new(2)),
                RingConfig::new(2, 64),
                Arc::new(HostMonitor::always_alive()),
            )
            .with_clock(clock.clone())
            .with_loader_lock_state(loader_lock);
            for tid in [1, 2] {
                for call in 1..=3 {
                    let _ = a.record_enter(tid, 1, 1, call, 0, b"x");
                }
                let state = a.state_for(tid).unwrap();
                let _ = state.writer.exclusive(|writer| {
                    assert_eq!(writer.loader_lock_state(), loader_lock);
                    if loader_lock == LoaderLockState::Unknown {
                        assert_eq!(writer.wait_count, 0);
                    } else {
                        assert!(writer.wait_count > 0);
                    }
                });
            }
            if loader_lock == LoaderLockState::Unknown {
                assert_eq!(clock.now_ticks(), 0);
            } else {
                assert!(clock.now_ticks() > 0);
            }
        }
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

    #[test]
    fn record_captured_writes_what_record_writes() {
        use shirusu_transport::ring::RingReader;
        let cfg = RingConfig::new(16, 512);
        let a = agent(2);
        let tid = 1;
        a.thread_begin(tid).unwrap();
        // First call is uncached (slow path), the rest take the fast path.
        for i in 1..=3u64 {
            let _ = a.record_captured(tid, EventKind::CallEnter, 7, 8, i, 40 + i, b"args");
        }
        let _ = a.record_enter(tid, 7, 8, 4, 44, b"args");
        let base = unsafe { a.thread_region_base(tid) }.unwrap();
        let events = unsafe { RingReader::new(base, cfg) }.drain_all().events;
        assert_eq!(events.len(), 4);
        for (i, e) in events.iter().enumerate() {
            let d = &e.descriptor;
            assert_eq!(d.kind_enum(), Some(EventKind::CallEnter));
            assert_eq!((d.api_id, d.schema_id), (7, 8));
            assert_eq!((d.call_id, d.parent_call_id), (i as u64 + 1, 41 + i as u64));
            assert_eq!(d.sequence, events[0].descriptor.sequence + i as u64);
            assert_eq!(e.payload, b"args");
        }
    }

    #[test]
    fn record_captured_skips_inside_a_publication_and_after_host_stop() {
        use shirusu_transport::ring::RingReader;
        let cfg = RingConfig::new(16, 512);
        let a = agent(2);
        let tid = 1;
        let _ = a.record_captured(tid, EventKind::CallEnter, 1, 1, 1, 0, b"");
        {
            let _inside = PublishGuard::enter();
            assert!(!a.record_captured(tid, EventKind::CallEnter, 1, 1, 2, 0, b""));
        }
        let base = unsafe { a.thread_region_base(tid) }.unwrap();
        assert_eq!(
            unsafe { RingReader::new(base, cfg) }
                .drain_all()
                .events
                .len(),
            1
        );

        let monitor = Arc::new(HostMonitor::new(|| false));
        let stopped = Agent::new(Arc::new(SlotPool::new(2)), RingConfig::new(4, 64), monitor)
            .with_policy(WriterPolicy {
                max_wait: std::time::Duration::ZERO,
                ..Default::default()
            });
        for i in 0..40u64 {
            let _ = stopped.record_captured(tid, EventKind::CallEnter, 1, 1, i, 0, b"0123456789");
        }
        assert!(!stopped.host_monitor().recording_enabled());
        assert_eq!(
            stopped.record_enter(tid, 1, 1, 999, 0, b"x"),
            RecordResult::PassthroughHostStopped
        );
    }
}
