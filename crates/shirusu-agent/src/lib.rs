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
use writer_cell::WriterCell;

pub use expansion::{ExpansionManager, ExpansionManagerHandle, ExpansionStats};

use shirusu_transport::clock::{system_clock, system_timestamp_source, Clock, TimestampSource};
use shirusu_transport::context::{should_record, CallOrigin, HostMonitor, PublishGuard};
use shirusu_transport::descriptor::{CaptureState, EventKind};
use shirusu_transport::expansion::{ExpansionDelivery, EXPANDED_SLOT_GENERATION};
use shirusu_transport::layout;
use shirusu_transport::ring::{
    EventInput, LoaderLockProbe, LoaderLockState, RingWriter, SharedRegion, WriteOutcome,
    WriterPolicy,
};
use shirusu_transport::slot::{SlotHandle, SlotPool};
use shirusu_transport::RingConfig;
use shirusu_transport_win::{EventClock, EventObject, HandleValue, RingNotify, SharedMapping};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    /// `--order=global` (L11) が有効かどうか。`with_order_global` で
    /// 構築時に設定し、以後は不変。Host は Bootstrap / セッション設定から
    /// 決める。無効な間は Descriptor の `global_order` は 0 のまま。
    order_global: bool,
    /// 全スレッド共通の観測順序カウンタ (L11)。`record` で書き込みが
    /// 確定する直前に 1 つ採番する。1 始まり（0 は未割当）。
    next_global_order: AtomicU64,
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
}

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
            order_global: false,
            next_global_order: AtomicU64::new(1),
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
                state
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
        let state = self.state_for_slow(thread_id)?;
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
    fn state_for_slow(&self, thread_id: u64) -> Option<Arc<ThreadSlotState>> {
        if let Some(s) = self.threads.read().unwrap().get(&thread_id).cloned() {
            if !s.retired.load(Ordering::Acquire) {
                return Some(s);
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
        let index = self.pool.add_slot().ok_or(())?;
        self.expanded_regions.lock().unwrap().insert(index, region);
        if !self.pool.publish_slot(index) {
            // 公開に失敗したら紐付けを取り消す (Slot は PREPARING のまま
            // 残るため claim はされず、記録が誤って始まることはない)。
            self.expanded_regions.lock().unwrap().remove(&index);
            return Err(());
        }
        Ok(index)
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
    #[inline]
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
            None => state
                .writer
                .exclusive(|writer| self.write_locked(writer, depth, input)),
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
            s.writer.exclusive(|w| w.mark_detached());
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
            // Exclusive access waits for an in-flight record to finish.
            state.writer.exclusive(|_| ());
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
        let removed = self.threads.write().unwrap().remove(&thread_id);
        let Some(state) = removed else {
            return false;
        };
        state.retired.store(true, Ordering::Release);
        {
            // 排他取得自体が、進行中の記録の完了待ちになる。
            state.writer.exclusive(|writer| writer.mark_detached());
        }
        // この Ring への space_available 結線はこの incarnation の
        // ものであるため外す (再利用時は ensure 経路が結び直す)。
        self.space_clocks.write().unwrap().remove(&thread_id);
        self.pool.begin_detach(&state.handle);
        self.pending_reclaim.lock().unwrap().push(state);
        true
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
        let mut pending = self.pending_reclaim.lock().unwrap();
        let mut reclaimed = 0usize;
        let mut i = 0;
        while i < pending.len() {
            let state = &pending[i];
            if !ring_is_drained(state.region.base()) {
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

/// Ring が drain 済みか (回収判定。レビュー #6 P1-4)。
/// 書き手は終了済みであることが前提で、読み位置が書き込み位置へ
/// 到達していれば公開済みイベントは全て読み手が取り出した。
fn ring_is_drained(base: *const u8) -> bool {
    let write_cursor = layout::load(base, layout::OFF_WRITE_CURSOR, Ordering::Acquire);
    let read_cursor = layout::load(base, layout::OFF_READ_CURSOR, Ordering::Acquire);
    let write_pos = layout::load(base, layout::OFF_PAYLOAD_WRITE_POSITION, Ordering::Acquire);
    let read_pos = layout::load(base, layout::OFF_PAYLOAD_READ_POSITION, Ordering::Acquire);
    read_cursor >= write_cursor && read_pos >= write_pos
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
        time("agent_part_record_enter", &mut |i| {
            black_box(a.record_enter(tid, 1, 1, i, 0, black_box(&payload)));
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
                state.writer.exclusive(|writer| {
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
}
