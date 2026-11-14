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
//! DLL が設定する LoaderLockState::Unknown と WriterPolicy 既定
//! （Loader Lock 保持が不明な書き込みは待機 0、A69）
//! に従う（SetEvent は待たない操作）。これは Ring 空き待ちの制約であり、
//! 初回登録・管理用ロックやメモリ確保まで待機なしと保証するものではない。

use crate::api::{ApiDef, MAX_API_ID};
use crate::callback::{
    CALLBACK_API_ID, CALLBACK_ENTER_SCHEMA_ID, CALLBACK_HOOK_COUNT, CALLBACK_LEAVE_SCHEMA_ID,
};
use crate::capture::{OverlappedRegistry, PendingOverlapped};
use crate::com::{
    ComTracker, COM_FACTORY_COUNT, COM_METHOD_API_ID, COM_METHOD_ENTER_SCHEMA_ID,
    COM_METHOD_LEAVE_SCHEMA_ID,
};
use crate::winrt::{
    WINRT_ACTIVATION_API_ID, WINRT_ACTIVATION_COUNT, WINRT_ACTIVATION_ENTER_SCHEMA_ID,
    WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
};
use shirusu_agent::{Agent, RecordResult};
use shirusu_transport::descriptor::EventKind;
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
    static CALL_STACK: RefCell<CallStack> = const { RefCell::new(CallStack(Vec::new())) };
}

/// The call stack's storage; its destructor ends [`CAPTURE_TLS_LIVE`].
struct CallStack(Vec<u64>);
impl std::ops::Deref for CallStack {
    type Target = Vec<u64>;
    #[inline(always)]
    fn deref(&self) -> &Vec<u64> {
        &self.0
    }
}
impl std::ops::DerefMut for CallStack {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Vec<u64> {
        &mut self.0
    }
}
impl Drop for CallStack {
    fn drop(&mut self) {
        capture_tls_teardown();
    }
}

pub fn current_parent_call() -> u64 {
    if !native_tls_available() {
        return 0;
    }
    CALL_STACK
        .try_with(|s| s.borrow().last().copied().unwrap_or(0))
        .unwrap_or(0)
}
pub fn push_call(call_id: u64) {
    if !native_tls_available() {
        return;
    }
    let _ = CALL_STACK.try_with(|s| s.borrow_mut().push(call_id));
}
/// スタック最上位が自分の Call ID のときにだけ取り除く（異常な
/// 対応ずれで他人のフレームを壊さない）。
pub fn pop_call(call_id: u64) {
    if !native_tls_available() {
        return;
    }
    let _ = CALL_STACK.try_with(|s| {
        let mut s = s.borrow_mut();
        if s.last() == Some(&call_id) {
            s.pop();
        }
    });
}

thread_local! {
    /// Detour の再入ガードの深さ (G15)。0 = 記録経路の外、1 = 記録経路の実行中。
    static REENTRANCY_DEPTH: Cell<u32> = const { Cell::new(0) };
    static THREAD_EXITING: Cell<bool> = const { Cell::new(false) };
    /// Every destructor-bearing TLS the capture path needs (the call stack,
    /// the runtime cache and the Agent's writer cache) is registered and
    /// alive, the runtime cache is ready, and exit has not begun. Set by a
    /// full [`ReentrancyGuard::try_enter`]; cleared when any of those keys
    /// starts destruction or the thread is marked exiting. While set, entry
    /// skips re-checking each key (several TLS lookups and a cross-crate
    /// call per Detour).
    static CAPTURE_TLS_LIVE: Cell<bool> = const { Cell::new(false) };
}

/// A capture TLS key is being destroyed: take the full entry checks again.
fn capture_tls_teardown() {
    if native_tls_available() {
        let _ = CAPTURE_TLS_LIVE.try_with(|live| live.set(false));
    }
}

#[inline(always)]
fn capture_tls_live() -> bool {
    CAPTURE_TLS_LIVE.with(Cell::get)
}

/// Loader heap operations can enter an inline hook before allocation or after
/// destruction of this thread's native TLS vector. Rust's try_with only checks
/// a key's lifecycle *after* loading that vector, so it cannot guard this case.
#[inline]
pub(crate) fn native_tls_available() -> bool {
    #[cfg(windows)]
    {
        extern "C" {
            static _tls_index: u32;
        }
        let vector: *const *const u8;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("mov {}, gs:[0x58]", out(reg) vector, options(nostack, preserves_flags, readonly))
        };
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!("mov {}, fs:[0x2c]", out(reg) vector, options(nostack, preserves_flags, readonly))
        };
        if vector.is_null() {
            return false;
        }
        // Windows sizes the vector for the loaded modules before filling its
        // per-module blocks. A block may not have been allocated yet either.
        let index = unsafe { std::ptr::read_volatile(std::ptr::addr_of!(_tls_index)) } as usize;
        !unsafe { std::ptr::read_volatile(vector.add(index)) }.is_null()
    }
    #[cfg(not(windows))]
    {
        true
    }
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
    #[inline]
    pub fn try_enter() -> Option<Self> {
        if !native_tls_available() {
            return None;
        }
        // Fast path: the full checks below already passed on this thread and
        // nothing they cover has been torn down since.
        let entered = REENTRANCY_DEPTH.with(|d| {
            if d.get() > 0 {
                return Some(false);
            }
            capture_tls_live().then(|| {
                d.set(1);
                true
            })
        });
        match entered {
            Some(true) => Some(Self { suspended: false }),
            Some(false) => None,
            None => Self::try_enter_full(),
        }
    }

    #[cold]
    #[inline(never)]
    fn try_enter_full() -> Option<Self> {
        let guard = Self::try_enter_with(|| {
            CALL_STACK.try_with(|_| ()).is_ok() && shirusu_agent::current_thread_capture_available()
        })?;
        // Initialize destructor-bearing runtime TLS only after all earlier TLS
        // registration has returned. Nested allocator detours cannot do this:
        // Rust rejects registering another destructor inside System allocation.
        let ready = RUNTIME_CACHE_READY
            .try_with(|ready| {
                // READY controls nested allocator access; it does not prove
                // that this destructor-bearing key still exists at thread exit.
                if DETOUR_RUNTIME.try_with(|_| ()).is_err() {
                    return false;
                }
                ready.set(true);
                true
            })
            .unwrap_or(false);
        if !ready {
            return None;
        }
        // Everything above is alive and initialized. Each destructor-bearing
        // key clears the shortcut when it starts destruction (the Agent's
        // through its teardown hook), and so does marking the thread exiting.
        shirusu_agent::set_thread_teardown_hook(capture_tls_teardown);
        if !THREAD_EXITING.try_with(Cell::get).unwrap_or(true) {
            let _ = CAPTURE_TLS_LIVE.try_with(|live| live.set(true));
        }
        Some(guard)
    }

    fn try_enter_with(available: impl FnOnce() -> bool) -> Option<Self> {
        if !native_tls_available() {
            return None;
        }
        REENTRANCY_DEPTH
            .try_with(|d| {
                if d.get() > 0 || THREAD_EXITING.try_with(Cell::get).unwrap_or(true) {
                    return None;
                }
                // Accessing destructor-bearing TLS can register a destructor
                // and allocate. Protect that initialization too: HeapAlloc's
                // detour must see an active guard before it touches more TLS.
                d.set(1);
                let guard = Self { suspended: false };
                available().then_some(guard)
            })
            .ok()
            .flatten()
    }

    /// FLS callbacks can run before or after Rust TLS destructors. Never resume
    /// capture on this thread once exit cleanup has begun.
    pub fn mark_thread_exiting() {
        if !native_tls_available() {
            return;
        }
        let _ = THREAD_EXITING.try_with(|exiting| exiting.set(true));
        let _ = CAPTURE_TLS_LIVE.try_with(|live| live.set(false));
    }

    /// 記録経路の実行中か。
    pub fn is_active() -> bool {
        native_tls_available() && REENTRANCY_DEPTH.with(|d| d.get() > 0)
    }

    /// 元の API 呼び出しの直前に呼ぶ: ガードを一時的に外す。
    pub fn suspend(&mut self) {
        if !self.suspended {
            if native_tls_available() {
                REENTRANCY_DEPTH.with(|d| d.set(0));
            }
            self.suspended = true;
        }
    }

    /// 元の API 呼び出しの直後に呼ぶ: ガードを戻す。
    pub fn resume(&mut self) {
        if self.suspended {
            if native_tls_available() {
                REENTRANCY_DEPTH.with(|d| d.set(1));
            }
            self.suspended = false;
        }
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        // suspend 中は深さは既に 0。保持中の場合だけ 0 に戻す。
        if !self.suspended && native_tls_available() {
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
/// Detours and original function pointers use `system-unwind`: external
/// exceptions may cross these frames. Native Windows exception transparency
/// still requires platform E2E validation; unwind metadata alone is insufficient.
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
        if !self.armed || !native_tls_available() {
            return;
        }
        self.armed = false;
        let _guard = ReentrancyGuard::try_enter();
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

/// [`CallGuard`] that owns the call's [`DetourFlight`] (and through it the only
/// runtime reference). Dropping it first records `CallAborted` if still armed,
/// then leaves the in-flight section, preserving the order of the separate guards.
pub struct FlightCallGuard {
    flight: DetourFlight,
    thread_id: u64,
    api: &'static ApiDef,
    call_id: u64,
    armed: bool,
}

impl FlightCallGuard {
    pub fn new(flight: DetourFlight, thread_id: u64, api: &'static ApiDef, call_id: u64) -> Self {
        Self {
            flight,
            thread_id,
            api,
            call_id,
            armed: true,
        }
    }

    pub fn runtime(&self) -> &HookRuntime {
        self.flight.runtime()
    }

    /// 元の呼び出しが正常に戻った: 武装解除する。
    pub fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for FlightCallGuard {
    fn drop(&mut self) {
        if !self.armed || !native_tls_available() {
            return;
        }
        self.armed = false;
        let _guard = ReentrancyGuard::try_enter();
        pop_call(self.call_id);
        let rt = self.flight.runtime();
        let (thread_id, api, call_id) = (self.thread_id, self.api, self.call_id);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.record_aborted(thread_id, api, call_id);
        }));
    }
}

/// Detour の LastError 保持プロトコル (レビュー #6 P1-5)。
///
/// 呼び出し側から見た LastError は「Detour が無い場合の元の API の
/// 結果」でなければならない。しかし Detour は元の API の前に引数
/// 取得と記録を行い、それが失敗すると (保護の無いメモリの読み取り
/// 等) スレッドの LastError が書き換わる。元の API が成功して
/// LastError を更新しない場合、呼び出し側には Hook 依存の値が見えて
/// しまう。旧実装は「元の API 直後の値を復元する」だけであり、
/// 元の API が観測する値の保存・復元が無かった。
///
/// 手順は全 Detour 共通で:
/// 1. Detour 入口で現在の LastError を保存する
///    ([`LastErrorGuard::capture`]。`prepare` の副作用も含め、ここが
///    基準になる)。
/// 2. 元の API を呼ぶ直前に保存値を復元する
///    ([`LastErrorGuard::restore_before_original`])。
/// 3. 元の API から戻った直後の値を記録用に保持する
///    ([`LastErrorGuard::capture_after_original`]。leave の値列は
///    この値で作る)。
/// 4. Detour を返る直前に手順 3 の値を復元する
///    ([`LastErrorGuard::restore_for_return`]。leave 記録が書き換えた
///    分を消す)。
///
/// セル (実物の GetLastError / SetLastError) は [`LastErrorCell`] で
/// 抽象化し、単体テストではモックで手順を観測する。Windows の実物は
/// engine が実装する。
pub trait LastErrorCell {
    fn get(&self) -> u32;
    fn set(&self, code: u32);
}

/// [`LastErrorCell`] に対する保持ガード。使い方は型の文書のとおり。
pub struct LastErrorGuard<C: LastErrorCell> {
    cell: C,
    entry: u32,
    after_original: Option<u32>,
}

impl<C: LastErrorCell> LastErrorGuard<C> {
    /// Detour 入口で現在の値を保存する。
    pub fn capture(cell: C) -> Self {
        let entry = cell.get();
        Self {
            cell,
            entry,
            after_original: None,
        }
    }

    /// 保存した入口時点の値。
    pub fn entry_value(&self) -> u32 {
        self.entry
    }

    /// 元の API を呼ぶ直前に、入口時点の値へ戻す。
    pub fn restore_before_original(&self) {
        self.cell.set(self.entry);
    }

    /// 元の API から戻った直後の値を保持し、その値を返す
    /// (leave の値列はこの値で作る)。
    pub fn capture_after_original(&mut self) -> u32 {
        let v = self.cell.get();
        self.after_original = Some(v);
        v
    }

    /// 保持した「元の API 直後の値」(未取得なら None)。
    pub fn after_original_value(&self) -> Option<u32> {
        self.after_original
    }

    /// Detour を返る直前に、元の API 直後の値を呼び出し側へ見せる。
    /// 未取得 (元の API を呼ばなかった) 場合は何もしない。
    pub fn restore_for_return(&self) {
        if let Some(v) = self.after_original {
            self.cell.set(v);
        }
    }
}

/// 中断した COM メソッド呼び出しの記録ガード (L08・L02)。
/// `CallGuard` と同じ役割だが、COM イベントは ApiDef を持たないため
/// api_id / schema_id を直接持つ。Drop 中の記録は失敗しても
/// プロセスを落とさないこと（`CallGuard` と同じ理由）。
/// `new` は COM メソッドイベント用。WinRT アクティベーションイベント用は
/// `new_for` で api_id / leave Schema を指定する（L14）。
pub struct ComCallGuard {
    rt: Arc<HookRuntime>,
    thread_id: u64,
    call_id: u64,
    api_id: u32,
    leave_schema_id: u32,
    armed: bool,
}

impl ComCallGuard {
    pub fn new(rt: &Arc<HookRuntime>, thread_id: u64, call_id: u64) -> Self {
        Self::new_for(
            rt,
            thread_id,
            call_id,
            COM_METHOD_API_ID,
            COM_METHOD_LEAVE_SCHEMA_ID,
        )
    }

    pub fn new_for(
        rt: &Arc<HookRuntime>,
        thread_id: u64,
        call_id: u64,
        api_id: u32,
        leave_schema_id: u32,
    ) -> Self {
        Self {
            rt: Arc::clone(rt),
            thread_id,
            call_id,
            api_id,
            leave_schema_id,
            armed: true,
        }
    }

    /// 元の呼び出しが正常に戻った：武装解除し、Drop しても何もしない。
    pub fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for ComCallGuard {
    fn drop(&mut self) {
        if !self.armed || !native_tls_available() {
            return;
        }
        self.armed = false;
        let _guard = ReentrancyGuard::try_enter();
        pop_call(self.call_id);
        let rt = Arc::clone(&self.rt);
        let (thread_id, call_id, api_id, leave_schema_id) = (
            self.thread_id,
            self.call_id,
            self.api_id,
            self.leave_schema_id,
        );
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if api_id == COM_METHOD_API_ID && leave_schema_id == COM_METHOD_LEAVE_SCHEMA_ID {
                // COM メソッドは専用の入口を使う（L02）。WinRT・コールバックは
                // 汎用の record_aborted_for で api_id を直接指定する。
                rt.record_com_aborted(thread_id, call_id);
            } else {
                rt.record_aborted_for(thread_id, call_id, api_id, leave_schema_id);
            }
        }));
    }
}
///
/// 保持している間、その Detour は「進行中」として数えられる。
/// 終了手順はこの数が 0 になるまで IAT を復元しないため、復元は
/// 進行中の呼び出しと競合しない。Drop で自動的に退出する。
pub struct DetourFlight {
    rt: RuntimeRef,
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
        Self::begin_owned(Arc::clone(rt))
    }

    /// [`DetourFlight::begin`] that takes over the caller's reference instead
    /// of cloning it (one fewer shared reference-count update per call).
    pub fn begin_owned(rt: Arc<HookRuntime>) -> Option<Self> {
        Self::begin_ref(RuntimeRef::Shared(rt))
    }

    /// Enter with a reference from [`RuntimeSlot::for_detour_ref`]. A hazard
    /// reference is already counted as in flight (it was published before
    /// this gate check, see [`crate::hazard`]); a shared one adds to the
    /// counter and re-checks the gate.
    #[inline]
    pub fn begin_ref(rt: RuntimeRef) -> Option<Self> {
        if !rt.recording_enabled.load(Ordering::SeqCst) {
            return None;
        }
        // P2-9: once an allocation has failed (the reserve was used), every
        // Detour passes through without recording: recording allocates, and
        // a failed allocation would abort the target. Counted as missing.
        if crate::alloc_reserve::low_memory() {
            rt.agent.note_missing_call();
            return None;
        }
        if let RuntimeRef::Shared(shared) = &rt {
            shared.in_flight.fetch_add(1, Ordering::SeqCst);
            if !shared.recording_enabled.load(Ordering::SeqCst) {
                shared.in_flight.fetch_sub(1, Ordering::SeqCst);
                return None;
            }
        }
        Some(Self { rt })
    }

    #[inline]
    pub fn runtime(&self) -> &HookRuntime {
        &self.rt
    }
}

impl Drop for DetourFlight {
    #[inline]
    fn drop(&mut self) {
        if let RuntimeRef::Shared(shared) = &self.rt {
            shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        // A hazard reference withdraws its hazard when `rt` drops.
    }
}

/// A Detour's reference to its runtime: a shared `Arc`, or a pointer kept
/// valid by this thread's published hazard ([`crate::hazard`]), which costs
/// no shared read-modify-write. Not `Send`: a hazard belongs to its thread.
pub enum RuntimeRef {
    Shared(Arc<HookRuntime>),
    Hazard {
        rt: std::ptr::NonNull<HookRuntime>,
        slot: u32,
        /// false when an outer Detour on this thread already publishes the
        /// same runtime; the outer one withdraws it.
        owned: bool,
    },
}

impl RuntimeRef {
    /// A shared reference to the same runtime.
    pub fn to_arc(&self) -> Arc<HookRuntime> {
        match self {
            Self::Shared(rt) => Arc::clone(rt),
            // SAFETY: the hazard keeps the allocation (and a strong count
            // held by the slot) alive; this adds one strong reference.
            Self::Hazard { rt, .. } => unsafe {
                Arc::increment_strong_count(rt.as_ptr());
                Arc::from_raw(rt.as_ptr())
            },
        }
    }
}

impl std::ops::Deref for RuntimeRef {
    type Target = HookRuntime;
    #[inline]
    fn deref(&self) -> &HookRuntime {
        match self {
            Self::Shared(rt) => rt,
            // SAFETY: valid while the hazard is published (see `to_arc`).
            Self::Hazard { rt, .. } => unsafe { rt.as_ref() },
        }
    }
}

impl Drop for RuntimeRef {
    #[inline]
    fn drop(&mut self) {
        if let Self::Hazard {
            slot, owned: true, ..
        } = self
        {
            crate::hazard::clear(*slot);
        }
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
// Globally unique revisions also distinguish slots reconstructed at the same address.
// Exhaustion refuses publication rather than wrapping into an old TLS identity.
static NEXT_RUNTIME_REVISION: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static RUNTIME_CACHE_READY: Cell<bool> = const { Cell::new(false) };
    static RUNTIME_CACHE_BUSY: Cell<bool> = const { Cell::new(false) };
    static DETOUR_RUNTIME: RefCell<RuntimeCache> = const { RefCell::new(RuntimeCache::EMPTY) };
}

/// This thread's last runtime: the slot revision it was read under, an
/// uncounted pointer (dereferenced only behind a published hazard after the
/// revision re-check), and the thread's hazard slot.
struct RuntimeCache {
    revision: u64,
    runtime: *const HookRuntime,
    hazard: u32,
}
/// No hazard slot claimed yet.
const NO_HAZARD: u32 = u32::MAX;
/// The table was full: this thread keeps the shared path.
const HAZARD_EXHAUSTED: u32 = u32::MAX - 1;
impl RuntimeCache {
    const EMPTY: Self = Self {
        revision: 0,
        runtime: std::ptr::null(),
        hazard: NO_HAZARD,
    };
    fn hazard_slot(&self) -> Option<u32> {
        (self.hazard < HAZARD_EXHAUSTED).then_some(self.hazard)
    }
}
impl Drop for RuntimeCache {
    fn drop(&mut self) {
        capture_tls_teardown();
        if let Some(slot) = self.hazard_slot() {
            crate::hazard::release(slot);
        }
    }
}

// Rust registers a destructor on first access to the cache's TLS key.
// That registration can allocate and enter HeapAlloc's detour before the
// RefCell borrow exists. Guard the *TLS access*, not just its contents.
struct RuntimeCacheAccess;
impl RuntimeCacheAccess {
    fn enter() -> Option<Self> {
        RUNTIME_CACHE_BUSY
            .try_with(|busy| if busy.replace(true) { None } else { Some(Self) })
            .ok()
            .flatten()
    }
}
impl Drop for RuntimeCacheAccess {
    fn drop(&mut self) {
        let _ = RUNTIME_CACHE_BUSY.try_with(|busy| busy.set(false));
    }
}

pub struct RuntimeSlot {
    revision: AtomicU64,
    current: RwLock<RuntimeState>,
}
struct RuntimeState {
    active: Option<Arc<HookRuntime>>,
    retired: Option<Arc<HookRuntime>>,
    /// Replaced runtimes a thread's hazard may still publish; freed once no
    /// hazard does ([`RuntimeSlot::reclaim`]).
    graveyard: Vec<Arc<HookRuntime>>,
}

impl RuntimeSlot {
    pub const fn new() -> Self {
        Self {
            revision: AtomicU64::new(0),
            current: RwLock::new(RuntimeState {
                active: None,
                retired: None,
                graveyard: Vec::new(),
            }),
        }
    }

    /// アクティブなセッションが無ければ登録する。ある場合は、
    /// 渡したランタイムをそのまま `Err` で返す。
    pub fn register(&self, rt: Arc<HookRuntime>) -> Result<(), Arc<HookRuntime>> {
        let mut cur = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cur.active.is_some() {
            return Err(rt);
        }
        if let Some(old) = &cur.retired {
            for id in 0..=MAX_API_ID {
                if rt.original(id as u32) == 0 {
                    rt.set_original(id as u32, old.original(id as u32));
                }
            }
            for i in 0..COM_FACTORY_COUNT {
                if rt.com_original(i) == 0 {
                    rt.set_com_original(i, old.com_original(i));
                }
            }
            for i in 0..WINRT_ACTIVATION_COUNT {
                if rt.winrt_original(i) == 0 {
                    rt.set_winrt_original(i, old.winrt_original(i));
                }
            }
            for i in 0..CALLBACK_HOOK_COUNT {
                if rt.callback_original(i) == 0 {
                    rt.set_callback_original(i, old.callback_original(i));
                }
            }
        }
        #[allow(deprecated)] // fetch_update supports the Rust 1.87 MSRV.
        let revision = NEXT_RUNTIME_REVISION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .expect("runtime revision exhausted");
        cur.active = Some(rt);
        self.revision.store(revision, Ordering::Release);
        Ok(())
    }

    /// 現在のセッションのランタイム（Detour の入口が掴む）。
    pub fn current(&self) -> Option<Arc<HookRuntime>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .clone()
    }

    /// Late detours retain a disabled runtime even after IAT restoration.
    pub fn for_detour(&self) -> Option<Arc<HookRuntime>> {
        self.for_detour_ref().map(|rt| rt.to_arc())
    }

    /// [`RuntimeSlot::for_detour`] for the recording path: on a warm cache
    /// the reference is a published hazard, with no shared reference-count
    /// update. An entry concurrent with replacement may still take the old
    /// runtime, whose recording gate is disabled before unregister publishes
    /// retirement.
    #[inline]
    pub fn for_detour_ref(&self) -> Option<RuntimeRef> {
        // The cache never keeps a session's Agent/mappings alive: its pointer
        // is uncounted and used only behind a hazard after the revision
        // re-check; a replaced runtime is freed once no hazard publishes it.
        // With every capture key alive the cache's TLS is already registered,
        // so its access needs no registration guard (nested borrows are still
        // refused by the RefCell below).
        if let Some(_access) = (ReentrancyGuard::is_active()
            && RUNTIME_CACHE_READY.try_with(Cell::get).unwrap_or(false))
        .then(|| {
            if capture_tls_live() {
                Some(None)
            } else {
                RuntimeCacheAccess::enter().map(Some)
            }
        })
        .flatten()
        {
            if let Ok(Some(rt)) = DETOUR_RUNTIME.try_with(|cache| {
                let mut cache = cache.try_borrow_mut().ok()?;
                let revision = self.revision.load(Ordering::Acquire);
                if revision != 0 && cache.revision == revision {
                    if let Some(rt) = Self::cached_hazard(&cache, || {
                        self.revision.load(Ordering::Acquire) == revision
                    }) {
                        return Some(rt);
                    }
                }
                self.fill_cache(&mut cache)
            }) {
                return Some(rt);
            }
        }
        let state = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .active
            .as_ref()
            .or(state.retired.as_ref())
            .cloned()
            .map(RuntimeRef::Shared)
    }

    #[inline(always)]
    fn cached_hazard(
        cache: &RuntimeCache,
        still_current: impl FnOnce() -> bool,
    ) -> Option<RuntimeRef> {
        let slot = cache.hazard_slot()?;
        let rt = std::ptr::NonNull::new(cache.runtime as *mut HookRuntime)?;
        let published = crate::hazard::published(slot);
        if std::ptr::eq(published, rt.as_ptr()) {
            // An outer Detour of this thread publishes it and outlives us.
            return Some(RuntimeRef::Hazard {
                rt,
                slot,
                owned: false,
            });
        }
        if !published.is_null() {
            return None; // the outer Detour uses another runtime
        }
        crate::hazard::publish(slot, rt.as_ptr());
        if !still_current() {
            crate::hazard::clear(slot);
            return None;
        }
        Some(RuntimeRef::Hazard {
            rt,
            slot,
            owned: true,
        })
    }

    #[cold]
    fn fill_cache(&self, cache: &mut RuntimeCache) -> Option<RuntimeRef> {
        let state = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = state.active.as_ref().or(state.retired.as_ref())?.clone();
        // Load under the lock: the revision must describe this snapshot.
        let revision = self.revision.load(Ordering::Relaxed);
        drop(state);
        if cache.hazard == NO_HAZARD {
            cache.hazard = crate::hazard::claim().unwrap_or(HAZARD_EXHAUSTED);
        }
        cache.revision = revision;
        cache.runtime = Arc::as_ptr(&rt);
        Some(RuntimeRef::Shared(rt))
    }

    /// Free graveyard runtimes no hazard publishes. Runs outside the lock:
    /// dropping a runtime can call hooked HeapFree.
    fn reclaim(&self, mut graveyard: Vec<Arc<HookRuntime>>) {
        // Each was replaced under an older revision; entering threads
        // re-check the revision after publishing (see `crate::hazard`).
        graveyard.retain(|rt| crate::hazard::count(Arc::as_ptr(rt)) > 0);
        if !graveyard.is_empty() {
            self.current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .graveyard
                .extend(graveyard);
        }
    }

    /// 登録解除は「自分が登録したランタイム」に対してだけ行う
    /// （後継セッションの登録を誤って消さない）。解除したら true。
    pub fn unregister(&self, rt: &Arc<HookRuntime>) -> bool {
        let mut cur = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cur.active.as_ref().is_some_and(|c| Arc::ptr_eq(c, rt)) {
            rt.shutdown_recording();
            let retired = cur.active.take();
            let previous = std::mem::replace(&mut cur.retired, retired);
            let mut graveyard = std::mem::take(&mut cur.graveyard);
            graveyard.extend(previous);
            drop(cur); // dropping an old runtime can itself call hooked HeapFree
            self.reclaim(graveyard);
            true
        } else {
            false
        }
    }
}

impl Drop for RuntimeSlot {
    fn drop(&mut self) {
        let state = self.current.get_mut().unwrap_or_else(|e| e.into_inner());
        let runtimes = state
            .active
            .take()
            .into_iter()
            .chain(state.retired.take())
            .chain(std::mem::take(&mut state.graveyard));
        for rt in runtimes {
            if crate::hazard::count(Arc::as_ptr(&rt)) > 0 {
                // A thread still publishes it: leak rather than free under it.
                std::mem::forget(rt);
            }
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

/// Call ID のセッション別シード。セッションごとに [`CALL_ID_RANGE`] の範囲を
/// 割り当てることで、終了間際に残ったスレッドローカルの呼出
/// スタックフレーム（旧セッションの Call ID）が、次セッションの
/// ID と衝突して親子関係を誤らせることを防ぐ。
static NEXT_CALL_ID_SEED: AtomicU64 = AtomicU64::new(1);
/// Call IDs per session. Threads reserve [`CALL_ID_BLOCK_LEN`] at a time and
/// abandon the rest of a block when they exit, so a session can consume up to
/// 256 IDs per thread. 2^32 per session ran out after about 16.7 million
/// short-lived threads and then overlapped the next session (review N4);
/// 2^40 needs 2^32 threads, and still leaves 2^24 sessions per process.
const CALL_ID_RANGE: u64 = 1 << 40;
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);
/// (runtime id, thread id, registration epoch)。
type RegistrationKey = (u64, u64, u64);
thread_local! {
    // Copy-only native TLS: no allocation or destructor registration in a Hook.
    static REGISTERED_THREAD: Cell<Option<(u64, u64, u64)>> = const { Cell::new(None) };
    /// Slot を取れなかった登録の否定キャッシュ (P1-1): (キー, 失敗時の
    /// SlotPool::free_epoch)。Slot が空くまで (free_epoch が進むまで) は
    /// 登録をやり直さない。やり直しは共有ロックを取るので、記録中の
    /// スレッドが空きの見込みなしに繰り返すと、そこで TerminateThread
    /// されたときにロックが残る (レビュー P0)。
    static REGISTER_FAILED: Cell<Option<(RegistrationKey, u64)>> = const { Cell::new(None) };
    /// Call IDs reserved by this thread: (runtime_id, next, end).
    static CALL_ID_BLOCK: Cell<(u64, u64, u64)> = const { Cell::new((0, 0, 0)) };
}
/// Call IDs a thread reserves at once. A shared atomic add per call was a
/// read-modify-write on a cache line every recording thread writes; one per
/// block amortizes it. IDs stay unique within the session's range; they
/// are not ordered across threads (nothing orders them, `global_order` does).
const CALL_ID_BLOCK_LEN: u64 = 256;

/// Registration epochs, one per bucket of thread IDs. The end of a thread
/// invalidates the cached registration only of threads in its bucket. A
/// single epoch made every recording thread re-register (taking the
/// registration locks) after any thread ended; a thread terminated by
/// `TerminateThread` while holding one of them blocked every later thread
/// (review P0, Windows E2E terminate-writer). Windows thread IDs are
/// multiples of 4, so two IDs share a bucket only 16384 IDs apart.
const REGISTRATION_EPOCH_BUCKETS: usize = 4096;

fn registration_bucket(thread_id: u64) -> usize {
    (thread_id >> 2) as usize % REGISTRATION_EPOCH_BUCKETS
}

pub struct HookRuntime {
    runtime_id: u64,
    registration_epochs: Box<[AtomicU64]>,
    agent: Arc<Agent>,
    /// Slot index 順の space_available 通知。スレッドが Slot を取得した
    /// 時点で、そのスレッド（Ring）へ結線する（R7 の Ring 単位結線）。
    space_notifies: Vec<Arc<RingNotify>>,
    data_ready: Option<ProcessNotify>,
    originals: Box<[AtomicUsize]>,
    /// Immutable target classification, computed before publishing this runtime.
    runtime_targets: Box<[bool]>,
    /// Capture Policy で記録対象から外した API（Bootstrap v15）。
    /// API ID で引く。既定は全 API が記録対象（false）。
    capture_excluded: Box<[bool]>,
    /// Detour 入口の判定表: Runtime 独自 API の除外と Capture Policy の
    /// 除外を合成したもの。入口では 1 回の配列参照だけで決める。
    suppressed: Box<[bool]>,
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
    /// Runtime 独自の API も記録するか（L07/L23）。既定は false
    /// （記録しない）。Bootstrap v5 で Host から渡す。
    record_runtime_apis: bool,
    /// 詳細調査モード（L15）。既定は false（内部 API を記録しない）。
    /// 有効な場合のみ、内部 API（Nt*）の呼び出しを記録する。
    /// Bootstrap v8 で Host から渡す。
    detailed_mode: bool,
    /// 呼び出し元アドレスによる標準の記録境界（L23）が準備できたか。
    /// 偽の間は呼び出し元を判定せず、全呼び出しを記録する（fail-open）。
    caller_boundary: AtomicBool,
    /// COM 追跡対象の登録表（L02）。セッション単位。Detour は
    /// ここからインターフェイスの同一性・寿命を引く。
    com_tracker: Mutex<ComTracker>,
    /// COM Factory 関数の元関数ポインタ（L02）。engine が Inline Hook
    /// の設置時に格納し、Factory Detour が引く。API 表の originals とは
    /// 別の表（Factory 関数は API 表に無いため）。
    com_factory_originals: [AtomicUsize; COM_FACTORY_COUNT],
    /// WinRT アクティベーション関数の元関数ポインタ（L14）。COM Factory
    /// と同じく API 表に無いため、別の表に持つ。
    winrt_activation_originals: [AtomicUsize; WINRT_ACTIVATION_COUNT],
    /// コールバック検出フック関数の元関数ポインタ（L16）。COM Factory /
    /// WinRT と同じく API 表に無いため、別の表に持つ。
    callback_hook_originals: [AtomicUsize; CALLBACK_HOOK_COUNT],
}

impl HookRuntime {
    pub fn new(
        agent: Arc<Agent>,
        space_notifies: Vec<Arc<RingNotify>>,
        data_ready: Option<ProcessNotify>,
    ) -> Self {
        Self {
            runtime_id: NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed),
            registration_epochs: (0..REGISTRATION_EPOCH_BUCKETS)
                .map(|_| AtomicU64::new(0))
                .collect(),
            agent,
            space_notifies,
            data_ready,
            // Indexed by API ID; heap storage keeps thousands of slots off
            // the initialization thread's stack.
            originals: (0..=MAX_API_ID).map(|_| AtomicUsize::new(0)).collect(),
            runtime_targets: (0..=MAX_API_ID)
                .map(|id| {
                    crate::api::api_by_id(id as u32)
                        .is_some_and(|api| shirusu_trace::module::is_runtime_module(api.module))
                })
                .collect(),
            capture_excluded: vec![false; MAX_API_ID + 1].into_boxed_slice(),
            suppressed: vec![false; MAX_API_ID + 1].into_boxed_slice(),
            next_call_id: AtomicU64::new(
                NEXT_CALL_ID_SEED.fetch_add(CALL_ID_RANGE, Ordering::Relaxed),
            ),
            seen_threads: Mutex::new(HashSet::new()),
            recording_enabled: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            pending_overlapped: OverlappedRegistry::new(),
            record_runtime_apis: false,
            detailed_mode: false,
            caller_boundary: AtomicBool::new(false),
            com_tracker: Mutex::new(ComTracker::new()),
            com_factory_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            winrt_activation_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            callback_hook_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
        .with_recomputed_suppression()
    }

    fn with_recomputed_suppression(mut self) -> Self {
        for id in 0..self.suppressed.len() {
            self.suppressed[id] = (!self.record_runtime_apis && self.runtime_targets[id])
                || self.capture_excluded[id];
        }
        self
    }

    /// Capture Policy（Bootstrap v15）を設定する。`selected` が Some の
    /// ときは、そこに含まれない API 表の API を記録せず素通しにする
    /// （引数取得・Ring 書き込み・Host の回収が起きない）。None は全 API を
    /// 記録する。構築時に 1 回だけ呼ぶ（`Arc` 化する前）。COM / WinRT /
    /// コールバックのイベントは API 表に無いため、この選択の対象外。
    pub fn with_capture_selection(mut self, selected: Option<&HashSet<u32>>) -> Self {
        for id in 0..self.capture_excluded.len() {
            self.capture_excluded[id] = match selected {
                Some(set) => id != 0 && !set.contains(&(id as u32)),
                None => false,
            };
        }
        self.with_recomputed_suppression()
    }

    /// Capture Policy で記録対象から外した API か。
    pub fn excluded_by_capture_policy(&self, api_id: u32) -> bool {
        self.capture_excluded
            .get(api_id as usize)
            .copied()
            .unwrap_or(false)
    }

    /// COM の診断用オプション（L02）を設定する。構築時に 1 回だけ
    /// 呼ぶ（`Arc` 化する前）。既定は false（Interceptor 自身は
    /// `QueryInterface` を呼ばない）。
    pub fn with_diagnostic_query_interface(self, enabled: bool) -> Self {
        self.com_tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_diagnostic_query_interface(enabled);
        self
    }

    /// COM 追跡対象の登録表へ排他的にアクセスする。engine の
    /// Factory / メソッド Detour が使う。ロック中に記録は行わないこと
    /// （記録経路はこのロックを取らないため、デッドロックはしないが、
    /// 長時間の保持は他の Detour を止める）。
    pub fn with_com_tracker<R>(&self, f: impl FnOnce(&mut ComTracker) -> R) -> R {
        f(&mut self
            .com_tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// COM Factory 関数の元関数ポインタを格納する（L02）。
    pub fn set_com_original(&self, factory_index: usize, addr: usize) {
        if let Some(slot) = self.com_factory_originals.get(factory_index) {
            slot.store(addr, Ordering::Release);
        }
    }

    /// COM Factory 関数の元関数ポインタを引く。
    pub fn com_original(&self, factory_index: usize) -> usize {
        self.com_factory_originals
            .get(factory_index)
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// WinRT アクティベーション関数の元関数ポインタを格納する（L14）。
    pub fn set_winrt_original(&self, activation_index: usize, addr: usize) {
        if let Some(slot) = self.winrt_activation_originals.get(activation_index) {
            slot.store(addr, Ordering::Release);
        }
    }

    /// WinRT アクティベーション関数の元関数ポインタを引く。
    pub fn winrt_original(&self, activation_index: usize) -> usize {
        self.winrt_activation_originals
            .get(activation_index)
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// コールバック検出フック関数の元関数ポインタを格納する（L16）。
    pub fn set_callback_original(&self, hook_index: usize, addr: usize) {
        if let Some(slot) = self.callback_hook_originals.get(hook_index) {
            slot.store(addr, Ordering::Release);
        }
    }

    /// コールバック検出フック関数の元関数ポインタを引く。
    pub fn callback_original(&self, hook_index: usize) -> usize {
        self.callback_hook_originals
            .get(hook_index)
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Runtime 独自の API も記録するかを設定する（L23）。構築時に
    /// 1 回だけ呼ぶ（`Arc` 化する前）。既定は false（記録しない）。
    pub fn with_record_runtime_apis(mut self, enabled: bool) -> Self {
        self.record_runtime_apis = enabled;
        self.with_recomputed_suppression()
    }

    /// Runtime 独自の API も記録するか。
    pub fn record_runtime_apis(&self) -> bool {
        self.record_runtime_apis
    }

    /// 詳細調査モード（L15）を設定する。構築時に 1 回だけ呼ぶ
    /// （`Arc` 化する前）。既定は false（内部 API を記録しない）。
    pub fn with_detailed_mode(mut self, enabled: bool) -> Self {
        self.detailed_mode = enabled;
        self
    }

    /// 詳細調査モード（L15）が有効か。
    pub fn detailed_mode(&self) -> bool {
        self.detailed_mode
    }

    /// 今回の Detour 呼び出しが内部 API（Nt*）で、詳細調査モードが
    /// 無効な場合に真。詳細調査モードが無効な間は、内部 API の Detour
    /// が設置されていても記録せず素通しにする（L15）。
    pub fn should_suppress_internal(&self, api_id: u32) -> bool {
        !self.detailed_mode && crate::api::is_internal_api(api_id)
    }

    /// 呼び出し元アドレスによる標準の記録境界を有効にする（L23）。Windows
    /// ディレクトリを特定できない場合は無効のまま偽を返す（全呼び出しを
    /// 記録する）。Agent の初期化スレッドで、Hook の設置前に呼ぶ。
    pub fn enable_caller_boundary(&self) -> bool {
        let ready = crate::caller::prepare_boundary();
        self.caller_boundary.store(ready, Ordering::Release);
        ready
    }

    /// 呼び出し元アドレスによる標準の記録境界が有効か。
    pub fn caller_boundary_enabled(&self) -> bool {
        self.caller_boundary.load(Ordering::Acquire)
    }

    /// 入口スタブが渡した呼び出し元アドレスが Windows 内部で、標準の境界の
    /// 外にあるか。`caller == 0`（IAT 等スタブを通らない経路）、境界が無効、
    /// 詳細調査モード、分類不明はいずれも偽（記録する）。
    #[inline]
    pub fn should_suppress_caller(&self, caller: usize) -> bool {
        if caller == 0 || self.detailed_mode || !self.caller_boundary_enabled() {
            return false;
        }
        crate::caller::should_suppress_caller(crate::caller::classify_caller(caller), false)
    }

    /// Runtime 独自の API の除外は呼び出し先で決める。
    /// Runtime から Windows 公開 API への呼び出しは標準でも記録する。
    pub fn should_suppress_api(&self, module: &str) -> bool {
        let target = shirusu_trace::module::is_runtime_module(module)
            .then_some(shirusu_trace::module::ModuleClass::Runtime);
        crate::caller::should_suppress_target(target, self.record_runtime_apis)
    }

    /// Apply the same Runtime-target policy using the immutable API index,
    /// combined with the Agent-side Capture Policy (Bootstrap v15).
    /// Unknown IDs remain fail-open; no caller module classification is implied.
    #[inline]
    pub fn should_suppress_api_id(&self, api_id: u32) -> bool {
        self.suppressed
            .get(api_id as usize)
            .copied()
            .unwrap_or(false)
    }

    /// 記録が有効か。終了手順 (shutdown_recording) が始まると false。
    pub fn recording_active(&self) -> bool {
        self.recording_enabled.load(Ordering::SeqCst)
    }

    /// 現在記録区間に入っている Detour の数。
    /// Detours in the recording section: shared references counted at entry
    /// plus threads whose hazard publishes this runtime. Call it after
    /// disabling recording to get an upper bound that only decreases.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst) + crate::hazard::count(self)
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
    ///
    /// Only the first check pays the process-wide fence of [`Self::in_flight`]
    /// (`FlushProcessWriteBuffers` on Windows). A Detour blocked in a wait is
    /// common at shutdown; polling with a fence each time interrupted every
    /// processor running the target for the whole timeout (review N2). After
    /// recording is disabled and one fenced scan ran, later scans only need to
    /// see hazards clear (see [`crate::hazard::count_published`]).
    pub fn wait_in_flight_drained(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        if self.in_flight() == 0 {
            return true;
        }
        let mut polls = 0u32;
        loop {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            // Brief yields first, then back off: a long-blocked Detour should
            // not keep a core busy for the whole timeout.
            if polls < 64 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_micros(500));
            }
            polls = polls.saturating_add(1);
            let remaining =
                self.in_flight.load(Ordering::SeqCst) + crate::hazard::count_published(self);
            if remaining == 0 {
                return true;
            }
        }
    }

    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }

    pub fn alloc_call_id(&self) -> u64 {
        let reserved = CALL_ID_BLOCK.try_with(|block| {
            let (owner, next, end) = block.get();
            if owner == self.runtime_id && next < end {
                block.set((owner, next + 1, end));
                return next;
            }
            let start = self
                .next_call_id
                .fetch_add(CALL_ID_BLOCK_LEN, Ordering::Relaxed);
            block.set((self.runtime_id, start + 1, start + CALL_ID_BLOCK_LEN));
            start
        });
        // Thread teardown: no thread-local block, take one ID directly.
        reserved.unwrap_or_else(|_| self.next_call_id.fetch_add(1, Ordering::Relaxed))
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
    #[inline]
    pub fn ensure_thread(&self, thread_id: u64) {
        if !native_tls_available() {
            return;
        }
        let key = self.registration_key(thread_id);
        if REGISTERED_THREAD
            .try_with(|cache| cache.get() == Some(key))
            .unwrap_or(false)
        {
            return;
        }
        // An exit of another thread in the same bucket (or of a terminated
        // thread whose ID this thread reused) invalidated the cache. A thread
        // that still records through its own live Ring confirms that without
        // a lock; registration (seen set, thread table, notification wiring)
        // takes global locks, which a thread terminated mid-recording must
        // never hold.
        if self.agent.current_thread_registered(thread_id) {
            let _ = REGISTERED_THREAD.try_with(|cache| cache.set(Some(key)));
            return;
        }
        // Exit notices queued by DLL_THREAD_DETACH are processed here, by a
        // thread about to register, and not on every recording call: the
        // processing (thread table, seen set, Heap frees) ran on whichever
        // thread recorded next, so TerminateThread could cut a long-running
        // recording thread off inside it with a global lock held (review P0,
        // Windows E2E terminate-writer). Draining first still retires an
        // exited thread's Ring before a new thread reuses its ID.
        // A thread that found no Slot retries only after a Slot was freed
        // (lock-free check), and its retry neither processes exit notices nor
        // reaps: it is a recording thread, possibly long-running.
        let failed_at = REGISTER_FAILED
            .try_with(|c| c.get())
            .ok()
            .flatten()
            .filter(|(k, _)| k.0 == self.runtime_id && k.1 == thread_id)
            .map(|(_, free_epoch)| free_epoch);
        if let Some(free_epoch) = failed_at {
            let now = self.agent.pool().free_epoch();
            if now == free_epoch {
                return;
            }
            // Not a registration: the Agent hands this thread a Ring that a
            // registering, exiting or reclaiming thread built for it (lock-free
            // for this thread). The seen set, notification wiring and exit
            // notice are skipped; an exit without notice is found by the
            // thread's liveness like a terminated thread's.
            let key = self.registration_key(thread_id);
            if self.agent.thread_begin(thread_id).is_some() {
                let _ = REGISTER_FAILED.try_with(|c| c.set(None));
                let _ = REGISTERED_THREAD.try_with(|cache| cache.set(Some(key)));
            } else {
                let _ = REGISTER_FAILED.try_with(|c| c.set(Some((key, now))));
            }
            return;
        }
        crate::fls::drain_pending_exits();
        let key = self.registration_key(thread_id);
        self.register_thread(thread_id, key);
    }

    fn registration_key(&self, thread_id: u64) -> (u64, u64, u64) {
        let epoch =
            self.registration_epochs[registration_bucket(thread_id)].load(Ordering::Acquire);
        (self.runtime_id, thread_id, epoch)
    }

    #[cold]
    #[inline(never)]
    fn register_thread(&self, thread_id: u64, key: (u64, u64, u64)) {
        // Read before claiming: a Slot freed after a failed claim is seen.
        let free_epoch = self.agent.pool().free_epoch();
        {
            let seen = self
                .seen_threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if seen.contains(&thread_id) {
                let _ = REGISTERED_THREAD.try_with(|cache| cache.set(Some(key)));
                return;
            }
        }
        let Some(handle) = self.agent.thread_begin(thread_id).or_else(|| {
            // Slot 不足は、終了したスレッドの回収がまだなだけかも
            // しれない (P1-4)。強制終了したスレッドの Ring も隔離して
            // (レビュー P0)、1 回だけ回収を試してから再取得する。
            self.reap_terminated_threads();
            self.agent.poll_reclaims();
            self.agent.thread_begin(thread_id)
        }) else {
            // Slot 不足。記録時に NoSlot として数えられる。次の数十回は
            // 登録をやり直さない (P1-1: 記録されないスレッドが最も遅く
            // なり、他スレッドとも共有 Mutex で競合していた)。
            let _ = REGISTER_FAILED.try_with(|c| c.set(Some((key, free_epoch))));
            return;
        };
        let _ = REGISTER_FAILED.try_with(|c| c.set(None));
        if let Some(notify) = self.space_notifies.get(handle.index) {
            self.agent
                .attach_space_available_notify(thread_id, Arc::clone(notify));
        }
        self.seen_threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(thread_id);
        // P1-4: このスレッドの終了通知 (FLS デストラクタ) を武装する。
        // 武装は呼び出しスレッド自身に対して行う (FLS はスレッド
        // ごとの格納域であり、ensure_thread は記録するスレッドの
        // 文脈で呼ばれる)。
        crate::fls::arm_current_thread(thread_id);
        let _ = REGISTERED_THREAD.try_with(|cache| cache.set(Some(key)));
    }

    /// スレッド終了の通知 (レビュー #6 P1-4)。FLS デストラクタ
    /// (agent-dll が結線する) から、終了するスレッド自身の文脈で
    /// 呼ばれる。seen から外し (同じ OS スレッド ID が再利用されて
    /// も新しい状態で始められる)、Agent へ終了を伝え、ついでに
    /// 回収可能な他の Slot の回収も試みる (管理パス)。
    pub fn thread_exit(&self, thread_id: u64) {
        self.seen_threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&thread_id);
        self.agent.thread_exit(thread_id);
        if self.agent.reap_due() {
            self.reap_terminated_threads();
        }
        self.agent.poll_reclaims();
        // Native detach is processed on a different thread. Invalidate cached
        // registration only after removing the old slot, including TID reuse.
        self.invalidate_registration(thread_id);
    }

    /// 強制終了 (`TerminateThread`) で終了通知が届かなかったスレッドの
    /// Ring を隔離して回収待ちへ送る (レビュー P0)。終了はカーネルの
    /// 終了状態で確かめる ([`Agent::reap_terminated_threads`])。回収した
    /// スレッドは通常の終了と同じく seen から外す。管理パス専用。
    pub fn reap_terminated_threads(&self) -> usize {
        let reaped = self.agent.reap_terminated_threads();
        if reaped.is_empty() {
            return 0;
        }
        let mut seen = self
            .seen_threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for tid in &reaped {
            seen.remove(tid);
        }
        drop(seen);
        for tid in &reaped {
            self.invalidate_registration(*tid);
        }
        reaped.len()
    }

    /// Make a thread with this ID register again on its next call.
    fn invalidate_registration(&self, thread_id: u64) {
        self.registration_epochs[registration_bucket(thread_id)].fetch_add(1, Ordering::Release);
    }

    fn signal_if_needed(&self, result: &RecordResult) {
        // A payload-degraded event still publishes a descriptor. Forward its
        // wakeup too, so the Host can drain it without waiting for the poll.
        if let RecordResult::Written(
            WriteOutcome::Published { notify, .. } | WriteOutcome::PublishedDegraded { notify, .. },
        ) = result
        {
            if *notify != NotifySignal::None {
                if let Some(n) = &self.data_ready {
                    let _ = n.notify_data_ready();
                }
            }
        }
    }

    /// Detour hot path for an Enter: [`HookRuntime::record_enter`] without
    /// returning the outcome (detours ignore it).
    #[inline]
    pub fn emit_enter(&self, thread_id: u64, api: &ApiDef, call_id: u64, payload: &[u8]) {
        self.emit(
            thread_id,
            EventKind::CallEnter,
            api.api_id,
            api.enter_schema_id(),
            call_id,
            payload,
        );
    }

    /// Detour hot path for a Leave (see [`HookRuntime::emit_enter`]).
    #[inline]
    pub fn emit_leave(&self, thread_id: u64, api: &ApiDef, call_id: u64, payload: &[u8]) {
        self.emit(
            thread_id,
            EventKind::CallLeave,
            api.api_id,
            api.leave_schema_id(),
            call_id,
            payload,
        );
    }

    #[inline(always)]
    fn emit(
        &self,
        thread_id: u64,
        kind: EventKind,
        api_id: u32,
        schema_id: u32,
        call_id: u64,
        payload: &[u8],
    ) {
        let parent = current_parent_call();
        if self
            .agent
            .record_captured(thread_id, kind, api_id, schema_id, call_id, parent, payload)
        {
            self.notify_data_ready();
        }
    }

    #[cold]
    #[inline(never)]
    fn notify_data_ready(&self) {
        if let Some(n) = &self.data_ready {
            let _ = n.notify_data_ready();
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

    /// COM メソッド呼び出しの enter を記録する（L02）。COM イベントは
    /// ApiDef を持たないため、api_id / schema_id を直接指定する。
    pub fn record_com_enter(&self, thread_id: u64, call_id: u64, payload: &[u8]) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_enter(
            thread_id,
            COM_METHOD_API_ID,
            COM_METHOD_ENTER_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    /// COM メソッド呼び出しの leave を記録する（L02）。
    pub fn record_com_leave(&self, thread_id: u64, call_id: u64, payload: &[u8]) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_leave(
            thread_id,
            COM_METHOD_API_ID,
            COM_METHOD_LEAVE_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    pub fn record_com_factory_enter(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let result = self.agent.record_enter(
            thread_id,
            COM_METHOD_API_ID,
            crate::com::COM_FACTORY_ENTER_SCHEMA_ID,
            call_id,
            current_parent_call(),
            payload,
        );
        self.signal_if_needed(&result);
        result
    }
    pub fn record_com_factory_leave(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let result = self.agent.record_leave(
            thread_id,
            COM_METHOD_API_ID,
            crate::com::COM_FACTORY_LEAVE_SCHEMA_ID,
            call_id,
            current_parent_call(),
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    /// 中断した COM メソッド呼び出しを記録する（L08・L02）。
    /// `ComCallGuard` の Drop から呼ぶ。
    pub fn record_com_aborted(&self, thread_id: u64, call_id: u64) {
        self.record_aborted_for(
            thread_id,
            call_id,
            COM_METHOD_API_ID,
            COM_METHOD_LEAVE_SCHEMA_ID,
        );
    }

    /// 中断した呼び出しを api_id / leave Schema を直接指定して記録する
    /// （L14：WinRT アクティベーションイベント・L16：コールバック用。COM は上の
    /// `record_com_aborted` 経由）。`ComCallGuard` の Drop から呼ぶ。
    pub fn record_aborted_for(
        &self,
        thread_id: u64,
        call_id: u64,
        api_id: u32,
        leave_schema_id: u32,
    ) {
        let parent = current_parent_call();
        let result = self
            .agent
            .record_aborted(thread_id, api_id, leave_schema_id, call_id, parent);
        self.signal_if_needed(&result);
    }

    /// WinRT アクティベーション呼び出しの enter を記録する（L14）。
    /// COM イベントと同じく ApiDef を持たないため、api_id / schema_id
    /// を直接指定する。
    pub fn record_winrt_activation_enter(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_enter(
            thread_id,
            WINRT_ACTIVATION_API_ID,
            WINRT_ACTIVATION_ENTER_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    /// WinRT アクティベーション呼び出しの leave を記録する（L14）。
    pub fn record_winrt_activation_leave(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_leave(
            thread_id,
            WINRT_ACTIVATION_API_ID,
            WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    /// コールバックの enter を記録する（L16）。COM / WinRT イベントと
    /// 同じく ApiDef を持たないため、api_id / schema_id を直接指定する。
    pub fn record_callback_enter(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_enter(
            thread_id,
            CALLBACK_API_ID,
            CALLBACK_ENTER_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
    }

    /// コールバックの leave を記録する（L16）。
    pub fn record_callback_leave(
        &self,
        thread_id: u64,
        call_id: u64,
        payload: &[u8],
    ) -> RecordResult {
        let parent = current_parent_call();
        let result = self.agent.record_leave(
            thread_id,
            CALLBACK_API_ID,
            CALLBACK_LEAVE_SCHEMA_ID,
            call_id,
            parent,
            payload,
        );
        self.signal_if_needed(&result);
        result
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

    pub fn begin_pending_overlapped(
        &self,
        address: u64,
        pending: PendingOverlapped,
    ) -> crate::capture::PendingSubmission {
        self.pending_overlapped.submit(address, pending)
    }

    /// [`Self::begin_pending_overlapped`] with the OVERLAPPED contents seen
    /// at submission, checked again at completion (P2-7).
    pub fn begin_signed_overlapped(
        &self,
        address: u64,
        pending: PendingOverlapped,
        signature: Option<crate::capture::OverlappedSignature>,
    ) -> crate::capture::PendingSubmission {
        self.pending_overlapped
            .submit_signed(address, pending, signature)
    }

    /// Take a completed operation only if it is still the one registered
    /// (see [`crate::capture::OverlappedRegistry::take_matching`]).
    pub fn take_matching_overlapped(
        &self,
        overlapped_addr: u64,
        handle: Option<u64>,
        signature: Option<crate::capture::OverlappedSignature>,
    ) -> Option<PendingOverlapped> {
        self.pending_overlapped
            .take_matching(overlapped_addr, handle, signature)
    }

    pub fn cancel_pending_overlapped(&self, address: u64, call_id: u64) {
        self.pending_overlapped.cancel(address, call_id);
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
    fn degraded_descriptor_wakes_waiting_host() {
        let (agent, mut rt) = runtime();
        rt.data_ready = Some(ProcessNotify::new().unwrap());
        let tid = 4141;
        rt.ensure_thread(tid);
        // SAFETY: this test retains the Agent and is the only producer/reader.
        let base = unsafe { agent.thread_region_base(tid) }.unwrap();
        shirusu_transport::layout::store(
            base,
            shirusu_transport::layout::OFF_HOST_WAITING,
            1,
            Ordering::Relaxed,
        );
        let result = rt.record_enter(
            tid,
            api_by_id(API_CREATE_FILE_W).unwrap(),
            rt.alloc_call_id(),
            &[0; 4097],
        );
        assert!(matches!(
            result,
            RecordResult::Written(WriteOutcome::PublishedDegraded {
                notify: NotifySignal::HostWaiting,
                ..
            })
        ));
        assert!(rt
            .data_ready
            .as_ref()
            .unwrap()
            .data_ready
            .wait_timeout(Duration::ZERO));
        let mut reader = unsafe { RingReader::new(base, agent.thread_config()) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert!(batch.events[0].descriptor.payload_dropped());
        assert!(!rt
            .data_ready
            .as_ref()
            .unwrap()
            .data_ready
            .wait_timeout(Duration::ZERO));
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
    fn com_factory_originals_roundtrip() {
        // L02: Factory 関数の元関数は API 表とは別の表に置く。
        let (_agent, rt) = runtime();
        assert_eq!(
            rt.com_original(crate::com::COM_FACTORY_CO_CREATE_INSTANCE),
            0
        );
        rt.set_com_original(crate::com::COM_FACTORY_CO_CREATE_INSTANCE, 0xCAFEBABE);
        assert_eq!(
            rt.com_original(crate::com::COM_FACTORY_CO_CREATE_INSTANCE),
            0xCAFEBABE
        );
        assert_eq!(
            rt.com_original(crate::com::COM_FACTORY_CO_GET_CLASS_OBJECT),
            0
        );
        // 範囲外は静かに 0。
        rt.set_com_original(99, 1);
        assert_eq!(rt.com_original(99), 0);
    }

    #[test]
    fn callback_hook_originals_roundtrip() {
        // L16: コールバック検出フック関数の元関数は API 表とは別の表に置く。
        let (_agent, rt) = runtime();
        assert_eq!(
            rt.callback_original(crate::callback::CALLBACK_HOOK_REGISTER_CLASS_EX_W),
            0
        );
        rt.set_callback_original(
            crate::callback::CALLBACK_HOOK_REGISTER_CLASS_EX_W,
            0xCAFEBABE,
        );
        assert_eq!(
            rt.callback_original(crate::callback::CALLBACK_HOOK_REGISTER_CLASS_EX_W),
            0xCAFEBABE
        );
        assert_eq!(
            rt.callback_original(crate::callback::CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W),
            0
        );
        // 範囲外は静かに 0。
        rt.set_callback_original(99, 1);
        assert_eq!(rt.callback_original(99), 0);
    }

    #[test]
    fn callback_enter_leave_reach_the_ring() {
        // L16: コールバックイベントが API 表と別の api_id / schema_id で
        // Ring へ記録され、親子関係が付く（コールバック中の API 呼び出しは
        // この call_id を親として記録される）。
        use crate::callback::{self, CallbackKind};
        let (agent, rt) = runtime();
        let tid = 4247u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        let enter = callback::callback_enter_values(
            0x1000,
            CallbackKind::WndProc,
            0x0010,
            0,
            0,
            0x7FFA_1234,
        );
        let bytes = callback::encode_callback_enter(&enter).expect("encode enter");
        let r = rt.record_callback_enter(tid, call_id, &bytes);
        assert!(matches!(r, RecordResult::Written(_)));
        // コールバック中の呼び出しは、コールバックイベントを親とする。
        push_call(call_id);
        assert_eq!(current_parent_call(), call_id);
        let leave = callback::callback_leave_values(0);
        let bytes = callback::encode_callback_leave(&leave).expect("encode leave");
        let r = rt.record_callback_leave(tid, call_id, &bytes);
        assert!(matches!(r, RecordResult::Written(_)));
        pop_call(call_id);
        assert_eq!(current_parent_call(), 0);
        // Ring に enter/leave の 2 イベントが残る。
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].descriptor.api_id, callback::CALLBACK_API_ID);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            callback::CALLBACK_ENTER_SCHEMA_ID
        );
        assert_eq!(batch.events[1].descriptor.call_id, call_id);
    }

    #[test]
    fn com_enter_leave_reach_the_ring() {
        // L02: COM メソッドイベントが API 表と別の api_id / schema_id で
        // Ring へ記録される。
        use crate::com;
        let (agent, rt) = runtime();
        let tid = 4246u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        let enter = com::com_method_enter_values(
            0x1000,
            &com::IID_ISHELL_LINK_W.bytes,
            20,
            "IShellLinkW::SetPath",
            &com::raw_arg_slots(&[0xABCD]),
            &[],
        );
        let bytes = com::encode_com_enter(&enter).expect("encode enter");
        let r = rt.record_com_enter(tid, call_id, &bytes);
        assert!(matches!(r, RecordResult::Written(_)));
        push_call(call_id);
        let leave = com::com_method_leave_values(0, 0, 0);
        let bytes = com::encode_com_leave(&leave).expect("encode leave");
        let r = rt.record_com_leave(tid, call_id, &bytes);
        assert!(matches!(r, RecordResult::Written(_)));
        pop_call(call_id);

        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].descriptor.api_id, com::COM_METHOD_API_ID);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            com::COM_METHOD_ENTER_SCHEMA_ID
        );
        assert_eq!(
            batch.events[1].descriptor.schema_id,
            com::COM_METHOD_LEAVE_SCHEMA_ID
        );
        assert_eq!(batch.events[0].descriptor.call_id, call_id);
        assert_eq!(batch.events[1].descriptor.call_id, call_id);
    }

    #[test]
    fn com_call_guard_records_aborted_when_dropped_armed() {
        // L02 + L08: COM メソッドの元の呼び出しが戻らずにガードが
        // drop されたら、CallAborted が COM の schema_id で記録される。
        use crate::com;
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4247u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        let enter = com::com_method_enter_values(
            0x1000,
            &com::IID_ISHELL_LINK_W.bytes,
            3,
            "IShellLinkW::GetPath",
            &[],
            &[],
        );
        let bytes = com::encode_com_enter(&enter).expect("encode enter");
        assert!(matches!(
            rt.record_com_enter(tid, call_id, &bytes),
            RecordResult::Written(_)
        ));
        push_call(call_id);
        {
            let _guard = ComCallGuard::new(&rt, tid, call_id);
        }
        assert_eq!(current_parent_call(), 0, "aborted call pops the stack");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(EventKind::CallAborted)
        );
        assert_eq!(batch.events[1].descriptor.api_id, com::COM_METHOD_API_ID);
        assert_eq!(
            batch.events[1].descriptor.schema_id,
            com::COM_METHOD_LEAVE_SCHEMA_ID
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
    fn nested_detour_during_capture_tls_registration_cannot_initialize_cache() {
        std::thread::spawn(|| {
            let slot = RuntimeSlot::new();
            let (_, rt) = runtime();
            let rt = Arc::new(rt);
            assert!(slot.register(rt.clone()).is_ok());
            assert!(!RUNTIME_CACHE_READY.with(Cell::get));
            let guard = ReentrancyGuard::try_enter_with(|| {
                // CALL_STACK/Agent TLS destructor registration can enter here
                // before try_enter has finished preparing capture TLS.
                assert!(ReentrancyGuard::is_active());
                assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &rt));
                true
            })
            .unwrap();
            assert_eq!(DETOUR_RUNTIME.with(|c| c.borrow().revision), 0);
            drop(guard);
            let _guard = ReentrancyGuard::try_enter().unwrap();
            assert!(RUNTIME_CACHE_READY.with(Cell::get));
            assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &rt));
            assert_ne!(DETOUR_RUNTIME.with(|c| c.borrow().revision), 0);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn runtime_tls_registration_reentry_uses_passthrough_snapshot() {
        let _guard = ReentrancyGuard::try_enter().unwrap();
        let slot = RuntimeSlot::new();
        let (_, rt) = runtime();
        let rt = Arc::new(rt);
        assert!(slot.register(rt.clone()).is_ok());
        let access = RuntimeCacheAccess::enter().unwrap();
        assert!(RuntimeCacheAccess::enter().is_none());
        // Models a detoured allocation while the TLS destructor is registered.
        assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &rt));
        drop(access);
        assert!(RuntimeCacheAccess::enter().is_some());
    }

    #[test]
    fn cached_runtime_tracks_replacement_without_retaining_session() {
        let _guard = ReentrancyGuard::try_enter().unwrap();
        let slot = RuntimeSlot::new();
        let (_, old) = runtime();
        let old = Arc::new(old);
        let weak = Arc::downgrade(&old);
        assert!(slot.register(old.clone()).is_ok());
        assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &old));
        // A hot cache must not acquire the shared lock.
        let lock = slot.current.write().unwrap();
        assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &old));
        drop(lock);
        assert!(slot.unregister(&old));
        assert!(!slot.for_detour().unwrap().recording_active());
        let (_, new) = runtime();
        let new = Arc::new(new);
        assert!(slot.register(new.clone()).is_ok());
        assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &new));
        assert!(slot.unregister(&new)); // releases the previous retired session
        drop(old);
        assert!(weak.upgrade().is_none());
        drop(new);
        drop(slot);
    }

    #[test]
    fn cached_reader_observes_shutdown_and_reattach_from_another_thread() {
        let slot = Arc::new(RuntimeSlot::new());
        let (_, old) = runtime();
        let old = Arc::new(old);
        assert!(slot.register(old.clone()).is_ok());
        let (_, new) = runtime();
        let new = Arc::new(new);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let reader = {
            let slot = slot.clone();
            let old = old.clone();
            let new = new.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let _guard = ReentrancyGuard::try_enter().unwrap();
                let held = slot.for_detour().unwrap();
                assert!(Arc::ptr_eq(&held, &old));
                barrier.wait();
                barrier.wait();
                assert!(DetourFlight::begin(&held).is_none());
                assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &new));
            })
        };
        barrier.wait();
        assert!(slot.unregister(&old));
        assert!(slot.register(new).is_ok());
        barrier.wait();
        reader.join().unwrap();
    }

    /// A warm cache takes the hazard path: no shared counter, still counted.
    fn warm_hazard(slot: &RuntimeSlot) -> RuntimeRef {
        let first = slot.for_detour_ref().unwrap();
        assert!(matches!(first, RuntimeRef::Shared(_)), "cold cache fills");
        drop(first);
        let warm = slot.for_detour_ref().unwrap();
        assert!(matches!(warm, RuntimeRef::Hazard { owned: true, .. }));
        warm
    }

    #[test]
    fn hazard_flight_is_counted_until_it_leaves() {
        std::thread::spawn(|| {
            let _guard = ReentrancyGuard::try_enter().unwrap();
            let slot = RuntimeSlot::new();
            let (_, rt) = runtime();
            let rt = Arc::new(rt);
            assert!(slot.register(rt.clone()).is_ok());
            let flight = DetourFlight::begin_ref(warm_hazard(&slot)).unwrap();
            assert_eq!(rt.in_flight.load(Ordering::SeqCst), 0, "no shared counter");
            assert_eq!(rt.in_flight(), 1);
            {
                // A nested Detour of the same thread shares the outer hazard.
                let nested = slot.for_detour_ref().unwrap();
                assert!(matches!(nested, RuntimeRef::Hazard { owned: false, .. }));
                let inner = DetourFlight::begin_ref(nested).unwrap();
                assert_eq!(rt.in_flight(), 1);
                drop(inner);
                assert_eq!(rt.in_flight(), 1, "the outer hazard stays published");
            }
            assert_eq!(rt.shutdown_recording(), 1);
            assert!(!rt.wait_in_flight_drained(Duration::from_millis(5)));
            drop(flight);
            assert_eq!(rt.in_flight(), 0);
            assert!(DetourFlight::begin_ref(slot.for_detour_ref().unwrap()).is_none());
            assert_eq!(
                rt.in_flight(),
                0,
                "a refused entry leaves nothing published"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn replaced_runtime_is_freed_only_after_its_hazard_clears() {
        let slot = Arc::new(RuntimeSlot::new());
        let (_, old) = runtime();
        let old = Arc::new(old);
        let weak = Arc::downgrade(&old);
        assert!(slot.register(old.clone()).is_ok());
        let (entered, release) = (
            Arc::new(std::sync::Barrier::new(2)),
            Arc::new(std::sync::Barrier::new(2)),
        );
        let holder = {
            let (slot, entered, release) = (slot.clone(), entered.clone(), release.clone());
            std::thread::spawn(move || {
                let _guard = ReentrancyGuard::try_enter().unwrap();
                let held = warm_hazard(&slot);
                entered.wait();
                release.wait();
                // Still the old runtime, still readable.
                assert!(!held.recording_active());
                drop(held);
            })
        };
        entered.wait();
        assert!(slot.unregister(&old));
        drop(old);
        let (_, mid) = runtime();
        let mid = Arc::new(mid);
        assert!(slot.register(mid.clone()).is_ok());
        assert!(slot.unregister(&mid)); // retires mid; old goes to the graveyard
        assert!(weak.upgrade().is_some(), "a published hazard keeps it");
        release.wait();
        holder.join().unwrap();
        let (_, last) = runtime();
        let last = Arc::new(last);
        assert!(slot.register(last.clone()).is_ok());
        assert!(slot.unregister(&last)); // the next reclaim frees it
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn shutdown_never_misses_a_hazard_flight() {
        let slot = Arc::new(RuntimeSlot::new());
        let (_, rt) = runtime();
        let rt = Arc::new(rt);
        assert!(slot.register(rt.clone()).is_ok());
        let drained = Arc::new(AtomicBool::new(false));
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let (slot, drained) = (slot.clone(), drained.clone());
                std::thread::spawn(move || {
                    let _guard = ReentrancyGuard::try_enter().unwrap();
                    let mut entered = 0u32;
                    loop {
                        let Some(rt) = slot.for_detour_ref() else {
                            break;
                        };
                        let Some(flight) = DetourFlight::begin_ref(rt) else {
                            break;
                        };
                        assert!(!drained.load(Ordering::SeqCst), "entered after drain");
                        std::hint::spin_loop();
                        assert!(!drained.load(Ordering::SeqCst), "in flight after drain");
                        drop(flight);
                        entered += 1;
                    }
                    entered
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        rt.shutdown_recording();
        assert!(rt.wait_in_flight_drained(Duration::from_secs(5)));
        drained.store(true, Ordering::SeqCst);
        let entered: u32 = workers.into_iter().map(|w| w.join().unwrap()).sum();
        assert!(entered > 0);
    }

    /// Review P1: record, shut down and re-attach over and over with the real
    /// asymmetric fences (compiler fence + FlushProcessWriteBuffers on the
    /// Windows x86 and x64 CI jobs). Persistent workers record through the
    /// hazard and writer-owner fast paths across runtime swaps; per cycle a
    /// management thread takes every writer's exclusive path and a reader
    /// drains the Rings while the main thread shuts down, unregisters and
    /// registers a fresh runtime. Checked: nothing is in flight on a drained
    /// runtime, every Ring validates with increasing sequences, and every
    /// replaced runtime is freed. `SHIRUSU_STRESS_CYCLES` scales it.
    #[test]
    fn record_shutdown_reattach_stress() {
        use std::sync::atomic::AtomicUsize;
        const WORKERS: u64 = 4;
        let cycles: u32 = std::env::var("SHIRUSU_STRESS_CYCLES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let cfg = RingConfig::new(64, 4096);
        let slot = Arc::new(RuntimeSlot::new());
        let drained_rt = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = Arc::new(AtomicU64::new(0));
        let workers: Vec<_> = (0..WORKERS)
            .map(|w| {
                let (slot, drained_rt, stop, recorded) = (
                    slot.clone(),
                    drained_rt.clone(),
                    stop.clone(),
                    recorded.clone(),
                );
                std::thread::spawn(move || {
                    let _guard = ReentrancyGuard::try_enter().unwrap();
                    let api = api_by_id(API_READ_FILE).unwrap();
                    let tid = 7000 + w;
                    let mut call = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let Some(rt) = slot.for_detour_ref() else {
                            std::thread::yield_now();
                            continue;
                        };
                        let Some(flight) = DetourFlight::begin_ref(rt) else {
                            std::thread::yield_now();
                            continue;
                        };
                        let rt = flight.runtime();
                        let me = rt as *const HookRuntime as usize;
                        assert_ne!(drained_rt.load(Ordering::SeqCst), me, "entered after drain");
                        call += 1;
                        let _ = rt.record_enter(tid, api, call, b"stress");
                        let _ = rt.record_leave(tid, api, call, b"stress");
                        assert_ne!(
                            drained_rt.load(Ordering::SeqCst),
                            me,
                            "in flight after drain"
                        );
                        drop(flight);
                        recorded.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        let mut replaced = Vec::new();
        for _ in 0..cycles {
            let agent = Arc::new(Agent::new(
                Arc::new(SlotPool::new(WORKERS as usize + 1)),
                cfg,
                Arc::new(HostMonitor::always_alive()),
            ));
            let rt = Arc::new(HookRuntime::new(Arc::clone(&agent), Vec::new(), None));
            assert!(slot.register(rt.clone()).is_ok());
            let cycle_done = AtomicBool::new(false);
            std::thread::scope(|scope| {
                // Remote users of every writer (exclusive path, heavy fence).
                scope.spawn(|| {
                    let notify = Arc::new(RingNotify::new().unwrap());
                    while !cycle_done.load(Ordering::Relaxed) {
                        for w in 0..WORKERS {
                            let _ = agent.attach_space_available_notify(7000 + w, notify.clone());
                        }
                        std::thread::yield_now();
                    }
                });
                // Single reader per Ring, validating as it drains.
                scope.spawn(|| {
                    let mut readers: std::collections::HashMap<u64, (RingReader, u64)> =
                        std::collections::HashMap::new();
                    let drain =
                        |readers: &mut std::collections::HashMap<u64, (RingReader, u64)>| {
                            for w in 0..WORKERS {
                                let tid = 7000 + w;
                                let (reader, last) = match readers.entry(tid) {
                                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        // SAFETY: the Agent outlives this scope
                                        // and keeps a registered thread's region.
                                        let Some(base) = (unsafe { agent.thread_region_base(tid) })
                                        else {
                                            continue;
                                        };
                                        e.insert((unsafe { RingReader::new(base, cfg) }, 0))
                                    }
                                };
                                let batch = reader.drain_all();
                                assert!(
                                    batch.integrity_error.is_none(),
                                    "{:?}",
                                    batch.integrity_error
                                );
                                for e in &batch.events {
                                    assert!(e.descriptor.sequence > *last || *last == 0);
                                    *last = e.descriptor.sequence;
                                }
                            }
                        };
                    while !cycle_done.load(Ordering::Relaxed) {
                        drain(&mut readers);
                        std::thread::yield_now();
                    }
                    drain(&mut readers);
                });
                std::thread::sleep(Duration::from_millis(3));
                rt.shutdown_recording();
                assert!(rt.wait_in_flight_drained(Duration::from_secs(10)));
                drained_rt.store(Arc::as_ptr(&rt) as usize, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
                cycle_done.store(true, Ordering::Relaxed);
            });
            assert!(slot.unregister(&rt));
            replaced.push(Arc::downgrade(&rt));
        }
        stop.store(true, Ordering::Relaxed);
        for w in workers {
            w.join().unwrap();
        }
        assert!(recorded.load(Ordering::Relaxed) > 0);
        // One more swap reclaims the graveyard now that no hazard remains.
        let (_, last) = runtime();
        let last = Arc::new(last);
        assert!(slot.register(last.clone()).is_ok());
        assert!(slot.unregister(&last));
        drop(last);
        let (_, sweep) = runtime();
        let sweep = Arc::new(sweep);
        assert!(slot.register(sweep.clone()).is_ok());
        assert!(slot.unregister(&sweep));
        for weak in &replaced {
            assert!(weak.upgrade().is_none(), "a replaced runtime leaked");
        }
    }

    #[test]
    fn cached_runtime_never_aliases_another_slot() {
        let _guard = ReentrancyGuard::try_enter().unwrap();
        for _ in 0..32 {
            let slot = RuntimeSlot::new();
            let (_, rt) = runtime();
            let rt = Arc::new(rt);
            assert!(slot.register(rt.clone()).is_ok());
            assert!(Arc::ptr_eq(&slot.for_detour().unwrap(), &rt));
        }
    }

    #[test]
    fn late_detour_after_unregister_retains_original() {
        let slot = Arc::new(RuntimeSlot::new());
        let (_, rt) = runtime();
        let rt = Arc::new(rt);
        rt.set_original(API_READ_FILE, 0x1234);
        assert!(slot.register(rt.clone()).is_ok());
        let gate = Arc::new(std::sync::Barrier::new(2));
        let late_slot = slot.clone();
        let late_gate = gate.clone();
        let late = std::thread::spawn(move || {
            late_gate.wait(); // entry delayed until restoration and unregistration
            let rt = late_slot.for_detour().expect("late passthrough runtime");
            assert!(!rt.recording_active());
            assert_eq!(rt.original(API_READ_FILE), 0x1234);
        });
        assert!(slot.unregister(&rt));
        gate.wait();
        late.join().unwrap();
        let (_, replacement) = runtime();
        let replacement = Arc::new(replacement);
        assert!(slot.register(replacement.clone()).is_ok());
        assert_eq!(replacement.original(API_READ_FILE), 0x1234);
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
        assert!(first1.abs_diff(first2) >= CALL_ID_RANGE);
    }

    #[derive(Clone, Copy)]
    struct MockLastError<'a>(&'a std::cell::Cell<u32>);
    impl LastErrorCell for MockLastError<'_> {
        fn get(&self) -> u32 {
            self.0.get()
        }
        fn set(&self, code: u32) {
            self.0.set(code);
        }
    }

    #[test]
    fn last_error_guard_restores_entry_value_before_original() {
        // レビュー #6 P1-5: 引数取得が LastError を書き換えても、
        // 元の API は呼び出し側の入口時点の値を観測する。元の API が
        // 成功して LastError を触らなかった場合、呼び出し側にも
        // 入口時点の値が見える (Hook 依存の値にならない)。
        let cell = std::cell::Cell::new(0x1234);
        let mut guard = LastErrorGuard::capture(MockLastError(&cell));
        assert_eq!(guard.entry_value(), 0x1234);
        cell.set(87); // 引数取得の失敗が書き換えた状況
        guard.restore_before_original();
        assert_eq!(cell.get(), 0x1234, "original observes the entry value");
        // 元の API が成功し LastError を触らなかった: 値は入口のまま
        assert_eq!(guard.capture_after_original(), 0x1234);
        assert_eq!(guard.after_original_value(), Some(0x1234));
        cell.set(55); // leave 記録が書き換えた状況
        guard.restore_for_return();
        assert_eq!(cell.get(), 0x1234, "caller observes the original's result");
    }

    #[test]
    fn last_error_guard_propagates_originals_error_to_caller() {
        // 元の API が失敗してセットした値が、記録側の書き換えに
        // 紛れず呼び出し側へ届く。
        let cell = std::cell::Cell::new(9);
        let mut guard = LastErrorGuard::capture(MockLastError(&cell));
        cell.set(87); // 引数取得の書き換え
        guard.restore_before_original();
        assert_eq!(cell.get(), 9);
        cell.set(2); // 元の API が ERROR_FILE_NOT_FOUND をセット
        assert_eq!(guard.capture_after_original(), 2);
        cell.set(123); // leave 記録の書き換え
        guard.restore_for_return();
        assert_eq!(cell.get(), 2);
    }

    #[test]
    fn repeated_thread_registration_does_not_acquire_the_shared_mutex() {
        let (_agent, rt) = runtime();
        rt.ensure_thread(771);
        // A cached hit must not even attempt to read this poisoned mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _seen = rt.seen_threads.lock().unwrap();
            panic!("poison management lock");
        }));
        rt.ensure_thread(771);
    }

    #[test]
    fn registration_cache_does_not_cross_runtime_sessions() {
        let (first_agent, first) = runtime();
        let (second_agent, second) = runtime();
        first.ensure_thread(772);
        assert!(unsafe { first_agent.thread_region_base(772) }.is_some());
        second.ensure_thread(772);
        assert!(unsafe { second_agent.thread_region_base(772) }.is_some());
        assert_ne!(first.runtime_id, second.runtime_id);
    }

    #[test]
    fn thread_exit_frees_the_slot_for_a_new_incarnation() {
        // レビュー #6 P1-4: 終了したスレッドの Slot は、Host が drain
        // すれば同じ TID の新しい incarnation が使える。Pool の
        // 2 スロットを両方埋めた状態で検証する (空きスロットへの
        // 逃げでは回収を検証できない)。
        let (agent, rt) = runtime();
        let tid = 777u64;
        let other = 888u64;
        rt.ensure_thread(tid);
        rt.ensure_thread(other); // 2 スロット目も埋める
        rt.ensure_thread(tid); // Keep this incarnation in the TLS cache.
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let call_id = rt.alloc_call_id();
        rt.record_enter(tid, create, call_id, b"enter-args");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        // Native TLS notices are drained by another still-live thread.
        std::thread::scope(|scope| scope.spawn(|| rt.thread_exit(tid)).join().unwrap());
        // drain されるまでは回収待ちのまま
        assert_eq!(agent.pending_reclaim_count(), 1);
        let mut reader =
            unsafe { shirusu_transport::ring::RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        // 次の ensure が (空きが無いため) 回収を進めてから取得する
        rt.ensure_thread(tid);
        assert_eq!(agent.pending_reclaim_count(), 0);
        let call_id2 = rt.alloc_call_id();
        let r = rt.record_enter(tid, create, call_id2, b"second-incarnation");
        assert!(matches!(r, RecordResult::Written(_)));
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
    fn tls_initialization_cannot_reenter_capture() {
        let guard = ReentrancyGuard::try_enter_with(|| {
            // Model a hooked allocator called while registering a TLS
            // destructor. The nested detour must take its passthrough path.
            assert!(ReentrancyGuard::try_enter().is_none());
            true
        })
        .unwrap();
        assert!(ReentrancyGuard::is_active());
        drop(guard);
        assert!(!ReentrancyGuard::is_active());

        assert!(ReentrancyGuard::try_enter_with(|| false).is_none());
        assert!(!ReentrancyGuard::is_active());
        assert!(std::panic::catch_unwind(|| {
            ReentrancyGuard::try_enter_with(|| panic!("TLS initialization failed"));
        })
        .is_err());
        assert!(ReentrancyGuard::try_enter().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn native_tls_vector_absence_bypasses_rust_tls_access() {
        // No OS calls, allocations, assertions or unwinding while the vector
        // is absent. This reproduces the loader teardown state from the AV.
        let (_agent, rt) = runtime();
        assert!(native_tls_available());
        let saved: usize;
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {}, gs:[0x58]", "mov qword ptr gs:[0x58], 0", out(reg) saved, options(nostack, preserves_flags));
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov {}, fs:[0x2c]", "mov dword ptr fs:[0x2c], 0", out(reg) saved, options(nostack, preserves_flags));
        }
        rt.ensure_thread(123);
        let entered = ReentrancyGuard::try_enter().is_some();
        let active = ReentrancyGuard::is_active();
        ReentrancyGuard::mark_thread_exiting();
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov gs:[0x58], {}", in(reg) saved, options(nostack, preserves_flags));
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov fs:[0x2c], {}", in(reg) saved, options(nostack, preserves_flags));
        }
        assert!(rt.seen_threads.lock().unwrap().is_empty());
        assert!(!entered);
        assert!(!active);
        assert!(ReentrancyGuard::try_enter().is_some());
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

    // --- カバレッジ gap（2026-11-12 13:29）: ビルダ・取得子と
    // WinRT / コールバック / COM 中断の記録経路 ---

    #[test]
    fn runtime_option_builders_roundtrip() {
        // 既定は両方 false。ビルダで立てると取得子がそれを返す。
        let (agent, rt) = runtime();
        assert!(!rt.record_runtime_apis());
        assert!(!rt.detailed_mode());
        let rt = HookRuntime::new(Arc::clone(&agent), Vec::new(), None)
            .with_record_runtime_apis(true)
            .with_detailed_mode(true);
        assert!(rt.record_runtime_apis());
        assert!(rt.detailed_mode());
    }

    #[test]
    fn should_suppress_internal_depends_on_detailed_mode() {
        let (agent, rt) = runtime();
        // 内部 API（Nt*、79〜85）は詳細調査モードが無効な間だけ抑止する。
        assert!(rt.should_suppress_internal(API_NT_CREATE_FILE));
        assert!(rt.should_suppress_internal(API_NT_CREATE_FILE + 6));
        assert!(!rt.should_suppress_internal(API_NT_CREATE_FILE + 7));
        assert!(!rt.should_suppress_internal(API_CREATE_FILE_W));
        let rt = HookRuntime::new(Arc::clone(&agent), Vec::new(), None).with_detailed_mode(true);
        assert!(!rt.should_suppress_internal(API_NT_CREATE_FILE));
    }

    #[test]
    fn original_slots_roundtrip_and_out_of_range() {
        let (_agent, rt) = runtime();
        assert_eq!(rt.com_original(0), 0);
        rt.set_com_original(0, 0x1234);
        assert_eq!(rt.com_original(0), 0x1234);
        rt.set_com_original(999, 0x5678);
        assert_eq!(rt.com_original(999), 0);

        assert_eq!(rt.winrt_original(1), 0);
        rt.set_winrt_original(1, 0x2233);
        assert_eq!(rt.winrt_original(1), 0x2233);
        rt.set_winrt_original(999, 0x4455);
        assert_eq!(rt.winrt_original(999), 0);

        assert_eq!(rt.callback_original(3), 0);
        rt.set_callback_original(3, 0x3344);
        assert_eq!(rt.callback_original(3), 0x3344);
        rt.set_callback_original(999, 0x6677);
        assert_eq!(rt.callback_original(999), 0);
    }

    #[test]
    fn diagnostic_query_interface_option_roundtrips() {
        let (_agent, rt) = runtime();
        assert!(!rt.with_com_tracker(|t| t.diagnostic_query_interface()));
        let rt = rt.with_diagnostic_query_interface(true);
        assert!(rt.with_com_tracker(|t| t.diagnostic_query_interface()));
    }

    #[test]
    fn runtime_slot_register_unregister() {
        // Default とプロセス全体のスロット取得子もここで通す（engine
        // 経由でしか呼ばれないため、Linux のテストでは未実行だった）。
        let _default_slot = RuntimeSlot::default();
        let _ = runtime_slot().current();
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let rt2 = Arc::new(HookRuntime::new(Arc::clone(&agent), Vec::new(), None));
        let slot = RuntimeSlot::new();
        assert!(slot.current().is_none());
        assert!(slot.register(Arc::clone(&rt)).is_ok());
        assert!(Arc::ptr_eq(&slot.current().unwrap(), &rt));
        // 既に登録がある間は 2 件目を拒み、渡したランタイムを返す。
        let back = slot.register(Arc::clone(&rt2)).expect_err("2 件目は拒否");
        assert!(Arc::ptr_eq(&back, &rt2));
        assert!(!slot.unregister(&rt2));
        assert!(slot.unregister(&rt));
        assert!(slot.current().is_none());
        assert!(slot.register(rt2).is_ok());
    }

    #[test]
    fn agent_accessor_returns_the_agent() {
        let (agent, rt) = runtime();
        assert!(Arc::ptr_eq(rt.agent(), &agent));
    }

    #[test]
    fn runtime_api_policy_does_not_exclude_windows_targets() {
        let (agent, rt) = runtime();
        assert!(!rt.should_suppress_api("kernel32.dll"));
        assert!(!rt.should_suppress_api("user32.dll"));
        assert!(rt.should_suppress_api("ucrtbase.dll"));
        let rt =
            HookRuntime::new(Arc::clone(&agent), Vec::new(), None).with_record_runtime_apis(true);
        assert!(!rt.should_suppress_api("ucrtbase.dll"));
        assert!(!rt.should_suppress_api("kernel32.dll"));
    }

    #[test]
    fn indexed_target_policy_matches_module_policy_for_every_api_and_mode() {
        let (agent, _) = runtime();
        for record_runtime in [false, true] {
            let rt = HookRuntime::new(agent.clone(), Vec::new(), None)
                .with_record_runtime_apis(record_runtime);
            for api in crate::api::api_table() {
                assert_eq!(
                    rt.should_suppress_api_id(api.api_id),
                    rt.should_suppress_api(api.module),
                    "{}!{}",
                    api.module,
                    api.function
                );
            }
            assert!(!rt.should_suppress_api_id(0));
            assert!(!rt.should_suppress_api_id(u32::MAX));
        }
    }

    #[test]
    fn capture_selection_suppresses_only_unselected_table_apis() {
        let (agent, _) = runtime();
        let selected: HashSet<u32> = [crate::api::API_CREATE_FILE_W, crate::api::API_CLOSE_HANDLE]
            .into_iter()
            .collect();
        let rt = HookRuntime::new(agent.clone(), Vec::new(), None)
            .with_capture_selection(Some(&selected));
        assert!(!rt.should_suppress_api_id(crate::api::API_CREATE_FILE_W));
        assert!(!rt.should_suppress_api_id(crate::api::API_CLOSE_HANDLE));
        assert!(rt.should_suppress_api_id(crate::api::API_READ_FILE));
        assert!(rt.excluded_by_capture_policy(crate::api::API_READ_FILE));
        // 範囲外の ID は従来どおり fail-open。
        assert!(!rt.should_suppress_api_id(0));
        assert!(!rt.should_suppress_api_id(u32::MAX));
        // Runtime 独自 API の除外は選択と合成され、後から設定しても失われない。
        let runtime_api = crate::api::api_table()
            .find(|a| shirusu_trace::module::is_runtime_module(a.module))
            .map(|a| a.api_id);
        let rt = HookRuntime::new(agent.clone(), Vec::new(), None)
            .with_capture_selection(None)
            .with_record_runtime_apis(false);
        if let Some(id) = runtime_api {
            assert!(rt.should_suppress_api_id(id));
            let mut with_runtime = selected.clone();
            with_runtime.insert(id);
            let rt = HookRuntime::new(agent.clone(), Vec::new(), None)
                .with_capture_selection(Some(&with_runtime))
                .with_record_runtime_apis(true);
            assert!(!rt.should_suppress_api_id(id));
            assert!(rt.should_suppress_api_id(crate::api::API_READ_FILE));
        }
        // 既定（選択なし）は何も外さない。
        let rt = HookRuntime::new(agent, Vec::new(), None).with_record_runtime_apis(true);
        assert!(crate::api::api_table().all(|a| !rt.should_suppress_api_id(a.api_id)));
    }

    #[test]
    fn caller_boundary_never_suppresses_without_a_stub_address_or_in_detailed_mode() {
        let (agent, rt) = runtime();
        assert!(!rt.caller_boundary_enabled());
        assert!(!rt.should_suppress_caller(0));
        let enabled = rt.enable_caller_boundary();
        assert_eq!(enabled, cfg!(windows));
        assert_eq!(rt.caller_boundary_enabled(), enabled);
        // IAT and other stub-less paths carry no caller and stay recorded.
        assert!(!rt.should_suppress_caller(0));
        // This test binary is the main module: Application, never suppressed.
        let own = caller_boundary_never_suppresses_without_a_stub_address_or_in_detailed_mode
            as *const () as usize;
        assert!(!rt.should_suppress_caller(own));
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
            let name: Vec<u16> = "kernelbase.dll".encode_utf16().chain([0]).collect();
            let kernelbase = unsafe { GetModuleHandleW(name.as_ptr()) } as usize;
            assert_ne!(kernelbase, 0);
            assert!(rt.should_suppress_caller(kernelbase + 0x1000));
            let detailed = HookRuntime::new(agent, Vec::new(), None).with_detailed_mode(true);
            assert!(detailed.enable_caller_boundary());
            assert!(!detailed.should_suppress_caller(kernelbase + 0x1000));
        }
        #[cfg(not(windows))]
        drop(agent);
    }

    #[test]
    fn record_com_aborted_writes_aborted_event() {
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let tid = 4250u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        rt.record_com_aborted(tid, call_id);
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallAborted)
        );
        assert_eq!(batch.events[0].descriptor.call_id, call_id);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            COM_METHOD_LEAVE_SCHEMA_ID
        );
    }

    #[test]
    fn com_call_guard_drop_records_aborted() {
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4251u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        push_call(call_id);
        {
            let _guard = ComCallGuard::new(&rt, tid, call_id);
            // 完了させずに drop（元の呼び出しが例外で中断したのと同じ）。
        }
        assert_eq!(current_parent_call(), 0, "aborted call pops the stack");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallAborted)
        );
        assert_eq!(batch.events[0].descriptor.call_id, call_id);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            COM_METHOD_LEAVE_SCHEMA_ID
        );
        assert_eq!(batch.events[0].descriptor.parent_call_id, 0);
    }

    #[test]
    fn com_call_guard_drop_for_winrt_records_aborted_with_winrt_ids() {
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4254u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        push_call(call_id);
        {
            // WinRT 用ガードは new_for で別 api_id を持ち、Drop は汎用の
            // record_aborted_for 経由で中断を記録する（COM 専用入口は使わない）。
            let _guard = ComCallGuard::new_for(
                &rt,
                tid,
                call_id,
                WINRT_ACTIVATION_API_ID,
                WINRT_ACTIVATION_LEAVE_SCHEMA_ID,
            );
        }
        assert_eq!(current_parent_call(), 0, "aborted call pops the stack");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallAborted)
        );
        assert_eq!(batch.events[0].descriptor.call_id, call_id);
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            WINRT_ACTIVATION_LEAVE_SCHEMA_ID
        );
        assert_eq!(batch.events[0].descriptor.parent_call_id, 0);
    }

    #[test]
    fn com_call_guard_completed_drop_records_nothing() {
        let (agent, rt) = runtime();
        let rt = Arc::new(rt);
        let tid = 4252u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        push_call(call_id);
        {
            let mut guard = ComCallGuard::new(&rt, tid, call_id);
            guard.complete();
        }
        pop_call(call_id);
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 0);
    }

    #[test]
    fn winrt_activation_enter_leave_reach_the_ring() {
        use shirusu_transport::descriptor::EventKind;
        let (agent, rt) = runtime();
        let tid = 4253u64;
        rt.ensure_thread(tid);
        let call_id = rt.alloc_call_id();
        assert!(matches!(
            rt.record_winrt_activation_enter(tid, call_id, b"winrt-enter"),
            RecordResult::Written(_)
        ));
        assert!(matches!(
            rt.record_winrt_activation_leave(tid, call_id, b"winrt-leave"),
            RecordResult::Written(_)
        ));
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        let mut reader = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(
            batch.events[0].descriptor.kind_enum(),
            Some(EventKind::CallEnter)
        );
        assert_eq!(
            batch.events[0].descriptor.schema_id,
            WINRT_ACTIVATION_ENTER_SCHEMA_ID
        );
        assert_eq!(batch.events[0].payload, b"winrt-enter");
        assert_eq!(
            batch.events[1].descriptor.kind_enum(),
            Some(EventKind::CallLeave)
        );
        assert_eq!(
            batch.events[1].descriptor.schema_id,
            WINRT_ACTIVATION_LEAVE_SCHEMA_ID
        );
        assert_eq!(batch.events[1].payload, b"winrt-leave");
    }
}
#[test]
fn detours_stay_passthrough_after_capture_tls_destruction() {
    struct ExitProbe(std::sync::mpsc::Sender<(bool, bool, u64)>);
    impl Drop for ExitProbe {
        fn drop(&mut self) {
            let destroyed = CALL_STACK.try_with(|_| ()).is_err();
            let passthrough = ReentrancyGuard::try_enter().is_none();
            self.0
                .send((destroyed, passthrough, current_parent_call()))
                .unwrap();
        }
    }
    thread_local! {
        static PROBE: RefCell<Option<ExitProbe>> = const { RefCell::new(None) };
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Registered first, so its destructor probes the already destroyed
        // capture TLS while the thread is still executing cleanup code.
        PROBE.with(|probe| *probe.borrow_mut() = Some(ExitProbe(tx)));
        push_call(42);
        assert!(ReentrancyGuard::try_enter().is_some());
    })
    .join()
    .unwrap();
    assert_eq!(rx.recv().unwrap(), (true, true, 0));
}

#[test]
fn capture_stops_after_runtime_cache_tls_destruction() {
    struct Probe(std::sync::mpsc::Sender<(bool, bool, bool)>);
    impl Drop for Probe {
        fn drop(&mut self) {
            self.0
                .send((
                    DETOUR_RUNTIME.try_with(|_| ()).is_err(),
                    CALL_STACK.try_with(|_| ()).is_ok(),
                    ReentrancyGuard::try_enter().is_none(),
                ))
                .unwrap();
        }
    }
    thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let guard = ReentrancyGuard::try_enter_with(|| {
            CALL_STACK.try_with(|_| ()).is_ok() && shirusu_agent::current_thread_capture_available()
        })
        .unwrap();
        PROBE.with(|p| *p.borrow_mut() = Some(Probe(tx)));
        drop(guard);
        drop(ReentrancyGuard::try_enter().unwrap());
    })
    .join()
    .unwrap();
    assert_eq!(rx.recv().unwrap(), (true, true, true));
}
