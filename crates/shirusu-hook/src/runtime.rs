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

use crate::api::{ApiDef, API_COUNT};
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
    pub fn try_enter() -> Option<Self> {
        Self::try_enter_with(|| {
            CALL_STACK.try_with(|_| ()).is_ok() && shirusu_agent::current_thread_capture_available()
        })
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
    current: RwLock<RuntimeState>,
}
struct RuntimeState {
    active: Option<Arc<HookRuntime>>,
    retired: Option<Arc<HookRuntime>>,
}

impl RuntimeSlot {
    pub const fn new() -> Self {
        Self {
            current: RwLock::new(RuntimeState {
                active: None,
                retired: None,
            }),
        }
    }

    /// アクティブなセッションが無ければ登録する。ある場合は、
    /// 渡したランタイムをそのまま `Err` で返す。
    pub fn register(&self, rt: Arc<HookRuntime>) -> Result<(), Arc<HookRuntime>> {
        let mut cur = self.current.write().unwrap();
        if cur.active.is_some() {
            return Err(rt);
        }
        if let Some(old) = &cur.retired {
            for id in 0..=API_COUNT {
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
        cur.active = Some(rt);
        Ok(())
    }

    /// 現在のセッションのランタイム（Detour の入口が掴む）。
    pub fn current(&self) -> Option<Arc<HookRuntime>> {
        self.current.read().unwrap().active.clone()
    }

    /// Late detours retain a disabled runtime even after IAT restoration.
    pub fn for_detour(&self) -> Option<Arc<HookRuntime>> {
        let state = self.current.read().unwrap();
        state.active.as_ref().or(state.retired.as_ref()).cloned()
    }

    /// 登録解除は「自分が登録したランタイム」に対してだけ行う
    /// （後継セッションの登録を誤って消さない）。解除したら true。
    pub fn unregister(&self, rt: &Arc<HookRuntime>) -> bool {
        let mut cur = self.current.write().unwrap();
        if cur.active.as_ref().is_some_and(|c| Arc::ptr_eq(c, rt)) {
            rt.shutdown_recording();
            let retired = cur.active.take();
            let previous = std::mem::replace(&mut cur.retired, retired);
            drop(cur); // dropping an old runtime can itself call hooked HeapFree
            drop(previous);
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
    originals: [AtomicUsize; API_COUNT + 1],
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
    /// 呼び出し元分類のためのモジュール一覧（L23）。Detour の入口で
    /// 戻りアドレスから呼び出し元を引く。DLL 起動時に作り、遅れて
    /// ロードされたモジュールには再列挙で追随する。
    caller_modules: RwLock<crate::caller::CallerModules>,
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
            agent,
            space_notifies,
            data_ready,
            originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            next_call_id: AtomicU64::new(NEXT_CALL_ID_SEED.fetch_add(1 << 32, Ordering::Relaxed)),
            seen_threads: Mutex::new(HashSet::new()),
            recording_enabled: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            pending_overlapped: OverlappedRegistry::new(),
            record_runtime_apis: false,
            detailed_mode: false,
            caller_modules: RwLock::new(crate::caller::CallerModules::new()),
            com_tracker: Mutex::new(ComTracker::new()),
            com_factory_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            winrt_activation_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
            callback_hook_originals: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    /// COM の診断用オプション（L02）を設定する。構築時に 1 回だけ
    /// 呼ぶ（`Arc` 化する前）。既定は false（Interceptor 自身は
    /// `QueryInterface` を呼ばない）。
    pub fn with_diagnostic_query_interface(self, enabled: bool) -> Self {
        self.com_tracker
            .lock()
            .unwrap()
            .set_diagnostic_query_interface(enabled);
        self
    }

    /// COM 追跡対象の登録表へ排他的にアクセスする。engine の
    /// Factory / メソッド Detour が使う。ロック中に記録は行わないこと
    /// （記録経路はこのロックを取らないため、デッドロックはしないが、
    /// 長時間の保持は他の Detour を止める）。
    pub fn with_com_tracker<R>(&self, f: impl FnOnce(&mut ComTracker) -> R) -> R {
        f(&mut self.com_tracker.lock().unwrap())
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
        self
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

    /// 呼び出し元分類のためのモジュール一覧を作り直す。DLL 初期化時と、
    /// 一覧に無い呼び出し元が現れたときに呼ぶ。列挙に失敗したら
    /// 従来の一覧を残す（呼び出し元不明 → 記録する fail-open）。
    pub fn refresh_caller_modules(&self) {
        if let Ok(mut guard) = self.caller_modules.write() {
            guard.refresh();
        }
    }

    /// Runtime 独自の API の除外は呼び出し先で決める。
    /// Runtime から Windows 公開 API への呼び出しは標準でも記録する。
    pub fn should_suppress_api(&self, module: &str) -> bool {
        let target = shirusu_trace::module::is_runtime_module(module)
            .then_some(shirusu_trace::module::ModuleClass::Runtime);
        crate::caller::should_suppress_target(target, self.record_runtime_apis)
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
        crate::fls::drain_pending_exits();
        {
            let seen = self.seen_threads.lock().unwrap();
            if seen.contains(&thread_id) {
                return;
            }
        }
        let Some(handle) = self.agent.thread_begin(thread_id).or_else(|| {
            // Slot 不足は、終了したスレッドの回収がまだなだけかも
            // しれない (P1-4)。1 回だけ回収を試してから再取得する。
            self.agent.poll_reclaims();
            self.agent.thread_begin(thread_id)
        }) else {
            return; // Slot 不足。記録時に NoSlot として数えられる
        };
        if let Some(notify) = self.space_notifies.get(handle.index) {
            self.agent
                .attach_space_available_notify(thread_id, Arc::clone(notify));
        }
        self.seen_threads.lock().unwrap().insert(thread_id);
        // P1-4: このスレッドの終了通知 (FLS デストラクタ) を武装する。
        // 武装は呼び出しスレッド自身に対して行う (FLS はスレッド
        // ごとの格納域であり、ensure_thread は記録するスレッドの
        // 文脈で呼ばれる)。
        crate::fls::arm_current_thread(thread_id);
    }

    /// スレッド終了の通知 (レビュー #6 P1-4)。FLS デストラクタ
    /// (agent-dll が結線する) から、終了するスレッド自身の文脈で
    /// 呼ばれる。seen から外し (同じ OS スレッド ID が再利用されて
    /// も新しい状態で始められる)、Agent へ終了を伝え、ついでに
    /// 回収可能な他の Slot の回収も試みる (管理パス)。
    pub fn thread_exit(&self, thread_id: u64) {
        self.seen_threads.lock().unwrap().remove(&thread_id);
        self.agent.thread_exit(thread_id);
        self.agent.poll_reclaims();
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
    ) -> crate::capture::PendingSubmission<'_> {
        self.pending_overlapped.submit(address, pending)
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
        assert!(first2 >= 1 << 32 || first1 >= 1 << 32);
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
        let create = api_by_id(API_CREATE_FILE_W).unwrap();
        let call_id = rt.alloc_call_id();
        rt.record_enter(tid, create, call_id, b"enter-args");
        let base = unsafe { agent.thread_region_base(tid) }.expect("region");
        rt.thread_exit(tid);
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
        assert!(native_tls_available());
        let saved: usize;
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {}, gs:[0x58]", "mov qword ptr gs:[0x58], 0", out(reg) saved, options(nostack, preserves_flags));
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov {}, fs:[0x2c]", "mov dword ptr fs:[0x2c], 0", out(reg) saved, options(nostack, preserves_flags));
        }
        let entered = ReentrancyGuard::try_enter().is_some();
        let active = ReentrancyGuard::is_active();
        ReentrancyGuard::mark_thread_exiting();
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov gs:[0x58], {}", in(reg) saved, options(nostack, preserves_flags));
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov fs:[0x2c], {}", in(reg) saved, options(nostack, preserves_flags));
        }
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
    fn refresh_caller_modules_does_not_panic() {
        let (_agent, rt) = runtime();
        rt.refresh_caller_modules();
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
