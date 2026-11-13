//! SPSC Ring の核。
//!
//! 公開契約（厳密に単一公開点）:
//! 書き手: Payload コピー → Descriptor 書込 → `write_cursor` を Release 更新。
//! 読み手: `write_cursor` を Acquire → 確定分だけコピー → 検証 →
//!         `read_cursor` / `payload_read_position` を Release 更新。
//! 通常経路にプロセス共通ロックも全順序フェンスも使わない。

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::clock::{system_timestamp_source, Clock, TimestampSource};
use crate::descriptor::{flags, CaptureState, EventDescriptor, EventKind};
use crate::layout::*;
use crate::notify::{NotifySignal, PublishNotifyTracker};
use crate::validate::{IntegrityError, MAX_DROPPED_ORIGINAL_LEN};

/// 満杯ポリシーの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowState {
    Normal,
    BoundedWait,
    Overflow,
}
impl OverflowState {
    pub fn to_u64(self) -> u64 {
        match self {
            Self::Normal => 0,
            Self::BoundedWait => 1,
            Self::Overflow => 2,
        }
    }
}

/// Loader Lock の保持状態（書き手への申告）。Windows では DllMain 等の
/// 経路で Loader Lock を保持したまま Hook が呼ばれることがあり、その間は
/// 待機するとデッドロックし得る。保持しているか常に判定できるとは限らない
/// ため、呼び出し側が「分からない」と申告できる三値とする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderLockState {
    /// Loader Lock を保持していないことが分かっている。通常の Hook 経路。
    NotHeld,
    /// Loader Lock を保持している。待機はしない。
    Held,
    /// 保持しているか判定できない。ポリシーに従い 0ms へ切り替える。
    Unknown,
}

#[derive(Debug, Clone)]
pub struct WriterPolicy {
    /// BOUNDED_WAIT の上限。既定 1ms。0 なら待たない。
    pub max_wait: Duration,
    /// OVERFLOW から復帰する使用率閾値（%）。例: 50。
    pub resume_threshold_percent: u64,
    /// 通知の使用率閾値（%）。Descriptor 件数と Payload バイト数を別々に判定する。
    pub notify_threshold_percent: u64,
    /// Loader Lock 等の危険経路では待機禁止。
    pub no_wait_dangerous_path: bool,
    /// Loader Lock の保持が判定できない書き込みで待機上限を 0ms にする。
    /// 既定 true（分からないときは待たないのが安全側）。
    /// 呼び出し側は `RingWriter::set_loader_lock_state` で現在の状態を申告する。
    pub zero_wait_when_loader_lock_unknown: bool,
}
impl Default for WriterPolicy {
    fn default() -> Self {
        Self {
            max_wait: Duration::from_millis(1),
            resume_threshold_percent: 50,
            notify_threshold_percent: 50,
            no_wait_dangerous_path: false,
            zero_wait_when_loader_lock_unknown: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventInput<'a> {
    pub kind: EventKind,
    pub api_id: u32,
    pub schema_id: u32,
    pub call_id: u64,
    pub parent_call_id: u64,
    pub payload: &'a [u8],
    /// Payload の取得結果が既に劣化している場合に指定する。
    pub capture_state: CaptureState,
    /// 全スレッド共通の観測順序番号（L11）。0 は未割当。
    /// Agent が `--order=global` 有効時に観測点で採番して入れる。
    pub global_order: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Published {
        sequence: u64,
        notify: NotifySignal,
    },
    /// Payload だけ落として Descriptor を残した。
    PublishedDegraded {
        sequence: u64,
        reason: CaptureState,
        notify: NotifySignal,
    },
    /// イベント自体を捨てた。Sequence は払い済みで欠番になる。
    Dropped {
        sequence: u64,
        reason: CaptureState,
    },
}

/// 共有領域（プロセス内ではヒープ、Windows では File Mapping が背後にある想定）。
/// バッファは u64 配列で確保し、ベースが 8 バイト（実際はそれ以上）境界に揃うことを保証する。
pub struct SharedRegion {
    // Box<[u64]> で保持すると、Box の move のたびに中身へ Unique retag が
    // 走り、導出済みポインタのタグが無効化される (Miri 検出)。共有メモリ
    // 領域は生割当てのまま保持するのが正しいモデル: アロケータから生まれた
    // ポインタは以後いかなる retag も受けず、構造体の move はスカラの
    // コピーでしかない。Drop で同じ Layout で解放する。
    ptr: *mut u8,
    layout: std::alloc::Layout,
    pub config: RingConfig,
}
// SAFETY: 領域へのアクセスは全て base ポインタ経由に限定され、
// 制御ワードはアトミック操作、Descriptor/Payload は SPSC 公開プロトコル
// (write_cursor の Release/Acquire) でのみ触れる。OS 共有メモリと同格の
// 対象であり、&SharedRegion をスレッド間で共有すること自体は安全。
unsafe impl Sync for SharedRegion {}
// SAFETY: 同上。所有権のスレッド間移動は Box を保持していた頃と同格。
unsafe impl Send for SharedRegion {}
impl SharedRegion {
    pub fn new(config: RingConfig, generation: u64, owner_thread_id: u64) -> Self {
        let layout =
            std::alloc::Layout::from_size_align(config.required_len(), 64).expect("region layout");
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "shared region allocation failed");
        init_control(ptr, config, generation, owner_thread_id);
        Self {
            ptr,
            layout,
            config,
        }
    }
    pub fn base(&self) -> *mut u8 {
        self.ptr
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base() as *const u8, self.config.required_len()) }
    }
    /// # Safety
    /// 返した writer/reader が生きている間、この領域を破棄・移動してはならない。
    pub unsafe fn writer(&self, policy: WriterPolicy, clock: Arc<dyn Clock>) -> RingWriter {
        RingWriter::new(self.base(), self.config, policy, clock)
    }
    /// イベント時刻源を指定して書き手を作る (Windows の QPC 実装用)。
    ///
    /// # Safety
    /// 返した writer が生きている間、この領域を破棄・移動してはならない。
    pub unsafe fn writer_with_timestamps(
        &self,
        policy: WriterPolicy,
        clock: Arc<dyn Clock>,
        timestamps: Arc<dyn TimestampSource>,
    ) -> RingWriter {
        RingWriter::new_with_timestamps(self.base(), self.config, policy, clock, timestamps)
    }
    /// # Safety
    /// 返した reader が生きている間、この領域を破棄・移動してはならない。
    ///
    /// 注意: 返る `RingReader` は検証なしの信頼済み内部用である (R2)。
    /// Host の通常回収経路では使わず、`shirusu-host` の検証付き経路を使うこと。
    pub unsafe fn reader(&self) -> RingReader {
        RingReader::new(self.base(), self.config)
    }
}
impl Drop for SharedRegion {
    fn drop(&mut self) {
        // SAFETY: ptr は new で同じ layout により確保したもので、二重解放はない
        // (SharedRegion はコピーを作らない)。writer/reader の借用が残ったまま
        // 落とすことは呼び出し側の契約違反であり、本クレート内の利用では無い。
        unsafe { std::alloc::dealloc(self.ptr, self.layout) }
    }
}

// Descriptor / Payload の生コピー（公開前領域への書込、確定領域からの読出）。
unsafe fn write_descriptor_at(base: *mut u8, cfg: RingConfig, cursor: u64, desc: &EventDescriptor) {
    let off = cfg.descriptors_offset()
        + (slot_index(cursor, cfg.descriptor_capacity as u64) as usize) * 64;
    std::ptr::copy_nonoverlapping(
        desc as *const EventDescriptor as *const u8,
        base.add(off),
        64,
    );
}
unsafe fn read_descriptor_at(base: *const u8, cfg: RingConfig, cursor: u64) -> EventDescriptor {
    let off = cfg.descriptors_offset()
        + (slot_index(cursor, cfg.descriptor_capacity as u64) as usize) * 64;
    let mut buf = [0u8; 64];
    std::ptr::copy_nonoverlapping(base.add(off), buf.as_mut_ptr(), 64);
    EventDescriptor::from_bytes(&buf).expect("64 bytes always decode")
}
/// 終端をまたぐ場合は末尾と先頭に分割してコピーする。
unsafe fn copy_payload_write(base: *mut u8, cfg: RingConfig, position: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let start = payload_index(position, cfg.payload_capacity as u64) as usize;
    let first = core::cmp::min(data.len(), cfg.payload_capacity - start);
    let dst = base.add(cfg.payload_offset() + start);
    std::ptr::copy_nonoverlapping(data.as_ptr(), dst, first);
    if first < data.len() {
        let dst2 = base.add(cfg.payload_offset());
        std::ptr::copy_nonoverlapping(data.as_ptr().add(first), dst2, data.len() - first);
    }
}
unsafe fn copy_payload_read(
    base: *const u8,
    cfg: RingConfig,
    position: u64,
    len: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if len == 0 {
        return out;
    }
    let start = payload_index(position, cfg.payload_capacity as u64) as usize;
    let first = core::cmp::min(len, cfg.payload_capacity - start);
    std::ptr::copy_nonoverlapping(
        base.add(cfg.payload_offset() + start),
        out.as_mut_ptr(),
        first,
    );
    if first < len {
        std::ptr::copy_nonoverlapping(
            base.add(cfg.payload_offset()),
            out.as_mut_ptr().add(first),
            len - first,
        );
    }
    out
}

/// Descriptor の `payload_len` (u32) への変換。落とした元の長さを格納する
/// ため、u32 を超える場合は切り捨てて小さく見せず u32::MAX へ飽和させる
/// (R6: Host 側の受理上限 MAX_DROPPED_ORIGINAL_LEN と対になる決め)。
/// 正確な欠落バイト数は u64 の Loss カウンタで別途数える。
fn payload_len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

pub struct RingWriter {
    base: *mut u8,
    cfg: RingConfig,
    policy: WriterPolicy,
    clock: Arc<dyn Clock>,
    /// イベント時刻専用の時刻源 (レビュー第2回・項目8)。待機用 `clock`
    /// とは分離し、Clock を差し替えても刻印の原点は動かない。
    timestamps: Arc<dyn TimestampSource>,
    next_sequence: u64,
    payload_write_position: u64,
    state: OverflowState,
    dropped_enter_calls: HashSet<u64>,
    notify_tracker: PublishNotifyTracker,
    payload_notify_tracker: PublishNotifyTracker,
    pub last_wait_ns: u64,
    pub total_wait_ns: u64,
    pub wait_count: u64,
    detached: bool,
    /// 呼び出し側が申告した Loader Lock の保持状態。既定は NotHeld
    /// （従来の挙動を保つ。Windows の Agent は分からない経路で Unknown を申告する）。
    loader_lock_state: LoaderLockState,
}
// SPSC: 書き手は 1 スレッドだけが使う。共有領域自体は Host スレッドと共有される。
unsafe impl Send for RingWriter {}

impl RingWriter {
    /// # Safety
    /// `base` は cfg 分の共有領域を指し、Ring の存続期間中有効であること。
    pub unsafe fn new(
        base: *mut u8,
        cfg: RingConfig,
        policy: WriterPolicy,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::new_with_timestamps(base, cfg, policy, clock, system_timestamp_source())
    }
    /// イベント時刻源を指定する構築。Windows では transport-win の QPC
    /// 実装を渡し、プロセス間で比較可能な刻印にする。
    ///
    /// # Safety
    /// `base` は cfg 分の共有領域を指し、Ring の存続期間中有効であること。
    pub unsafe fn new_with_timestamps(
        base: *mut u8,
        cfg: RingConfig,
        policy: WriterPolicy,
        clock: Arc<dyn Clock>,
        timestamps: Arc<dyn TimestampSource>,
    ) -> Self {
        Self {
            base,
            cfg,
            policy,
            clock,
            timestamps,
            next_sequence: 1,
            payload_write_position: load(base, OFF_PAYLOAD_WRITE_POSITION, Ordering::Relaxed),
            state: OverflowState::Normal,
            dropped_enter_calls: HashSet::new(),
            notify_tracker: PublishNotifyTracker::new(),
            payload_notify_tracker: PublishNotifyTracker::new(),
            last_wait_ns: 0,
            total_wait_ns: 0,
            wait_count: 0,
            detached: false,
            loader_lock_state: LoaderLockState::NotHeld,
        }
    }
    pub fn state(&self) -> OverflowState {
        self.state
    }
    /// 待機に使う Clock を差し替える。Host からその Ring の
    /// `space_available` を受け取ったときに、Agent が Ring ごとに
    /// EventClock へ切り替えるために使う (R7: 通知は Ring 単位であり、
    /// Clock も書き手ごとに結びつける)。
    pub fn set_clock(&mut self, clock: Arc<dyn Clock>) {
        self.clock = clock;
    }
    /// イベント時刻源を差し替える。待機用 Clock の差し替え (R7 の
    /// EventClock 化) とは独立で、刻印だけに効く。
    pub fn set_timestamp_source(&mut self, timestamps: Arc<dyn TimestampSource>) {
        self.timestamps = timestamps;
    }
    /// この書き手が刻印に使うイベント時刻源の周波数。
    pub fn timestamp_frequency(&self) -> u64 {
        self.timestamps.frequency()
    }
    /// 現在の Loader Lock 保持状態の申告を変える。DllMain に入る・出る等、
    /// 呼び出し側が文脈を知った時点で呼ぶ。
    pub fn set_loader_lock_state(&mut self, state: LoaderLockState) {
        self.loader_lock_state = state;
    }
    pub fn loader_lock_state(&self) -> LoaderLockState {
        self.loader_lock_state
    }
    pub fn next_sequence_peek(&self) -> u64 {
        self.next_sequence
    }
    pub fn mark_detached(&mut self) {
        self.detached = true;
    }
    pub fn is_detached(&self) -> bool {
        self.detached
    }
    fn write_cursor(&self) -> u64 {
        load(self.base, OFF_WRITE_CURSOR, Ordering::Relaxed)
    }
    fn read_cursor(&self) -> u64 {
        load(self.base, OFF_READ_CURSOR, Ordering::Acquire)
    }
    fn payload_read_position(&self) -> u64 {
        load(self.base, OFF_PAYLOAD_READ_POSITION, Ordering::Acquire)
    }
    fn descriptor_free(&self) -> u64 {
        let wc = self.write_cursor();
        descriptor_free(wc, self.read_cursor(), self.cfg.descriptor_capacity as u64).unwrap_or(0)
    }
    fn payload_free(&self) -> u64 {
        let used = self
            .payload_write_position
            .saturating_sub(self.payload_read_position());
        (self.cfg.payload_capacity as u64).saturating_sub(used)
    }
    fn usage_percent(&self) -> u64 {
        let wc = self.write_cursor();
        let used = wc.saturating_sub(self.read_cursor());
        usage_percent(used, self.cfg.descriptor_capacity as u64)
    }
    fn set_state(&mut self, s: OverflowState) {
        self.state = s;
        store(self.base, OFF_OVERFLOW_STATE, s.to_u64(), Ordering::Relaxed);
    }

    /// 唯一の公開点。Payload コピー → Descriptor 書込 → write_cursor Release 更新。
    fn publish(&mut self, desc: EventDescriptor, payload: Option<&[u8]>) -> NotifySignal {
        let wc = self.write_cursor();
        let used_before = wc.saturating_sub(self.read_cursor());
        // Descriptor and payload capacities are independent. A large descriptor
        // Ring can exhaust payload storage before its count watermark is reached.
        let payload_usage = payload.filter(|p| !p.is_empty()).map(|p| {
            let before = self
                .payload_write_position
                .saturating_sub(self.payload_read_position());
            (before, before + p.len() as u64)
        });
        if let Some(p) = payload {
            unsafe { copy_payload_write(self.base, self.cfg, desc.payload_position, p) };
            self.payload_write_position = desc.payload_position + p.len() as u64;
            store(
                self.base,
                OFF_PAYLOAD_WRITE_POSITION,
                self.payload_write_position,
                Ordering::Relaxed,
            );
        }
        unsafe { write_descriptor_at(self.base, self.cfg, wc, &desc) };
        // 単一公開点: この Release store より前の書込みは、Acquire で読む読み手から見える。
        store(self.base, OFF_WRITE_CURSOR, wc + 1, Ordering::Release);
        let used_after = used_before + 1;
        let host_waiting = load(self.base, OFF_HOST_WAITING, Ordering::Relaxed) != 0;
        let descriptor_signal = self.notify_tracker.after_publish(
            used_before,
            used_after,
            self.cfg.descriptor_capacity as u64,
            self.policy.notify_threshold_percent,
            host_waiting,
        );
        let payload_signal = payload_usage.map(|(before, after)| {
            self.payload_notify_tracker.after_publish(
                before,
                after,
                self.cfg.payload_capacity as u64,
                self.policy.notify_threshold_percent,
                false,
            )
        });
        if payload_signal == Some(NotifySignal::ThresholdCrossing) {
            NotifySignal::ThresholdCrossing
        } else {
            descriptor_signal
        }
    }

    fn make_desc(
        &self,
        seq: u64,
        input: &EventInput,
        payload_position: u64,
        stored_len: u32,
        extra_flags: u16,
    ) -> EventDescriptor {
        let mut d = EventDescriptor::new(input.kind, seq);
        // 刻印はイベント時刻専用の源から取る (待機用 Clock ではない)。
        d.timestamp_qpc = self.timestamps.now_qpc();
        d.call_id = input.call_id;
        d.parent_call_id = input.parent_call_id;
        d.api_id = input.api_id;
        d.schema_id = input.schema_id;
        d.payload_position = payload_position;
        d.payload_len = stored_len;
        d.flags = input.capture_state.to_flags() | extra_flags;
        d.global_order = input.global_order;
        d
    }

    /// 上限付き待機。空けば true。待機時間は Clock で実測し Control と内部に記録する。
    ///
    /// 仕様の通知節どおり、待機に入る前に「空き待ち中」の意思を Control に示し、
    /// 全順序フェンスを打ってから空きを再確認する。Host はこのフラグを見て、回収で
    /// 空きができたときに `space_available` を SetEvent する。待機を抜けるときは
    /// 必ずフラグを下ろす（タイムアウト・空き獲得のどちらの経路でも）。
    fn bounded_wait(&mut self, need_desc: u64, need_payload: u64) -> bool {
        // Loader Lock 保持中は待機しない。保持が判定できないときは
        // ポリシーに従い 0ms へ切り替える（既定で待たない）。
        if self.policy.no_wait_dangerous_path
            || self.policy.max_wait.is_zero()
            || self.loader_lock_state == LoaderLockState::Held
            || (self.loader_lock_state == LoaderLockState::Unknown
                && self.policy.zero_wait_when_loader_lock_unknown)
        {
            return false;
        }
        self.set_state(OverflowState::BoundedWait);
        self.wait_count += 1;
        store(self.base, OFF_WRITER_WAITING, 1, Ordering::Release);
        std::sync::atomic::fence(Ordering::SeqCst);
        let got_space = self.bounded_wait_inner(need_desc, need_payload);
        store(self.base, OFF_WRITER_WAITING, 0, Ordering::Release);
        got_space
    }
    fn bounded_wait_inner(&mut self, need_desc: u64, need_payload: u64) -> bool {
        let start = self.clock.now_ticks();
        let deadline_ns = self.policy.max_wait.as_nanos() as u64;
        loop {
            if self.descriptor_free() >= need_desc && self.payload_free() >= need_payload {
                let waited = self.clock.elapsed_ns(start, self.clock.now_ticks());
                self.record_wait(waited);
                return true;
            }
            let waited = self.clock.elapsed_ns(start, self.clock.now_ticks());
            if waited >= deadline_ns {
                self.record_wait(waited);
                return false;
            }
            // 残り時間と 50µs の小さい方だけ待つ。スピンし続けない。
            let remain = deadline_ns - waited;
            self.clock.sleep(Duration::from_nanos(remain.min(50_000)));
        }
    }
    fn record_wait(&mut self, ns: u64) {
        self.last_wait_ns = ns;
        self.total_wait_ns = self.total_wait_ns.saturating_add(ns);
        store(self.base, OFF_LAST_WAIT_NS, ns, Ordering::Relaxed);
    }

    /// イベントを 1 件書く（満杯ポリシー状態機械を通す）。
    pub fn write(&mut self, input: EventInput) -> WriteOutcome {
        let seq = self.next_sequence;
        self.next_sequence += 1; // 失敗したイベントにも Sequence を割り当てる
        let payload_len = input.payload.len() as u64;
        // A dropped Enter cannot have a paired normal or exceptional terminal event.
        // Consume tracking on either path and account for every discarded byte.
        if matches!(input.kind, EventKind::CallLeave | EventKind::CallAborted)
            && self.dropped_enter_calls.remove(&input.call_id)
        {
            fetch_add(self.base, OFF_DROPPED_EVENTS, 1);
            fetch_add(self.base, OFF_DROPPED_PAYLOAD_BYTES, payload_len);
            return WriteOutcome::Dropped {
                sequence: seq,
                reason: CaptureState::DroppedByBackpressure,
            };
        }
        let need_desc = 1u64;
        let fits = |w: &Self| {
            w.descriptor_free() >= need_desc
                && (payload_len == 0 || w.payload_free() >= payload_len)
        };
        if self.state == OverflowState::Overflow
            && self.usage_percent() < self.policy.resume_threshold_percent
        {
            self.set_state(OverflowState::Normal);
        }
        if self.state == OverflowState::Normal {
            if fits(self) {
                return self.publish_normal(seq, &input);
            }
            // 容量不足 → BOUNDED_WAIT（危険経路/0ms では待たず OVERFLOW へ）
            if self.bounded_wait(need_desc, payload_len) && fits(self) {
                self.set_state(OverflowState::Normal);
                return self.publish_normal(seq, &input);
            }
            self.set_state(OverflowState::Overflow);
        }
        // OVERFLOW: 待たずに劣化させる
        self.degrade(seq, &input)
    }

    fn publish_normal(&mut self, seq: u64, input: &EventInput) -> WriteOutcome {
        let pos = self.payload_write_position;
        let stored = if input.capture_state == CaptureState::Captured {
            Some(input.payload)
        } else {
            None // 取得できていない値は Payload として格納しない
        };
        let len_for_desc = if stored.is_some() {
            payload_len_u32(input.payload.len())
        } else if input.capture_state == CaptureState::Captured {
            0
        } else {
            payload_len_u32(input.payload.len()) // 落とした元の長さを残す（PAYLOAD_DROPPED 系フラグで区別）
        };
        let extra = if stored.is_none() && input.capture_state != CaptureState::Captured {
            flags::PAYLOAD_DROPPED
        } else {
            0
        };
        let d = self.make_desc(seq, input, pos, len_for_desc, extra);
        let notify = self.publish(d, stored);
        WriteOutcome::Published {
            sequence: seq,
            notify,
        }
    }

    fn degrade(&mut self, seq: u64, input: &EventInput) -> WriteOutcome {
        let payload_len = input.payload.len() as u64;
        // (1) Payload だけ落として Descriptor を残す
        if self.descriptor_free() >= 1 {
            fetch_add(self.base, OFF_DEGRADED_EVENTS, 1);
            fetch_add(self.base, OFF_DROPPED_PAYLOAD_BYTES, payload_len);
            let pos = self.payload_write_position;
            let d = self.make_desc(
                seq,
                input,
                pos,
                payload_len_u32(input.payload.len()),
                flags::PAYLOAD_DROPPED | CaptureState::DroppedByBackpressure.to_flags(),
            );
            let notify = self.publish(d, None);
            return WriteOutcome::PublishedDegraded {
                sequence: seq,
                reason: CaptureState::DroppedByBackpressure,
                notify,
            };
        }
        // (2) Descriptor も書けないのでイベントを捨てる
        fetch_add(self.base, OFF_DROPPED_EVENTS, 1);
        fetch_add(self.base, OFF_DROPPED_PAYLOAD_BYTES, payload_len);
        if input.kind == EventKind::CallEnter {
            self.dropped_enter_calls.insert(input.call_id);
        }
        WriteOutcome::Dropped {
            sequence: seq,
            reason: CaptureState::DroppedByBackpressure,
        }
    }

    pub fn loss_counters(&self) -> LossCounters {
        LossCounters::read_from(self.base)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedEvent {
    pub descriptor: EventDescriptor,
    pub payload: Vec<u8>,
}
impl ReceivedEvent {
    pub fn capture_state(&self) -> CaptureState {
        self.descriptor.capture_state()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainBatch {
    pub events: Vec<ReceivedEvent>,
    /// Sequence 欠番として検出した欠落数。
    pub sequence_gaps: u64,
    /// 多層防御の検証で破損を検出した場合の理由 (レビュー第2回・項目5)。
    /// `Some` のとき、その Descriptor 以降は取り出しておらず、Cursor も
    /// 検証が通った分までしか進んでいない。Reader は破損として停止し、
    /// 以後の drain も同じ理由を返し続ける。
    pub integrity_error: Option<IntegrityError>,
}

/// 検証付き経路と分離された読み手 (信頼済み内部／テスト専用。R2 で格下げ)。
///
/// 共有メモリは Host から見て信頼できないデータであり、**Host の通常回収
/// 経路では使ってはならない**。通常経路は `shirusu-host` の `DrainWorker` /
/// `ValidatingHost` (copy→検証→前進) を使うこと。
/// この型は、書き手と読み手が同じプロセス内で信頼できるテスト・ベンチ・
/// E2E の簡易確認のためにだけ残している。
///
/// 多層防御 (レビュー第2回・項目5): 直接呼ばれた場合に備え、drain は
/// コピーの前に `ValidatingReader` と同等の最低限の検証 (種別・予約領域・
/// 格納長と容量・Payload 位置の範囲と連続性・Sequence の後退) を行い、
/// 破損した Descriptor を生ポインタのコピーへ届かせない。検証失敗時は
/// コピーせず、その Ring の破損として停止する (`DrainBatch::integrity_error`)。
/// ただし Control 全体の検証や世代照合までは行わないため、本番の代替には
/// ならない。
pub struct RingReader {
    base: *mut u8,
    cfg: RingConfig,
    expected_sequence: u64,
    /// 次に期待する Payload 論理位置 (None は未確立＝初めて見る Descriptor)。
    expected_payload_position: Option<u64>,
    /// 一度検出した破損。以後は drain が即座に同じ理由を返す (Ring 停止)。
    integrity_error: Option<IntegrityError>,
    /// `--order=global` 有効なセッションとして検証する (L11)。既定は false。
    allow_global_order: bool,
}
unsafe impl Send for RingReader {}

impl RingReader {
    /// # Safety
    /// `base` は cfg 分の共有領域を指し、Ring の存続期間中有効であること。
    pub unsafe fn new(base: *mut u8, cfg: RingConfig) -> Self {
        Self {
            base,
            cfg,
            expected_sequence: 1,
            expected_payload_position: None,
            integrity_error: None,
            allow_global_order: false,
        }
    }
    /// `--order=global` 有効なセッションとして検証する。
    pub fn with_global_order(mut self, allow: bool) -> Self {
        self.allow_global_order = allow;
        self
    }
    pub fn write_cursor(&self) -> u64 {
        load(self.base, OFF_WRITE_CURSOR, Ordering::Acquire)
    }
    pub fn read_cursor(&self) -> u64 {
        load(self.base, OFF_READ_CURSOR, Ordering::Relaxed)
    }
    /// 未回収の Descriptor 数（write_cursor - read_cursor）。バッファ使用率の
    /// 観測用（L10）。Cursor は進めない。読み取りだけなので回収中の
    /// DrainWorker と並行して使える。
    pub fn descriptor_used(&self) -> u64 {
        self.write_cursor().saturating_sub(self.read_cursor())
    }
    /// 未回収の Payload バイト数（payload_write_position -
    /// payload_read_position）。同上。
    pub fn payload_used(&self) -> u64 {
        load(self.base, OFF_PAYLOAD_WRITE_POSITION, Ordering::Acquire).saturating_sub(load(
            self.base,
            OFF_PAYLOAD_READ_POSITION,
            Ordering::Acquire,
        ))
    }
    /// 書き手が空き待ち中かどうか（Host が `space_available` 通知の要否を判断する）。
    pub fn writer_waiting(&self) -> bool {
        crate::layout::writer_waiting(self.base)
    }
    /// 確定済みイベントを取り出す（最大 max 件）。契約どおりコピーしてから Release で解放する。
    /// コピーの前に多層防御の最小検証を行い、破損を検出したらその Descriptor
    /// 以降は取り出さず Cursor も進めない (型の doc を参照)。
    pub fn drain(&mut self, max: usize) -> DrainBatch {
        let mut batch = DrainBatch::default();
        if let Some(e) = &self.integrity_error {
            batch.integrity_error = Some(e.clone());
            return batch;
        }
        let wc = self.write_cursor(); // Acquire: これが唯一の確定境界
        let rc = self.read_cursor();
        let avail = wc.saturating_sub(rc);
        let n = core::cmp::min(avail, max as u64);
        // 検証の上限は書き手が Control に公開した書込み済み位置。write_cursor を
        // Acquire で読んだ後なので、確定分についてはこの値以下に収まる。
        let payload_write_position = load(self.base, OFF_PAYLOAD_WRITE_POSITION, Ordering::Acquire);
        let mut processed: u64 = 0;
        let mut last_payload_end: Option<u64> = None;
        for i in 0..n {
            let cursor = rc + i;
            let desc = unsafe { read_descriptor_at(self.base, self.cfg, cursor) };
            if let Err(e) = self.check_descriptor(&desc, payload_write_position) {
                batch.integrity_error = Some(e.clone());
                self.integrity_error = Some(e);
                break;
            }
            if desc.sequence > self.expected_sequence {
                batch.sequence_gaps += desc.sequence - self.expected_sequence;
            }
            if desc.sequence >= self.expected_sequence {
                self.expected_sequence = desc.sequence + 1;
            }
            let payload = if desc.payload_dropped() || desc.payload_len == 0 {
                Vec::new()
            } else {
                unsafe {
                    copy_payload_read(
                        self.base,
                        self.cfg,
                        desc.payload_position,
                        desc.payload_len as usize,
                    )
                }
            };
            if !desc.payload_dropped() && desc.payload_len > 0 {
                last_payload_end = Some(desc.payload_position + desc.payload_len as u64);
            } else if !desc.payload_dropped() {
                last_payload_end = Some(desc.payload_position);
            }
            batch.events.push(ReceivedEvent {
                descriptor: desc,
                payload,
            });
            processed += 1;
        }
        if processed > 0 {
            if let Some(end) = last_payload_end {
                store(self.base, OFF_PAYLOAD_READ_POSITION, end, Ordering::Release);
            }
            store(
                self.base,
                OFF_READ_CURSOR,
                rc + processed,
                Ordering::Release,
            );
            fetch_add(self.base, OFF_HOST_DRAIN_COUNT, 1);
        }
        batch
    }
    /// 多層防御の最小検証 (ValidatingReader の `decode_descriptor_checked`
    /// と同じ契約)。通れば期待 Payload 位置をこの Descriptor の終端へ進める。
    fn check_descriptor(
        &mut self,
        desc: &EventDescriptor,
        payload_write_position: u64,
    ) -> Result<(), IntegrityError> {
        if EventKind::from_u16(desc.kind).is_none() || desc.kind == EventKind::Unknown as u16 {
            return Err(IntegrityError::UnknownKind(desc.kind));
        }
        if !self.allow_global_order && desc.global_order != 0 {
            return Err(IntegrityError::GlobalOrderNotAllowed);
        }
        if desc.sequence < self.expected_sequence {
            return Err(IntegrityError::SequenceRegressed {
                expected_at_least: self.expected_sequence,
                found: desc.sequence,
            });
        }
        let stored = if desc.payload_dropped() {
            if desc.payload_len as u64 > MAX_DROPPED_ORIGINAL_LEN {
                return Err(IntegrityError::PayloadTooLarge {
                    len: desc.payload_len as u64,
                    capacity: MAX_DROPPED_ORIGINAL_LEN,
                });
            }
            0
        } else {
            if desc.payload_len as u64 > self.cfg.payload_capacity as u64 {
                return Err(IntegrityError::PayloadTooLarge {
                    len: desc.payload_len as u64,
                    capacity: self.cfg.payload_capacity as u64,
                });
            }
            desc.payload_len as u64
        };
        let end = desc
            .payload_position
            .checked_add(stored)
            .ok_or(IntegrityError::PayloadRangeInvalid)?;
        if end > payload_write_position {
            return Err(IntegrityError::PayloadPositionOutOfRange {
                position: desc.payload_position,
                end,
                write_position: payload_write_position,
            });
        }
        if let Some(expected) = self.expected_payload_position {
            if desc.payload_position != expected {
                return Err(IntegrityError::PayloadPositionNotContiguous {
                    expected,
                    found: desc.payload_position,
                });
            }
        }
        self.expected_payload_position = Some(end);
        Ok(())
    }
    pub fn drain_all(&mut self) -> DrainBatch {
        self.drain(usize::MAX)
    }
    pub fn loss_counters(&self) -> LossCounters {
        LossCounters::read_from(self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn test_writer_reader(cap: usize, pcap: usize) -> (SharedRegion, RingWriter, RingReader) {
        let cfg = RingConfig::new(cap, pcap);
        let region = SharedRegion::new(cfg, 1, 100);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let w = unsafe { region.writer(WriterPolicy::default(), clock) };
        let r = unsafe { region.reader() };
        (region, w, r)
    }
    fn input(kind: EventKind, call: u64, payload: &[u8]) -> EventInput<'_> {
        EventInput {
            kind,
            api_id: 10,
            schema_id: 20,
            call_id: call,
            parent_call_id: 0,
            payload,
            capture_state: CaptureState::Captured,
            global_order: 0,
        }
    }

    #[test]
    fn payload_threshold_notifies_with_sparse_descriptors_and_rearms_after_drain() {
        let (_region, mut writer, mut reader) = test_writer_reader(64, 128);
        let payload = [7u8; 32];
        let signals = [
            NotifySignal::None,
            NotifySignal::ThresholdCrossing,
            NotifySignal::None,
        ];
        for (index, expected) in signals.into_iter().enumerate() {
            let result = writer.write(input(EventKind::CallEnter, index as u64 + 1, &payload));
            assert!(
                matches!(result, WriteOutcome::Published { notify, .. } if notify == expected),
                "{result:?}"
            );
        }
        // Drain two payloads, leaving 25% payload usage but only one descriptor.
        assert_eq!(reader.drain(2).events.len(), 2);
        let result = writer.write(input(EventKind::CallEnter, 4, &payload));
        assert!(
            matches!(
                result,
                WriteOutcome::Published {
                    notify: NotifySignal::ThresholdCrossing,
                    ..
                }
            ),
            "{result:?}"
        );
        let batch = reader.drain_all();
        assert_eq!(batch.events.len(), 2);
        assert!(batch.events.iter().all(|event| event.payload == payload));
        assert_eq!(writer.loss_counters().dropped_events, 0);
    }

    #[test]
    fn single_publish_point_roundtrip() {
        let (_r, mut w, mut rd) = test_writer_reader(8, 256);
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 1, b"hello")),
            WriteOutcome::Published { .. }
        ));
        let b = rd.drain_all();
        assert_eq!(b.events.len(), 1);
        assert_eq!(b.events[0].payload, b"hello");
        assert_eq!(b.events[0].descriptor.api_id, 10);
        assert_eq!(b.sequence_gaps, 0);
    }

    #[test]
    fn stored_payload_positions_do_not_overlap() {
        // 転送レベルの事実: 格納済み Payload の payload_position は互いに
        // 重ならない区間を占める。落とした Payload は格納長 0 で位置を
        // 再利用する。A72 の一時キーはこの位置に Host 側の識別情報を
        // 組み合わせて作る（shirusu-host の TemporaryPayloadKey で検証）。
        let (_r, mut w, mut rd) = test_writer_reader(8, 256);
        w.write(input(EventKind::CallEnter, 1, b"aaa"));
        w.write(input(EventKind::CallEnter, 2, b"bbbbb"));
        w.write(input(EventKind::CallEnter, 3, b"c"));
        let dropped = EventInput {
            kind: EventKind::CallEnter,
            api_id: 10,
            schema_id: 20,
            call_id: 4,
            parent_call_id: 0,
            payload: b"dddd",
            capture_state: CaptureState::DroppedByBackpressure,
            global_order: 0,
        };
        w.write(dropped);
        w.write(input(EventKind::CallEnter, 5, b"e"));
        let b = rd.drain_all();
        assert_eq!(b.events.len(), 5);
        let positions: Vec<u64> = b
            .events
            .iter()
            .map(|e| e.descriptor.payload_position)
            .collect();
        // 格納済み 3, 5, 1 バイトで位置は 0, 3, 8, 9。落とした件は 9 を再利用し、
        // 次の格納済みも 9 から始まる。
        assert_eq!(positions, vec![0, 3, 8, 9, 9]);
        assert!(b.events[3].descriptor.payload_dropped());
        assert_eq!(b.events[3].payload.len(), 0);
        // 格納済み同士の開始位置はすべて異なる。
        let stored: Vec<u64> = b
            .events
            .iter()
            .filter(|e| !e.descriptor.payload_dropped())
            .map(|e| e.descriptor.payload_position)
            .collect();
        assert_eq!(stored, vec![0, 3, 8, 9]);
    }

    #[test]
    fn payload_wraparound_split_copy() {
        let (_r, mut w, mut rd) = test_writer_reader(8, 16);
        w.write(input(EventKind::CallEnter, 1, b"0123456789")); // 10 bytes
        let b1 = rd.drain_all();
        assert_eq!(b1.events[0].payload, b"0123456789");
        w.write(input(EventKind::CallEnter, 2, b"ABCDEFGHIJ")); // position 10 -> wraps at 16
        let b2 = rd.drain_all();
        assert_eq!(b2.events[0].payload, b"ABCDEFGHIJ");
    }

    #[test]
    fn unpublished_is_not_read() {
        let (region, w, mut rd) = test_writer_reader(4, 64);
        drop(w);
        // write_cursor が進んでいない領域は読まない
        assert_eq!(rd.drain_all().events.len(), 0);
        let _ = region;
    }

    #[test]
    fn bounded_wait_flag_cleared_on_timeout() {
        // 仮想時計で決定的にタイムアウトさせ、抜けた後にフラグが下りていること。
        let (region, mut w, _rd) = test_writer_reader(2, 64);
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 1, b"a")),
            WriteOutcome::Published { .. }
        ));
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 2, b"b")),
            WriteOutcome::Published { .. }
        ));
        // 満杯: 3 件目は BOUNDED_WAIT (仮想 1ms) の末に劣化または欠落する。
        let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
        assert!(!crate::layout::writer_waiting(region.base()));
    }

    #[test]
    fn loader_lock_unknown_waits_zero_by_default() {
        // 満杯の Ring で、Loader Lock の保持が判定できない申告 (Unknown) のまま
        // 既定ポリシーで書くと、待たずに劣化・欠落し wait_count は 0 のまま。
        let (region, mut w, _rd) = test_writer_reader(2, 64);
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 1, b"a")),
            WriteOutcome::Published { .. }
        ));
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 2, b"b")),
            WriteOutcome::Published { .. }
        ));
        w.set_loader_lock_state(LoaderLockState::Unknown);
        let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
        assert_eq!(w.wait_count, 0);
        assert_eq!(w.state(), OverflowState::Overflow);
        assert!(!crate::layout::writer_waiting(region.base()));
    }

    #[test]
    fn loader_lock_unknown_waits_when_policy_allows() {
        // zero_wait_when_loader_lock_unknown=false なら、Unknown でも上限まで待つ。
        let cfg = RingConfig::new(2, 64);
        let region = SharedRegion::new(cfg, 1, 100);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut w = unsafe {
            region.writer(
                WriterPolicy {
                    zero_wait_when_loader_lock_unknown: false,
                    ..Default::default()
                },
                clock,
            )
        };
        w.write(input(EventKind::CallEnter, 1, b"a"));
        w.write(input(EventKind::CallEnter, 2, b"b"));
        w.set_loader_lock_state(LoaderLockState::Unknown);
        let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
        assert_eq!(w.wait_count, 1);
        assert!(!crate::layout::writer_waiting(region.base()));
    }

    #[test]
    fn loader_lock_held_never_waits() {
        // 保持中 (Held) の申告なら、max_wait が長く設定が false でも待たない。
        let cfg = RingConfig::new(2, 64);
        let region = SharedRegion::new(cfg, 1, 100);
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new());
        let mut w = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: Duration::from_millis(300),
                    zero_wait_when_loader_lock_unknown: false,
                    ..Default::default()
                },
                clock,
            )
        };
        w.write(input(EventKind::CallEnter, 1, b"a"));
        w.write(input(EventKind::CallEnter, 2, b"b"));
        w.set_loader_lock_state(LoaderLockState::Held);
        let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
        assert_eq!(w.wait_count, 0);
        assert_eq!(w.loader_lock_state(), LoaderLockState::Held);
        assert!(!crate::layout::writer_waiting(region.base()));
        // NotHeld に戻し、空きを作ってから再度満杯にすれば待つようになる
        w.set_loader_lock_state(LoaderLockState::NotHeld);
        let mut rd = unsafe { region.reader() };
        let _ = rd.drain_all(); // 使用率 0% → 次の write で Normal に復帰
        w.write(input(EventKind::CallEnter, 4, b"d"));
        w.write(input(EventKind::CallEnter, 5, b"e"));
        let _ = w.write(input(EventKind::CallEnter, 6, b"f"));
        assert_eq!(w.wait_count, 1);
    }

    #[test]
    fn bounded_wait_flag_visible_while_waiting() {
        // 実時計で別スレッドが待機中、フラグが立っていることを Host 側から観測できる。
        use crate::clock::SystemClock;
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};
        let cfg = RingConfig::new(2, 64);
        let region = SharedRegion::new(cfg, 1, 100);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let mut w = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: Duration::from_millis(300),
                    ..Default::default()
                },
                clock,
            )
        };
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 1, b"a")),
            WriteOutcome::Published { .. }
        ));
        assert!(matches!(
            w.write(input(EventKind::CallEnter, 2, b"b")),
            WriteOutcome::Published { .. }
        ));
        let base = region.base();
        let seen = Arc::new(AtomicBool::new(false));
        let seen_writer = seen.clone();
        std::thread::scope(|s| {
            let h = s.spawn(move || {
                let _ = w.write(input(EventKind::CallEnter, 3, b"c"));
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while std::time::Instant::now() < deadline {
                if crate::layout::writer_waiting(base) {
                    seen_writer.store(true, AOrd::Relaxed);
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = h.join();
        });
        assert!(
            seen.load(AOrd::Relaxed),
            "writer_waiting flag was never observed during bounded wait"
        );
        assert!(!crate::layout::writer_waiting(base));
    }
}
