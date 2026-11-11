//! shirusu-host: 読み手側。Ring 毎に単一 Drain Worker 前提の取出し、検証、Loss Event 生成、
//! Enter/Leave 対応付けと終了不明判定、スレッド終了確認後の Slot 解放、完全性報告。

pub mod child_tree;
pub mod expansion;
pub mod recorder;
#[cfg(windows)]
pub mod recorder_launch;
pub mod trace_convert;

use shirusu_transport::descriptor::EventKind;
use shirusu_transport::layout::{self, LossCounters};
use shirusu_transport::ring::{DrainBatch, ReceivedEvent, SharedRegion};
use shirusu_transport::slot::{SlotHandle, SlotPool};
use shirusu_transport::validate::{IntegrityError, KnownConfig, ValidatingReader};
use shirusu_transport::RingConfig;
use shirusu_transport_win::{notify_space_if_writer_waiting, RingNotify};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::atomic::Ordering;
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

/// Host が管理するプロセス実例の識別子。OS の PID そのものではなく、
/// 同じ PID の再利用やプロセス再起動を別実例として区別するため、Host が
/// Capture Session 内で一意に採番する値（A72）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessInstanceId(pub u64);

/// Host が管理する Ring の識別子。Capture Session 内で一意に Host が採番する
/// 値であり、転送 ABI には現れない（A72）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RingId(pub u64);

/// Host が回収対象の Ring に付ける識別情報。`ring_id` と `generation` は
/// Host が管理する値を使う（A72 確定仕様）。`generation` は Ring 再利用の
/// たびに Host が増やす世代であり、Control 領域の Generation
/// （`ValidatingReader` が `expected_generation` として照合する値）に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RingIdentity {
    pub process_id: ProcessInstanceId,
    pub ring_id: RingId,
    pub generation: u64,
}
impl RingIdentity {
    pub fn new(process_id: ProcessInstanceId, ring_id: RingId, generation: u64) -> Self {
        Self {
            process_id,
            ring_id,
            generation,
        }
    }
    /// Ring 再利用時の次世代の識別情報。識別子の他の要素は保ち、世代だけ進める。
    pub fn next_generation(&self) -> Self {
        Self {
            generation: self.generation.wrapping_add(1),
            ..*self
        }
    }
    /// 検証済み Descriptor を持つ回収イベントについて、格納済み Payload が
    /// ある場合にだけ一時キーを生成する。欠落した Payload（ドロップ、または
    /// 格納バイトが無い）にはキーを生成しない。欠落の事実と理由は Loss
    /// カウンタ／Loss Event 側に残る（A72 確定仕様 5）。
    pub fn payload_key(&self, event: &ReceivedEvent) -> Option<TemporaryPayloadKey> {
        if event.descriptor.payload_dropped() || event.payload.is_empty() {
            return None;
        }
        Some(TemporaryPayloadKey {
            process_id: self.process_id,
            ring_id: self.ring_id,
            generation: self.generation,
            sequence: event.descriptor.sequence,
            payload_position: event.descriptor.payload_position,
        })
    }
}

/// Host 内部の一時キー（A72 確定仕様、kota 2026-11-09）。
///
/// Payload は Agent–Host 間で独立した ID を持たない。Host は検証済みの
/// Ring 識別情報・Generation・Sequence・Payload の論理オフセットから
/// このキーを回収時に生成し、内部管理（Blob 化待ちの突き合わせ等）に使う。
/// `sequence + payload_position` だけでは別 Ring や Ring 再利用で重複する
/// ため、Host 管理の `process_id` / `ring_id` / `generation` を含める。
/// Host が BLAKE3 を計算して Blob を保存した後、公開 Trace では Blob ID を
/// 参照する。このキーは Host 内部だけで使用し、公開 Trace 形式には含めない。
/// 対象範囲は Capture Session 内であり、別 Session と統合する場合は
/// Session ID を呼び出し側で組み合わせる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TemporaryPayloadKey {
    pub process_id: ProcessInstanceId,
    pub ring_id: RingId,
    pub generation: u64,
    pub sequence: u64,
    pub payload_position: u64,
}

/// 共有 Control の現在の Generation を読む（診断用）。
///
/// # Safety
/// `base` は RingConfig 分の共有領域を指し、読み取りの間も有効であること。
pub unsafe fn ring_generation(base: *const u8) -> u64 {
    layout::load(base, layout::OFF_GENERATION, Ordering::Acquire)
}

/// 共有 Control が初期化され (Magic が現れ)、Generation が期待値へ
/// 遷移するまで待つ。遷移しなければ最後に観測した Generation を
/// Err で返す。
///
/// Host が未来の Generation 用の [`DrainWorker`] を先に作って回収を
/// 始めると、検証側が GenerationMismatch を検出して Ring を恒久
/// 停止させ、その世代のイベントを以後一切受け取れなくなる
/// (レビュー #4 の production_path_interprocess 仮説)。通知
/// (data_ready) の残留は「その世代が始まった」証拠にはならないため、
/// Reader を作る前に Control 自身で遷移を確認するのが正しい順序。
///
/// # Safety
/// `base` は RingConfig 分の共有領域を指し、待機の間も有効であること。
pub unsafe fn wait_for_ring_generation(
    base: *const u8,
    expected_generation: u64,
    timeout: std::time::Duration,
) -> Result<(), u64> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let magic = layout::load(base, layout::OFF_MAGIC, Ordering::Acquire);
        // SAFETY: 呼び出し側の契約に従う (ring_generation と同じ前提)。
        let generation = unsafe { ring_generation(base) };
        if magic == layout::MAGIC && generation == expected_generation {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(generation);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Ring 1 本分の Drain Worker。単一読み手を前提とし、複数 Worker で同じ Ring を扱わない。
///
/// 回収は必ず検証付き経路を通る (R2): 共有領域を Host 側バッファへコピーし
/// (copy)、`ValidatingReader` で検証しながら取り出し (validate)、成功した
/// 場合にだけ共有メモリの read_cursor / payload_read_position を前進させる
/// (advance)。矛盾を見つけたら Ring を止め、`integrity_lost` と
/// `LossEvent::IntegrityLost` を記録して、以後は空のバッチを返す。
/// 無検証の `RingReader` は通常経路では使わない (テスト／信頼済み内部専用
/// として transport 側に残してある)。
pub struct DrainWorker {
    base: *mut u8,
    reader: ValidatingReader,
    /// Host 側のコピー先バッファ。検証はこの像に対してだけ行い、共有メモリを
    /// 読み直さない。
    image: Vec<u8>,
    prev_loss: LossCounters,
    open_calls: HashMap<u64, u64>, // call_id -> enter sequence
    closed_calls: HashSet<u64>,
    identity: Option<RingIdentity>,
    /// 回収した格納済み Payload の一時キー（A72）。`identity` を設定した
    /// 場合にだけ生成する。欠落 Payload には生成されない。
    pub payload_keys: Vec<TemporaryPayloadKey>,
    pub loss_events: Vec<LossEvent>,
    pub unknown_terminations: Vec<u64>,
    /// 中断した呼び出し（CallAborted）の回収数（L08）。Host 側の
    /// 「終了不明」とは別で、異常終了したことが分かっているもの。
    pub aborted_calls: u64,
    /// 完了した非同期 I/O（CallCompleted）の回収数（F27）。leave は
    /// 既に回収済みのため、呼び出しの開閉には通常影響しない。leave が
    /// 欠落していた場合にだけ開いた呼び出しを閉じる。
    pub completed_calls: u64,
    pub total_events: u64,
    /// 共有メモリの矛盾で Ring を停止したかどうか。
    pub integrity_lost: bool,
    degraded_seen: u64,
}
// SAFETY: base はコンストラクタの契約により Worker の生存期間中有効であり、
// Ring ごとに単一 Worker で使う前提 (SPSC の読み手側) のため、所有権の移動は安全。
unsafe impl Send for DrainWorker {}
impl DrainWorker {
    /// # Safety
    /// `base` は `cfg` 分の共有領域を指し、この Worker が破棄されるまで有効
    /// であること。`expected_generation` は Control 領域の Generation と
    /// 一致する Host 管理の値であること。
    pub unsafe fn new(base: *mut u8, cfg: RingConfig, expected_generation: u64) -> Self {
        let known = KnownConfig::new(cfg, cfg.required_len());
        Self {
            base,
            reader: ValidatingReader::new(known, expected_generation),
            image: vec![0u8; cfg.required_len()],
            prev_loss: LossCounters::default(),
            open_calls: HashMap::new(),
            closed_calls: HashSet::new(),
            identity: None,
            payload_keys: Vec::new(),
            loss_events: Vec::new(),
            unknown_terminations: Vec::new(),
            aborted_calls: 0,
            completed_calls: 0,
            total_events: 0,
            integrity_lost: false,
            degraded_seen: 0,
        }
    }
    /// 共有メモリの矛盾で Ring を停止したかどうか。
    pub fn is_stopped(&self) -> bool {
        self.reader.is_stopped()
    }
    /// Host 再起動後の引き継ぎ: 共有側の読み位置を正として検証状態を同期
    /// する (`ValidatingReader::resume_from_image`)。同期に失敗したら Ring
    /// は止まった状態になり、`integrity_lost` が立つ。以後は
    /// `drain_*` は空のバッチを返す。
    pub fn resume_from_shared(&mut self) {
        // SAFETY: base はコンストラクタの契約で有効。image は同じ長さ。
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.base as *const u8,
                self.image.as_mut_ptr(),
                self.image.len(),
            );
        }
        if let Err(e) = self.reader.resume_from_image(&self.image) {
            self.integrity_lost = true;
            self.loss_events.push(LossEvent::IntegrityLost {
                reason: format!("{e:?}"),
            });
        }
    }
    fn writer_waiting(&self) -> bool {
        // 空き通知の要否判断にだけ使う助言フラグ。検証対象ではない
        // (書き手は通知が無くても待機上限で必ず前に進む)。
        layout::writer_waiting(self.base)
    }
    /// 回収対象 Ring の識別情報を設定する（A72）。設定後は回収のたびに
    /// 格納済み Payload の一時キーを `payload_keys` に生成する。
    pub fn set_identity(&mut self, identity: RingIdentity) {
        self.identity = Some(identity);
    }
    /// `--order=global` 有効なセッションとして検証する（L11）。
    /// 回収開始前（最初の drain より前）に呼ぶこと。
    pub fn set_global_order(&mut self, allow: bool) {
        self.reader.set_global_order(allow);
    }
    pub fn identity(&self) -> Option<RingIdentity> {
        self.identity
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
        if !batch.events.is_empty() && self.writer_waiting() {
            notify_space();
        }
        batch
    }
    pub fn drain_all_with_space_notify(&mut self, notify_space: impl Fn()) -> DrainBatch {
        let batch = self.drain_once_inner(usize::MAX);
        if !batch.events.is_empty() && self.writer_waiting() {
            notify_space();
        }
        batch
    }
    fn drain_once_inner(&mut self, max: usize) -> DrainBatch {
        if self.reader.is_stopped() {
            return DrainBatch::default();
        }
        // 1. copy: 共有領域を Host 側バッファへ写す。以後はこの像だけを見る。
        // SAFETY: base はコンストラクタの契約で有効。image は同じ長さで確保した。
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.base as *const u8,
                self.image.as_mut_ptr(),
                self.image.len(),
            );
        }
        // 2. validate + take: 検証済みの範囲だけを取り出す。矛盾したら
        // Ring を止め、完全性喪失として記録する (バッチは返さない)。
        let events = match self.reader.drain_image_up_to(&self.image, max) {
            Ok(events) => events,
            Err(e) => {
                self.integrity_lost = true;
                self.loss_events.push(LossEvent::IntegrityLost {
                    reason: format!("{e:?}"),
                });
                return DrainBatch::default();
            }
        };
        // 3. advance: 検証済みの分だけ共有メモリの読み位置を前進させる。
        // Sequence 欠番は検証側 (ValidatingReader) が数えた分を使う
        // (resume で引き継いだ期待値とも一貫する単一の数え手)。
        let batch = DrainBatch {
            events,
            sequence_gaps: self.reader.take_sequence_gaps(),
            // Host の検証経路は破損を integrity_lost 側で扱うため、バッチ側の
            // 多層防御エラーは常に None (RingReader 専用の報告経路)。
            integrity_error: None,
        };
        if !batch.events.is_empty() {
            // 前進は検証済み範囲に限る (layout の原子操作は base の有効性が前提)。
            layout::store(
                self.base,
                layout::OFF_PAYLOAD_READ_POSITION,
                self.reader.payload_read_position(),
                Ordering::Release,
            );
            layout::store(
                self.base,
                layout::OFF_READ_CURSOR,
                self.reader.read_cursor(),
                Ordering::Release,
            );
            layout::fetch_add(self.base, layout::OFF_HOST_DRAIN_COUNT, 1);
        }
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
            if let Some(id) = &self.identity {
                if let Some(key) = id.payload_key(e) {
                    self.payload_keys.push(key);
                }
            }
        }
        // Loss カウンタは検証済み Control スナップショットから読む
        // (共有メモリを直接読み直さない)。
        let now = self
            .reader
            .control_snapshot()
            .map(|s| s.loss)
            .unwrap_or(self.prev_loss);
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
            // L08: 中断した呼び出しも「閉じた」ものとして扱う。Leave と
            // 同じく開いた呼び出しを閉じ、finalize での「終了不明」に
            // しない。対応する Enter が無い Aborted は無視する（孤立した
            // Leave と同じ扱い）。
            Some(EventKind::CallAborted)
                if self.open_calls.remove(&e.descriptor.call_id).is_some() =>
            {
                self.closed_calls.insert(e.descriptor.call_id);
                self.aborted_calls += 1;
            }
            // F27: 完了した非同期 I/O。leave は既に回収されて呼び出しを
            // 閉じているのが通常で、その場合は数を数えるだけ。leave が
            // 欠落してまだ開いている場合にだけ、Aborted と同じくここで
            // 閉じる。対応する Enter が無いものは無視する（孤立した
            // Leave と同じ扱い）。完了は別スレッドで観測されることが
            // あるが、ここは call_id だけで追跡するためスレッドは問わない。
            Some(EventKind::CallCompleted) => {
                if self.open_calls.remove(&e.descriptor.call_id).is_some() {
                    self.closed_calls.insert(e.descriptor.call_id);
                }
                if self.closed_calls.contains(&e.descriptor.call_id) {
                    self.completed_calls += 1;
                }
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
    /// 回収した CallAborted の数（L08）。
    pub fn aborted_call_count(&self) -> u64 {
        self.aborted_calls
    }
    /// 回収した CallCompleted の数（F27）。
    pub fn completed_call_count(&self) -> u64 {
        self.completed_calls
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
    identity: Option<RingIdentity>,
    /// 回収した格納済み Payload の一時キー（A72）。`set_identity` で識別情報を
    /// 設定した場合にだけ生成する。identity の generation は
    /// `expected_generation` と一致させること（Host が管理する同じ世代）。
    pub payload_keys: Vec<TemporaryPayloadKey>,
    pub loss_events: Vec<LossEvent>,
    pub integrity_lost: bool,
}
impl ValidatingHost {
    pub fn new(known: KnownConfig, expected_generation: u64) -> Self {
        Self {
            reader: ValidatingReader::new(known, expected_generation),
            identity: None,
            payload_keys: Vec::new(),
            loss_events: Vec::new(),
            integrity_lost: false,
        }
    }
    /// 回収対象 Ring の識別情報を設定する（A72）。
    pub fn set_identity(&mut self, identity: RingIdentity) {
        self.identity = Some(identity);
    }
    /// `--order=global` 有効なセッションとして検証する（L11）。
    /// 回収開始前に呼ぶこと。
    pub fn set_global_order(&mut self, allow: bool) {
        self.reader.set_global_order(allow);
    }
    pub fn drain_image(&mut self, image: &[u8]) -> Result<Vec<ReceivedEvent>, IntegrityError> {
        match self.reader.drain_image(image) {
            Ok(events) => {
                if let Some(id) = &self.identity {
                    for e in &events {
                        if let Some(key) = id.payload_key(e) {
                            self.payload_keys.push(key);
                        }
                    }
                }
                Ok(events)
            }
            Err(e) => {
                self.integrity_lost = true;
                self.loss_events.push(LossEvent::IntegrityLost {
                    reason: format!("{e:?}"),
                });
                Err(e)
            }
        }
    }
    /// 実 File Mapping のビューに対する回収 (R2): copy→検証→Cursor 前進を
    /// 1 回で行う。`drain_image` は渡された像のコピーを検証するだけで共有側
    /// の読み位置は進めないため、実 Mapping を相手にする場合はこちらを使う。
    /// 前進は検証に成功した範囲に限り、失敗時は共有側を一切変更しない。
    ///
    /// # Safety
    /// `base` は `len` バイトの共有領域を指し、呼び出し中有効であること。
    /// `len` が検証側の要求長に満たない場合は `ImageTooSmall` で失敗する。
    pub unsafe fn drain_shared(
        &mut self,
        base: *mut u8,
        len: usize,
    ) -> Result<Vec<ReceivedEvent>, IntegrityError> {
        // SAFETY: 呼び出し側の契約 (base は len バイト有効) に従う。
        let image = unsafe { std::slice::from_raw_parts(base as *const u8, len) }.to_vec();
        let events = self.drain_image(&image)?;
        if !events.is_empty() {
            // 前進は検証済み範囲に限る (base の契約は呼び出し側が保証する)。
            layout::store(
                base,
                layout::OFF_PAYLOAD_READ_POSITION,
                self.reader.payload_read_position(),
                Ordering::Release,
            );
            layout::store(
                base,
                layout::OFF_READ_CURSOR,
                self.reader.read_cursor(),
                Ordering::Release,
            );
            layout::fetch_add(base, layout::OFF_HOST_DRAIN_COUNT, 1);
        }
        Ok(events)
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
        let worker = unsafe { DrainWorker::new(region.base(), cfg, 1) };
        (region, w, worker)
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
            global_order: 0,
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
    fn completed_call_counts_without_reopening() {
        // F27: CallCompleted は leave が閉じた呼び出しを数えるだけで、
        // 開き直さない。leave が欠落していた場合はここで閉じる。
        let (_rg, mut w, mut host) = setup();
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        w.write(ev(EventKind::CallLeave, 1, b"b"));
        w.write(ev(EventKind::CallCompleted, 1, b"c"));
        w.write(ev(EventKind::CallEnter, 2, b"d")); // leave missing
        w.write(ev(EventKind::CallCompleted, 2, b"e"));
        w.write(ev(EventKind::CallCompleted, 3, b"f")); // enter 無しは無視
        host.drain_all();
        assert_eq!(host.open_call_count(), 0);
        assert_eq!(host.completed_call_count(), 2);
        assert_eq!(host.finalize_thread(), Vec::<u64>::new());
    }
    #[test]
    fn aborted_call_closes_open_call_not_unknown_termination() {
        // L08: 中断した呼び出しは「終了不明」ではない。CallAborted で
        // 開いた呼び出しが閉じ、finalize で UnknownTermination にならない。
        let (_rg, mut w, mut host) = setup();
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        w.write(ev(EventKind::CallAborted, 1, b""));
        w.write(ev(EventKind::CallEnter, 2, b"c")); // leave missing
        host.drain_all();
        assert_eq!(host.open_call_count(), 1);
        assert_eq!(host.aborted_call_count(), 1);
        let unterminated = host.finalize_thread();
        assert_eq!(unterminated, vec![2]);
        assert!(!host
            .loss_events
            .iter()
            .any(|l| matches!(l, LossEvent::UnknownTermination { call_id: 1 })));
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
        let mut host = unsafe { DrainWorker::new(region.base(), cfg, 1) };
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

    fn received(seq: u64, pos: u64, payload: &[u8], dropped: bool) -> ReceivedEvent {
        let mut d = shirusu_transport::EventDescriptor::new(EventKind::CallEnter, seq);
        d.payload_position = pos;
        d.payload_len = payload.len() as u32;
        if dropped {
            d.flags |= shirusu_transport::descriptor::flags::PAYLOAD_DROPPED;
        }
        ReceivedEvent {
            descriptor: d,
            payload: payload.to_vec(),
        }
    }
    #[test]
    fn validating_host_drain_shared_advances_shared_cursors() {
        // R2: 実 Mapping 向けの copy→検証→前進。検証成功分だけ共有側の
        // read_cursor が進み、破損時は進まない。
        use shirusu_transport::layout::{load, OFF_READ_CURSOR};
        use std::sync::atomic::Ordering as AOrd;
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
        let len = cfg.required_len();
        let evs = unsafe { host.drain_shared(region.base(), len) }.unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(load(region.base(), OFF_READ_CURSOR, AOrd::Relaxed), 2);
        // 続きは無いので 2 回目は空で、Cursor も動かない。
        let evs = unsafe { host.drain_shared(region.base(), len) }.unwrap();
        assert!(evs.is_empty());
        assert_eq!(load(region.base(), OFF_READ_CURSOR, AOrd::Relaxed), 2);
        // 破損した像では失敗し、Cursor は前進しない。
        w.write(ev(EventKind::CallEnter, 2, b"again"));
        let mut image = AlignedImage::copy_of(region.as_slice());
        shirusu_transport::layout::store(
            image.as_mut_ptr(),
            shirusu_transport::layout::OFF_WRITE_CURSOR,
            u64::MAX - 3,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(host.drain_image(image.as_slice()).is_err());
        assert_eq!(load(region.base(), OFF_READ_CURSOR, AOrd::Relaxed), 2);
    }
    #[test]
    fn drain_worker_resume_continues_from_shared_cursors() {
        // Host 再起動: 新しい Worker が resume_from_shared で読み位置を
        // 引き継ぎ、回収済みイベントを二重に取り込まず続きから読む。
        let (region, mut w, mut host) = setup();
        w.write(ev(EventKind::CallEnter, 1, b"a"));
        w.write(ev(EventKind::CallEnter, 2, b"b"));
        assert_eq!(host.drain_all().events.len(), 2);
        let cfg = region.config;
        let mut host2 = unsafe { DrainWorker::new(region.base(), cfg, 1) };
        host2.resume_from_shared();
        assert!(!host2.integrity_lost);
        assert!(
            host2.drain_all().events.is_empty(),
            "no replay after resume"
        );
        w.write(ev(EventKind::CallEnter, 3, b"c"));
        let b = host2.drain_all();
        assert_eq!(b.events.len(), 1);
        assert_eq!(b.events[0].payload, b"c");
        assert_eq!(b.sequence_gaps, 0, "resume keeps sequence continuity");
        assert_eq!(host2.total_events, 1);
    }

    #[test]
    fn temporary_key_components_distinguish_keys() {
        // A72: sequence + payload_position が同じでも、Host 管理の要素が
        // どれか 1 つでも違えばキーは異なる。同一入力では決定的に同じ。
        let e = received(7, 100, b"payload", false);
        let base = RingIdentity::new(ProcessInstanceId(1), RingId(2), 3);
        let k = base.payload_key(&e).unwrap();
        assert_eq!(
            k,
            TemporaryPayloadKey {
                process_id: ProcessInstanceId(1),
                ring_id: RingId(2),
                generation: 3,
                sequence: 7,
                payload_position: 100,
            }
        );
        assert_eq!(base.payload_key(&e), Some(k), "deterministic");
        let other_ring = RingIdentity::new(ProcessInstanceId(1), RingId(9), 3);
        assert_ne!(other_ring.payload_key(&e), Some(k), "ring_id differs");
        let other_process = RingIdentity::new(ProcessInstanceId(8), RingId(2), 3);
        assert_ne!(other_process.payload_key(&e), Some(k), "process differs");
        let other_gen = RingIdentity::new(ProcessInstanceId(1), RingId(2), 4);
        assert_ne!(other_gen.payload_key(&e), Some(k), "generation differs");
        // 同一 Ring でも sequence / position が違えば異なる。
        assert_ne!(
            base.payload_key(&received(8, 100, b"payload", false)),
            Some(k)
        );
        assert_ne!(
            base.payload_key(&received(7, 107, b"payload", false)),
            Some(k)
        );
    }
    #[test]
    fn temporary_key_not_generated_for_dropped_or_empty_payload() {
        // A72 確定仕様 5: 欠落 Payload にはキーを生成しない。
        let id = RingIdentity::new(ProcessInstanceId(1), RingId(2), 3);
        assert_eq!(id.payload_key(&received(7, 100, b"", true)), None);
        // ドロップ扱いの Descriptor は、仮にバイトが付いていても生成しない。
        assert_eq!(id.payload_key(&received(7, 100, b"bytes", true)), None);
        // 格納済みでも長さ 0 なら Blob 化する対象が無いので生成しない。
        assert_eq!(id.payload_key(&received(7, 100, b"", false)), None);
        assert!(id.payload_key(&received(7, 100, b"x", false)).is_some());
    }
    #[test]
    fn drain_worker_generates_payload_keys_with_identity() {
        let (_rg, mut w, mut host) = setup();
        // identity 未設定では従来どおりキーを生成しない。
        w.write(ev(EventKind::CallEnter, 1, b"aaa"));
        host.drain_all();
        assert!(host.payload_keys.is_empty());
        // identity を設定すると、格納済み Payload にだけキーが付く。
        host.set_identity(RingIdentity::new(ProcessInstanceId(7), RingId(3), 1));
        let mut dropped = ev(EventKind::CallEnter, 2, b"dddd");
        dropped.capture_state = CaptureState::DroppedByBackpressure;
        w.write(dropped);
        w.write(ev(EventKind::CallEnter, 3, b"e"));
        host.drain_all();
        // seq 1 は identity 前に回収済み。seq 2 は欠落（キーなし、理由は
        // Degraded として残る）。seq 3 は位置 3（欠落分は位置を進めない）。
        assert_eq!(
            host.payload_keys,
            vec![TemporaryPayloadKey {
                process_id: ProcessInstanceId(7),
                ring_id: RingId(3),
                generation: 1,
                sequence: 3,
                payload_position: 3,
            }]
        );
        assert_eq!(host.total_events, 3);
        let report = host.integrity_report(0, false);
        assert_eq!(report.semantic_completeness, IntegrityLevel::Degraded);
    }
    #[test]
    fn ring_reuse_old_key_does_not_collide_with_new_payload() {
        // A72: Ring 再利用で sequence と payload_position が同じ値に戻っても、
        // generation が進むため古いキーは新しい Payload のキーと一致しない。
        let e = received(1, 0, b"x", false);
        let gen1 = RingIdentity::new(ProcessInstanceId(1), RingId(2), 1);
        let old_key = gen1.payload_key(&e).unwrap();
        let gen2 = gen1.next_generation();
        assert_eq!(gen2.generation, 2);
        let new_key = gen2.payload_key(&e).unwrap();
        assert_ne!(old_key, new_key);
        assert_eq!(old_key.sequence, new_key.sequence);
        assert_eq!(old_key.payload_position, new_key.payload_position);
    }
    #[test]
    fn validating_host_generates_payload_keys_with_identity() {
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
        host.set_identity(RingIdentity::new(ProcessInstanceId(9), RingId(4), 3));
        let evs = host.drain_image(region.as_slice()).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(
            host.payload_keys,
            vec![
                TemporaryPayloadKey {
                    process_id: ProcessInstanceId(9),
                    ring_id: RingId(4),
                    generation: 3,
                    sequence: 1,
                    payload_position: 0,
                },
                TemporaryPayloadKey {
                    process_id: ProcessInstanceId(9),
                    ring_id: RingId(4),
                    generation: 3,
                    sequence: 2,
                    payload_position: 5,
                },
            ]
        );
    }
    #[test]
    fn future_generation_worker_stops_ring_on_mismatch() {
        // レビュー #4 の production_path 仮説の機構そのもの: まだ
        // Generation 1 の Ring に対して Generation 2 用の Worker で
        // 回収を始めると、検証が GenerationMismatch で Ring を恒久
        // 停止させ、その世代のイベントは以後一切回収できない。
        // Supervisor は Reader を作る前に遷移を確認しなければならない。
        let cfg = RingConfig::new(16, 512);
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
        w.write(ev(EventKind::CallEnter, 1, b"gen1"));
        let mut host = unsafe { DrainWorker::new(region.base(), cfg, 2) };
        let batch = host.drain_all();
        assert!(batch.events.is_empty());
        assert!(host.integrity_lost);
        assert!(host.is_stopped());
        assert!(
            host.loss_events.iter().any(|l| matches!(
                l,
                LossEvent::IntegrityLost { reason } if reason.contains("GenerationMismatch")
            )),
            "stop reason must name the generation mismatch: {:?}",
            host.loss_events
        );
        // 停止は恒久的: 後から正しい世代のイベントが来ても回収しない。
        let batch = host.drain_all();
        assert!(batch.events.is_empty());
    }
    #[test]
    fn wait_for_ring_generation_gates_worker_creation() {
        // 修正後の順序 (Supervisor の drain_phase と同じ): 遷移を待って
        // から Worker を作れば、新世代のイベントを正常に回収できる。
        let cfg = RingConfig::new(16, 512);
        let region = SharedRegion::new(cfg, 1, 1);
        let base = region.base();
        // 未遷移の間は待機がタイムアウトし、観測した世代を返す。
        let observed =
            unsafe { wait_for_ring_generation(base, 2, std::time::Duration::from_millis(50)) };
        assert_eq!(observed, Err(1));
        // Producer 側の再初期化 (Slot 再利用時の init_control) を模す。
        let base_addr = base as usize;
        let reinit = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            layout::init_control(base_addr as *mut u8, cfg, 2, 1);
        });
        let waited =
            unsafe { wait_for_ring_generation(base, 2, std::time::Duration::from_secs(5)) };
        reinit.join().unwrap();
        assert_eq!(waited, Ok(()));
        // 遷移後に作った Worker は新世代のイベントを回収できる。
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
        w.write(ev(EventKind::CallEnter, 9, b"gen2"));
        let mut host = unsafe { DrainWorker::new(region.base(), cfg, 2) };
        let batch = host.drain_all();
        assert_eq!(batch.events.len(), 1);
        assert!(!host.integrity_lost);
    }
    #[test]
    fn wait_for_ring_generation_requires_initialization() {
        // Magic が無い (未初期化) 領域は、Generation 欄が 0 でも
        // 「世代 0 に遷移した」とはみなさない。
        let cfg = RingConfig::new(16, 512);
        let len = cfg.required_len();
        let layout_alloc = std::alloc::Layout::from_size_align(len, 64).expect("region layout");
        let ptr = unsafe { std::alloc::alloc_zeroed(layout_alloc) };
        assert!(!ptr.is_null());
        let observed =
            unsafe { wait_for_ring_generation(ptr, 0, std::time::Duration::from_millis(50)) };
        assert_eq!(observed, Err(0));
        unsafe { std::alloc::dealloc(ptr, layout_alloc) };
    }
}
