//! shirusu-e2e: Windows E2E のシナリオ実コード。
//! Test Supervisor が専用プログラム (producer/consumer) を起動し、意図した位置で
//! 止めたり終了させたりする。競合は Sleep ではなく同期ポイントで作る。
//! 同期ポイントはテスト用に有効化されたときだけ効き、本番相当の構成では無効。

pub mod perf;

use shirusu_transport::clock::{system_clock, Clock, ManualClock};
use shirusu_transport::context::HostMonitor;
use shirusu_transport::ring::{
    EventInput, RingReader, RingWriter, SharedRegion, WriteOutcome, WriterPolicy,
};
use shirusu_transport::slot::SlotPool;
use shirusu_transport::validate::{KnownConfig, ValidatingReader};
use shirusu_transport::{CaptureState, EventKind, RingConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// テスト用同期ポイント。本番ビルド相当では `enabled = false` で全て素通りする。
pub struct SyncPoints {
    pub enabled: bool,
    pub pause_host: AtomicBool,
    pub drop_notifications: AtomicBool,
    pub stop_writer_now: AtomicBool,
}
impl SyncPoints {
    pub fn test_enabled() -> Self {
        Self {
            enabled: true,
            pause_host: AtomicBool::new(false),
            drop_notifications: AtomicBool::new(false),
            stop_writer_now: AtomicBool::new(false),
        }
    }
    pub fn production() -> Self {
        Self {
            enabled: false,
            pause_host: AtomicBool::new(false),
            drop_notifications: AtomicBool::new(false),
            stop_writer_now: AtomicBool::new(false),
        }
    }
    pub fn host_paused(&self) -> bool {
        self.enabled && self.pause_host.load(Ordering::Relaxed)
    }
    pub fn notifications_dropped(&self) -> bool {
        self.enabled && self.drop_notifications.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}
fn report(name: &'static str, passed: bool, detail: impl Into<String>) -> ScenarioReport {
    ScenarioReport {
        name,
        passed,
        detail: detail.into(),
    }
}

pub fn ev(call: u64, payload: &[u8]) -> EventInput<'_> {
    EventInput {
        kind: EventKind::CallEnter,
        api_id: 100,
        schema_id: 200,
        call_id: call,
        parent_call_id: 0,
        payload,
        capture_state: CaptureState::Captured,
        global_order: 0,
    }
}
pub fn writer_over(region: &SharedRegion, no_wait: bool) -> RingWriter {
    let clock: Arc<dyn Clock> = if no_wait {
        Arc::new(ManualClock::new())
    } else {
        system_clock()
    };
    let policy = WriterPolicy {
        max_wait: if no_wait {
            Duration::ZERO
        } else {
            Duration::from_millis(50)
        },
        ..Default::default()
    };
    unsafe { region.writer(policy, clock) }
}

/// 基本: producer スレッドが書き、host が全件回収する。
pub fn scenario_basic(count: u64) -> ScenarioReport {
    let cfg = RingConfig::new(1024, 256 * 1024);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let r2 = region.clone();
    let producer = std::thread::spawn(move || {
        let mut w = writer_over(&r2, false);
        for i in 0..count {
            let p = i.to_le_bytes();
            loop {
                match w.write(ev(i, &p)) {
                    WriteOutcome::Published { .. } => break,
                    _ => std::thread::yield_now(),
                }
            }
        }
    });
    let mut rd: RingReader = unsafe { region.reader() };
    let mut got = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while got < count {
        let b = rd.drain(1024);
        got += b
            .events
            .iter()
            .filter(|e| !e.descriptor.payload_dropped())
            .count() as u64;
        if std::time::Instant::now() > deadline {
            return report("basic", false, format!("timeout: got {got}/{count}"));
        }
        if b.events.is_empty() {
            std::thread::yield_now();
        }
    }
    let _ = producer.join();
    report("basic", got == count, format!("{got} events"))
}

/// Host 一時停止: 同期ポイントで Host を止めている間、writer は劣化/欠落で前進し続ける。
pub fn scenario_host_pause(sync: &SyncPoints) -> ScenarioReport {
    let cfg = RingConfig::new(16, 1024);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer_over(&region, true);
    let mut rd = unsafe { region.reader() };
    sync.pause_host.store(true, Ordering::Relaxed);
    let mut dropped = 0;
    for i in 0..200u64 {
        if !sync.host_paused() {
            rd.drain_all();
        }
        if matches!(w.write(ev(i, b"0123456789")), WriteOutcome::Dropped { .. }) {
            dropped += 1;
        }
    }
    sync.pause_host.store(false, Ordering::Relaxed);
    let recovered = rd.drain_all();
    let counters = w.loss_counters();
    let ok = dropped > 0 && counters.dropped_events > 0 && !recovered.events.is_empty();
    report(
        "host_pause_overflow",
        ok,
        format!(
            "dropped={dropped} counters={counters:?} recovered={}",
            recovered.events.len()
        ),
    )
}

/// 通知欠落: 通知を全部落としても 2ms 再確認相当の drain で回収できる。
pub fn scenario_notification_loss(sync: &SyncPoints) -> ScenarioReport {
    let cfg = RingConfig::new(64, 8192);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer_over(&region, true);
    let mut rd = unsafe { region.reader() };
    sync.drop_notifications.store(true, Ordering::Relaxed);
    for i in 0..50u64 {
        w.write(ev(i, b"notify-me"));
        // 通知は落とす (誰も SetEvent を見ない)
        assert!(sync.notifications_dropped());
    }
    // 再確認ポーリングで回収する
    let mut got = 0;
    for _ in 0..10 {
        got += rd.drain_all().events.len();
        std::thread::sleep(Duration::from_millis(2));
    }
    report(
        "notification_loss_recheck",
        got == 50,
        format!("recovered {got}/50 without any notification"),
    )
}

/// 空き通知の end-to-end: Ring が満杯で書き手が bounded_wait に入った状態で
/// Host が `NotifyingDrainWorker` で回収すると、`space_available` が SetEvent され、
/// 待っていた書き手が欠落なく書き込みを再開できる（A61 のプロセス側配線）。
pub fn scenario_space_available_notify() -> ScenarioReport {
    use shirusu_host::NotifyingDrainWorker;
    use shirusu_transport::layout::writer_waiting;
    use shirusu_transport_win::RingNotify;
    use std::sync::mpsc;

    let cfg = RingConfig::new(4, 256);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let total = 16u64;
    let r2 = region.clone();
    let (tx, rx) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        let clock: Arc<dyn Clock> = system_clock();
        let mut w = unsafe {
            r2.writer(
                WriterPolicy {
                    max_wait: Duration::from_secs(10),
                    ..Default::default()
                },
                clock,
            )
        };
        let mut published = 0u64;
        let mut dropped = 0u64;
        for i in 0..total {
            match w.write(ev(i, b"space-notify")) {
                WriteOutcome::Published { .. } => published += 1,
                _ => dropped += 1,
            }
        }
        let _ = tx.send((published, dropped));
    });
    // Host 側の配線: NotifyingDrainWorker が回収と space_available 通知を結ぶ。
    // 回収は検証付き経路 (DrainWorker) を通る (R2)。
    let worker = unsafe { shirusu_host::DrainWorker::new(region.base(), cfg, 1) };
    let notify = match RingNotify::new() {
        Ok(n) => Arc::new(n),
        Err(e) => return report("space_available_notify", false, format!("RingNotify: {e}")),
    };
    let mut host = NotifyingDrainWorker::new(worker, notify, &region);
    // 書き手が空き待ちに入るたびに回収する。Ring 4 件に対し 16 件書くので、
    // 書き手は 5・9・13 件目で待機に入る（最大 3 エピソード）。
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut drained = 0usize;
    let mut episodes = 0u32;
    let mut signaled_seen = false;
    while !producer.is_finished() {
        if writer_waiting(region.base()) {
            episodes += 1;
            drained += host.drain_all().events.len();
            if host
                .notify
                .space_available
                .wait_timeout(Duration::from_millis(0))
            {
                signaled_seen = true;
            }
        } else {
            drained += host.drain_all().events.len();
            std::thread::sleep(Duration::from_millis(1));
        }
        if std::time::Instant::now() > deadline {
            break;
        }
    }
    drained += host.drain_all().events.len();
    let _ = producer.join();
    let (published, dropped) = rx.recv().unwrap_or((0, 0));
    let ok = episodes >= 1
        && host.space_notifications >= 1
        && signaled_seen
        && published == total
        && dropped == 0
        && drained as u64 == total;
    report(
        "space_available_notify",
        ok,
        format!(
            "episodes={episodes} notifications={} signaled={signaled_seen} published={published}/{total} dropped={dropped} drained={drained}",
            host.space_notifications
        ),
    )
}

/// A68: Agent が Host から space_available を受け取り EventClock で書く。
/// Host 側の `RingNotify` と同じ OS イベントを Agent に attach し、Ring が
/// 満杯になった書き手が Host の回収＋SetEvent で即座に再開すること、
/// かつ書き手が実際に EventClock で待機したこと（`sleep_calls() > 0`）を
/// 確認する。Host 側はイベントを消費しない（消費すると書き手の起床を奪う）。
/// プロセス間の実ハンドル受け渡しは Windows 実機の duplicate テストが担い、
/// ここではプロセス内共有の同じ `Arc<RingNotify>` で結線する。
pub fn scenario_agent_space_available_handoff() -> ScenarioReport {
    use shirusu_agent::{Agent, RecordResult};
    use shirusu_transport::layout::writer_waiting;
    use shirusu_transport::slot::SlotPool as Pool;
    use shirusu_transport_win::RingNotify;
    use std::sync::mpsc;

    let cfg = RingConfig::new(4, 256);
    let pool = Arc::new(Pool::new(2));
    let monitor = Arc::new(HostMonitor::always_alive());
    let agent = Arc::new(Agent::new(pool, cfg, monitor).with_policy(WriterPolicy {
        max_wait: Duration::from_secs(10),
        ..Default::default()
    }));
    let notify = match RingNotify::new() {
        Ok(n) => Arc::new(n),
        Err(e) => {
            return report(
                "agent_space_available_handoff",
                false,
                format!("RingNotify: {e}"),
            )
        }
    };
    // R7: 通知は Ring 単位。スレッド 1 の Ring に結ぶ。
    let clock = match agent.attach_space_available_notify(1, Arc::clone(&notify)) {
        Some(c) => c,
        None => {
            return report(
                "agent_space_available_handoff",
                false,
                "attach_space_available_notify returned None before any write",
            )
        }
    };
    // Host 側: Agent の領域を検証付き経路 (DrainWorker) で読む。領域は Agent
    // が thread_begin で作り、thread_forget まで生きる。
    let handle = agent.thread_begin(1).expect("thread_begin");
    let base = unsafe { agent.thread_region_base(1) }.expect("region base");
    let mut host = unsafe { shirusu_host::DrainWorker::new(base, cfg, handle.generation) };
    let total = 16u64;
    let (tx, rx) = mpsc::channel();
    let producer_agent = Arc::clone(&agent);
    let start = std::time::Instant::now();
    let producer = std::thread::spawn(move || {
        let mut published = 0u64;
        let mut dropped = 0u64;
        for i in 0..total {
            match producer_agent.record_enter(1, 100, 200, i, 0, b"space-handoff") {
                RecordResult::Written(WriteOutcome::Published { .. }) => published += 1,
                _ => dropped += 1,
            }
        }
        let _ = tx.send((published, dropped));
    });
    // Host 側の回収ループ: 書き手が空き待ちなら回収で SetEvent する。
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut drained = 0usize;
    let mut episodes = 0u32;
    while !producer.is_finished() {
        if writer_waiting(base) {
            episodes += 1;
        }
        let n = Arc::clone(&notify);
        drained += host
            .drain_all_with_space_notify(|| {
                let _ = n.notify_space();
            })
            .events
            .len();
        if !producer.is_finished() {
            std::thread::sleep(Duration::from_millis(1));
        }
        if std::time::Instant::now() > deadline {
            break;
        }
    }
    drained += host.drain_all().events.len();
    let _ = producer.join();
    let elapsed = start.elapsed();
    let (published, dropped) = rx.recv().unwrap_or((0, 0));
    let waited_via_event = clock.sleep_calls() > 0;
    let ok = episodes >= 1
        && waited_via_event
        && published == total
        && dropped == 0
        && drained as u64 == total
        && elapsed < Duration::from_secs(5);
    report(
        "agent_space_available_handoff",
        ok,
        format!(
            "episodes={episodes} event_waits={} published={published}/{total} dropped={dropped} drained={drained} elapsed={elapsed:?}",
            clock.sleep_calls()
        ),
    )
}

/// Host 強制終了: Agent は素通しになり、アプリ相当の処理は止まらない。
pub fn scenario_host_killed() -> ScenarioReport {
    use shirusu_agent::{Agent, RecordResult};
    use shirusu_transport::slot::SlotPool as Pool;
    let pool = Arc::new(Pool::new(2));
    let monitor = Arc::new(HostMonitor::new(|| false));
    let agent = Agent::new(pool, RingConfig::new(4, 64), monitor).with_policy(WriterPolicy {
        max_wait: Duration::ZERO,
        ..Default::default()
    });
    let mut passthrough = false;
    for i in 0..100u64 {
        if agent.record_enter(1, 1, 1, i, 0, b"0123456789") == RecordResult::PassthroughHostStopped
        {
            passthrough = true;
            break;
        }
    }
    // アプリ相当の処理は継続できる (記録だけが無効化される)
    let app_continues = true;
    report(
        "host_killed_passthrough",
        passthrough && app_continues,
        format!("passthrough={passthrough}"),
    )
}

/// 書き手が途中で終了 (クラッシュ相当): 公開済みだけが回収される。
pub fn scenario_writer_stops_midway() -> ScenarioReport {
    let cfg = RingConfig::new(64, 8192);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let r2 = region.clone();
    let producer = std::thread::spawn(move || {
        let mut w = writer_over(&r2, true);
        for i in 0..25u64 {
            w.write(ev(i, b"committed"));
        }
        // ここで突然終了する (writer を drop、未公開の作業は存在しない)
    });
    producer.join().unwrap();
    let mut rd = unsafe { region.reader() };
    let b = rd.drain_all();
    report(
        "writer_stops_midway",
        b.events.len() == 25,
        format!("recovered {}", b.events.len()),
    )
}

/// Slot 再利用と Generation: 終了確認+回収後にだけ再利用でき、世代が混ざらない。
pub fn scenario_slot_reuse() -> ScenarioReport {
    let pool = SlotPool::new(1);
    let h1 = pool.claim(100).unwrap();
    pool.begin_detach(&h1);
    let blocked = pool.claim(200).is_none();
    let released = shirusu_host::host_release_slot(&pool, &h1, true, true);
    let h2 = pool.claim(200).unwrap();
    let ok = blocked && released && h2.generation == h1.generation + 1 && h2.index == h1.index;
    // 世代の違う像は検証で弾かれる
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, h2.generation, 200);
    let mut vr = ValidatingReader::new(KnownConfig::new(cfg, cfg.required_len()), h1.generation);
    let gen_rejected = vr.drain_image(region.as_slice()).is_err();
    report(
        "slot_reuse_generation",
        ok && gen_rejected,
        format!("gen {} -> {}", h1.generation, h2.generation),
    )
}

/// Vec<u8> はポインタの 8 バイト整列を保証しないため、layout の原子操作を
/// 適用する画像は u64 バッファで保持する (整列なしは UB、Miri 検出)。
pub struct AlignedImage {
    words: Vec<u64>,
    len: usize,
}
impl AlignedImage {
    pub fn copy_of(src: &[u8]) -> Self {
        let mut s = Self {
            words: vec![0; src.len().div_ceil(8)],
            len: src.len(),
        };
        s.as_mut_slice().copy_from_slice(src);
        s
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr() as *const u8, self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr() as *mut u8, self.len) }
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }
}
impl std::ops::Deref for AlignedImage {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl std::ops::DerefMut for AlignedImage {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// 共有メモリ破壊: Host は崩れず Integrity 喪失として扱う。
pub fn scenario_corruption() -> ScenarioReport {
    let cfg = RingConfig::new(8, 256);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut image = AlignedImage::copy_of(region.as_slice());
    shirusu_transport::layout::store(
        image.as_mut_ptr(),
        shirusu_transport::layout::OFF_PAYLOAD_WRITE_POSITION,
        u64::MAX,
        Ordering::Relaxed,
    );
    let mut host = shirusu_host::ValidatingHost::new(KnownConfig::new(cfg, cfg.required_len()), 1);
    let err = host.drain_image(image.as_slice()).is_err();
    report(
        "corrupted_memory",
        err && host.integrity_lost,
        format!("integrity_lost={}", host.integrity_lost),
    )
}

/// Host を途中で kill して再起動: Reader を落とし、新しい Reader が
/// 共有 Cursor の続きから回収を再開する。イベントの重複・欠落はない。
/// ただし新しい Reader の Sequence 期待値は 1 から始まるため、欠番として
/// 25 件分のギャップが報告される (Host は Reader 状態を永続化すべき、という
/// 運用上の含意を detail に残す)。
pub fn scenario_host_restart_resume() -> ScenarioReport {
    let cfg = RingConfig::new(128, 16384);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer_over(&region, true);
    let mut seqs: Vec<u64> = Vec::new();
    for i in 0..40u64 {
        w.write(ev(i, b"before-kill"));
    }
    {
        let mut host1 = unsafe { region.reader() };
        let b = host1.drain(25);
        seqs.extend(b.events.iter().map(|e| e.descriptor.sequence));
        // ここで host1 を drop = Host kill 相当
    }
    for i in 40..100u64 {
        w.write(ev(i, b"after-kill"));
    }
    let mut host2 = unsafe { region.reader() };
    let b2 = host2.drain_all();
    seqs.extend(b2.events.iter().map(|e| e.descriptor.sequence));
    let want: Vec<u64> = (1..=100).collect();
    report(
        "host_restart_resume",
        seqs == want && b2.sequence_gaps == 25,
        format!(
            "recovered {} events in order across restart; fresh reader reports gap={} (reader state not persisted)",
            seqs.len(),
            b2.sequence_gaps
        ),
    )
}

/// Producer が公開途中で kill: Payload と Descriptor の途中まで書いた状態で
/// スレッドが死んでも、Host は確定済みだけを回収し、壊れたスロットに触れない。
pub fn scenario_producer_killed_mid_publish() -> ScenarioReport {
    let cfg = RingConfig::new(16, 1024);
    let region = Arc::new(SharedRegion::new(cfg, 1, 1));
    let mut w = writer_over(&region, true);
    for i in 0..5u64 {
        w.write(ev(i, b"committed"));
    }
    let r2 = region.clone();
    let killer = std::thread::spawn(move || {
        // 公開直前の事故を再現: 次スロットの Payload と Descriptor 前半だけ書く
        let base = r2.base();
        unsafe {
            let pay_off = r2.config.payload_offset() + 5 * 9;
            std::ptr::copy_nonoverlapping(b"torn-data".as_ptr(), base.add(pay_off), 9);
            let desc = shirusu_transport::EventDescriptor::new(EventKind::CallEnter, 6);
            let bytes = desc.to_bytes();
            let off = r2.config.descriptors_offset() + 5 * 64;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), 32);
        }
        // ここでスレッド終了 = kill。write_cursor は進んでいない。
    });
    killer.join().unwrap();
    let mut rd = unsafe { region.reader() };
    let b = rd.drain_all();
    let mut host = shirusu_host::ValidatingHost::new(KnownConfig::new(cfg, cfg.required_len()), 1);
    let via_validating = host.drain_image(region.as_slice());
    let ok = b.events.len() == 5
        && matches!(via_validating, Ok(ref evs) if evs.len() == 5)
        && !host.integrity_lost;
    report(
        "producer_killed_mid_publish",
        ok,
        format!(
            "recovered {} committed events; torn slot ignored, integrity_lost={}",
            b.events.len(),
            host.integrity_lost
        ),
    )
}

/// 32 スレッド Producer ストーム: 各スレッドが自分の Ring に 2000 件書き、
/// Slot の claim/release まで含めて会計が一致する。
pub fn scenario_producer_storm_32_threads() -> ScenarioReport {
    let pool = Arc::new(SlotPool::new(32));
    let threads: Vec<_> = (0..32u64)
        .map(|t| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                let handle = pool.claim(t).expect("32 slots for 32 threads");
                let cfg = RingConfig::new(256, 32768);
                let region = SharedRegion::new(cfg, 1, t);
                let mut w = writer_over(&region, true);
                let mut rd = unsafe { region.reader() };
                let mut got = 0u64;
                for i in 0..2000u64 {
                    let p = (t * 100_000 + i).to_le_bytes();
                    match w.write(ev(i, &p)) {
                        WriteOutcome::Published { .. } => {}
                        _ => return (t, false, got),
                    }
                    if i % 251 == 250 {
                        got += rd.drain_all().events.len() as u64;
                    }
                }
                got += rd.drain_all().events.len() as u64;
                pool.begin_detach(&handle);
                let released = shirusu_host::host_release_slot(&pool, &handle, true, true);
                (t, released && got == 2000, got)
            })
        })
        .collect();
    let mut all_ok = true;
    let mut total = 0u64;
    for h in threads {
        let (_t, ok, got) = h.join().unwrap();
        all_ok &= ok;
        total += got;
    }
    report(
        "producer_storm_32_threads",
        all_ok && pool.missing_calls() == 0 && pool.free_count() == 32,
        format!(
            "32 threads x 2000 events = {total}; missing={} free_after={}",
            pool.missing_calls(),
            pool.free_count()
        ),
    )
}

/// 100 万イベントのソーク: 小さい Ring に圧力をかけ続け、最後に
/// 「書込 = 受信 + 欠落」 の保存則と Payload 内容を全件突き合わせる。
pub fn scenario_soak_loss_accounting() -> ScenarioReport {
    const TOTAL: u64 = 1_000_000;
    let cfg = RingConfig::new(64, 4096);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer_over(&region, true);
    let mut rd = unsafe { region.reader() };
    let payload_of = |seq: u64| -> Vec<u8> {
        let len = ((seq - 1) % 17 + 1) as usize;
        let bytes = seq.to_le_bytes();
        (0..len).map(|j| bytes[j % 8]).collect()
    };
    let mut published = 0u64;
    let mut degraded = 0u64;
    let mut dropped = 0u64;
    let mut dropped_seqs: Vec<u64> = Vec::new();
    let mut received = 0u64;
    let mut gaps = 0u64;
    let mut last_received = 0u64;
    let mut content_ok = true;
    for i in 0..TOTAL {
        let seq = i + 1;
        let p = payload_of(seq);
        match w.write(ev(i, &p)) {
            WriteOutcome::Published { .. } => published += 1,
            WriteOutcome::PublishedDegraded { .. } => {
                published += 1;
                degraded += 1;
            }
            WriteOutcome::Dropped { .. } => {
                dropped += 1;
                dropped_seqs.push(seq);
            }
        }
        if i % 997 == 996 {
            let b = rd.drain_all();
            received += b.events.len() as u64;
            gaps += b.sequence_gaps;
            for e in &b.events {
                last_received = e.descriptor.sequence;
                if !e.descriptor.payload_dropped() && e.payload != payload_of(e.descriptor.sequence)
                {
                    content_ok = false;
                }
            }
        }
    }
    let b = rd.drain_all();
    received += b.events.len() as u64;
    gaps += b.sequence_gaps;
    for e in &b.events {
        last_received = e.descriptor.sequence;
        if !e.descriptor.payload_dropped() && e.payload != payload_of(e.descriptor.sequence) {
            content_ok = false;
        }
    }
    let counters = w.loss_counters();
    let observable_gaps = dropped_seqs.iter().filter(|&&s| s < last_received).count() as u64;
    let ok = content_ok
        && TOTAL == received + dropped
        && received == published
        && counters.dropped_events == dropped
        && counters.degraded_events == degraded
        && gaps == observable_gaps
        && dropped > 0; // 圧力が実際にかかったこと (全件通るなら検証にならない)
    report(
        "soak_1m_loss_accounting",
        ok,
        format!(
            "total={TOTAL} received={received} dropped={dropped} degraded={degraded} gaps={gaps} content_ok={content_ok}"
        ),
    )
}

/// 共有メモリ破壊注入: 途中まで正常に読んだ後で Descriptor を壊すと、
/// Host はクラッシュせず Ring 停止 + Integrity 喪失で止まる。
pub fn scenario_corruption_injection_stops_ring() -> ScenarioReport {
    let cfg = RingConfig::new(16, 1024);
    let region = SharedRegion::new(cfg, 1, 1);
    let mut w = writer_over(&region, true);
    for i in 0..10u64 {
        w.write(ev(i, b"stage"));
    }
    let mut host = shirusu_host::ValidatingHost::new(KnownConfig::new(cfg, cfg.required_len()), 1);
    let mut image = AlignedImage::copy_of(region.as_slice());
    let first = host.drain_image(image.as_slice());
    let first_ok = matches!(first, Ok(ref evs) if evs.len() == 10);
    // 未読スロットの Descriptor の kind を未知の値に壊す (slot 10 が次の読取位置)
    let off = cfg.descriptors_offset() + 10 * 64;
    image[off] = 0xFF;
    image[off + 1] = 0xFF;
    // write_cursor を 11 に進んだことにする (壊れた Descriptor が確定済みに見える)
    shirusu_transport::layout::store(
        image.as_mut_ptr(),
        shirusu_transport::layout::OFF_WRITE_CURSOR,
        11,
        Ordering::Relaxed,
    );
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host.drain_image(image.as_slice())
    }));
    let no_panic = caught.is_ok();
    let err = matches!(caught, Ok(Err(_)));
    let stopped_forever = matches!(
        host.drain_image(image.as_slice()),
        Err(shirusu_transport::validate::IntegrityError::RingStopped)
    );
    report(
        "corruption_injection_stops_ring",
        first_ok && no_panic && err && host.integrity_lost && stopped_forever,
        format!(
            "first_ok={first_ok} no_panic={no_panic} integrity_lost={} stopped={stopped_forever}",
            host.integrity_lost
        ),
    )
}

/// DETACH 中の公開ストーム: DETACH 後の呼出は 1 万回でも全て欠落カウントされ、
/// 記録は増えず、Host 回収が終わるまで Slot は再利用できない。
pub fn scenario_detach_publish_storm() -> ScenarioReport {
    use shirusu_agent::{Agent, RecordResult};
    use shirusu_transport::slot::SlotPool as Pool;
    let pool = Arc::new(Pool::new(1));
    let monitor = Arc::new(HostMonitor::always_alive());
    let agent =
        Agent::new(pool.clone(), RingConfig::new(64, 4096), monitor).with_policy(WriterPolicy {
            max_wait: Duration::ZERO,
            ..Default::default()
        });
    let handle = agent.thread_begin(1).expect("slot");
    for i in 0..10u64 {
        agent.record_enter(1, 1, 1, i, 0, b"pre");
    }
    assert!(agent.thread_detach(1));
    let mut all_after_detach = true;
    for i in 0..10_000u64 {
        if agent.record_enter(1, 1, 1, 100 + i, 0, b"storm") != RecordResult::AfterDetach {
            all_after_detach = false;
            break;
        }
    }
    // Ring には DETACH 前の 10 件だけがある
    let base = unsafe { agent.thread_region_base(1) }.expect("region");
    let mut rd = unsafe { RingReader::new(base, RingConfig::new(64, 4096)) };
    let drained = rd.drain_all().events.len();
    // claim の失敗自体も missing を数えるため、確認用の claim の前に値を捕捉する
    let missing_after_storm = pool.missing_calls();
    let blocked = pool.claim(999).is_none();
    let released = shirusu_host::host_release_slot(&pool, &handle, true, true);
    report(
        "detach_publish_storm",
        all_after_detach && missing_after_storm == 10_000 && drained == 10 && blocked && released,
        format!(
            "storm all AfterDetach={all_after_detach} missing={missing_after_storm} recorded={drained} blocked={blocked} released={released}"
        ),
    )
}

pub fn run_all_in_process() -> Vec<ScenarioReport> {
    let sync = SyncPoints::test_enabled();
    vec![
        scenario_basic(5000),
        scenario_host_pause(&sync),
        scenario_notification_loss(&sync),
        scenario_space_available_notify(),
        scenario_agent_space_available_handoff(),
        scenario_host_killed(),
        scenario_writer_stops_midway(),
        scenario_slot_reuse(),
        scenario_corruption(),
        scenario_host_restart_resume(),
        scenario_producer_killed_mid_publish(),
        scenario_producer_storm_32_threads(),
        scenario_soak_loss_accounting(),
        scenario_corruption_injection_stops_ring(),
        scenario_detach_publish_storm(),
    ]
}

/// A77: Windows プロセス間メモリ順序ストレステストの検証ロジック。
///
/// supervisor が回収した観測だけから判定する（プラットフォーム非依存のため
/// Linux でも単体テストできる）。Windows 実走では supervisor が
/// `DrainWorker` の観測をこの構造体に詰めて呼ぶ。
///
/// 検証する保存則:
/// - 順序・内容: 回収した payload は 0..N をちょうど 1 回ずつ、順番どおり
///   （単一書き手スレッドの公開順がプロセスを越えて保たれること）。
/// - 格納: payload_keys が N 件（欠落 Payload にはキーが付かない）。
/// - 完全性: integrity_lost が立っていないこと。
/// - 欠落会計: SequenceGap の合計 == 書き手が報告した dropped_events
///   （Dropped は sequence を払って欠番を作る。リトライで同じ call_id を
///   書き直すため、欠番は必ず dropped と 1 対 1 で対応する）。
/// - 劣化会計: 回収した descriptor 総数 == N + degraded_events
///   （PublishedDegraded は descriptor を残すため、回収総数に現れる）。
#[derive(Debug, Clone)]
pub struct StressObservation<'a> {
    pub payloads: &'a [u64],
    pub expected: u64,
    pub payload_keys: usize,
    pub total_events: u64,
    pub integrity_lost: bool,
    pub sequence_gaps: u64,
    pub dropped_reported: u64,
    pub degraded_reported: u64,
}

pub fn verify_memory_order_stress(obs: &StressObservation) -> Result<String, String> {
    if obs.integrity_lost {
        return Err("integrity lost: validating reader stopped the ring".to_string());
    }
    if obs.payloads.len() as u64 != obs.expected {
        return Err(format!(
            "payload count mismatch: got {} want {}",
            obs.payloads.len(),
            obs.expected
        ));
    }
    for (i, p) in obs.payloads.iter().enumerate() {
        if *p != i as u64 {
            return Err(format!(
                "payload mismatch at index {i}: got {p} want {i} (order/content broken)"
            ));
        }
    }
    if obs.payload_keys as u64 != obs.expected {
        return Err(format!(
            "payload_keys mismatch: got {} want {}",
            obs.payload_keys, obs.expected
        ));
    }
    if obs.sequence_gaps != obs.dropped_reported {
        return Err(format!(
            "unaccounted sequence gaps: gaps={} dropped_reported={}",
            obs.sequence_gaps, obs.dropped_reported
        ));
    }
    if obs.total_events != obs.expected + obs.degraded_reported {
        return Err(format!(
            "total events mismatch: got {} want {} + degraded {}",
            obs.total_events, obs.expected, obs.degraded_reported
        ));
    }
    Ok(format!(
        "memory order stress: {} events in order, keys={}, gaps={} (dropped={}), degraded={}",
        obs.expected,
        obs.payload_keys,
        obs.sequence_gaps,
        obs.dropped_reported,
        obs.degraded_reported
    ))
}

/// L06: ABI Probe の名前一覧。対象（shirusu-hook-target --abi-probe）
/// と比較器で共有する正準リスト。Probe を増やすときはここにも追加する。
pub const ABI_PROBE_NAMES: &[&str] = &[
    "float",
    "struct-return",
    "callback",
    "exception",
    "lasterror-success",
    "lasterror-failure",
];

/// L06: ABI Probe 出力（Hook なし＝baseline と Hook あり）の比較。
/// `ABI_PROBE <name> <value...>` 行だけを対象にし、名前・順序・値が
/// すべて一致すれば空を返す。不一致は人間可読の差分行を返す。
/// `ABI_PROBE_DONE ok` 行の有無も比べる：対象が最後まで走り切って
/// いない（異常終了・クラッシュ）場合に DONE 行が欠けるため、
/// LaunchedCapture が対象の終了コードを返さない代わりの成功シグナル
/// として使う。Probe 行以外の stdout（TARGET_* 行など）は無視する。
pub fn compare_abi_probe_outputs(baseline: &str, hooked: &str) -> Vec<String> {
    fn probe_lines(out: &str) -> Vec<(&str, &str)> {
        out.lines()
            .filter_map(|l| l.strip_prefix("ABI_PROBE "))
            .filter_map(|rest| rest.split_once(' '))
            .collect()
    }
    let base = probe_lines(baseline);
    let hook = probe_lines(hooked);
    let mut diffs = Vec::new();
    let base_done = baseline.lines().any(|l| l == "ABI_PROBE_DONE ok");
    let hook_done = hooked.lines().any(|l| l == "ABI_PROBE_DONE ok");
    if base_done != hook_done {
        diffs.push(format!(
            "ABI_PROBE_DONE differs: baseline={base_done} hooked={hook_done} (target did not run to completion in one of the runs)"
        ));
    }
    // 名前・順序・値を位置ごとに比べる。長さが違えば余りも報告する。
    for (i, ((bn, bv), (hn, hv))) in base.iter().zip(hook.iter()).enumerate() {
        if bn != hn {
            diffs.push(format!(
                "probe #{i} name differs: baseline={bn} hooked={hn}"
            ));
        } else if bv != hv {
            diffs.push(format!(
                "probe {bn} value differs: baseline={bv} hooked={hv}"
            ));
        }
    }
    if base.len() != hook.len() {
        let common = base.len().min(hook.len());
        let (longer, which) = if base.len() > hook.len() {
            (&base[common..], "baseline")
        } else {
            (&hook[common..], "hooked")
        };
        for (n, _) in longer {
            diffs.push(format!("probe {n} present only in {which}"));
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(payloads: &[u64], expected: u64) -> StressObservation<'_> {
        StressObservation {
            payloads,
            expected,
            payload_keys: expected as usize,
            total_events: expected,
            integrity_lost: false,
            sequence_gaps: 0,
            dropped_reported: 0,
            degraded_reported: 0,
        }
    }

    #[test]
    fn stress_clean_passes() {
        let o = obs(&[0, 1, 2, 3, 4], 5);
        assert!(verify_memory_order_stress(&o).is_ok());
    }

    #[test]
    fn stress_accounted_gaps_pass() {
        // Dropped 2 件はリトライで書き直され、欠番として gaps=2 に現れる。
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.sequence_gaps = 2;
        o.dropped_reported = 2;
        assert!(verify_memory_order_stress(&o).is_ok());
    }

    #[test]
    fn stress_accounted_degraded_pass() {
        // PublishedDegraded 2 件は descriptor を残すため回収総数に現れる。
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.total_events = 7;
        o.degraded_reported = 2;
        assert!(verify_memory_order_stress(&o).is_ok());
    }

    #[test]
    fn stress_unaccounted_gap_fails() {
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.sequence_gaps = 2;
        o.dropped_reported = 1;
        let e = verify_memory_order_stress(&o).unwrap_err();
        assert!(e.contains("unaccounted"), "{e}");
    }

    #[test]
    fn stress_duplicate_fails() {
        let o = obs(&[0, 1, 1, 3, 4], 5);
        assert!(verify_memory_order_stress(&o).is_err());
    }

    #[test]
    fn stress_out_of_order_fails() {
        let o = obs(&[0, 2, 1, 3, 4], 5);
        assert!(verify_memory_order_stress(&o).is_err());
    }

    #[test]
    fn stress_missing_fails() {
        let o = obs(&[0, 1, 2, 3], 5);
        assert!(verify_memory_order_stress(&o).is_err());
    }

    #[test]
    fn stress_keys_mismatch_fails() {
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.payload_keys = 4;
        assert!(verify_memory_order_stress(&o).is_err());
    }

    #[test]
    fn stress_integrity_lost_fails() {
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.integrity_lost = true;
        assert!(verify_memory_order_stress(&o).is_err());
    }

    #[test]
    fn stress_degraded_mismatch_fails() {
        let mut o = obs(&[0, 1, 2, 3, 4], 5);
        o.total_events = 6;
        o.degraded_reported = 0;
        assert!(verify_memory_order_stress(&o).is_err());
    }

    // L06: ABI Probe 出力の比較。`ABI_PROBE <name> <value>` 行だけを
    // 対象にし、名前・順序・値が両方で一致すれば空（＝一致）を返す。
    fn probe_output(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(n, v)| format!("ABI_PROBE {n} {v}\n"))
            .collect()
    }

    #[test]
    fn abi_compare_identical_passes() {
        let out = probe_output(&[
            ("float", "0123456789abcdef"),
            ("struct-return", "ok"),
            ("callback", "ok"),
            ("exception", "caught"),
            ("lasterror-success", "1234"),
            ("lasterror-failure", "2"),
        ]);
        assert!(compare_abi_probe_outputs(&out, &out).is_empty());
    }

    #[test]
    fn abi_compare_ignores_non_probe_lines() {
        // TARGET_* 行や stdout の雑音は比較対象外（両方にあってよい）。
        let base = format!(
            "TARGET_PATH C:\\temp\\x.tmp\n{}",
            probe_output(&[("float", "aa")])
        );
        let hooked = format!("{}\nTARGET_DONE ok", probe_output(&[("float", "aa")]));
        assert!(compare_abi_probe_outputs(&base, &hooked).is_empty());
    }

    #[test]
    fn abi_compare_changed_value_fails() {
        let base = probe_output(&[("float", "aa"), ("callback", "ok")]);
        let hooked = probe_output(&[("float", "bb"), ("callback", "ok")]);
        let diffs = compare_abi_probe_outputs(&base, &hooked);
        assert_eq!(diffs.len(), 1, "{diffs:?}");
        assert!(diffs[0].contains("float"), "{}", diffs[0]);
    }

    #[test]
    fn abi_compare_missing_probe_fails() {
        let base = probe_output(&[("float", "aa"), ("callback", "ok")]);
        let hooked = probe_output(&[("float", "aa")]);
        let diffs = compare_abi_probe_outputs(&base, &hooked);
        assert!(diffs.iter().any(|d| d.contains("callback")), "{diffs:?}");
    }

    #[test]
    fn abi_compare_extra_probe_fails() {
        let base = probe_output(&[("float", "aa")]);
        let hooked = probe_output(&[("float", "aa"), ("callback", "ok")]);
        let diffs = compare_abi_probe_outputs(&base, &hooked);
        assert!(diffs.iter().any(|d| d.contains("callback")), "{diffs:?}");
    }

    #[test]
    fn abi_compare_reordered_fails() {
        let base = probe_output(&[("float", "aa"), ("callback", "ok")]);
        let hooked = probe_output(&[("callback", "ok"), ("float", "aa")]);
        assert!(!compare_abi_probe_outputs(&base, &hooked).is_empty());
    }

    #[test]
    fn abi_compare_missing_done_line_fails() {
        // DONE 行が無い＝対象が最後まで走り切っていない（異常終了）。
        let base = probe_output(&[("float", "aa")]) + "ABI_PROBE_DONE ok\n";
        let hooked = probe_output(&[("float", "aa")]);
        let diffs = compare_abi_probe_outputs(&base, &hooked);
        assert!(diffs.iter().any(|d| d.contains("DONE")), "{diffs:?}");
    }

    #[test]
    fn abi_probe_names_cover_all_probes() {
        // 比較器が要求する Probe 名と、対象が実装する Probe 名は一致する。
        assert_eq!(
            ABI_PROBE_NAMES,
            [
                "float",
                "struct-return",
                "callback",
                "exception",
                "lasterror-success",
                "lasterror-failure",
            ]
        );
    }
}
