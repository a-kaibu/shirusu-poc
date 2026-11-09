//! 低水位時の非同期 Mapping 追加フロー (A70) の Agent 側管理スレッド。
//!
//! - `SlotPool` の拡張要求フラグを消費し、Host へ要求を送る。
//! - Host から配送された Mapping を受け取り、[`Agent::register_expanded_mapping`]
//!   で `SlotPool` へ登録する。登録が完了した Slot だけが以後の claim で
//!   使える。
//! - 登録 (Slot 追加 + Mapping の紐付け) はこの管理スレッドだけが行う。
//!   記録経路 (record / Hook 相当) は登録も待機もしない。
//! - 進行中の拡張が 1 件ある間は新規要求を出さない (二重作成しない)。
//!   要求フラグはラッチ型なので、進行中に立った要求は次の step で改めて
//!   処理される。
//! - 追加中に Host が止まったら要求を破棄し、後で再要求できる状態に戻す。
//!   既存 Ring での記録は止めない (C11)。

use crate::Agent;
use shirusu_transport::expansion::{ExpansionDelivery, ExpansionRequest, ExpansionRequester};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

/// 管理スレッドの動作実績。テストと運用観測用。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionStats {
    /// Host へ送った要求の数。
    pub requested: u64,
    /// SlotPool へ登録を完了した Mapping の数。
    pub registered: u64,
    /// 総メモリ上限のために拡張を断念した回数 (要求前・配送後の両方)。
    pub declined_limit: u64,
    /// Host 停止が分かっているため要求を送らなかった回数。
    pub skipped_host_stopped: u64,
    /// 追加中に Host 停止を検知して要求を破棄した回数。
    pub discarded_host_stopped: u64,
    /// 配送の写像化に失敗した回数 (ハンドル値の展開失敗、世代の不一致など)。
    /// 失敗した配送では Slot は追加しない。
    pub failed_delivery: u64,
}

/// 低水位時の非同期 Mapping 追加を担う管理スレッドの実体。
/// `step()` で 1 回分の処理を行い、`run()` で回し続ける。`step()` は
/// 待たない (配送の受取は `try_recv`、要求の送信は即時) ため、テストで
/// 駆動できる。
pub struct ExpansionManager {
    agent: Arc<Agent>,
    requester: Box<dyn ExpansionRequester>,
    deliveries: Receiver<ExpansionDelivery>,
    poll_interval: Duration,
    in_flight: bool,
    stats: ExpansionStats,
}

/// 管理スレッドを別スレッドで回すためのハンドル。`stop()` で停止して
/// 統計を回収する。
pub struct ExpansionManagerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<ExpansionStats>>,
}
impl ExpansionManagerHandle {
    /// 管理スレッドを止め、統計を回収する。
    pub fn stop(mut self) -> ExpansionStats {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .expect("expansion manager thread")
            .join()
            .expect("expansion manager thread panicked")
    }
}
impl Drop for ExpansionManagerHandle {
    fn drop(&mut self) {
        // 止め忘れてもスレッドが残り続けないよう、停止だけは要求する
        // (join は stop() の役目)。
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ExpansionManager {
    /// 管理対象の Agent、Host への要求口、Host からの配送口から作る。
    pub fn new(
        agent: Arc<Agent>,
        requester: Box<dyn ExpansionRequester>,
        deliveries: Receiver<ExpansionDelivery>,
    ) -> Self {
        Self {
            agent,
            requester,
            deliveries,
            poll_interval: Duration::from_millis(5),
            in_flight: false,
            stats: ExpansionStats::default(),
        }
    }
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
    /// 進行中の拡張があるかどうか。
    pub fn is_in_flight(&self) -> bool {
        self.in_flight
    }
    pub fn stats(&self) -> ExpansionStats {
        self.stats
    }
    /// 1 回分の処理。待たない。
    ///
    /// - 進行中の拡張があれば、配送を待つ。届いたら登録し、Host 停止を
    ///   検知したら要求を破棄する。
    /// - 進行中の拡張が無ければ、要求フラグを消費する。Host 停止中は送らず、
    ///   総メモリ上限なら断念し、それ以外なら要求を送る。
    pub fn step(&mut self) {
        if self.in_flight {
            match self.deliveries.try_recv() {
                Ok(delivery) => {
                    self.in_flight = false;
                    self.register(delivery);
                }
                Err(TryRecvError::Empty) => {
                    if self.host_stopped() {
                        // Host が止まった: 要求を破棄する。フラグは消費済みだが、
                        // 次に claim が低水位を踏めば要求は再び立つので、
                        // 「後で再要求できる状態」に戻っている。
                        self.in_flight = false;
                        self.stats.discarded_host_stopped += 1;
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    // Host 側が止まった (配送口が切断された): 要求を破棄する。
                    self.in_flight = false;
                    self.stats.discarded_host_stopped += 1;
                }
            }
            return;
        }
        // 進行中の拡張が無ければ、新しい要求フラグを消費する。
        if !self.agent.pool().take_expansion_request() {
            return;
        }
        if self.host_stopped() {
            // Host 停止が分かっている間は要求を送らない (送り先が無い)。
            self.stats.skipped_host_stopped += 1;
            return;
        }
        if !self.agent.pool().can_add_slot() {
            // 総メモリ上限: 拡張を断念し、フラグを落とす。次に claim が
            // 低水位を踏んでも上限が変わらなければ再び断念するだけである。
            self.stats.declined_limit += 1;
            return;
        }
        self.requester.request_expansion(ExpansionRequest::new());
        self.in_flight = true;
        self.stats.requested += 1;
    }
    /// `stop` が立つまで `step()` を回し続ける。統計を返す。
    pub fn run(mut self, stop: Arc<AtomicBool>) -> ExpansionStats {
        while !stop.load(Ordering::Relaxed) {
            self.step();
            std::thread::sleep(self.poll_interval);
        }
        self.stats
    }
    fn host_stopped(&self) -> bool {
        !self.agent.host_monitor().recording_enabled()
    }
    fn register(&mut self, delivery: ExpansionDelivery) {
        if !self.agent.pool().can_add_slot() {
            self.stats.declined_limit += 1;
            return;
        }
        match self.agent.register_expanded_mapping(delivery) {
            Ok(_) => self.stats.registered += 1,
            Err(()) => self.stats.failed_delivery += 1,
        }
    }
}

impl Agent {
    /// 拡張管理スレッドを起動する。`request_tx` で Host へ要求し、
    /// `delivery_rx` で Mapping を受け取る。管理スレッドだけが SlotPool へ
    /// 登録する (record 経路は登録しない)。
    pub fn spawn_expansion_manager(
        agent: Arc<Agent>,
        request_tx: std::sync::mpsc::Sender<ExpansionRequest>,
        delivery_rx: Receiver<ExpansionDelivery>,
    ) -> ExpansionManagerHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let manager = ExpansionManager::new(agent, Box::new(request_tx), delivery_rx);
        let stop_clone = Arc::clone(&stop);
        let thread = std::thread::spawn(move || manager.run(stop_clone));
        ExpansionManagerHandle {
            stop,
            thread: Some(thread),
        }
    }
}
