//! 低水位時の非同期 Mapping 追加フロー (A70) の Host 側。
//!
//! 要求 ([`ExpansionRequest`]) を受けてバックグラウンドで新しい Mapping
//! ([`SharedMapping`]) を作り、[`ExpansionDelivery`] で Agent へ配送する。
//! 作成は同期的に待たせない (要求した管理スレッドは待たない)。追加中に
//! Host が止まっても、Agent は既存の Ring で続ける (C11)。
//!
//! 作成した Mapping はこのサービスが保持し続ける。プロセス内実装では
//! Agent はその `base` を借りて使う。Windows プロセス間では要求の
//! `target_pid` へ Mapping を duplicate したハンドル値を配送し、Agent は
//! 自分の写像を作る (Host は自分の写像を保持し続け、そこから回収する)。

use shirusu_transport::expansion::{
    ExpansionDeliverer, ExpansionDelivery, ExpansionRequest, EXPANDED_SLOT_GENERATION,
};
use shirusu_transport::RingConfig;
use shirusu_transport_win::SharedMapping;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

/// Host 側の非同期 Mapping 作成サービス。要求チャネルから要求を受け取り、
/// 新しい Mapping を作って配送口へ渡す。
pub struct ExpansionService {
    requests: Receiver<ExpansionRequest>,
    deliverer: Box<dyn ExpansionDeliverer>,
    config: RingConfig,
    /// 作成済み Mapping の保持。Agent (プロセス内) は `base` を借りるため、
    /// このサービスが生存する間は有効に保つ。Windows でも Host は自分の
    /// 写像を保持し続け、そこから回収する。
    mappings: Vec<SharedMapping>,
    /// 作成して配送した Mapping の数。
    pub created: u64,
    /// 作成に失敗した要求の数 (長さ 0 など)。
    pub declined_create: u64,
    /// プロセス間 duplicate に失敗した要求の数 (スタブの Unsupported を含む)。
    /// 失敗した要求の Mapping は保持せず破棄する。
    pub declined_duplicate: u64,
    poll_interval: Duration,
}

/// サービスを別スレッドで回すためのハンドル。`stop()` で停止して統計付きの
/// サービス本体を回収する。
pub struct ExpansionServiceHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<ExpansionService>>,
}
impl ExpansionServiceHandle {
    /// サービススレッドを止め、本体を回収する。作成済み Mapping は本体と
    /// ともに破棄される (Agent が借りている `base` は以後使えない)。
    pub fn stop(mut self) -> ExpansionService {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .expect("expansion service thread")
            .join()
            .expect("expansion service thread panicked")
    }
}
impl Drop for ExpansionServiceHandle {
    fn drop(&mut self) {
        // 止め忘れてもスレッドが残り続けないよう、停止だけは要求する
        // (join は stop() の役目)。
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ExpansionService {
    /// 要求の受け口・配送口・Ring 設定から作る。`config` は Agent と同じ
    /// Ring 設定であること (Mapping の大きさ = `required_len()`)。
    pub fn new(
        requests: Receiver<ExpansionRequest>,
        deliverer: Box<dyn ExpansionDeliverer>,
        config: RingConfig,
    ) -> Self {
        Self {
            requests,
            deliverer,
            config,
            mappings: Vec::new(),
            created: 0,
            declined_create: 0,
            declined_duplicate: 0,
            poll_interval: Duration::from_millis(5),
        }
    }
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
    /// 作成済み Mapping の数 (保持中のもの)。
    pub fn mappings_held(&self) -> usize {
        self.mappings.len()
    }
    /// 要求を 1 件だけ処理する (テスト駆動用)。要求が無ければ false を返す。
    /// 作成や duplicate に失敗した要求も消費し、件数を数える。
    pub fn poll_once(&mut self) -> bool {
        let Ok(req) = self.requests.try_recv() else {
            return false;
        };
        self.handle_request(req);
        true
    }
    /// 要求チャネルが切断されるか `stop` が立つまで回し続ける。サービス本体を返す。
    pub fn run(mut self, stop: Arc<AtomicBool>) -> Self {
        while !stop.load(Ordering::Relaxed) {
            match self.requests.recv_timeout(self.poll_interval) {
                Ok(req) => self.handle_request(req),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self
    }
    /// 別スレッドで回す。返したハンドルの `stop()` で停止する。
    pub fn spawn(self, stop: Arc<AtomicBool>) -> ExpansionServiceHandle {
        let stop_clone = Arc::clone(&stop);
        let thread = std::thread::spawn(move || self.run(stop_clone));
        ExpansionServiceHandle {
            stop,
            thread: Some(thread),
        }
    }
    fn handle_request(&mut self, req: ExpansionRequest) {
        let _ = req.slots; // 現行は 1 要求 = 1 Slot。将来の複数要求はここで扱う。
        let len = self.config.required_len();
        let mapping = match SharedMapping::create(len) {
            Ok(m) => m,
            Err(_) => {
                self.declined_create += 1;
                return;
            }
        };
        // Windows プロセス間の場合だけ duplicate し、ハンドル値を配送する。
        // duplicate に失敗したら Mapping は保持せず破棄する。
        let handle_value = match req.target_pid {
            Some(pid) => match mapping.duplicate_to_process(pid) {
                Ok(h) => Some(h),
                Err(_) => {
                    self.declined_duplicate += 1;
                    return;
                }
            },
            None => None,
        };
        let base = if handle_value.is_none() {
            Some(mapping.as_ptr())
        } else {
            None
        };
        // 保持: プロセス内では Agent が base を借りるため、Mapping を落としては
        // ならない。Windows でも Host は自分の写像から回収するため保持する。
        self.mappings.push(mapping);
        self.created += 1;
        self.deliverer.deliver(ExpansionDelivery {
            len,
            base,
            handle_value,
            generation: EXPANDED_SLOT_GENERATION,
        });
    }
}
