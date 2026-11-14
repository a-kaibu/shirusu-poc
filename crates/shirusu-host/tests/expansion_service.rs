//! A70: 低水位時の非同期 Mapping 追加フロー (Host 側サービス)。
//!
//! `ExpansionService` が要求を受けて新しい Mapping を作り、Agent へ配送する。

use shirusu_host::expansion::ExpansionService;
use shirusu_transport::expansion::ExpansionRequest;
use shirusu_transport::RingConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

fn cfg() -> RingConfig {
    RingConfig::new(16, 512)
}

#[test]
fn service_creates_mapping_and_delivers_base() {
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, del_rx) = mpsc::channel();
    let mut service = ExpansionService::new(req_rx, Box::new(del_tx), cfg())
        .with_poll_interval(Duration::from_millis(1));
    req_tx.send(ExpansionRequest::new()).unwrap();
    assert!(service.poll_once(), "one request is processed");
    assert!(!service.poll_once(), "no more requests");
    let delivery = del_rx.try_recv().expect("delivery must arrive");
    assert_eq!(delivery.len, cfg().required_len());
    assert!(delivery.base.is_some(), "in-process delivery carries base");
    assert!(!delivery.base.unwrap().is_null());
    assert_eq!(delivery.handle_value, None);
    assert_eq!(delivery.generation, 0);
    assert_eq!(service.created, 1);
    assert_eq!(service.mappings_held(), 1);
    assert_eq!(service.declined_create, 0);
    assert_eq!(service.declined_duplicate, 0);
}

#[test]
fn service_with_target_pid_duplicate_path() {
    // Windows プロセス間: 対象プロセスへ duplicate したハンドル値を配送する。
    // Linux スタブでは duplicate が Unsupported のため要求は断念される。
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, del_rx) = mpsc::channel();
    let mut service = ExpansionService::new(req_rx, Box::new(del_tx), cfg());
    req_tx
        .send(ExpansionRequest::for_process(std::process::id()))
        .unwrap();
    assert!(service.poll_once());
    #[cfg(not(windows))]
    {
        assert_eq!(service.created, 0);
        assert_eq!(service.declined_duplicate, 1);
        assert_eq!(service.mappings_held(), 0, "failed mapping is not retained");
        assert!(del_rx.try_recv().is_err(), "no delivery on failure");
    }
    #[cfg(windows)]
    {
        assert_eq!(service.created, 1);
        assert_eq!(service.declined_duplicate, 0);
        let delivery = del_rx.try_recv().expect("delivery must arrive");
        assert!(delivery.handle_value.is_some());
        assert_eq!(delivery.base, None);
    }
}

#[test]
fn service_run_stops_on_disconnect() {
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, _del_rx) = mpsc::channel();
    let service = ExpansionService::new(req_rx, Box::new(del_tx), cfg());
    drop(req_tx); // 要求元が無くなった = Agent 側が止まった。
    let stop = Arc::new(AtomicBool::new(false));
    let started = std::time::Instant::now();
    let service = service.run(stop);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(service.created, 0);
}

#[test]
fn service_spawn_and_stop() {
    let (req_tx, req_rx) = mpsc::channel();
    let (del_tx, del_rx) = mpsc::channel();
    let service = ExpansionService::new(req_rx, Box::new(del_tx), cfg());
    let stop = Arc::new(AtomicBool::new(false));
    let handle = service.spawn(Arc::clone(&stop));
    req_tx.send(ExpansionRequest::new()).unwrap();
    let delivery = del_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("delivery must arrive");
    assert!(delivery.base.is_some());
    let service = handle.stop();
    assert_eq!(service.created, 1);
    assert_eq!(service.mappings_held(), 1);
    let _ = stop.load(Ordering::Relaxed);
}

#[test]
fn dropping_the_handle_asks_the_service_thread_to_stop() {
    let (req_tx, req_rx) = mpsc::channel::<ExpansionRequest>();
    let (del_tx, _del_rx) = mpsc::channel();
    let service = ExpansionService::new(req_rx, Box::new(del_tx), cfg());
    let stop = Arc::new(AtomicBool::new(false));
    let handle = service.spawn(Arc::clone(&stop));
    assert!(!stop.load(Ordering::Relaxed));
    drop(handle);
    assert!(stop.load(Ordering::Relaxed), "drop requests the stop");
    // 要求元は生きたままでも、スレッドは停止要求で受け口を手放す。
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while req_tx.send(ExpansionRequest::new()).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "service thread kept running"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
