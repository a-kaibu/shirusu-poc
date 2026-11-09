//! E2E producer: 専用プログラムとして起動され、イベントを書く側を演じる。
//! モード:
//!   --mapping <handle> --len <bytes> --count <n> [--event-handle <h>]  (Windows: 実 File Mapping)
//!   --agent-path --mapping <handle> --len <bytes> --count1 <n> --count2 <n>
//!       --data-ready <h> --phase-done <h> --reclaim-ok <h>
//!       (Windows: 本番経路 D77。実 shirusu_agent::Agent を agent-dll と
//!        同じ手順で構築し、Slot 再利用を挟んで 2 フェーズ記録する)
//!   --file <path> --count <n>   (フォールバック: レコードをファイルへ。共有メモリではない)
//!   --selftest                  (自己完結で書込/回収を検証)

use shirusu_e2e::ev;
use shirusu_transport::ring::{SharedRegion, WriterPolicy};
use shirusu_transport::{Clock, RingConfig};
use std::io::Write as _;
use std::sync::Arc;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count: u64 = arg(&args, "--count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);

    if args.iter().any(|a| a == "--selftest") {
        let cfg = RingConfig::new(256, 64 * 1024);
        let region = SharedRegion::new(cfg, 1, std::process::id() as u64);
        let clock: Arc<dyn Clock> = shirusu_transport::clock::system_clock();
        let mut w = unsafe { region.writer(WriterPolicy::default(), clock) };
        let mut rd = unsafe { region.reader() };
        for i in 0..count {
            let p = i.to_le_bytes();
            w.write(ev(i, &p));
        }
        let b = rd.drain_all();
        let ok = b
            .events
            .iter()
            .filter(|e| !e.descriptor.payload_dropped())
            .count() as u64;
        println!("producer selftest: wrote {count}, drained {ok}");
        std::process::exit(if ok == count { 0 } else { 1 });
    }

    if let Some(path) = arg(&args, "--file") {
        // レコード形式: [seq u64][len u32][payload] の繰り返し (consumer が検証する)
        let mut f = std::fs::File::create(&path).expect("create file");
        for i in 0..count {
            let p = i.to_le_bytes();
            f.write_all(&i.to_le_bytes()).unwrap();
            f.write_all(&(p.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&p).unwrap();
        }
        println!("producer file: wrote {count} records to {path}");
        return;
    }

    if args.iter().any(|a| a == "--agent-path") {
        #[cfg(windows)]
        {
            agent_path(&args);
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("producer agent-path: Windows only");
            std::process::exit(2);
        }
    }

    if let Some(handle) = arg(&args, "--mapping") {
        #[cfg(windows)]
        {
            use shirusu_transport_win::{EventObject, SharedMapping};
            let len: usize = arg(&args, "--len")
                .and_then(|v| v.parse().ok())
                .expect("--len");
            let cfg = RingConfig::new(4096, 1024 * 1024);
            assert_eq!(len, cfg.required_len(), "mapping len mismatch");
            let mapping =
                unsafe { SharedMapping::from_handle_value(handle.parse().expect("handle"), len) }
                    .expect("map view");
            let clock: Arc<dyn Clock> = shirusu_transport::clock::system_clock();
            let mut w = unsafe {
                shirusu_transport::RingWriter::new(
                    mapping.as_ptr(),
                    cfg,
                    WriterPolicy::default(),
                    clock,
                )
            };
            for i in 0..count {
                let p = i.to_le_bytes();
                loop {
                    match w.write(ev(i, &p)) {
                        shirusu_transport::WriteOutcome::Published { .. } => break,
                        _ => std::thread::yield_now(),
                    }
                }
            }
            if let Some(eh) = arg(&args, "--event-handle") {
                let event = unsafe {
                    EventObject::from_handle_value(eh.parse().expect("event handle"), true)
                };
                let _ = event.set(); // data_ready
                std::mem::forget(event); // 親のイベントを閉じない
            }
            println!("producer mapping: wrote {count} events");
            return;
        }
        #[cfg(not(windows))]
        {
            eprintln!("producer mapping: Windows only (handle={handle})");
            std::process::exit(2);
        }
    }

    eprintln!(
        "usage: --selftest | --file <path> --count <n> | --mapping <handle> --len <n> --count <n>"
    );
    std::process::exit(2);
}

/// D77 の本番経路 (producer 側): 実 `shirusu_agent::Agent` を Agent DLL と
/// 同じ手順 (空の SlotPool + register_slot_mapping) で構築し、共有メモリへ
/// 記録する。フェーズ 1 の記録 → DETACH → Host の回収確認 (reclaim-ok
/// イベント) → Slot 再利用 → フェーズ 2 の記録、までを行う。
///
/// Host の確認をイベントで受けるのはテスト用同期ポイント (D34) であり、
/// 本番では Host プロセスがスレッド終了確認と回収完了を判断し、Agent
/// 側の管理経路が回収を駆動する (A70 の管理スレッドの役割)。ここでは
/// その判断結果だけをイベントで受け取り、回収操作は自プロセスの
/// SlotPool に対して host_release_slot で行う。
#[cfg(windows)]
fn agent_path(args: &[String]) {
    use shirusu_agent::{Agent, RecordResult};
    use shirusu_transport::context::HostMonitor;
    use shirusu_transport::expansion::ExpansionDelivery;
    use shirusu_transport::slot::SlotPool;
    use shirusu_transport::{RingConfig, EXPANDED_SLOT_GENERATION};
    use shirusu_transport_win::{EventObject, ProcessNotify};
    use std::time::{Duration, Instant};

    let parse = |name: &str| -> usize {
        arg(args, name)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("missing/invalid {name}"))
    };
    let mapping_handle = parse("--mapping");
    let len = parse("--len");
    let count1 = parse("--count1") as u64;
    let count2 = parse("--count2") as u64;
    let cfg = RingConfig::new(4096, 1024 * 1024);
    assert_eq!(len, cfg.required_len(), "mapping len mismatch");

    let pool = Arc::new(SlotPool::new(0));
    let agent = Agent::new(pool.clone(), cfg, Arc::new(HostMonitor::always_alive()));
    let delivery = ExpansionDelivery {
        len,
        base: None,
        handle_value: Some(mapping_handle),
        generation: EXPANDED_SLOT_GENERATION,
    };
    let slot_index = agent
        .register_slot_mapping(delivery)
        .expect("register_slot_mapping");
    assert_eq!(slot_index, 0);

    // SAFETY: いずれも Host (supervisor) が継承可能にして渡した、この
    // プロセスで有効なイベントハンドル。所有は持たない (forget する)。
    let data_ready = ProcessNotify {
        data_ready: unsafe { EventObject::from_handle_value(parse("--data-ready"), true) },
    };
    let phase_done = unsafe { EventObject::from_handle_value(parse("--phase-done"), true) };
    let reclaim_ok = unsafe { EventObject::from_handle_value(parse("--reclaim-ok"), true) };

    let record_range = |agent: &Agent, thread_id: u64, from: u64, count: u64| {
        for i in from..from + count {
            let p = i.to_le_bytes();
            loop {
                match agent.record_enter(thread_id, 100, 200, i, 0, &p) {
                    RecordResult::Written(shirusu_transport::WriteOutcome::Published {
                        ..
                    }) => break,
                    RecordResult::Written(_) => std::thread::yield_now(),
                    other => panic!("record failed at {i}: {other:?}"),
                }
            }
            // 本番経路の通知: 公開後に data_ready を立てる (A15/A17)。
            let _ = data_ready.notify_data_ready();
        }
    };

    // フェーズ 1: スレッド 1 が記録して DETACH する。
    let h1 = agent.thread_begin(1).expect("thread_begin phase 1");
    assert_eq!(h1.generation, EXPANDED_SLOT_GENERATION);
    record_range(&agent, 1, 0, count1);
    assert!(agent.thread_detach(1), "thread_detach phase 1");
    let _ = phase_done.set();

    // Host が「スレッド終了確認 + 回収完了」を済ませるまで待つ。
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if reclaim_ok.wait_timeout(Duration::from_millis(100)) {
            break;
        }
        if Instant::now() > deadline {
            eprintln!("producer agent-path: timed out waiting for reclaim-ok");
            std::process::exit(3);
        }
    }

    // Host 確認済みを受けて Slot を回収し、Agent 側の保持を解く。
    assert!(
        shirusu_host::host_release_slot(&pool, &h1, true, true),
        "host_release_slot must succeed after host confirmation"
    );
    agent.thread_forget(1);

    // フェーズ 2: 同じ Slot が次の Generation で再利用される。
    let h2 = agent.thread_begin(2).expect("thread_begin phase 2");
    assert_eq!(h2.index, h1.index, "slot must be reused");
    assert_eq!(
        h2.generation,
        h1.generation + 1,
        "generation must advance on reuse"
    );
    record_range(&agent, 2, count1, count2);
    assert!(agent.thread_detach(2), "thread_detach phase 2");
    let _ = phase_done.set();

    std::mem::forget(data_ready);
    std::mem::forget(phase_done);
    std::mem::forget(reclaim_ok);
    println!(
        "producer agent-path: phase1={count1} phase2={count2} slot={} gen {}->{} ",
        h1.index, h1.generation, h2.generation
    );
}
