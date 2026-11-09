//! E2E producer: 専用プログラムとして起動され、イベントを書く側を演じる。
//! モード:
//!   --mapping <handle> --len <bytes> --count <n> [--event-handle <h>]  (Windows: 実 File Mapping)
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
