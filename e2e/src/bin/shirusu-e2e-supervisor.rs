//! E2E Test Supervisor: シナリオを実行し、専用プログラムを起動して検証する。
//! 使い方:
//!   shirusu-e2e-supervisor --all          プロセス内シナリオ + 子プロセス起動スモーク
//!   shirusu-e2e-supervisor --cross-arch   (Windows) i686 producer + x64 host のプロセス間実テスト
//!   shirusu-e2e-supervisor --list

use shirusu_e2e::{run_all_in_process, ScenarioReport};
use std::io::Read as _;

fn print_reports(reports: &[ScenarioReport]) -> bool {
    let mut all = true;
    for r in reports {
        println!(
            "[{}] {}: {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.name,
            r.detail
        );
        all &= r.passed;
    }
    all
}

/// 子プロセス (producer --file / consumer 相当の検証) を起動するスモーク。
/// 共有メモリの実テストは --cross-arch (Windows) が担う。ここはプロセス起動と検証の配線確認。
fn subprocess_smoke(count: u64) -> ScenarioReport {
    let exe = std::env::current_exe().expect("current exe");
    let dir = exe.parent().unwrap().to_path_buf();
    let producer = dir.join(if cfg!(windows) {
        "shirusu-e2e-producer.exe"
    } else {
        "shirusu-e2e-producer"
    });
    let tmp = std::env::temp_dir().join(format!("shirusu-e2e-{}.bin", std::process::id()));
    let out = std::process::Command::new(&producer)
        .args([
            "--file",
            tmp.to_str().unwrap(),
            "--count",
            &count.to_string(),
        ])
        .output();
    let detail = match out {
        Ok(o) if o.status.success() => {
            let mut f = std::fs::File::open(&tmp).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            let mut idx = 0usize;
            let mut n = 0u64;
            let mut ok = true;
            while idx < buf.len() {
                let seq = u64::from_le_bytes(buf[idx..idx + 8].try_into().unwrap());
                let len = u32::from_le_bytes(buf[idx + 8..idx + 12].try_into().unwrap()) as usize;
                let payload = &buf[idx + 12..idx + 12 + len];
                if seq != n || payload != seq.to_le_bytes() {
                    ok = false;
                    break;
                }
                idx += 12 + len;
                n += 1;
            }
            let _ = std::fs::remove_file(&tmp);
            if ok && n == count {
                format!("subprocess file records verified: {n}")
            } else {
                format!("record mismatch at {n}")
            }
        }
        Ok(o) => format!("producer failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => format!("producer spawn failed: {e}"),
    };
    let passed = detail.contains("verified");
    ScenarioReport {
        name: "subprocess_smoke",
        passed,
        detail,
    }
}

/// Windows: x64 の本プロセス (Host) が Mapping を作り、継承ハンドルで producer を起動し、
/// producer が書いたイベントを x64 Host が回収する。producer が i686 バイナリなら
/// 「x86 Agent + x64 Host」のプロセス間実テストになる (GHA の windows-x86 ジョブ)。
#[cfg(windows)]
fn cross_arch() -> ScenarioReport {
    use shirusu_transport::layout::init_control;
    use shirusu_transport::RingConfig;
    use shirusu_transport_win::{spawn_inheriting, wait_process, ProcessNotify, SharedMapping};
    use std::time::Duration;

    let producer_path = std::env::var("SHIRUSU_E2E_PRODUCER").unwrap_or_else(|_| {
        let exe = std::env::current_exe().unwrap();
        exe.parent()
            .unwrap()
            .join("shirusu-e2e-producer.exe")
            .to_string_lossy()
            .into_owned()
    });
    let count = 2000u64;
    let cfg = RingConfig::new(4096, 1024 * 1024);
    let len = cfg.required_len();
    let mapping = match SharedMapping::create(len) {
        Ok(m) => m,
        Err(e) => {
            return ScenarioReport {
                name: "cross_arch_interprocess",
                passed: false,
                detail: format!("mapping: {e}"),
            }
        }
    };
    init_control(mapping.as_ptr(), cfg, 1, 4242);
    let notify = match ProcessNotify::new() {
        Ok(n) => n,
        Err(e) => {
            return ScenarioReport {
                name: "cross_arch_interprocess",
                passed: false,
                detail: format!("event: {e}"),
            }
        }
    };
    if let Err(e) = mapping
        .make_inheritable()
        .and_then(|_| notify.data_ready.make_inheritable())
    {
        return ScenarioReport {
            name: "cross_arch_interprocess",
            passed: false,
            detail: format!("inheritable: {e}"),
        };
    }
    let cmdline = format!(
        "\"{}\" --mapping {} --len {} --count {} --event-handle {}",
        producer_path,
        mapping.handle_value(),
        len,
        count,
        notify.data_ready.handle_value()
    );
    let proc = match spawn_inheriting(&cmdline) {
        Ok(p) => p,
        Err(e) => {
            return ScenarioReport {
                name: "cross_arch_interprocess",
                passed: false,
                detail: format!("spawn: {e}"),
            }
        }
    };
    // data_ready を 2ms 再確認付きで待ちながら回収する。producer 終了後にも残りを回収する。
    let mut rd = unsafe { shirusu_transport::ring::RingReader::new(mapping.as_ptr(), cfg) };
    let mut got: Vec<u64> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut exit_code = wait_process(proc, Duration::from_millis(10));
    while (got.len() as u64) < count {
        let b = rd.drain(4096);
        for e in b.events {
            if !e.descriptor.payload_dropped() {
                got.push(u64::from_le_bytes(e.payload.try_into().unwrap()));
            }
        }
        if std::time::Instant::now() > deadline {
            break;
        }
        if exit_code.is_none() {
            exit_code = wait_process(proc, Duration::from_millis(2));
        } else {
            // producer 終了済みで、これ以上増えないなら打ち切る
            let wc = rd.write_cursor();
            if wc as usize <= got.len() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(2)); // 2ms 再確認
    }
    let in_order = got.iter().enumerate().all(|(i, v)| *v == i as u64);
    let passed = exit_code == Some(0) && got.len() as u64 == count && in_order;
    ScenarioReport {
        name: "cross_arch_interprocess",
        passed,
        detail: format!(
            "producer={producer_path} exit={exit_code:?} got={} in_order={in_order}",
            got.len()
        ),
    }
}

#[cfg(not(windows))]
fn cross_arch() -> ScenarioReport {
    ScenarioReport {
        name: "cross_arch_interprocess",
        passed: false,
        detail: "SKIP: Windows 専用。GHA windows-latest で実行する".into(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--list") {
        println!("basic, host_pause_overflow, notification_loss_recheck, space_available_notify, agent_space_available_handoff, host_killed_passthrough, writer_stops_midway, slot_reuse_generation, corrupted_memory, host_restart_resume, producer_killed_mid_publish, producer_storm_32_threads, soak_1m_loss_accounting, corruption_injection_stops_ring, detach_publish_storm, subprocess_smoke, cross_arch_interprocess");
        return;
    }
    if args.iter().any(|a| a == "--cross-arch") {
        let r = cross_arch();
        let passed = r.passed;
        print_reports(&[r]);
        // Windows では必須、他 OS では SKIP を成功として扱う (CI の OS 別ジョブ前提)
        std::process::exit(if passed || !cfg!(windows) { 0 } else { 1 });
    }
    // --all (既定)
    let mut reports = run_all_in_process();
    reports.push(subprocess_smoke(1000));
    if cfg!(windows) {
        reports.push(cross_arch());
    }
    let ok = print_reports(&reports);
    std::process::exit(if ok { 0 } else { 1 });
}
