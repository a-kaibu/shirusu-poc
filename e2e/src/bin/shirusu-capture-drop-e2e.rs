//! Native lifecycle regression: abandon an initialized attach without finish.
//! The companion C target verifies restored code and survives a subsequent attach.
#[cfg(windows)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture};
    use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
    use shirusu_transport::{RingConfig, TimestampSource};

    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || !matches!(args[3].as_str(), "drop" | "unwind") {
        return Err("usage: shirusu-capture-drop-e2e <dll> <pid> <trace> <drop|unwind>".into());
    }
    let pid = args[1].parse::<u32>()?;
    let frequency = shirusu_transport_win::QpcTimestampSource::new().frequency();
    let config = CaptureSessionConfig {
        session_id: 4242,
        ring_config: RingConfig::PRODUCTION,
        environment: CaptureEnvironment {
            session: SessionMetadata {
                session_id: 4242,
                created_by: "shirusu-capture-drop-e2e".into(),
                qpc_frequency: frequency,
            },
            target_description: format!("pid {pid}"),
            ..Default::default()
        },
        qpc_frequency: frequency,
        durability: shirusu_trace::writer::Durability::Buffered,
        order_global: false,
        record_runtime_apis: false,
        diagnostic_query_interface: false,
        record_mode: shirusu_host::trace_convert::RecordMode::Full,
    };
    let capture = LaunchedCapture::attach(
        pid,
        &args[2],
        LaunchConfig::new(config, args[0].clone().into()),
    )?;
    if args[3] == "unwind" {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _capture = capture;
            panic!("intentional capture abandonment regression");
        }));
        assert!(result.is_err());
    } else {
        drop(capture);
    }
    let trace = shirusu_trace::read_trace(&std::fs::read(&args[2])?)?;
    assert!(
        trace.finalization.is_none(),
        "abandonment must not fabricate successful finalization"
    );
    println!(
        "abandoned attach completed without finalization ({})",
        args[3]
    );
    Ok(())
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("capture abandonment regression failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("SKIP: capture abandonment requires Windows");
}
