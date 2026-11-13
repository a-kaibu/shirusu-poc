//! Capacity experiment with the unchanged native high-load fixture.
//! This is separate from the default-configuration performance acceptance run.
#[cfg(windows)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use shirusu_host::recorder::CaptureSessionConfig;
    use shirusu_host::recorder_launch::{LaunchConfig, LaunchedCapture};
    use shirusu_trace::proto::{CaptureEnvironment, SessionMetadata};
    use shirusu_transport::{RingConfig, TimestampSource};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: shirusu-buffer-bench <dll> <exe> <trace> <descriptor-capacity>".into());
    }
    let capacity = args[3].parse::<usize>()?;
    if !matches!(capacity, 4096 | 16384 | 65536) || args[1].contains('"') {
        return Err("invalid capacity or executable path".into());
    }
    let frequency = shirusu_transport_win::QpcTimestampSource::new().frequency();
    let config = CaptureSessionConfig {
        session_id: 4242,
        ring_config: RingConfig::new(capacity, 1024 * 1024),
        environment: CaptureEnvironment {
            session: SessionMetadata {
                session_id: 4242,
                created_by: "shirusu-buffer-bench".into(),
                qpc_frequency: frequency,
            },
            target_description: "native high-load capacity sweep".into(),
            ..Default::default()
        },
        qpc_frequency: frequency,
        durability: shirusu_trace::writer::Durability::Buffered,
        order_global: false,
        record_runtime_apis: false,
        diagnostic_query_interface: false,
        record_mode: shirusu_host::trace_convert::RecordMode::Full,
    };
    let capture = LaunchedCapture::launch(
        &format!("\"{}\" high-load", args[1]),
        &args[2],
        LaunchConfig::new(config, args[0].clone().into()),
    )?;
    let summary = capture.run_to_completion(std::time::Duration::from_millis(2))?;
    if summary.target_exit_code != Some(0) {
        return Err(format!("target failed: {:?}", summary.target_exit_code).into());
    }
    println!(
        "capacity={capacity} events={} loss_records={} host={:?}",
        summary.total_events, summary.total_loss_records, summary.host_pipeline
    );
    Ok(())
}
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("buffer experiment failed: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    println!("SKIP: requires Windows");
}
