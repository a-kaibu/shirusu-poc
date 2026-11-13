#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_trace::stream::{StreamItem, TraceStream};
use std::io::Cursor;

// 任意バイト列をストリーミング Reader と全体読み込みの両方で読み、
// 受理の可否・内容・issue が一致することを確かめる (stream_trace)。
fuzz_target!(|data: &[u8]| {
    let full = shirusu_trace::recover_trace(data);
    let stream = TraceStream::open(Cursor::new(data));
    let (full, mut stream) = match (full, stream) {
        (Err(_), Err(_)) => return,
        (Ok(f), Ok(s)) => (f, s),
        _ => panic!("acceptance differs between readers"),
    };
    let mut batches = Vec::new();
    let mut schemas = Vec::new();
    let mut loss = Vec::new();
    let mut environment = None;
    let mut finalization = None;
    while let Some(item) = stream.next_item().expect("in-memory reads do not fail") {
        match item {
            StreamItem::Events(b) => batches.push(b),
            StreamItem::Schemas(s) => schemas.extend(s),
            StreamItem::Loss(l) => loss.extend(l),
            StreamItem::Environment(e) => environment = Some(e),
            StreamItem::Finalization {
                finalization: f,
                cleanly,
            } => finalization = Some((f, cleanly)),
            _ => {}
        }
    }
    for (id, content) in &full.blobs {
        assert_eq!(
            stream.load_blob(id).expect("read").as_deref(),
            Some(content.as_slice())
        );
    }
    let summary = stream.finish().expect("in-memory reads do not fail");
    assert_eq!(batches, full.batches);
    assert_eq!(schemas, full.schemas);
    assert_eq!(loss, full.loss_records);
    assert_eq!(environment, full.environment);
    assert_eq!(
        finalization,
        full.finalization.clone().map(|f| (f, full.finalized_cleanly))
    );
    assert_eq!(summary.blocks, full.blocks);
    let mut a: Vec<String> = full.issues.iter().map(|i| format!("{i:?}")).collect();
    let mut b: Vec<String> = summary.issues.iter().map(|i| format!("{i:?}")).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
});
