#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_trace::{BlobId,TraceWriter,writer::FinalizationInfo,reader::{read_trace_with_limits,ReaderLimits}};
fuzz_target!(|data: &[u8]| {
    let limits=ReaderLimits {max_blocks:128,max_events:128,max_blobs:4,max_decoded_bytes:16384,max_blob_bytes:4096};
    // Raw malformed containers and structure-aware valid update chains.
    if let Ok(t)=read_trace_with_limits(data,limits) {
        assert!(t.blobs.len()<=limits.max_blobs);
        assert!(t.blobs.values().map(|b|b.len() as u64).sum::<u64>()<=limits.max_blob_bytes);
    }
    let mut w=TraceWriter::new(Vec::new(),Default::default()).unwrap();
    let mut base=vec![0;1024];let id=w.add_payload(&base).unwrap();
    for (i,&byte) in data.iter().take(16).enumerate() {
        base[i]=byte;w.write_blob_update(id,BlobId::of_content(&base),i as u64,&[byte]).unwrap();
    }
    let encoded=w.finish(FinalizationInfo::default()).unwrap();
    let t=read_trace_with_limits(&encoded,limits).unwrap();
    assert!(t.blobs.len()<=limits.max_blobs);
    assert!(t.blobs.values().map(|b|b.len() as u64).sum::<u64>()<=limits.max_blob_bytes);
});
