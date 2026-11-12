#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text)=std::str::from_utf8(data) {
        let id=shirusu_trace::BlobId::parse_hex(text);
        assert_eq!(id.is_some(),text.len()==64 && text.bytes().all(|b| b.is_ascii_hexdigit()));
        if let Some(id)=id {assert_eq!(id.to_hex(),text.to_ascii_lowercase());}
    }
});
