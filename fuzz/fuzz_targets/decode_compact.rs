#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_trace::compact::{decode_compact, decode_values, encode_values};
use shirusu_trace::proto::SchemaSet;
use shirusu_trace::schema::schema_types;

// 入力形式: 先頭 2 バイト (LE) が SchemaSet のバイト長、続いて
// SchemaSet (Protobuf)、残りが Compact Binary の値列。
// どちらが壊れていても panic せず、復号できた場合は再符号化→再復号で
// 値が一致すること (冪等性) まで確かめる。
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let slen = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + slen {
        return;
    }
    let schema_bytes = &data[2..2 + slen];
    let values_bytes = &data[2 + slen..];
    if let Ok(values) = decode_compact(schema_bytes, values_bytes) {
        let set = SchemaSet::decode(schema_bytes).expect("decode_compact accepted it");
        let types = schema_types(&set.schemas[0]).expect("types resolved");
        let re = encode_values(&types, &values).expect("re-encode");
        let values2 = decode_values(&types, &re).expect("re-decode");
        assert_eq!(values, values2);
    }
});
