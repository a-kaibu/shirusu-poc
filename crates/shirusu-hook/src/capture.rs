//! 型付き引数取得。生の引数値（ポインタはアドレス値）を、Schema に
//! 沿った `CapturedValue` 列へ変換する。メモリ読み取りは
//! [`MemoryReader`] トレイト越しに行い、実メモリの読み方（Windows の
//! 同一プロセス内読み取り）は engine 側が実装する。ここは純粋な
//! 変換ロジックであり、Linux でも単体テストできる。
//!
//! 取得の原則（overview「型付きの値」）:
//! - 読めなかった値を NULL / 0 として保存しない。取得状態
//!   （Unreadable / Truncated / Unsupported）を必ず付ける。
//! - 文字列・バッファには上限を設け、超過分は Truncated として記録する。
//! - 入力バッファは呼び出し前（before)、出力バッファは元の API が
//!   書き込んだ後（after）に取得する。取得タイミングは API ごとに
//!   enter/leave のどちらで値を埋めるかで表す。

use crate::api::ApiDef;
use shirusu_trace::compact::encode_values;
use shirusu_trace::schema::{schema_types, CapturedValue, TypedValue, ValueCapture};
use shirusu_trace::CompactError;

/// UTF-16 文字列の取得上限（終端 NUL を除く単位数）。
pub const MAX_STRING_UNITS: usize = 1024;
/// バッファ内容の取得上限（バイト数）。超過は Truncated。
pub const MAX_BUFFER_BYTES: usize = 4096;

/// 対象プロセスのメモリを読む抽象。実装は「addr から buf を満たす
/// 全バイトが読めた場合にだけ true」を返すこと。部分的に読めた場合の
/// 扱いは取得側がブロック単位で制御する。
pub trait MemoryReader {
    fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool;
    fn read_u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        if self.read_exact(addr, &mut b) {
            Some(u32::from_le_bytes(b))
        } else {
            None
        }
    }
}

/// テスト用の地図型メモリ。書いた範囲だけが読める。
#[derive(Debug, Default)]
pub struct MapMemory {
    bytes: std::collections::BTreeMap<u64, u8>,
}
impl MapMemory {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn write(&mut self, addr: u64, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.bytes.insert(addr + i as u64, *b);
        }
    }
    pub fn write_u16s(&mut self, addr: u64, units: &[u16]) {
        for (i, u) in units.iter().enumerate() {
            self.write(addr + (i as u64) * 2, &u.to_le_bytes());
        }
    }
    pub fn write_u32(&mut self, addr: u64, v: u32) {
        self.write(addr, &v.to_le_bytes());
    }
}
impl MemoryReader for MapMemory {
    fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool {
        for (i, slot) in buf.iter_mut().enumerate() {
            match self.bytes.get(&(addr + i as u64)) {
                Some(b) => *slot = *b,
                None => return false,
            }
        }
        true
    }
}

fn cap(value: TypedValue, capture: ValueCapture) -> CapturedValue {
    CapturedValue { capture, value }
}
pub fn u64v(v: u64) -> CapturedValue {
    CapturedValue::captured(TypedValue::U64(v))
}
pub fn u32v(v: u32) -> CapturedValue {
    CapturedValue::captured(TypedValue::U32(v))
}
pub fn i32v(v: i32) -> CapturedValue {
    CapturedValue::captured(TypedValue::I32(v))
}

/// UTF-16 文字列（NUL 終端）を Str16 値として取得する。
/// NULL ポインタは「読めない」と区別するため Unreadable として記録する
/// （overview: 読めなかった値を NULL として保存しない）。
pub fn read_utf16_string(mem: &dyn MemoryReader, addr: u64) -> CapturedValue {
    if addr == 0 {
        return cap(TypedValue::Str16(Vec::new()), ValueCapture::Unreadable);
    }
    let mut units: Vec<u16> = Vec::new();
    let mut buf = [0u8; 64]; // 32 units ずつ読む
    loop {
        let chunk_addr = addr + (units.len() as u64) * 2;
        if mem.read_exact(chunk_addr, &mut buf) {
            for pair in buf.chunks_exact(2) {
                let u = u16::from_le_bytes([pair[0], pair[1]]);
                if u == 0 {
                    return cap(TypedValue::Str16(units), ValueCapture::Captured);
                }
                units.push(u);
                if units.len() >= MAX_STRING_UNITS {
                    return cap(TypedValue::Str16(units), ValueCapture::Truncated);
                }
            }
            continue;
        }
        // ブロック全体が読めない場合は 1 unit ずつ救済する（ブロックが
        // ページ境界を跨いで後半だけ読めないケースや、終端 NUL の直後が
        // 未マップなケースで、前半の文字列を失わないため）。
        let mut salvaged_any = false;
        for i in 0..32u64 {
            let mut b2 = [0u8; 2];
            if !mem.read_exact(chunk_addr + i * 2, &mut b2) {
                break;
            }
            salvaged_any = true;
            let u = u16::from_le_bytes(b2);
            if u == 0 {
                return cap(TypedValue::Str16(units), ValueCapture::Captured);
            }
            units.push(u);
            if units.len() >= MAX_STRING_UNITS {
                return cap(TypedValue::Str16(units), ValueCapture::Truncated);
            }
        }
        // 最初のブロックすら読めなければ Unreadable、途中なら Truncated
        return if units.is_empty() && !salvaged_any {
            cap(TypedValue::Str16(Vec::new()), ValueCapture::Unreadable)
        } else {
            cap(TypedValue::Str16(units), ValueCapture::Truncated)
        };
    }
}

/// バッファ内容を Bytes 値として取得する。上限を超える分は切り捨てて
/// Truncated を付ける。1 バイトも読めなければ Unreadable。
pub fn read_buffer(mem: &dyn MemoryReader, addr: u64, len: usize) -> CapturedValue {
    if len == 0 {
        return CapturedValue::captured(TypedValue::Bytes(Vec::new()));
    }
    if addr == 0 {
        return cap(TypedValue::Bytes(Vec::new()), ValueCapture::Unreadable);
    }
    let want = len.min(MAX_BUFFER_BYTES);
    let mut out = vec![0u8; want];
    if mem.read_exact(addr, &mut out) {
        let state = if len > MAX_BUFFER_BYTES {
            ValueCapture::Truncated
        } else {
            ValueCapture::Captured
        };
        return cap(TypedValue::Bytes(out), state);
    }
    // 全体が読めない場合は 1 バイトずつ可能な範囲まで拾い、部分取得として残す
    let mut got = 0usize;
    let mut one = [0u8; 1];
    while got < want && mem.read_exact(addr + got as u64, &mut one) {
        out[got] = one[0];
        got += 1;
    }
    if got == 0 {
        cap(TypedValue::Bytes(Vec::new()), ValueCapture::Unreadable)
    } else {
        out.truncate(got);
        cap(TypedValue::Bytes(out), ValueCapture::Truncated)
    }
}

fn unsupported_bytes() -> CapturedValue {
    cap(TypedValue::Bytes(Vec::new()), ValueCapture::Unsupported)
}
fn unsupported_u32() -> CapturedValue {
    cap(TypedValue::U32(0), ValueCapture::Unsupported)
}

// ---- API ごとの取得（フィールド順は api.rs の定義と一致させる） ----

#[allow(clippy::too_many_arguments)]
pub fn create_file_w_enter(
    mem: &dyn MemoryReader,
    file_name_addr: u64,
    desired_access: u32,
    share_mode: u32,
    security_attributes: u64,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template_file: u64,
) -> Vec<CapturedValue> {
    vec![
        read_utf16_string(mem, file_name_addr),
        u32v(desired_access),
        u32v(share_mode),
        u64v(security_attributes),
        u32v(creation_disposition),
        u32v(flags_and_attributes),
        u64v(template_file),
    ]
}

pub fn create_file_w_leave(return_handle: u64, last_error: u32) -> Vec<CapturedValue> {
    vec![u64v(return_handle), u32v(last_error)]
}

pub fn read_file_enter(handle: u64, buffer: u64, bytes_to_read: u32) -> Vec<CapturedValue> {
    vec![u64v(handle), u64v(buffer), u32v(bytes_to_read)]
}

/// ReadFile の leave。`bytes_read_addr` は lpNumberOfBytesRead の
/// アドレス（0 なら NULL が渡された）。OVERLAPPED 指定時は完了が
/// 非同期のため、読取バイト数とバッファ内容は Unsupported。
pub fn read_file_leave(
    mem: &dyn MemoryReader,
    success: i32,
    buffer: u64,
    bytes_read_addr: u64,
    overlapped: bool,
    last_error: u32,
) -> Vec<CapturedValue> {
    if overlapped {
        return vec![
            i32v(success),
            unsupported_u32(),
            unsupported_bytes(),
            u32v(last_error),
        ];
    }
    let bytes_read = if bytes_read_addr == 0 {
        None
    } else {
        mem.read_u32(bytes_read_addr)
    };
    let (count_value, data) = match bytes_read {
        Some(n) => {
            let data = if success == 0 {
                // 失敗時は出力バッファに有効なデータが無い
                CapturedValue::captured(TypedValue::Bytes(Vec::new()))
            } else {
                read_buffer(mem, buffer, n as usize)
            };
            (u32v(n), data)
        }
        None => (unsupported_u32(), unsupported_bytes()),
    };
    vec![i32v(success), count_value, data, u32v(last_error)]
}

pub fn write_file_enter(
    mem: &dyn MemoryReader,
    handle: u64,
    buffer: u64,
    bytes_to_write: u32,
) -> Vec<CapturedValue> {
    vec![
        u64v(handle),
        read_buffer(mem, buffer, bytes_to_write as usize),
        u32v(bytes_to_write),
    ]
}

pub fn write_file_leave(
    mem: &dyn MemoryReader,
    success: i32,
    bytes_written_addr: u64,
    overlapped: bool,
    last_error: u32,
) -> Vec<CapturedValue> {
    let written = if overlapped || bytes_written_addr == 0 {
        None
    } else {
        mem.read_u32(bytes_written_addr)
    };
    let count = match written {
        Some(n) => u32v(n),
        None => unsupported_u32(),
    };
    vec![i32v(success), count, u32v(last_error)]
}

pub fn close_handle_enter(handle: u64) -> Vec<CapturedValue> {
    vec![u64v(handle)]
}

pub fn close_handle_leave(success: i32, last_error: u32) -> Vec<CapturedValue> {
    vec![i32v(success), u32v(last_error)]
}

/// 取得した値列を、その API の Schema で Compact Binary へ符号化する。
/// 転送 Payload として運び、Host 変換で TraceEvent.args へ写す。
pub fn encode_enter(api: &ApiDef, values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types = schema_types(&api.enter_schema()).expect("hook schemas use known tags only");
    encode_values(&types, values)
}
pub fn encode_leave(api: &ApiDef, values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    let types = schema_types(&api.leave_schema()).expect("hook schemas use known tags only");
    encode_values(&types, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::*;
    use shirusu_trace::compact::decode_values;
    use shirusu_trace::schema::Ty;

    fn mem_with_str(addr: u64, s: &str) -> MapMemory {
        let mut m = MapMemory::new();
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.push(0);
        m.write_u16s(addr, &units);
        m
    }

    #[test]
    fn utf16_string_roundtrip_and_null() {
        let m = mem_with_str(0x1000, "C:\\data\\save.dat");
        let v = read_utf16_string(&m, 0x1000);
        assert_eq!(v.capture, ValueCapture::Captured);
        assert_eq!(
            v.value,
            TypedValue::Str16("C:\\data\\save.dat".encode_utf16().collect())
        );
        // NULL は空文字列と区別される
        let null = read_utf16_string(&m, 0);
        assert_eq!(null.capture, ValueCapture::Unreadable);
        // 未書込アドレスも Unreadable
        let missing = read_utf16_string(&m, 0x9000);
        assert_eq!(missing.capture, ValueCapture::Unreadable);
    }

    #[test]
    fn utf16_string_truncates_at_cap() {
        let mut m = MapMemory::new();
        let units: Vec<u16> = std::iter::repeat_n(0x41u16, MAX_STRING_UNITS + 500).collect();
        m.write_u16s(0x2000, &units);
        let v = read_utf16_string(&m, 0x2000);
        assert_eq!(v.capture, ValueCapture::Truncated);
        match v.value {
            TypedValue::Str16(u) => assert_eq!(u.len(), MAX_STRING_UNITS),
            _ => panic!("expected Str16"),
        }
    }

    #[test]
    fn buffer_capture_limits_and_states() {
        let mut m = MapMemory::new();
        m.write(0x3000, b"hello");
        let v = read_buffer(&m, 0x3000, 5);
        assert_eq!(
            v,
            CapturedValue::captured(TypedValue::Bytes(b"hello".to_vec()))
        );
        // 0 バイトは Captured の空
        assert_eq!(
            read_buffer(&m, 0, 0),
            CapturedValue::captured(TypedValue::Bytes(Vec::new()))
        );
        // NULL ポインタで len>0 は Unreadable
        assert_eq!(read_buffer(&m, 0, 4).capture, ValueCapture::Unreadable);
        // 上限超過は Truncated で先頭だけ残る
        let big = vec![0xABu8; MAX_BUFFER_BYTES + 100];
        m.write(0x8000, &big);
        let v = read_buffer(&m, 0x8000, big.len());
        assert_eq!(v.capture, ValueCapture::Truncated);
        match v.value {
            TypedValue::Bytes(b) => assert_eq!(b.len(), MAX_BUFFER_BYTES),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn create_file_enter_encodes_and_decodes() {
        let api = api_by_id(API_CREATE_FILE_W).unwrap();
        let m = mem_with_str(0x1000, "D:\\game\\config.ini");
        let values = create_file_w_enter(&m, 0x1000, 0x8000_0000, 3, 0, 3, 0x80, 0);
        let bytes = encode_enter(api, &values).expect("encode");
        let types = schema_types(&api.enter_schema()).unwrap();
        let back = decode_values(&types, &bytes).expect("decode");
        assert_eq!(back, values);
        assert_eq!(back[0].value.ty(), Ty::Str16);
    }

    #[test]
    fn read_file_leave_captures_written_data() {
        let api = api_by_id(API_READ_FILE).unwrap();
        let mut m = MapMemory::new();
        m.write(0x4000, b"save-data-1234");
        m.write_u32(0x5000, 14);
        let values = read_file_leave(&m, 1, 0x4000, 0x5000, false, 0);
        assert_eq!(values[1], u32v(14));
        assert_eq!(
            values[2],
            CapturedValue::captured(TypedValue::Bytes(b"save-data-1234".to_vec()))
        );
        let bytes = encode_leave(api, &values).expect("encode");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), values);
        // 失敗時はデータ空、last_error が残る
        let failed = read_file_leave(&m, 0, 0x4000, 0x5000, false, 5);
        assert_eq!(
            failed[2],
            CapturedValue::captured(TypedValue::Bytes(Vec::new()))
        );
        assert_eq!(failed[3], u32v(5));
        // OVERLAPPED は Unsupported
        let ov = read_file_leave(&m, 0, 0x4000, 0x5000, true, 997);
        assert_eq!(ov[1].capture, ValueCapture::Unsupported);
        assert_eq!(ov[2].capture, ValueCapture::Unsupported);
        assert_eq!(ov[3], u32v(997));
    }

    #[test]
    fn write_file_enter_captures_input_before_call() {
        let mut m = MapMemory::new();
        m.write(0x6000, &[1, 2, 3, 4, 5]);
        let values = write_file_enter(&m, 0x1234, 0x6000, 5);
        assert_eq!(
            values[1],
            CapturedValue::captured(TypedValue::Bytes(vec![1, 2, 3, 4, 5]))
        );
        let leave = write_file_leave(&m, 1, 0, false, 0);
        assert_eq!(leave[1].capture, ValueCapture::Unsupported, "null out-ptr");
    }
}
