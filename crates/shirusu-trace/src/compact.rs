//! Compact Binary の符号化・復号。形式の正は `docs/trace-format.md` の
//! 「Compact Binary」節。
//!
//! - 値列：Schema が型と順序を定め、値ごとの型タグは持たない。
//!   各値は「取得状態 1 バイト＋値本体」。
//! - イベント列：Event Chunk 内で、Batch 文脈との差分で符号化する。

use crate::blob::BlobId;
use crate::error::CompactError;
use crate::model::{EventBatch, PayloadLossReason, PayloadRef, TraceEvent};
use crate::proto::BatchHeader;
use crate::schema::{CapturedValue, EventCapture, Ty, TypedValue, ValueCapture};

// ---------------------------------------------------------------------------
// LEB128
// ---------------------------------------------------------------------------

pub fn write_uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub fn write_sleb(out: &mut Vec<u8>, v: i64) {
    // zigzag: (v << 1) ^ (v >> 63)
    let zz = ((v << 1) ^ (v >> 63)) as u64;
    write_uleb(out, zz);
}

pub struct Cursor<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn is_done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    pub fn read_u8(&mut self) -> Result<u8, CompactError> {
        let b = *self.buf.get(self.pos).ok_or(CompactError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], CompactError> {
        if self.remaining() < n {
            return Err(CompactError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub fn read_uleb(&mut self) -> Result<u64, CompactError> {
        let mut result: u64 = 0;
        for i in 0..10 {
            let b = self.read_u8().map_err(|_| CompactError::Leb128TooLong)?;
            if i == 9 && b > 1 {
                return Err(CompactError::Leb128TooLong);
            }
            result |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(CompactError::Leb128TooLong)
    }
    pub fn read_sleb(&mut self) -> Result<i64, CompactError> {
        let zz = self.read_uleb()?;
        Ok(((zz >> 1) as i64) ^ -((zz & 1) as i64))
    }
    pub fn read_len_bytes(&mut self) -> Result<&'a [u8], CompactError> {
        let len = self.read_uleb()?;
        let len = usize::try_from(len).map_err(|_| CompactError::Truncated)?;
        self.read_exact(len)
    }
}

// ---------------------------------------------------------------------------
// 値列（Schema 駆動）
// ---------------------------------------------------------------------------

fn write_value(out: &mut Vec<u8>, v: &TypedValue) {
    match v {
        TypedValue::I32(x) => write_sleb(out, *x as i64),
        TypedValue::I64(x) => write_sleb(out, *x),
        TypedValue::U32(x) => write_uleb(out, *x as u64),
        TypedValue::U64(x) => write_uleb(out, *x),
        TypedValue::F32Bits(b) => out.extend_from_slice(&b.to_le_bytes()),
        TypedValue::F64Bits(b) => out.extend_from_slice(&b.to_le_bytes()),
        TypedValue::Bool(b) => out.push(*b as u8),
        TypedValue::Str(s) => {
            write_uleb(out, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        TypedValue::Str16(units) => {
            write_uleb(out, units.len() as u64);
            for u in units {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        TypedValue::Bytes(b) => {
            write_uleb(out, b.len() as u64);
            out.extend_from_slice(b);
        }
        TypedValue::BlobRef(id) => out.extend_from_slice(id.as_bytes()),
        TypedValue::Ptr32(p) => out.extend_from_slice(&p.to_le_bytes()),
        TypedValue::Ptr64(p) => out.extend_from_slice(&p.to_le_bytes()),
    }
}

fn read_value(cur: &mut Cursor, ty: Ty) -> Result<TypedValue, CompactError> {
    Ok(match ty {
        Ty::I32 => TypedValue::I32(
            i32::try_from(cur.read_sleb()?).map_err(|_| CompactError::IntegerOutOfRange)?,
        ),
        Ty::I64 => TypedValue::I64(cur.read_sleb()?),
        Ty::U32 => TypedValue::U32(
            u32::try_from(cur.read_uleb()?).map_err(|_| CompactError::IntegerOutOfRange)?,
        ),
        Ty::U64 => TypedValue::U64(cur.read_uleb()?),
        Ty::F32 => {
            let b = cur.read_exact(4)?;
            TypedValue::F32Bits(u32::from_le_bytes(b.try_into().expect("4 bytes")))
        }
        Ty::F64 => {
            let b = cur.read_exact(8)?;
            TypedValue::F64Bits(u64::from_le_bytes(b.try_into().expect("8 bytes")))
        }
        Ty::Bool => {
            let b = cur.read_u8()?;
            match b {
                0 => TypedValue::Bool(false),
                1 => TypedValue::Bool(true),
                _ => return Err(CompactError::InvalidBool(b)),
            }
        }
        Ty::Str => {
            let b = cur.read_len_bytes()?;
            let s = std::str::from_utf8(b).map_err(|_| CompactError::InvalidUtf8)?;
            TypedValue::Str(s.to_string())
        }
        Ty::Str16 => {
            let n = cur.read_uleb()?;
            let n = usize::try_from(n).map_err(|_| CompactError::Truncated)?;
            let mut units = Vec::with_capacity(n.min(1 << 20));
            for _ in 0..n {
                let b = cur.read_exact(2)?;
                units.push(u16::from_le_bytes(b.try_into().expect("2 bytes")));
            }
            TypedValue::Str16(units)
        }
        Ty::Bytes => TypedValue::Bytes(cur.read_len_bytes()?.to_vec()),
        Ty::BlobRef => {
            let b = cur.read_exact(32)?;
            TypedValue::BlobRef(BlobId::from_bytes(b.try_into().expect("32 bytes")))
        }
        Ty::Ptr32 => {
            let b = cur.read_exact(4)?;
            TypedValue::Ptr32(u32::from_le_bytes(b.try_into().expect("4 bytes")))
        }
        Ty::Ptr64 => {
            let b = cur.read_exact(8)?;
            TypedValue::Ptr64(u64::from_le_bytes(b.try_into().expect("8 bytes")))
        }
    })
}

/// Schema の型列に従って値列を符号化する。値の個数と型は Schema と
/// 一致していなければならない。
pub fn encode_values(types: &[Ty], values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    encode_values_iter(types.iter().copied(), values)
}

/// Encode using an existing field table without constructing a Schema or
/// allocating a separate type vector on the recorder's hot path.
pub fn encode_values_iter(
    types: impl ExactSizeIterator<Item = Ty>,
    values: &[CapturedValue],
) -> Result<Vec<u8>, CompactError> {
    if types.len() != values.len() {
        return Err(CompactError::FieldCountMismatch {
            expected: types.len(),
            actual: values.len(),
        });
    }
    let mut out = Vec::new();
    for (i, (ty, v)) in types.zip(values.iter()).enumerate() {
        if v.value.ty() != ty {
            return Err(CompactError::TypeMismatch { field: i });
        }
        out.push(v.capture.code());
        write_value(&mut out, &v.value);
    }
    Ok(out)
}

/// 値列を復号する。末尾の余分なバイトは不正として拒否する。
pub fn decode_values(types: &[Ty], data: &[u8]) -> Result<Vec<CapturedValue>, CompactError> {
    let mut cur = Cursor::new(data);
    let mut out = Vec::with_capacity(types.len());
    for ty in types {
        let code = cur.read_u8()?;
        let capture = ValueCapture::from_code(code).ok_or(CompactError::InvalidCapture(code))?;
        let value = read_value(&mut cur, *ty)?;
        out.push(CapturedValue { capture, value });
    }
    if !cur.is_done() {
        return Err(CompactError::TrailingBytes(cur.remaining()));
    }
    Ok(out)
}

/// Validate an encoded value sequence without retaining decoded values or
/// allocating string/buffer storage. Acceptance matches `decode_values`.
pub fn validate_values(types: &[Ty], data: &[u8]) -> Result<(), CompactError> {
    let mut cur = Cursor::new(data);
    for ty in types {
        let code = cur.read_u8()?;
        ValueCapture::from_code(code).ok_or(CompactError::InvalidCapture(code))?;
        match ty {
            Ty::Str => {
                std::str::from_utf8(cur.read_len_bytes()?)
                    .map_err(|_| CompactError::InvalidUtf8)?;
            }
            Ty::Str16 => {
                let n = usize::try_from(cur.read_uleb()?).map_err(|_| CompactError::Truncated)?;
                let bytes = n.checked_mul(2).ok_or(CompactError::Truncated)?;
                cur.read_exact(bytes)?;
            }
            Ty::Bytes => {
                cur.read_len_bytes()?;
            }
            // Scalar decoding does not allocate and shares range/bool checks.
            _ => {
                read_value(&mut cur, *ty)?;
            }
        }
    }
    if !cur.is_done() {
        return Err(CompactError::TrailingBytes(cur.remaining()));
    }
    Ok(())
}

/// fuzz ターゲット `decode_compact` の入口：SchemaSet の Protobuf
/// バイト列と値列バイト列を受け、最初の Schema で値列を復号する。
/// どちらの入力が壊れていても panic せず Err を返す。
pub fn decode_compact(
    schema_set_bytes: &[u8],
    data: &[u8],
) -> Result<Vec<CapturedValue>, crate::error::TraceError> {
    let set = crate::proto::SchemaSet::decode(schema_set_bytes)?;
    let first = set
        .schemas
        .first()
        .ok_or_else(|| crate::error::TraceError::InvalidInput("schema set is empty".into()))?;
    let types = crate::schema::schema_types(first).ok_or_else(|| {
        crate::error::TraceError::InvalidInput("schema contains unknown type tag".into())
    })?;
    Ok(decode_values(&types, data)?)
}

// ---------------------------------------------------------------------------
// イベント列（Event Chunk の payload）
// ---------------------------------------------------------------------------

/// 1 イベント分のフィールド列を書く（seq / ts は呼び出し側が差分を渡す）。
/// `encode_event_chunk` と、Writer のチャンク分割サイズ見積もりで共有する。
/// `global_delta` は Batch の `has_global_order` が真の場合にだけ Some
/// （先頭イベントは絶対値、2 件目以降は前件からの差分。同一 Batch 内では
/// global_order が厳密に増加するため差分は 1 以上）。
pub fn encode_event_fields(
    out: &mut Vec<u8>,
    e: &TraceEvent,
    seq_delta: u64,
    ts_delta: i64,
    global_delta: Option<u64>,
) {
    write_uleb(out, seq_delta);
    write_sleb(out, ts_delta);
    write_uleb(out, e.kind as u64);
    write_uleb(out, e.call_id);
    write_uleb(out, e.parent_call_id);
    write_uleb(out, e.api_id as u64);
    write_uleb(out, e.schema_id as u64);
    out.push(e.capture.code());
    match &e.payload {
        PayloadRef::None => out.push(0),
        PayloadRef::Blob(id) => {
            out.push(1);
            out.extend_from_slice(id.as_bytes());
        }
        PayloadRef::Inline(bytes) => {
            out.push(2);
            write_uleb(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        PayloadRef::Dropped {
            original_len,
            reason,
        } => {
            out.push(3);
            write_uleb(out, *original_len);
            out.push(reason.code());
        }
    }
    match &e.args {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            write_uleb(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
    }
    // L11: 全体順序は args の後に ULEB128 で 1 個だけ書く。BatchHeader の
    // has_global_order が真の場合にのみ存在する（旧ファイルには無い）。
    if let Some(delta) = global_delta {
        write_uleb(out, delta);
    }
}

/// Event Chunk の payload を作る：BatchHeader 長（LEB128）＋
/// BatchHeader（Protobuf）＋ Compact イベント列。
/// sequence は Batch 内で単調非減少である前提（減少する入力では
/// 差分が巨大な値になり、復号側が overflow として拒否する。
/// 呼び出し側は Writer 経由で使うこと。Writer が事前に検証する）。
/// global_order は Batch 内で全件 Some なら Header に旗を立てて差分で
/// 書く（先頭は絶対値）。混在は Writer が拒否するためここでは来ない。
pub fn encode_event_chunk(batch: &EventBatch) -> Vec<u8> {
    encode_event_chunk_slice(batch, &batch.events)
}

/// Encode a chunk using batch identity and borrowed events, without copying
/// every event's argument/payload buffers just to split a batch.
pub(crate) fn encode_event_chunk_slice(batch: &EventBatch, events: &[TraceEvent]) -> Vec<u8> {
    let first_sequence = events.first().map_or(0, |e| e.sequence);
    let base_timestamp_qpc = events.first().map_or(0, |e| e.timestamp_qpc);
    let has_global_order = events.iter().any(|e| e.global_order.is_some());
    let header = BatchHeader {
        session_id: batch.session_id,
        process_id: batch.process_id,
        raw_pid: batch.raw_pid,
        thread_id: batch.thread_id,
        base_timestamp_qpc,
        qpc_frequency: batch.qpc_frequency,
        first_sequence,
        event_count: events.len() as u32,
        has_global_order,
    };
    let header_bytes = header.encode();
    let mut out = Vec::new();
    write_uleb(&mut out, header_bytes.len() as u64);
    out.extend_from_slice(&header_bytes);
    let mut prev_seq = first_sequence;
    let mut prev_ts = base_timestamp_qpc;
    let mut prev_global: Option<u64> = None;
    for e in events {
        let seq_delta = e.sequence.wrapping_sub(prev_seq);
        prev_seq = e.sequence;
        let ts_delta = e.timestamp_qpc.wrapping_sub(prev_ts) as i64;
        prev_ts = e.timestamp_qpc;
        let global_delta = if has_global_order {
            let g = e.global_order.unwrap_or(0);
            let d = match prev_global {
                None => g,
                Some(p) => g.wrapping_sub(p),
            };
            prev_global = Some(g);
            Some(d)
        } else {
            None
        };
        encode_event_fields(&mut out, e, seq_delta, ts_delta, global_delta);
    }
    out
}

/// Event Chunk の payload を復号する。宣言された event_count と
/// 実際に読めた個数が一致しない、sequence が減少する、末尾に
/// 余分なバイトがある場合は破損として Err を返す。
pub fn decode_event_chunk(payload: &[u8]) -> Result<EventBatch, crate::error::TraceError> {
    let corrupt = |reason: &str| crate::error::TraceError::CorruptBlock {
        offset: 0,
        reason: reason.into(),
    };
    let mut cur = Cursor::new(payload);
    let header_len = cur
        .read_uleb()
        .map_err(|_| corrupt("missing batch header length"))?;
    let header_len = usize::try_from(header_len).map_err(|_| corrupt("batch header too long"))?;
    let header_bytes = cur
        .read_exact(header_len)
        .map_err(|_| corrupt("batch header truncated"))?;
    let header = BatchHeader::decode(header_bytes)?;
    let mut events = Vec::with_capacity((header.event_count as usize).min(1 << 20));
    let mut prev_seq = header.first_sequence;
    let mut prev_ts = header.base_timestamp_qpc;
    let mut prev_global: Option<u64> = None;
    for _ in 0..header.event_count {
        let seq_delta = cur.read_uleb().map_err(|_| corrupt("event truncated"))?;
        let sequence = prev_seq
            .checked_add(seq_delta)
            .ok_or_else(|| corrupt("sequence overflow"))?;
        // seq_delta は符号なしなので sequence は自動的に単調非減少になる。
        prev_seq = sequence;
        let ts_delta = cur.read_sleb().map_err(|_| corrupt("event truncated"))?;
        let timestamp_qpc = prev_ts.wrapping_add(ts_delta as u64);
        prev_ts = timestamp_qpc;
        let kind = u16::try_from(cur.read_uleb().map_err(|_| corrupt("event truncated"))?)
            .map_err(|_| corrupt("kind overflow"))?;
        let call_id = cur.read_uleb().map_err(|_| corrupt("event truncated"))?;
        let parent_call_id = cur.read_uleb().map_err(|_| corrupt("event truncated"))?;
        let api_id = u32::try_from(cur.read_uleb().map_err(|_| corrupt("event truncated"))?)
            .map_err(|_| corrupt("api_id overflow"))?;
        let schema_id = u32::try_from(cur.read_uleb().map_err(|_| corrupt("event truncated"))?)
            .map_err(|_| corrupt("schema_id overflow"))?;
        let capture = EventCapture::from_code(cur.read_u8().map_err(|_| corrupt("truncated"))?);
        let payload_tag = cur.read_u8().map_err(|_| corrupt("event truncated"))?;
        let payload = match payload_tag {
            0 => PayloadRef::None,
            1 => {
                let b = cur
                    .read_exact(32)
                    .map_err(|_| corrupt("blob ref truncated"))?;
                PayloadRef::Blob(BlobId::from_bytes(b.try_into().expect("32 bytes")))
            }
            2 => {
                let b = cur
                    .read_len_bytes()
                    .map_err(|_| corrupt("inline payload truncated"))?;
                PayloadRef::Inline(b.to_vec())
            }
            3 => {
                let original_len = cur
                    .read_uleb()
                    .map_err(|_| corrupt("dropped payload truncated"))?;
                let reason =
                    PayloadLossReason::from_code(cur.read_u8().map_err(|_| corrupt("truncated"))?);
                PayloadRef::Dropped {
                    original_len,
                    reason,
                }
            }
            t => return Err(corrupt(&format!("unknown payload tag {t}"))),
        };
        let args_tag = cur.read_u8().map_err(|_| corrupt("event truncated"))?;
        let args = match args_tag {
            0 => None,
            1 => Some(
                cur.read_len_bytes()
                    .map_err(|_| corrupt("args truncated"))?
                    .to_vec(),
            ),
            t => return Err(corrupt(&format!("unknown args tag {t}"))),
        };
        // L11: has_global_order の場合のみ、args の後に全体順序の差分が
        // 1 個ある。先頭は絶対値（0 は未割当のはずなので破損）、2 件目
        // 以降は前件からの差分（同一 Batch 内で厳密に増加するため 1 以上。
        // 0 は破損）。旗が無ければ None（旧ファイルとの互換）。
        let global_order = if header.has_global_order {
            let delta = cur.read_uleb().map_err(|_| corrupt("event truncated"))?;
            let g = match prev_global {
                None => {
                    if delta == 0 {
                        return Err(corrupt("global order 0 in first event"));
                    }
                    delta
                }
                Some(p) => {
                    if delta == 0 {
                        return Err(corrupt("global order not increasing"));
                    }
                    p.checked_add(delta)
                        .ok_or_else(|| corrupt("global order overflow"))?
                }
            };
            prev_global = Some(g);
            Some(g)
        } else {
            None
        };
        events.push(TraceEvent {
            kind,
            sequence,
            timestamp_qpc,
            call_id,
            parent_call_id,
            api_id,
            schema_id,
            capture,
            payload,
            args,
            global_order,
        });
    }
    if !cur.is_done() {
        return Err(corrupt("trailing bytes after events"));
    }
    Ok(EventBatch {
        session_id: header.session_id,
        process_id: header.process_id,
        raw_pid: header.raw_pid,
        thread_id: header.thread_id,
        qpc_frequency: header.qpc_frequency,
        events,
    })
}

#[cfg(test)]
mod integer_bounds_tests {
    use super::*;

    #[test]
    fn rejects_narrow_integer_overflow() {
        let mut bytes = Vec::new();
        write_uleb(&mut bytes, u32::MAX as u64 + 1);
        assert!(matches!(
            read_value(&mut Cursor::new(&bytes), Ty::U32),
            Err(CompactError::IntegerOutOfRange)
        ));
        for value in [i32::MIN as i64 - 1, i32::MAX as i64 + 1] {
            bytes.clear();
            write_sleb(&mut bytes, value);
            assert!(matches!(
                read_value(&mut Cursor::new(&bytes), Ty::I32),
                Err(CompactError::IntegerOutOfRange)
            ));
        }
        for value in [i32::MIN, i32::MAX] {
            bytes.clear();
            write_sleb(&mut bytes, value as i64);
            assert_eq!(
                read_value(&mut Cursor::new(&bytes), Ty::I32).unwrap(),
                TypedValue::I32(value)
            );
        }
    }
}
