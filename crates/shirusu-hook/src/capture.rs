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
//!   書き込んだ後（after）に取得する。取得タイミングは Schema の
//!   `CaptureTiming` として引数ごとに宣言され（F19）、enter Schema の
//!   フィールドは Before、leave Schema のフィールドは After を持つ。
//!   非同期 I/O の完了時取得は `Completion` と宣言されるが、完了を捕捉
//!   する仕組みは別途必要になる（F27）。
//! - GetLastError の生値は、API の意味条件（Schema の
//!   `LastErrorMeaning`。戻り値が失敗を示す場合等）を満たす場合に
//!   だけ「その呼び出しのエラー値」として意味を持つ。満たさない生値は
//!   古い残留値のため `ValueCapture::Stale` として記録する（値本体は
//!   生値を保持する。F20）。

use crate::api::ApiDef;
use shirusu_trace::compact::encode_values_iter;
use shirusu_trace::schema::{CapturedValue, LastErrorMeaning, Ty, TypedValue, ValueCapture};
use shirusu_trace::CompactError;

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
pub fn i64v(v: i64) -> CapturedValue {
    CapturedValue::captured(TypedValue::I64(v))
}
pub fn boolv(v: bool) -> CapturedValue {
    CapturedValue::captured(TypedValue::Bool(v))
}

/// UTF-16 文字列（NUL 終端）を Str16 値として取得する。
/// NULL ポインタは「読めない」と区別するため Unreadable として記録する
/// （overview: 読めなかった値を NULL として保存しない）。
pub fn read_utf16_string(mem: &dyn MemoryReader, addr: u64) -> CapturedValue {
    if addr == 0 {
        return cap(TypedValue::Str16(Vec::new()), ValueCapture::Unreadable);
    }
    let mut units: Vec<u16> = Vec::new();
    // ページ境界までをまとめて読む（レビュー 2026-11-14 P2-5: 以前は
    // 64 バイトずつで、260 文字のパスに 9 回の ReadProcessMemory を
    // 要した）。1 ページの中は読めるか読めないかのどちらかなので、
    // 境界を越えない限りまとめて読んでも前半を失わない。
    let mut buf = [0u8; STRING_READ_CHUNK];
    loop {
        let chunk_addr = addr + (units.len() as u64) * 2;
        let to_page_end = PAGE_SIZE - (chunk_addr % PAGE_SIZE);
        // 奇数アドレスでページ末尾に 1 バイトだけ残る場合は 1 unit を読む。
        let len = ((to_page_end as usize).min(STRING_READ_CHUNK) & !1).max(2);
        let block = &mut buf[..len];
        if mem.read_exact(chunk_addr, block) {
            for pair in block.chunks_exact(2) {
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
        // ブロック全体が読めない場合は 1 unit ずつ救済する（読み手が
        // ページ単位でない場合や、終端 NUL の直後が未マップなケースで、
        // 前半の文字列を失わないため）。
        let mut salvaged_any = false;
        for i in 0..(len as u64 / 2) {
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

/// 文字列を読むときの 1 回の最大バイト数と、境界とみなすページの大きさ。
const STRING_READ_CHUNK: usize = 1024;
const PAGE_SIZE: u64 = 4096;

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

/// GetLastError の生値を、API の意味条件と戻り値で分類して記録する
/// （F20）。条件を満たせば生値を Captured として記録し、満たさな
/// ければ生値は古い残留値のため `ValueCapture::Stale` として記録する。
/// Stale でも値本体は生値を保持する（再検証のため）。`return_value` は
/// leave Schema の `return` フィールドの生値（HANDLE は U64、BOOL は
/// I32 の生値を u64 へ写したもの）。
pub fn last_error_value(meaning: LastErrorMeaning, return_value: u64, raw: u32) -> CapturedValue {
    if meaning == LastErrorMeaning::DependsOnInputs {
        // This return-only helper cannot evaluate an input-dependent contract.
        // Preserve the raw value without claiming its meaning was captured.
        return cap(TypedValue::U32(raw), ValueCapture::Unsupported);
    }
    if meaning.is_meaningful(return_value) {
        u32v(raw)
    } else {
        cap(TypedValue::U32(raw), ValueCapture::Stale)
    }
}

// The finite capture operations below are selected by the semantic contract.
// Keep raw memory access behind MemoryReader and existing bounded readers.
fn read_io_count(mem: &dyn MemoryReader, address: u64, asynchronous: bool) -> CapturedValue {
    if asynchronous || address == 0 {
        return unsupported_u32();
    }
    mem.read_u32(address)
        .map(u32v)
        .unwrap_or_else(unsupported_u32)
}

fn read_io_output(
    mem: &dyn MemoryReader,
    success: i32,
    buffer: u64,
    capacity: u32,
    count: &CapturedValue,
    asynchronous: bool,
) -> CapturedValue {
    if asynchronous {
        return unsupported_bytes();
    }
    let CapturedValue {
        capture: ValueCapture::Captured,
        value: TypedValue::U32(count),
    } = count
    else {
        return unsupported_bytes();
    };
    if success == 0 {
        return CapturedValue::captured(TypedValue::Bytes(Vec::new()));
    }
    read_output_buffer(mem, buffer, capacity, *count)
}

include!("capture_file_io_generated.inc");

/// OVERLAPPED 操作の転送バイト数を、完了を観測した時点で読む
/// （F27）。`bytes_addr`（lpNumberOfBytesTransferred 等）が非 NULL
/// ならそこから、NULL なら OVERLAPPED.InternalHigh から読む。どちらも
/// 読めなければ None（完了イベントは記録できない）。
pub fn read_overlapped_transferred(
    mem: &dyn MemoryReader,
    bytes_addr: u64,
    overlapped_addr: u64,
) -> Option<u32> {
    read_overlapped_transferred_with_width(mem, bytes_addr, overlapped_addr, size_of::<usize>())
}

/// ポインタ幅を指定する版（レビュー #6 P0-2）。InternalHigh の
/// レイアウトは対象のポインタ幅で決まるため、幅の異なる対象の
/// Fixture でも検証できるよう分離してある。
pub fn read_overlapped_transferred_with_width(
    mem: &dyn MemoryReader,
    bytes_addr: u64,
    overlapped_addr: u64,
    pointer_width: usize,
) -> Option<u32> {
    if bytes_addr != 0 {
        if let Some(n) = mem.read_u32(bytes_addr) {
            return Some(n);
        }
    }
    read_overlapped_internal_high_with_width(mem, overlapped_addr, pointer_width)
        .and_then(|n| u32::try_from(n).ok())
}

pub fn get_overlapped_result_enter(file: u64, overlapped: u64, wait: i32) -> Vec<CapturedValue> {
    vec![u64v(file), u64v(overlapped), i32v(wait)]
}

/// GetOverlappedResult の leave。転送バイト数が読めなければ
/// Unsupported（完了イベントの記録も同じ理由でできない）。
pub fn get_overlapped_result_leave(
    success: i32,
    transferred: Option<u32>,
    last_error: u32,
) -> Vec<CapturedValue> {
    vec![
        i32v(success),
        match transferred {
            Some(n) => u32v(n),
            None => unsupported_u32(),
        },
        last_error_value(
            LastErrorMeaning::WhenReturnIsFalse,
            success as u64,
            last_error,
        ),
    ]
}

pub fn get_queued_completion_status_enter(
    port: u64,
    bytes_transferred: u64,
    completion_key: u64,
    overlapped: u64,
    milliseconds: u32,
) -> Vec<CapturedValue> {
    vec![
        u64v(port),
        u64v(bytes_transferred),
        u64v(completion_key),
        u64v(overlapped),
        u32v(milliseconds),
    ]
}

/// GetQueuedCompletionStatus の leave。転送バイト数が読めなければ
/// Unsupported。
pub fn get_queued_completion_status_leave(
    success: i32,
    transferred: Option<u32>,
    last_error: u32,
) -> Vec<CapturedValue> {
    vec![
        i32v(success),
        match transferred {
            Some(n) => u32v(n),
            None => unsupported_u32(),
        },
        last_error_value(
            LastErrorMeaning::WhenReturnIsFalse,
            success as u64,
            last_error,
        ),
    ]
}

/// Win32 の非同期 I/O 完了関連のエラー値（F27）。
/// `ERROR_IO_PENDING` (997): 操作は開始したがまだ完了していない。
/// `ERROR_IO_INCOMPLETE` (996): GetOverlappedResult で未完了。
pub const ERROR_IO_PENDING: u32 = 997;
pub const ERROR_IO_INCOMPLETE: u32 = 996;

/// OVERLAPPED.InternalHigh（転送済みバイト数）の先頭からのオフセット。
///
/// OVERLAPPED = { Internal: ULONG_PTR, InternalHigh: ULONG_PTR, Offset,
/// OffsetHigh, hEvent } で、InternalHigh は 2 番目のフィールドである。
/// オフセットと読み取り幅はどちらもポインタ幅に等しい: x64 では 8、
/// x86 では 4。旧実装は 8 固定であり、x86 ではオフセット 8 以降の
/// Offset フィールド（ファイル位置）を転送バイト数として誤読して
/// いた（レビュー #6 P0-2）。
pub fn overlapped_internal_high_offset(pointer_width: usize) -> u64 {
    pointer_width as u64
}

/// 完了待ちの非同期 I/O 操作（F27）。ReadFile / WriteFile の Detour が
/// OVERLAPPED 指定で ERROR_IO_PENDING を返したときに登録し、完了の
/// 観測（GetOverlappedResult / GetQueuedCompletionStatus）で取り出す。
/// 完了は別スレッドで観測されることがある（IOCP）ため、登録表は
/// プロセス全体で共有する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlappedDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingOverlapped {
    /// 元の呼び出しの API（ReadFile / WriteFile）。
    pub api_id: u32,
    /// 元の呼び出しの call_id。完了イベントは同じ call_id で記録する。
    pub call_id: u64,
    pub handle: u64,
    /// 入出力バッファのアドレス。
    pub buffer: u64,
    pub requested_len: u32,
    pub direction: OverlappedDirection,
    /// lpNumberOfBytesRead / lpNumberOfBytesWritten のアドレス（0 なら NULL）。
    pub bytes_addr: u64,
}

/// 完了待ちの非同期 I/O 操作の登録表（F27）。鍵は OVERLAPPED 構造体
/// のアドレス。同じ構造体で完了前に再登録された場合は古い方を上書き
/// する（Win32 は完了前の構造体再利用を禁じているため、古い操作の
/// 完了は以後対応付けできない）。
///
/// 照合はアドレスに加え、提出時の Offset／hEvent と（分かれば）ハンドル
/// でも行う（レビュー 2026-11-14 P2-7）。Detour の無い経路
/// （GetQueuedCompletionStatusEx、スレッドプール I/O、イベント待ち）で
/// 完了した登録は残り、同じアドレスが別の操作に再利用されると古い
/// call_id の完了として誤記録していた。登録は
/// [`MAX_PENDING_OVERLAPPED`] 件までとし、越えたら古い半分を捨てる。
#[derive(Debug, Default, Clone)]
pub struct OverlappedRegistry {
    pending: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, PendingEntry>>>,
}

/// 保持する完了待ちの登録の上限。
pub const MAX_PENDING_OVERLAPPED: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct PendingEntry {
    op: PendingOverlapped,
    signature: Option<OverlappedSignature>,
}

/// 提出時の OVERLAPPED の内容のうち、I/O の間カーネルが書き換えない
/// もの（Offset／OffsetHigh と hEvent）。構造体が別の操作に再利用された
/// ことを見分けるのに使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlappedSignature {
    pub offset: u64,
    pub event: u64,
}

/// [`OverlappedSignature`] を読む。読めなければ None。
pub fn read_overlapped_signature(
    mem: &dyn MemoryReader,
    overlapped_addr: u64,
) -> Option<OverlappedSignature> {
    read_overlapped_signature_with_width(mem, overlapped_addr, size_of::<usize>())
}

/// ポインタ幅を指定する版。Offset は Internal と InternalHigh の後
/// (2 × 幅)、hEvent はその 8 バイト後に置かれる。
pub fn read_overlapped_signature_with_width(
    mem: &dyn MemoryReader,
    overlapped_addr: u64,
    pointer_width: usize,
) -> Option<OverlappedSignature> {
    if overlapped_addr == 0 || !matches!(pointer_width, 4 | 8) {
        return None;
    }
    let at = overlapped_addr + 2 * pointer_width as u64;
    let mut b = [0u8; 16];
    let len = 8 + pointer_width;
    if !mem.read_exact(at, &mut b[..len]) {
        return None;
    }
    let mut event = [0u8; 8];
    event[..pointer_width].copy_from_slice(&b[8..len]);
    Some(OverlappedSignature {
        offset: u64::from_le_bytes(b[..8].try_into().unwrap()),
        event: u64::from_le_bytes(event),
    })
}

/// A provisional registration is cancelled on unwind as well as synchronous
/// failure. Cancellation is generation checked so an early completion may reuse
/// the address while the original submitter is still unwinding/returning.
pub struct PendingSubmission {
    /// None for a synchronous call (no OVERLAPPED): nothing was registered,
    /// so dropping it touches no shared state (review 2026-11-14 P2-5).
    registry: Option<OverlappedRegistry>,
    address: u64,
    call_id: u64,
    keep: bool,
}
impl PendingSubmission {
    pub fn finish(mut self, pending: bool) {
        self.keep = pending;
    }
}
impl Drop for PendingSubmission {
    fn drop(&mut self) {
        if let (false, Some(registry)) = (self.keep, &self.registry) {
            registry.cancel(self.address, self.call_id);
        }
    }
}

impl OverlappedRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn submit(&self, address: u64, pending: PendingOverlapped) -> PendingSubmission {
        self.submit_signed(address, pending, None)
    }
    /// [`Self::submit`] with the OVERLAPPED contents seen at submission.
    pub fn submit_signed(
        &self,
        address: u64,
        pending: PendingOverlapped,
        signature: Option<OverlappedSignature>,
    ) -> PendingSubmission {
        self.register_signed(address, pending, signature);
        PendingSubmission {
            registry: (address != 0).then(|| self.clone()),
            address,
            call_id: pending.call_id,
            keep: false,
        }
    }
    pub fn register(&self, overlapped_addr: u64, pending: PendingOverlapped) {
        self.register_signed(overlapped_addr, pending, None);
    }
    fn register_signed(
        &self,
        overlapped_addr: u64,
        op: PendingOverlapped,
        signature: Option<OverlappedSignature>,
    ) {
        if overlapped_addr == 0 {
            return;
        }
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING_OVERLAPPED && !pending.contains_key(&overlapped_addr) {
            // Completed through a path without a Detour: drop the oldest.
            let mut ids: Vec<u64> = pending.values().map(|e| e.op.call_id).collect();
            ids.sort_unstable();
            let cutoff = ids[ids.len() / 2];
            pending.retain(|_, e| e.op.call_id >= cutoff);
        }
        pending.insert(overlapped_addr, PendingEntry { op, signature });
    }
    /// Remove only this operation, never a newer reuse of the same address.
    pub fn cancel(&self, address: u64, call_id: u64) {
        if address == 0 {
            return;
        }
        let mut pending = self.pending.lock().unwrap();
        if pending
            .get(&address)
            .is_some_and(|p| p.op.call_id == call_id)
        {
            pending.remove(&address);
        }
    }
    pub fn take(&self, overlapped_addr: u64) -> Option<PendingOverlapped> {
        self.pending
            .lock()
            .unwrap()
            .remove(&overlapped_addr)
            .map(|e| e.op)
    }
    /// Take the registration at `overlapped_addr` and return it only if it
    /// is still the same operation: the handle (when the completion API
    /// names one) and the OVERLAPPED contents recorded at submission must
    /// match. A mismatching registration is stale and is dropped.
    pub fn take_matching(
        &self,
        overlapped_addr: u64,
        handle: Option<u64>,
        signature: Option<OverlappedSignature>,
    ) -> Option<PendingOverlapped> {
        let entry = self.pending.lock().unwrap().remove(&overlapped_addr)?;
        if handle.is_some_and(|h| h != entry.op.handle) {
            return None;
        }
        if let (Some(then), Some(now)) = (entry.signature, signature) {
            if then != now {
                return None;
            }
        }
        Some(entry.op)
    }
    pub fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// OVERLAPPED.InternalHigh（転送済みバイト数）を読む。同期完了した
/// 操作は leave 時点で既に値が入っている。読めなければ None。
/// レイアウトは自プロセスのポインタ幅（`size_of::<usize>()`）で決める。
pub fn read_overlapped_internal_high(mem: &dyn MemoryReader, overlapped_addr: u64) -> Option<u64> {
    read_overlapped_internal_high_with_width(mem, overlapped_addr, size_of::<usize>())
}

/// ポインタ幅を指定する版（レビュー #6 P0-2）。オフセット = 幅 =
/// `pointer_width` で読み、値は u64 へゼロ拡張する。幅として受理
/// するのは 4 (x86) と 8 (x64) だけであり、それ以外は None。
pub fn read_overlapped_internal_high_with_width(
    mem: &dyn MemoryReader,
    overlapped_addr: u64,
    pointer_width: usize,
) -> Option<u64> {
    if overlapped_addr == 0 || !matches!(pointer_width, 4 | 8) {
        return None;
    }
    let mut b = [0u8; 8];
    if mem.read_exact(
        overlapped_addr + overlapped_internal_high_offset(pointer_width),
        &mut b[..pointer_width],
    ) {
        Some(u64::from_le_bytes(b))
    } else {
        None
    }
}

/// The completion count is observed memory, not authority to read beyond the
/// application's original buffer. Preserve the raw count separately and refuse
/// data capture when its relationship to the requested capacity is invalid.
fn read_output_buffer(
    mem: &dyn MemoryReader,
    buffer: u64,
    requested: u32,
    transferred: u32,
) -> CapturedValue {
    if transferred > requested {
        unsupported_bytes()
    } else {
        read_buffer(mem, buffer, transferred as usize)
    }
}

/// 完了時の ReadFile leave 値列（F27）。leave Schema と同じフィールド順
/// （return / lpNumberOfBytesRead / data / last_error）で、完了時点の
/// 転送バイト数とバッファ内容を取る。失敗時は同期 leave と同じく
/// バイト数は Unsupported、データは空として記録する。
pub fn complete_read_file_leave(
    mem: &dyn MemoryReader,
    buffer: u64,
    requested_len: u32,
    transferred: u32,
    success: bool,
    last_error: u32,
) -> Vec<CapturedValue> {
    let success_i32 = if success { 1 } else { 0 };
    if success {
        vec![
            i32v(success_i32),
            u32v(transferred),
            read_output_buffer(mem, buffer, requested_len, transferred),
            last_error_value(
                LastErrorMeaning::WhenReturnIsFalse,
                success_i32 as u64,
                last_error,
            ),
        ]
    } else {
        vec![
            i32v(success_i32),
            unsupported_u32(),
            CapturedValue::captured(TypedValue::Bytes(Vec::new())),
            last_error_value(
                LastErrorMeaning::WhenReturnIsFalse,
                success_i32 as u64,
                last_error,
            ),
        ]
    }
}

/// 完了時の WriteFile leave 値列（F27）。leave Schema と同じフィールド順
/// （return / lpNumberOfBytesWritten / last_error）。
pub fn complete_write_file_leave(
    transferred: u32,
    success: bool,
    last_error: u32,
) -> Vec<CapturedValue> {
    let success_i32 = if success { 1 } else { 0 };
    vec![
        i32v(success_i32),
        if success {
            u32v(transferred)
        } else {
            unsupported_u32()
        },
        last_error_value(
            LastErrorMeaning::WhenReturnIsFalse,
            success_i32 as u64,
            last_error,
        ),
    ]
}

/// 取得した値列を、その API の Schema で Compact Binary へ符号化する。
/// 転送 Payload として運び、Host 変換で TraceEvent.args へ写す。
pub fn encode_enter(api: &ApiDef, values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    encode_values_iter(api.enter_fields.iter().map(|field| field.1), values)
}
pub fn encode_leave(api: &ApiDef, values: &[CapturedValue]) -> Result<Vec<u8>, CompactError> {
    encode_values_iter(api.leave_fields.iter().map(|field| field.1), values)
}

/// L1 生成 API（L03）の汎用取得。生の引数値（usize を u64 へ写した
/// もの）を、その API の enter Schema の型に沿って値列へ変換する。
///
/// 生成表は整数・ポインタ型だけを使う（U32 / I32 / U64 / I64 / Bool）。
/// 文字列・バッファの中身、構造体の参照先は L1 では取得しない
/// （ポインタ値だけを記録する。L2 で手書き仕様により拡張する）。
/// 対応外の型が表に現れたら panic する：生成表はコンパイル時に固定
/// され、テストで型の制限を検査するためである（encode_enter の
/// expect と同じ方針）。
pub fn generic_enter(api: &ApiDef, args: &[u64]) -> Vec<CapturedValue> {
    assert_eq!(
        args.len(),
        api.enter_fields.len(),
        "{}: generic detour arity mismatch (args {} vs fields {})",
        api.function,
        args.len(),
        api.enter_fields.len()
    );
    api.enter_fields
        .iter()
        .zip(args.iter())
        .map(|((name, ty, _, _), raw)| raw_to_value(api.function, name, *ty, *raw))
        .collect()
}

/// L1 生成 API（L03）の汎用 leave 取得。leave Schema の `return`
/// フィールドを戻り値の生値から、`last_error` フィールドを
/// `last_error_value`（F20 の意味条件）で作る。void 戻りの API は
/// `return` フィールドを持たず `last_error` だけになる。
pub fn generic_leave(api: &ApiDef, return_value: u64, last_error: u32) -> Vec<CapturedValue> {
    let meaning = generic_last_error_meaning(api, return_value, last_error, &[]);
    api.leave_fields
        .iter()
        .map(|(name, ty, _, _)| match *name {
            "return" => raw_to_value(api.function, name, *ty, return_value),
            "last_error" => last_error_value(meaning, return_value, last_error),
            other => panic!(
                "{}: unexpected leave field {other} in generated table",
                api.function
            ),
        })
        .collect()
}

/// Stack storage for generated L1 scalar fields. Each field needs at most one
/// capture byte plus ten LEB128 bytes. This has no allocator or destructor.
pub struct GenericPayload<const FIELDS: usize> {
    bytes: [[u8; 11]; FIELDS],
    len: usize,
}

impl<const FIELDS: usize> GenericPayload<FIELDS> {
    fn new() -> Self {
        Self {
            bytes: [[0; 11]; FIELDS],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_flattened()[..self.len]
    }

    #[cfg(test)]
    fn byte(&mut self, byte: u8) {
        self.bytes.as_flattened_mut()[self.len] = byte;
        self.len += 1;
    }

    #[cfg(test)]
    fn uleb(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            self.byte(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                break;
            }
        }
    }

    /// Encode a raw generated-table scalar exactly as `scalar(raw_to_value(..))`
    /// would, without building the intermediate `CapturedValue`. A field takes
    /// at most 11 bytes (state + 10-byte ULEB), so it is written into one
    /// fixed window: one bounds check per field instead of one per byte.
    #[inline(always)]
    fn raw_scalar(&mut self, capture: ValueCapture, function: &str, name: &str, ty: Ty, raw: u64) {
        let start = self.len;
        let window: &mut [u8; 11] = (&mut self.bytes.as_flattened_mut()[start..start + 11])
            .try_into()
            .expect("field window");
        window[0] = capture.code();
        let n = match ty {
            Ty::U32 => write_uleb(window, raw as u32 as u64),
            Ty::U64 => write_uleb(window, raw),
            Ty::I32 => {
                let v = raw as i32 as i64;
                write_uleb(window, ((v << 1) ^ (v >> 63)) as u64)
            }
            Ty::I64 => {
                let v = raw as i64;
                write_uleb(window, ((v << 1) ^ (v >> 63)) as u64)
            }
            Ty::Bool => {
                window[1] = (raw != 0) as u8;
                1
            }
            Ty::F32 => {
                window[1..5].copy_from_slice(&(raw as u32).to_le_bytes());
                4
            }
            Ty::F64 => {
                window[1..9].copy_from_slice(&raw.to_le_bytes());
                8
            }
            other => {
                panic!(
                    "{function}: field {name} uses unsupported Ty {other:?} for generic L1 capture"
                )
            }
        };
        self.len = start + 1 + n;
    }

    #[cfg(test)]
    fn scalar(&mut self, value: CapturedValue) {
        self.byte(value.capture.code());
        match value.value {
            TypedValue::U32(v) => self.uleb(v as u64),
            TypedValue::U64(v) => self.uleb(v),
            TypedValue::I32(v) => {
                let v = v as i64;
                self.uleb(((v << 1) ^ (v >> 63)) as u64);
            }
            TypedValue::I64(v) => self.uleb(((v << 1) ^ (v >> 63)) as u64),
            TypedValue::Bool(v) => self.byte(v as u8),
            TypedValue::F32Bits(v) => {
                for byte in v.to_le_bytes() {
                    self.byte(byte);
                }
            }
            TypedValue::F64Bits(v) => {
                for byte in v.to_le_bytes() {
                    self.byte(byte);
                }
            }
            _ => unreachable!("generated L1 capture only produces scalar values"),
        }
    }
}

/// ULEB128 of `value` into `window[1..]`; returns its length (1..=10).
#[inline(always)]
fn write_uleb(window: &mut [u8; 11], mut value: u64) -> usize {
    if value < 0x80 {
        window[1] = value as u8;
        return 1;
    }
    let mut i = 1;
    while value >= 0x80 && i < 10 {
        window[i] = (value as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    window[i] = value as u8;
    i
}

/// Encode generated arguments directly into bounded stack storage.
/// FIELDS must cover every argument; the generated wrapper uses its exact arity.
pub fn encode_generic_enter<const FIELDS: usize>(
    api: &ApiDef,
    args: &[u64],
) -> GenericPayload<FIELDS> {
    assert_eq!(
        args.len(),
        api.enter_fields.len(),
        "generated detour arity mismatch"
    );
    assert!(args.len() <= FIELDS, "generated payload capacity exceeded");
    let mut payload = GenericPayload::new();
    for ((name, ty, _, _), raw) in api.enter_fields.iter().zip(args) {
        payload.raw_scalar(ValueCapture::Captured, api.function, name, *ty, *raw);
    }
    payload
}

/// Encode the optional return value and LastError without heap allocation.
pub fn encode_generic_leave(api: &ApiDef, return_value: u64, last_error: u32) -> GenericPayload<2> {
    encode_generic_leave_with_inputs(api, return_value, last_error, &[])
}

/// Resolve supported input-dependent error semantics from the original scalar
/// arguments. Missing context stays Unsupported, retaining the raw error value.
pub fn encode_generic_leave_with_inputs(
    api: &ApiDef,
    return_value: u64,
    last_error: u32,
    args: &[u64],
) -> GenericPayload<2> {
    let meaning = generic_last_error_meaning(api, return_value, last_error, args);
    assert!(
        api.leave_fields.len() <= 2,
        "generated leave capacity exceeded"
    );
    let mut payload = GenericPayload::new();
    for (name, ty, _, _) in api.leave_fields {
        match *name {
            "return" => payload.raw_scalar(
                ValueCapture::Captured,
                api.function,
                name,
                *ty,
                return_value,
            ),
            // Same capture state as `last_error_value`, always a U32 value.
            "last_error" => {
                let capture = if meaning == LastErrorMeaning::DependsOnInputs {
                    ValueCapture::Unsupported
                } else if meaning.is_meaningful(return_value) {
                    ValueCapture::Captured
                } else {
                    ValueCapture::Stale
                };
                payload.raw_scalar(capture, api.function, name, Ty::U32, last_error as u64)
            }
            other => panic!("{}: unexpected leave field {other}", api.function),
        }
    }
    payload
}

// Successful named-object creation can report ERROR_ALREADY_EXISTS. Other
// successful named results need more semantic context; retain them Unsupported
// rather than asserting that they are stale. Failure needs no name context.
fn generic_last_error_meaning(
    api: &ApiDef,
    returned: u64,
    raw_error: u32,
    args: &[u64],
) -> LastErrorMeaning {
    if api.last_error_meaning != LastErrorMeaning::DependsOnInputs
        || !api.module.eq_ignore_ascii_case("kernel32.dll")
    {
        return api.last_error_meaning;
    }
    if api.function == "CreateFileA" {
        return match args.get(4).copied().and_then(|v| u32::try_from(v).ok()) {
            Some(2 | 4) => LastErrorMeaning::Always,
            Some(_) => LastErrorMeaning::WhenReturnIsInvalidHandle,
            None => LastErrorMeaning::DependsOnInputs,
        };
    }
    let name_index = match api.function {
        "CreateMutexW" => 2,
        "CreateMutexExW" | "CreateEventExW" => 1,
        "CreateEventW" | "CreateSemaphoreW" => 3,
        _ => return LastErrorMeaning::DependsOnInputs,
    };
    if returned == 0 {
        return LastErrorMeaning::Always;
    }
    match args.get(name_index) {
        Some(0) => LastErrorMeaning::Never,
        Some(_) if raw_error == 183 => LastErrorMeaning::Always,
        _ => LastErrorMeaning::DependsOnInputs,
    }
}

/// 生の u64 値を Schema の型に沿った `CapturedValue` へ変換する。
/// 32bit 型は下位ビット、64bit 型は全ビット、Bool は 0 以外を真とする。
/// 生成表で使わない型（Str16 / Bytes 等）は panic する。
fn raw_to_value(function: &str, name: &str, ty: Ty, raw: u64) -> CapturedValue {
    match ty {
        Ty::U32 => u32v(raw as u32),
        Ty::I32 => i32v(raw as i32),
        Ty::U64 => u64v(raw),
        Ty::I64 => i64v(raw as i64),
        Ty::Bool => boolv(raw != 0),
        Ty::F32 => CapturedValue::captured(TypedValue::F32Bits(raw as u32)),
        Ty::F64 => CapturedValue::captured(TypedValue::F64Bits(raw)),
        other => {
            panic!("{function}: field {name} uses unsupported Ty {other:?} for generic L1 capture")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::*;
    use shirusu_trace::compact::{decode_values, encode_values};
    use shirusu_trace::schema::schema_types;
    use shirusu_trace::schema::Ty;

    /// Page-granular reader that counts reads, like ReadProcessMemory.
    struct PagedMemory {
        mapped_pages: std::ops::Range<u64>,
        bytes: MapMemory,
        reads: std::cell::Cell<usize>,
    }
    impl MemoryReader for PagedMemory {
        fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool {
            self.reads.set(self.reads.get() + 1);
            let last = addr + buf.len() as u64 - 1;
            if !self.mapped_pages.contains(&(addr / PAGE_SIZE))
                || !self.mapped_pages.contains(&(last / PAGE_SIZE))
            {
                return false;
            }
            for (i, b) in buf.iter_mut().enumerate() {
                let mut one = [0u8];
                *b = if self.bytes.read_exact(addr + i as u64, &mut one) {
                    one[0]
                } else {
                    0xAA
                };
            }
            true
        }
    }

    #[test]
    fn strings_are_read_up_to_page_boundaries_in_few_calls() {
        // P2-5: a 260-character path takes one read, not nine.
        let path: Vec<u16> = std::iter::repeat_n(0x43u16, 259).chain([0]).collect();
        let mut bytes = MapMemory::new();
        bytes.write_u16s(0x10_000, &path);
        let mem = PagedMemory {
            mapped_pages: 0x10..0x12,
            bytes,
            reads: Default::default(),
        };
        let v = read_utf16_string(&mem, 0x10_000);
        assert_eq!(v.capture, ValueCapture::Captured);
        assert_eq!(v.value, TypedValue::Str16(path[..259].to_vec()));
        assert_eq!(mem.reads.get(), 1);

        // Ending right before an unmapped page: the read stops at the
        // boundary and never touches the next page.
        let tail: Vec<u16> = std::iter::repeat_n(0x44u16, 9).chain([0]).collect();
        let at = 0x12_000 - 20;
        let mut bytes = MapMemory::new();
        bytes.write_u16s(at, &tail);
        let mem = PagedMemory {
            mapped_pages: 0x11..0x12,
            bytes,
            reads: Default::default(),
        };
        let v = read_utf16_string(&mem, at);
        assert_eq!(v.capture, ValueCapture::Captured);
        assert_eq!(v.value, TypedValue::Str16(tail[..9].to_vec()));
        assert_eq!(mem.reads.get(), 1);

        // Crossing into an unmapped page keeps what was read.
        let cut: Vec<u16> = std::iter::repeat_n(0x45u16, 10).collect();
        let mut bytes = MapMemory::new();
        bytes.write_u16s(at, &cut);
        let mem = PagedMemory {
            mapped_pages: 0x11..0x12,
            bytes,
            reads: Default::default(),
        };
        let v = read_utf16_string(&mem, at);
        assert_eq!(v.capture, ValueCapture::Truncated);
        assert_eq!(v.value, TypedValue::Str16(cut));
    }

    fn op(call_id: u64, handle: u64) -> PendingOverlapped {
        PendingOverlapped {
            api_id: 1,
            call_id,
            handle,
            buffer: 0,
            requested_len: 0,
            direction: OverlappedDirection::Read,
            bytes_addr: 0,
        }
    }

    #[test]
    fn a_reused_overlapped_is_not_completed_as_the_old_call() {
        // P2-7: the old registration must not describe a new operation.
        let registry = OverlappedRegistry::new();
        let then = OverlappedSignature {
            offset: 4096,
            event: 0x44,
        };
        let reused = OverlappedSignature {
            offset: 0,
            event: 0x44,
        };
        registry
            .submit_signed(0x40, op(1, 7), Some(then))
            .finish(true);
        assert!(registry
            .take_matching(0x40, Some(7), Some(reused))
            .is_none());
        assert!(registry.is_empty(), "the stale registration is dropped");
        registry
            .submit_signed(0x40, op(2, 7), Some(then))
            .finish(true);
        assert!(registry.take_matching(0x40, Some(8), Some(then)).is_none());
        registry
            .submit_signed(0x40, op(3, 7), Some(then))
            .finish(true);
        assert_eq!(
            registry
                .take_matching(0x40, Some(7), Some(then))
                .map(|p| p.call_id),
            Some(3)
        );
        // Completion ports name no handle; the contents still have to match.
        registry
            .submit_signed(0x40, op(4, 7), Some(then))
            .finish(true);
        assert_eq!(
            registry
                .take_matching(0x40, None, Some(then))
                .map(|p| p.call_id),
            Some(4)
        );
    }

    #[test]
    fn pending_overlapped_registrations_are_bounded() {
        let registry = OverlappedRegistry::new();
        for i in 0..(MAX_PENDING_OVERLAPPED as u64 + 1) {
            registry.submit(0x1000 + i * 64, op(i + 1, 1)).finish(true);
        }
        assert!(registry.len() <= MAX_PENDING_OVERLAPPED / 2 + 1);
        // The newest survive.
        let newest = 0x1000 + MAX_PENDING_OVERLAPPED as u64 * 64;
        assert!(registry.take(newest).is_some());
        assert!(registry.take(0x1000).is_none());
    }

    #[test]
    fn overlapped_signature_follows_pointer_width() {
        let mut mem = MapMemory::new();
        // x64: Offset at +16, OffsetHigh at +20, hEvent at +24.
        mem.write(0x100, &[0u8; 32]);
        mem.write_u32(0x110, 0x10);
        mem.write_u32(0x114, 0x2);
        mem.write(0x118, &0x1234_5678_9abcu64.to_le_bytes());
        assert_eq!(
            read_overlapped_signature_with_width(&mem, 0x100, 8),
            Some(OverlappedSignature {
                offset: 0x2_0000_0010,
                event: 0x1234_5678_9abc,
            })
        );
        // x86: Offset at +8, hEvent at +16 (4 bytes).
        let mut mem = MapMemory::new();
        mem.write(0x200, &[0u8; 20]);
        mem.write_u32(0x208, 0x30);
        mem.write_u32(0x210, 0x77);
        assert_eq!(
            read_overlapped_signature_with_width(&mem, 0x200, 4),
            Some(OverlappedSignature {
                offset: 0x30,
                event: 0x77,
            })
        );
        assert_eq!(read_overlapped_signature_with_width(&mem, 0, 4), None);
        assert_eq!(read_overlapped_signature_with_width(&mem, 0x200, 2), None);
    }

    #[test]
    fn synchronous_submission_holds_no_registry() {
        // P2-5: without an OVERLAPPED nothing is registered or cancelled.
        let registry = OverlappedRegistry::new();
        let pending = PendingOverlapped {
            api_id: 1,
            call_id: 7,
            handle: 1,
            buffer: 0,
            requested_len: 0,
            direction: OverlappedDirection::Read,
            bytes_addr: 0,
        };
        let sync = registry.submit(0, pending);
        assert!(sync.registry.is_none());
        drop(sync);
        let overlapped = registry.submit(0x40, pending);
        assert!(overlapped.registry.is_some());
        assert_eq!(registry.len(), 1);
        drop(overlapped);
        assert!(registry.is_empty());
    }

    #[test]
    fn ansi_create_file_error_uses_original_disposition_or_stays_unsupported() {
        let api = api_by_import("kernel32.dll", "CreateFileA").unwrap();
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(api.last_error_meaning, LastErrorMeaning::DependsOnInputs);
        for disposition in 1..=5 {
            let args = [0, 0, 0, 0, disposition, 128, 0];
            for returned in [0x1234, u32::MAX as u64, u64::MAX] {
                let encoded = encode_generic_leave_with_inputs(api, returned, 183, &args);
                let values = decode_values(&types, encoded.as_bytes()).unwrap();
                assert_eq!(values[1].value, TypedValue::U32(183));
                assert_eq!(
                    values[1].capture,
                    if returned == 0x1234 && !matches!(disposition, 2 | 4) {
                        ValueCapture::Stale
                    } else {
                        ValueCapture::Captured
                    }
                );
            }
        }
        for args in [&[][..], &[0, 0, 0, 0, u64::MAX][..]] {
            let encoded = encode_generic_leave_with_inputs(api, 0x1234, 183, args);
            let values = decode_values(&types, encoded.as_bytes()).unwrap();
            assert_eq!(values[1].capture, ValueCapture::Unsupported);
            assert_eq!(values[1].value, TypedValue::U32(183));
        }
    }

    #[test]
    fn named_object_creation_preserves_already_exists_and_unknown_context() {
        for (name, index) in [
            ("CreateMutexW", 2),
            ("CreateMutexExW", 1),
            ("CreateEventW", 3),
            ("CreateEventExW", 1),
            ("CreateSemaphoreW", 3),
        ] {
            let api = api_by_name(name).unwrap();
            assert_eq!(
                api.enter_fields[index].0, "lpName",
                "{name} contract binding"
            );
            let types = schema_types(&api.leave_schema()).unwrap();
            for (returned, name_ptr, error, expected) in [
                (0, 0, 5, ValueCapture::Captured),
                (0, 0x1000, 6, ValueCapture::Captured),
                (0x1234, 0, 183, ValueCapture::Stale),
                (0x1234, 0x1000, 183, ValueCapture::Captured),
                (0x1234, 0x1000, 0, ValueCapture::Unsupported),
                (0x1234, 0x1000, 5, ValueCapture::Unsupported),
            ] {
                let mut args = vec![0; api.enter_fields.len()];
                args[index] = name_ptr;
                let bytes = encode_generic_leave_with_inputs(api, returned, error, &args);
                let values = decode_values(&types, bytes.as_bytes()).unwrap();
                assert_eq!(values[1].capture, expected, "{name}");
                assert_eq!(values[1].value, TypedValue::U32(error));
            }
            let bytes = encode_generic_leave(api, 0x1234, 183);
            assert_eq!(
                decode_values(&types, bytes.as_bytes()).unwrap()[1].capture,
                ValueCapture::Unsupported
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_named_event_reopen_reports_meaningful_already_exists() {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn CreateEventW(
                attributes: *const c_void,
                manual: i32,
                initial: i32,
                name: *const u16,
            ) -> *mut c_void;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        let name: Vec<u16> = format!("Local\\shirusu-semantic-event-{}", std::process::id())
            .encode_utf16()
            .chain([0])
            .collect();
        // SAFETY: null attributes and a live, NUL-terminated UTF-16 name.
        let first = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        assert!(!first.is_null());
        crate::last_error::set(5);
        let second = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        let error = crate::last_error::get();
        // Close both independently acquired handles before assertions/encoding.
        unsafe {
            CloseHandle(first);
            if !second.is_null() {
                CloseHandle(second);
            }
        }
        assert!(!second.is_null());
        assert_eq!(error, 183);
        let api = api_by_name("CreateEventW").unwrap();
        let args = [0, 0, 0, name.as_ptr() as usize as u64];
        let bytes = encode_generic_leave_with_inputs(api, second as usize as u64, error, &args);
        let values = decode_values(
            &schema_types(&api.leave_schema()).unwrap(),
            bytes.as_bytes(),
        )
        .unwrap();
        assert_eq!(values[1].capture, ValueCapture::Captured);
        assert_eq!(values[1].value, TypedValue::U32(183));
    }

    #[test]
    fn heap_alloc_does_not_claim_residual_last_error_on_failure() {
        // HeapAlloc explicitly does not set LastError, including NULL failures.
        let api = api_by_name("HeapAlloc").unwrap();
        let types = schema_types(&api.leave_schema()).unwrap();
        for returned in [0, 0x1234] {
            for raw_error in [0, 5, 8, u32::MAX] {
                let encoded = encode_generic_leave(api, returned, raw_error);
                let values = decode_values(&types, encoded.as_bytes()).unwrap();
                assert_eq!(values[1].capture, ValueCapture::Stale);
                assert_eq!(values[1].value, TypedValue::U32(raw_error));
            }
        }
    }

    #[test]
    fn direct_field_encoding_matches_published_schemas_for_all_generated_apis() {
        for api in GENERATED_API_TABLE {
            for raw in [
                0,
                1,
                u32::MAX as u64,
                u64::MAX,
                i64::MIN as u64,
                0x7ff8_0000_0000_1234,
            ] {
                let args = vec![raw; api.enter_fields.len()];
                let enter = generic_enter(api, &args);
                let leave = generic_leave(api, raw, u32::MAX);
                assert_eq!(
                    encode_generic_enter::<32>(api, &args).as_bytes(),
                    encode_enter(api, &enter).unwrap(),
                    "{} stack enter",
                    api.function
                );
                assert_eq!(
                    encode_generic_leave(api, raw, u32::MAX).as_bytes(),
                    encode_leave(api, &leave).unwrap(),
                    "{} stack leave",
                    api.function
                );
                assert_eq!(
                    encode_enter(api, &enter).unwrap(),
                    encode_values(&schema_types(&api.enter_schema()).unwrap(), &enter).unwrap(),
                    "{} enter",
                    api.function
                );
                assert_eq!(
                    encode_leave(api, &leave).unwrap(),
                    encode_values(&schema_types(&api.leave_schema()).unwrap(), &leave).unwrap(),
                    "{} leave",
                    api.function
                );
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn stack_encoding_matches_reference_for_arbitrary_scalar_bits(
            api_index in 0usize..GENERATED_API_TABLE.len(),
            raw_args in proptest::collection::vec(proptest::prelude::any::<u64>(), 32),
            returned in proptest::prelude::any::<u64>(),
            last_error in proptest::prelude::any::<u32>(),
        ) {
            let api = &GENERATED_API_TABLE[api_index];
            let args = &raw_args[..api.enter_fields.len()];
            let expected = encode_enter(api, &generic_enter(api, args)).unwrap();
            let actual = encode_generic_enter::<32>(api, args);
            proptest::prop_assert_eq!(actual.as_bytes(), expected);
            let expected = encode_leave(api, &generic_leave(api, returned, last_error)).unwrap();
            let actual = encode_generic_leave(api, returned, last_error);
            proptest::prop_assert_eq!(actual.as_bytes(), expected);
        }
    }

    #[test]
    fn scalar_payload_handles_zero_fields_and_maximum_varint() {
        let api = api_by_name("GetCurrentProcessId").unwrap();
        assert!(encode_generic_enter::<0>(api, &[]).as_bytes().is_empty());
        let mut payload = GenericPayload::<1>::new();
        payload.scalar(CapturedValue::captured(TypedValue::U64(u64::MAX)));
        assert_eq!(payload.as_bytes().len(), 11);
        assert_eq!(
            decode_values(&[Ty::U64], payload.as_bytes()).unwrap(),
            vec![CapturedValue::captured(TypedValue::U64(u64::MAX))]
        );
    }

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
    fn read_results_outside_requested_capacity_never_read_the_buffer() {
        struct CountOnly(u32);
        impl MemoryReader for CountOnly {
            fn read_exact(&self, addr: u64, buf: &mut [u8]) -> bool {
                assert_eq!(addr, 0x5000, "must not attempt any output-buffer read");
                assert_eq!(buf.len(), 4);
                buf.copy_from_slice(&self.0.to_le_bytes());
                true
            }
        }
        for requested in [0, 1, 4096, u32::MAX - 1] {
            let transferred = requested + 1;
            let mem = CountOnly(transferred);
            let sync = read_file_leave(&mem, 1, 0x4000, requested, 0x5000, false, 0);
            let completion =
                complete_read_file_leave(&mem, 0x4000, requested, transferred, true, 0);
            for values in [sync, completion] {
                assert_eq!(
                    values[1],
                    u32v(transferred),
                    "retain observed count, not a clamped count"
                );
                assert_eq!(values[2], unsupported_bytes());
            }
        }
    }

    #[test]
    fn read_result_at_requested_capacity_preserves_valid_data() {
        let mut mem = MapMemory::new();
        mem.write(0x4000, b"data-neighbor");
        mem.write_u32(0x5000, 4);
        let sync = read_file_leave(&mem, 1, 0x4000, 4, 0x5000, false, 0);
        let completion = complete_read_file_leave(&mem, 0x4000, 4, 4, true, 0);
        assert_eq!(sync, completion);
        assert_eq!(
            sync[2],
            CapturedValue::captured(TypedValue::Bytes(b"data".to_vec()))
        );
    }

    #[test]
    fn overlapped_count_cannot_truncate_into_a_small_valid_length() {
        let mut mem = MapMemory::new();
        for oversized in [u32::MAX as u64 + 1, u64::MAX] {
            mem.write(0x1008, &oversized.to_le_bytes());
            assert_eq!(
                read_overlapped_transferred_with_width(&mem, 0, 0x1000, 8),
                None
            );
        }
        mem.write(0x1008, &(u32::MAX as u64).to_le_bytes());
        assert_eq!(
            read_overlapped_transferred_with_width(&mem, 0, 0x1000, 8),
            Some(u32::MAX)
        );
    }

    #[test]
    fn read_file_leave_captures_written_data() {
        let api = api_by_id(API_READ_FILE).unwrap();
        let mut m = MapMemory::new();
        m.write(0x4000, b"save-data-1234");
        m.write_u32(0x5000, 14);
        let values = read_file_leave(&m, 1, 0x4000, 32, 0x5000, false, 0);
        assert_eq!(values[1], u32v(14));
        assert_eq!(
            values[2],
            CapturedValue::captured(TypedValue::Bytes(b"save-data-1234".to_vec()))
        );
        let bytes = encode_leave(api, &values).expect("encode");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), values);
        // 失敗時はデータ空、last_error が残る
        let failed = read_file_leave(&m, 0, 0x4000, 32, 0x5000, false, 5);
        assert_eq!(
            failed[2],
            CapturedValue::captured(TypedValue::Bytes(Vec::new()))
        );
        assert_eq!(failed[3], u32v(5));
        // OVERLAPPED は Unsupported
        let ov = read_file_leave(&m, 0, 0x4000, 32, 0x5000, true, 997);
        assert_eq!(ov[1].capture, ValueCapture::Unsupported);
        assert_eq!(ov[2].capture, ValueCapture::Unsupported);
        assert_eq!(ov[3], u32v(997));
    }

    #[test]
    fn write_file_enter_captures_input_before_call() {
        let mut m = MapMemory::new();
        m.write(0x6000, &[1, 2, 3, 4, 5]);
        let values = write_file_enter(&m, 0x1234, 0x6000, 5, 0);
        assert_eq!(
            values[1],
            CapturedValue::captured(TypedValue::Bytes(vec![1, 2, 3, 4, 5]))
        );
        let leave = write_file_leave(&m, 1, 0, false, 0);
        assert_eq!(leave[1].capture, ValueCapture::Unsupported, "null out-ptr");
    }

    #[test]
    fn timing_declarations_match_capture_points() {
        // F19: Schema の取得タイミング宣言と実際の取得点が一致する。
        use shirusu_trace::schema::CaptureTiming;
        let write = api_by_id(API_WRITE_FILE).unwrap();
        let read = api_by_id(API_READ_FILE).unwrap();
        // WriteFile の data は Before: enter で呼び出し前の内容を取る。
        let mut m = MapMemory::new();
        m.write(0x6000, &[9, 8, 7]);
        let enter = write_file_enter(&m, 0x1234, 0x6000, 3, 0);
        assert_eq!(
            CaptureTiming::from_flags(write.enter_schema().fields[1].flags),
            CaptureTiming::Before
        );
        assert_eq!(
            enter[1],
            CapturedValue::captured(TypedValue::Bytes(vec![9, 8, 7]))
        );
        // ReadFile の data は After: leave で API が書き込んだ後の内容を取る。
        m.write(0x4000, b"after-call");
        m.write_u32(0x5000, 10);
        let leave = read_file_leave(&m, 1, 0x4000, 32, 0x5000, false, 0);
        assert_eq!(
            CaptureTiming::from_flags(read.leave_schema().fields[2].flags),
            CaptureTiming::After
        );
        assert_eq!(
            leave[2],
            CapturedValue::captured(TypedValue::Bytes(b"after-call".to_vec()))
        );
        // OVERLAPPED (非同期) の data は完了時に取得するものだが、leave
        // 時点では完了していないため Unsupported として記録する。完了時
        // の取得そのものは F27 の対象。
        let ov = read_file_leave(&m, 1, 0x4000, 32, 0x5000, true, 0);
        assert_eq!(ov[2].capture, ValueCapture::Unsupported);
    }

    #[test]
    fn overlapped_registry_register_take_and_overwrite() {
        // F27: 完了待ちの登録表は OVERLAPPED アドレスを鍵にし、take で
        // 取り出したら消える。同じ構造体の再登録は古い方を上書きする。
        let reg = OverlappedRegistry::new();
        assert!(reg.is_empty());
        let first = PendingOverlapped {
            api_id: API_READ_FILE,
            call_id: 10,
            handle: 0x1234,
            buffer: 0x4000,
            requested_len: 100,
            direction: OverlappedDirection::Read,
            bytes_addr: 0x5000,
        };
        reg.register(0x8000, first);
        assert_eq!(reg.len(), 1);
        // NULL の OVERLAPPED は登録しない
        reg.register(0, first);
        assert_eq!(reg.len(), 1);
        // 別スレッドからの take でも同じ鍵で取り出せる
        assert_eq!(reg.take(0x8000), Some(first));
        assert!(reg.is_empty());
        assert_eq!(reg.take(0x8000), None);
        // 再登録は上書き
        reg.register(0x8000, first);
        let second = PendingOverlapped {
            call_id: 11,
            ..first
        };
        reg.register(0x8000, second);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.take(0x8000), Some(second));
    }

    #[test]
    fn overlapped_internal_high_uses_native_pointer_width() {
        // OVERLAPPED.InternalHigh follows one native-width ULONG_PTR.
        let mut m = MapMemory::new();
        m.write(
            0x1000 + std::mem::size_of::<usize>() as u64,
            &42usize.to_le_bytes(),
        );
        assert_eq!(read_overlapped_internal_high(&m, 0x1000), Some(42));
        assert_eq!(read_overlapped_internal_high(&m, 0), None);
        assert_eq!(read_overlapped_internal_high(&m, 0x9000), None);
    }

    #[test]
    fn overlapped_internal_high_x86_layout_uses_offset_and_width_4() {
        // レビュー #6 P0-2: x86 の OVERLAPPED は Internal (ULONG_PTR = 4B)
        // の直後、オフセット 4 に InternalHigh (4B) がある。オフセット 8
        // 以降は Offset / OffsetHigh (ファイル位置) であり別物。
        let mut m = MapMemory::new();
        m.write_u32(0x1000, 0x1111_2222); // Internal
        m.write_u32(0x1004, 77); // InternalHigh = 転送バイト数
        m.write_u32(0x1008, 0xDEAD_BEEF); // Offset (転送量ではない)
        m.write_u32(0x100C, 0); // OffsetHigh
        assert_eq!(
            read_overlapped_internal_high_with_width(&m, 0x1000, 4),
            Some(77)
        );
        assert_eq!(
            read_overlapped_transferred_with_width(&m, 0, 0x1000, 4),
            Some(77)
        );
        // 旧実装 (オフセット 8・幅 8 固定) はこの Fixture で Offset を
        // 読んで 0xDEAD_BEEF を転送量として返していた。
        // lpNumberOfBytesTransferred があればそちらが優先 (幅に依らない)。
        m.write_u32(0x5000, 99);
        assert_eq!(
            read_overlapped_transferred_with_width(&m, 0x5000, 0x1000, 4),
            Some(99)
        );
    }

    #[test]
    fn overlapped_internal_high_x64_layout_uses_offset_and_width_8() {
        // x64: Internal (8B) の直後、オフセット 8 に InternalHigh (8B)。
        let mut m = MapMemory::new();
        m.write(0x1000, &0x1111_2222_3333_4444u64.to_le_bytes()); // Internal
        m.write(0x1008, &123_456u64.to_le_bytes()); // InternalHigh
        assert_eq!(
            read_overlapped_internal_high_with_width(&m, 0x1000, 8),
            Some(123_456)
        );
        assert_eq!(
            read_overlapped_transferred_with_width(&m, 0, 0x1000, 8),
            Some(123_456)
        );
        // Only a 64-bit process can interpret this x64 fixture natively.
        if cfg!(target_pointer_width = "64") {
            assert_eq!(read_overlapped_internal_high(&m, 0x1000), Some(123_456));
        }
        assert_eq!(overlapped_internal_high_offset(4), 4);
        assert_eq!(overlapped_internal_high_offset(8), 8);
        // 4 / 8 以外の幅は受理しない
        assert_eq!(
            read_overlapped_internal_high_with_width(&m, 0x1000, 2),
            None
        );
    }

    #[test]
    fn complete_read_file_leave_captures_buffer_at_completion() {
        // F27: 完了時点の転送バイト数とバッファ内容を、leave Schema と
        // 同じフィールド順で取る。成功時は last_error は残留値 (Stale)。
        let api = api_by_id(API_READ_FILE).unwrap();
        let mut m = MapMemory::new();
        m.write(0x4000, b"async-data-99");
        let values = complete_read_file_leave(&m, 0x4000, 32, 13, true, 0);
        assert_eq!(values[0], i32v(1));
        assert_eq!(values[1], u32v(13));
        assert_eq!(
            values[2],
            CapturedValue::captured(TypedValue::Bytes(b"async-data-99".to_vec()))
        );
        assert_eq!(values[3].capture, ValueCapture::Stale);
        // leave Schema で往復する
        let bytes = encode_leave(api, &values).expect("encode");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), values);
        // 失敗時はバイト数 Unsupported・データ空・last_error は意味あり
        let failed = complete_read_file_leave(&m, 0x4000, 32, 0, false, 5);
        assert_eq!(failed[0], i32v(0));
        assert_eq!(failed[1].capture, ValueCapture::Unsupported);
        assert_eq!(
            failed[2],
            CapturedValue::captured(TypedValue::Bytes(Vec::new()))
        );
        assert_eq!(failed[3], u32v(5));
    }

    #[test]
    fn complete_write_file_leave_captures_transferred_count() {
        // F27: 完了時の WriteFile leave 値列。
        let api = api_by_id(API_WRITE_FILE).unwrap();
        let values = complete_write_file_leave(7, true, 0);
        assert_eq!(
            values,
            vec![i32v(1), u32v(7), {
                let mut v = u32v(0);
                v.capture = ValueCapture::Stale;
                v
            }]
        );
        let bytes = encode_leave(api, &values).expect("encode");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), values);
        let failed = complete_write_file_leave(0, false, 5);
        assert_eq!(failed[1].capture, ValueCapture::Unsupported);
        assert_eq!(failed[2], u32v(5));
    }

    #[test]
    fn overlapped_transferred_prefers_bytes_addr_then_internal_high() {
        // F27: 転送バイト数は lpNumberOfBytesTransferred から、NULL なら
        // OVERLAPPED.InternalHigh から読む。
        let mut m = MapMemory::new();
        m.write_u32(0x5000, 77);
        m.write(
            0x1000 + std::mem::size_of::<usize>() as u64,
            &55usize.to_le_bytes(),
        );
        assert_eq!(read_overlapped_transferred(&m, 0x5000, 0x1000), Some(77));
        assert_eq!(read_overlapped_transferred(&m, 0, 0x1000), Some(55));
        assert_eq!(read_overlapped_transferred(&m, 0x9000, 0x1000), Some(55));
        assert_eq!(read_overlapped_transferred(&m, 0, 0x9000), None);
    }

    #[test]
    fn completion_observation_leaves_encode_and_decode() {
        // F27: 完了観測 API の leave 値列は各 API の leave Schema で往復する。
        let gor = api_by_id(API_GET_OVERLAPPED_RESULT).unwrap();
        let enter = get_overlapped_result_enter(0x1234, 0x8000, 1);
        let bytes = encode_enter(gor, &enter).expect("encode");
        let types = schema_types(&gor.enter_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), enter);
        let leave = get_overlapped_result_leave(1, Some(13), 0);
        assert_eq!(leave[1], u32v(13));
        assert_eq!(leave[2].capture, ValueCapture::Stale);
        let bytes = encode_leave(gor, &leave).expect("encode");
        let types = schema_types(&gor.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), leave);
        // 転送バイト数が読めなければ Unsupported
        let missing = get_overlapped_result_leave(0, None, 996);
        assert_eq!(missing[1].capture, ValueCapture::Unsupported);
        assert_eq!(missing[2], u32v(996));

        let gqcs = api_by_id(API_GET_QUEUED_COMPLETION_STATUS).unwrap();
        let enter = get_queued_completion_status_enter(0x7777, 0x5000, 0x1234, 0x9000, 1000);
        let bytes = encode_enter(gqcs, &enter).expect("encode");
        let types = schema_types(&gqcs.enter_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), enter);
        let leave = get_queued_completion_status_leave(1, Some(9), 0);
        let bytes = encode_leave(gqcs, &leave).expect("encode");
        let types = schema_types(&gqcs.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), leave);
    }

    #[test]
    fn last_error_meaning_matches_declaration() {
        // F20: Schema の宣言と実際の取得が一致する。失敗時は生値を
        // Captured、成功時は残留値として Stale（生値は保持）。
        // L15: 内部 API (Nt*) は last_error フィールドを持たないため
        // 対象外（意味条件は Never として表に宣言済み）。
        use shirusu_trace::schema::LastErrorMeaning;
        for api in api_table() {
            if crate::api::is_internal_api(api.api_id) {
                continue;
            }
            let declared =
                LastErrorMeaning::from_flags(api.leave_schema().fields.last().unwrap().flags);
            assert_eq!(declared, api.last_error_meaning, "{}", api.function);
        }
        assert_eq!(
            last_error_value(LastErrorMeaning::DependsOnInputs, 42, 183),
            CapturedValue {
                value: TypedValue::U32(183),
                capture: ValueCapture::Unsupported
            }
        );
        // CreateFileW: failures always matter; CREATE_ALWAYS / OPEN_ALWAYS also
        // define LastError on success. Other successful dispositions are stale.
        let failed = create_file_w_leave(u64::MAX, 2, 3);
        assert_eq!(failed[1], u32v(2));
        let failed32 = create_file_w_leave(0x0000_0000_ffff_ffff, 2, 3);
        assert_eq!(failed32[1], u32v(2), "32bit INVALID_HANDLE_VALUE");
        for disposition in 1..=5 {
            let values = create_file_w_leave(0x1234, 183, disposition);
            assert_eq!(
                values[1].capture,
                if matches!(disposition, 2 | 4) {
                    ValueCapture::Captured
                } else {
                    ValueCapture::Stale
                }
            );
            assert_eq!(values[1].value, TypedValue::U32(183));
            assert_eq!(create_file_w_leave(u64::MAX, 80, disposition)[1], u32v(80));
        }
        let create_ok = create_file_w_leave(0x1234, 5, 3);
        assert_eq!(create_ok[1].capture, ValueCapture::Stale);
        assert_eq!(
            create_ok[1].value,
            TypedValue::U32(5),
            "stale keeps the raw value"
        );
        // ReadFile: FALSE なら意味あり、TRUE なら Stale
        let m = MapMemory::new();
        let failed = read_file_leave(&m, 0, 0x4000, 32, 0, false, 5);
        assert_eq!(failed[3], u32v(5));
        let ok = read_file_leave(&m, 1, 0x4000, 32, 0, false, 5);
        assert_eq!(ok[3].capture, ValueCapture::Stale);
        assert_eq!(ok[3].value, TypedValue::U32(5));
        // WriteFile / CloseHandle も同様
        let failed = write_file_leave(&m, 0, 0, false, 5);
        assert_eq!(failed[2], u32v(5));
        let ok = write_file_leave(&m, 1, 0, false, 5);
        assert_eq!(ok[2].capture, ValueCapture::Stale);
        let failed = close_handle_leave(0, 6);
        assert_eq!(failed[1], u32v(6));
        let ok = close_handle_leave(1, 6);
        assert_eq!(ok[1].capture, ValueCapture::Stale);
        // Stale 値も Compact Binary を往復する（符号化 5）。
        let api = api_by_id(API_CREATE_FILE_W).unwrap();
        let bytes = encode_leave(api, &create_ok).expect("encode");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), create_ok);
    }

    /// L03 の生成 API 用のテスト定義（RegCloseKey 相当）。
    fn reg_close_key_def() -> ApiDef {
        use shirusu_trace::schema::{CaptureTiming, LastErrorMeaning, ValueKind};
        ApiDef {
            api_id: 900,
            module: "advapi32.dll",
            function: "RegCloseKey",
            level: 1,
            level_note: "test",
            enter_fields: &[("hKey", Ty::U64, ValueKind::Handle, CaptureTiming::Before)],
            leave_fields: &[
                ("return", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
                (
                    "last_error",
                    Ty::U32,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
            ],
            last_error_meaning: LastErrorMeaning::Never,
        }
    }

    #[test]
    fn generic_enter_and_leave_roundtrip() {
        // L03: 生の引数値を Schema の型に沿って変換し、符号化が往復する。
        let api = reg_close_key_def();
        let enter = generic_enter(&api, &[0x1234_5678_9abc_def0]);
        assert_eq!(enter, vec![u64v(0x1234_5678_9abc_def0)]);
        // 戻り値 0 (ERROR_SUCCESS) でも Never なら last_error は Stale。
        let leave = generic_leave(&api, 0, 5);
        assert_eq!(leave[0], u32v(0));
        assert_eq!(leave[1].capture, ValueCapture::Stale);
        assert_eq!(leave[1].value, TypedValue::U32(5));
        let bytes = encode_enter(&api, &enter).expect("encode enter");
        let types = schema_types(&api.enter_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), enter);
        let bytes = encode_leave(&api, &leave).expect("encode leave");
        let types = schema_types(&api.leave_schema()).unwrap();
        assert_eq!(decode_values(&types, &bytes).unwrap(), leave);
    }

    #[test]
    fn generic_enter_truncates_and_sign_extends() {
        // L03: 32bit 型は下位ビット、64bit 型は全ビット、Bool は 0 以外を真。
        use shirusu_trace::schema::{CaptureTiming, LastErrorMeaning, ValueKind};
        let api = ApiDef {
            api_id: 901,
            module: "kernel32.dll",
            function: "FakeMixed",
            level: 1,
            level_note: "test",
            enter_fields: &[
                ("a", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
                ("b", Ty::I32, ValueKind::Scalar, CaptureTiming::Before),
                ("c", Ty::U64, ValueKind::Scalar, CaptureTiming::Before),
                ("d", Ty::I64, ValueKind::Scalar, CaptureTiming::Before),
                ("e", Ty::Bool, ValueKind::Scalar, CaptureTiming::Before),
            ],
            leave_fields: &[
                ("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After),
                (
                    "last_error",
                    Ty::U32,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
            ],
            last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
        };
        let enter = generic_enter(
            &api,
            &[
                0x1_0000_0002,
                0xffff_ffff,
                0x1234_5678_9abc_def0,
                0xffff_ffff_ffff_ffff,
                2,
            ],
        );
        assert_eq!(
            enter,
            vec![
                u32v(2),
                i32v(-1),
                u64v(0x1234_5678_9abc_def0),
                i64v(-1),
                boolv(true),
            ]
        );
        // 戻り値 0 (FALSE) なら last_error は意味あり、非 0 なら Stale。
        assert_eq!(generic_leave(&api, 0, 5)[1], u32v(5));
        assert_eq!(generic_leave(&api, 1, 5)[1].capture, ValueCapture::Stale);
    }

    #[test]
    fn memory_release_marks_error_only_when_handle_is_returned() {
        for name in ["GlobalFree", "LocalFree"] {
            let api = crate::api::api_table()
                .find(|api| api.function == name)
                .unwrap();
            assert_eq!(generic_leave(api, 0, 5)[1].capture, ValueCapture::Stale);
            for handle in [1, 0x8000_0000, 0xffff_ffff_0000_0000] {
                assert_eq!(generic_leave(api, handle, 5)[1], u32v(5));
            }
            let fields = api.leave_schema().fields;
            assert_eq!(
                LastErrorMeaning::from_flags(fields[1].flags),
                LastErrorMeaning::WhenReturnIsNotNull
            );
        }
    }

    #[test]
    fn generic_leave_handles_null_return_and_void_return() {
        // L03: HANDLE 返し (WhenReturnIsNull) は NULL 時のみ意味あり。
        use shirusu_trace::schema::{CaptureTiming, LastErrorMeaning, ValueKind};
        let api = ApiDef {
            api_id: 902,
            module: "kernel32.dll",
            function: "FakeHandle",
            level: 1,
            level_note: "test",
            enter_fields: &[("a", Ty::U32, ValueKind::Scalar, CaptureTiming::Before)],
            leave_fields: &[
                ("return", Ty::U64, ValueKind::Handle, CaptureTiming::After),
                (
                    "last_error",
                    Ty::U32,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
            ],
            last_error_meaning: LastErrorMeaning::WhenReturnIsNull,
        };
        assert_eq!(generic_leave(&api, 0, 5)[1], u32v(5));
        assert_eq!(
            generic_leave(&api, 0x1234, 5)[1].capture,
            ValueCapture::Stale
        );
        // void 戻りは leave が last_error だけになる。
        let void_api = ApiDef {
            api_id: 903,
            module: "kernel32.dll",
            function: "FakeVoid",
            level: 1,
            level_note: "test",
            enter_fields: &[("a", Ty::U32, ValueKind::Scalar, CaptureTiming::Before)],
            leave_fields: &[(
                "last_error",
                Ty::U32,
                ValueKind::Scalar,
                CaptureTiming::After,
            )],
            last_error_meaning: LastErrorMeaning::Never,
        };
        let leave = generic_leave(&void_api, 0, 5);
        assert_eq!(leave.len(), 1);
        assert_eq!(leave[0].capture, ValueCapture::Stale);
    }

    #[test]
    #[should_panic(expected = "arity mismatch")]
    fn generic_enter_rejects_arity_mismatch() {
        let api = reg_close_key_def();
        let _ = generic_enter(&api, &[]);
    }

    #[test]
    #[should_panic(expected = "unsupported Ty")]
    fn generic_enter_rejects_unsupported_type() {
        // L03: 生成表に Str16 等が混ざると panic する（表の検査は
        // api.rs のテストが担い、ここでは変換側の防御を確認する）。
        use shirusu_trace::schema::{CaptureTiming, LastErrorMeaning, ValueKind};
        let api = ApiDef {
            api_id: 904,
            module: "kernel32.dll",
            function: "FakeString",
            level: 1,
            level_note: "test",
            enter_fields: &[("s", Ty::Str16, ValueKind::Scalar, CaptureTiming::Before)],
            leave_fields: &[
                ("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After),
                (
                    "last_error",
                    Ty::U32,
                    ValueKind::Scalar,
                    CaptureTiming::After,
                ),
            ],
            last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
        };
        let _ = generic_enter(&api, &[0x1000]);
    }
}
