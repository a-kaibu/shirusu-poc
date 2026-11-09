//! エミッタ本体：セッション管理と、compare / 適合性チェッカが
//! 前提とする規約に沿ったイベント構築。
//!
//! このキットが呼び出し側の代わりに保証すること（＝外部レコーダが
//! 自前で再実装しなくてよい規約）:
//!
//! - **Schema 登録**: ApiSet の全 Schema を、イベントより前に
//!   TraceWriter へ登録する（前方参照は起きない）。
//! - **sequence の単調性**: スレッドごとに 1 から単調増加で
//!   自動採番する。呼び出し側が番号を管理することはない。
//! - **Enter/Leave の対応**: begin_call が発行する CallToken で
//!   end_call を呼ぶ。call_id はスレッド内で一意に自動採番され、
//!   Enter と Leave で同じ値を共有する。親呼び出し（ネスト）は
//!   begin 時点のオープン中呼び出しから parent_call_id を引く。
//!   非同期完了（OVERLAPPED 等）のために end の順序は LIFO を
//!   要求しない。対応は call_id で取る。
//! - **引数の検証**: 値列は登録済み Schema の型列と個数・型を
//!   照合してから Compact Binary へ符号化する（不一致はエラー）。
//! - **Payload の前方参照禁止**: Blob は参照するイベントより前に
//!   書かれる（TraceWriter の順序保証を利用）。
//! - **完全性メタデータ**: finish で Finalization を必ず書く。
//!   3 指標の値は呼び出し側が正直に決める（このキットは値を
//!   作らない）。終了時点でオープンな呼び出しが残っていれば
//!   finish は失敗する。記録対象が呼び出しの途中で終わった場合は
//!   abandon_call で明示的に破棄し、Loss Record（kind =
//!   UNKNOWN_TERMINATION）を呼び出し側が書くこと。
//!
//! タイムスタンプは呼び出し側が自前の時計（QPC 等）で測って渡す。
//! このキットは時刻を発明しない。SessionConfig.qpc_frequency は
//! その時計の周波数と一致させること。

use crate::api_set::ApiSet;
use shirusu_trace::compact::encode_values;
use shirusu_trace::error::{CompactError, TraceError};
use shirusu_trace::model::{EventBatch, PayloadRef, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, SessionMetadata};
use shirusu_trace::schema::{CapturedValue, EventCapture, Ty};
use shirusu_trace::writer::{FinalizationInfo, TraceWriter};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;

/// 転送 Descriptor の kind と同じ番号（CallEnter / CallLeave）。
pub const KIND_ENTER: u16 = 1;
pub const KIND_LEAVE: u16 = 2;

/// 1 スレッドのバッファに溜めるイベント数の目安（到達で自動 flush）。
const BATCH_FLUSH_EVENTS: usize = 256;

/// エミッタのエラー。
#[derive(Debug)]
pub enum EmitError {
    /// ApiSet に無い API 名で記録しようとした。
    UnknownApi(String),
    /// ApiSet への同名 API の再登録。
    DuplicateApi(String),
    /// ApiSpec 自体が不正（名前が空など）。
    InvalidSpec(String),
    /// end_call / abandon_call に渡されたトークンがオープン中でない。
    UnknownCall { thread_id: u64, call_id: u64 },
    /// finish 時点でオープンな呼び出しが残っている。
    OpenCallsAtFinish { thread_id: u64, call_ids: Vec<u64> },
    /// Trace 形式層のエラー（Writer 不変条件を含む）。
    Trace(TraceError),
    /// 引数値列が Schema と一致しない。
    Compact(CompactError),
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::UnknownApi(name) => write!(f, "api not in the emitter's ApiSet: {name}"),
            EmitError::DuplicateApi(name) => write!(f, "api already registered: {name}"),
            EmitError::InvalidSpec(msg) => write!(f, "invalid api spec: {msg}"),
            EmitError::UnknownCall { thread_id, call_id } => {
                write!(
                    f,
                    "call {call_id} on thread {thread_id} is not open (unknown or already ended)"
                )
            }
            EmitError::OpenCallsAtFinish {
                thread_id,
                call_ids,
            } => write!(
                f,
                "thread {thread_id} still has {} open call(s) at finish: {call_ids:?}",
                call_ids.len()
            ),
            EmitError::Trace(e) => write!(f, "trace error: {e}"),
            EmitError::Compact(e) => write!(f, "argument encoding error: {e}"),
        }
    }
}

impl std::error::Error for EmitError {}

impl From<TraceError> for EmitError {
    fn from(e: TraceError) -> Self {
        EmitError::Trace(e)
    }
}

impl From<CompactError> for EmitError {
    fn from(e: CompactError) -> Self {
        EmitError::Compact(e)
    }
}

pub type Result<T> = std::result::Result<T, EmitError>;

/// イベントに付ける Payload の渡し方。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PayloadData {
    #[default]
    None,
    /// イベントへ直接埋め込む（小さいデータ向け）。
    Inline(Vec<u8>),
    /// Blob として格納し、イベントからは Blob ID で参照する。
    /// 内容アドレスのため、同じ内容は自動で重複排除される。
    Blob(Vec<u8>),
}

/// イベント単位の付帯情報。既定は「取得成功・Payload なし」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMeta {
    pub capture: EventCapture,
    pub payload: PayloadData,
}

impl Default for EventMeta {
    fn default() -> Self {
        EventMeta {
            capture: EventCapture::Captured,
            payload: PayloadData::None,
        }
    }
}

impl EventMeta {
    pub fn with_payload(payload: PayloadData) -> Self {
        EventMeta {
            payload,
            ..Default::default()
        }
    }
}

/// セッション（1 プロセス分の記録）の設定。CaptureEnvironment と
/// Event Batch の文脈になる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub session_id: u64,
    /// 生成者の識別（例 `sake 0.3.0`）。適合性チェッカは空を弾く：
    /// 「誰が出した Trace か」が分からないものは取り込まない。
    pub created_by: String,
    /// Trace 内プロセス ID（セッション内で一意ならよい）。
    pub process_id: u64,
    /// OS の PID 生値。
    pub raw_pid: u32,
    /// タイムスタンプの周波数（Hz）。呼び出し側の時計と一致させる。
    /// 既定は Windows の QPC で典型的な 10 MHz。
    pub qpc_frequency: u64,
    pub os_version: String,
    pub os_build: u32,
    pub cpu_arch: String,
    pub pointer_width: u32,
    pub capture_config: String,
    pub target_description: String,
}

impl SessionConfig {
    pub fn new(session_id: u64, created_by: &str) -> Self {
        SessionConfig {
            session_id,
            created_by: created_by.to_string(),
            process_id: 1,
            raw_pid: 0,
            qpc_frequency: 10_000_000,
            os_version: String::new(),
            os_build: 0,
            cpu_arch: "x86_64".to_string(),
            pointer_width: 64,
            capture_config: String::new(),
            target_description: String::new(),
        }
    }
}

/// begin_call が返す呼び出しトークン。end_call / abandon_call は
/// このトークンで対応する Enter を特定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallToken {
    pub thread_id: u64,
    pub call_id: u64,
    pub api_id: u32,
}

#[derive(Debug)]
struct ThreadState {
    next_sequence: u64,
    next_call_id: u64,
    /// オープン中の call_id（begin 順）。親子関係と finish 時の
    /// 未終了検出に使う。end の順序は LIFO でなくてよい。
    open_calls: Vec<u64>,
    pending: Vec<TraceEvent>,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadState {
    fn new() -> Self {
        ThreadState {
            next_sequence: 1,
            next_call_id: 1,
            open_calls: Vec::new(),
            pending: Vec::new(),
        }
    }
}

/// 外部レコーダ向けエミッタ。`TraceWriter` の上に薄く乗り、
/// 規約に沿ったイベント列の構築だけを担う。
pub struct Emitter<W: Write> {
    writer: TraceWriter<W>,
    set: ApiSet,
    cfg: SessionConfig,
    threads: HashMap<u64, ThreadState>,
}

impl<W: Write> Emitter<W> {
    /// Header / Environment を書き、ApiSet の全 Schema を登録する。
    pub fn new(inner: W, set: ApiSet, cfg: SessionConfig) -> Result<Self> {
        let environment = CaptureEnvironment {
            session: SessionMetadata {
                session_id: cfg.session_id,
                created_by: cfg.created_by.clone(),
                qpc_frequency: cfg.qpc_frequency,
            },
            os_version: cfg.os_version.clone(),
            os_build: cfg.os_build,
            cpu_arch: cfg.cpu_arch.clone(),
            pointer_width: cfg.pointer_width,
            capture_config: cfg.capture_config.clone(),
            feature_flags: 0,
            target_description: cfg.target_description.clone(),
        };
        let mut writer = TraceWriter::new(inner, environment)?;
        for def in set.schemas() {
            writer.register_schema(def)?;
        }
        Ok(Emitter {
            writer,
            set,
            cfg,
            threads: HashMap::new(),
        })
    }

    pub fn api_set(&self) -> &ApiSet {
        &self.set
    }

    pub fn session_config(&self) -> &SessionConfig {
        &self.cfg
    }

    /// 呼び出しの開始（CallEnter）を記録する。引数値列は API の
    /// enter Schema と照合される。
    pub fn begin_call(
        &mut self,
        thread_id: u64,
        api: &str,
        values: &[CapturedValue],
        timestamp_qpc: u64,
        meta: EventMeta,
    ) -> Result<CallToken> {
        let api_id = self
            .set
            .api_id(api)
            .ok_or_else(|| EmitError::UnknownApi(api.to_string()))?;
        let spec = self.set.spec(api_id).expect("api_id from set");
        let types: Vec<Ty> = spec.enter_fields.iter().map(|(_, t, _)| *t).collect();
        let args = encode_args(&types, values)?;
        let payload = self.resolve_payload(meta.payload)?;
        let state = self.threads.entry(thread_id).or_default();
        let call_id = state.next_call_id;
        state.next_call_id += 1;
        let parent_call_id = state.open_calls.last().copied().unwrap_or(0);
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.open_calls.push(call_id);
        state.pending.push(TraceEvent {
            kind: KIND_ENTER,
            sequence,
            timestamp_qpc,
            call_id,
            parent_call_id,
            api_id,
            schema_id: ApiSet::enter_schema_id(api_id),
            capture: meta.capture,
            payload,
            args,
        });
        if state.pending.len() >= BATCH_FLUSH_EVENTS {
            self.flush_thread(thread_id)?;
        }
        Ok(CallToken {
            thread_id,
            call_id,
            api_id,
        })
    }

    /// 呼び出しの終了（CallLeave）を記録する。トークンが指す
    /// 呼び出しがオープン中でなければならない（対応の保証）。
    pub fn end_call(
        &mut self,
        token: CallToken,
        values: &[CapturedValue],
        timestamp_qpc: u64,
        meta: EventMeta,
    ) -> Result<()> {
        let spec = self
            .set
            .spec(token.api_id)
            .ok_or_else(|| EmitError::UnknownApi(format!("api_id {}", token.api_id)))?;
        let types: Vec<Ty> = spec.leave_fields.iter().map(|(_, t, _)| *t).collect();
        let args = encode_args(&types, values)?;
        let payload = self.resolve_payload(meta.payload)?;
        let state = self
            .threads
            .get_mut(&token.thread_id)
            .ok_or(EmitError::UnknownCall {
                thread_id: token.thread_id,
                call_id: token.call_id,
            })?;
        let pos = state
            .open_calls
            .iter()
            .position(|&c| c == token.call_id)
            .ok_or(EmitError::UnknownCall {
                thread_id: token.thread_id,
                call_id: token.call_id,
            })?;
        state.open_calls.remove(pos);
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.pending.push(TraceEvent {
            kind: KIND_LEAVE,
            sequence,
            timestamp_qpc,
            call_id: token.call_id,
            parent_call_id: 0,
            api_id: token.api_id,
            schema_id: ApiSet::leave_schema_id(token.api_id),
            capture: meta.capture,
            payload,
            args,
        });
        if state.pending.len() >= BATCH_FLUSH_EVENTS {
            self.flush_thread(token.thread_id)?;
        }
        Ok(())
    }

    /// 対象が呼び出しの途中で終了した等で、対応する Leave が
    /// 永遠に来ない呼び出しを明示的に破棄する。痕跡は呼び出し側が
    /// write_loss_records で UNKNOWN_TERMINATION として残すこと
    /// （勝手に Leave を捏造しないための区別）。
    pub fn abandon_call(&mut self, token: CallToken) -> Result<()> {
        let state = self
            .threads
            .get_mut(&token.thread_id)
            .ok_or(EmitError::UnknownCall {
                thread_id: token.thread_id,
                call_id: token.call_id,
            })?;
        let pos = state
            .open_calls
            .iter()
            .position(|&c| c == token.call_id)
            .ok_or(EmitError::UnknownCall {
                thread_id: token.thread_id,
                call_id: token.call_id,
            })?;
        state.open_calls.remove(pos);
        Ok(())
    }

    /// そのスレッドで現在オープン中の呼び出し数。
    pub fn open_call_count(&self, thread_id: u64) -> usize {
        self.threads
            .get(&thread_id)
            .map(|s| s.open_calls.len())
            .unwrap_or(0)
    }

    /// Loss Record を Loss Block として書く（バッファ中のイベント
    /// より先に書かれることがある点に注意：Loss は文脈情報であり
    /// イベント列との順序は形式上の意味を持たない）。
    pub fn write_loss_records(&mut self, records: &[LossRecord]) -> Result<()> {
        self.writer.write_loss_records(records)?;
        Ok(())
    }

    /// スレッドのバッファを Event Batch として書き出す。
    pub fn flush_thread(&mut self, thread_id: u64) -> Result<()> {
        let Some(state) = self.threads.get_mut(&thread_id) else {
            return Ok(());
        };
        if state.pending.is_empty() {
            return Ok(());
        }
        let events = std::mem::take(&mut state.pending);
        let batch = EventBatch {
            session_id: self.cfg.session_id,
            process_id: self.cfg.process_id,
            raw_pid: self.cfg.raw_pid,
            thread_id,
            qpc_frequency: self.cfg.qpc_frequency,
            events,
        };
        self.writer.write_batch(&batch)?;
        Ok(())
    }

    /// 全スレッドを flush し、Index と Finalization を書いて
    /// 内側の Writer を返す。オープン中の呼び出しが残っている
    /// スレッドがあれば失敗する（abandon_call で明示的に閉じる
    /// こと）。integrity の 3 指標は呼び出し側が正直に決める。
    pub fn finish(mut self, info: FinalizationInfo) -> Result<W> {
        let mut thread_ids: Vec<u64> = self.threads.keys().copied().collect();
        thread_ids.sort_unstable();
        for tid in &thread_ids {
            if let Some(state) = self.threads.get(tid) {
                if !state.open_calls.is_empty() {
                    return Err(EmitError::OpenCallsAtFinish {
                        thread_id: *tid,
                        call_ids: state.open_calls.clone(),
                    });
                }
            }
        }
        for tid in &thread_ids {
            self.flush_thread(*tid)?;
        }
        Ok(self.writer.finish(info)?)
    }

    fn resolve_payload(&mut self, payload: PayloadData) -> Result<PayloadRef> {
        Ok(match payload {
            PayloadData::None => PayloadRef::None,
            PayloadData::Inline(bytes) => PayloadRef::Inline(bytes),
            PayloadData::Blob(bytes) => PayloadRef::Blob(self.writer.add_payload(&bytes)?),
        })
    }
}

/// 値列を符号化する。フィールドが無い Schema では args 自体を
/// 持たない（None）形にする。
fn encode_args(types: &[Ty], values: &[CapturedValue]) -> Result<Option<Vec<u8>>> {
    if types.is_empty() && values.is_empty() {
        return Ok(None);
    }
    Ok(Some(encode_values(types, values)?))
}
