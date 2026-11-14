//! 正規化：環境ごとに変わる非決定値を、比較可能な正準形へ写す。
//!
//! 正規化ルール（v1、すべて本モジュールの定数的な振る舞いとして固定）:
//!
//! 1. **タイムスタンプ**: `timestamp_qpc` の絶対値は比較しない（QPC の
//!    原点も頻度も環境依存）。順序だけが意味を持つ。
//! 2. **プロセス/スレッド**: raw PID・論理 process_id・thread_id は
//!    「Trace 内で最初に現れた順」の序数に置き換える。
//! 3. **オブジェクト（ハンドル）相関**: Schema が
//!    `ValueKind::CreatedObject` と宣言したフィールド（取得成功、
//!    0 でも INVALID_HANDLE_VALUE でもない）を「オブジェクトの
//!    生成」とみなす。生成された生値は
//!    `(生成 API 名, その API の取得済み生成結果の序数)` という ObjectKey に
//!    置き換わり、後続イベントで同じ生値が現れたら同じキーに解決する。
//!    失敗した取得済み結果も序数へ含め、以後の成功結果がずれないようにする。
//!    これにより Trace 全体のハンドル再番号付けは差分にならない。
//!    生値が再利用された場合（Close 後の再生成）は、参照位置より前に
//!    起きた最新の生成へ解決する。
//!    意味種別の無い旧来の Schema (Unspecified) では、従来規約
//!    「CallLeave の `return` フィールド (Ty::U64) が生成」へ
//!    フォールバックする（互換のための経過措置。推定である以上、
//!    U64 スカラーを返す API では誤判定しうる。レビュー #4 の #7）。
//! 4. **意味種別による値の扱い**: `Scalar` は値をそのまま比較する
//!    （U64 のカウンタや時刻も消さない）。`Pointer` と、生成に
//!    対応しない `Handle` の値は中身を消す（`Pointer`）。ただし
//!    0 は `Null`、INVALID_HANDLE_VALUE の番兵値は `Invalid` として
//!    区別を残す。番兵値はポインタ幅依存である（64bit: 全ビット 1、
//!    32bit: 下位 32 ビットのみ 1。`CaptureEnvironment.pointer_width`
//!    で判断する。レビュー第5回 #5）。
//!    Ptr32 / Ptr64 は型そのものがポインタ宣言であるため従来どおり
//!    ポインタとして扱う（Scalar 宣言がある場合だけ値を比較する）。
//!    Unspecified の U64 は従来規約（ハンドル/ポインタ級）で扱う。
//! 5. **取得状態**: `ValueCapture != Captured` の値は本体がダミーの
//!    ため、値ではなく取得状態そのものを比較対象にする。例外は
//!    `Stale`（F20）で、本体は読み取った生値を保持するが、古い残留値
//!    のため比較対象にしない（状態名だけで比較する）。
//! 6. **Payload**: Blob 参照は内容で比較する（Blob ID は内容ハッシュ
//!    なので、Inline と Blob の表現差は吸収される）。欠落した
//!    Payload は「落ちた」という事実と元長・理由を残す。
//! 7. **戻り値・last_error・引数の意味値**（整数、文字列、バイト列、
//!    浮動小数点のビット列）は正規化しない。ここが差分の本体である。
//!    ただし `last_error` が `Stale`（呼び出しが成功し、生値が古い
//!    残留値）の場合は規則 5 により状態名だけで比較し、残留値の違いは
//!    差分にしない（F20）。

use shirusu_analysis::{Phase, TraceView};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{Ty, TypedValue, ValueCapture, ValueKind};
use std::collections::HashMap;

/// 正準化したオブジェクト同一性。生ハンドル値は含まない。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    /// 生成した API 名（例 `kernel32!CreateFileW`）。
    pub creator_api: String,
    /// その API の取得済み生成結果の序数（0 始まり、失敗した結果も数える）。
    pub ordinal: u32,
}

impl ObjectKey {
    pub fn describe(&self) -> String {
        format!("{}#{}", self.creator_api, self.ordinal)
    }
}

/// オブジェクト 1 件の生成情報。
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: ObjectKey,
    /// 生成した生値（本 Trace 内でのみ有効。証跡表示用）。
    pub raw_value: u64,
    /// 生成イベントの平坦化インデックス。
    pub created_at_event: usize,
}

/// 正規化済みの値。
#[derive(Debug, Clone, PartialEq)]
pub enum NormValue {
    Null,
    Invalid,
    Object(ObjectKey),
    /// 中身を消したポインタ級の値。
    Pointer,
    Int(i128),
    Bool(bool),
    /// 浮動小数点のビット列（幅の区別つき）。
    FloatBits {
        bits: u64,
        is64: bool,
    },
    Text(String),
    /// Ill-formed UTF-16 must remain distinguishable.
    Utf16(Vec<u16>),
    Bytes(Vec<u8>),
    /// Blob の内容そのもの（BlobRef フィールドと Payload 共通）。
    /// Shared with every other reference to the same Blob (review
    /// 2026-11-14 P2-13: each reference used to copy the content).
    BlobContent(std::sync::Arc<[u8]>),
    /// 内容を解決できなかった Blob（ID の 16 進文字列）。
    BlobUnknown(String),
    /// 取得できなかった値。比較対象は取得状態の名前。
    NotCaptured(&'static str),
}

impl NormValue {
    pub fn describe(&self) -> String {
        match self {
            NormValue::Null => "null".to_string(),
            NormValue::Invalid => "invalid".to_string(),
            NormValue::Object(key) => format!("object:{}", key.describe()),
            NormValue::Pointer => "pointer".to_string(),
            NormValue::Int(v) => v.to_string(),
            NormValue::Bool(b) => b.to_string(),
            NormValue::FloatBits { bits, is64 } => {
                if *is64 {
                    format!("f64(0x{bits:016x})")
                } else {
                    format!("f32(0x{:08x})", *bits as u32)
                }
            }
            NormValue::Text(s) => format!("{s:?}"),
            NormValue::Utf16(s) => format!("utf16:{s:04x?}"),
            NormValue::Bytes(b) => format!("bytes[{}]", b.len()),
            NormValue::BlobContent(b) => format!("blob-content[{}]", b.len()),
            NormValue::BlobUnknown(hex) => format!("blob:{hex}"),
            NormValue::NotCaptured(name) => format!("<{name}>"),
        }
    }
}

/// 正規化済みフィールド。
#[derive(Debug, Clone, PartialEq)]
pub struct NormField {
    pub name: String,
    pub value: NormValue,
}

/// 正規化済み Payload。
#[derive(Debug, Clone, PartialEq)]
pub enum NormPayload {
    None,
    Content(std::sync::Arc<[u8]>),
    Dropped { original_len: u64, reason_code: u8 },
    UnknownBlob(String),
}

impl NormPayload {
    pub fn describe(&self) -> String {
        match self {
            NormPayload::None => "none".to_string(),
            NormPayload::Content(b) => format!("content[{}]", b.len()),
            NormPayload::Dropped {
                original_len,
                reason_code,
            } => format!("dropped(len={original_len}, reason={reason_code})"),
            NormPayload::UnknownBlob(hex) => format!("blob:{hex}"),
        }
    }
}

/// 正規化済みイベント（Call の片側）。
#[derive(Debug, Clone)]
pub struct NormEvent {
    /// Original file position, including the actual completion thread.
    pub source_index: usize,
    pub sequence: u64,
    /// イベント単位の取得状態が Captured か（false なら値に欠けがある）。
    pub fully_captured: bool,
    pub fields: Vec<NormField>,
    pub payload: NormPayload,
}

/// 正規化済みの呼び出し（Enter/Leave を call_id で対にしたもの）。
#[derive(Debug, Clone)]
pub struct NormCall {
    /// 正準スレッド序数。
    pub thread: usize,
    /// スレッド内での位置（最初のイベント順）。
    pub position: usize,
    pub api: String,
    pub raw_call_id: u64,
    pub enter: Option<NormEvent>,
    pub leave: Option<NormEvent>,
    /// 中断した呼び出しの終了イベント（L08）。CallLeave の代わりに
    /// 記録される。leave と同時に存在しない。
    pub aborted: Option<NormEvent>,
    /// 非同期 I/O の完了イベント（F27）。leave の後に記録され、leave
    /// Schema の値列を持つ。leave と同時に存在しうる（leave は未完了
    /// の Unsupported 値列、completed が完了時点の実値）。比較では
    /// completed があればそれを実効 leave として使う。
    pub completed: Option<NormEvent>,
    /// Enter/Leave でない単独イベント（kind が 1/2/7 以外）。
    pub solo: Option<NormEvent>,
    /// この呼び出しが生成したオブジェクト。
    pub created: Option<ObjectKey>,
    /// 参照したオブジェクト（生成を除く、出現順・重複なし）。
    pub referenced: Vec<ObjectKey>,
    pub first_sequence: u64,
}

impl NormCall {
    /// オブジェクトに関与するか（生成または参照）。
    pub fn involves_object(&self) -> bool {
        self.created.is_some() || !self.referenced.is_empty()
    }

    /// 関与する全オブジェクト（生成→参照の順）。
    pub fn objects(&self) -> Vec<ObjectKey> {
        let mut v = Vec::new();
        if let Some(c) = &self.created {
            v.push(c.clone());
        }
        for r in &self.referenced {
            if !v.contains(r) {
                v.push(r.clone());
            }
        }
        v
    }
}

/// 正規化済み Trace。
pub struct NormTrace {
    pub calls: Vec<NormCall>,
    /// 正準スレッド序数 → そのスレッドの呼び出しインデックス列。
    pub threads: Vec<Vec<usize>>,
    pub objects: Vec<ObjectInfo>,
    /// オブジェクト → それに関与する呼び出しインデックス列（出現順）。
    pub object_calls: HashMap<ObjectKey, Vec<usize>>,
    pub total_events: usize,
}

/// INVALID_HANDLE_VALUE の番兵値 (レビュー第5回 #5)。ポインタ幅で
/// 決まる: 64bit 環境では全ビット 1、32bit 環境では下位 32 ビット
/// だけが 1 (HANDLE は 32bit で、記録時に u64 へゼロ拡張される)。
/// 幅が 32 以外・不明 (環境情報なし、0) の場合は 64bit とみなす。
fn invalid_handle_sentinel(pointer_width: u32) -> u64 {
    if pointer_width == 32 {
        0x0000_0000_FFFF_FFFF
    } else {
        u64::MAX
    }
}

/// Trace の記録環境から番兵値を決める。
fn trace_invalid_handle(trace: &ReadTrace) -> u64 {
    invalid_handle_sentinel(trace.environment.as_ref().map_or(0, |e| e.pointer_width))
}

impl NormTrace {
    pub fn build(trace: &ReadTrace) -> NormTrace {
        let invalid_handle = trace_invalid_handle(trace);
        let mut view = TraceView::build(trace);
        let identity: HashMap<usize, (u64, u64)> = view
            .events
            .iter()
            .map(|e| (e.index, (e.session_id, e.process_id)))
            .collect();
        // File chunk order is drain order, not execution order. Prefer the
        // explicit observation order; otherwise compare QPC in common units.
        let global = view.events.iter().all(|e| e.global_order.is_some());
        let comparable_qpc = view.events.iter().all(|e| e.qpc_frequency != 0);
        view.events.sort_by(|a, b| {
            let order = if global {
                a.global_order.cmp(&b.global_order)
            } else if comparable_qpc {
                ((a.timestamp_qpc as u128) * b.qpc_frequency as u128)
                    .cmp(&((b.timestamp_qpc as u128) * a.qpc_frequency as u128))
            } else {
                std::cmp::Ordering::Equal
            };
            order.then_with(|| a.index.cmp(&b.index))
        });
        let rank: HashMap<usize, usize> = view
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| (e.index, i))
            .collect();
        // --- パス A: オブジェクト生成の収集 ---
        // (session, process, raw value) -> [(source index, ObjectKey)] in observation order.
        let mut productions: HashMap<(u64, u64, u64), Vec<(usize, ObjectKey)>> = HashMap::new();
        // 生成イベント index -> ObjectKey（生成の帰属を正確に引くため）
        let mut created_by_event: HashMap<usize, ObjectKey> = HashMap::new();
        let mut objects: Vec<ObjectInfo> = Vec::new();
        let mut creator_counts: HashMap<String, u32> = HashMap::new();
        for ev in &view.events {
            if ev.phase() != Phase::Leave {
                continue;
            }
            let Some(api) = &ev.api_name else { continue };
            for f in &ev.fields {
                // 生成の判定は Schema の意味種別が正。CreatedObject の
                // 宣言があるフィールドだけが生成であり、Scalar 等の
                // U64 戻り値は生成ではない (レビュー #4 の #7)。
                // 種別が無い旧来の Schema では従来規約へフォールバック。
                let is_creation = match f.kind {
                    ValueKind::CreatedObject => true,
                    ValueKind::Unspecified => f.name == "return" && f.ty == Ty::U64,
                    _ => false,
                };
                if !is_creation || f.capture != ValueCapture::Captured {
                    continue;
                }
                let TypedValue::U64(raw) = f.value else {
                    continue;
                };
                // Count captured creation results, including failure. Otherwise
                // one failed creation shifts every later successful object's
                // identity and pairs unrelated lifetimes across the two traces.
                let ordinal = {
                    let n = creator_counts.entry(api.clone()).or_default();
                    let cur = *n;
                    *n += 1;
                    cur
                };
                if raw == 0 || raw == invalid_handle {
                    continue;
                }
                let key = ObjectKey {
                    creator_api: api.clone(),
                    ordinal,
                };
                productions
                    .entry((ev.session_id, ev.process_id, raw))
                    .or_default()
                    .push((ev.index, key.clone()));
                created_by_event.insert(ev.index, key.clone());
                objects.push(ObjectInfo {
                    key,
                    raw_value: raw,
                    created_at_event: ev.index,
                });
            }
        }
        let resolve = |raw: u64, at_event: usize| -> Option<ObjectKey> {
            let (session, process) = identity[&at_event];
            productions.get(&(session, process, raw)).and_then(|list| {
                list.iter()
                    .rev()
                    .find(|(idx, _)| rank[idx] <= rank[&at_event])
                    .map(|(_, key)| key.clone())
            })
        };

        // --- パス B: 呼び出しの構築 ---
        let mut thread_ordinals: HashMap<(u64, u64, u64), usize> = HashMap::new();
        let mut threads: Vec<Vec<usize>> = Vec::new();
        let mut calls: Vec<NormCall> = Vec::new();
        let mut pending: HashMap<(usize, u64), usize> = HashMap::new();
        let mut object_calls: HashMap<ObjectKey, Vec<usize>> = HashMap::new();
        // Calls by raw call_id, in creation order (review 2026-11-14 P2-13:
        // each completion scanned every call so far).
        let mut calls_by_call_id: HashMap<u64, Vec<usize>> = HashMap::new();

        let blob_cache: BlobCache = std::cell::RefCell::new(HashMap::new());
        let norm_event = |ev: &shirusu_analysis::EventView| -> NormEvent {
            let fields = ev
                .fields
                .iter()
                .map(|f| NormField {
                    name: f.name.clone(),
                    value: norm_value(trace, &blob_cache, f, ev.index, &resolve),
                })
                .collect();
            let payload = match &ev.payload {
                shirusu_analysis::PayloadView::None => NormPayload::None,
                shirusu_analysis::PayloadView::Inline(b) => {
                    NormPayload::Content(std::sync::Arc::from(b.as_slice()))
                }
                shirusu_analysis::PayloadView::Blob(id) => {
                    match shared_blob(&blob_cache, trace, id) {
                        Some(content) => NormPayload::Content(content),
                        None => NormPayload::UnknownBlob(id.to_hex()),
                    }
                }
                shirusu_analysis::PayloadView::Dropped {
                    original_len,
                    reason,
                } => NormPayload::Dropped {
                    original_len: *original_len,
                    reason_code: reason.code(),
                },
            };
            NormEvent {
                source_index: ev.index,
                sequence: ev.sequence,
                fully_captured: ev.capture == shirusu_trace::schema::EventCapture::Captured
                    && ev.args_error.is_none(),
                fields,
                payload,
            }
        };

        for ev in &view.events {
            let thread_key = (ev.session_id, ev.process_id, ev.thread_id);
            let thread = *thread_ordinals.entry(thread_key).or_insert_with(|| {
                threads.push(Vec::new());
                threads.len() - 1
            });
            let api = ev
                .api_name
                .clone()
                .unwrap_or_else(|| format!("api#{}", ev.api_id));
            let phase = ev.phase();
            if matches!(phase, Phase::Other(_)) {
                let idx = calls.len();
                calls.push(NormCall {
                    thread,
                    position: threads[thread].len(),
                    api,
                    raw_call_id: ev.call_id,
                    enter: None,
                    leave: None,
                    aborted: None,
                    completed: None,
                    solo: Some(norm_event(ev)),
                    created: None,
                    referenced: Vec::new(),
                    first_sequence: ev.sequence,
                });
                threads[thread].push(idx);
                calls_by_call_id.entry(ev.call_id).or_default().push(idx);
                continue;
            }
            // 完了は同じ session/process/API/call_id の一意な呼び出しに
            // 付ける。別スレッドで観測されるため thread は問わない。
            // 曖昧なら単独イベントとして残す。二重の完了は最初を残す。
            if phase == Phase::Completed {
                let nev = norm_event(ev);
                // call_id can be reused by external emitters on different
                // threads. Only correlate an unambiguous call in this process
                // with the same API; never attach to an unrelated latest call.
                let same_id: &[usize] =
                    calls_by_call_id.get(&ev.call_id).map_or(&[], Vec::as_slice);
                let mut candidates = same_id
                    .iter()
                    .map(|&index| (index, &calls[index]))
                    .filter(|(_, c)| {
                        let origin = c.enter.as_ref().or(c.leave.as_ref());
                        origin.is_some_and(|origin| {
                            let original = &view.events[rank[&origin.source_index]];
                            original.session_id == ev.session_id
                                && original.process_id == ev.process_id
                                && original.api_id == ev.api_id
                                && c.raw_call_id == ev.call_id
                                && c.aborted.is_none()
                        })
                    })
                    .map(|(index, _)| index);
                let first = candidates.next();
                let unique = first.filter(|_| candidates.next().is_none());
                if let Some(idx) = unique {
                    if calls[idx].completed.is_none() {
                        calls[idx].completed = Some(nev);
                    }
                } else {
                    let idx = calls.len();
                    calls.push(NormCall {
                        thread,
                        position: threads[thread].len(),
                        api,
                        raw_call_id: ev.call_id,
                        enter: None,
                        leave: None,
                        aborted: None,
                        completed: None,
                        solo: Some(nev),
                        created: None,
                        referenced: Vec::new(),
                        first_sequence: ev.sequence,
                    });
                    threads[thread].push(idx);
                    calls_by_call_id.entry(ev.call_id).or_default().push(idx);
                }
                continue;
            }
            let pkey = (thread, ev.call_id);
            let call_idx = match phase {
                Phase::Enter => {
                    if let Some(&existing) = pending.get(&pkey) {
                        if calls[existing].enter.is_some() {
                            // 同じ call_id の Enter が二重に来た（ID 再利用）。
                            // 先行分は未終了のまま確定し、新規に始める。
                            pending.remove(&pkey);
                            None
                        } else {
                            Some(existing)
                        }
                    } else {
                        None
                    }
                }
                _ => pending.get(&pkey).copied(),
            };
            let idx = match call_idx {
                Some(i) => i,
                None => {
                    let idx = calls.len();
                    calls.push(NormCall {
                        thread,
                        position: threads[thread].len(),
                        api: api.clone(),
                        raw_call_id: ev.call_id,
                        enter: None,
                        leave: None,
                        aborted: None,
                        completed: None,
                        solo: None,
                        created: None,
                        referenced: Vec::new(),
                        first_sequence: ev.sequence,
                    });
                    threads[thread].push(idx);
                    calls_by_call_id.entry(ev.call_id).or_default().push(idx);
                    pending.insert(pkey, idx);
                    idx
                }
            };
            let nev = norm_event(ev);
            match phase {
                Phase::Enter => calls[idx].enter = Some(nev),
                Phase::Leave => {
                    if let Some(key) = created_by_event.get(&ev.index) {
                        calls[idx].created = Some(key.clone());
                    }
                    calls[idx].leave = Some(nev);
                    pending.remove(&pkey);
                }
                // L08: 中断は Leave と同じく呼び出しを閉じるが、正常終了
                // とは区別する（比較で形の相違になる）。
                Phase::Aborted => {
                    calls[idx].aborted = Some(nev);
                    pending.remove(&pkey);
                }
                // F27: Completed は上で処理済み。ここには来ない。
                Phase::Completed => unreachable!(),
                Phase::Other(_) => unreachable!(),
            }
        }

        // 参照の確定（フィールド値に Object が現れた場所から拾い、
        // 自分が生成したものは参照から除く）。
        for (idx, call) in calls.iter_mut().enumerate() {
            let mut referenced: Vec<ObjectKey> = Vec::new();
            for side in [
                &call.enter,
                &call.leave,
                &call.aborted,
                &call.completed,
                &call.solo,
            ] {
                let Some(ev) = side else { continue };
                for f in &ev.fields {
                    if let NormValue::Object(key) = &f.value {
                        if Some(key) != call.created.as_ref() && !referenced.contains(key) {
                            referenced.push(key.clone());
                        }
                    }
                }
            }
            call.referenced = referenced;
            for key in call.objects() {
                object_calls.entry(key).or_default().push(idx);
            }
        }

        NormTrace {
            calls,
            threads,
            objects,
            object_calls,
            total_events: view.events.len(),
        }
    }
}

/// U64 値の正規化。意味種別が判断の正であり、型だけでは決めない
/// (レビュー #4 の #7)。
/// - Scalar: 個数・カウンタ・時刻などの数値。そのまま比較する。
/// - Pointer: アドレス。中身は消す（0 は Null として区別）。
/// - Handle / CreatedObject: 生成との相関で Object へ解決し、
///   相関できなければポインタ級として消す。0 は Null、番兵値
///   (`invalid_handle`、ポインタ幅依存) は Invalid
///   (INVALID_HANDLE_VALUE) として区別を残す。
/// - Unspecified: 旧来の Schema 向けに Handle と同じ従来規約を適用
///   する（U64 はハンドル/ポインタ級という公開 Schema の前提）。
fn norm_u64(
    kind: ValueKind,
    raw: u64,
    invalid_handle: u64,
    at_event: usize,
    resolve: &dyn Fn(u64, usize) -> Option<ObjectKey>,
) -> NormValue {
    match kind {
        ValueKind::Scalar => NormValue::Int(raw as i128),
        ValueKind::Pointer => {
            if raw == 0 {
                NormValue::Null
            } else {
                NormValue::Pointer
            }
        }
        ValueKind::Handle | ValueKind::CreatedObject | ValueKind::Unspecified => {
            if raw == 0 {
                NormValue::Null
            } else if raw == invalid_handle {
                NormValue::Invalid
            } else if let Some(key) = resolve(raw, at_event) {
                NormValue::Object(key)
            } else {
                NormValue::Pointer
            }
        }
    }
}

/// Blob contents shared between their references (P2-13).
type BlobCache = std::cell::RefCell<HashMap<shirusu_trace::BlobId, std::sync::Arc<[u8]>>>;

/// One shared copy per Blob, made on its first reference.
fn shared_blob(
    cache: &BlobCache,
    trace: &ReadTrace,
    id: &shirusu_trace::BlobId,
) -> Option<std::sync::Arc<[u8]>> {
    if let Some(shared) = cache.borrow().get(id) {
        return Some(shared.clone());
    }
    let shared: std::sync::Arc<[u8]> = std::sync::Arc::from(trace.blobs.get(id)?.as_slice());
    cache.borrow_mut().insert(*id, shared.clone());
    Some(shared)
}

fn norm_value(
    trace: &ReadTrace,
    blob_cache: &BlobCache,
    f: &shirusu_analysis::FieldView,
    at_event: usize,
    resolve: &dyn Fn(u64, usize) -> Option<ObjectKey>,
) -> NormValue {
    if f.capture != ValueCapture::Captured {
        return NormValue::NotCaptured(shirusu_analysis::value_capture_name(f.capture));
    }
    match &f.value {
        TypedValue::U64(raw) => {
            norm_u64(f.kind, *raw, trace_invalid_handle(trace), at_event, resolve)
        }
        // Ptr32 / Ptr64 は型自体がポインタ宣言。Scalar と明示された
        // 場合だけ値を比較し、それ以外は従来どおり中身を消す。
        TypedValue::Ptr32(v) => {
            if f.kind == ValueKind::Scalar {
                NormValue::Int(*v as i128)
            } else if *v == 0 {
                NormValue::Null
            } else {
                NormValue::Pointer
            }
        }
        TypedValue::Ptr64(v) => {
            if f.kind == ValueKind::Scalar {
                NormValue::Int(*v as i128)
            } else if *v == 0 {
                NormValue::Null
            } else {
                NormValue::Pointer
            }
        }
        TypedValue::I32(v) => NormValue::Int(*v as i128),
        TypedValue::I64(v) => NormValue::Int(*v as i128),
        TypedValue::U32(v) => NormValue::Int(*v as i128),
        TypedValue::Bool(b) => NormValue::Bool(*b),
        TypedValue::F32Bits(bits) => NormValue::FloatBits {
            bits: *bits as u64,
            is64: false,
        },
        TypedValue::F64Bits(bits) => NormValue::FloatBits {
            bits: *bits,
            is64: true,
        },
        TypedValue::Str(s) => NormValue::Text(s.clone()),
        TypedValue::Str16(units) => match String::from_utf16(units) {
            Ok(s) => NormValue::Text(s),
            Err(_) => NormValue::Utf16(units.clone()),
        },
        TypedValue::Bytes(b) => NormValue::Bytes(b.clone()),
        TypedValue::BlobRef(id) => match shared_blob(blob_cache, trace, id) {
            Some(content) => NormValue::BlobContent(content),
            None => NormValue::BlobUnknown(id.to_hex()),
        },
    }
}
