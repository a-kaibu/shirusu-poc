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
//!    `(生成 API 名, その API による生成の序数)` という ObjectKey に
//!    置き換わり、後続イベントで同じ生値が現れたら同じキーに解決する。
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
//!    0 は `Null`、U64 の全ビット 1 は `Invalid` として区別を残す。
//!    Ptr32 / Ptr64 は型そのものがポインタ宣言であるため従来どおり
//!    ポインタとして扱う（Scalar 宣言がある場合だけ値を比較する）。
//!    Unspecified の U64 は従来規約（ハンドル/ポインタ級）で扱う。
//! 5. **取得状態**: `ValueCapture != Captured` の値は本体がダミーの
//!    ため、値ではなく取得状態そのものを比較対象にする。
//! 6. **Payload**: Blob 参照は内容で比較する（Blob ID は内容ハッシュ
//!    なので、Inline と Blob の表現差は吸収される）。欠落した
//!    Payload は「落ちた」という事実と元長・理由を残す。
//! 7. **戻り値・last_error・引数の意味値**（整数、文字列、バイト列、
//!    浮動小数点のビット列）は正規化しない。ここが差分の本体である。

use shirusu_analysis::{Phase, TraceView};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{Ty, TypedValue, ValueCapture, ValueKind};
use std::collections::HashMap;

/// 正準化したオブジェクト同一性。生ハンドル値は含まない。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    /// 生成した API 名（例 `kernel32!CreateFileW`）。
    pub creator_api: String,
    /// その API が生成したオブジェクトの中での序数（0 始まり）。
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
    Bytes(Vec<u8>),
    /// Blob の内容そのもの（BlobRef フィールドと Payload 共通）。
    BlobContent(Vec<u8>),
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
    Content(Vec<u8>),
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
    /// Enter/Leave でない単独イベント（kind が 1/2 以外）。
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

impl NormTrace {
    pub fn build(trace: &ReadTrace) -> NormTrace {
        let view = TraceView::build(trace);
        // --- パス A: オブジェクト生成の収集 ---
        // raw value -> [(生成イベント index, ObjectKey)]（時刻順）
        let mut productions: HashMap<u64, Vec<(usize, ObjectKey)>> = HashMap::new();
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
                if raw == 0 || raw == u64::MAX {
                    continue;
                }
                let ordinal = {
                    let n = creator_counts.entry(api.clone()).or_default();
                    let cur = *n;
                    *n += 1;
                    cur
                };
                let key = ObjectKey {
                    creator_api: api.clone(),
                    ordinal,
                };
                productions
                    .entry(raw)
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
            productions.get(&raw).and_then(|list| {
                list.iter()
                    .rev()
                    .find(|(idx, _)| *idx <= at_event)
                    .map(|(_, key)| key.clone())
            })
        };

        // --- パス B: 呼び出しの構築 ---
        let mut thread_ordinals: HashMap<(u64, u64, u64), usize> = HashMap::new();
        let mut threads: Vec<Vec<usize>> = Vec::new();
        let mut calls: Vec<NormCall> = Vec::new();
        let mut pending: HashMap<(usize, u64), usize> = HashMap::new();
        let mut object_calls: HashMap<ObjectKey, Vec<usize>> = HashMap::new();

        let norm_event = |ev: &shirusu_analysis::EventView| -> NormEvent {
            let fields = ev
                .fields
                .iter()
                .map(|f| NormField {
                    name: f.name.clone(),
                    value: norm_value(trace, f, ev.index, &resolve),
                })
                .collect();
            let payload = match &ev.payload {
                shirusu_analysis::PayloadView::None => NormPayload::None,
                shirusu_analysis::PayloadView::Inline(b) => NormPayload::Content(b.clone()),
                shirusu_analysis::PayloadView::Blob(id) => match trace.blobs.get(id) {
                    Some(content) => NormPayload::Content(content.clone()),
                    None => NormPayload::UnknownBlob(id.to_hex()),
                },
                shirusu_analysis::PayloadView::Dropped {
                    original_len,
                    reason,
                } => NormPayload::Dropped {
                    original_len: *original_len,
                    reason_code: reason.code(),
                },
            };
            NormEvent {
                sequence: ev.sequence,
                fully_captured: ev.capture == shirusu_trace::schema::EventCapture::Captured,
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
                    solo: Some(norm_event(ev)),
                    created: None,
                    referenced: Vec::new(),
                    first_sequence: ev.sequence,
                });
                threads[thread].push(idx);
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
                        solo: None,
                        created: None,
                        referenced: Vec::new(),
                        first_sequence: ev.sequence,
                    });
                    threads[thread].push(idx);
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
                Phase::Other(_) => unreachable!(),
            }
        }

        // 参照の確定（フィールド値に Object が現れた場所から拾い、
        // 自分が生成したものは参照から除く）。
        for (idx, call) in calls.iter_mut().enumerate() {
            let mut referenced: Vec<ObjectKey> = Vec::new();
            for side in [&call.enter, &call.leave, &call.solo] {
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
///   相関できなければポインタ級として消す。0 は Null、全ビット 1
///   は Invalid (INVALID_HANDLE_VALUE) として区別を残す。
/// - Unspecified: 旧来の Schema 向けに Handle と同じ従来規約を適用
///   する（U64 はハンドル/ポインタ級という公開 Schema の前提）。
fn norm_u64(
    kind: ValueKind,
    raw: u64,
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
            } else if raw == u64::MAX {
                NormValue::Invalid
            } else if let Some(key) = resolve(raw, at_event) {
                NormValue::Object(key)
            } else {
                NormValue::Pointer
            }
        }
    }
}

fn norm_value(
    trace: &ReadTrace,
    f: &shirusu_analysis::FieldView,
    at_event: usize,
    resolve: &dyn Fn(u64, usize) -> Option<ObjectKey>,
) -> NormValue {
    if f.capture != ValueCapture::Captured {
        return NormValue::NotCaptured(shirusu_analysis::value_capture_name(f.capture));
    }
    match &f.value {
        TypedValue::U64(raw) => norm_u64(f.kind, *raw, at_event, resolve),
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
        TypedValue::Str16(units) => NormValue::Text(String::from_utf16_lossy(units)),
        TypedValue::Bytes(b) => NormValue::Bytes(b.clone()),
        TypedValue::BlobRef(id) => match trace.blobs.get(id) {
            Some(content) => NormValue::BlobContent(content.clone()),
            None => NormValue::BlobUnknown(id.to_hex()),
        },
    }
}
