//! シナリオ/PBT 共通の合成 Trace ビルダ（フック表と同じ名前・形の
//! スキーマで Create/Read/Write/Close/Ping を記録する）。
//! テストバイナリごとに使うメソッドが違うため dead_code と、
//! 記録ヘルパの引数の多さはここでは許容する。
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use shirusu_trace::compact::encode_values;
use shirusu_trace::model::{EventBatch, TraceEvent};
use shirusu_trace::proto::{CaptureEnvironment, LossRecord, SessionMetadata};
use shirusu_trace::reader::ReadTrace;
use shirusu_trace::schema::{
    make_schema, CapturedValue, EventCapture, Ty, TypedValue, ValueCapture,
};
use shirusu_trace::writer::FinalizationInfo;
use shirusu_trace::{PayloadRef, TraceWriter};

fn cv(v: TypedValue) -> CapturedValue {
    CapturedValue::captured(v)
}

/// F20: 成功時の GetLastError 生値は古い残留値のため Stale として記録
/// する（値本体は生値を保持）。失敗時は意味のある値として Captured。
fn last_error(ok: bool, err: u32) -> CapturedValue {
    if ok {
        CapturedValue {
            capture: ValueCapture::Stale,
            value: TypedValue::U32(err),
        }
    } else {
        cv(TypedValue::U32(err))
    }
}

fn unsupported_u32() -> CapturedValue {
    CapturedValue {
        capture: ValueCapture::Unsupported,
        value: TypedValue::U32(0),
    }
}

fn unsupported_bytes() -> CapturedValue {
    CapturedValue {
        capture: ValueCapture::Unsupported,
        value: TypedValue::Bytes(Vec::new()),
    }
}

fn str16(s: &str) -> TypedValue {
    TypedValue::Str16(s.encode_utf16().collect())
}

/// Trace 構築のパラメータ。環境依存値（ハンドル・PID・スレッド・
/// 時刻）を差し替えて「同じ振る舞いの別記録」を作るために使う。
pub struct Env {
    pub handle_base: u64,
    pub raw_pid: u32,
    pub process_id: u64,
    pub thread_id: u64,
    pub ts_base: u64,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            handle_base: 0x100,
            raw_pid: 1234,
            process_id: 7,
            thread_id: 55,
            ts_base: 1_000,
        }
    }
}

pub struct Builder {
    pub events: Vec<TraceEvent>,
    seq: u64,
    env: Env,
}

impl Builder {
    pub fn new(env: Env) -> Self {
        Builder {
            events: Vec::new(),
            seq: 0,
            env,
        }
    }

    /// オブジェクト通し番号 → 生ハンドル値。
    pub fn handle(&self, obj: u32) -> u64 {
        self.env.handle_base + (obj as u64) * 0x40
    }

    fn push(
        &mut self,
        kind: u16,
        call_id: u64,
        api_id: u32,
        schema_id: u32,
        types: &[Ty],
        values: Vec<CapturedValue>,
        payload: PayloadRef,
    ) {
        self.seq += 1;
        self.events.push(TraceEvent {
            kind,
            sequence: self.seq,
            timestamp_qpc: self.env.ts_base + self.seq * 10,
            call_id,
            parent_call_id: 0,
            api_id,
            schema_id,
            capture: EventCapture::Captured,
            payload,
            args: Some(encode_values(types, &values).unwrap()),
            global_order: None,
        });
    }

    pub fn create_file(&mut self, call: u64, obj: u32, path: &str) {
        let h = self.handle(obj);
        self.push(
            1,
            call,
            1,
            1,
            &[Ty::Str16, Ty::U32, Ty::U64],
            vec![
                cv(str16(path)),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U64(0)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            1,
            2,
            &[Ty::U64, Ty::U32],
            vec![cv(TypedValue::U64(h)), last_error(true, 0)],
            PayloadRef::None,
        );
    }

    pub fn read_file(
        &mut self,
        call: u64,
        obj: u32,
        want: u32,
        got: u32,
        data: &[u8],
        ok: bool,
        err: u32,
    ) {
        let h = self.handle(obj);
        self.push(
            1,
            call,
            2,
            3,
            &[Ty::U64, Ty::U64, Ty::U32],
            vec![
                cv(TypedValue::U64(h)),
                cv(TypedValue::U64(0x7ff0_0000)),
                cv(TypedValue::U32(want)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            2,
            4,
            &[Ty::I32, Ty::U32, Ty::Bytes, Ty::U32],
            vec![
                cv(TypedValue::I32(ok as i32)),
                cv(TypedValue::U32(got)),
                cv(TypedValue::Bytes(data.to_vec())),
                last_error(ok, err),
            ],
            PayloadRef::None,
        );
    }

    /// 非同期 ReadFile（F27）。enter の後、leave は未完了のため戻り値
    /// FALSE・last_error=997 (ERROR_IO_PENDING) で、バイト数とデータが
    /// Unsupported。その後、完了観測で CallCompleted (kind 8) が leave
    /// Schema の値列で実値を運ぶ（成功時は last_error は Stale）。
    pub fn read_file_async(&mut self, call: u64, obj: u32, want: u32, got: u32, data: &[u8]) {
        let h = self.handle(obj);
        self.push(
            1,
            call,
            2,
            3,
            &[Ty::U64, Ty::U64, Ty::U32],
            vec![
                cv(TypedValue::U64(h)),
                cv(TypedValue::U64(0x7ff0_0000)),
                cv(TypedValue::U32(want)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            2,
            4,
            &[Ty::I32, Ty::U32, Ty::Bytes, Ty::U32],
            vec![
                cv(TypedValue::I32(0)),
                unsupported_u32(),
                unsupported_bytes(),
                cv(TypedValue::U32(997)),
            ],
            PayloadRef::None,
        );
        self.seq += 1;
        self.events.push(TraceEvent {
            kind: 8,
            sequence: self.seq,
            timestamp_qpc: self.env.ts_base + self.seq * 10,
            call_id: call,
            parent_call_id: 0,
            api_id: 2,
            schema_id: 4,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: Some(
                encode_values(
                    &[Ty::I32, Ty::U32, Ty::Bytes, Ty::U32],
                    &[
                        cv(TypedValue::I32(1)),
                        cv(TypedValue::U32(got)),
                        cv(TypedValue::Bytes(data.to_vec())),
                        last_error(true, 0),
                    ],
                )
                .unwrap(),
            ),
            global_order: None,
        });
    }

    pub fn write_file(&mut self, call: u64, obj: u32, data: &[u8]) {
        let h = self.handle(obj);
        self.push(
            1,
            call,
            3,
            5,
            &[Ty::U64, Ty::Bytes, Ty::U32],
            vec![
                cv(TypedValue::U64(h)),
                cv(TypedValue::Bytes(data.to_vec())),
                cv(TypedValue::U32(data.len() as u32)),
            ],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            3,
            6,
            &[Ty::I32, Ty::U32, Ty::U32],
            vec![
                cv(TypedValue::I32(1)),
                cv(TypedValue::U32(data.len() as u32)),
                last_error(true, 0),
            ],
            PayloadRef::None,
        );
    }

    /// CreateFileW の enter の後に CallAborted（L08）。引数値列は無く、
    /// leave Schema の ID だけが残る。ハンドルは生成されない。
    pub fn abort_create_file(&mut self, call: u64, _obj: u32, path: &str) {
        self.push(
            1,
            call,
            1,
            1,
            &[Ty::Str16, Ty::U32, Ty::U64],
            vec![
                cv(str16(path)),
                cv(TypedValue::U32(0x8000_0000)),
                cv(TypedValue::U64(0)),
            ],
            PayloadRef::None,
        );
        self.seq += 1;
        self.events.push(TraceEvent {
            kind: 7,
            sequence: self.seq,
            timestamp_qpc: self.env.ts_base + self.seq * 10,
            call_id: call,
            parent_call_id: 0,
            api_id: 1,
            schema_id: 2,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
            global_order: None,
        });
    }

    /// Ping の enter の後に CallAborted（L08）。オブジェクトに関与
    /// しない呼び出しの中断を表す。
    pub fn abort_ping(&mut self, call: u64, x: u32) {
        self.push(
            1,
            call,
            9,
            17,
            &[Ty::U32],
            vec![cv(TypedValue::U32(x))],
            PayloadRef::None,
        );
        self.seq += 1;
        self.events.push(TraceEvent {
            kind: 7,
            sequence: self.seq,
            timestamp_qpc: self.env.ts_base + self.seq * 10,
            call_id: call,
            parent_call_id: 0,
            api_id: 9,
            schema_id: 18,
            capture: EventCapture::Captured,
            payload: PayloadRef::None,
            args: None,
            global_order: None,
        });
    }

    pub fn close_handle(&mut self, call: u64, obj: u32) {
        let h = self.handle(obj);
        self.push(
            1,
            call,
            4,
            7,
            &[Ty::U64],
            vec![cv(TypedValue::U64(h))],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            4,
            8,
            &[Ty::I32, Ty::U32],
            vec![cv(TypedValue::I32(1)), last_error(true, 0)],
            PayloadRef::None,
        );
    }

    /// オブジェクトに関与しない呼び出し（test!Ping）。
    pub fn ping(&mut self, call: u64, x: u32, ret: u32) {
        self.push(
            1,
            call,
            9,
            17,
            &[Ty::U32],
            vec![cv(TypedValue::U32(x))],
            PayloadRef::None,
        );
        self.push(
            2,
            call,
            9,
            18,
            &[Ty::U32],
            vec![cv(TypedValue::U32(ret))],
            PayloadRef::None,
        );
    }

    pub fn finish(self, fin: FinalizationInfo, losses: &[LossRecord]) -> ReadTrace {
        let bytes = self.finish_bytes(fin, losses);
        shirusu_trace::read_trace(&bytes).unwrap()
    }

    pub fn finish_bytes(self, fin: FinalizationInfo, losses: &[LossRecord]) -> Vec<u8> {
        let env = CaptureEnvironment {
            session: SessionMetadata {
                session_id: 42,
                created_by: "compare-test".into(),
                qpc_frequency: 10_000_000,
            },
            ..Default::default()
        };
        let mut w = TraceWriter::new(Vec::new(), env).unwrap();
        for def in all_schemas() {
            w.register_schema(def).unwrap();
        }
        if !losses.is_empty() {
            w.write_loss_records(losses).unwrap();
        }
        if !self.events.is_empty() {
            w.write_batch(&EventBatch {
                session_id: 42,
                process_id: self.env.process_id,
                raw_pid: self.env.raw_pid,
                thread_id: self.env.thread_id,
                qpc_frequency: 10_000_000,
                events: self.events,
            })
            .unwrap();
        }
        w.finish(fin).unwrap()
    }
}

pub fn all_schemas() -> Vec<shirusu_trace::proto::SchemaDef> {
    vec![
        make_schema(
            1,
            "kernel32!CreateFileW/enter",
            vec![
                ("lpFileName".into(), Ty::Str16, 0),
                ("dwDesiredAccess".into(), Ty::U32, 0),
                ("hTemplateFile".into(), Ty::U64, 0),
            ],
        ),
        make_schema(
            2,
            "kernel32!CreateFileW/leave",
            vec![
                ("return".into(), Ty::U64, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            3,
            "kernel32!ReadFile/enter",
            vec![
                ("hFile".into(), Ty::U64, 0),
                ("lpBuffer".into(), Ty::U64, 0),
                ("nNumberOfBytesToRead".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            4,
            "kernel32!ReadFile/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("lpNumberOfBytesRead".into(), Ty::U32, 0),
                ("data".into(), Ty::Bytes, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            5,
            "kernel32!WriteFile/enter",
            vec![
                ("hFile".into(), Ty::U64, 0),
                ("data".into(), Ty::Bytes, 0),
                ("nNumberOfBytesToWrite".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            6,
            "kernel32!WriteFile/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("lpNumberOfBytesWritten".into(), Ty::U32, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(
            7,
            "kernel32!CloseHandle/enter",
            vec![("hObject".into(), Ty::U64, 0)],
        ),
        make_schema(
            8,
            "kernel32!CloseHandle/leave",
            vec![
                ("return".into(), Ty::I32, 0),
                ("last_error".into(), Ty::U32, 0),
            ],
        ),
        make_schema(17, "test!Ping/enter", vec![("x".into(), Ty::U32, 0)]),
        make_schema(18, "test!Ping/leave", vec![("return".into(), Ty::U32, 0)]),
    ]
}
