// Generated from file-io-contracts.toml; do not edit.
const FILE_IO_API_TABLE: &[ApiDef] = &[
    ApiDef {
        api_id: 1,
        module: "kernel32.dll",
        function: "CreateFileW",
        level: 2,
        level_note: "パス文字列 (Str16) を復元する。lpSecurityAttributes と hTemplateFile は生ポインタ値のみ。返した HANDLE は生値で 後続イベントと相関可能だが Object ID は未割当 (L3 部分達成)",
        enter_fields: &[
            ("lpFileName", Ty::Str16, ValueKind::Scalar, CaptureTiming::Before),
            ("dwDesiredAccess", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("dwShareMode", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("lpSecurityAttributes", Ty::U64, ValueKind::Pointer, CaptureTiming::Before),
            ("dwCreationDisposition", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("dwFlagsAndAttributes", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("hTemplateFile", Ty::U64, ValueKind::Handle, CaptureTiming::Before),
        ],
        leave_fields: &[
            ("return", Ty::U64, ValueKind::CreatedObject, CaptureTiming::After),
            ("last_error", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
        ],
        last_error_meaning: LastErrorMeaning::WhenReturnIsInvalidHandle,
    },
    ApiDef {
        api_id: 2,
        module: "kernel32.dll",
        function: "ReadFile",
        level: 2,
        level_note: "同期完了時の出力バッファ内容を上限付きで復元する (上限超過は Truncated)。OVERLAPPED 指定時は完了が非同期の ためバッファ内容と読取バイト数は Unsupported として記録する",
        enter_fields: &[
            ("hFile", Ty::U64, ValueKind::Handle, CaptureTiming::Before),
            ("lpBuffer", Ty::U64, ValueKind::Pointer, CaptureTiming::Before),
            ("nNumberOfBytesToRead", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("lpOverlapped", Ty::U64, ValueKind::Pointer, CaptureTiming::Before),
        ],
        leave_fields: &[
            ("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After),
            ("lpNumberOfBytesRead", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
            ("data", Ty::Bytes, ValueKind::Scalar, CaptureTiming::After),
            ("last_error", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
        ],
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: 3,
        module: "kernel32.dll",
        function: "WriteFile",
        level: 2,
        level_note: "入力バッファ内容を呼び出し前に上限付きで復元する (上限超過は Truncated)",
        enter_fields: &[
            ("hFile", Ty::U64, ValueKind::Handle, CaptureTiming::Before),
            ("data", Ty::Bytes, ValueKind::Scalar, CaptureTiming::Before),
            ("nNumberOfBytesToWrite", Ty::U32, ValueKind::Scalar, CaptureTiming::Before),
            ("lpOverlapped", Ty::U64, ValueKind::Pointer, CaptureTiming::Before),
        ],
        leave_fields: &[
            ("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After),
            ("lpNumberOfBytesWritten", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
            ("last_error", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
        ],
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
    ApiDef {
        api_id: 4,
        module: "kernel32.dll",
        function: "CloseHandle",
        level: 1,
        level_note: "型付き引数・戻り値のみ。対象 HANDLE の生値で生成側 イベントと相関可能 (Object ID は未割当)",
        enter_fields: &[
            ("hObject", Ty::U64, ValueKind::Handle, CaptureTiming::Before),
        ],
        leave_fields: &[
            ("return", Ty::I32, ValueKind::Scalar, CaptureTiming::After),
            ("last_error", Ty::U32, ValueKind::Scalar, CaptureTiming::After),
        ],
        last_error_meaning: LastErrorMeaning::WhenReturnIsFalse,
    },
];
