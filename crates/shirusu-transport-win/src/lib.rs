//! shirusu-transport-win: Windows バックエンド。
//! - 名前付きでない File Mapping を Host が作り、`DuplicateHandle` で対象プロセスへ渡す前提の API。
//! - Event Object: `data_ready` はプロセス単位・auto-reset、`space_available` は Ring 単位。
//! - Host 待機は 2ms 再確認付き（transport の ReCheckPolicy と対応）。
//!
//! Windows 以外では同じ API 形のスタブとしてコンパイルでき、プロセス間機能は Unsupported を返す。

use shirusu_transport::notify::ReCheckPolicy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// L23: ロード済みモジュールの列挙・署名検証・API Set 契約の解決。
pub mod modules;
pub mod system;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinError {
    Unsupported,
    OsError {
        api: &'static str,
        code: u32,
    },
    /// The remote thread may still be using its parameter. Do not free it.
    RemoteCallPending {
        wait_status: u32,
    },
    InvalidArgument(&'static str),
}
impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "not supported on this platform"),
            Self::OsError { api, code } => write!(f, "{api} failed with OS error {code}"),
            Self::RemoteCallPending { wait_status } => write!(
                f,
                "remote call did not finish (wait status {wait_status}); parameter memory retained"
            ),
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
        }
    }
}
impl std::error::Error for WinError {}
pub type Result<T> = std::result::Result<T, WinError>;

/// OS ハンドルの数値表現（プロセス間受け渡し用）。共有メモリに置く値ではない。
pub type HandleValue = usize;

/// 起動したプロセスのハンドル一式（CREATE_SUSPENDED 起動用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnedProcess {
    pub process: HandleValue,
    pub thread: HandleValue,
    pub pid: u32,
}

// Win32 waits accept integer milliseconds. Round positive fractional values up:
// truncation turns the final sub-millisecond recheck slice into a busy poll.
// Reserve INFINITE (u32::MAX); a finite Duration must remain a finite wait.
#[cfg(any(windows, test))]
fn wait_timeout_millis(timeout: Duration) -> u32 {
    timeout
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u128::from(u32::MAX - 1)) as u32
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, SetHandleInformation, DUPLICATE_SAME_ACCESS,
        HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, SetEvent, WaitForSingleObject,
        PROCESS_DUP_HANDLE,
    };

    pub(super) fn last_err(api: &'static str) -> WinError {
        WinError::OsError {
            api,
            code: unsafe { GetLastError() },
        }
    }
    pub(super) fn h(v: HandleValue) -> HANDLE {
        v as HANDLE
    }
    pub(super) fn hv(h: HANDLE) -> HandleValue {
        h as HandleValue
    }

    /// 現在のユーザーの SID だけに GENERIC_ALL を許可する DACL 付き
    /// SECURITY_ATTRIBUTES を作る。バッファは構造体が保持し、呼び出し元が
    /// CreateFileMappingW を呼ぶ間だけ有効であればよい。
    /// `acl`/`sd` は構築後にフィールドとして読まれないが、解放してはならない:
    /// `sa.lpSecurityDescriptor` が `sd` を指し、`sd` 内の DACL が `acl` を
    /// 指しているため、この構造体がバッファの生存を保証している。
    #[allow(dead_code)]
    struct RestrictedSecurityAttributes {
        /// TOKEN_USER のコピー。SID は ACE へ複写済みだが念のため保持する。
        _token_info: Vec<u8>,
        acl: Vec<u8>,
        sd: Vec<u8>,
        sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    }

    fn restricted_security_attributes() -> Result<RestrictedSecurityAttributes> {
        // SECURITY_DESCRIPTOR_REVISION (= 1)。Win32 では Win32::System::SystemServices
        // にある定数だが値は固定のため、feature 追加を避けてここで定義する。
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
        use windows_sys::Win32::Foundation::GENERIC_ALL;
        use windows_sys::Win32::Security::{
            AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl, TokenUser, ACCESS_ALLOWED_ACE,
            ACL, ACL_REVISION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
            TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::OpenProcessToken;
        // 1. プロセストークンからユーザー SID を取得する。
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_err("OpenProcessToken"));
        }
        let mut needed: u32 = 0;
        unsafe {
            // 必要サイズの問い合わせ（ERROR_INSUFFICIENT_BUFFER を期待する）。
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        let mut token_info = vec![0u8; needed as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_info.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            let e = last_err("GetTokenInformation");
            unsafe { CloseHandle(token) };
            return Err(e);
        }
        unsafe { CloseHandle(token) };
        let user = unsafe { &*(token_info.as_ptr() as *const TOKEN_USER) };
        let sid = user.User.Sid;
        // 2. ACL を構築する（ユーザー SID に GENERIC_ALL の ACE 1 本だけ）。
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        let acl_len = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + sid_len;
        let mut acl = vec![0u8; acl_len];
        let acl_ptr = acl.as_mut_ptr() as *mut ACL;
        if unsafe { InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) } == 0 {
            return Err(last_err("InitializeAcl"));
        }
        if unsafe { AddAccessAllowedAce(acl_ptr, ACL_REVISION, GENERIC_ALL, sid) } == 0 {
            return Err(last_err("AddAccessAllowedAce"));
        }
        // 3. セキュリティ記述子に DACL を設定する。
        let mut sd = vec![0u8; std::mem::size_of::<SECURITY_DESCRIPTOR>()];
        let sd_ptr = sd.as_mut_ptr() as PSECURITY_DESCRIPTOR;
        if unsafe { InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
            return Err(last_err("InitializeSecurityDescriptor"));
        }
        if unsafe { SetSecurityDescriptorDacl(sd_ptr, 1, acl_ptr, 0) } == 0 {
            return Err(last_err("SetSecurityDescriptorDacl"));
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr,
            bInheritHandle: 0,
        };
        Ok(RestrictedSecurityAttributes {
            _token_info: token_info,
            acl,
            sd,
            sa,
        })
    }

    /// File Mapping のサイズを CreateFileMappingW の (high, low) DWORD
    /// 対へ分ける。`usize` のまま `>> 32` すると、32bit ターゲットでは
    /// シフト量が型の幅以上になり算術オーバーフローとしてコンパイル
    /// エラーになる (レビュー #4 の #1: i686 ビルド失敗の原因)。
    /// u64 へ広げてから分ける。
    fn split_mapping_size(len: usize) -> (u32, u32) {
        let size = len as u64;
        ((size >> 32) as u32, (size & 0xFFFF_FFFF) as u32)
    }

    pub struct SharedMapping {
        handle: HANDLE,
        view: *mut u8,
        len: usize,
        owns_handle: bool,
    }
    unsafe impl Send for SharedMapping {}
    impl SharedMapping {
        pub fn create(len: usize) -> Result<Self> {
            if len == 0 {
                return Err(WinError::InvalidArgument("len"));
            }
            let (size_high, size_low) = split_mapping_size(len);
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    size_high,
                    size_low,
                    std::ptr::null(), // 名前付きにしない
                )
            };
            if handle.is_null() {
                return Err(last_err("CreateFileMappingW"));
            }
            let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, len) };
            if view.Value.is_null() {
                unsafe { CloseHandle(handle) };
                return Err(last_err("MapViewOfFile"));
            }
            Ok(Self {
                handle,
                view: view.Value as *mut u8,
                len,
                owns_handle: true,
            })
        }
        /// アクセス制御付きで作る。仕様: 共有メモリのセクションには、Host と対象
        /// プロセス以外から開けないアクセス制御を付ける。DACL は現在のユーザーの
        /// SID にだけ GENERIC_ALL を許可し、それ以外には何も許可しない（Host と
        /// 対象プロセスは同じユーザーで動く前提）。Event 等のハンドル受け渡しは
        /// DuplicateHandle 経由のため、この DACL では妨げない。
        pub fn create_restricted(len: usize) -> Result<Self> {
            if len == 0 {
                return Err(WinError::InvalidArgument("len"));
            }
            let restricted = restricted_security_attributes()?;
            let (size_high, size_low) = split_mapping_size(len);
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    &restricted.sa,
                    PAGE_READWRITE,
                    size_high,
                    size_low,
                    std::ptr::null(), // 名前付きにしない
                )
            };
            if handle.is_null() {
                return Err(last_err("CreateFileMappingW(restricted)"));
            }
            let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, len) };
            if view.Value.is_null() {
                unsafe { CloseHandle(handle) };
                return Err(last_err("MapViewOfFile(restricted)"));
            }
            Ok(Self {
                handle,
                view: view.Value as *mut u8,
                len,
                owns_handle: true,
            })
        }
        ///
        /// # Safety
        /// `handle_value` は有効な File Mapping ハンドルで、`len` はその大きさ以下であること。
        pub unsafe fn from_handle_value(handle_value: HandleValue, len: usize) -> Result<Self> {
            let handle = h(handle_value);
            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, len);
            if view.Value.is_null() {
                return Err(last_err("MapViewOfFile(from handle)"));
            }
            Ok(Self {
                handle,
                view: view.Value as *mut u8,
                len,
                owns_handle: true,
            })
        }
        pub fn handle_value(&self) -> HandleValue {
            hv(self.handle)
        }
        /// 対象プロセスへ DuplicateHandle で渡す。
        pub fn duplicate_to_process(&self, target_pid: u32) -> Result<HandleValue> {
            let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, target_pid) };
            if target.is_null() {
                return Err(last_err("OpenProcess"));
            }
            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.handle,
                    target,
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            unsafe { CloseHandle(target) };
            if ok == 0 {
                return Err(last_err("DuplicateHandle"));
            }
            Ok(hv(dup))
        }
        /// 継承可能なハンドルにする（CreateProcess で子へ渡す E2E 用）。
        pub fn make_inheritable(&self) -> Result<()> {
            let ok = unsafe {
                SetHandleInformation(self.handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            };
            if ok == 0 {
                return Err(last_err("SetHandleInformation"));
            }
            Ok(())
        }
        pub fn as_ptr(&self) -> *mut u8 {
            self.view
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.view, self.len) }
        }
    }
    impl Drop for SharedMapping {
        fn drop(&mut self) {
            unsafe {
                if !self.view.is_null() {
                    UnmapViewOfFile(
                        windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                            Value: self.view as *mut c_void,
                        },
                    );
                }
                if self.owns_handle && !self.handle.is_null() {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    pub struct EventObject {
        handle: HANDLE,
        auto_reset: bool,
    }
    unsafe impl Send for EventObject {}
    /// `EventObject` の共有: カーネルのイベント操作（SetEvent /
    /// WaitForSingleObject）はスレッドセーフなため、`&EventObject` を複数
    /// スレッドで共有できる。`make_inheritable` は共有を開始する前に 1 回
    /// だけ呼ぶこと。ハンドル自体は呼び出し中ずっと有効であること。
    unsafe impl Sync for EventObject {}
    impl EventObject {
        pub fn new(auto_reset: bool, initially_signaled: bool) -> Result<Self> {
            let handle = unsafe {
                CreateEventW(
                    std::ptr::null(),
                    if auto_reset { 0 } else { 1 },
                    if initially_signaled { 1 } else { 0 },
                    std::ptr::null(),
                )
            };
            if handle.is_null() {
                return Err(last_err("CreateEventW"));
            }
            Ok(Self { handle, auto_reset })
        }
        /// # Safety
        /// `value` は有効な Event ハンドルであること。
        pub unsafe fn from_handle_value(value: HandleValue, auto_reset: bool) -> Self {
            Self {
                handle: h(value),
                auto_reset,
            }
        }
        pub fn handle_value(&self) -> HandleValue {
            hv(self.handle)
        }
        pub fn is_auto_reset(&self) -> bool {
            self.auto_reset
        }
        /// 対象プロセスへ DuplicateHandle で渡す（Host→Agent の space_available
        /// 受け渡し。A68）。返した値は対象プロセス側のハンドル値。
        pub fn duplicate_to_process(&self, target_pid: u32) -> Result<HandleValue> {
            let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, target_pid) };
            if target.is_null() {
                return Err(last_err("OpenProcess"));
            }
            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.handle,
                    target,
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            unsafe { CloseHandle(target) };
            if ok == 0 {
                return Err(last_err("DuplicateHandle"));
            }
            Ok(hv(dup))
        }
        pub fn make_inheritable(&self) -> Result<()> {
            let ok = unsafe {
                SetHandleInformation(self.handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            };
            if ok == 0 {
                return Err(last_err("SetHandleInformation(event)"));
            }
            Ok(())
        }
        pub fn set(&self) -> Result<()> {
            if unsafe { SetEvent(self.handle) } == 0 {
                return Err(last_err("SetEvent"));
            }
            Ok(())
        }
        /// タイムアウト付き待機。true = signaled。
        pub fn wait_timeout(&self, timeout: Duration) -> bool {
            let ms = super::wait_timeout_millis(timeout);
            unsafe { WaitForSingleObject(self.handle, ms) == 0 }
        }
    }
    impl Drop for EventObject {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { CloseHandle(self.handle) };
            }
        }
    }

    /// 継承ハンドル付きで子プロセスを起動する（E2E 用）。
    /// 呼び手が対象ハンドルへ make_inheritable 済みであること。
    pub fn spawn_inheriting(cmdline: &str) -> Result<HandleValue> {
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
        };
        let mut cmd: Vec<u16> = cmdline.encode_utf16().chain([0]).collect();
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1, // inherit handles
                0,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(last_err("CreateProcessW"));
        }
        unsafe {
            CloseHandle(pi.hThread);
        }
        Ok(pi.hProcess as HandleValue)
    }
    pub fn wait_process(process_handle_value: HandleValue, timeout: Duration) -> Option<u32> {
        use windows_sys::Win32::Foundation::CloseHandle as CH;
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        let handle = h(process_handle_value);
        let ms = super::wait_timeout_millis(timeout);
        let r = unsafe { WaitForSingleObject(handle, ms) };
        if r != 0 {
            return None;
        }
        let mut code: u32 = 0;
        unsafe {
            GetExitCodeProcess(handle, &mut code);
            CH(handle);
        }
        Some(code)
    }

    /// CREATE_SUSPENDED で起動する。メインスレッドは止まったままで、
    /// 呼び手が `resume_main_thread` するまで対象のコードは動かない
    /// （Agent の初期化完了を Host が確認してから再開する、overview の手順）。
    pub fn spawn_suspended(cmdline: &str) -> Result<SpawnedProcess> {
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
        };
        let mut cmd: Vec<u16> = cmdline.encode_utf16().chain([0]).collect();
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            return Err(last_err("CreateProcessW(suspended)"));
        }
        Ok(SpawnedProcess {
            process: hv(pi.hProcess),
            thread: hv(pi.hThread),
            pid: pi.dwProcessId,
        })
    }

    /// 停止中のメインスレッドを再開する。戻り値は直前のサスペンド数。
    pub fn resume_main_thread(thread: HandleValue) -> Result<u32> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        let prev = unsafe { ResumeThread(h(thread)) };
        if prev == u32::MAX {
            return Err(last_err("ResumeThread"));
        }
        Ok(prev)
    }

    /// DLL 注入に必要な権限（スレッド作成・VM 操作・複製）でプロセスを開く。
    pub fn open_process_for_injection(pid: u32) -> Result<HandleValue> {
        use windows_sys::Win32::System::Threading::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        };
        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_DUP_HANDLE
            | PROCESS_SYNCHRONIZE;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return Err(last_err("OpenProcess(inject)"));
        }
        Ok(hv(handle))
    }

    /// プロセスが終了済みかどうか（待たない確認）。
    pub fn process_exited(process: HandleValue) -> Result<bool> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        match unsafe { WaitForSingleObject(h(process), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(last_err("WaitForSingleObject(process)")),
        }
    }

    /// Read an exited process's status without consuming its handle. Waiting
    /// first distinguishes a live process from one that actually exited with 259
    /// (STILL_ACTIVE).
    pub fn process_exit_code(process: HandleValue) -> Result<Option<u32>> {
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        if !process_exited(process)? {
            return Ok(None);
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(h(process), &mut code) } == 0 {
            return Err(last_err("GetExitCodeProcess"));
        }
        Ok(Some(code))
    }

    pub fn process_creation_time(process: HandleValue) -> Result<u64> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
        if unsafe {
            GetProcessTimes(
                h(process),
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return Err(last_err("GetProcessTimes"));
        }
        Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
    }

    pub fn close_handle_value(v: HandleValue) {
        if v != 0 {
            unsafe { CloseHandle(h(v)) };
        }
    }

    /// 任意のハンドルを対象プロセスへ複製する（Host プロセスへの
    /// ハンドルを生存確認用に渡すなど、型付き API が無いものの受け渡し）。
    pub fn duplicate_handle_to_process(
        handle_value: HandleValue,
        target_pid: u32,
    ) -> Result<HandleValue> {
        let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, target_pid) };
        if target.is_null() {
            return Err(last_err("OpenProcess"));
        }
        let mut dup: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                h(handle_value),
                target,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        unsafe { CloseHandle(target) };
        if ok == 0 {
            return Err(last_err("DuplicateHandle"));
        }
        Ok(hv(dup))
    }

    pub fn write_process_memory(
        process: HandleValue,
        dest: usize,
        src: *const u8,
        len: usize,
    ) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        let mut written: usize = 0;
        let ok = unsafe {
            WriteProcessMemory(
                h(process),
                dest as *const c_void,
                src as *const c_void,
                len,
                &mut written,
            )
        };
        if ok == 0 || written != len {
            return Err(last_err("WriteProcessMemory"));
        }
        Ok(())
    }

    /// 対象プロセスのメモリを読む (Bootstrap の初期化結果の読み戻し等)。
    pub fn read_process_memory(
        process: HandleValue,
        src: usize,
        dest: *mut u8,
        len: usize,
    ) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                h(process),
                src as *const c_void,
                dest as *mut c_void,
                len,
                &mut read,
            )
        };
        if ok == 0 || read != len {
            return Err(last_err("ReadProcessMemory"));
        }
        Ok(())
    }

    /// 対象プロセスで `start(param)` をリモートスレッドで実行し、戻り値
    /// （スレッド終了コード）を返す。30 秒で打ち切る。
    pub fn remote_call(process: HandleValue, start: usize, param: usize) -> Result<u32> {
        remote_call_with_timeout(process, start, param, Duration::from_secs(30))
    }

    fn remote_call_with_timeout(
        process: HandleValue,
        start: usize,
        param: usize,
        timeout: Duration,
    ) -> Result<u32> {
        use windows_sys::Win32::System::Threading::{
            CreateRemoteThread, GetExitCodeThread, LPTHREAD_START_ROUTINE,
        };
        // SAFETY: start は対象プロセス内で有効な関数アドレスであること
        // （呼び出し側が LoadLibrary 済みモジュールのベース + RVA で保証する）。
        let routine: LPTHREAD_START_ROUTINE =
            unsafe { std::mem::transmute(start as *const c_void) };
        let thread = unsafe {
            CreateRemoteThread(
                h(process),
                std::ptr::null(),
                0,
                routine,
                param as *mut c_void,
                0,
                std::ptr::null_mut(),
            )
        };
        if thread.is_null() {
            return Err(last_err("CreateRemoteThread"));
        }
        let waited = unsafe { WaitForSingleObject(thread, super::wait_timeout_millis(timeout)) };
        if waited != 0 {
            unsafe { CloseHandle(thread) };
            return Err(WinError::RemoteCallPending {
                wait_status: waited,
            });
        }
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeThread(thread, &mut code) };
        unsafe { CloseHandle(thread) };
        if ok == 0 {
            return Err(last_err("GetExitCodeThread"));
        }
        Ok(code)
    }

    /// 対象プロセスで `LoadLibraryW(dll_path)` を実行する。
    /// 前提： 対象と同一ビットネス（自プロセスの kernel32 の
    /// LoadLibraryW アドレスが対象でも有効。同一ブート・同一
    /// ビットネスの system DLL はプロセス間で同じベースを持つ）。
    pub fn remote_load_library(process: HandleValue, dll_path: &str) -> Result<()> {
        remote_load_library_with_call(process, dll_path, remote_call)
    }

    fn remote_load_library_with_call(
        process: HandleValue,
        dll_path: &str,
        call: impl FnOnce(HandleValue, usize, usize) -> Result<u32>,
    ) -> Result<()> {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows_sys::Win32::System::Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        };
        let proc_handle = h(process);
        let wide: Vec<u16> = dll_path.encode_utf16().chain([0]).collect();
        let bytes = wide.len() * 2;
        let remote = unsafe {
            VirtualAllocEx(
                proc_handle,
                std::ptr::null(),
                bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote.is_null() {
            return Err(last_err("VirtualAllocEx"));
        }
        let result = (|| -> Result<()> {
            write_process_memory(process, remote as usize, wide.as_ptr() as *const u8, bytes)?;
            let k32_name: Vec<u16> = "kernel32.dll".encode_utf16().chain([0]).collect();
            let k32 = unsafe { GetModuleHandleW(k32_name.as_ptr()) };
            if k32.is_null() {
                return Err(last_err("GetModuleHandleW"));
            }
            let load = unsafe { GetProcAddress(k32, c"LoadLibraryW".as_ptr() as *const u8) };
            let Some(load) = load else {
                return Err(WinError::OsError {
                    api: "GetProcAddress(LoadLibraryW)",
                    code: 0,
                });
            };
            let code = call(process, load as usize, remote as usize)?;
            if code == 0 {
                return Err(WinError::OsError {
                    api: "LoadLibraryW(remote) returned NULL",
                    code: 0,
                });
            }
            Ok(())
        })();
        // A timeout does not stop LoadLibraryW. Its input must remain valid
        // until the remote thread finishes (or the target process exits).
        if !matches!(result, Err(WinError::RemoteCallPending { .. })) {
            unsafe { VirtualFreeEx(proc_handle, remote, 0, MEM_RELEASE) };
        }
        result
    }

    /// 実行中の全プロセスの (pid, 親 pid) 一覧を返す
    /// （L05 の子プロセス発見用。Toolhelp のプロセススナップショット）。
    pub fn enumerate_processes() -> Result<Vec<(u32, u32)>> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(last_err("CreateToolhelp32Snapshot"));
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        unsafe {
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    out.push((entry.th32ProcessID, entry.th32ParentProcessID));
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        Ok(out)
    }

    /// 対象プロセスのモジュール一覧から、名前でモジュールのベースを引く。
    pub fn module_base(pid: u32, module_name: &str) -> Result<usize> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        };
        let snap =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(last_err("CreateToolhelp32Snapshot"));
        }
        let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut result = Err(WinError::InvalidArgument("module not loaded in target"));
        unsafe {
            if Module32FirstW(snap, &mut entry) != 0 {
                loop {
                    let name_len = entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len());
                    let name = String::from_utf16_lossy(&entry.szModule[..name_len]);
                    if name.eq_ignore_ascii_case(module_name) {
                        result = Ok(entry.modBaseAddr as usize);
                        break;
                    }
                    if Module32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        result
    }

    /// 対象プロセス内にメモリを確保する（Bootstrap の受け渡し用）。
    pub fn remote_alloc(process: HandleValue, len: usize) -> Result<usize> {
        use windows_sys::Win32::System::Memory::{
            VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
        };
        let addr = unsafe {
            VirtualAllocEx(
                h(process),
                std::ptr::null(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if addr.is_null() {
            return Err(last_err("VirtualAllocEx(bootstrap)"));
        }
        Ok(addr as usize)
    }

    /// `remote_alloc` で確保したメモリを解放する。
    pub fn remote_free(process: HandleValue, addr: usize) {
        use windows_sys::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE};
        if addr != 0 {
            unsafe { VirtualFreeEx(h(process), addr as *mut c_void, 0, MEM_RELEASE) };
        }
    }

    /// プロセスを終了させる。起動に失敗した対象の後始末専用
    /// （他人のプロセスに使わないこと）。
    pub fn terminate_process(process: HandleValue, exit_code: u32) -> Result<()> {
        use windows_sys::Win32::System::Threading::TerminateProcess;
        let ok = unsafe { TerminateProcess(h(process), exit_code) };
        if ok == 0 {
            return Err(last_err("TerminateProcess"));
        }
        Ok(())
    }
    #[cfg(test)]
    mod remote_parameter_tests {
        use super::*;
        use std::sync::atomic::{AtomicU32, AtomicUsize};

        #[test]
        fn timed_out_load_keeps_parameter_for_delayed_native_reader() {
            static GATE: AtomicUsize = AtomicUsize::new(0);
            static DONE: AtomicUsize = AtomicUsize::new(0);
            static OBSERVED: AtomicU32 = AtomicU32::new(u32::MAX);

            unsafe extern "system" fn delayed_read(parameter: *mut c_void) -> u32 {
                let waited = unsafe { WaitForSingleObject(h(GATE.load(Ordering::SeqCst)), 5_000) };
                if waited == 0 {
                    let mut first = [0u8; 2];
                    // ReadProcessMemory reports a freed allocation without
                    // deliberately crashing the test process on an invalid read.
                    if read_process_memory(
                        unsafe { hv(GetCurrentProcess()) },
                        parameter as usize,
                        first.as_mut_ptr(),
                        first.len(),
                    )
                    .is_ok()
                    {
                        OBSERVED.store(u16::from_le_bytes(first) as u32, Ordering::SeqCst);
                    }
                }
                unsafe { SetEvent(h(DONE.load(Ordering::SeqCst))) };
                1
            }

            let process = unsafe { hv(GetCurrentProcess()) };
            let gate = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            let done = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            assert!(!gate.is_null() && !done.is_null());
            GATE.store(hv(gate), Ordering::SeqCst);
            DONE.store(hv(done), Ordering::SeqCst);
            let mut parameter = 0;
            let result = remote_load_library_with_call(process, "Q-test.dll", |process, _, ptr| {
                parameter = ptr;
                remote_call_with_timeout(
                    process,
                    delayed_read as *const () as usize,
                    ptr,
                    Duration::ZERO,
                )
            });
            // The thread cannot complete before this signal, irrespective of
            // scheduler speed. Its delayed read happens after the timeout path.
            unsafe { SetEvent(gate) };
            let finished = unsafe { WaitForSingleObject(done, 5_000) } == 0;
            let observed = OBSERVED.load(Ordering::SeqCst);
            if finished {
                // The callback has finished using parameter before signaling.
                remote_free(process, parameter);
                unsafe {
                    CloseHandle(gate);
                    CloseHandle(done);
                }
            } // On failure retain resources rather than close a live wait.
            assert!(matches!(
                result,
                Err(WinError::RemoteCallPending { wait_status: 0x102 })
            ));
            assert!(finished, "native reader did not finish");
            assert_eq!(
                observed,
                u32::from(b'Q'),
                "parameter was freed before the late read"
            );
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub struct SharedMapping {
        view: Vec<u8>,
        len: usize,
    }
    impl SharedMapping {
        pub fn create(len: usize) -> Result<Self> {
            if len == 0 {
                return Err(WinError::InvalidArgument("len"));
            }
            // スタブ: ローカルヒープで代替し API 形だけ保つ（プロセス間共有ではない）
            Ok(Self {
                view: vec![0u8; len],
                len,
            })
        }
        /// スタブ: アクセス制御は Windows の概念のため Unsupported。
        pub fn create_restricted(_len: usize) -> Result<Self> {
            Err(WinError::Unsupported)
        }
        /// # Safety
        /// スタブでは常に Unsupported を返すため、実際には何もしない。
        pub unsafe fn from_handle_value(_handle_value: HandleValue, _len: usize) -> Result<Self> {
            Err(WinError::Unsupported)
        }
        pub fn handle_value(&self) -> HandleValue {
            0
        }
        pub fn duplicate_to_process(&self, _target_pid: u32) -> Result<HandleValue> {
            Err(WinError::Unsupported)
        }
        pub fn make_inheritable(&self) -> Result<()> {
            Err(WinError::Unsupported)
        }
        pub fn as_ptr(&self) -> *mut u8 {
            self.view.as_ptr() as *mut u8
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.view
        }
    }
    pub struct EventObject {
        auto_reset: bool,
        // Windows の Event と同じ意味論のスタブ。condvar で真のブロッキング待機をする
        // （1ms ポーリングでは待機の遅延が Windows 実機と大きく変わってしまうため）。
        // auto-reset: 待機がシグナルを消費する。現状の全用途は auto-reset。
        state: std::sync::Mutex<bool>,
        condvar: std::sync::Condvar,
    }
    impl EventObject {
        pub fn new(auto_reset: bool, initially_signaled: bool) -> Result<Self> {
            Ok(Self {
                auto_reset,
                state: std::sync::Mutex::new(initially_signaled),
                condvar: std::sync::Condvar::new(),
            })
        }
        /// # Safety
        /// スタブではハンドルを使わない。
        pub unsafe fn from_handle_value(_value: HandleValue, auto_reset: bool) -> Self {
            Self {
                auto_reset,
                state: std::sync::Mutex::new(false),
                condvar: std::sync::Condvar::new(),
            }
        }
        pub fn handle_value(&self) -> HandleValue {
            0
        }
        pub fn is_auto_reset(&self) -> bool {
            self.auto_reset
        }
        /// スタブ: プロセス間ハンドル受け渡しは Windows の概念のため Unsupported。
        pub fn duplicate_to_process(&self, _target_pid: u32) -> Result<HandleValue> {
            Err(WinError::Unsupported)
        }
        pub fn make_inheritable(&self) -> Result<()> {
            Err(WinError::Unsupported)
        }
        pub fn set(&self) -> Result<()> {
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            *g = true;
            self.condvar.notify_one();
            Ok(())
        }
        pub fn wait_timeout(&self, timeout: Duration) -> bool {
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if *g {
                *g = false;
                return true;
            }
            let (mut g2, _t) = self.condvar.wait_timeout(g, timeout).unwrap();
            if *g2 {
                *g2 = false;
                true
            } else {
                false
            }
        }
    }
    pub fn spawn_inheriting(_cmdline: &str) -> Result<HandleValue> {
        Err(WinError::Unsupported)
    }
    pub fn wait_process(_h: HandleValue, _t: Duration) -> Option<u32> {
        None
    }
    pub fn spawn_suspended(_cmdline: &str) -> Result<SpawnedProcess> {
        Err(WinError::Unsupported)
    }
    pub fn resume_main_thread(_thread: HandleValue) -> Result<u32> {
        Err(WinError::Unsupported)
    }
    pub fn open_process_for_injection(_pid: u32) -> Result<HandleValue> {
        Err(WinError::Unsupported)
    }
    pub fn process_exited(_process: HandleValue) -> Result<bool> {
        Err(WinError::Unsupported)
    }
    pub fn close_handle_value(_v: HandleValue) {}
    pub fn duplicate_handle_to_process(
        _handle_value: HandleValue,
        _target_pid: u32,
    ) -> Result<HandleValue> {
        Err(WinError::Unsupported)
    }
    pub fn write_process_memory(
        _process: HandleValue,
        _dest: usize,
        _src: *const u8,
        _len: usize,
    ) -> Result<()> {
        Err(WinError::Unsupported)
    }
    pub fn read_process_memory(
        _process: HandleValue,
        _src: usize,
        _dest: *mut u8,
        _len: usize,
    ) -> Result<()> {
        Err(WinError::Unsupported)
    }
    pub fn remote_call(_process: HandleValue, _start: usize, _param: usize) -> Result<u32> {
        Err(WinError::Unsupported)
    }
    pub fn remote_load_library(_process: HandleValue, _dll_path: &str) -> Result<()> {
        Err(WinError::Unsupported)
    }
    pub fn module_base(_pid: u32, _module_name: &str) -> Result<usize> {
        Err(WinError::Unsupported)
    }
    /// スタブ: プロセス一覧は Windows の概念のため Unsupported。
    pub fn enumerate_processes() -> Result<Vec<(u32, u32)>> {
        Err(WinError::Unsupported)
    }
    pub fn remote_alloc(_process: HandleValue, _len: usize) -> Result<usize> {
        Err(WinError::Unsupported)
    }
    pub fn remote_free(_process: HandleValue, _addr: usize) {}
    pub fn terminate_process(_process: HandleValue, _exit_code: u32) -> Result<()> {
        Err(WinError::Unsupported)
    }
    pub fn process_exit_code(_process: HandleValue) -> Result<Option<u32>> {
        Err(WinError::Unsupported)
    }
    pub fn process_creation_time(_process: HandleValue) -> Result<u64> {
        Err(WinError::Unsupported)
    }
}

pub use imp::{
    close_handle_value, duplicate_handle_to_process, enumerate_processes, module_base,
    open_process_for_injection, process_creation_time, process_exit_code, process_exited,
    read_process_memory, remote_alloc, remote_call, remote_free, remote_load_library,
    resume_main_thread, spawn_inheriting, spawn_suspended, terminate_process, wait_process,
    write_process_memory, EventObject, SharedMapping,
};

/// プロセス単位の通知イベント群。data_ready は auto-reset。
pub struct ProcessNotify {
    pub data_ready: EventObject,
}
impl ProcessNotify {
    pub fn new() -> Result<Self> {
        Ok(Self {
            data_ready: EventObject::new(true, false)?,
        })
    }
    pub fn notify_data_ready(&self) -> Result<()> {
        self.data_ready.set()
    }
    /// 2ms 再確認付きで待つ。通知を取りこぼしても再確認で必ず戻る。
    ///
    /// 1 回の待機スライスは「その反復で待つ長さ」であり、毎回
    /// `policy.interval` を上限に、残り時間で切り取る (R4)。累積経過を
    /// `ReCheckPolicy::wait_timeout` (待機開始からの経過に対する残り) に
    /// 渡すと、interval 経過後にスライスが 0 になり、ゼロ待機の
    /// ビジーループになるため、ここでは使わない。
    pub fn wait_with_recheck(
        &self,
        policy: ReCheckPolicy,
        mut recheck: impl FnMut() -> bool,
        total_timeout: Duration,
    ) -> bool {
        let start = std::time::Instant::now();
        loop {
            if recheck() {
                return true;
            }
            let waited = start.elapsed();
            if waited >= total_timeout {
                return recheck();
            }
            let slice = policy.interval.min(total_timeout - waited);
            if self.data_ready.wait_timeout(slice) && recheck() {
                return true;
            }
        }
    }
}

/// Ring 単位の空き通知。
pub struct RingNotify {
    pub space_available: EventObject,
}
impl RingNotify {
    pub fn new() -> Result<Self> {
        Ok(Self {
            space_available: EventObject::new(true, false)?,
        })
    }
    pub fn notify_space(&self) -> Result<()> {
        self.space_available.set()
    }
    /// Host→Agent の受け渡し: `space_available` イベントを対象プロセスへ
    /// DuplicateHandle で渡す（A68）。返した値は対象プロセス側のハンドル値で、
    /// Agent は `EventObject::from_handle_value` で取り込む。Windows 以外は
    /// Unsupported（スタブにプロセス間の実体が無いため）。
    pub fn duplicate_space_to_process(&self, target_pid: u32) -> Result<HandleValue> {
        self.space_available.duplicate_to_process(target_pid)
    }
}

/// Host 側: 回収で空きができ、書き手が空き待ち中なら `space_available` を SetEvent する。
/// 書き手は待機の意思表示＋全順序フェンスの後に空きを再確認しているので、この通知と
/// 再確認の組合せで空き待ちの取りこぼしが起きない。
///
/// # Safety
/// `control_base` は Control 領域の先頭を指し、呼び出し中有効であること。
pub unsafe fn notify_space_if_writer_waiting(
    control_base: *const u8,
    notify: &RingNotify,
) -> Result<bool> {
    if shirusu_transport::layout::writer_waiting(control_base) {
        notify.notify_space()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 書き手の待機を `space_available` イベントで実現する `Clock`。
/// `bounded_wait` は `Clock::sleep` を 50µs スライスで呼ぶ。実 sleep だと空きが
/// できても次のスライス境界まで起きないが、この Clock では回収時の SetEvent で
/// 即座に起きる（ベンチマーク A65 の選定結果: Event）。
/// Windows の `WaitForSingleObject` は ms 単位のため、タイムアウトは 1ms へ
/// 切り上げる。待機上限の判定は `now_ticks`（実時間）で行うため、上限を大きく
/// 超えて待つことはない。`space_available` は auto-reset で、待機 1 回につき
/// シグナルを 1 回消費する（Ring 単位で書き手は 1 人の前提）。
pub struct EventClock {
    notify: Arc<RingNotify>,
    origin: Instant,
    calls: AtomicU64,
}
impl EventClock {
    pub fn new(notify: Arc<RingNotify>) -> Self {
        Self {
            notify,
            origin: Instant::now(),
            calls: AtomicU64::new(0),
        }
    }
    pub fn sleep_calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}
impl shirusu_transport::Clock for EventClock {
    fn now_ticks(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64
    }
    fn ticks_per_second(&self) -> u64 {
        1_000_000_000
    }
    fn sleep(&self, dur: Duration) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        // イベントが立ていれば即復帰する。立っていなければタイムアウトまで待つ。
        let wait = dur.max(Duration::from_millis(1));
        let _ = self.notify.space_available.wait_timeout(wait);
    }
}

/// 本物の QPC を返すイベント時刻源 (レビュー第2回・項目8)。
///
/// Descriptor の `timestamp_qpc` はプロセス間で比較できることが仕様の
/// 要求であり、Windows では `QueryPerformanceCounter` の値そのものが
/// それに当たる。周波数は `QueryPerformanceFrequency` で取得して保持
/// する (起動後に変わらない値)。待機実測用の `Clock` とは別系統で、
/// Agent は Writer 構築時にこちらを `TimestampSource` として渡す。
/// Windows 以外では transport の既定時刻源へ委譲する (API 形のスタブ)。
pub struct QpcTimestampSource {
    frequency: u64,
    #[cfg(not(windows))]
    fallback: shirusu_transport::SystemTimestampSource,
}
impl QpcTimestampSource {
    pub fn new() -> Self {
        Self {
            frequency: qpc_frequency(),
            #[cfg(not(windows))]
            fallback: shirusu_transport::SystemTimestampSource::new(),
        }
    }
}
impl Default for QpcTimestampSource {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(windows)]
fn qpc_frequency() -> u64 {
    use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;
    let mut f: i64 = 0;
    let ok = unsafe { QueryPerformanceFrequency(&mut f) };
    if ok != 0 && f > 0 {
        f as u64
    } else {
        // QPF が失敗する環境は実質無いが、0 除算を避けるための保険。
        1_000_000_000
    }
}
#[cfg(not(windows))]
fn qpc_frequency() -> u64 {
    1_000_000_000
}
impl shirusu_transport::TimestampSource for QpcTimestampSource {
    fn now_qpc(&self) -> u64 {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Performance::QueryPerformanceCounter;
            let mut v: i64 = 0;
            let ok = unsafe { QueryPerformanceCounter(&mut v) };
            if ok != 0 && v > 0 {
                v as u64
            } else {
                0
            }
        }
        #[cfg(not(windows))]
        {
            shirusu_transport::TimestampSource::now_qpc(&self.fallback)
        }
    }
    fn frequency(&self) -> u64 {
        self.frequency
    }
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;
    #[test]
    fn injection_handle_can_wait_for_process_exit() {
        // Missing PROCESS_SYNCHRONIZE used to make WAIT_FAILED look like
        // "still running", hanging child-tree capture after the child exited.
        let own = open_process_for_injection(std::process::id()).unwrap();
        assert!(!process_exited(own).unwrap());
        close_handle_value(own);
        let child = spawn_suspended("cmd.exe /C exit 0").unwrap();
        let handle = open_process_for_injection(child.pid).unwrap();
        resume_main_thread(child.thread).unwrap();
        assert_eq!(wait_process(child.process, Duration::from_secs(5)), Some(0));
        close_handle_value(child.thread);
        assert!(process_exited(handle).unwrap());
        close_handle_value(handle);
        assert!(
            process_exited(0).is_err(),
            "invalid handle must not mean alive"
        );
    }

    #[test]
    fn exit_status_preserves_live_nonzero_and_still_active_codes() {
        let own = open_process_for_injection(std::process::id()).unwrap();
        assert_eq!(process_exit_code(own).unwrap(), None);
        close_handle_value(own);
        for code in [0, 37, 259] {
            let child = spawn_suspended(&format!("cmd.exe /C exit {code}")).unwrap();
            let handle = open_process_for_injection(child.pid).unwrap();
            resume_main_thread(child.thread).unwrap();
            assert_eq!(
                wait_process(child.process, Duration::from_secs(5)),
                Some(code)
            );
            close_handle_value(child.thread);
            assert_eq!(process_exit_code(handle).unwrap(), Some(code));
            // Querying the status must not close the borrowed handle.
            assert_eq!(process_exit_code(handle).unwrap(), Some(code));
            close_handle_value(handle);
        }
        assert!(process_exit_code(0).is_err());
    }

    #[test]
    fn mapping_and_event_roundtrip() {
        let m = SharedMapping::create(4096).unwrap();
        unsafe { std::ptr::write_bytes(m.as_ptr(), 0xAB, 16) };
        assert_eq!(m.as_slice()[0], 0xAB);
        let e = EventObject::new(true, false).unwrap();
        assert!(e.is_auto_reset());
        assert!(!e.wait_timeout(Duration::from_millis(1)));
        e.set().unwrap();
        assert!(e.wait_timeout(Duration::from_millis(100)));
        assert!(!e.wait_timeout(Duration::from_millis(1)));
    }
    #[test]
    fn duplicate_handle_to_self_process() {
        let m = SharedMapping::create(2048).unwrap();
        let pid = std::process::id();
        let dup = m.duplicate_to_process(pid).unwrap();
        assert!(dup != 0);
    }
    #[test]
    fn restricted_mapping_roundtrip() {
        // 現在のユーザーだけに開ける DACL 付き Mapping が作れて使えること。
        let m = SharedMapping::create_restricted(4096).unwrap();
        unsafe { std::ptr::write_bytes(m.as_ptr(), 0x5A, 16) };
        assert_eq!(m.as_slice()[0], 0x5A);
        assert_eq!(m.len(), 4096);
    }
    #[test]
    fn duplicate_event_to_self_process_signals_across_handle() {
        // A68 の DuplicateHandle 経路: 自プロセスへ複製したハンドルから作った
        // EventObject で、元の EventObject の SetEvent を観測できること。
        let e = EventObject::new(true, false).unwrap();
        let dup_value = e.duplicate_to_process(std::process::id()).unwrap();
        assert_ne!(dup_value, 0);
        let dup = unsafe { EventObject::from_handle_value(dup_value, true) };
        assert!(!dup.wait_timeout(Duration::from_millis(1)));
        e.set().unwrap();
        assert!(dup.wait_timeout(Duration::from_millis(100)));
        // auto-reset: 複製側の待機がシグナルを消費したので、元側ももう立っていない。
        assert!(!e.wait_timeout(Duration::from_millis(1)));
    }
    #[test]
    fn duplicate_ring_notify_space_to_self_process() {
        // レビュー第5回 #1 の対側: RingNotify の space イベントも自プロセスへ
        // 複製でき、非ゼロのハンドル値が返ること (スタブ版テストの Windows 側)。
        let notify = RingNotify::new().unwrap();
        let dup = notify
            .duplicate_space_to_process(std::process::id())
            .unwrap();
        assert_ne!(dup, 0);
    }
}

#[cfg(test)]
mod portable_tests {
    use super::*;
    #[test]
    fn positive_waits_round_up_without_using_infinite() {
        assert_eq!(wait_timeout_millis(Duration::ZERO), 0);
        assert_eq!(wait_timeout_millis(Duration::from_nanos(1)), 1);
        assert_eq!(wait_timeout_millis(Duration::from_micros(999)), 1);
        assert_eq!(wait_timeout_millis(Duration::from_millis(1)), 1);
        assert_eq!(wait_timeout_millis(Duration::from_micros(1001)), 2);
        assert_eq!(wait_timeout_millis(Duration::MAX), u32::MAX - 1);
    }
    #[test]
    fn qpc_timestamp_source_is_monotonic_with_stable_frequency() {
        use shirusu_transport::TimestampSource as _;
        let src = QpcTimestampSource::new();
        let freq = src.frequency();
        assert!(freq > 0);
        assert_eq!(src.frequency(), freq, "frequency must be stable");
        let a = src.now_qpc();
        let b = src.now_qpc();
        assert!(b >= a, "QPC stamps must be monotonic: {b} < {a}");
        // 別のインスタンスでも同じ時刻系 (プロセス間で比較可能な前提)。
        let other = QpcTimestampSource::new();
        assert_eq!(other.frequency(), freq);
        assert!(other.now_qpc() >= a);
    }
    #[test]
    fn wait_with_recheck_recovers_missed_notification() {
        let notify = ProcessNotify::new().unwrap();
        let mut calls = 0;
        let found = notify.wait_with_recheck(
            ReCheckPolicy::default(),
            || {
                calls += 1;
                calls >= 3
            },
            Duration::from_millis(50),
        );
        assert!(found);
    }
    #[test]
    fn wait_with_recheck_does_not_busy_loop() {
        // R4: 累積経過時間を ReCheckPolicy::wait_timeout (interval - waited) に
        // 渡すと、2ms 経過後はスライスが 0 になり、ゼロ待機のまま
        // total_timeout まで再確認だけが猛烈に回る (ビジーループ)。
        // 修正後は反復ごとに interval を上限に待つため、再確認は
        // 約 total/interval 回 (100ms / 2ms = 約 50 回) に収まる。
        let notify = ProcessNotify::new().unwrap();
        let calls = AtomicU64::new(0);
        let start = std::time::Instant::now();
        let found = notify.wait_with_recheck(
            ReCheckPolicy::default(),
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                false
            },
            Duration::from_millis(100),
        );
        assert!(!found, "no data and no notification -> false after timeout");
        assert!(
            start.elapsed() >= Duration::from_millis(90),
            "must wait out the total timeout"
        );
        let n = calls.load(Ordering::Relaxed);
        assert!(n < 200, "recheck called {n} times in 100ms: busy loop");
    }
    #[test]
    fn stub_mapping_has_requested_len() {
        let m = SharedMapping::create(128).unwrap();
        assert_eq!(m.len(), 128);
    }

    /// L05: プロセス一覧の列挙。Windows では自プロセスが含まれ、
    /// Windows 以外では Unsupported を返す（スタブ）。
    #[test]
    fn enumerate_processes_lists_self_on_windows() {
        let list = enumerate_processes();
        #[cfg(windows)]
        {
            let list = list.expect("enumerate_processes on windows");
            let me = std::process::id();
            assert!(
                list.iter().any(|(pid, _)| *pid == me),
                "own pid {me} must be in the process list"
            );
            assert!(!list.is_empty());
        }
        #[cfg(not(windows))]
        {
            assert!(matches!(list, Err(WinError::Unsupported)));
        }
    }
    #[test]
    fn notify_space_only_when_writer_waiting() {
        let cfg = shirusu_transport::RingConfig::new(8, 256);
        let region = shirusu_transport::ring::SharedRegion::new(cfg, 1, 1);
        let notify = RingNotify::new().unwrap();
        assert!(!unsafe { notify_space_if_writer_waiting(region.base(), &notify) }.unwrap());
        shirusu_transport::layout::store(
            region.base(),
            shirusu_transport::layout::OFF_WRITER_WAITING,
            1,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(unsafe { notify_space_if_writer_waiting(region.base(), &notify) }.unwrap());
    }
    #[test]
    fn event_clock_wakes_on_space_available() {
        use shirusu_transport::Clock;
        let notify = Arc::new(RingNotify::new().unwrap());
        let clock = EventClock::new(Arc::clone(&notify));
        // イベントが立っていなければタイムアウトまで待つ（即復帰しない）。
        let start = std::time::Instant::now();
        clock.sleep(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(5));
        // イベントを立てれば、長い待機でも即復帰する。
        notify.notify_space().unwrap();
        let start = std::time::Instant::now();
        clock.sleep(Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_millis(50));
        assert_eq!(clock.sleep_calls(), 2);
    }
    #[cfg(not(windows))]
    #[test]
    fn duplicate_space_to_process_is_unsupported_on_stub() {
        // Linux スタブにプロセス間の実体は無い。Windows 実機では
        // `duplicate_event_to_self_process_signals_across_handle` と
        // `duplicate_ring_notify_space_to_self_process` が通ること。
        // (レビュー第5回 #1: cfg が無いと Windows 実機で Ok が返り失敗する)
        let notify = RingNotify::new().unwrap();
        assert_eq!(
            notify.duplicate_space_to_process(std::process::id()),
            Err(WinError::Unsupported)
        );
    }
    #[test]
    fn mapping_create_zero_len_is_invalid_argument() {
        // Windows 実装でも len==0 は CreateFileMappingW の前に弾く
        assert!(matches!(
            SharedMapping::create(0),
            Err(WinError::InvalidArgument("len"))
        ));
    }
    #[test]
    fn win_error_display_strings() {
        assert_eq!(
            WinError::Unsupported.to_string(),
            "not supported on this platform"
        );
        assert_eq!(
            WinError::OsError {
                api: "CreateEventW",
                code: 5
            }
            .to_string(),
            "CreateEventW failed with OS error 5"
        );
        assert_eq!(
            WinError::InvalidArgument("len").to_string(),
            "invalid argument: len"
        );
    }
    #[cfg(not(windows))]
    #[test]
    fn stub_event_manual_reset_and_initially_signaled() {
        let e = EventObject::new(false, true).unwrap();
        assert!(!e.is_auto_reset());
        assert!(
            e.wait_timeout(Duration::from_millis(10)),
            "initially signaled"
        );
        // スタブの wait は auto/manual を区別せずシグナルを消費する
        // (Windows 実機の manual-reset とは違う、スタブの割り切り)。
        assert!(!e.wait_timeout(Duration::from_millis(1)));
        e.set().unwrap();
        assert!(e.wait_timeout(Duration::from_millis(10)));
    }
    #[test]
    fn event_clock_ticks_and_monotonicity() {
        use shirusu_transport::Clock;
        let notify = Arc::new(RingNotify::new().unwrap());
        let clock = EventClock::new(notify);
        assert_eq!(clock.ticks_per_second(), 1_000_000_000);
        let a = clock.now_ticks();
        let b = clock.now_ticks();
        assert!(b >= a);
        assert_eq!(clock.sleep_calls(), 0);
    }
    #[test]
    fn process_notify_recheck_timeout_returns_false() {
        let notify = ProcessNotify::new().unwrap();
        let start = std::time::Instant::now();
        let found = notify.wait_with_recheck(
            ReCheckPolicy::default(),
            || false,
            Duration::from_millis(30),
        );
        assert!(!found, "no data and no notification -> false after timeout");
        assert!(start.elapsed() >= Duration::from_millis(25));
    }
    #[test]
    fn process_notify_set_event_wakes_wait() {
        let notify = ProcessNotify::new().unwrap();
        notify.notify_data_ready().unwrap();
        // data_ready を消費する待機が成功すれば recheck が呼ばれる
        let found =
            notify.wait_with_recheck(ReCheckPolicy::default(), || true, Duration::from_millis(10));
        assert!(found);
    }
    #[cfg(not(windows))]
    #[test]
    fn stub_process_operations_are_unsupported() {
        let m = SharedMapping::create(64).unwrap();
        assert!(matches!(
            SharedMapping::create_restricted(64),
            Err(WinError::Unsupported)
        ));
        assert!(matches!(
            unsafe { SharedMapping::from_handle_value(0, 64) },
            Err(WinError::Unsupported)
        ));
        assert_eq!(m.handle_value(), 0);
        assert!(!m.is_empty());
        assert!(matches!(
            m.duplicate_to_process(1),
            Err(WinError::Unsupported)
        ));
        assert!(matches!(m.make_inheritable(), Err(WinError::Unsupported)));
        let e = EventObject::new(true, false).unwrap();
        assert!(matches!(
            e.duplicate_to_process(1),
            Err(WinError::Unsupported)
        ));
        assert!(matches!(e.make_inheritable(), Err(WinError::Unsupported)));
        assert!(matches!(
            spawn_inheriting("true"),
            Err(WinError::Unsupported)
        ));
        assert_eq!(wait_process(0, Duration::from_millis(1)), None);
        // ハンドル値から作ったスタブイベントは独立した新しいイベントとして動く
        let stub = unsafe { EventObject::from_handle_value(123, true) };
        assert_eq!(stub.handle_value(), 0);
        assert!(!stub.wait_timeout(Duration::from_millis(1)));
        stub.set().unwrap();
        assert!(stub.wait_timeout(Duration::from_millis(10)));
    }
}
