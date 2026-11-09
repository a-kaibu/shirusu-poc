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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinError {
    Unsupported,
    OsError { api: &'static str, code: u32 },
    InvalidArgument(&'static str),
}
impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "not supported on this platform"),
            Self::OsError { api, code } => write!(f, "{api} failed with OS error {code}"),
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
        }
    }
}
impl std::error::Error for WinError {}
pub type Result<T> = std::result::Result<T, WinError>;

/// OS ハンドルの数値表現（プロセス間受け渡し用）。共有メモリに置く値ではない。
pub type HandleValue = usize;

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
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    (len >> 32) as u32,
                    (len & 0xFFFF_FFFF) as u32,
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
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    &restricted.sa,
                    PAGE_READWRITE,
                    (len >> 32) as u32,
                    (len & 0xFFFF_FFFF) as u32,
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
            let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
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
        let handle = h(process_handle_value as usize);
        let ms = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
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
}

pub use imp::{spawn_inheriting, wait_process, EventObject, SharedMapping};

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
            let slice = policy.wait_timeout(waited).min(total_timeout - waited);
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

#[cfg(all(windows, test))]
mod tests {
    use super::*;
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
}

#[cfg(test)]
mod portable_tests {
    use super::*;
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
    fn stub_mapping_has_requested_len() {
        let m = SharedMapping::create(128).unwrap();
        assert_eq!(m.len(), 128);
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
    #[test]
    fn duplicate_space_to_process_is_unsupported_on_stub() {
        // Linux スタブにプロセス間の実体は無い。Windows 実機では
        // `duplicate_event_to_self_process_signals_across_handle` が通ること。
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
