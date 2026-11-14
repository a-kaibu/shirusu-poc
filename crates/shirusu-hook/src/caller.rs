//! 標準の呼び出し境界（L23）: 呼び出し元アドレスによる Windows 内部起点の除外。
//!
//! overview「記録境界とモジュール分類」の標準記録は、Application と Runtime
//! から Windows の公開 API へ入る呼び出しである。Inline Hook は呼び出し元を
//! 区別せずに全呼び出しを捕捉するため、Windows 自身の内部呼び出し
//! （`SHCreateStreamOnFileEx` 内部の `CreateFileW`、Windows DLL 内部の
//! `HeapAlloc` など）も Detour に届く。ここではそれを呼び出し元アドレスで
//! 判定する。
//!
//! 仕組み:
//! 1. API 表の Inline Hook はパッチ先を Detour ではなく**入口スタブ**にする。
//!    スタブはトランポリン領域の中に置き、入口時点の戻りアドレス
//!    （`[rsp]` / `[esp]`）を TEB の TLS スロットへ書いてから Detour へ
//!    分岐する。x64 は `r11`、x86 は `eax` だけを使う。どちらも MS の
//!    呼び出し規約で引数に使われない揮発レジスタであり、スタックは
//!    変更しない（[`entry_stub_bytes`]）。
//! 2. Detour は入口の最初に [`take_entry_caller`] でスロットを読み、0 へ戻す。
//!    これより前に Hook 対象 API を呼ぶ処理はないため、入れ子の呼び出しが
//!    値を上書きすることはない。スロットが 0 の場合はスタブを通らない経路
//!    （メインモジュールの IAT、スタブを置けなかった Inline Hook）であり、
//!    従来どおり記録する。IAT はメインモジュール（Application）だけを
//!    パッチするため、呼び出し元は Application と確定している。
//! 3. 戻りアドレスを含むイメージを [`classify_caller`] で分類する。結果は
//!    イメージ範囲ごとにキャッシュし、DLL のアンロード通知で無効化する。
//!    非イメージ（JIT 生成コード等）は Unknown とし記録する（fail-open）。
//! 4. 呼び出し元が Windows で、詳細調査モードでない場合だけ記録せず素通しに
//!    する（[`should_suppress_caller`]）。Windows → アプリのコールバック内で
//!    アプリが呼んだ API は、呼び出し元が Application なので記録される。
//!
//! Agent 内の Windows 判定は、実際にロードされた `kernel32.dll` と同じ
//! Windows ディレクトリ配下の `System32` / `SysWOW64` / `WinSxS` に
//! マップされたイメージである（デバイスパスで比較し、名前の一部一致は
//! 使わない）。Host の Trace 上の分類は署名確認付き（`classify_module`）で
//! あり、Agent 内では Detour からの署名検証（WinVerifyTrust）を行わない。
//! 既知の実行基盤（UCRT / VC++ Runtime / CLR）は配置に関係なく Runtime、
//! 対象 EXE 自身は配置に関係なく Application とする。`--module-class` の
//! 上書きは現在 Agent の境界判定へ渡していない。

use shirusu_trace::module::{is_runtime_module, ModuleClass};

/// 呼び出し元分類のためのモジュール範囲 1 件。`[base, end)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleRange {
    pub base: u64,
    pub end: u64,
    pub class: ModuleClass,
}

/// `ranges`（base の昇順）から `addr` を含む範囲の分類を引く。
/// 見つからなければ `None`。
pub fn classify_address(ranges: &[ModuleRange], addr: usize) -> Option<ModuleClass> {
    let addr = addr as u64;
    // base <= addr となる最後の範囲が候補。base の昇順が前提。
    let idx = ranges.partition_point(|r| r.base <= addr);
    if idx == 0 {
        return None;
    }
    let r = &ranges[idx - 1];
    if addr < r.end {
        Some(r.class)
    } else {
        None
    }
}

/// 呼び出し先の分類から、今回の呼び出しを記録しないかを決める。
/// 呼び出し先が Runtime で `record_runtime_apis` が無効な場合にだけ真。不明
/// （`None`）の場合は記録する（fail-open）。
pub fn should_suppress_target(class: Option<ModuleClass>, record_runtime_apis: bool) -> bool {
    !record_runtime_apis && class == Some(ModuleClass::Runtime)
}

/// 呼び出し元の分類から、標準の境界の外（Windows 内部起点）かを決める。
/// 詳細調査モードでは Windows 内部の呼び出しも親子付きで記録するため偽。
/// 呼び出し元不明（`None` / Unknown）は記録する（fail-open）。
pub fn should_suppress_caller(class: Option<ModuleClass>, detailed_mode: bool) -> bool {
    !detailed_mode && class == Some(ModuleClass::Windows)
}

/// Windows ディレクトリ（デバイスパス、小文字、末尾 `\` なし）から、
/// Windows モジュールとみなす配置の接頭辞を作る。
pub fn windows_image_prefixes(windows_dir: &str) -> Vec<String> {
    let dir = windows_dir
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    ["system32", "syswow64", "winsxs"]
        .iter()
        .map(|sub| format!("{dir}\\{sub}\\"))
        .collect()
}

/// `kernel32.dll` の実際のパスから Windows ディレクトリを得る
/// （`...\Windows\System32\kernel32.dll` → `...\Windows`）。
pub fn windows_dir_from_kernel32(kernel32_path: &str) -> Option<String> {
    let norm = kernel32_path.replace('/', "\\");
    let (system_dir, file) = norm.rsplit_once('\\')?;
    if !file.eq_ignore_ascii_case("kernel32.dll") {
        return None;
    }
    let (windows_dir, sub) = system_dir.rsplit_once('\\')?;
    if !(sub.eq_ignore_ascii_case("system32") || sub.eq_ignore_ascii_case("syswow64")) {
        return None;
    }
    (!windows_dir.is_empty()).then(|| windows_dir.to_string())
}

/// 呼び出し元イメージ 1 件の分類。`is_main_module` は対象 EXE 自身か。
/// 実行基盤（名前）→ Runtime、対象 EXE → Application、Windows 配置
/// → Windows、それ以外 → Application の順に判定する。
pub fn classify_caller_image(path: &str, is_main_module: bool, prefixes: &[String]) -> ModuleClass {
    let norm = path.replace('/', "\\");
    let file = norm.rsplit('\\').next().unwrap_or(&norm);
    if is_runtime_module(file) {
        return ModuleClass::Runtime;
    }
    if is_main_module {
        return ModuleClass::Application;
    }
    let lower = norm.to_lowercase();
    if prefixes.iter().any(|p| lower.starts_with(p.as_str())) {
        ModuleClass::Windows
    } else {
        ModuleClass::Application
    }
}

/// 呼び出し元範囲のキャッシュ。base の昇順で重なりを持たない。
#[derive(Debug, Default)]
pub struct CallerCache {
    ranges: Vec<ModuleRange>,
    /// 登録中の Unknown (非イメージ) 範囲の数 (P2-2)。
    unknown: usize,
}

/// Unknown (JIT など非イメージ) の範囲を覚える上限 (2026-11-14 レビュー
/// P2-2)。JIT が領域を作り直すアプリでは無制限に増え、挿入のたびに配列を
/// ずらしていた。超えたら Unknown の範囲だけを捨てて覚え直す。
pub const MAX_UNKNOWN_RANGES: usize = 1024;

impl CallerCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ranges: Vec::with_capacity(capacity),
            unknown: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn classify(&self, addr: usize) -> Option<ModuleClass> {
        classify_address(&self.ranges, addr)
    }

    /// `addr` を含む範囲。
    pub fn range_of(&self, addr: usize) -> Option<ModuleRange> {
        let a = addr as u64;
        let idx = self.ranges.partition_point(|r| r.base <= a);
        let r = *self.ranges.get(idx.checked_sub(1)?)?;
        (a < r.end).then_some(r)
    }

    /// 範囲を登録する。重なる既存の範囲は古い情報として取り除く。
    /// 空の範囲は登録しない。
    pub fn insert(&mut self, range: ModuleRange) {
        if range.end <= range.base {
            return;
        }
        self.remove_overlapping(range.base, range.end);
        if range.class == ModuleClass::Unknown {
            if self.unknown >= MAX_UNKNOWN_RANGES {
                self.ranges.retain(|r| r.class != ModuleClass::Unknown);
                self.unknown = 0;
            }
            self.unknown += 1;
        }
        let idx = self.ranges.partition_point(|r| r.base < range.base);
        self.ranges.insert(idx, range);
    }

    /// `[base, end)` と重なる範囲を取り除く（アンロード通知）。確保はしない。
    pub fn remove_overlapping(&mut self, base: u64, end: u64) {
        let mut removed_unknown = 0;
        self.ranges.retain(|r| {
            let keep = r.end <= base || r.base >= end;
            if !keep && r.class == ModuleClass::Unknown {
                removed_unknown += 1;
            }
            keep
        });
        self.unknown -= removed_unknown;
    }
}

/// TEB 内の `TlsSlots[0]` の位置。x64 は gs 基準、x86 は fs 基準。
pub const TEB_TLS_SLOTS_X64: u32 = 0x1480;
pub const TEB_TLS_SLOTS_X86: u32 = 0xE10;
/// TEB に直接置かれる TLS スロット数（`TLS_MINIMUM_AVAILABLE`）。
/// これ以上の index は拡張領域にあり、スタブから直接書けない。
pub const TEB_DIRECT_TLS_SLOTS: u32 = 64;

/// TLS index から TEB 内のスロットの位置を求める。直接書けない index は `None`。
pub fn tls_slot_offset(index: u32, bitness: u32) -> Option<u32> {
    if index >= TEB_DIRECT_TLS_SLOTS {
        return None;
    }
    match bitness {
        64 => Some(TEB_TLS_SLOTS_X64 + index * 8),
        32 => Some(TEB_TLS_SLOTS_X86 + index * 4),
        _ => None,
    }
}

/// 入口スタブのうち、戻りアドレスをスロットへ保存する部分の長さ。
pub fn entry_capture_len(bitness: u32) -> usize {
    if bitness == 64 {
        13
    } else {
        9
    }
}

/// `stub` に置く入口スタブのバイト列。戻りアドレスを `slot_offset` の
/// TLS スロットへ書き、`detour` へ分岐する。
///
/// x64: `mov r11, [rsp]` / `mov gs:[slot], r11` / `jmp detour`
/// x86: `mov eax, [esp]` / `mov fs:[slot], eax` / `jmp detour`
pub fn entry_stub_bytes(stub: u64, detour: u64, bitness: u32, slot_offset: u32) -> Vec<u8> {
    let mut code = Vec::with_capacity(32);
    if bitness == 64 {
        code.extend_from_slice(&[0x4C, 0x8B, 0x1C, 0x24]);
        code.extend_from_slice(&[0x65, 0x4C, 0x89, 0x1C, 0x25]);
    } else {
        code.extend_from_slice(&[0x8B, 0x04, 0x24]);
        code.extend_from_slice(&[0x64, 0xA3]);
    }
    code.extend_from_slice(&slot_offset.to_le_bytes());
    debug_assert_eq!(code.len(), entry_capture_len(bitness));
    let jump = crate::inline::jump_bytes(stub + code.len() as u64, detour, bitness);
    code.extend_from_slice(&jump);
    code
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{OnceLock, RwLock};

    /// 0 = スタブ無効。TEB 内のスロットの位置。
    static ENTRY_SLOT_OFFSET: AtomicU32 = AtomicU32::new(0);
    static ENTRY_SLOT: OnceLock<Option<u32>> = OnceLock::new();
    static CACHE: RwLock<CallerCache> = RwLock::new(CallerCache {
        ranges: Vec::new(),
        unknown: 0,
    });
    /// 表を書き換えるたびに進む番号 (P2-2)。スレッドごとの直前の範囲は、
    /// この番号が変わっていない間だけ使う。
    static CACHE_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    thread_local! {
        /// 直前に当たった範囲: (base, end, class code, generation)。
        /// 共有 RwLock を呼び出しごとに取らない (読みロックでも共有
        /// キャッシュラインへ書き込む)。Copy だけで解放処理を持たない。
        static LAST_RANGE: std::cell::Cell<(u64, u64, u32, u64)> =
            const { std::cell::Cell::new((0, 0, 0, u64::MAX)) };
    }
    static BOUNDARY: OnceLock<Option<Boundary>> = OnceLock::new();

    struct Boundary {
        prefixes: Vec<String>,
        main_module: usize,
    }

    const BITNESS: u32 = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };

    /// 入口スタブ用の TLS スロットを確保する（プロセスで 1 回）。
    /// スロットはプロセス終了まで解放しない。トランポリン領域と同じく、
    /// 残ったスタブが後から書く可能性があるためである。
    pub fn entry_slot_offset() -> Option<u32> {
        *ENTRY_SLOT.get_or_init(|| {
            use windows_sys::Win32::System::Threading::{TlsAlloc, TlsFree, TLS_OUT_OF_INDEXES};
            // SAFETY: 引数なしの確保。全スレッドの値は 0 で始まる。
            let index = unsafe { TlsAlloc() };
            if index == TLS_OUT_OF_INDEXES {
                return None;
            }
            match tls_slot_offset(index, BITNESS) {
                Some(offset) => {
                    // Prepare the cache's storage before any Detour can observe it.
                    if let Ok(mut cache) = CACHE.write() {
                        cache.ranges.reserve(256);
                    }
                    ENTRY_SLOT_OFFSET.store(offset, Ordering::Release);
                    Some(offset)
                }
                None => {
                    // SAFETY: 今確保した index で、どのスタブにも渡していない。
                    unsafe { TlsFree(index) };
                    None
                }
            }
        })
    }

    /// Detour 入口で呼ぶ。入口スタブが保存した戻りアドレスを取り出し、
    /// スロットを 0 に戻す。スタブを通らない経路では 0。
    #[inline(always)]
    pub fn take_entry_caller() -> usize {
        let offset = ENTRY_SLOT_OFFSET.load(Ordering::Relaxed) as usize;
        if offset == 0 {
            return 0;
        }
        let value: usize;
        // SAFETY: offset は TlsAlloc で確保した TEB 内のスロットの位置で、
        // 現在のスレッドの TEB を読み書きするだけである。
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov {v}, qword ptr gs:[{o}]",
                "mov qword ptr gs:[{o}], 0",
                o = in(reg) offset,
                v = out(reg) value,
                options(nostack, preserves_flags),
            );
        }
        #[cfg(target_arch = "x86")]
        unsafe {
            core::arch::asm!(
                "mov {v}, dword ptr fs:[{o}]",
                "mov dword ptr fs:[{o}], 0",
                o = in(reg) offset,
                v = out(reg) value,
                options(nostack, preserves_flags),
            );
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            value = 0;
        }
        value
    }

    fn mapped_file_name(address: usize) -> Option<String> {
        use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut buf = [0u16; 1024];
        // SAFETY: buf は 1024 要素の書き込み可能な領域。
        let n = unsafe {
            K32GetMappedFileNameW(
                GetCurrentProcess(),
                address as *const core::ffi::c_void,
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        } as usize;
        (n != 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
    }

    fn boundary() -> Option<&'static Boundary> {
        BOUNDARY
            .get_or_init(|| {
                use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
                let name: Vec<u16> = "kernel32.dll".encode_utf16().chain([0]).collect();
                // SAFETY: name は NUL 終端。kernel32 は常にロード済み。
                let kernel32 = unsafe { GetModuleHandleW(name.as_ptr()) } as usize;
                // SAFETY: NULL はメインモジュール。
                let main_module = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
                if kernel32 == 0 {
                    return None;
                }
                let path = mapped_file_name(kernel32)?;
                let windows_dir = windows_dir_from_kernel32(&path)?;
                register_unload_notification();
                Some(Boundary {
                    prefixes: windows_image_prefixes(&windows_dir),
                    main_module,
                })
            })
            .as_ref()
    }

    /// 境界判定の準備（Windows ディレクトリの特定とアンロード通知の登録）。
    /// Agent の初期化スレッドで呼ぶ。失敗した場合は境界判定を行わない。
    pub fn prepare_boundary() -> bool {
        boundary().is_some()
    }

    fn resolve(address: usize, boundary: &Boundary) -> ModuleRange {
        use windows_sys::Win32::System::Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_IMAGE,
        };
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: mbi は MEMORY_BASIC_INFORMATION 分の領域。
        let n = unsafe {
            VirtualQuery(
                address as *const core::ffi::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        let unknown = |base: usize, end: usize| ModuleRange {
            base: base as u64,
            end: end as u64,
            class: ModuleClass::Unknown,
        };
        if n == 0 {
            return unknown(address, address + 1);
        }
        let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
        let allocation = mbi.AllocationBase as usize;
        if mbi.Type != MEM_IMAGE || allocation == 0 {
            // 非イメージ（JIT 等）。この確保の範囲を Unknown として覚える。
            // 後で別のものがマップされても、記録する側（fail-open）に倒れる。
            let base = if allocation != 0 && allocation <= address {
                allocation
            } else {
                mbi.BaseAddress as usize
            };
            return unknown(base, region_end.max(address + 1));
        }
        let Some(size) = image_size(allocation) else {
            return unknown(allocation, region_end);
        };
        let class = match mapped_file_name(allocation) {
            Some(path) => classify_caller_image(
                &path,
                allocation == boundary.main_module,
                &boundary.prefixes,
            ),
            None => ModuleClass::Unknown,
        };
        ModuleRange {
            base: allocation as u64,
            end: (allocation + size) as u64,
            class,
        }
    }

    /// PE ヘッダの SizeOfImage。呼び出し元を含むイメージはマップ済み。
    fn image_size(base: usize) -> Option<usize> {
        use crate::capture::MemoryReader;
        let memory = crate::engine::ProcessMemory;
        let mut dos = [0u8; 64];
        if !memory.read_exact(base as u64, &mut dos) || dos[..2] != *b"MZ" {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(dos[60..64].try_into().ok()?) as u64;
        // Signature (4) + FileHeader (20) + OptionalHeader.SizeOfImage at +56.
        let mut header = [0u8; 4 + 20 + 60];
        if !memory.read_exact(base as u64 + e_lfanew, &mut header) || header[..4] != *b"PE\0\0" {
            return None;
        }
        let size = u32::from_le_bytes(header[24 + 56..24 + 60].try_into().ok()?) as usize;
        (size != 0).then_some(size)
    }

    /// 呼び出し元アドレスの分類。キャッシュに無ければイメージを調べて登録する。
    /// 境界判定の準備ができていなければ `None`（記録する）。
    pub fn classify_caller(address: usize) -> Option<ModuleClass> {
        if address == 0 {
            return None;
        }
        use std::sync::atomic::Ordering;
        let generation = CACHE_GENERATION.load(Ordering::Acquire);
        let addr = address as u64;
        if let Ok((base, end, class, seen)) = LAST_RANGE.try_with(std::cell::Cell::get) {
            if seen == generation && base <= addr && addr < end {
                return Some(ModuleClass::from_code(class));
            }
        }
        let remember = |r: &ModuleRange| {
            let _ = LAST_RANGE.try_with(|c| c.set((r.base, r.end, r.class.code(), generation)));
        };
        if let Ok(cache) = CACHE.read() {
            if let Some(range) = cache.range_of(address) {
                remember(&range);
                return Some(range.class);
            }
        }
        let boundary = BOUNDARY.get()?.as_ref()?;
        // Query outside the lock: no loader lock or cache lock is held here.
        let range = resolve(address, boundary);
        if let Ok(mut cache) = CACHE.write() {
            cache.insert(range);
            CACHE_GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        Some(range.class)
    }

    #[repr(C)]
    struct DllNotificationData {
        flags: u32,
        full_dll_name: *const core::ffi::c_void,
        base_dll_name: *const core::ffi::c_void,
        dll_base: *mut core::ffi::c_void,
        size_of_image: u32,
    }

    const LDR_DLL_NOTIFICATION_REASON_UNLOADED: u32 = 2;

    unsafe extern "system" fn on_dll_notification(
        reason: u32,
        data: *const DllNotificationData,
        _context: *mut core::ffi::c_void,
    ) {
        if reason != LDR_DLL_NOTIFICATION_REASON_UNLOADED || data.is_null() {
            return;
        }
        // SAFETY: ローダーが渡す通知データ。呼び出し中は有効。
        let (base, size) = unsafe { ((*data).dll_base as u64, (*data).size_of_image as u64) };
        // Under the loader lock: retain() does not allocate, and no thread holds
        // the cache lock while waiting for the loader lock.
        if let Ok(mut cache) = CACHE.write() {
            cache.remove_overlapping(base, base + size.max(1));
            CACHE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    type LdrRegisterDllNotificationFn = unsafe extern "system" fn(
        u32,
        unsafe extern "system" fn(u32, *const DllNotificationData, *mut core::ffi::c_void),
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> i32;

    /// アンロードされたイメージのキャッシュを捨てる通知を登録する。Agent DLL
    /// はプロセス終了までアンロードしないため、登録は解除しない。登録に
    /// 失敗した場合、アンロード後に同じ範囲へ別のイメージが入ると古い分類が
    /// 残る（Coverage には現れない既知の制約）。
    fn register_unload_notification() {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain([0]).collect();
        // SAFETY: name は NUL 終端。
        let ntdll = unsafe { GetModuleHandleW(name.as_ptr()) };
        if ntdll.is_null() {
            return;
        }
        // SAFETY: ntdll はロード済み、名前は NUL 終端。
        let Some(proc) =
            (unsafe { GetProcAddress(ntdll, c"LdrRegisterDllNotification".as_ptr().cast()) })
        else {
            return;
        };
        // SAFETY: 公開されている LdrRegisterDllNotification のシグネチャ。
        let register: LdrRegisterDllNotificationFn = unsafe { std::mem::transmute(proc) };
        let mut cookie = std::ptr::null_mut();
        // SAFETY: コールバックは 'static。cookie は書き込み可能。
        let _ = unsafe { register(0, on_dll_notification, std::ptr::null_mut(), &mut cookie) };
    }

    #[cfg(test)]
    pub(super) fn cached_len() -> usize {
        CACHE.read().map(|c| c.len()).unwrap_or(0)
    }
}

#[cfg(windows)]
pub use win::{classify_caller, entry_slot_offset, prepare_boundary, take_entry_caller};

/// Windows 以外ではスタブも呼び出し元分類もない。
#[cfg(not(windows))]
pub fn take_entry_caller() -> usize {
    0
}

#[cfg(not(windows))]
pub fn classify_caller(_address: usize) -> Option<ModuleClass> {
    None
}

#[cfg(not(windows))]
pub fn entry_slot_offset() -> Option<u32> {
    None
}

#[cfg(not(windows))]
pub fn prepare_boundary() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Decoder, DecoderOptions, Register};

    fn ranges() -> Vec<ModuleRange> {
        vec![
            ModuleRange {
                base: 0x1000,
                end: 0x1200,
                class: ModuleClass::Windows,
            },
            ModuleRange {
                base: 0x2000,
                end: 0x2100,
                class: ModuleClass::Runtime,
            },
            ModuleRange {
                base: 0x3000,
                end: 0x4000,
                class: ModuleClass::Application,
            },
        ]
    }

    /// P2-2: Unknown の範囲は上限を超えたら捨てて覚え直し、イメージの
    /// 範囲は残す。
    #[test]
    fn unknown_ranges_are_bounded() {
        let mut c = CallerCache::default();
        c.insert(ModuleRange {
            base: 0x10,
            end: 0x20,
            class: ModuleClass::Windows,
        });
        for i in 0..(MAX_UNKNOWN_RANGES as u64 + 5) {
            let base = 0x1_0000 + i * 0x100;
            c.insert(ModuleRange {
                base,
                end: base + 0x10,
                class: ModuleClass::Unknown,
            });
        }
        assert!(c.len() <= MAX_UNKNOWN_RANGES + 1, "{}", c.len());
        assert_eq!(c.classify(0x15), Some(ModuleClass::Windows));
        let last = 0x1_0000 + (MAX_UNKNOWN_RANGES as u64 + 4) * 0x100;
        assert_eq!(
            c.range_of(last as usize + 1).map(|r| r.class),
            Some(ModuleClass::Unknown)
        );
        c.remove_overlapping(0, u64::MAX);
        assert!(c.is_empty());
    }

    #[test]
    fn classify_address_hits_and_boundaries() {
        let r = ranges();
        assert_eq!(classify_address(&r, 0x1000), Some(ModuleClass::Windows));
        assert_eq!(classify_address(&r, 0x11ff), Some(ModuleClass::Windows));
        // end は半開区間。
        assert_eq!(classify_address(&r, 0x1200), None);
        assert_eq!(classify_address(&r, 0x1500), None);
        assert_eq!(classify_address(&r, 0x2000), Some(ModuleClass::Runtime));
        assert_eq!(classify_address(&r, 0x20ff), Some(ModuleClass::Runtime));
        assert_eq!(classify_address(&r, 0x2100), None);
        assert_eq!(classify_address(&r, 0x3fff), Some(ModuleClass::Application));
        assert_eq!(classify_address(&r, 0x4000), None);
        assert_eq!(classify_address(&r, 0x0fff), None);
        assert_eq!(classify_address(&r, 0), None);
        assert_eq!(classify_address(&[], 0x1000), None);
    }

    #[test]
    fn should_suppress_only_runtime_targets_when_disabled() {
        assert!(should_suppress_target(Some(ModuleClass::Runtime), false));
        assert!(!should_suppress_target(Some(ModuleClass::Runtime), true));
        assert!(!should_suppress_target(Some(ModuleClass::Windows), false));
        assert!(!should_suppress_target(
            Some(ModuleClass::Application),
            false
        ));
        assert!(!should_suppress_target(Some(ModuleClass::Unknown), false));
        assert!(!should_suppress_target(None, false));
        assert!(!should_suppress_target(None, true));
    }

    #[test]
    fn caller_boundary_suppresses_only_windows_callers_outside_detailed_mode() {
        assert!(should_suppress_caller(Some(ModuleClass::Windows), false));
        assert!(!should_suppress_caller(Some(ModuleClass::Windows), true));
        for class in [
            ModuleClass::Application,
            ModuleClass::Runtime,
            ModuleClass::Unknown,
        ] {
            assert!(!should_suppress_caller(Some(class), false), "{class:?}");
        }
        assert!(!should_suppress_caller(None, false));
    }

    #[test]
    fn windows_dir_comes_from_the_loaded_kernel32_directory() {
        assert_eq!(
            windows_dir_from_kernel32(r"\Device\HarddiskVolume3\Windows\System32\KERNEL32.DLL"),
            Some(r"\Device\HarddiskVolume3\Windows".into())
        );
        assert_eq!(
            windows_dir_from_kernel32(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll"),
            Some(r"\Device\HarddiskVolume3\Windows".into())
        );
        assert_eq!(
            windows_dir_from_kernel32(r"C:\app\System32\kernel32.dll"),
            Some(r"C:\app".into()),
            "the directory is taken from the module the loader actually mapped"
        );
        assert_eq!(
            windows_dir_from_kernel32(r"C:\Windows\System32\user32.dll"),
            None
        );
        assert_eq!(windows_dir_from_kernel32(r"C:\Windows\kernel32.dll"), None);
        assert_eq!(windows_dir_from_kernel32("kernel32.dll"), None);
    }

    #[test]
    fn caller_image_classification_is_anchored_to_the_windows_directory() {
        let p = windows_image_prefixes(r"\Device\HarddiskVolume3\Windows\");
        let win = r"\Device\HarddiskVolume3\Windows";
        let class = |path: &str| classify_caller_image(path, false, &p);
        assert_eq!(
            class(&format!(r"{win}\System32\shcore.dll")),
            ModuleClass::Windows
        );
        assert_eq!(
            class(&format!(r"{win}\SYSTEM32\KernelBase.dll")),
            ModuleClass::Windows
        );
        assert_eq!(
            class(&format!(r"{win}\SysWOW64\user32.dll")),
            ModuleClass::Windows
        );
        assert_eq!(
            class(&format!(
                r"{win}\WinSxS\x86_microsoft.windows.common-controls\comctl32.dll"
            )),
            ModuleClass::Windows
        );
        // Runtime is decided by the module, even inside System32.
        assert_eq!(
            class(&format!(r"{win}\System32\ucrtbase.dll")),
            ModuleClass::Runtime
        );
        assert_eq!(
            class(&format!(r"{win}\System32\vcruntime140.dll")),
            ModuleClass::Runtime
        );
        // A directory merely named system32 elsewhere is not Windows.
        assert_eq!(
            class(r"\Device\HarddiskVolume3\app\system32\plugin.dll"),
            ModuleClass::Application
        );
        assert_eq!(
            class(r"\Device\HarddiskVolume4\Windows\System32\shcore.dll"),
            ModuleClass::Application,
            "another volume's Windows directory is not the loaded one"
        );
        assert_eq!(
            class(&format!(r"{win}\System32x\a.dll")),
            ModuleClass::Application
        );
        assert_eq!(
            class(&format!(r"{win}\notepad.exe")),
            ModuleClass::Application
        );
        // The target EXE stays Application even when it lives in System32.
        assert_eq!(
            classify_caller_image(&format!(r"{win}\System32\notepad.exe"), true, &p),
            ModuleClass::Application
        );
    }

    #[test]
    fn caller_cache_replaces_overlaps_and_forgets_unloaded_images() {
        let mut cache = CallerCache::with_capacity(4);
        assert!(cache.is_empty());
        for r in ranges().into_iter().rev() {
            cache.insert(r);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.classify(0x2050), Some(ModuleClass::Runtime));
        // A new image overlapping a stale entry replaces it.
        cache.insert(ModuleRange {
            base: 0x1100,
            end: 0x2080,
            class: ModuleClass::Application,
        });
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.classify(0x1000), None);
        assert_eq!(cache.classify(0x1100), Some(ModuleClass::Application));
        assert_eq!(cache.classify(0x3000), Some(ModuleClass::Application));
        cache.remove_overlapping(0x3800, 0x3900);
        assert_eq!(cache.classify(0x3000), None);
        assert_eq!(cache.len(), 1);
        cache.insert(ModuleRange {
            base: 5,
            end: 5,
            class: ModuleClass::Windows,
        });
        assert_eq!(cache.len(), 1, "empty ranges are not cached");
    }

    #[test]
    fn tls_slot_offsets_follow_the_teb_layout() {
        assert_eq!(tls_slot_offset(0, 64), Some(0x1480));
        assert_eq!(tls_slot_offset(5, 64), Some(0x1480 + 40));
        assert_eq!(tls_slot_offset(63, 32), Some(0xE10 + 252));
        assert_eq!(tls_slot_offset(64, 64), None);
        assert_eq!(tls_slot_offset(1, 16), None);
    }

    #[test]
    fn x64_entry_stub_saves_the_return_address_in_r11_and_jumps() {
        let stub = 0x7ff0_0000_0f00u64;
        let detour = 0x7ff0_1000_0000u64;
        let code = entry_stub_bytes(stub, detour, 64, 0x1488);
        let mut d = Decoder::with_ip(64, &code, stub, DecoderOptions::NONE);
        let load = d.decode();
        assert_eq!(load.code(), Code::Mov_r64_rm64);
        assert_eq!(load.op0_register(), Register::R11);
        assert_eq!(load.memory_base(), Register::RSP);
        assert_eq!(load.memory_displacement64(), 0);
        let store = d.decode();
        assert_eq!(store.code(), Code::Mov_rm64_r64);
        assert_eq!(store.segment_prefix(), Register::GS);
        assert_eq!(store.memory_base(), Register::None);
        assert_eq!(store.memory_displacement64(), 0x1488);
        assert_eq!(store.op1_register(), Register::R11);
        assert_eq!(d.position(), entry_capture_len(64));
        let jump = d.decode();
        assert_eq!(jump.near_branch_target(), detour);
        assert_eq!(d.position(), code.len());
        // A far detour still gets a complete absolute jump.
        let far = entry_stub_bytes(stub, 0x1000, 64, 0x1488);
        assert_eq!(far.len(), entry_capture_len(64) + 14);
    }

    #[test]
    fn x86_entry_stub_saves_the_return_address_in_eax_and_jumps() {
        let stub = 0x1000_0f00u64;
        let detour = 0x6000_0000u64;
        let code = entry_stub_bytes(stub, detour, 32, 0xE14);
        let mut d = Decoder::with_ip(32, &code, stub, DecoderOptions::NONE);
        let load = d.decode();
        assert_eq!(load.code(), Code::Mov_r32_rm32);
        assert_eq!(load.op0_register(), Register::EAX);
        assert_eq!(load.memory_base(), Register::ESP);
        let store = d.decode();
        assert_eq!(store.code(), Code::Mov_moffs32_EAX);
        assert_eq!(store.segment_prefix(), Register::FS);
        assert_eq!(store.memory_displacement64(), 0xE14);
        assert_eq!(d.position(), entry_capture_len(32));
        let jump = d.decode();
        assert_eq!(jump.near_branch_target(), detour);
        assert_eq!(d.position(), code.len());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_has_no_entry_caller() {
        assert_eq!(take_entry_caller(), 0);
        assert_eq!(classify_caller(0x1000), None);
        assert_eq!(entry_slot_offset(), None);
        assert!(!prepare_boundary());
    }

    /// Windows での実働テスト。CI の windows.ps1（`cargo test --workspace`）と
    /// windows-x86.ps1（`cargo test -p shirusu-hook`）で実行される。
    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        fn module(name: &str) -> usize {
            let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
            unsafe { GetModuleHandleW(wide.as_ptr()) as usize }
        }

        #[inline(never)]
        extern "system" fn report_entry_caller(a: usize, b: usize) -> usize {
            // Read first, as Detours do. Asserting here would abort across
            // the extern boundary; the test checks the consumed slot after return.
            let caller = take_entry_caller();
            std::hint::black_box(a.wrapping_add(b));
            caller
        }

        #[test]
        fn entry_stub_hands_the_callers_return_address_to_the_detour() {
            let offset = entry_slot_offset().expect("a direct TEB TLS slot");
            let bitness = if cfg!(target_pointer_width = "64") {
                64
            } else {
                32
            };
            let memory = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    0x1000,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            } as usize;
            assert_ne!(memory, 0);
            let code = entry_stub_bytes(
                memory as u64,
                report_entry_caller as *const () as usize as u64,
                bitness,
                offset,
            );
            unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), memory as *mut u8, code.len()) };
            let stub: extern "system" fn(usize, usize) -> usize =
                unsafe { std::mem::transmute(memory) };
            let caller = std::hint::black_box(stub)(1, 2);
            assert_eq!(take_entry_caller(), 0, "the first read consumes the slot");
            // Arguments and the return value pass through unchanged, and the
            // reported address is a return site in this test binary.
            let exe = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
            assert_ne!(caller, 0);
            assert!(
                caller > exe && caller < exe + 0x0400_0000,
                "caller {caller:#x} in test image at {exe:#x}"
            );
            assert_eq!(
                classify_caller_after_prepare(caller),
                Some(ModuleClass::Application)
            );
            // Calls that do not pass through a stub report no caller.
            assert_eq!(report_entry_caller(3, 4), 0);
            unsafe { VirtualFree(memory as *mut _, 0, MEM_RELEASE) };
        }

        fn classify_caller_after_prepare(address: usize) -> Option<ModuleClass> {
            assert!(prepare_boundary(), "Windows directory detected");
            classify_caller(address)
        }

        #[test]
        fn loaded_images_are_classified_by_their_mapping() {
            let kernelbase = module("kernelbase.dll");
            let kernel32 = module("kernel32.dll");
            let ntdll = module("ntdll.dll");
            assert_ne!(kernel32, 0);
            for base in [kernelbase, kernel32, ntdll] {
                if base != 0 {
                    assert_eq!(
                        classify_caller_after_prepare(base + 0x1000),
                        Some(ModuleClass::Windows),
                        "{base:#x}"
                    );
                }
            }
            let exe = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
            assert_eq!(
                classify_caller_after_prepare(exe + 0x1000),
                Some(ModuleClass::Application)
            );
            let ucrt = module("ucrtbase.dll");
            if ucrt != 0 {
                assert_eq!(
                    classify_caller_after_prepare(ucrt + 0x1000),
                    Some(ModuleClass::Runtime)
                );
            }
            let heap = Box::new([0u8; 64]);
            assert_eq!(
                classify_caller_after_prepare(heap.as_ptr() as usize),
                Some(ModuleClass::Unknown)
            );
            assert!(win::cached_len() >= 3);
            // Cached lookups return the same class.
            assert_eq!(
                classify_caller_after_prepare(kernel32 + 0x1000),
                Some(ModuleClass::Windows)
            );
        }
    }
}
