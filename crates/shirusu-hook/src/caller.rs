//! L23: フック時の呼び出し元分類。
//!
//! Detour の入口で、API 呼び出しの戻りアドレスから呼び出し元の
//! モジュールを特定する。記録ポリシーは呼び出し先で判断する。
//! Runtime から Windows API へ入る呼び出しは標準でも記録する。
//!
//! 戻りアドレスは `RtlCaptureStackBackTrace` で取る（安定 Rust で使える
//! 公開 API。`_ReturnAddress` 相当の組み込みは安定版に無い）。Detour・
//! prepare・ヘルパ自体は Agent DLL の `.text` にあるため、歩いた
//! フレームのうち DLL 自身の `AllocationBase` と同じものを飛ばし、最初
//! に DLL 外へ出たアドレスを呼び出し元の戻りアドレスとする。prepare の
//! インライン化の有無に依存しない。
//!
//! モジュール一覧は DLL 起動時に 1 回作り、呼び出し元が一覧に無い場合
//! にだけ再列挙する（遅れてロードされたモジュールへの追随。再列挙は
//! 500ms に 1 回まで）。DLL 側の分類は名前だけに依存する Runtime 判定
//! が目的のため、署名検証はしない（System32 のモジュールは Unknown に
//! なるが、抑制の判定は Runtime かどうかだけを見るため影響しない。
//! 署名付きの正式な分類は Host 側の列挙が Trace へ残す）。
//!
//! 現行の IAT フックはメインモジュール限定のため、Detour へ到達する
//! 呼び出し元の戻りアドレスは実質つねに exe 内（Application）になる。
//! そのため抑制の実動はフック範囲の拡大（L01 Inline Hook）後に初めて
//! 観測できる。ここでは強制の仕組みとその単体検証を用意し、E2E での
//! 抑制確認は L01 待ちとして traceability に明記する。

use shirusu_trace::module::{classify_module, is_api_set_contract, ModuleClass, ModuleEvidence};
use shirusu_transport_win::modules::LoadedModule;
use std::time::{Duration, Instant};

/// 呼び出し元分類のためのモジュール範囲 1 件。`[base, end)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleRange {
    pub base: u64,
    pub end: u64,
    pub class: ModuleClass,
}

/// `ranges`（base の昇順）から `addr` を含む範囲の分類を引く。
/// 見つからなければ `None`（呼び出し元不明 → 記録する）。
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

/// ロード済みモジュールの一覧から呼び出し元分類用の範囲列を作る。
/// `resolve_api_set` は API Set 契約名を実装モジュールへ解決する関数
/// （`shirusu_transport_win::resolve_api_set_contract`）。
/// DLL 側の分類は署名を使わない（前掲の理由）ため、証拠の
/// `microsoft_signed` は常に `None` である。
pub fn build_caller_ranges(
    modules: &[LoadedModule],
    resolve_api_set: &dyn Fn(&str) -> Option<String>,
) -> Vec<ModuleRange> {
    let mut ranges: Vec<ModuleRange> = modules
        .iter()
        .map(|m| {
            let mut evidence = ModuleEvidence::new(&m.path);
            if is_api_set_contract(&m.path) {
                if let Some(impl_path) = resolve_api_set(&m.path) {
                    evidence = evidence.implementation(&impl_path);
                }
            }
            let class = classify_module(&evidence).class;
            ModuleRange {
                base: m.base_address as u64,
                end: m.base_address as u64 + m.size_bytes as u64,
                class,
            }
        })
        .collect();
    ranges.sort_by_key(|r| r.base);
    ranges
}

/// 再列挙の間隔。遅れてロードされたモジュールへの追随は、呼び出し元が
/// 一覧に無い場合にだけ行い、連続する再列挙はこの間隔で抑える。
pub const CALLER_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// 呼び出し元分類のためのモジュール一覧（スナップショット）。
#[derive(Debug)]
pub struct CallerModules {
    ranges: Vec<ModuleRange>,
    last_refresh: Option<Instant>,
}

impl Default for CallerModules {
    fn default() -> Self {
        Self::new()
    }
}

impl CallerModules {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            last_refresh: None,
        }
    }

    /// 一覧が空でないこと（初期化済みかどうか）。
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// `addr` の分類を引く。一覧に無ければ `None`。
    pub fn classify(&self, addr: usize) -> Option<ModuleClass> {
        classify_address(&self.ranges, addr)
    }

    /// 再列挙が必要な間隔が空いたか。未初期化の場合は真。
    pub fn needs_refresh(&self) -> bool {
        match self.last_refresh {
            None => true,
            Some(t) => t.elapsed() >= CALLER_REFRESH_INTERVAL,
        }
    }

    /// 一覧を作り直す。Windows では自プロセスのモジュールを列挙する。
    /// 列挙に失敗した場合は従来の一覧を残す。Windows 以外では何もしない。
    /// 呼び出しのたびに `last_refresh` を更新し、失敗時の連続再試行を抑える。
    pub fn refresh(&mut self) {
        self.last_refresh = Some(Instant::now());
        #[cfg(windows)]
        {
            if let Ok(modules) =
                shirusu_transport_win::modules::enumerate_modules(std::process::id())
            {
                self.ranges = build_caller_ranges(&modules, &|name| {
                    shirusu_transport_win::modules::resolve_api_set_contract(name)
                });
            }
        }
        #[cfg(not(windows))]
        {
            let _ = &self.ranges;
        }
    }
}

/// 呼び出し元の戻りアドレスを返す。Detour から見て、Agent DLL 自身の
/// フレームを飛ばした最初の DLL 外のアドレスである。取れなければ
/// `None`（呼び出し元不明 → 記録する）。
#[cfg(windows)]
#[inline(never)]
pub fn caller_return_address() -> Option<usize> {
    let self_base = allocation_base(caller_return_address as *const () as usize)?;
    return_address_outside_module(self_base)
}

#[cfg(windows)]
fn allocation_base(addr: usize) -> Option<usize> {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let n = unsafe {
        VirtualQuery(
            addr as *const core::ffi::c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    (n != 0).then_some(mbi.AllocationBase as usize)
}

#[cfg(windows)]
#[inline(never)]
fn return_address_outside_module(self_base: usize) -> Option<usize> {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;
    let mut frames = [std::ptr::null_mut::<c_void>(); 8];
    // SAFETY: frames は 8 要素分の領域。0 フレームをスキップし、
    // 最大 8 フレームを取る。
    let captured = unsafe {
        RtlCaptureStackBackTrace(
            0,
            frames.len() as u32,
            frames.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    for i in 0..captured as usize {
        let addr = frames[i] as usize;
        if addr == 0 {
            continue;
        }
        // 自身のモジュール内のフレームは飛ばす。VirtualQuery が
        // 失敗したアドレスは別モジュールとして扱う（fail-open）。
        match allocation_base(addr) {
            Some(base) if base == self_base => continue,
            _ => return Some(addr),
        }
    }
    None
}

/// Windows 以外では呼び出し元は取れない。
#[cfg(not(windows))]
pub fn caller_return_address() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // 呼び出し元不明は記録する（fail-open）。
        assert!(!should_suppress_target(None, false));
        assert!(!should_suppress_target(None, true));
    }

    #[test]
    fn build_caller_ranges_classifies_by_name() {
        let modules = vec![
            LoadedModule::new(0x1000, 0x1000, r"C:\Windows\System32\ucrtbase.dll"),
            LoadedModule::new(0x3000, 0x1000, r"C:\tools\app\game.exe"),
            LoadedModule::new(0x2000, 0x1000, r"C:\Windows\System32\kernel32.dll"),
        ];
        // 署名を使わないため kernel32 は Unknown になる（抑制の判定には
        // 影響しない）。Runtime と Application は名前で決まる。
        let ranges = build_caller_ranges(&modules, &|_| None);
        assert_eq!(ranges.len(), 3);
        // base の昇順に揃うこと。
        assert!(ranges.windows(2).all(|w| w[0].base <= w[1].base));
        assert_eq!(
            classify_address(&ranges, 0x1000),
            Some(ModuleClass::Runtime)
        );
        assert_eq!(
            classify_address(&ranges, 0x2000),
            Some(ModuleClass::Unknown)
        );
        assert_eq!(
            classify_address(&ranges, 0x3000),
            Some(ModuleClass::Application)
        );
    }

    #[test]
    fn build_caller_ranges_resolves_api_set_contract() {
        let modules = vec![LoadedModule::new(
            0x1000,
            0x1000,
            "api-ms-win-core-file-l1-1-0.dll",
        )];
        // 解決できれば実装モジュールの分類（署名なしのため Unknown）。
        // 解決できなければ Unknown のまま。いずれも Unknown だが、
        // 解決の有無で reason が変わるわけではなく、範囲の有無が同じ
        // ことを確認する（解決の成否は分類器のテストで担保する）。
        let resolved = build_caller_ranges(&modules, &|_| {
            Some(r"C:\Windows\System32\kernel32.dll".into())
        });
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            classify_address(&resolved, 0x1000),
            Some(ModuleClass::Unknown)
        );
        let unresolved = build_caller_ranges(&modules, &|_| None);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            classify_address(&unresolved, 0x1000),
            Some(ModuleClass::Unknown)
        );
    }

    #[test]
    fn caller_modules_needs_refresh_before_first_refresh() {
        let mut cm = CallerModules::new();
        assert!(cm.is_empty());
        assert_eq!(cm.len(), 0);
        assert!(cm.needs_refresh());
        assert_eq!(cm.classify(0x1000), None);
        cm.refresh();
        // refresh は試行のたびに last_refresh を更新するため、直後は
        // 再列挙不要になる（Windows 以外では一覧は空のまま）。
        assert!(!cm.needs_refresh());
        #[cfg(windows)]
        {
            assert!(!cm.is_empty(), "own process modules must be listed");
        }
        #[cfg(not(windows))]
        {
            assert!(cm.is_empty());
        }
    }

    /// Windows での実働テスト。CI の windows.ps1（`cargo test
    /// --workspace`）と windows-x86.ps1（`cargo test -p shirusu-hook`）
    /// で実行される。
    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        #[test]
        fn caller_return_address_points_into_test_binary() {
            // This unit test is linked into the exe, not the injected DLL.
            // Excluding the exe would intentionally skip the test's own frames.
            // Use kernel32 as the excluded module to exercise native stack capture
            // and the same module-selection code with a known external caller.
            let kernel32: Vec<u16> = "kernel32.dll".encode_utf16().chain([0]).collect();
            let excluded = unsafe { GetModuleHandleW(kernel32.as_ptr()) } as usize;
            assert_ne!(excluded, 0);
            let addr = return_address_outside_module(excluded).expect("return address captured");
            // 呼び出し元はこのテスト関数自身（テストバイナリ内）であること。
            // SAFETY: NULL は実行ファイル自身のハンドルを返す。
            let exe_base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
            assert_ne!(exe_base, 0);
            // テストバイナリの AllocationBase と一致すること。
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                unsafe { std::mem::zeroed() };
            // SAFETY: mbi は MEMORY_BASIC_INFORMATION 分の領域。
            let n = unsafe {
                windows_sys::Win32::System::Memory::VirtualQuery(
                    addr as *const std::ffi::c_void,
                    &mut mbi,
                    std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(
                    ),
                )
            };
            assert_ne!(n, 0, "VirtualQuery on the return address");
            assert_eq!(
                mbi.AllocationBase as usize, exe_base,
                "caller must be inside the test binary"
            );
        }

        #[test]
        fn public_caller_capture_never_returns_its_own_module() {
            let self_base = allocation_base(caller_return_address as *const () as usize).unwrap();
            if let Some(address) = caller_return_address() {
                assert_ne!(allocation_base(address), Some(self_base));
            }
        }

        #[test]
        fn refresh_lists_own_process_and_classifies_runtime() {
            let mut cm = CallerModules::new();
            cm.refresh();
            assert!(!cm.is_empty());
            // 実行ファイル自身は Application。
            // SAFETY: NULL は実行ファイル自身のハンドルを返す。
            let exe_base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
            assert_eq!(
                cm.classify(exe_base + 0x1000),
                Some(ModuleClass::Application),
                "test binary must classify as application"
            );
            // ucrtbase.dll がロードされていれば Runtime。
            let wide: Vec<u16> = "ucrtbase.dll".encode_utf16().chain([0]).collect();
            // SAFETY: wide は NUL 終端の有効な文字列。
            let ucrt = unsafe { GetModuleHandleW(wide.as_ptr()) };
            if !ucrt.is_null() {
                assert_eq!(
                    cm.classify(ucrt as usize + 0x1000),
                    Some(ModuleClass::Runtime),
                    "ucrtbase.dll must classify as runtime"
                );
            }
        }
    }
}
