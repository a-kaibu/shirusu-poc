//! L23: ロード済みモジュールの列挙・署名検証・API Set 契約の解決（Windows 側）。
//!
//! - [`enumerate_modules`]: `EnumProcessModulesEx` +
//!   `GetModuleFileNameExW` + `GetModuleInformation` で、対象プロセスの
//!   全ロード済みモジュール（ベースアドレス・イメージサイズ・パス）を列挙する。
//! - [`verify_microsoft_signature`]: `WinVerifyTrust` で署名の有効性を
//!   確認し、署名者証明書の Organization 属性（OID 2.5.4.10）が
//!   大文字小文字を除いて "Microsoft Corporation" と全体一致することを
//!   確認する。失効確認は行わない（オフライン CI での遅延・失敗を避ける
//!   ため。分類に必要なのは「Microsoft 製であること」であり、失効状態
//!   ではない）。
//! - [`resolve_api_set_contract`]: ローダ経由で API Set 契約名を実装
//!   モジュールへ解決する。ローダは PEB の apisets スキーマを参照して
//!   契約名をホスト DLL へ写すため、`GetModuleHandleW(契約名)` は実装
//!   モジュールのハンドルを返し、`GetModuleFileNameW` で実装パスが
//!   得られる。スキーマを直接パースしないのは、スキーマ版（v2/v4/v6）の
//!   差異を OS に委ね、将来の版にも壊れないようにするためである。
//!   未ロードの名前は `None`（分類器は Unknown として扱う）。
//!
//! Windows 以外では同じ API 形のスタブとしてコンパイルでき、列挙と署名
//! 検証は `Unsupported`、契約解決は `None` を返す。

use crate::{Result, WinError};

/// 直前の OS エラーを `WinError::OsError` へ包む（`imp::last_err` と
/// 同じ形。`imp` は private のためここでは自前のものを使う）。
#[cfg(windows)]
fn last_err(api: &'static str) -> WinError {
    WinError::OsError {
        api,
        code: unsafe { windows_sys::Win32::Foundation::GetLastError() },
    }
}

/// ロード済みモジュール 1 件。`base_address` はイメージの先頭、
/// `size_bytes` は `MODULEINFO.SizeOfImage`（イメージ全体の大きさ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedModule {
    pub base_address: usize,
    pub size_bytes: u32,
    pub path: String,
}

impl LoadedModule {
    pub fn new(base_address: usize, size_bytes: u32, path: &str) -> Self {
        Self {
            base_address,
            size_bytes,
            path: path.to_string(),
        }
    }

    /// `[base_address, base_address + size_bytes)` に `addr` が入るか。
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base_address && (addr - self.base_address) < self.size_bytes as usize
    }
}

/// 対象プロセスの全ロード済みモジュールを列挙する。返値はベース
/// アドレスの昇順。対象プロセスが存在しない・開けない場合は Err。
#[cfg(windows)]
pub fn enumerate_modules(pid: u32) -> Result<Vec<LoadedModule>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    // SAFETY: OpenProcess の権限は列挙に必要な最小限（照会＋読み取り）。
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process.is_null() {
        return Err(last_err("OpenProcess"));
    }
    let result = (|| {
        let mut needed: u32 = 0;
        // 1 回目で必要バイト数を得る。モジュール数が 0 でも needed は
        // 0 になりうるため、失敗は戻り値で判定する。
        // SAFETY: バッファ無し・長さ 0 の問い合わせ。
        let ok = unsafe {
            EnumProcessModulesEx(
                process as HANDLE,
                std::ptr::null_mut(),
                0,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return Err(last_err("EnumProcessModulesEx"));
        }
        let count = (needed as usize) / std::mem::size_of::<HANDLE>();
        let mut handles = vec![0 as HANDLE; count.max(1)];
        // SAFETY: handles は count 分の領域。needed が 0 の場合は
        // 空のまま返す（モジュール無しはありえないが、失敗にしない）。
        let ok = unsafe {
            EnumProcessModulesEx(
                process as HANDLE,
                handles.as_mut_ptr(),
                needed,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return Err(last_err("EnumProcessModulesEx"));
        }
        let count = (needed as usize) / std::mem::size_of::<HANDLE>();
        handles.truncate(count);
        let mut out = Vec::with_capacity(handles.len());
        let mut name_buf = vec![0u16; 4096];
        for h in handles {
            // SAFETY: h は列挙で得た有効なモジュールハンドル。
            let n = unsafe {
                GetModuleFileNameExW(
                    process as HANDLE,
                    h,
                    name_buf.as_mut_ptr(),
                    name_buf.len() as u32,
                )
            };
            if n == 0 {
                continue;
            }
            let path = String::from_utf16_lossy(&name_buf[..n as usize]);
            let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
            // SAFETY: info は MODULEINFO 分の領域。
            let ok = unsafe {
                GetModuleInformation(
                    process as HANDLE,
                    h,
                    &mut info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
            };
            let size = if ok != 0 { info.SizeOfImage } else { 0 };
            out.push(LoadedModule::new(info.lpBaseOfDll as usize, size, &path));
        }
        // GetModuleFileNameExW はパス順ではなくロード順に近い並びを返す
        // ため、呼び出し側の二分探索のためにベースアドレス順へ揃える。
        out.sort_by_key(|m| m.base_address);
        Ok(out)
    })();
    // SAFETY: OpenProcess で得た有効なハンドル。
    unsafe { CloseHandle(process as HANDLE) };
    result
}

/// Windows 以外のスタブ：プロセス間列挙はできない。
#[cfg(not(windows))]
pub fn enumerate_modules(_pid: u32) -> Result<Vec<LoadedModule>> {
    Err(WinError::Unsupported)
}

/// `path` のファイルが Microsoft 製の署名付きファイルか。署名が無い・
/// 壊れている・署名者が Microsoft でない・ファイルが読めない場合は
/// すべて false（「確認できない」は分類器の Unknown へ直結する）。
/// 失敗理由の区別はここではしない（呼び出し側が区別する必要は無い）。
#[cfg(windows)]
pub fn verify_microsoft_signature(path: &str) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Cryptography::Catalog::*;
    use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_ATTR_TYPE};
    use windows_sys::Win32::Security::WinTrust::*;

    // Reject embedded NULs rather than verifying a different, truncated path.
    if path.encode_utf16().any(|c| c == 0) {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();

    // Inspect the signer belonging to the successful trust operation BEFORE CLOSE.
    // The provider owns the certificate; neither free it nor query a second PKCS#7.
    unsafe fn verify(data: &mut WINTRUST_DATA) -> bool {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status =
            unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, data as *mut _ as *mut _) };
        let microsoft = if status == 0 {
            let provider = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
            let signer = if provider.is_null() {
                std::ptr::null_mut()
            } else {
                unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) }
            };
            if signer.is_null()
                || unsafe {
                    (*signer).dwError != 0
                        || (*signer).csCertChain == 0
                        || (*signer).pasCertChain.is_null()
                }
            {
                false
            } else {
                let cert = unsafe { &*(*signer).pasCertChain };
                if cert.pCert.is_null() || cert.dwError != 0 {
                    false
                } else {
                    // Compare the complete organization attribute, not a substring
                    // of a display name (which could name an unrelated publisher).
                    let oid = b"2.5.4.10\0";
                    let n = unsafe {
                        CertGetNameStringW(
                            cert.pCert,
                            CERT_NAME_ATTR_TYPE,
                            0,
                            oid.as_ptr() as *const _,
                            std::ptr::null_mut(),
                            0,
                        )
                    };
                    if n <= 1 || n > 4096 {
                        false
                    } else {
                        let mut name = vec![0u16; n as usize];
                        let actual = unsafe {
                            CertGetNameStringW(
                                cert.pCert,
                                CERT_NAME_ATTR_TYPE,
                                0,
                                oid.as_ptr() as *const _,
                                name.as_mut_ptr(),
                                n,
                            )
                        };
                        actual == n
                            && String::from_utf16_lossy(&name[..n as usize - 1])
                                .eq_ignore_ascii_case("Microsoft Corporation")
                    }
                }
            }
        } else {
            false
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(std::ptr::null_mut(), &mut action, data as *mut _ as *mut _);
        }
        microsoft
    }
    fn trust_data() -> WINTRUST_DATA {
        // SAFETY: all optional pointers/flags start at zero; required fields follow.
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        data
    }
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = trust_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut info;
    if unsafe { verify(&mut data) } {
        return true;
    }

    // System DLLs can be catalog-signed. Verify membership of this file's hash,
    // not merely the signature on a catalog with a matching publisher.
    for algorithm in ["SHA256", "SHA1"] {
        let algorithm: Vec<u16> = algorithm.encode_utf16().chain([0]).collect();
        let mut admin = 0;
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                std::ptr::null(),
                algorithm.as_ptr(),
                std::ptr::null(),
                0,
            )
        } == 0
        {
            continue;
        }
        let mut len = 0;
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file.as_raw_handle(),
                &mut len,
                std::ptr::null_mut(),
                0,
            );
        }
        let mut matched = false;
        if len > 0 && len <= 4096 {
            let mut hash = vec![0u8; len as usize];
            if unsafe {
                CryptCATAdminCalcHashFromFileHandle2(
                    admin,
                    file.as_raw_handle(),
                    &mut len,
                    hash.as_mut_ptr(),
                    0,
                )
            } != 0
            {
                hash.truncate(len as usize);
                let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
                let tag: Vec<u16> = tag.encode_utf16().chain([0]).collect();
                let mut catalog = unsafe {
                    CryptCATAdminEnumCatalogFromHash(
                        admin,
                        hash.as_ptr(),
                        len,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                while catalog != 0 {
                    let mut catalog_info: CATALOG_INFO = unsafe { std::mem::zeroed() };
                    catalog_info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                    if unsafe { CryptCATCatalogInfoFromContext(catalog, &mut catalog_info, 0) } != 0
                    {
                        let mut info: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
                        info.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                        info.pcwszCatalogFilePath = catalog_info.wszCatalogFile.as_ptr();
                        info.pcwszMemberTag = tag.as_ptr();
                        info.pcwszMemberFilePath = wide.as_ptr();
                        info.hMemberFile = file.as_raw_handle();
                        info.pbCalculatedFileHash = hash.as_mut_ptr();
                        info.cbCalculatedFileHash = len;
                        info.hCatAdmin = admin;
                        let mut data = trust_data();
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.Anonymous.pCatalog = &mut info;
                        matched = unsafe { verify(&mut data) };
                    }
                    if matched {
                        unsafe {
                            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                        }
                        break;
                    }
                    // Enumeration consumes the previous context, including at end.
                    catalog = unsafe {
                        CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, &mut catalog)
                    };
                }
            }
        }
        unsafe {
            CryptCATAdminReleaseContext(admin, 0);
        }
        if matched {
            return true;
        }
    }
    false
}

/// Windows 以外のスタブ：署名は確認できない。
#[cfg(not(windows))]
pub fn verify_microsoft_signature(_path: &str) -> bool {
    false
}

/// API Set 契約名（`api-ms-win-*` / `ext-ms-win-*`）を実装モジュールの
/// パスへ解決する。ローダが apisets スキーマを参照して契約名をホスト
/// DLL へ写すため、`GetModuleHandleW` は実装モジュールのハンドルを
/// 返す。契約でない名前（既にロード済みの実モジュール名）に対しては
/// そのモジュール自身のパスを返し、未ロードの名前には `None` を返す。
/// 契約名かどうかは呼び出し側が `is_api_set_contract` で判定する。
#[cfg(windows)]
pub fn resolve_api_set_contract(name: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: wide は NUL 終端の有効な文字列。GetModuleHandleW は
    // ロード済みモジュールへのハンドルを返す（ロードはしない）。
    let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 4096];
    // SAFETY: handle は GetModuleHandleW が返した有効なハンドル。
    let n = unsafe { GetModuleFileNameW(handle as HMODULE, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n as usize]))
}

/// Windows 以外のスタブ：解決できない。
#[cfg(not(windows))]
pub fn resolve_api_set_contract(_name: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_module_contains_is_half_open() {
        let m = LoadedModule::new(0x1000, 0x200, r"C:\Windows\System32\kernel32.dll");
        assert!(m.contains(0x1000));
        assert!(m.contains(0x11ff));
        assert!(!m.contains(0x1200));
        assert!(!m.contains(0x0fff));
        assert!(!m.contains(0));
    }

    #[test]
    fn loaded_module_new_keeps_fields() {
        let m = LoadedModule::new(0x7ff0_0000, 4096, "x.dll");
        assert_eq!(m.base_address, 0x7ff0_0000);
        assert_eq!(m.size_bytes, 4096);
        assert_eq!(m.path, "x.dll");
    }

    #[cfg(not(windows))]
    #[test]
    fn stubs_report_unsupported() {
        assert!(matches!(enumerate_modules(1), Err(WinError::Unsupported)));
        assert!(!verify_microsoft_signature(
            r"C:\Windows\System32\kernel32.dll"
        ));
        assert_eq!(
            resolve_api_set_contract("api-ms-win-core-file-l1-1-0.dll"),
            None
        );
    }

    /// Windows での実働テスト。CI の windows.ps1（`cargo test
    /// --workspace`）と windows-x86.ps1（`cargo test -p
    /// shirusu-transport-win`）で実行される。
    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn enumerate_own_process_lists_system_modules() {
            let pid = std::process::id();
            let modules = enumerate_modules(pid).expect("enumerate own process");
            assert!(!modules.is_empty(), "own process has modules");
            // ベースアドレスの昇順であること。
            assert!(modules
                .windows(2)
                .all(|w| w[0].base_address <= w[1].base_address));
            // ntdll と kernel32 はどの Windows プロセスにもある。
            let names: Vec<String> = modules
                .iter()
                .map(|m| {
                    m.path
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                })
                .collect();
            assert!(names.iter().any(|n| n == "ntdll.dll"), "ntdll: {names:?}");
            assert!(
                names.iter().any(|n| n == "kernel32.dll"),
                "kernel32: {names:?}"
            );
            // 実行ファイル自身（テストバイナリ）も含まれる。
            let exe = std::env::current_exe().expect("current exe");
            let exe_name = exe
                .file_name()
                .expect("exe name")
                .to_string_lossy()
                .to_ascii_lowercase();
            assert!(names.contains(&exe_name), "self: {names:?}");
            // 全モジュールが非ゼロの範囲を持つこと。
            assert!(modules
                .iter()
                .all(|m| m.size_bytes > 0 && !m.path.is_empty()));
        }

        #[test]
        fn enumerate_unknown_pid_fails() {
            // 存在しない pid は開けない（0 は System Idle Process で
            // 開けないはずだが、環境差を避けるため u32::MAX を使う）。
            assert!(enumerate_modules(u32::MAX).is_err());
        }

        #[test]
        fn kernel32_is_microsoft_signed_and_unsigned_file_is_not() {
            // System32 の kernel32.dll は Microsoft 署名付きであること。
            let dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let kernel32 = format!("{dir}\\System32\\kernel32.dll");
            assert!(
                verify_microsoft_signature(&kernel32),
                "kernel32.dll must verify as Microsoft-signed"
            );
            // 署名の無い一時ファイルは false。
            let unsigned =
                std::env::temp_dir().join(format!("shirusu-unsigned-{}.bin", std::process::id()));
            std::fs::write(&unsigned, b"not a signed PE").unwrap();
            assert!(!verify_microsoft_signature(&unsigned.to_string_lossy()));
            // 存在しないパスも false（Err ではなく false）。
            assert!(!verify_microsoft_signature(
                r"C:\no-such-dir\no-such-file.dll"
            ));
            let _ = std::fs::remove_file(&unsigned);
        }

        #[test]
        fn copied_system_dll_verifies_but_tampered_copy_does_not() {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let source = format!("{root}\\System32\\kernel32.dll");
            let copy = std::env::temp_dir()
                .join(format!("shirusu-signature-copy-{}.dll", std::process::id()));
            std::fs::copy(&source, &copy).unwrap();
            assert!(
                verify_microsoft_signature(&copy.to_string_lossy()),
                "signature verification follows content, including catalog membership"
            );
            let mut bytes = std::fs::read(&copy).unwrap();
            assert!(bytes.len() > 0x1000);
            bytes[0x1000] ^= 0x80;
            std::fs::write(&copy, &bytes).unwrap();
            assert!(
                !verify_microsoft_signature(&copy.to_string_lossy()),
                "a trusted catalog must not authorize changed member bytes"
            );
            assert!(
                !verify_microsoft_signature(&format!("{source}\0ignored")),
                "NUL must not truncate the requested path"
            );
            std::fs::remove_file(copy).unwrap();
        }

        #[test]
        fn api_set_contract_resolves_to_implementation() {
            // api-ms-win-core-file-l1-1-0.dll は kernel32/kernelbase の
            // どちらかへ解決される（版で変わるため両方を許す）。
            let resolved = resolve_api_set_contract("api-ms-win-core-file-l1-1-0.dll")
                .expect("contract resolves");
            let lower = resolved.to_ascii_lowercase();
            assert!(
                lower.ends_with("kernel32.dll") || lower.ends_with("kernelbase.dll"),
                "unexpected implementation: {resolved}"
            );
            assert!(
                std::path::Path::new(&resolved).exists(),
                "implementation path must exist: {resolved}"
            );
            // 未ロードの名前は None。
            assert_eq!(
                resolve_api_set_contract("shirusu-definitely-not-loaded-xyz.dll"),
                None
            );
            // 既にロード済みの実モジュール名はそのモジュール自身を返す。
            let kernel32 = resolve_api_set_contract("kernel32.dll").expect("kernel32 loaded");
            assert!(kernel32.to_ascii_lowercase().ends_with("kernel32.dll"));
        }
    }
}
