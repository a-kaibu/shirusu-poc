//! Host-side OS version evidence, queried before capture initialization.
use crate::{Result, WinError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

/// Query the version reported by ntdll without manifest-dependent GetVersionEx.
/// This is reported OS evidence, not an assertion about a marketing edition or
/// proof that a compatibility layer is an authentic Windows installation.
#[cfg(windows)]
pub fn windows_version() -> Result<WindowsVersion> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    #[repr(C)]
    struct NativeVersion {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }
    type RtlGetVersion = unsafe extern "system" fn(*mut NativeVersion) -> i32;
    let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return Err(WinError::InvalidArgument(
            "ntdll version provider unavailable",
        ));
    }
    let function = unsafe { GetProcAddress(module, c"RtlGetVersion".as_ptr().cast()) }
        .ok_or(WinError::InvalidArgument("RtlGetVersion unavailable"))?;
    // SAFETY: RtlGetVersion's documented RTL_OSVERSIONINFOW layout and ABI.
    let function: RtlGetVersion = unsafe { std::mem::transmute(function) };
    let mut version = NativeVersion {
        size: std::mem::size_of::<NativeVersion>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    let status = unsafe { function(&mut version) };
    if status != 0 {
        return Err(WinError::OsError {
            api: "RtlGetVersion",
            code: status as u32,
        });
    }
    if version.major == 0 || version.build == 0 {
        return Err(WinError::InvalidArgument(
            "RtlGetVersion returned no version evidence",
        ));
    }
    Ok(WindowsVersion {
        major: version.major,
        minor: version.minor,
        build: version.build,
    })
}

#[cfg(not(windows))]
pub fn windows_version() -> Result<WindowsVersion> {
    Err(WinError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_native_evidence_or_explicitly_unsupported() {
        #[cfg(windows)]
        {
            let version = windows_version().expect("native ntdll version evidence");
            assert!(version.major > 0);
            assert!(version.build > 0);
        }
        #[cfg(not(windows))]
        assert_eq!(windows_version(), Err(WinError::Unsupported));
    }
}
