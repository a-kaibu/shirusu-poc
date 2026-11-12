//! Opt-in native fault evidence for CI. The handler only writes to a file-backed
//! view prepared before hook installation; it never allocates or takes a lock.
//! The view/handler remain valid until process exit, including failed init.
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Once,
};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS},
        Memory::{
            CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
        },
    },
};

static INIT: Once = Once::new();
static VIEW: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static RECORDED: AtomicBool = AtomicBool::new(false);

pub fn install() {
    INIT.call_once(|| {
        if let Some(dir) = std::env::var_os("SHIRUSU_DIAGNOSTIC_DIR") {
            if let Err(error) = prepare(std::path::Path::new(&dir)) {
                eprintln!("shirusu native diagnostics unavailable: {error}");
            }
        }
    });
}

fn prepare(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    let pid = std::process::id();
    std::fs::create_dir_all(dir)?;
    let modules =
        shirusu_transport_win::modules::enumerate_modules(pid).map_err(std::io::Error::other)?;
    let mut text = String::from("base\tsize\tpath\n");
    for module in modules {
        text.push_str(&format!(
            "{:x}\t{:x}\t{}\n",
            module.base_address, module.size_bytes, module.path
        ));
    }
    std::fs::write(dir.join(format!("native-{pid}-modules.tsv")), text)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.join(format!("native-{pid}-exception.bin")))?;
    file.set_len(4096)?;
    let mapping = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            4096,
            std::ptr::null(),
        )
    };
    if mapping.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4096) };
    unsafe { CloseHandle(mapping) };
    if view.Value.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    VIEW.store(view.Value.cast(), Ordering::Release);
    if unsafe { AddVectoredExceptionHandler(1, Some(exception)) }.is_null() {
        VIEW.store(std::ptr::null_mut(), Ordering::Release);
        unsafe { UnmapViewOfFile(view) };
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "system" fn exception(pointers: *mut EXCEPTION_POINTERS) -> i32 {
    const CONTINUE_SEARCH: i32 = 0;
    if pointers.is_null() {
        return CONTINUE_SEARCH;
    }
    let pointers = unsafe { &*pointers };
    if pointers.ExceptionRecord.is_null() || pointers.ContextRecord.is_null() {
        return CONTINUE_SEARCH;
    }
    let record = unsafe { &*pointers.ExceptionRecord };
    if record.ExceptionCode as u32 != 0xc000_0005 {
        return CONTINUE_SEARCH;
    }
    let view = VIEW.load(Ordering::Acquire);
    if view.is_null() || RECORDED.swap(true, Ordering::AcqRel) {
        return CONTINUE_SEARCH;
    }
    let context = unsafe { &*pointers.ContextRecord };
    // Fixed little-endian u64 words, independent of target pointer width:
    // magic, pointer bits, exception code, address, IP, SP, access kind,
    // fault address, then integer registers (AX,CX,DX,BX,BP,SI,DI,R8..R15).
    #[cfg(target_arch = "x86_64")]
    let registers = [
        context.Rax,
        context.Rcx,
        context.Rdx,
        context.Rbx,
        context.Rbp,
        context.Rsi,
        context.Rdi,
        context.R8,
        context.R9,
        context.R10,
        context.R11,
        context.R12,
        context.R13,
        context.R14,
        context.R15,
    ];
    #[cfg(target_arch = "x86")]
    let registers = [
        context.Eax as u64,
        context.Ecx as u64,
        context.Edx as u64,
        context.Ebx as u64,
        context.Ebp as u64,
        context.Esi as u64,
        context.Edi as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    #[cfg(target_arch = "x86_64")]
    let (ip, sp) = (context.Rip, context.Rsp);
    #[cfg(target_arch = "x86")]
    let (ip, sp) = (context.Eip as u64, context.Esp as u64);
    let header = [
        0x3147_4149_4452_4853,
        usize::BITS as u64,
        record.ExceptionCode as u32 as u64,
        record.ExceptionAddress as u64,
        ip,
        sp,
        if record.NumberParameters > 0 {
            record.ExceptionInformation[0] as u64
        } else {
            u64::MAX
        },
        if record.NumberParameters > 1 {
            record.ExceptionInformation[1] as u64
        } else {
            0
        },
    ];
    for (index, value) in header.into_iter().chain(registers).enumerate() {
        unsafe { std::ptr::write_volatile(view.add(index), value) };
    }
    CONTINUE_SEARCH
}
