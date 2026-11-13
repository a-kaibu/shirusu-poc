//! IAT パッチの設置・解除と公開状態。

use super::*;

/// One owned IAT publication and any outstanding page-protection restoration.
#[derive(Debug)]
pub struct IatSlot {
    pub rva: u32,
    pub original: usize,
    pub detour: usize,
    pub(super) owned: std::sync::atomic::AtomicBool,
    pub(super) protection: std::sync::atomic::AtomicU32,
}
impl IatSlot {
    pub fn installed(rva: u32, original: usize, detour: usize) -> Self {
        Self {
            rva,
            original,
            detour,
            owned: std::sync::atomic::AtomicBool::new(true),
            protection: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

/// Installation and retry state. Dropping it does not restore published hooks.
#[derive(Debug)]
pub struct InstalledHooks {
    pub module_base: usize,
    pub slots: Vec<IatSlot>,
    pub plan: HookPlan,
}

/// # Safety
/// The aligned slot remains mapped in the original module. Lifecycle operations
/// and page-protection changes are serialized; other pointer owners may replace
/// our pointer and must not be overwritten during restoration.
pub(super) unsafe fn exchange_iat(
    slot: *mut usize,
    state: &IatSlot,
    install: bool,
) -> Result<(), EngineError> {
    unsafe {
        exchange_iat_with(slot, state, install, |address, size, protection, old| {
            VirtualProtect(address, size, protection, old)
        })
    }
}

pub(super) unsafe fn exchange_iat_with(
    slot: *mut usize,
    state: &IatSlot,
    install: bool,
    mut protect: impl FnMut(*const c_void, usize, u32, *mut u32) -> i32,
) -> Result<(), EngineError> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    if (slot as usize) & (std::mem::align_of::<AtomicUsize>() - 1) != 0 {
        return Err(EngineError::UnalignedIatSlot);
    }
    let address = slot as *const c_void;
    let size = std::mem::size_of::<usize>();
    let mut changed = true;
    if install || state.owned.load(Ordering::Acquire) {
        let mut old = 0;
        if protect(address, size, PAGE_READWRITE, &mut old) == 0 {
            return Err(EngineError::ProtectFailed { iat_rva: state.rva });
        }
        // Never replace an earlier outstanding restoration with PAGE_READWRITE.
        let _ = state
            .protection
            .compare_exchange(0, old, Ordering::AcqRel, Ordering::Acquire);
        let (expected, value) = if install {
            (state.original, state.detour)
        } else {
            (state.detour, state.original)
        };
        changed = unsafe { AtomicUsize::from_ptr(slot) }
            .compare_exchange(expected, value, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        // A foreign replacement ends our pointer ownership, but protection
        // restoration still belongs to us and must be retried if it fails.
        state.owned.store(install && changed, Ordering::Release);
    }
    let old = state.protection.load(Ordering::Acquire);
    if old != 0 {
        let mut ignored = 0;
        if protect(address, size, old, &mut ignored) == 0 {
            return Err(EngineError::ProtectFailed { iat_rva: state.rva });
        }
        state.protection.store(0, Ordering::Release);
    }
    if install && !changed {
        Err(EngineError::IatChanged)
    } else {
        Ok(())
    }
}

/// モジュール（ロード済みイメージ）の IAT をパッチし、対象 API を
/// Detour へ向ける。元の値はランタイムと戻り値の両方へ保存する。
///
/// # Safety
/// `module_base` はロード済み PE モジュールのベースアドレスであり、
/// 設置中は対象モジュールのコードが IAT 経由の呼び出しを行っていない
/// こと（初期化は対象のメインスレッド再開前に行う）。
pub unsafe fn install_hooks(
    module_base: *mut u8,
    rt: &HookRuntime,
) -> Result<InstalledHooks, EngineError> {
    // SAFETY: ベースはロード済みモジュール。ヘッダー分だけ先に読む。
    let header = unsafe { std::slice::from_raw_parts(module_base, 0x1000) };
    let size = pe::size_of_image(header).ok_or(EngineError::NotPe)? as usize;
    // SAFETY: SizeOfImage 分がモジュールイメージ。
    let image = unsafe { std::slice::from_raw_parts(module_base, size) };
    let sites = pe::parse_imports(image);
    let mut plan = build_plan(&sites);
    // Inline installation later replaces the per-API original with its export
    // trampoline. Routing a preexisting IAT wrapper through that shared slot
    // would silently bypass the wrapper. Leave such imports untouched.
    plan.preserve_noncanonical(|entry| {
        let Some(export) = resolve_export(&entry.dll_name, entry.api.function) else {
            return false;
        };
        // SAFETY: the import parser bounds-checks the pointer slot in this image.
        let original =
            unsafe { (module_base.add(entry.iat_rva as usize) as *const usize).read_unaligned() };
        follow_import_thunks(original) == Some(export)
    });
    if plan.entries.is_empty() {
        return Err(EngineError::NoTargets(plan));
    }
    let mut installed = InstalledHooks {
        module_base: module_base as usize,
        slots: Vec::with_capacity(plan.entries.len()),
        plan,
    };
    for index in 0..installed.plan.entries.len() {
        let entry = &installed.plan.entries[index];
        let rva = entry.iat_rva;
        let slot = unsafe { module_base.add(rva as usize) }.cast::<usize>();
        let original = unsafe { slot.read_unaligned() };
        let canonical = resolve_export(&entry.dll_name, entry.api.function)
            .is_some_and(|export| follow_import_thunks(original) == Some(export));
        if canonical {
            rt.set_original(entry.api.api_id, original);
        }
        let state = IatSlot::installed(rva, original, detour_for(entry.api.api_id));
        state
            .owned
            .store(false, std::sync::atomic::Ordering::Release);
        // Save the descriptor BEFORE publication, including the failing entry.
        installed.slots.push(state);
        if !canonical
            || unsafe { exchange_iat(slot, installed.slots.last().unwrap(), true) }.is_err()
        {
            unsafe {
                uninstall_pending_hooks(&mut installed);
            }
            return Err(EngineError::InstallFailed {
                failed_iat_rva: rva,
                unrestored: installed.slots.iter().map(|s| s.rva).collect(),
                pending: Box::new(installed),
            });
        }
    }
    Ok(installed)
}

/// IAT を元の値へ戻す（設置の巻き戻し）。復元できなかったスロットの
/// IAT RVA を返す (レビュー #6 P1-6)。
///
/// 順序制御は設置側と対称な [`crate::plan::restore_all`] に委ねる:
/// 失敗しても残りを全て試みる。戻り値が空でなければ、対象プロセス
/// に Detour が残存する重大な状態であり、呼び出し側は終了状態
/// (SHUTDOWN_INCOMPLETE) へ反映しなければならない。旧実装は
/// 書き戻しの失敗を捨てており、残存があっても「解除できた」ことに
/// なっていた。
///
/// # Safety
/// `installed` は install_hooks が返したものであり、対象モジュールが
/// まだロードされていること。
pub(super) unsafe fn uninstall_iat_indices(installed: &InstalledHooks) -> Vec<usize> {
    crate::plan::restore_all(installed.slots.len(), |i| {
        let state = &installed.slots[i];
        // SAFETY: 呼び出し側の契約に従う。
        let slot =
            unsafe { (installed.module_base as *mut u8).add(state.rva as usize) } as *mut usize;
        // SAFETY: 同上。
        unsafe { exchange_iat(slot, state, false) }
    })
}

/// Restore IAT slots and report RVAs that could not be restored.
///
/// # Safety
/// Same installed-module lifetime contract as `uninstall_pending_hooks`.
pub unsafe fn uninstall_hooks(installed: &InstalledHooks) -> Vec<u32> {
    unsafe { uninstall_iat_indices(installed) }
        .into_iter()
        .map(|i| installed.slots[i].rva)
        .collect()
}

/// Retain only IAT slots whose restoration failed, so retries never overwrite
/// slots already restored (and possibly changed by the application afterwards).
///
/// # Safety
/// The installed module and remaining slots must still be mapped at their
/// original addresses; only a lifecycle owner may modify this installation.
pub unsafe fn uninstall_pending_hooks(installed: &mut InstalledHooks) -> usize {
    let failed = unsafe { uninstall_iat_indices(installed) };
    retain_failed_indices(&mut installed.slots, &failed);
    installed.slots.len()
}

pub(super) fn retain_failed_indices<T>(items: &mut Vec<T>, failed: &[usize]) {
    let mut index = 0;
    items.retain(|_| {
        let keep = failed.contains(&index);
        index += 1;
        keep
    });
}
