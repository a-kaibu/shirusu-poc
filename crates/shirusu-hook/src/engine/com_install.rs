//! COM / WinRT / コールバック検出フックの設置と、オブジェクト単位の COM 追跡（L02 / L14 / L16）。

use super::*;

// ---- L02: COM Interception ----
//
// 方式は「オブジェクト単位の vtable 複製」（com.rs の文書を参照）。
// Factory 関数（CoCreateInstance / CoGetClassObject）には Inline Hook
// を設置し、返されたインターフェイスを起点に追跡する。返された
// オブジェクトの vtable を複製し、複製のスロットを COM メソッド用
// Detour へ向け、オブジェクトの vtable ポインタだけを複製へ向ける。
// 共有 vtable は書き換えないため、同じ実装の別オブジェクトには及ばない。
// Proxy を使わないため、アプリへ返すポインタの同一性は壊れない。
//
// 設置・解除の安全性:
// - Factory 関数の Inline Hook は L01 と同じ手順（全スレッド一時停止＋
//   命令ポインタ検査＋トランポリン近傍確保）で設置し、解除も
//   uninstall_inline_hooks で行う（agent-dll が保持する）。
// - オブジェクトの vtable 複製は、Factory / QueryInterface の Detour
//   の中で、ポインタがアプリへ返される前に行う。アプリの他スレッドが
//   そのポインタを持つことはまだ無いため、パッチ中の呼び出しと競合しない。
// - 複製 vtable とその登録は解放しない（Release で寿命が終わった後も、
//   他スレッドが呼び出し中かもしれないため。プロセス終了時に OS が回収する）。
//   そのためセッション終了後にアプリが COM メソッドを呼んでも、Detour は
//   登録から元のメソッドを引いて素通しで呼べる（記録はしない）。

/// オブジェクトへの vtable 複製による Detour 設置の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComInterceptOutcome {
    /// 複製 vtable を設置した。
    Intercepted,
    /// 既に設置済み（同じポインタへの二重設置はしない）。
    AlreadyIntercepted,
    /// 未知のインターフェイス（追跡対象としては記録するが、メソッドの
    /// Detour は設置しない。カスタムインターフェイスは未対応）。
    UnknownInterface,
    /// Factory / QI does not prove exclusive access to the returned object.
    SharedObjectSafetyUnproven,
    /// Installed only the three typed IUnknown methods in an image-backed table.
    IUnknownIntercepted,
    IUnknownAlreadyIntercepted,
    MethodInterceptionSkipped(&'static str),
    /// オブジェクト／元の vtable の読み取りに失敗した。
    ReadFailed,
    /// 複製 vtable の確保に失敗した。
    AllocFailed,
    /// オブジェクトの vtable ポインタの書き換えに失敗した。
    VtablePatchFailed,
}

/// COM Factory 関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct ComFactoryOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

pub(super) fn com_factory_name(index: usize) -> &'static str {
    match index {
        COM_FACTORY_CO_CREATE_INSTANCE => "CoCreateInstance",
        COM_FACTORY_CO_GET_CLASS_OBJECT => "CoGetClassObject",
        _ => "?",
    }
}

pub(super) fn winrt_activation_name(index: usize) -> &'static str {
    match index {
        WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE => "RoActivateInstance",
        WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY => "RoGetActivationFactory",
        _ => "?",
    }
}

pub(super) fn callback_hook_name(index: usize) -> &'static str {
    CALLBACK_HOOKS
        .get(index)
        .map(|def| def.function)
        .unwrap_or("?")
}

/// 計画済み Inline Hook の表示名（見送り理由の報告用）。
pub(super) fn planned_inline_name(p: &PlannedInline) -> &'static str {
    match p.slot {
        InlineOriginalSlot::Api(_) => "?",
        InlineOriginalSlot::ComFactory(i) => com_factory_name(i),
        InlineOriginalSlot::WinRtActivation(i) => winrt_activation_name(i),
        InlineOriginalSlot::Callback(i) => callback_hook_name(i),
    }
}

/// 対象プロセスのメモリから usize を 1 個読む。読めなければ None
/// （アクセス違反ではなく失敗として返す。レビュー #6 P0-3 と同じ方針）。
pub(super) fn read_usize(addr: u64) -> Option<usize> {
    let mut buf = [0u8; std::mem::size_of::<usize>()];
    if ProcessMemory.read_exact(addr, &mut buf) {
        Some(usize::from_le_bytes(buf))
    } else {
        None
    }
}

/// 対象プロセスのメモリから GUID を 1 個読む。読めなければ None。
pub(super) fn read_guid(addr: u64) -> Option<Guid> {
    if addr == 0 {
        return None;
    }
    let mut bytes = [0u8; 16];
    if ProcessMemory.read_exact(addr, &mut bytes) {
        Some(Guid { bytes })
    } else {
        None
    }
}

/// 対象プロセスのメモリへ usize を 1 個書く。保護属性を一時変更する。
/// 失敗したら Err（書き込み途中の半端な状態は残さない）。
pub(super) fn write_usize(addr: u64, value: usize) -> Result<(), ()> {
    let mut old: u32 = 0;
    // SAFETY: 呼び出し側が有効な対象アドレスを渡す。
    let ok = unsafe {
        VirtualProtect(
            addr as *const c_void,
            std::mem::size_of::<usize>(),
            PAGE_READWRITE,
            &mut old,
        )
    };
    if ok == 0 {
        return Err(());
    }
    // SAFETY: 同上。
    unsafe {
        std::ptr::write_unaligned(addr as *mut usize, value);
        let mut tmp: u32 = 0;
        VirtualProtect(
            addr as *const c_void,
            std::mem::size_of::<usize>(),
            old,
            &mut tmp,
        );
    }
    Ok(())
}

/// COM Factory 関数（CoCreateInstance / CoGetClassObject）へ Inline Hook
/// を設置する（L02）。`Direct3DCreate9` はメソッド表が無いため設置しない
/// （KNOWN_FACTORIES の `hookable` が false）。
///
/// IAT フックの後・Inline Hook とは別に呼ぶこと。設置は Factory 関数
/// ごとの best-effort: 1 件の見送りは他に影響しない。ただし他スレッドの
/// 停止に失敗した場合は全体を見送る（L01 と同じ理由）。
///
/// # Safety
/// L01 の Inline Hook と同じ前提（Loader Lock 下では呼ばないこと）。
pub unsafe fn install_com_factory_hooks(rt: &HookRuntime) -> ComFactoryOutcome {
    let mut outcome = ComFactoryOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let factories: [(usize, usize); COM_FACTORY_COUNT] = [
        (
            COM_FACTORY_CO_CREATE_INSTANCE,
            detour_co_create_instance as CoCreateInstanceFn as usize,
        ),
        (
            COM_FACTORY_CO_GET_CLASS_OBJECT,
            detour_co_get_class_object as CoGetClassObjectFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in factories {
        let def = &KNOWN_FACTORIES[index];
        debug_assert!(def.hookable, "{} must be hookable", def.function);
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::ComFactory(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

/// WinRT アクティベーション関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct WinRtActivationOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

/// WinRT アクティベーション関数（RoActivateInstance /
/// RoGetActivationFactory）へ Inline Hook を設置する（L14）。
///
/// COM Factory 関数と同じ手順（全スレッド一時停止＋命令ポインタ検査＋
/// トランポリン近傍確保）で、IAT フックの後・Inline Hook とは別に呼ぶ
/// こと。設置は関数ごとの best-effort で、見送りがあっても初期化は
/// 成功として継続する（COM Factory と同じ扱い）。
///
/// # Safety
/// 対象プロセスの全スレッドを一時停止してからパッチするため、呼び出し元
/// スレッド以外が対象 API の先頭命令を実行中でないことを確認してから
/// 書き換える。Loader Lock 下（DllMain 内）では呼ばないこと。
pub unsafe fn install_winrt_activation_hooks(rt: &HookRuntime) -> WinRtActivationOutcome {
    let mut outcome = WinRtActivationOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let activations: [(usize, usize); WINRT_ACTIVATION_COUNT] = [
        (
            WINRT_ACTIVATION_RO_ACTIVATE_INSTANCE,
            detour_ro_activate_instance as RoActivateInstanceFn as usize,
        ),
        (
            WINRT_ACTIVATION_RO_GET_ACTIVATION_FACTORY,
            detour_ro_get_activation_factory as RoGetActivationFactoryFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in activations {
        let def = &WINRT_ACTIVATIONS[index];
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::WinRtActivation(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

/// コールバック検出フック関数の Inline Hook 設置結果。解除は
/// `uninstall_inline_hooks` で行う（agent-dll が保持する）。
#[derive(Debug, Default)]
pub struct CallbackOutcome {
    pub installed: Vec<InlineHook>,
    /// (関数名, 見送り理由)
    pub skipped: Vec<(&'static str, &'static str)>,
}

/// コールバック検出フック関数（RegisterClassExW/A /
/// SetWindowLongPtrW/A）へ Inline Hook を設置する（L16）。
///
/// COM Factory 関数・WinRT アクティベーション関数と同じ手順（全スレッド
/// 一時停止＋命令ポインタ検査＋トランポリン近傍確保）で、IAT フックの後・
/// Inline Hook とは別に呼ぶこと。設置は関数ごとの best-effort で、見送りが
/// あっても初期化は成功として継続する（COM Factory と同じ扱い）。
///
/// # Safety
/// 対象プロセスの全スレッドを一時停止してからパッチするため、呼び出し元
/// スレッド以外が対象 API の先頭命令を実行中でないことを確認してから
/// 書き換える。Loader Lock 下（DllMain 内）では呼ばないこと。
pub unsafe fn install_callback_hooks(rt: &HookRuntime) -> CallbackOutcome {
    let mut outcome = CallbackOutcome::default();
    let bitness: u32 = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let hooks: [(usize, usize); CALLBACK_HOOK_COUNT] = [
        (
            CALLBACK_HOOK_REGISTER_CLASS_EX_W,
            detour_register_class_ex_w as RegisterClassExFn as usize,
        ),
        (
            CALLBACK_HOOK_REGISTER_CLASS_EX_A,
            detour_register_class_ex_a as RegisterClassExFn as usize,
        ),
        (
            CALLBACK_HOOK_SET_WINDOW_LONG_PTR_W,
            detour_set_window_long_ptr_w as SetWindowLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_SET_WINDOW_LONG_PTR_A,
            detour_set_window_long_ptr_a as SetWindowLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_WINDOW_LONG_PTR_W,
            detour_get_window_long_ptr_w as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_WINDOW_LONG_PTR_A,
            detour_get_window_long_ptr_a as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_CLASS_LONG_PTR_W,
            detour_get_class_long_ptr_w as GetLongPtrFn as usize,
        ),
        (
            CALLBACK_HOOK_GET_CLASS_LONG_PTR_A,
            detour_get_class_long_ptr_a as GetLongPtrFn as usize,
        ),
    ];
    let mut planned: Vec<PlannedInline> = Vec::new();
    for (index, detour) in hooks {
        let def = &CALLBACK_HOOKS[index];
        let target = match resolve_export(def.module, def.function) {
            Some(t) => t,
            None => {
                outcome.skipped.push((def.function, "not-exported"));
                continue;
            }
        };
        let mut bytes = [0u8; 32];
        if !ProcessMemory.read_exact(target as u64, &mut bytes) {
            outcome.skipped.push((def.function, "read-failed"));
            continue;
        }
        if is_existing_detour(target, detour, bitness, &bytes) {
            outcome.skipped.push((def.function, "already-hooked"));
            continue;
        }
        match plan_with_near_relay(&bytes, target as u64, detour as u64, bitness) {
            Ok(plan) => planned.push(PlannedInline {
                slot: InlineOriginalSlot::Callback(index),
                target,
                detour,
                original_bytes: bytes[..plan.stolen_len].to_vec(),
                plan,
            }),
            Err(e) => outcome.skipped.push((def.function, e.reason())),
        }
    }
    for (p, result) in planned.iter().zip(install_planned(rt, &planned, bitness)) {
        match result {
            Ok(hook) => outcome.installed.push(hook),
            Err(reason) => outcome.skipped.push((planned_inline_name(p), reason)),
        }
    }
    outcome
}

pub(super) fn retire_unloaded_com_address(tracker: &mut crate::com::ComTracker, ptr: u64) {
    if tracker
        .lookup(ptr)
        .and_then(|o| o.iunknown_slot)
        .is_some_and(crate::shared_com::installation_retired)
    {
        tracker.note_implementation_unloaded(ptr);
    }
}

/// Install typed IUnknown adapters without replacing the object's vptr.
///
/// # Safety
/// `ptr` must hold a valid owned COM reference throughout installation and
/// obey the IUnknown ABI and module lifetime contract of `shared_com::install`.
pub unsafe fn intercept_object(
    rt: &Arc<HookRuntime>,
    ptr: usize,
    iid: Guid,
) -> ComInterceptOutcome {
    if interface_by_iid(&iid).is_none() {
        return ComInterceptOutcome::UnknownInterface;
    }
    // The standard path sets `iunknown_intercepted`; checking only
    // `intercepted` reinstalled (3 VirtualQuery, 4 ReadProcessMemory) on
    // every QI of a known object (review 2026-11-14 P2-6).
    let known = rt.with_com_tracker(|t| {
        t.lookup(ptr as u64)
            .filter(|o| !o.destroyed)
            .map(|o| (o.intercepted, o.iunknown_intercepted))
    });
    match known {
        Some((true, _)) => return ComInterceptOutcome::AlreadyIntercepted,
        Some((_, true)) => return ComInterceptOutcome::IUnknownAlreadyIntercepted,
        _ => {}
    }
    match unsafe { crate::shared_com::install(rt, ptr) } {
        Ok(installed) => {
            rt.with_com_tracker(|t| {
                t.note_iunknown_intercepted(ptr as u64, installed.table as u64, installed.slot)
            });
            if installed.newly_installed {
                ComInterceptOutcome::IUnknownIntercepted
            } else {
                ComInterceptOutcome::IUnknownAlreadyIntercepted
            }
        }
        Err(reason) => {
            rt.with_com_tracker(|t| t.note_interception_skipped_with_reason(ptr as u64, reason));
            ComInterceptOutcome::MethodInterceptionSkipped(reason)
        }
    }
}

/// 追跡対象のインターフェイスへ vtable 複製による Detour を設置する。
///
/// 手順：元の vtable とメソッド列を読み、複製を作って Detour で
/// スロットを置き換え、複製を登録し、オブジェクトの vtable ポインタを
/// 複製へ向ける。呼び出し側は、ポインタがアプリへ返される前（Factory /
/// QueryInterface の Detour の中）で呼ぶこと。
///
/// # Safety
/// `ptr` は有効な COM インターフェイスのポインタであり、呼び出し元が
/// 設置中に他スレッドがこのポインタでメソッドを呼ばないことを保証すること。
pub unsafe fn intercept_exclusive_object(
    rt: &HookRuntime,
    ptr: usize,
    iid: Guid,
) -> ComInterceptOutcome {
    let Some(def) = interface_by_iid(&iid) else {
        return ComInterceptOutcome::UnknownInterface;
    };
    if rt.with_com_tracker(|t| t.lookup(ptr as u64).is_some_and(|o| o.iunknown_intercepted)) {
        return ComInterceptOutcome::IUnknownAlreadyIntercepted;
    }
    let already =
        rt.with_com_tracker(|t| t.lookup(ptr as u64).map(|o| o.intercepted).unwrap_or(false));
    if already {
        return ComInterceptOutcome::AlreadyIntercepted;
    }
    let Some(vtbl) = read_usize(ptr as u64) else {
        return ComInterceptOutcome::ReadFailed;
    };
    if vtbl == 0 {
        return ComInterceptOutcome::ReadFailed;
    }
    // 既に複製 vtable を指している場合は二重設置しない（前セッションで
    // 設置された複製が残っている等）。登録から元の列を引いて追跡表へ
    // 記録し、設置済みとして扱う（元の vtable アドレスは不明のため 0）。
    if let Some(originals) = ComCloneRegistry::originals(vtbl as u64) {
        rt.with_com_tracker(|t| {
            t.note_intercepted(ptr as u64, 0, vtbl as u64, originals);
        });
        return ComInterceptOutcome::AlreadyIntercepted;
    }
    let count = def.methods.len();
    let mut originals = vec![0usize; count];
    for (i, slot) in originals.iter_mut().enumerate() {
        match read_usize(vtbl as u64 + (i * std::mem::size_of::<usize>()) as u64) {
            Some(v) => *slot = v,
            None => return ComInterceptOutcome::ReadFailed,
        }
    }
    let detours: Vec<(u32, usize)> = def
        .methods
        .iter()
        .filter_map(|m| com_detour_for(m.index, m.arity).map(|d| (m.index, d)))
        .collect();
    if detours.len() != count {
        // 既知メソッドに Detour が無い（実装の不整合）。設置しない。
        return ComInterceptOutcome::ReadFailed;
    }
    let cloned = build_cloned_vtable(&originals, &detours);
    let size = cloned.len() * std::mem::size_of::<usize>();
    // SAFETY: 複製 vtable 用の領域を確保する。データであり実行は不要。
    let mem = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if mem.is_null() {
        return ComInterceptOutcome::AllocFailed;
    }
    // SAFETY: 確保したての領域へ複製を書き込む。
    unsafe {
        std::ptr::copy_nonoverlapping(cloned.as_ptr(), mem as *mut usize, cloned.len());
    }
    // Detour が元のメソッドを引けるよう、複製のアドレスで登録する。
    // パッチに失敗しても登録は残る（リークするが安全。Detour は呼ばれない）。
    ComCloneRegistry::register(mem as u64, originals.iter().map(|a| *a as u64).collect());
    if write_usize(ptr as u64, mem as usize).is_err() {
        return ComInterceptOutcome::VtablePatchFailed;
    }
    // 診断用オプション：同一性の確認（標準では行わない）。
    if rt.with_com_tracker(|t| t.diagnostic_query_interface()) {
        diagnostic_confirm_identity(rt, ptr, &originals);
    }
    rt.with_com_tracker(|t| {
        t.note_intercepted(
            ptr as u64,
            vtbl as u64,
            mem as u64,
            originals.iter().map(|a| *a as u64).collect(),
        );
    });
    ComInterceptOutcome::Intercepted
}

/// 診断用オプション：Interceptor 自身が `QueryInterface(IID_IUnknown)`
/// を呼んで同一性を確認する。元の QI（vtable スロット 0 の元の
/// メソッド）を直接呼び、Detour は通さない（アプリの呼び出しとして
/// 記録しない）。成功したら返された IUnknown ポインタで同一性を確定し、
/// 参照カウントを戻すため Release（スロット 2 の元のメソッド）を呼ぶ。
/// 失敗しても追跡には影響しない。
pub(super) fn diagnostic_confirm_identity(rt: &HookRuntime, ptr: usize, originals: &[usize]) {
    let qi = match originals.first() {
        Some(&f) if f != 0 => f,
        _ => return,
    };
    let release = match originals.get(2) {
        Some(&f) if f != 0 => f,
        _ => return,
    };
    type QueryInterfaceFn =
        unsafe extern "system-unwind" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type ReleaseFn = unsafe extern "system-unwind" fn(*mut c_void) -> u32;
    let mut unk: *mut c_void = std::ptr::null_mut();
    // SAFETY: qi / release は元の vtable から読んだ有効なメソッド。
    let hr = unsafe {
        std::mem::transmute::<usize, QueryInterfaceFn>(qi)(
            ptr as *mut c_void,
            &IID_IUNKNOWN,
            &mut unk,
        )
    };
    if hr != 0 || unk.is_null() {
        return;
    }
    rt.with_com_tracker(|t| t.note_identity_confirmed(ptr as u64, unk as u64));
    // 参照カウントを元へ戻す（QI で +1 された分）。
    unsafe {
        std::mem::transmute::<usize, ReleaseFn>(release)(unk);
    };
}
