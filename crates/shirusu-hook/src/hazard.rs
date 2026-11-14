//! Per-thread hazard slots for Detour runtime references.
//!
//! A recorded call used to pay four atomic read-modify-write operations on
//! shared cache lines: the runtime `Arc` upgrade and drop, and the in-flight
//! counter's add and subtract. Each is a locked instruction even uncontended.
//! A thread that holds a hazard slot instead publishes the runtime it uses
//! with a plain store, under the asymmetric handshake of
//! [`shirusu_transport_win::asymmetric_fence_light`]:
//!
//! - entry: store the runtime pointer in the slot, light fence, then re-check
//!   the slot revision and the recording gate.
//! - reclaimer / shutdown: change the revision or the gate, heavy fence, then
//!   scan every slot.
//!
//! Either the entering thread sees the change and backs off, or the scan sees
//! its hazard. A published hazard therefore keeps the runtime allocated (the
//! slot defers freeing it) and counts as in flight (shutdown waits for it).
//! Threads without a slot (the table is full, or their thread-local cache is
//! gone) keep the `Arc` and counter path.

use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::runtime::HookRuntime;

/// Slots in the process. A thread holds one from its first cached Detour
/// entry until its thread-local runtime cache is destroyed.
pub(crate) const HAZARD_SLOTS: usize = 1024;

/// One thread's published runtime. Padded so threads do not share lines.
#[repr(align(128))]
pub(crate) struct HazardSlot {
    runtime: AtomicPtr<HookRuntime>,
    claimed: AtomicBool,
}

impl HazardSlot {
    const fn new() -> Self {
        Self {
            runtime: AtomicPtr::new(std::ptr::null_mut()),
            claimed: AtomicBool::new(false),
        }
    }
}

static SLOTS: [HazardSlot; HAZARD_SLOTS] = [const { HazardSlot::new() }; HAZARD_SLOTS];

/// Claim a free slot for the calling thread (management path).
pub(crate) fn claim() -> Option<u32> {
    SLOTS
        .iter()
        .position(|s| {
            !s.claimed.load(Ordering::Relaxed)
                && s.claimed
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
        })
        .map(|i| i as u32)
}

/// Give a slot back. Its owner must not be publishing through it.
pub(crate) fn release(index: u32) {
    let slot = &SLOTS[index as usize];
    slot.runtime.store(std::ptr::null_mut(), Ordering::Release);
    slot.claimed.store(false, Ordering::Release);
}

/// The runtime this thread's slot currently publishes (owner only).
#[inline(always)]
pub(crate) fn published(index: u32) -> *const HookRuntime {
    SLOTS[index as usize].runtime.load(Ordering::Relaxed)
}

/// Publish `rt` and order the store before the caller's re-checks.
#[inline(always)]
pub(crate) fn publish(index: u32, rt: *const HookRuntime) {
    SLOTS[index as usize]
        .runtime
        .store(rt as *mut HookRuntime, Ordering::Relaxed);
    shirusu_transport_win::asymmetric_fence_light();
}

/// Withdraw this thread's hazard (Release: its uses of the runtime happen
/// before a scan that no longer sees it).
#[inline(always)]
pub(crate) fn clear(index: u32) {
    SLOTS[index as usize]
        .runtime
        .store(std::ptr::null_mut(), Ordering::Release);
}

/// Slots that publish `rt`. The caller has already changed the revision or
/// the gate that entering threads re-check; the heavy fence makes every
/// hazard stored before their re-check visible here.
pub(crate) fn count(rt: *const HookRuntime) -> usize {
    shirusu_transport_win::asymmetric_fence_heavy();
    count_published(rt)
}

/// [`count`] without the heavy fence, for re-scans after one fenced scan.
/// Once the gate or revision changed and a fenced scan ran, every later entry
/// observes the change and withdraws, so only hazards already counted can
/// remain; their Release clears become visible to these Acquire loads. A
/// polling waiter therefore pays the process-wide fence once, not per poll
/// (review N2).
pub(crate) fn count_published(rt: *const HookRuntime) -> usize {
    SLOTS
        .iter()
        .filter(|s| std::ptr::eq(s.runtime.load(Ordering::Acquire), rt))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_slots_are_distinct_and_reusable() {
        let a = claim().unwrap();
        let b = claim().unwrap();
        assert_ne!(a, b);
        release(a);
        release(b);
    }
}
