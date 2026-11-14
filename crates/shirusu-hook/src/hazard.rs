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
//!
//! The handshake is model-checked with store→load reordering in
//! `tla/AsymmetricHandshake.tla` (`HazardSafe`).
//!
//! Forced termination (review P0): a thread ended by `TerminateThread` inside
//! a Detour never clears its hazard. Each slot keeps its owner's
//! [`ThreadLiveness`]; a scan that finds a hazard whose owner has terminated
//! withdraws it and frees the slot. That is safe because a terminated thread
//! never runs again, so it can no longer dereference the runtime. A hazard of
//! a live thread (even one suspended for ever) is always counted.

use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Mutex;

use shirusu_transport_win::ThreadLiveness;

use crate::runtime::HookRuntime;

/// Slots in the process. A thread holds one from its first cached Detour
/// entry until its thread-local runtime cache is destroyed.
pub(crate) const HAZARD_SLOTS: usize = 1024;

/// One thread's published runtime. Padded so threads do not share lines.
#[repr(align(128))]
pub(crate) struct HazardSlot {
    runtime: AtomicPtr<HookRuntime>,
    claimed: AtomicBool,
    /// The claiming thread's liveness (cold paths only). `None`: unknown,
    /// the owner is treated as alive.
    owner: Mutex<Option<ThreadLiveness>>,
}

impl HazardSlot {
    const fn new() -> Self {
        Self {
            runtime: AtomicPtr::new(std::ptr::null_mut()),
            claimed: AtomicBool::new(false),
            owner: Mutex::new(None),
        }
    }
}

static SLOTS: [HazardSlot; HAZARD_SLOTS] = [const { HazardSlot::new() }; HAZARD_SLOTS];

/// Claim a free slot for the calling thread (management path).
pub(crate) fn claim() -> Option<u32> {
    let index = SLOTS.iter().position(|s| {
        !s.claimed.load(Ordering::Relaxed)
            && s.claimed
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
    })?;
    // Before the first publication: a scan that sees this thread's hazard
    // finds its liveness (the slot lock orders the two).
    *lock_owner(&SLOTS[index]) = ThreadLiveness::current();
    Some(index as u32)
}

fn lock_owner(slot: &HazardSlot) -> std::sync::MutexGuard<'_, Option<ThreadLiveness>> {
    slot.owner.lock().unwrap_or_else(|e| e.into_inner())
}

/// Give a slot back. Its owner must not be publishing through it.
pub(crate) fn release(index: u32) {
    let slot = &SLOTS[index as usize];
    let liveness = lock_owner(slot).take();
    drop(liveness);
    slot.runtime.store(std::ptr::null_mut(), Ordering::Release);
    slot.claimed.store(false, Ordering::Release);
}

/// Withdraw `slot`'s hazard and free the slot if its owner has terminated.
/// Returns whether it did.
#[cold]
fn reap_if_terminated(slot: &HazardSlot) -> bool {
    let mut owner = lock_owner(slot);
    if !owner.as_ref().is_some_and(ThreadLiveness::has_terminated) {
        return false;
    }
    let liveness = owner.take();
    // The owner never runs again: nobody else stores to this slot until it
    // is claimed anew, which needs `claimed` false.
    slot.runtime.store(std::ptr::null_mut(), Ordering::Release);
    slot.claimed.store(false, Ordering::Release);
    drop(owner);
    drop(liveness);
    true
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
///
/// A hazard whose owner has terminated is withdrawn instead of counted (see
/// the module notes); a terminated thread can never dereference `rt` again.
pub(crate) fn count_published(rt: *const HookRuntime) -> usize {
    SLOTS
        .iter()
        .filter(|s| std::ptr::eq(s.runtime.load(Ordering::Acquire), rt) && !reap_if_terminated(s))
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

    /// Review P0: a thread terminated with a published hazard (it skipped
    /// every destructor) no longer holds the runtime or its slot.
    #[test]
    fn terminated_owner_hazard_is_withdrawn() {
        const RT: usize = 0x1000; // compared, never dereferenced
        let rt = RT as *const HookRuntime;
        let index = std::thread::spawn(move || {
            let index = claim().unwrap();
            publish(index, RT as *const HookRuntime);
            index // exits without clear/release, as after TerminateThread
        })
        .join()
        .unwrap();
        assert_eq!(count(rt), 0, "a terminated thread's hazard was counted");
        assert!(!SLOTS[index as usize].claimed.load(Ordering::Acquire));
        // A live publisher is still counted.
        let live = claim().unwrap();
        publish(live, rt);
        assert_eq!(count(rt), 1);
        clear(live);
        release(live);
    }
}
