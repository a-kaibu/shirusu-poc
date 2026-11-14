//! Per-Ring writer ownership without an atomic read-modify-write per event.
//!
//! A Ring has one writer. Before this cell it sat behind a `Mutex`, so every
//! recorded event paid an uncontended lock and unlock: two atomic
//! read-modify-write operations, the largest fixed cost of a publication
//! after the timestamp. Contention is almost never real: the recording OS
//! thread owns its Ring, and other threads only touch the writer on
//! management paths (thread detach, retirement, tests).
//!
//! The cell gives the owning OS thread a fast path guarded by an asymmetric
//! Dekker handshake:
//!
//! - owner: `owner_busy = true`, light fence, read `remote`; if no remote
//!   access is pending, use the writer and clear `owner_busy` (Release).
//! - remote: take `exclusive`, set `remote = true`, heavy fence
//!   (`FlushProcessWriteBuffers` on Windows), wait until `owner_busy` is
//!   false, use the writer, clear `remote` (Release).
//!
//! Either the owner sees `remote` and backs off to the exclusive path, or the
//! remote side sees `owner_busy` and waits for it. Only the first OS thread
//! that uses the fast path owns it; any other thread recording for the same
//! logical thread takes the exclusive path. The handshake is model-checked in
//! `tla/AsymmetricHandshake.tla` with store buffers (store→load reordering)
//! and an owner that may be terminated at any step.
//!
//! Forced termination (review P0): an owner ended by `TerminateThread` runs
//! no `Drop`, so `owner_busy` can stay set forever. The remote side never
//! clears it on a timeout (a suspended owner would resume inside the writer).
//! It waits while the owner is alive and gives up only when the owner's
//! [`ThreadLiveness`] proves the thread terminated. The cell is then
//! *abandoned*: the writer may be half way through an event, so nobody uses
//! it again, `remote` stays set so no thread re-enters the fast path, and
//! [`WriterCell::exclusive`] returns [`Access::OwnerTerminated`] without
//! running its closure. The Ring keeps every event published before the
//! termination; unpublished bytes are never published.

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use shirusu_transport::ring::RingWriter;
use shirusu_transport_win::ThreadLiveness;

thread_local! {
    /// Its address identifies the calling OS thread while it lives.
    static THREAD_TOKEN: u8 = const { 0 };
}

fn thread_token() -> usize {
    THREAD_TOKEN.with(|t| t as *const u8 as usize)
}

pub(crate) struct WriterCell {
    writer: UnsafeCell<RingWriter>,
    /// Token of the OS thread allowed the fast path (0: not claimed yet).
    owner: AtomicUsize,
    owner_busy: AtomicBool,
    remote: AtomicBool,
    /// Serializes exclusive (non-owner) users among themselves.
    exclusive: Mutex<()>,
    /// The owner's liveness, set before `owner` is published (cold, once).
    /// Unset (taking it failed): the owner is treated as alive forever.
    owner_liveness: OnceLock<ThreadLiveness>,
    /// Serializes claims so the liveness belongs to the thread that won.
    claiming: Mutex<()>,
    /// The owner terminated while holding the fast path; the writer is
    /// poisoned for good (see the module notes).
    abandoned: AtomicBool,
}

/// Result of [`WriterCell::exclusive`].
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum Access<R> {
    Done(R),
    /// The owner was terminated inside the fast path. The closure did not
    /// run and never will on this cell.
    OwnerTerminated,
}

impl<R> Access<R> {
    pub(crate) fn done(self) -> Option<R> {
        match self {
            Self::Done(r) => Some(r),
            Self::OwnerTerminated => None,
        }
    }
}

/// Yields between liveness checks while the owner holds the fast path. An
/// owner normally leaves within one event; the check costs a system call.
const SPINS_PER_LIVENESS_CHECK: u32 = 64;

// SAFETY: the writer is only reached through `try_owner` (its owning OS
// thread, excluded from remote users by the handshake) or `exclusive`
// (serialized by the mutex and the handshake). RingWriter is Send.
unsafe impl Sync for WriterCell {}

struct ClearOnDrop<'a>(&'a AtomicBool);
impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl WriterCell {
    pub(crate) fn new(writer: RingWriter) -> Self {
        Self {
            writer: UnsafeCell::new(writer),
            owner: AtomicUsize::new(0),
            owner_busy: AtomicBool::new(false),
            remote: AtomicBool::new(false),
            exclusive: Mutex::new(()),
            owner_liveness: OnceLock::new(),
            claiming: Mutex::new(()),
            abandoned: AtomicBool::new(false),
        }
    }

    /// Enter the owner fast path. `None` when the caller is not the owning OS
    /// thread or a remote user is pending; then use [`WriterCell::exclusive`].
    /// The guard must not be held across another entry on the same cell.
    #[inline(always)]
    pub(crate) fn try_owner(&self) -> Option<OwnerGuard<'_>> {
        let me = thread_token();
        let owner = self.owner.load(Ordering::Relaxed);
        if owner != me && (owner != 0 || !self.claim(me)) {
            return None;
        }
        self.owner_busy.store(true, Ordering::Relaxed);
        shirusu_transport_win::asymmetric_fence_light();
        // Acquire pairs with the remote user's Release clear: its writer
        // updates are visible before the owner touches the writer again.
        if self.remote.load(Ordering::Acquire) {
            self.owner_busy.store(false, Ordering::Release);
            return None;
        }
        Some(OwnerGuard {
            cell: self,
            _not_send: PhantomData,
        })
    }

    #[cold]
    #[inline(never)]
    fn claim(&self, me: usize) -> bool {
        let _claiming = self.claiming.lock().unwrap_or_else(|e| e.into_inner());
        if self.owner.load(Ordering::Relaxed) != 0 {
            return false;
        }
        // Liveness first: a remote user that sees this owner busy must be
        // able to tell whether it terminated. The Release store of `owner`
        // orders it before every later owner_busy store of this thread.
        if let Some(liveness) = ThreadLiveness::current() {
            let _ = self.owner_liveness.set(liveness);
        }
        self.owner.store(me, Ordering::Release);
        true
    }

    /// Whether the fast-path owner has terminated (false while unclaimed or
    /// when its liveness is unknown). Final once true.
    pub(crate) fn owner_terminated(&self) -> bool {
        self.owner.load(Ordering::Acquire) != 0
            && self
                .owner_liveness
                .get()
                .is_some_and(ThreadLiveness::has_terminated)
    }

    /// The owner was terminated inside the fast path (see module notes).
    pub(crate) fn is_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }

    /// Run `f` on the owner fast path, or give it back (see `try_owner`).
    #[cfg(test)]
    pub(crate) fn with_owner<R, F: FnOnce(&mut RingWriter) -> R>(&self, f: F) -> Result<R, F> {
        match self.try_owner() {
            Some(mut guard) => Ok(f(&mut guard)),
            None => Err(f),
        }
    }

    /// Run `f` with exclusive access from any thread (management path).
    ///
    /// Waits while a live owner holds the fast path (an owner waiting for
    /// Ring space leaves within the writer's `max_wait`). Returns
    /// [`Access::OwnerTerminated`] instead of waiting forever when the owner
    /// was terminated there; never on a timeout.
    #[cold]
    #[inline(never)]
    pub(crate) fn exclusive<R>(&self, f: impl FnOnce(&mut RingWriter) -> R) -> Access<R> {
        let _serialized = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        if self.abandoned.load(Ordering::Acquire) {
            return Access::OwnerTerminated;
        }
        self.remote.store(true, Ordering::Relaxed);
        shirusu_transport_win::asymmetric_fence_heavy();
        let mut spins = 0u32;
        while self.owner_busy.load(Ordering::Acquire) {
            spins = spins.wrapping_add(1);
            if spins.is_multiple_of(SPINS_PER_LIVENESS_CHECK) && self.owner_terminated() {
                // Terminated inside the fast path: `remote` stays set, so the
                // fast path stays closed, and the writer is never used again.
                self.abandoned.store(true, Ordering::Release);
                return Access::OwnerTerminated;
            }
            std::thread::yield_now();
        }
        let _done = ClearOnDrop(&self.remote);
        // SAFETY: the mutex excludes other remote users and the handshake
        // excludes the owner until `remote` clears.
        Access::Done(f(unsafe { &mut *self.writer.get() }))
    }

    /// Fast path when possible, otherwise exclusive.
    #[cfg(test)]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut RingWriter) -> R) -> R {
        match self.try_owner() {
            Some(mut guard) => f(&mut guard),
            None => self.exclusive(f).done().expect("owner terminated"),
        }
    }
}

/// Owner access to the writer; clears `owner_busy` (Release) on drop. Not
/// `Send`: the handshake is tied to the owning OS thread.
pub(crate) struct OwnerGuard<'a> {
    cell: &'a WriterCell,
    _not_send: PhantomData<*const ()>,
}

impl Deref for OwnerGuard<'_> {
    type Target = RingWriter;
    #[inline(always)]
    fn deref(&self) -> &RingWriter {
        // SAFETY: owner_busy is set and no remote user is active; a remote
        // user arriving now waits for owner_busy to clear.
        unsafe { &*self.cell.writer.get() }
    }
}

impl DerefMut for OwnerGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut RingWriter {
        // SAFETY: as in `deref`; the guard is the only owner access.
        unsafe { &mut *self.cell.writer.get() }
    }
}

impl Drop for OwnerGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.cell.owner_busy.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shirusu_transport::clock::system_clock;
    use shirusu_transport::ring::{SharedRegion, WriterPolicy};
    use shirusu_transport::RingConfig;
    use std::sync::Arc;

    #[test]
    fn owner_and_remote_users_never_overlap() {
        let cfg = RingConfig::new(64, 4096);
        let region = SharedRegion::new(cfg, 1, 1);
        let writer =
            unsafe { RingWriter::new(region.base(), cfg, WriterPolicy::default(), system_clock()) };
        let cell = Arc::new(WriterCell::new(writer));
        let inside = Arc::new(AtomicBool::new(false));
        let enter = |inside: &AtomicBool| {
            assert!(!inside.swap(true, Ordering::AcqRel), "overlapping access");
            std::hint::spin_loop();
            inside.store(false, Ordering::Release);
        };
        // The main thread claims ownership; the others are remote users.
        let mut fast = 0;
        cell.with(|_| ());
        let remotes: Vec<_> = (0..3)
            .map(|_| {
                let (cell, inside) = (Arc::clone(&cell), Arc::clone(&inside));
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        assert!(cell.with_owner(|_| ()).is_err(), "not the owner");
                        cell.exclusive(|_| enter(&inside)).done().unwrap();
                    }
                })
            })
            .collect();
        for _ in 0..20_000 {
            if cell.with_owner(|_| enter(&inside)).is_ok() {
                fast += 1;
            } else {
                cell.exclusive(|_| enter(&inside)).done().unwrap();
            }
        }
        for r in remotes {
            r.join().unwrap();
        }
        assert!(fast > 0);
    }

    fn cell() -> Arc<WriterCell> {
        let cfg = RingConfig::new(64, 4096);
        let region = Box::leak(Box::new(SharedRegion::new(cfg, 1, 1)));
        let writer =
            unsafe { RingWriter::new(region.base(), cfg, WriterPolicy::default(), system_clock()) };
        Arc::new(WriterCell::new(writer))
    }

    /// Review P0: an owner terminated inside the fast path (modeled by
    /// leaking its guard, as TerminateThread skips Drop) must not block
    /// remote users forever, and its writer must never be used again.
    #[test]
    fn terminated_owner_is_detected_and_its_writer_abandoned() {
        let cell = cell();
        let c = Arc::clone(&cell);
        std::thread::spawn(move || {
            let guard = c.try_owner().expect("first user owns the cell");
            std::mem::forget(guard); // terminated while busy
        })
        .join()
        .unwrap();
        assert!(cell.owner_terminated());
        let ran = AtomicBool::new(false);
        assert_eq!(
            cell.exclusive(|_| ran.store(true, Ordering::Relaxed)),
            Access::OwnerTerminated
        );
        assert!(!ran.load(Ordering::Relaxed), "poisoned writer was used");
        assert!(cell.is_abandoned());
        // The fast path stays closed for any thread (TLS addresses recycle).
        assert!(cell.try_owner().is_none());
        assert_eq!(cell.exclusive(|_| ()), Access::OwnerTerminated);
    }

    /// An owner that exited outside the fast path leaves a usable writer.
    #[test]
    fn owner_terminated_outside_the_fast_path_keeps_the_writer() {
        let cell = cell();
        let c = Arc::clone(&cell);
        std::thread::spawn(move || drop(c.try_owner().unwrap()))
            .join()
            .unwrap();
        assert!(cell.owner_terminated());
        assert_eq!(cell.exclusive(|_| 7), Access::Done(7));
        assert!(!cell.is_abandoned());
    }

    /// A live owner that holds the fast path for a long time is waited for,
    /// never overtaken on a timeout.
    #[test]
    fn slow_live_owner_is_never_overtaken() {
        let cell = cell();
        let inside = Arc::new(AtomicBool::new(false));
        let (c, i) = (Arc::clone(&cell), Arc::clone(&inside));
        let (tx, rx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            let guard = c.try_owner().unwrap();
            i.store(true, Ordering::Release);
            tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            i.store(false, Ordering::Release);
            drop(guard);
        });
        rx.recv().unwrap();
        let saw_inside = cell.exclusive(|_| inside.load(Ordering::Acquire));
        assert_eq!(saw_inside, Access::Done(false));
        owner.join().unwrap();
    }
}
