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
//! logical thread takes the exclusive path.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use shirusu_transport::ring::RingWriter;

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
}

// SAFETY: the writer is only reached through `with_owner` (its owning OS
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
        }
    }

    /// Run `f` on the owner fast path. Gives `f` back when the caller is not
    /// the owning OS thread or a remote user is pending; then use
    /// [`WriterCell::exclusive`]. Must not be called re-entrantly from `f`.
    #[inline]
    pub(crate) fn with_owner<R, F: FnOnce(&mut RingWriter) -> R>(&self, f: F) -> Result<R, F> {
        let me = thread_token();
        let owner = self.owner.load(Ordering::Relaxed);
        if owner != me
            && (owner != 0
                || self
                    .owner
                    .compare_exchange(0, me, Ordering::Relaxed, Ordering::Relaxed)
                    .is_err())
        {
            return Err(f);
        }
        self.owner_busy.store(true, Ordering::Relaxed);
        shirusu_transport_win::asymmetric_fence_light();
        // Acquire pairs with the remote user's Release clear: its writer
        // updates are visible before the owner touches the writer again.
        if self.remote.load(Ordering::Acquire) {
            self.owner_busy.store(false, Ordering::Release);
            return Err(f);
        }
        let _done = ClearOnDrop(&self.owner_busy);
        // SAFETY: owner_busy is set and no remote user is active; a remote
        // user arriving now waits for owner_busy to clear.
        Ok(f(unsafe { &mut *self.writer.get() }))
    }

    /// Run `f` with exclusive access from any thread (management path).
    pub(crate) fn exclusive<R>(&self, f: impl FnOnce(&mut RingWriter) -> R) -> R {
        let _serialized = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        self.remote.store(true, Ordering::Relaxed);
        shirusu_transport_win::asymmetric_fence_heavy();
        while self.owner_busy.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let _done = ClearOnDrop(&self.remote);
        // SAFETY: the mutex excludes other remote users and the handshake
        // excludes the owner until `remote` clears.
        f(unsafe { &mut *self.writer.get() })
    }

    /// Fast path when possible, otherwise exclusive.
    #[inline]
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut RingWriter) -> R) -> R {
        match self.with_owner(f) {
            Ok(r) => r,
            Err(f) => self.exclusive(f),
        }
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
                        cell.exclusive(|_| enter(&inside));
                    }
                })
            })
            .collect();
        for _ in 0..20_000 {
            if cell.with_owner(|_| enter(&inside)).is_ok() {
                fast += 1;
            } else {
                cell.exclusive(|_| enter(&inside));
            }
        }
        for r in remotes {
            r.join().unwrap();
        }
        assert!(fast > 0);
    }
}
