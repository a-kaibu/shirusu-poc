//! 確保失敗で対象プロセスを落とさないための予備領域（2026-11-14 レビュー
//! P2-9）。
//!
//! Rust の `Vec` や `String` は確保に失敗すると `handle_alloc_error` で
//! プロセスを abort させる。記録が無ければアプリは NULL を受け取って処理
//! できた場面でも、Detour の中の確保が失敗すると対象アプリごと落ちる
//! （x86 でメモリ上限に近い対象で起こり得る）。
//!
//! [`ReserveAllocator`] は Agent DLL の global allocator として使う。
//! 通常はシステムの確保をそのまま使い、失敗したときだけ静的な予備領域
//! から切り出して返す。予備領域を使ったら [`low_memory`] が真になり、
//! 以後の Detour は記録せずに元の API を素通しで呼ぶ（欠落として数える）。
//! 予備領域は再利用しない（解放は何もしない）ため、使い切った後の失敗は
//! 従来どおり abort になる。

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// 予備領域の大きさ。記録中の 1 回分の確保を十分に賄い、残りの Detour が
/// 素通しへ切り替わるまでの間をつなぐ。
pub const RESERVE_BYTES: usize = 1 << 20;

#[repr(C, align(64))]
struct Reserve(UnsafeCell<[u8; RESERVE_BYTES]>);
// SAFETY: 領域は重ならない区間ごとに 1 回だけ切り出される（`NEXT` の CAS）。
unsafe impl Sync for Reserve {}

static RESERVE: Reserve = Reserve(UnsafeCell::new([0; RESERVE_BYTES]));
static NEXT: AtomicUsize = AtomicUsize::new(0);
static LOW_MEMORY: AtomicBool = AtomicBool::new(false);

/// システムの確保が一度でも失敗し、予備領域を使ったか。
#[inline]
pub fn low_memory() -> bool {
    LOW_MEMORY.load(Ordering::Relaxed)
}

fn base() -> usize {
    RESERVE.0.get() as usize
}

fn in_reserve(ptr: *mut u8) -> bool {
    let p = ptr as usize;
    p >= base() && p < base() + RESERVE_BYTES
}

/// 予備領域から切り出す。足りなければ null。切り出した領域は一度も
/// 使われていないため 0 で埋まっている。
fn carve(layout: Layout) -> *mut u8 {
    LOW_MEMORY.store(true, Ordering::Relaxed);
    carve_raw(layout)
}

fn carve_raw(layout: Layout) -> *mut u8 {
    let base = base();
    let mut next = NEXT.load(Ordering::Relaxed);
    loop {
        let start = (base + next).next_multiple_of(layout.align()) - base;
        let Some(end) = start.checked_add(layout.size().max(1)) else {
            return std::ptr::null_mut();
        };
        if end > RESERVE_BYTES {
            return std::ptr::null_mut();
        }
        match NEXT.compare_exchange_weak(next, end, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return (base + start) as *mut u8,
            Err(seen) => next = seen,
        }
    }
}

/// 確保に失敗したときだけ予備領域を使う global allocator。
pub struct ReserveAllocator;

// SAFETY: システムの確保をそのまま委ね、失敗時は重ならない予備区間を返す。
// 予備区間の解放は何もしない（システムへは返さない）。
unsafe impl GlobalAlloc for ReserveAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if p.is_null() {
            carve(layout)
        } else {
            p
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() {
            carve(layout)
        } else {
            p
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !in_reserve(ptr) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !in_reserve(ptr) {
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                return p;
            }
        }
        // SAFETY: the caller guarantees new_size forms a valid layout.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let p = if in_reserve(ptr) {
            unsafe { self.alloc(new_layout) }
        } else {
            carve(new_layout)
        };
        if !p.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, p, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carved_blocks_are_aligned_disjoint_and_never_freed() {
        let a = carve_raw(Layout::from_size_align(10, 8).unwrap());
        let b = carve_raw(Layout::from_size_align(100, 64).unwrap());
        assert!(in_reserve(a) && in_reserve(b));
        assert_eq!(b as usize % 64, 0);
        assert!(b as usize >= a as usize + 10);
        // Freeing a carved block is a no-op; it is never handed out again.
        unsafe { ReserveAllocator.dealloc(a, Layout::from_size_align(10, 8).unwrap()) };
        let c = carve_raw(Layout::from_size_align(10, 8).unwrap());
        assert!(c as usize > b as usize);
        // Growing a carved block copies it.
        unsafe {
            *c = 7;
            let grown = ReserveAllocator.realloc(c, Layout::from_size_align(10, 8).unwrap(), 4096);
            assert!(!grown.is_null());
            assert_eq!(*grown, 7);
            ReserveAllocator.dealloc(grown, Layout::from_size_align(4096, 8).unwrap());
        }
        assert!(carve_raw(Layout::from_size_align(RESERVE_BYTES + 1, 1).unwrap()).is_null());
    }
}
