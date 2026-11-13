//! TSC interpolation of event timestamps.
//!
//! Recording a short API costs two timestamps. On the Windows CI virtual
//! machines `QueryPerformanceCounter` measured about 22 ns while the whole
//! high-load budget is about 18 ns per event, so each writer may instead read
//! the processor time-stamp counter and convert it to the source's QPC units.
//!
//! The conversion is anchored to real source readings rather than to a fixed
//! frequency:
//!
//! - The first readings of a writer return the source value directly until at
//!   least one millisecond of source time has passed. That establishes a scale
//!   from an origin pair `(tsc0, qpc0)` taken together.
//! - Afterwards a value is `anchor_qpc + (tsc - anchor_tsc) * scale`. When the
//!   counter has advanced by about one millisecond since the anchor, the writer
//!   reads the source again, re-anchors there and refines the scale over the
//!   whole baseline from the origin (the estimate improves with time).
//! - Values never decrease within a writer. A counter that moves backwards or
//!   jumps far ahead (another core, migration, suspend) is not interpolated:
//!   the source is read directly and becomes the new anchor.
//!
//! Interpolation therefore deviates from the source by at most the scale error
//! times one anchor interval (about 100 ns right after start-up, decreasing as
//! the baseline grows), and every value stays in source units, so traces keep
//! the existing QPC meaning and cross-process comparison. The mode is used only
//! when the source asks for it and the CPU reports an invariant TSC.

use crate::clock::TimestampSource;
use std::sync::Arc;

/// Reads the processor time-stamp counter when it is usable for interpolation.
#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is available on every x86_64 CPU; it has no memory effects.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: RDTSC exists on every supported i686 (Pentium-class or later) CPU.
        unsafe { core::arch::x86::_rdtsc() }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        0
    }
}

/// Whether the CPU reports an invariant TSC (CPUID.80000007H:EDX[8]): constant
/// rate across P-/C-states, the precondition for interpolating with one scale.
pub fn invariant_tsc_available() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        // Every supported 32-bit target (i686, SSE2 baseline) implements CPUID.
        #[cfg(target_arch = "x86")]
        use core::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::__cpuid;
        // SAFETY: CPUID exists on every supported x86/x86_64 target.
        #[allow(unused_unsafe)] // `__cpuid` became safe after the 1.87 MSRV.
        let max_extended = unsafe { __cpuid(0x8000_0000) }.eax;
        if max_extended < 0x8000_0007 {
            return false;
        }
        // SAFETY: leaf 0x80000007 is within the reported extended range.
        #[allow(unused_unsafe)]
        let power = unsafe { __cpuid(0x8000_0007) };
        power.edx & (1 << 8) != 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Source ticks between anchors (about 1 ms of source time).
fn anchor_interval_qpc(frequency: u64) -> u64 {
    (frequency / 1000).max(1)
}

#[derive(Debug, Clone, Copy)]
struct Interpolation {
    origin_tsc: u64,
    origin_qpc: u64,
    anchor_tsc: u64,
    anchor_qpc: u64,
    /// Source ticks per TSC tick, fixed point with 32 fractional bits.
    scale_q32: u64,
    /// TSC ticks after which the writer re-anchors (about one interval).
    reanchor_tsc: u64,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Every value is a direct source reading.
    Direct,
    /// Waiting for one interval of source time to establish a scale.
    Calibrating {
        origin_tsc: u64,
        origin_qpc: u64,
    },
    Interpolating(Interpolation),
}

/// Per-writer event clock. Not shared between threads: each Ring writer owns one.
pub struct EventTimestamper {
    source: Arc<dyn TimestampSource>,
    mode: Mode,
    interval_qpc: u64,
    last: u64,
}

impl EventTimestamper {
    pub fn new(source: Arc<dyn TimestampSource>) -> Self {
        let interval_qpc = anchor_interval_qpc(source.frequency());
        let mode = if source.tsc_interpolation() {
            let (origin_tsc, origin_qpc) = paired_sample(source.as_ref());
            Mode::Calibrating {
                origin_tsc,
                origin_qpc,
            }
        } else {
            Mode::Direct
        };
        Self {
            source,
            mode,
            interval_qpc,
            last: 0,
        }
    }

    pub fn source(&self) -> &Arc<dyn TimestampSource> {
        &self.source
    }

    pub fn frequency(&self) -> u64 {
        self.source.frequency()
    }

    /// Whether values are currently interpolated from the TSC (diagnostics).
    pub fn interpolating(&self) -> bool {
        matches!(self.mode, Mode::Interpolating(_))
    }

    #[inline]
    pub fn now(&mut self) -> u64 {
        let value = match &mut self.mode {
            Mode::Direct => self.source.now_qpc(),
            Mode::Interpolating(state) => {
                let tsc = read_tsc();
                let delta = tsc.wrapping_sub(state.anchor_tsc);
                // `delta` is below `reanchor_tsc` here, so the product fits in u64
                // for any realistic scale (checked when the scale is computed).
                if delta < state.reanchor_tsc {
                    state.anchor_qpc + ((delta * state.scale_q32) >> 32)
                } else {
                    self.reanchor(tsc)
                }
            }
            Mode::Calibrating {
                origin_tsc,
                origin_qpc,
            } => {
                let (origin_tsc, origin_qpc) = (*origin_tsc, *origin_qpc);
                let (tsc, qpc) = paired_sample(self.source.as_ref());
                if qpc.saturating_sub(origin_qpc) >= self.interval_qpc && tsc > origin_tsc {
                    self.mode =
                        match interpolation(origin_tsc, origin_qpc, tsc, qpc, self.interval_qpc) {
                            Some(state) => Mode::Interpolating(state),
                            None => Mode::Direct,
                        };
                } else if tsc < origin_tsc {
                    // The counter is not monotonic for this thread: never interpolate.
                    self.mode = Mode::Direct;
                }
                qpc
            }
        };
        // Monotonic within the writer, whatever the source or estimate does.
        let value = value.max(self.last);
        self.last = value;
        value
    }

    #[cold]
    fn reanchor(&mut self, tsc_hint: u64) -> u64 {
        let Mode::Interpolating(state) = self.mode else {
            return self.source.now_qpc();
        };
        let (tsc, qpc) = paired_sample(self.source.as_ref());
        // A backward or unrelated counter value restarts calibration from here.
        if tsc < state.anchor_tsc || tsc_hint < state.anchor_tsc || qpc < state.anchor_qpc {
            self.mode = Mode::Calibrating {
                origin_tsc: tsc,
                origin_qpc: qpc,
            };
            return qpc;
        }
        self.mode = match interpolation(
            state.origin_tsc,
            state.origin_qpc,
            tsc,
            qpc,
            self.interval_qpc,
        ) {
            Some(next) => Mode::Interpolating(next),
            None => Mode::Calibrating {
                origin_tsc: tsc,
                origin_qpc: qpc,
            },
        };
        qpc
    }
}

/// Reads the source between two counter readings and pairs it with their midpoint.
fn paired_sample(source: &dyn TimestampSource) -> (u64, u64) {
    let before = read_tsc();
    let qpc = source.now_qpc();
    let after = read_tsc();
    (before + after.wrapping_sub(before) / 2, qpc)
}

/// Builds an interpolation anchored at `(tsc, qpc)` with the scale measured
/// over the baseline from the origin. Rejects scales whose products could
/// overflow within one anchor interval, or a source/counter that did not advance.
fn interpolation(
    origin_tsc: u64,
    origin_qpc: u64,
    tsc: u64,
    qpc: u64,
    interval_qpc: u64,
) -> Option<Interpolation> {
    let tsc_span = tsc.checked_sub(origin_tsc).filter(|&span| span > 0)?;
    let qpc_span = qpc.checked_sub(origin_qpc).filter(|&span| span > 0)?;
    let scale_q32 = u64::try_from(((qpc_span as u128) << 32) / tsc_span as u128).ok()?;
    if scale_q32 == 0 {
        return None;
    }
    // TSC ticks per anchor interval.
    let reanchor_tsc = u64::try_from(((interval_qpc as u128) << 32) / scale_q32 as u128).ok()?;
    // Guarantee `delta * scale_q32` cannot overflow for any delta < reanchor_tsc.
    reanchor_tsc.checked_mul(scale_q32)?;
    Some(Interpolation {
        origin_tsc,
        origin_qpc,
        anchor_tsc: tsc,
        anchor_qpc: qpc,
        scale_q32,
        reanchor_tsc: reanchor_tsc.max(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualTimestampSource;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn direct_mode_is_the_source_value() {
        let source = Arc::new(ManualTimestampSource::new(10, 1000));
        let mut clock = EventTimestamper::new(source.clone());
        assert_eq!(clock.now(), 10);
        source.set(25);
        assert_eq!(clock.now(), 25);
        assert!(!clock.interpolating());
    }

    #[test]
    fn values_never_decrease_even_if_the_source_does() {
        let source = Arc::new(ManualTimestampSource::new(100, 1000));
        let mut clock = EventTimestamper::new(source.clone());
        assert_eq!(clock.now(), 100);
        source.set(50);
        assert_eq!(clock.now(), 100);
    }

    #[test]
    fn interpolation_scale_and_bounds() {
        // 3 GHz counter, 10 MHz source.
        let state = interpolation(0, 0, 3_000_000, 10_000, 10_000).unwrap();
        let expected = ((10_000u128 << 32) / 3_000_000) as u64;
        assert_eq!(state.scale_q32, expected);
        assert!(state.reanchor_tsc.abs_diff(3_000_000) <= 1);
        assert!(interpolation(5, 0, 5, 10, 10).is_none());
        assert!(interpolation(0, 7, 5, 7, 10).is_none());
        assert!(interpolation(10, 0, 5, 10, 10).is_none());
    }

    /// A source that follows the real counter at a known ratio, so the
    /// interpolation can be compared with the exact value.
    struct CounterSource {
        origin: u64,
        divisor: u64,
        reads: AtomicU64,
    }
    impl TimestampSource for CounterSource {
        fn now_qpc(&self) -> u64 {
            self.reads.fetch_add(1, Ordering::Relaxed);
            (read_tsc() - self.origin) / self.divisor
        }
        fn frequency(&self) -> u64 {
            // One anchor interval is 30_000 source ticks (about 70 us here).
            30_000_000
        }
        fn tsc_interpolation(&self) -> bool {
            true
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn interpolated_values_follow_the_source_and_read_it_rarely() {
        if !invariant_tsc_available() {
            return;
        }
        let source = Arc::new(CounterSource {
            origin: read_tsc(),
            divisor: 7,
            reads: AtomicU64::new(0),
        });
        let mut clock = EventTimestamper::new(source.clone());
        let mut previous = 0;
        let mut samples = 0u64;
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(30) {
            let value = clock.now();
            assert!(value >= previous);
            previous = value;
            let exact = (read_tsc() - source.origin) / source.divisor;
            // Interpolation stays within a small fraction of an anchor
            // interval of the truth (pairing noise bounds the scale error).
            assert!(value <= exact + 60 + 2, "value {value} ahead of {exact}");
            samples += 1;
        }
        assert!(clock.interpolating());
        let reads = source.reads.load(Ordering::Relaxed);
        assert!(
            reads * 10 < samples,
            "source read {reads} times for {samples} values"
        );
    }
}
