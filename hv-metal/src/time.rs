// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The ARM generic timer, behind the [`hv_hal::TimeSource`] fence (Arc 3)
//!
//! `hv-core` owns no clock; it reads time only through [`hv_hal::TimeSource`], a trait whose sole
//! guarantee is that the value *does not run backwards*. On the host, `hv-sim` realizes it with a
//! counter advanced by hand. Arc 3 realizes it on ARM with the **generic timer's physical count** —
//! the first piece of the `hv-hal` fence to gain a real hardware backing (Architecture Audit #1).
//!
//! The fence is **architecture-neutral by construction**: [`hv_hal::Ticks`] is a plain `u64` and the
//! trait names no timer register. `CNTPCT_EL0` appears only *here*, in the ARM implementation — an
//! x86 backend would read the TSC behind the very same trait, and `hv-core` above cannot tell.
//!
//! ## Contract
//!
//! - **Property:** [`GenericTimer::now`] returns the current physical count, a value that increments
//!   monotonically at a constant rate and never runs backwards (Arm ARM: the system counter is
//!   monotonic, ≥56-bit, and — outside counter power-down, which does not occur under EL2 execution
//!   or QEMU — does not wrap in any span that matters). That is exactly, and only, what
//!   `TimeSource` promises.
//! - **Check:** the boot reads `now()` across a bounded spin ([`witness_advance`]) and confirms the
//!   count is non-decreasing throughout *and* strictly advances (the counter is live, not frozen at
//!   zero); the CI boot-test matches the resulting marker.
//! - **Scope:** *refines* the fence — the ARM timer is a faithful `TimeSource`. **Realized but not
//!   yet consumed by a hypercall:** `hv-core` takes time as a plain `Ticks` *input* on `SchedRun`
//!   (the caller stamps it; the core owns no clock), so the first place this value flows into a
//!   dispatched call is M4's first `SchedRun`. Arc 3 proves the fence is honored on the metal; it
//!   does not yet drive a scheduler.
//!
//! ## The QEMU-vs-metal line, drawn per mechanism
//!
//! `now()` issues an `isb` *before* the count read. The Arm ARM permits `mrs CNTPCT_EL0` to be
//! observed out of program order; without a barrier two of our own reads could, on real silicon, be
//! reordered so a later read appears smaller. QEMU's TCG has much stronger effective ordering and
//! would **never** expose that — so the barrier is invisible under emulation and load-bearing on
//! metal. This is precisely the weak-memory blind spot `docs/QEMU-AND-METAL.md` item (2) warns of:
//! we write the metal-correct code and do not let a green QEMU run lull us (design-lesson #23:
//! draw the QEMU-vs-metal line per mechanism). (`FEAT_ECV`'s self-synchronizing `CNTPCTSS_EL0`
//! would fold the barrier into the read, but it is optional; `isb; mrs` is correct on every core.)
//!
//! ## A note on `CNTFRQ_EL0`
//!
//! [`frequency`] reads `CNTFRQ_EL0` for the human-readable banner only. Per the Arm ARM it is a
//! *firmware-programmed label* (boot firmware advertises the rate to lower ELs), not measured
//! hardware — as trustworthy as whoever set it (here, QEMU: 62.5 MHz on `virt`). The **count** is
//! the real, monotonic thing and is what backs `Ticks`; the frequency is advisory metadata, needed
//! only to convert ticks to wall-time, which the fence deliberately does not do.
//!
//! ## Unsafe
//!
//! The `unsafe` is read-only `mrs` of `CNTPCT_EL0` / `CNTFRQ_EL0` (with a leading `isb` for the
//! count), both readable at EL2 with no enable bit. No memory effect beyond the named register.

use core::arch::asm;

use hv_hal::{Ticks, TimeSource};

/// A [`hv_hal::TimeSource`] backed by the ARM generic timer's physical count (`CNTPCT_EL0`).
///
/// Zero-sized: the "clock" is a system register, so an instance carries no state. This is the ARM
/// realization of the fence; the trait above it names nothing ARM-specific.
pub(crate) struct GenericTimer;

impl TimeSource for GenericTimer {
    /// The current physical count. Monotonic and never backwards — the `TimeSource` contract,
    /// realized. The leading `isb` orders the read on real silicon (see the module's
    /// QEMU-vs-metal note).
    fn now(&self) -> Ticks {
        let count: u64;
        // SAFETY: `CNTPCT_EL0` is readable at EL2 with no enable bit; the `isb` prevents the read
        // from being speculated ahead of program order. Read-only, no memory effect.
        unsafe {
            asm!(
                "isb",
                "mrs {c}, cntpct_el0",
                c = out(reg) count,
                options(nomem, nostack, preserves_flags),
            );
        }
        count
    }
}

/// The counter frequency in Hz, from `CNTFRQ_EL0`. Advisory (a firmware/QEMU-programmed label — see
/// the module note); used for the banner, never for the monotonic `Ticks` themselves.
pub(crate) fn frequency() -> u64 {
    let freq: u64;
    // SAFETY: `CNTFRQ_EL0` is readable at EL2; read-only, no memory effect.
    unsafe {
        asm!("mrs {f}, cntfrq_el0", f = out(reg) freq, options(nomem, nostack, preserves_flags));
    }
    freq
}

/// Outcome of the boot-time monotonicity witness.
pub(crate) struct Advance {
    /// The count first read.
    pub start: Ticks,
    /// The count last read (≥ `start`).
    pub end: Ticks,
    /// Whether the count strictly advanced within the spin budget (proves it is live, not frozen).
    pub advanced: bool,
    /// Whether every read was ≥ its predecessor (the monotonic, never-backwards property held).
    pub monotonic: bool,
}

/// Spin reading [`GenericTimer::now`] up to `budget` times, witnessing that the count is monotonic
/// and strictly advances. Returns as soon as it advances (or when the budget is spent).
///
/// The count is non-decreasing by the architecture; this *observes* it, turning the `TimeSource`
/// contract into a checked boot-time fact rather than an assumed one. Under QEMU `virt`'s 62.5 MHz
/// counter a single `isb; mrs` plus loop overhead spans several ticks, so it advances almost
/// immediately; the budget is generous so a slow/cold emulator still witnesses the advance.
pub(crate) fn witness_advance(timer: &GenericTimer, budget: u32) -> Advance {
    let start = timer.now();
    let mut prev = start;
    let mut monotonic = true;
    let mut end = start;
    let mut advanced = false;
    for _ in 0..budget {
        let t = timer.now();
        if t < prev {
            monotonic = false;
        }
        prev = t;
        end = t;
        if t > start {
            advanced = true;
            break;
        }
    }
    Advance {
        start,
        end,
        advanced,
        monotonic,
    }
}
