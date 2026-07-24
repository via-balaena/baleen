// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The concurrency predicate, made checkable (M5 Arc 4)
//!
//! Every interior-mutable `static` on the metal used to carry its own `unsafe impl Sync` justified
//! by one commented predicate — *"single boot CPU; secondaries stay PSCI-parked in `_start`"* —
//! repeated at nine sites. Nine prose justifications for one claim is exactly the class of thing
//! this project converts to a machine check, so this module holds **one** cell type, **one** `Sync`
//! argument, and a **runtime guard** that makes the claim fire loudly the moment it stops holding.
//!
//! ## The audit: it was never one predicate. It is three.
//!
//! Classifying the nine sites before proposing a mechanism (design-lessons #37/#39) split them into
//! three genuinely different obligations, enforced at three different tiers:
//!
//! 1. **No second CPU executes hypervisor code.** *Already machine-enforced*, and not by PSCI:
//!    `_start` masks `MPIDR_EL1[23:0]` and hard-parks any core with nonzero affinity before the boot
//!    stack is even set (see `main.rs`). The SAFETY comments cited PSCI parking and thereby
//!    *under*-claimed what the code actually does. [`assert_boot_cpu`] re-states it on the
//!    *executing* path (`_start` covers only the *entry* path).
//! 2. **No agent observes a half-built structure.** The second agent here is not a CPU — it is the
//!    Stage-2 **page-table walker** and the VMID-tagged TLB. This is a *publication* obligation
//!    (barriers + TLB maintenance), discharged by `stage2::enable_stage2` and the rebirth `tlbi`
//!    (design-lesson #28f), not by exclusion. It is live *today*, on one CPU.
//! 3. **No two mutable borrows of one cell are live at once.** A *single-CPU* property, and the one
//!    that was pure prose. Four accessors handed out `&'static mut` with no lifetime tie, so nothing
//!    — not the type system, not a comment — prevented two live aliases. **This is what [`BootCell`]
//!    enforces.**
//!
//! Class 3 is what breaks first, and *not because of SMP*: `handle_guest_irq` touches no cell today,
//! but `VcpuOps::inject_interrupt` is unrealized and sits in the deferral ledger. Realizing it puts
//! an asynchronous EL2 handler onto `hv-core` state — a second agent **on one CPU**.
//!
//! ## Contract
//!
//! - **Property:** at most one [`BootRef`] to a given [`BootCell`] exists at any instant, so the
//!   `&mut T` it derefs to is genuinely exclusive. The claim is taken with a
//!   `compare_exchange` on a per-cell [`AtomicBool`] and released in [`BootRef`]'s `Drop`; a second
//!   claim **halts loudly** rather than aliasing.
//! - **Check:** the `selftest` boot runs [`selftest_exclusion`] — a live guard, a refused
//!   `try_borrow_mut`, the guard dropped, an accepted `try_borrow_mut` — so the flag is witnessed
//!   *by the mechanism under test* on every CI boot (design-lesson #24(f)), not merely asserted.
//! - **Scope:** this **does not make anything SMP-safe**. A second CPU still cannot run hypervisor
//!   code. What changes is the failure mode: an AP's `compare_exchange` loses and the machine
//!   *stops*, instead of nine `unsafe` blocks silently ceasing to be sound at once.
//! - **Honest limit:** a runtime flag is a **check, not a proof** — it catches a violation on the
//!   path actually taken; it does not prove no path violates. The compile-time half is real though,
//!   and does most of the work: [`BootRef`] has a *bounded* lifetime, so a `&mut` derived from it
//!   cannot outlive it, and the borrow checker rejects the overlap statically at every site that
//!   used to mint an unbounded `&'static mut`.

use core::cell::UnsafeCell;
use core::fmt::Write;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::park;

/// The boot CPU's `MPIDR_EL1` affinity — all-zero, matching the `_start` gate's `cbnz` on
/// `MPIDR_EL1 & 0xffffff` (Aff2:Aff1:Aff0, so a secondary whose index lands in a higher affinity
/// level is still caught).
const BOOT_CPU_AFFINITY: u64 = 0;

/// This core's `MPIDR_EL1` affinity (Aff2:Aff1:Aff0), masked exactly as `_start` masks it.
fn cpu_affinity() -> u64 {
    let mpidr: u64;
    // SAFETY: `MPIDR_EL1` is a read-only identification register, readable at EL2; the read has no
    // memory effect and no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {m}, mpidr_el1",
            m = out(reg) mpidr,
            options(nomem, nostack, pure),
        );
    }
    mpidr & 0x00ff_ffff
}

/// Halt unless this is the boot CPU — the "single boot CPU" predicate, checked on the **executing**
/// path rather than only at the entry path `_start` gates.
///
/// **Expected never to fire.** `_start` already parks every non-primary core unconditionally, so on
/// any boot that reaches Rust this is a tautology; it earns its place by covering a core that
/// reaches hypervisor code *without* passing the reset entry (a future AP bring-up, a non-PSCI or
/// real-hardware reset path). That it does not fire is recorded, not hidden — see
/// `docs/ARC4-CONCURRENCY-PREDICATE.md`'s hypothesis-deletion table (design-lesson #39).
pub(crate) fn assert_boot_cpu(what: &str) {
    let aff = cpu_affinity();
    if aff != BOOT_CPU_AFFINITY {
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: {what}: hypervisor code reached on a non-boot CPU (MPIDR affinity 0x{aff:06x}); halting"
        );
        park();
    }
}

/// An interior-mutable `static` whose exclusivity is **checked**, not commented.
///
/// Replaces the per-site `UnsafeCell` + `unsafe impl Sync` + unbounded `&'static mut` accessor with
/// one type carrying one `Sync` argument and a runtime claim. See the module docs for the
/// three-class audit that decided this shape (a lock would have been wrong for six of the nine
/// sites: most of them need *exclusive borrow* or *publication*, not mutual exclusion).
pub(crate) struct BootCell<T> {
    /// The name reported when a double claim halts the machine — so the halt message names the
    /// cell, not just the fact.
    name: &'static str,
    /// Set while a [`BootRef`] to this cell is live.
    claimed: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: **the one `Sync` argument on the metal's exclusive-mutable statics** (nine sites collapsed
// to this). `&BootCell<T>` exposes `T` only through [`BootCell::borrow_mut`] /
// [`BootCell::try_borrow_mut`], each of which hands back a [`BootRef`] only after winning a
// `compare_exchange` on `claimed`, and `BootRef`'s `Drop` is the sole release. So at most one
// `&mut T` derived from this cell exists at any instant — on this CPU (where the hazard is
// re-entrancy: the trap handler versus phase setup) and, were an AP ever brought online, across
// CPUs too (where the loser halts rather than aliasing). `BootCell::as_ptr` is the one documented
// hole and does not claim; its two call sites are the hand-off to the guest-entry trampoline, where
// EL2 is *leaving* and holds no borrow.
unsafe impl<T> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    /// A cell holding `value`, unclaimed. `const` so it can initialize a `static`.
    pub(crate) const fn new(name: &'static str, value: T) -> Self {
        BootCell {
            name,
            claimed: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Claim exclusive access, or **halt**.
    ///
    /// A refused claim means a second mutable borrow of this cell is live — either EL2 code
    /// re-entered itself (the single-CPU hazard) or a second CPU reached hypervisor state (the SMP
    /// one). Neither is recoverable and neither may proceed, so this halts loudly in the project's
    /// idiom rather than returning an error nobody could act on.
    pub(crate) fn borrow_mut(&'static self) -> BootRef<T> {
        assert_boot_cpu(self.name);
        match self.try_claim() {
            Some(r) => r,
            None => {
                let mut uart = crate::uart();
                let _ = writeln!(
                    uart,
                    "baleen: {}: second mutable borrow while one is live (re-entrant EL2 path, or a second CPU); halting",
                    self.name
                );
                park();
            }
        }
    }

    /// Claim exclusive access, or return `None` — the non-halting form, so the boot self-test can
    /// *witness* a refusal without ending the boot.
    #[cfg(feature = "selftest")]
    pub(crate) fn try_borrow_mut(&'static self) -> Option<BootRef<T>> {
        self.try_claim()
    }

    /// The raw storage, **without** claiming it.
    ///
    /// The one documented hole in the exclusivity argument, kept narrow deliberately: its callers
    /// hand a pointer to the guest-entry trampoline and then `eret` out of EL2, so there is no
    /// borrow to hold and no EL2 code left to alias with. Every other access goes through
    /// [`borrow_mut`](Self::borrow_mut).
    pub(crate) fn as_ptr(&'static self) -> *mut T {
        self.value.get()
    }

    fn try_claim(&'static self) -> Option<BootRef<T>> {
        // `Acquire`/`Release` rather than `Relaxed`: the claim must order the *contents* of the cell
        // against the previous holder's writes. On one CPU that is free; it is written correctly
        // here so the mechanism does not need revisiting if an AP is ever onlined.
        if self
            .claimed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(BootRef { cell: self })
        } else {
            None
        }
    }
}

/// A live exclusive borrow of a [`BootCell`]. Derefs to the cell's `T`; releases the claim on drop.
///
/// The type-level half of the mechanism: unlike the `&'static mut` accessors it replaces, a `&mut T`
/// taken from a `BootRef` is bounded by the guard, so the borrow checker — not a comment — rejects
/// an overlapping use.
pub(crate) struct BootRef<T: 'static> {
    cell: &'static BootCell<T>,
}

impl<T> Deref for BootRef<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard holds the cell's claim (taken in `try_claim`, released only in `Drop`),
        // so no other reference into the cell exists.
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for BootRef<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `Deref`, and `&mut self` makes this the sole path to the value through the sole
        // live guard.
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for BootRef<T> {
    fn drop(&mut self) {
        self.cell.claimed.store(false, Ordering::Release);
    }
}

/// **The non-vacuity witness (`selftest` builds).** Assert the exclusion flag actually excludes:
/// with a guard live, a second claim is REFUSED; once it drops, the same claim is ACCEPTED. Both
/// halves matter — a flag stuck at "claimed" would pass the first and fail the second, and a flag
/// that never sets would pass the second and fail the first, so neither degenerate mechanism can
/// print this marker.
///
/// Run against a dedicated cell so the check cannot perturb live guest state, and then against the
/// **production** [`crate::guest::GUEST_HV`] cell (idle at this point in the boot) so the witness is
/// about the real statics rather than only about the type.
#[cfg(feature = "selftest")]
pub(crate) fn selftest_exclusion(uart: &mut crate::Pl011) {
    static PROBE: BootCell<u64> = BootCell::new("selftest-probe", 0);

    let held = PROBE.borrow_mut();
    let refused = PROBE.try_borrow_mut().is_none();
    drop(held);
    let regained = PROBE.try_borrow_mut().is_some();

    let hv_held = crate::guest::GUEST_HV.borrow_mut();
    let hv_refused = crate::guest::GUEST_HV.try_borrow_mut().is_none();
    drop(hv_held);
    let hv_regained = crate::guest::GUEST_HV.try_borrow_mut().is_some();

    if refused && regained && hv_refused && hv_regained {
        let _ = writeln!(
            uart,
            "baleen: selftest: BootCell exclusion OK (second borrow refused while live, accepted after drop; probe + the live GUEST_HV cell)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: selftest: BootCell exclusion FAIL (refused={refused} regained={regained} hv_refused={hv_refused} hv_regained={hv_regained}); halting"
        );
        park();
    }
}
