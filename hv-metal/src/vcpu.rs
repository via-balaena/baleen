// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # A real guest's vCPU context — the state a switch must carry (③-b2b-i, feature `real-linux`)
//!
//! ## What this is for
//!
//! `guest.rs` already time-slices two domains on one pCPU, each in its own VMID-tagged Stage-2,
//! switched by `hv-core`'s real scheduler. That machinery is proven and boot-witnessed — and it is
//! scoped to guests a real kernel is nothing like. Its saved context is **four system registers**
//! (`SP_EL1`, `ELR_EL2`, `SPSR_EL2`, `SCTLR_EL1`) plus the GPRs and the vGIC list-register bank,
//! which is complete for integer-register-only synthetic guests and nowhere near enough for Linux:
//! `TTBR0_EL1`/`TTBR1_EL1` alone are not in it, so a switch would leave the peer's Stage-1 tables
//! installed.
//!
//! This module is the context a *real* kernel needs, and the mechanism that proves the list is
//! right rather than merely plausible.
//!
//! ## ★ The vacuity trap, and why POISON is the design
//!
//! The obvious shape for this rung — switch the guest away and back at the timer tick, check it
//! still boots — **passes trivially**. A switch-to-self that saves nothing and restores nothing is
//! indistinguishable from a correct one. That is design-lesson #105's failure exactly: a witness
//! that cannot tell the rung from its absence.
//!
//! So the switch **poisons**. Between save and restore, every register in the table below is
//! clobbered with a distinctive value. If any register the kernel depends on is missing from the
//! table, the poison survives into EL1 and the guest dies — immediately, loudly, and at a point the
//! console names. Safe to do because EL2 runs MMU-off identity and no EL1 register affects EL2's
//! own execution.
//!
//! This inverts the hard part of the problem. **"Which registers must be saved?" stops being a
//! transcription exercise and becomes an experiment**: poison everything, watch what breaks, and
//! let the failures name the list. A register omitted by an author reading the ARM ARM is silent
//! for years; a register omitted here fails on the next boot.
//!
//! ## One derivation
//!
//! The table is declared **once**, by [`ctx_regs!`], which generates the enum, the `ALL` slice, the
//! names and both accessors together. There is no second list to drift from the first — adding a
//! register is one line, and the exhaustive wildcard-free matches mean the compiler, not a reviewer,
//! is what notices if an accessor forgets it (the Phase I-1 `Transition` shape, one layer out).
//!
//! ## Which of these are actually load-bearing — MEASURED, not asserted
//!
//! The poison makes that an experiment too: skip *restoring* one register while still poisoning it,
//! and see whether the guest lives. (Note the probe that does NOT work — removing a register from
//! the table removes it from the poison as well, so the guest keeps its own value and survives.
//! The discriminating probe is poison-but-do-not-restore.) Measured on the shipped Alpine boot:
//!
//! | register | skipping its restore |
//! |---|---|
//! | `ttbr1_el1` · `sp_el1` · `sp_el0` · `vbar_el1` · `tpidr_el1` · `mdscr_el1` | **kills the boot** |
//! | `par_el1` · `amair_el1` · `esr_el1` · `cntv_cval_el0` | boot survives |
//!
//! Two things worth carrying. **`sp_el0` is load-bearing** — this scoping had it down as "AArch64
//! Linux's choice of `SPSel` is not ours to assume", and the experiment settled it rather than the
//! documentation. And the four survivors **stay in the table**: a register this boot does not depend
//! on may be depended on by another workload (`esr_el1` across a nested exception, `par_el1` across
//! an `AT`, `cntv_cval_el0` when a guest programs a long deadline). What the measurement changes is
//! not the table but the honesty of the claim about it — six of these are verified, four are here on
//! the architecture's authority.
//!
//! ## Honest ceiling — state it before reading the witness
//!
//! The poison proves the table covers what **this** kernel touches on **this** workload. A register
//! the kernel uses only on a path this boot does not take is still unsaved and still undetected.
//! This is a boot-witness-grade result, not a ∀ one: the macro bounds the omission (nothing can be
//! half-added) but does not eliminate it. `hv-metal` is not a Kani target, so there is no theorem
//! here — say so rather than letting "type-total" read as "proven".

use core::arch::asm;

/// Declare the vCPU's system-register context **once**, generating the enum, the enumeration order,
/// the names and both accessors from a single list.
///
/// Every match this expands to is exhaustive and wildcard-free, so a new variant cannot be added
/// without the compiler demanding its read and its write.
macro_rules! ctx_regs {
    ($($variant:ident => $reg:literal),* $(,)?) => {
        /// One system register of a vCPU's context.
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(crate) enum CtxReg {
            $(
                #[doc = concat!("`", $reg, "`")]
                $variant,
            )*
        }

        impl CtxReg {
            /// Every register in the context, in save/restore order.
            pub(crate) const ALL: &'static [CtxReg] = &[$(CtxReg::$variant),*];

            /// The architectural name, for a diagnostic.
            pub(crate) const fn name(self) -> &'static str {
                match self { $(CtxReg::$variant => $reg),* }
            }

            /// Read this register from the live CPU.
            fn read(self) -> u64 {
                let v: u64;
                // SAFETY: every register named in the table is readable at EL2 (EL1 system
                // registers are accessible from EL2, and the two EL2 registers trivially so). No
                // memory operand, no stack effect.
                unsafe {
                    match self {
                        $(CtxReg::$variant => asm!(
                            concat!("mrs {0}, ", $reg),
                            out(reg) v,
                            options(nomem, nostack, preserves_flags),
                        )),*
                    }
                }
                v
            }

            /// Write this register on the live CPU.
            ///
            /// # Safety
            /// The caller must be at EL2 and must be about to restore a coherent context: these
            /// registers steer EL1 translation and exception entry, so writing a value that does not
            /// belong to the vCPU being resumed hands the guest someone else's address space.
            unsafe fn write(self, v: u64) {
                // SAFETY: forwarded from this function's own contract; each register is writable at
                // EL2 and none affects EL2's own (MMU-off, identity) execution.
                unsafe {
                    match self {
                        $(CtxReg::$variant => asm!(
                            concat!("msr ", $reg, ", {0}"),
                            in(reg) v,
                            options(nomem, nostack, preserves_flags),
                        )),*
                    }
                }
            }
        }
    };
}

ctx_regs! {
    // ── where the vCPU resumes ──
    ElrEl2 => "elr_el2",
    SpsrEl2 => "spsr_el2",
    // ── stacks. Both, because AArch64 Linux's choice of `SPSel` is not ours to assume. ──
    SpEl0 => "sp_el0",
    SpEl1 => "sp_el1",
    // ── EL1 translation: the half whose absence would be immediately fatal ──
    SctlrEl1 => "sctlr_el1",
    Ttbr0El1 => "ttbr0_el1",
    Ttbr1El1 => "ttbr1_el1",
    TcrEl1 => "tcr_el1",
    MairEl1 => "mair_el1",
    AmairEl1 => "amair_el1",
    ContextidrEl1 => "contextidr_el1",
    // ── EL1 exception handling ──
    VbarEl1 => "vbar_el1",
    EsrEl1 => "esr_el1",
    FarEl1 => "far_el1",
    ElrEl1 => "elr_el1",
    SpsrEl1 => "spsr_el1",
    ParEl1 => "par_el1",
    // ── per-thread pointers: Linux keeps per-CPU and per-task state here ──
    TpidrEl0 => "tpidr_el0",
    TpidrroEl0 => "tpidrro_el0",
    TpidrEl1 => "tpidr_el1",
    // ── traps and timers ──
    CpacrEl1 => "cpacr_el1",
    CntkctlEl1 => "cntkctl_el1",
    CntvCvalEl0 => "cntv_cval_el0",
    CntvCtlEl0 => "cntv_ctl_el0",
    MdscrEl1 => "mdscr_el1",
}

/// The value written over every context register between save and restore.
///
/// Deliberately not `0`: zero is a plausible reset value for several of these, and a register that
/// "works" after being zeroed would hide a missing save. This pattern is a non-canonical address, an
/// invalid `TCR`, and an obviously-wrong counter value all at once, so whichever register is missing,
/// the guest's next use of it is a fault rather than a subtly wrong result.
const POISON: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// A vCPU's saved context: the GPRs live in the trap frame, everything else here.
///
/// **The vGIC list-register bank is NOT here, and for ③-b2b-i that is correct rather than merely
/// convenient — but it is a DECLARED RESIDUE, not a solved problem.** This switch resumes the *same*
/// vCPU, and nothing between the save and the restore touches `ICH_LR<n>_EL2`, so the bank the guest
/// left is the bank it returns to; carrying it would be a copy with no reader. `guest.rs` carries it
/// (Arc 7c/8b, III-1) because its switch resumes a *different* vCPU, which is exactly the case
/// ③-b2b-ii introduces here. **When a second guest lands, this context must carry the LR bank too,
/// or the incoming guest inherits the outgoing one's pending virtual interrupts** — the cross-vCPU
/// leak Arc 8b and Phase III-3 closed for the synthetic path, reopened on the real one.
///
/// It should then be carried by *reusing* `gic.rs`'s existing save/restore rather than by adding a
/// second copy of the bank here — the two-derivations defect ⑭ spent a rung removing.
pub(crate) struct VcpuCtx {
    /// `x0..x30`, mirrored to and from the trap frame.
    pub(crate) x: [u64; 31],
    /// One entry per [`CtxReg::ALL`], in that order.
    regs: [u64; CtxReg::ALL.len()],
}

impl VcpuCtx {
    /// An empty context.
    pub(crate) const fn new() -> Self {
        Self {
            x: [0; 31],
            regs: [0; CtxReg::ALL.len()],
        }
    }

    /// Capture the live vCPU state into this context.
    pub(crate) fn save(&mut self, x: &[u64; 31]) {
        self.x = *x;
        for (slot, reg) in self.regs.iter_mut().zip(CtxReg::ALL) {
            *slot = reg.read();
        }
    }

    /// Write this context back onto the CPU.
    ///
    /// # Safety
    /// Restores EL1 translation and exception state; the caller must be at EL2 and this context must
    /// belong to the vCPU about to be resumed.
    pub(crate) unsafe fn restore(&self, x: &mut [u64; 31]) {
        *x = self.x;
        for (slot, reg) in self.regs.iter().zip(CtxReg::ALL) {
            // SAFETY: forwarded from this function's contract.
            unsafe { reg.write(*slot) };
        }
    }
}

/// Clobber every context register, so a restore that misses one cannot go unnoticed.
///
/// **This is the rung's instrument, not a debugging aid.** Without it a switch-to-self proves
/// nothing: see the module docs. It runs between [`VcpuCtx::save`] and [`VcpuCtx::restore`], while
/// the machine is at EL2 and no EL1 state is live.
///
/// # Safety
/// The caller must be at EL2 with a saved context in hand, and must restore before returning to EL1.
/// Between this call and that restore the guest's entire EL1 configuration is garbage.
pub(crate) unsafe fn poison() {
    for reg in CtxReg::ALL {
        // SAFETY: forwarded from this function's contract. None of these registers affects EL2's own
        // execution, which runs MMU-off and identity-mapped with its own vectors already installed.
        unsafe { reg.write(POISON) };
    }
}
