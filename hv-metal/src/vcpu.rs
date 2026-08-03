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
//! **③-b2b-ii-c2 changed what the poison is FOR, and it is worth being precise about.** With two
//! kernels time-slicing, the switch is no longer a switch-to-self, so it is not vacuous on its own:
//! a register left unsaved now carries one guest's value into the other, and the second kernel dies
//! of it. The poison is no longer the only thing making the mechanism observable. It stays because
//! it still catches the case the two-guest switch cannot — a register whose values happen to AGREE
//! between the two guests at the moment of the switch, which is exactly the register a boot would
//! otherwise keep getting away with. What was the instrument is now the backstop.
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

use crate::ctx::CtxComponent;
#[cfg(feature = "real-linux")]
use crate::ctx::CtxPoison;
use crate::gic;

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

            /// This register's slot in a saved context.
            ///
            /// The enum's discriminants and [`Self::ALL`]'s order are both generated from the one
            /// list below, so the discriminant *is* the index — checked by
            /// [`discriminants_are_indices`] rather than left as a assumption a future edit could
            /// quietly break.
            pub(crate) const fn index(self) -> usize {
                self as usize
            }

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

/// [`CtxReg::index`] returns the register's position in [`CtxReg::ALL`].
///
/// True by construction — one macro generates the enum and the slice from one list — and checked
/// anyway, because "by construction" is what stops being true when someone adds a variant by hand or
/// gives one an explicit discriminant. A wrong index here would silently restore one register's
/// value into another, which is a corrupted guest rather than a build error.
const fn discriminants_are_indices() -> bool {
    let mut i = 0;
    while i < CtxReg::ALL.len() {
        if CtxReg::ALL[i] as usize != i {
            return false;
        }
        i += 1;
    }
    true
}
const _: () = assert!(
    discriminants_are_indices(),
    "a CtxReg's discriminant must be its index in CtxReg::ALL"
);

/// The value written over every context register between save and restore.
///
/// Deliberately not `0`: zero is a plausible reset value for several of these, and a register that
/// "works" after being zeroed would hide a missing save. This pattern is a non-canonical address, an
/// invalid `TCR`, and an obviously-wrong counter value all at once, so whichever register is missing,
/// the guest's next use of it is a fault rather than a subtly wrong result.
const POISON: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// The components a vCPU context is made of, **named for the boot transcript** (⑰-a).
///
/// The compiler is what enforces that every one of these is saved, restored and poisoned — see
/// [`crate::ctx`]. This array exists so the *boot* records which components this build believes a
/// context has, in the same spirit as the register list beside it: a component silently added or
/// removed changes a line the gate asserts. It is a build-time constant, not a count of anything a
/// guest did, so it is structural rather than a claim about the workload (design-lesson #127).
///
/// ⚠ It is a NAME list, not the obligation. Nothing here forces it to agree with the struct — that
/// job belongs to the destructurings, which the compiler checks. Kept short and adjacent for that
/// reason: a reviewer comparing three lines against three fields is a check this file can afford,
/// where three *traversals* against four fields was not.
pub(crate) const CTX_COMPONENTS: [&str; 4] = ["gprs", "sysregs", "vgic", "fp"];

/// The EL1 system-register half of a context, as one **component** (⑰-a).
///
/// A newtype over the array rather than the bare `[u64; N]` for one reason: a component is a thing
/// that implements [`crate::ctx::CtxComponent`], and `VcpuCtx`'s traversals drive every field
/// through that trait. Without it this half would be the one piece of the context whose save and
/// restore were open-coded — which is exactly the shape the rung exists to remove.
#[derive(Clone, Copy)]
pub(crate) struct SysRegs([u64; CtxReg::ALL.len()]);

impl SysRegs {
    /// An empty set.
    const ZERO: Self = Self([0; CtxReg::ALL.len()]);

    /// Overwrite one register's saved value — the boot seed's only reason to reach inside.
    fn set(&mut self, reg: CtxReg, value: u64) {
        self.0[reg.index()] = value;
    }
}

impl crate::ctx::CtxComponent for SysRegs {
    fn save(&mut self) {
        for (slot, reg) in self.0.iter_mut().zip(CtxReg::ALL) {
            *slot = reg.read();
        }
    }

    /// # Safety
    /// Restores EL1 translation and exception state; the caller must be at EL2 and this context must
    /// belong to the vCPU about to be resumed.
    unsafe fn restore(&self) {
        for (slot, reg) in self.0.iter().zip(CtxReg::ALL) {
            // SAFETY: forwarded from this function's contract.
            unsafe { reg.write(*slot) };
        }
    }
}

#[cfg(feature = "real-linux")]
impl crate::ctx::CtxPoison for SysRegs {
    /// # Safety
    /// The caller must be at EL2 with a saved context in hand and must restore before returning to
    /// EL1.
    unsafe fn poison(&self) {
        for reg in CtxReg::ALL {
            // SAFETY: forwarded from this function's contract. None of these registers affects EL2's
            // own execution, which runs MMU-off and identity-mapped with its own vectors installed.
            unsafe { reg.write(POISON) };
        }
    }
}

/// A vCPU's saved context: the GPRs live in the trap frame, everything else here.
///
/// The vGIC per-vCPU state rides along in [`gic::VgicCtx`] — **one type, shared with `guest.rs`'s
/// switch**, because two hand-rolled answers to "what is a vGIC context" is the second-derivation
/// defect ⑭ spent a rung removing (#74).
///
/// ③-b2b-i declared its absence as a residue: correct then (a switch-to-self resumes the same vCPU,
/// so the bank it left is the bank it returns to) and a genuine cross-guest interrupt leak the moment
/// a second guest runs. Closing it early also closed a **latent gap in the synthetic path**, which
/// carried the list registers since Arc 7c/8b but never `ICH_VMCR_EL2` — the guest's own priority
/// mask and group enables, which two domains would have cross-leaked.
pub(crate) struct VcpuCtx {
    /// `x0..x30`, mirrored to and from the trap frame.
    pub(crate) x: [u64; 31],
    /// One entry per [`CtxReg::ALL`], in that order.
    regs: SysRegs,
    /// The vGIC state the hardware keeps per-vCPU and does not swap.
    vgic: gic::VgicCtx,
    /// The FP/SIMD register file, which the hardware does not swap either (③-b2b-ii-f).
    ///
    /// The **last** enumerated member of that class, and the one that stayed open longest: it was
    /// declared a residue when the vGIC members were closed, on the reasoning that no guest here
    /// used floating point. Two real kernels made that false — see [`crate::fp`] for the
    /// measurement (~31 first-FP-uses-after-a-switch per boot, each with the guest's own
    /// `CPACR_EL1` permitting the access).
    fp: crate::fp::FpCtx,
}

impl VcpuCtx {
    /// An empty context.
    pub(crate) const fn new() -> Self {
        Self {
            x: [0; 31],
            regs: SysRegs::ZERO,
            vgic: gic::VgicCtx::ZERO,
            fp: crate::fp::FpCtx::ZERO,
        }
    }

    /// **Seed the context of a vCPU that has never run** (③-b2b-ii-c2).
    ///
    /// **This is what makes a second kernel's BOOT and its RESUME the same code path.** hv-metal
    /// enters guest A by writing `ELR_EL2`/`SPSR_EL2` and `eret`-ing; guest B is never entered that
    /// way at all. Its first instruction is executed by [`Self::restore`] on a switch, exactly like
    /// its ten-thousandth — so there is no second entry sequence to keep in step with the first, and
    /// no path that runs once at boot and is never exercised again.
    ///
    /// The state is the arm64 boot protocol's, and everything not named here is deliberately zero:
    /// `x1..x3` (the protocol requires it), and every EL1 register the kernel sets up for itself.
    /// `TTBR*`/`TCR_EL1` being zero is not a hazard because `sctlr` is entered with the MMU off,
    /// which is the same condition guest A is entered under.
    ///
    /// `sctlr` is passed in rather than computed: it is read back from the live CPU after
    /// [`crate::linux`]'s `init_guest_el1` has cleared the enables, so guest B starts from the
    /// identical value guest A did — RES1 bits and all. Deriving it here would be a second answer to
    /// "what `SCTLR_EL1` does a guest boot with", and the two would agree until a board changed.
    pub(crate) fn seed_boot(&mut self, entry: u64, dtb: u64, spsr: u64, sctlr: u64) {
        *self = Self::new();
        // The arm64 boot protocol: `x0` is the DTB, `x1..x3` are zero.
        self.x[0] = dtb;
        self.regs.set(CtxReg::ElrEl2, entry);
        self.regs.set(CtxReg::SpsrEl2, spsr);
        self.regs.set(CtxReg::SctlrEl1, sctlr);
    }

    /// Capture the live vCPU state into this context.
    /// Capture the live vCPU state into this context.
    ///
    /// **⑰-a: the destructuring is the mechanism, not style.** No `..`, so adding a field to
    /// [`VcpuCtx`] fails to compile here with E0027 — and binding one without acting on it is
    /// `unused_variables`, which `metal-lint` runs as `-D warnings`. `gprs` is the one component
    /// that is not a [`CtxComponent`]: it moves between the context and the exception frame rather
    /// than the hardware, and a whole-array assignment has no partial-failure mode for a trait to
    /// protect against. It is still named here, because being named is what makes it reviewed.
    pub(crate) fn save(&mut self, x: &[u64; 31]) {
        let Self {
            x: gprs,
            regs,
            vgic,
            fp,
        } = self;
        *gprs = *x;
        regs.save();
        vgic.save();
        fp.save();
    }

    /// This context's FP state, for the leak witness in [`crate::linux`].
    pub(crate) fn fp(&self) -> crate::fp::FpCtx {
        self.fp
    }

    /// **Demote this saved context's forwarded interrupts to purely virtual ones**, returning how
    /// many were converted (③-b2b-ii-c1).
    ///
    /// Called between [`Self::save`] and the physical release, because a `HW=1` list register is a
    /// claim on a *physical* interrupt that this vCPU is about to stop owning. See
    /// [`gic::VgicCtx::release_hardware_mappings`] for why the claim cannot travel and what the
    /// outgoing guest does and does not lose.
    pub(crate) fn release_hardware_mappings(&mut self) -> u64 {
        self.vgic.release_hardware_mappings()
    }

    /// Write this context back onto the CPU.
    ///
    /// # Safety
    /// Restores EL1 translation and exception state; the caller must be at EL2 and this context must
    /// belong to the vCPU about to be resumed.
    pub(crate) unsafe fn restore(&self, x: &mut [u64; 31]) {
        // ⑰-a: exhaustive, for the reason given on `save`. The ORDER is ③-b2b-ii-f's and unchanged:
        // the three components are independent (`CPACR_EL1` gates EL0/EL1 FP access, not EL2's,
        // which is `CPTR_EL2`), so this is preserved to keep the rung behaviour-nil rather than
        // because it is forced.
        let Self {
            x: gprs,
            regs,
            vgic,
            fp,
        } = self;
        *x = *gprs;
        // SAFETY: forwarded from this function's contract.
        unsafe { regs.restore() };
        // SAFETY: forwarded from this function's contract.
        unsafe { vgic.restore() };
        // SAFETY: forwarded from this function's contract.
        unsafe { fp.restore() };
    }
}

/// Clobber every component of the live vCPU state, so a restore that misses one cannot go unnoticed.
///
/// **This is the rung's instrument, not a debugging aid.** Without it a switch-to-self proves
/// nothing: see the module docs. It runs between [`VcpuCtx::save`] and [`VcpuCtx::restore`], while
/// the machine is at EL2 and no EL1 state is live.
///
/// ## ⑰-a — why this became a method on a context it does not read
///
/// It was a free function, and that is exactly why the FP register file could be absent from it for
/// six arcs without anyone noticing. `&self` is a **type witness**: it lets the body destructure
/// `Self` exhaustively, which puts poisoning under the same E0027 obligation as `save` and
/// `restore`. A free function cannot be driven from a destructuring, so a forgotten component there
/// degrades from a hard error to nothing at all.
///
/// `x: _` is the other half of the statement. The GPR array is deliberately NOT poisoned — the trap
/// frame is overwritten wholesale by the restore, so there is no partial-restore failure for a
/// poison to expose — and binding it to `_` says that on purpose, in a place a reviewer must look.
///
/// Each component brings its own poison VALUE rather than inheriting [`POISON`], because a poison
/// belongs to the state kind it clobbers (design-lesson #126): a garbage list-register encoding is
/// architecturally UNPREDICTABLE, and `FPCR`/`FPSR` need valid-but-hostile encodings, while
/// `v0..v31` and the EL1 system registers take the blanket pattern.
///
/// # Safety
/// The caller must be at EL2 with a saved context in hand, and must restore before returning to EL1.
/// Between this call and that restore the guest's entire EL1 configuration is garbage.
impl VcpuCtx {
    pub(crate) unsafe fn poison(&self) {
        let Self {
            x: _,
            regs,
            vgic,
            fp,
        } = self;
        // SAFETY: forwarded from this function's contract.
        unsafe {
            regs.poison();
            vgic.poison();
            fp.poison();
        }
    }
}
