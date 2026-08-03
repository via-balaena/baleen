// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The FP/SIMD register file, as a vCPU context (③-b2b-ii-f)
//!
//! **The last enumerated member of the "state the hardware does not swap" class.** `v0..v31`,
//! `FPCR` and `FPSR` are a single physical register file shared by every execution context on the
//! CPU. Nothing in the architecture makes them per-vCPU, and until this module nothing in hv-metal
//! saved them — so a guest resumed after a peer had used floating point read **the peer's data**.
//!
//! ## Why this was a real leak and not a theoretical one — MEASURED, not argued
//!
//! `CPACR_EL1` *is* in [`crate::vcpu::CtxReg`], so each guest's FP **trap** state is its own. That
//! is what makes the leak reachable rather than latent: a guest resumes with its own `CPACR_EL1`
//! permitting FP, and its kernel's lazy-FP bookkeeping still believes the live registers hold the
//! current task's state, so it does **not** reload them. It reads whatever the peer left.
//!
//! Scoped with `CPTR_EL2.TFP`, which traps EL1/EL0 FP access to EL2. An `EC=0x07` arriving there
//! means `CPACR_EL1` *allowed* the access — i.e. the guest believed the registers were its own. On
//! the shipped two-kernel boot: **dom 1 took 15 such traps and dom 2 took 16, and every one of them
//! was the guest's first FP use after a switch-in.** So roughly thirty times per boot, a kernel
//! reached for the register file immediately after being switched in, believing it held its own
//! task's state. Stated that way on purpose: that this coincides with a switch on which the *peer*
//! wrote the file is the second measurement below, and the two were never intersected — see the
//! honest ceiling.
//!
//! That trap is a measurement instrument, not the fix. The fix is here, and it is unconditional.
//!
//! ## Honest ceiling — what is measured and what is NOT claimed
//!
//! Two things are measured on the shipped boot: the register file held the **peer's** data at 24
//! switch-ins (12 per guest — `crate::linux`'s `FP_FOREIGN`), and the guests touched FP immediately
//! after a switch-in ~31 times with their own `CPACR_EL1` permitting it. Those are the two halves of
//! a live leak, and each is read off the machine.
//!
//! What is **not** demonstrated is a guest printing a value it took from its peer. That would be the
//! ③-b2b-ii-d-grade claim — guest-observed, unforgeable — and it would need an FP-using program in
//! the initramfs deriving a per-domain pattern (both guests run the SAME initramfs, so a fixed
//! pattern would prove nothing). Recorded as the honest gap rather than papered over: this rung says
//! the registers demonstrably contained the peer's data at moments the guest demonstrably used them,
//! not that a guest was caught reading one.
//!
//! ## Eager, not lazy — and the reason is isolation, not simplicity
//!
//! The classical optimization is to leave `CPTR_EL2.TFP` set, track which vCPU owns the register
//! file, and swap only on first use. It is faster and it is the wrong trade here: it replaces a
//! mechanism that cannot be partially right with one whose failure mode is a **silent** leak of the
//! exact data this rung exists to protect. The cost of doing it eagerly is 16 `stp`/`ldp` pairs
//! against the ~30 system-register accesses a switch already performs, on ~150 switches per boot —
//! unmeasurable next to the emulated-console traffic. Slow is fast ([[workflow-strongest-foundation]]).
//!
//! ## One type, both switches
//!
//! This module exists rather than a field in [`crate::vcpu::VcpuCtx`] because **both** switch paths
//! need it: the real-Linux one and `guest.rs`'s synthetic one, which has carried its own context
//! struct since M5 Arc 1. Two hand-rolled answers to "what is an FP context" is precisely the
//! second-derivation defect ⑭ spent a rung removing for the vGIC, and [`crate::gic::VgicCtx`] is the
//! shape this follows. The synthetic guests are integer-only today, so their half is behaviour-nil —
//! which is the point: the thesis path gets the guarantee before a guest needs it, not after.
//!
//! ## Declared residue — the rest of the class, named rather than left to be discovered
//!
//! Design-lesson #124 is that the moment one member of "state the hardware does not swap" turns up,
//! the whole class is worth enumerating, because naming a class is not enumerating it. So: **SVE
//! (`z0..z31`, `p0..p15`, `FFR`) and SME are NOT saved here.** They are unreachable on this
//! platform — `cortex-a72` implements neither, and `CPTR_EL2.TZ`/`TSM` would trap them if a guest
//! tried — so this is a genuine "not applicable", not an oversight. On a CPU that implements them
//! they become the same leak this module closes for `v0..v31`, and the fix is the same shape.

use core::arch::asm;

/// `CPTR_EL2.TFP` — bit 10. `1` traps FP/SIMD access **at EL2 as well as below it**.
const CPTR_EL2_TFP: u64 = 1 << 10;

/// **Make EL2 able to touch the FP register file at all**, returning `CPTR_EL2` read back
/// (③-b2b-ii-f).
///
/// ## Why this is not "QEMU already zeroes it"
///
/// `CPTR_EL2`'s reset value is architecturally **UNKNOWN**, exactly like `HCR_EL2`'s — which is why
/// [`crate::el2::configure`] writes that register explicitly rather than trusting reset. Nothing in
/// hv-metal had ever written `CPTR_EL2`, so [`FpCtx::save`]'s very first `stp q0, q1` was relying on
/// an UNKNOWN field happening to be 0. It is on this emulator. On silicon that came up with `TFP=1`,
/// EL2 would take a trap **inside its own context switch**, which is about the worst place to
/// discover a reset assumption.
///
/// ## Read-modify-write, and that IS a departure from `el2::configure` — deliberately
///
/// `HCR_EL2` is written whole because that arc wanted *every* field defined. Here a full write would
/// mean encoding `CPTR_EL2`'s RES1 bits from memory, and getting those wrong is a silent
/// CONSTRAINED-UNPREDICTABLE rather than a loud failure. Clearing the one bit whose value this rung
/// depends on, and then **reading it back to prove it took**, gets the property without betting on a
/// bit pattern. The other trap bits are left as found: `TTA` (trace), `TAM`, `TCPAC` and `TZ` gate
/// facilities hv-metal does not use.
pub(crate) fn enable_at_el2() -> u64 {
    let readback: u64;
    // SAFETY: `CPTR_EL2` is RW at EL2. The read-modify-write clears exactly `TFP` and preserves every
    // other field, including whatever RES1 bits this implementation defines; `isb` context-
    // synchronizes the write before the read-back and before any later FP access. No memory effect.
    unsafe {
        asm!(
            "mrs {r}, cptr_el2",
            "bic {r}, {r}, {b}",
            "msr cptr_el2, {r}",
            "isb",
            "mrs {r}, cptr_el2",
            r = out(reg) readback,
            b = in(reg) CPTR_EL2_TFP,
            options(nomem, nostack, preserves_flags),
        );
    }
    readback
}

/// Whether `CPTR_EL2.TFP` is clear in a read-back — the post-condition [`enable_at_el2`] establishes.
pub(crate) fn el2_fp_enabled(cptr: u64) -> bool {
    cptr & CPTR_EL2_TFP == 0
}

/// A vCPU's floating-point context: the whole SIMD register file plus its two control registers.
///
/// `#[repr(C, align(16))]` because the save/restore below addresses `v` with `stp`/`ldp` of `q`
/// registers, which require 16-byte alignment; the `const _` block pins that so a future field
/// insertion cannot silently misalign it.
#[repr(C, align(16))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FpCtx {
    /// `v0..v31`, two `u64` halves each, in register order. A `[u64; 64]` rather than `[u128; 32]`
    /// so the layout is obvious at the asm boundary that reads it.
    v: [u64; 64],
    /// `FPCR` — rounding mode, flush-to-zero, default-NaN. Per-task state in Linux.
    fpcr: u64,
    /// `FPSR` — the cumulative exception flags. Also per-task.
    fpsr: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(FpCtx, v) == 0);
    assert!(core::mem::align_of::<FpCtx>().is_multiple_of(16));
};

impl FpCtx {
    /// A zeroed context — what a vCPU that has never run owns.
    ///
    /// Not merely an initializer: it is what guest B's seeded context carries into its first
    /// instruction, so a second kernel starts with a register file of zeroes rather than with
    /// whatever the first kernel happened to leave there. The isolation property holds from
    /// instruction one, not from the first save.
    pub(crate) const ZERO: Self = Self {
        v: [0; 64],
        fpcr: 0,
        fpsr: 0,
    };

    /// Capture the live FP register file into this context. See the [`crate::ctx::CtxComponent`]
    /// impl below, which is what obliges a switch to call it.
    pub(crate) fn save_live(&mut self) {
        let p = core::ptr::addr_of_mut!(self.v) as *mut u64;
        // SAFETY: `p` points at 512 aligned, owned bytes (`v`, pinned at offset 0 by the `const _`
        // above). The `stp` pairs write exactly that range. `fpcr`/`fpsr` are readable at EL2 —
        // `CPTR_EL2.TFP` is left clear, which is what lets EL2 touch the register file at all.
        unsafe {
            asm!(
                // `hv-metal` builds for `aarch64-unknown-none-softfloat`, which disables `fp-armv8`
                // and makes the integrated assembler REJECT `q`-register instructions. That is the
                // right default for EL2 — it must not compute in floating point — but saving a
                // guest's register file is not computing in it: these are 128-bit MOVES, exactly as
                // KVM does them. So the extension is re-enabled for this block only. ⚠ `cargo xtask
                // metal-lint` does NOT catch a mistake here: clippy never runs the assembler on
                // inline asm, so this file passed all five lint configs while failing to build.
                ".arch_extension fp",
                "stp q0,  q1,  [{p}, #0]",
                "stp q2,  q3,  [{p}, #32]",
                "stp q4,  q5,  [{p}, #64]",
                "stp q6,  q7,  [{p}, #96]",
                "stp q8,  q9,  [{p}, #128]",
                "stp q10, q11, [{p}, #160]",
                "stp q12, q13, [{p}, #192]",
                "stp q14, q15, [{p}, #224]",
                "stp q16, q17, [{p}, #256]",
                "stp q18, q19, [{p}, #288]",
                "stp q20, q21, [{p}, #320]",
                "stp q22, q23, [{p}, #352]",
                "stp q24, q25, [{p}, #384]",
                "stp q26, q27, [{p}, #416]",
                "stp q28, q29, [{p}, #448]",
                "stp q30, q31, [{p}, #480]",
                p = in(reg) p,
                options(nostack, preserves_flags),
            );
            // `.arch_extension fp` again: `FPCR`/`FPSR` are gated by the same feature as the `q`
            // registers, so a softfloat build rejects even reading them.
            asm!(".arch_extension fp", "mrs {c}, fpcr", "mrs {s}, fpsr",
                 c = out(reg) self.fpcr, s = out(reg) self.fpsr,
                 options(nomem, nostack, preserves_flags));
        }
    }

    /// Write this context back onto the live CPU.
    ///
    /// # Safety
    /// The caller must be at EL2 with the outgoing context already saved; between a [`poison`] and
    /// this call the register file belongs to nobody.
    pub(crate) unsafe fn restore_live(&self) {
        let p = core::ptr::addr_of!(self.v) as *const u64;
        // SAFETY: forwarded from this function's contract; `p` covers the same 512 aligned bytes
        // `save` wrote, and the `ldp` pairs read exactly that range.
        unsafe {
            asm!(
                // See `save` for why the extension is re-enabled here.
                ".arch_extension fp",
                "ldp q0,  q1,  [{p}, #0]",
                "ldp q2,  q3,  [{p}, #32]",
                "ldp q4,  q5,  [{p}, #64]",
                "ldp q6,  q7,  [{p}, #96]",
                "ldp q8,  q9,  [{p}, #128]",
                "ldp q10, q11, [{p}, #160]",
                "ldp q12, q13, [{p}, #192]",
                "ldp q14, q15, [{p}, #224]",
                "ldp q16, q17, [{p}, #256]",
                "ldp q18, q19, [{p}, #288]",
                "ldp q20, q21, [{p}, #320]",
                "ldp q22, q23, [{p}, #352]",
                "ldp q24, q25, [{p}, #384]",
                "ldp q26, q27, [{p}, #416]",
                "ldp q28, q29, [{p}, #448]",
                "ldp q30, q31, [{p}, #480]",
                p = in(reg) p,
                options(readonly, nostack, preserves_flags),
            );
            asm!(".arch_extension fp", "msr fpcr, {c}", "msr fpsr, {s}", "isb",
                 c = in(reg) self.fpcr, s = in(reg) self.fpsr,
                 options(nomem, nostack, preserves_flags));
        }
    }
}

/// The poison context — a **designed** value, not `vcpu.rs`'s blanket `0xDEAD_BEEF_DEAD_BEEF`.
///
/// Design-lesson #126: a poison belongs to the state kind it clobbers, and does not transfer between
/// kinds. Taken field by field:
///
/// * **`v0..v31` carry no encoding constraints at all** — they are pure data, so an arbitrary
///   recognizable pattern is both safe and maximally destructive. ⚠ **It is still not loud.** An
///   earlier draft of this bullet claimed a kernel resuming into a file of `0xDEADBEEF…` would
///   produce wrong bytes immediately; the kill probe below refuted that, and the claim is corrected
///   here rather than left sitting three paragraphs above its own refutation.
/// * **`FPCR` is a valid-but-hostile encoding**, in the shape `ICH_VMCR_EL2`'s poison established:
///   default-NaN, flush-to-zero and round-toward-zero, all architecturally legal with no RES0 bit
///   set. An unrestored `FPCR` changes arithmetic semantics rather than destroying data — quieter
///   again. Setting the FP exception-trap enables would be louder but is unreliable: those bits are
///   RES0 unless `FEAT_TRAPFP` is implemented.
/// * **`FPSR` gets every cumulative exception flag set** — also a valid encoding, and one no correct
///   guest would be holding.
#[cfg(feature = "real-linux")]
const POISON: FpCtx = FpCtx {
    v: [0xDEAD_BEEF_DEAD_BEEF; 64],
    // DN (25) | FZ (24) | RMode = 0b11, round toward zero (23:22).
    fpcr: (1 << 25) | (1 << 24) | (0b11 << 22),
    // IDC | IXC | UFC | OFC | DZC | IOC.
    fpsr: (1 << 7) | (1 << 4) | (1 << 3) | (1 << 2) | (1 << 1) | 1,
};

/// Clobber the live FP register file, so a restore that misses part of it cannot go unnoticed.
///
/// **The instrument, not a debugging aid** — the same standing as [`crate::vcpu::poison`], but be
/// precise about what it buys, because the read-back witness overlaps it. A broken restore is caught
/// *without* poison on any switch between two different guests: the live file still holds the
/// outgoing guest's data, which differs from the incoming one's saved copy. What poison adds is the
/// **switch-to-self** case — where live and incoming are the same context, so a restore that did
/// nothing at all would read back as correct. Poison is what stops that being vacuous, exactly as it
/// is for the system-register half.
///
/// It is one call to [`FpCtx::restore`] rather than its own asm, so the poison path and the resume
/// path are the same code (design-lesson #130): a restore bug cannot hide by being absent from the
/// poison.
///
/// ## ⚠ THE KILL PROBE DOES NOT KILL, AND THAT IS THE MOST IMPORTANT THING ON THIS PAGE
///
/// Run it — delete the `fp.restore()` in [`crate::vcpu::VcpuCtx::restore`], leaving this poison in
/// place — and **the boot survives**. Both kernels reach userspace, print every marker, and power
/// off: no `Kernel panic`, no `LINUX GUEST TRAP`. Only `crate::linux`'s read-back witness notices,
/// reporting `fp FAIL: dom 1 verified 56 FP restores across 66 switch-ins`.
///
/// That is the opposite of `vcpu.rs`'s system-register poison, where six of ten registers kill the
/// kernel outright and the boot surviving IS the witness. The reason is Linux's own lazy-FP
/// bookkeeping: the guest reloads a task's FP state from memory on its *own* task switches often
/// enough that a clobbered register file is usually overwritten before anything reads it.
///
/// **So the read-back is not belt-and-braces here — it is the only thing standing between a broken
/// FP restore and a silent, green boot.** And the only way to know that was to run the probe rather
/// than reason about it (design-lesson #117).
///
/// Note also what the failure count says: 56 of 66 "verified" rather than 0 of 66, because the
/// poison PROPAGATES — a guest that does not touch FP before its next switch-out has the poison
/// saved into its own context, so the next comparison matches. The ~10 that fail are exactly the
/// switches where a guest really used floating point in between.
///
/// Gated to `real-linux` for the same reason [`crate::gic::VgicCtx::poison`] is: that is the only
/// switch which poisons. The synthetic path's cross-vCPU witness is guest-OBSERVED (Phase III-3) and
/// needs no destructive step to discriminate.
///
/// # Safety
/// The caller must be at EL2 with the outgoing context saved, and must restore before returning to
/// EL1. Between this call and that restore the FP register file is garbage.
#[cfg(feature = "real-linux")]
pub(crate) unsafe fn poison() {
    // SAFETY: forwarded from this function's contract. EL2 is built for
    // `aarch64-unknown-none-softfloat` and executes no FP instructions of its own, so a garbage
    // register file cannot affect EL2's own execution between here and the restore.
    unsafe { POISON.restore_live() };
}

/// ⑰-a: the FP register file as a declared context component.
impl crate::ctx::CtxComponent for FpCtx {
    fn save(&mut self) {
        self.save_live();
    }

    /// # Safety
    /// Forwarded to [`FpCtx::restore_live`], whose contract this is.
    unsafe fn restore(&self) {
        // SAFETY: forwarded from this function's contract.
        unsafe { self.restore_live() };
    }
}

#[cfg(feature = "real-linux")]
impl crate::ctx::CtxPoison for FpCtx {
    /// # Safety
    /// Forwarded to [`poison`], whose contract this is.
    unsafe fn poison(&self) {
        // SAFETY: forwarded from this function's contract. `&self` is the type witness only.
        unsafe { poison() };
    }
}
