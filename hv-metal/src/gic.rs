// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # vGIC — hardware GIC virtualization (M5 Arc 5a)
//!
//! The first step toward a real Linux guest: give a guest **interrupts**. Rather than emulate a GICv3 in
//! software, we use the ARM **GIC virtualization extensions** the QEMU `virt` machine exposes at EL2 —
//! exactly how KVM and Xen do it. The hypervisor programs the **list registers** (`ICH_LR<n>_EL2`) to
//! make a virtual interrupt *pending* for the guest, and the hardware GICv3 CPU interface delivers it to
//! the guest's EL1 (or lets the guest acknowledge it via `ICC_IAR1_EL1`). No software distributor.
//!
//! ## Scope (5a) — plumbing, NO isolation content
//!
//! This arc adds a capability (interrupt injection), not an isolation property; the isolation thesis is
//! already proven on the synthetic guests of Arcs 0–4. Audit #7 (Arc 5's small audit) asks only whether
//! the vGIC/timer/PSCI open any *new* cross-domain channel — the injected interrupt reaches only the
//! guest whose list registers the hypervisor programmed, so it does not.
//!
//! ## The registers (GICv3, Arm ARM — the GIC Architecture Specification)
//!
//! - **EL2 control:** `ICC_SRE_EL2` (system-register interface + `Enable` for lower ELs), `ICH_HCR_EL2`
//!   (`En` — turn the virtual CPU interface on), `ICH_LR<n>_EL2` (the list registers), and `HCR_EL2.IMO`
//!   (route physical IRQ to EL2 and enable the *virtual* IRQ to EL1) — the last set by the phase's HCR.
//! - **Guest (EL1) CPU interface:** `ICC_SRE_EL1` (`SRE`), `ICC_PMR_EL1` (priority mask), `ICC_IGRPEN1_EL1`
//!   (enable Group 1), `ICC_IAR1_EL1` (acknowledge → INTID), `ICC_EOIR1_EL1` (end of interrupt).
//!
//! ## Unsafe
//!
//! Every function here is a small `msr`/`mrs` sequence on EL2-legal GIC system registers with an `isb`
//! where a later access depends on the write. No memory effect.

use core::arch::asm;

/// `ICC_SRE_EL2.SRE` (bit 0) — EL2 uses the GICv3 system-register interface (not the memory-mapped one).
const ICC_SRE_EL2_SRE: u64 = 1 << 0;
/// `ICC_SRE_EL2.Enable` (bit 3) — permit lower ELs (the guest) to access `ICC_SRE_EL1`.
const ICC_SRE_EL2_ENABLE: u64 = 1 << 3;
/// `ICH_HCR_EL2.En` (bit 0) — enable the virtual CPU interface (the list registers become active).
const ICH_HCR_EL2_EN: u64 = 1 << 0;
/// `HCR_EL2.IMO` (bit 4) — route physical IRQ to EL2 **and** enable the virtual IRQ to EL1 (the
/// mechanism by which a pending list-register interrupt is presented to the guest).
const HCR_EL2_IMO: u64 = 1 << 4;

// ─── ICH_LR<n>_EL2 field layout (GICv3 list register) ────────────────────────────────────────────
/// vINTID — the virtual interrupt id the guest sees, bits [31:0].
const LR_VINTID_SHIFT: u64 = 0;
/// Priority, bits [55:48] (only the top `ICH_VTR_EL2.PRIbits` are significant).
const LR_PRIORITY_SHIFT: u64 = 48;
/// Group, bit [60] — 1 = Group 1 (acknowledged via `ICC_IAR1_EL1`).
const LR_GROUP1: u64 = 1 << 60;
/// State = Pending, bits [63:62] = 0b01.
const LR_STATE_PENDING: u64 = 0b01 << 62;
// HW (bit 61) is left 0: a pure *virtual* interrupt not mapped to a physical one.

/// A moderate priority for injected interrupts — below `ICC_PMR_EL1 = 0xff`, so it passes the mask.
const INJECT_PRIORITY: u64 = 0x80;

/// Enable the hardware virtual CPU interface at EL2: `ICC_SRE_EL2` (SRE + Enable, so the guest may use
/// `ICC_SRE_EL1`), `ICH_HCR_EL2.En`, and `HCR_EL2.IMO` (so a list-register interrupt reaches the guest).
/// Call once, after `enable_stage2`, before entering an interrupt-capable guest. Only the block phases
/// that want interrupts call this, so physical IRQ routing to EL2 does not affect the cooperative arcs.
pub(crate) fn enable_el2() {
    // SAFETY: `ICC_SRE_EL2`/`ICH_HCR_EL2`/`HCR_EL2` are EL2 control registers; we set only the documented
    // enable bits (read-modify-write to preserve the existing `HCR_EL2` bits — `RW`/`VM` — and IMPDEF
    // SRE bits), `isb` before the guest relies on the interface. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "isb",
            "msr ICH_HCR_EL2, {en}",
            "mrs {t}, hcr_el2",
            "orr {t}, {t}, {imo}",
            "msr hcr_el2, {t}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE | ICC_SRE_EL2_ENABLE,
            en = in(reg) ICH_HCR_EL2_EN,
            imo = in(reg) HCR_EL2_IMO,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Inject virtual interrupt `intid` into the guest by making list register 0 hold a *pending* Group 1
/// virtual interrupt. The hardware CPU interface then presents it to the guest (as a taken IRQ if the
/// guest has `PSTATE.I` unmasked, or via `ICC_IAR1_EL1` if it polls).
pub(crate) fn inject(intid: u32) {
    let lr = LR_STATE_PENDING
        | LR_GROUP1
        | (INJECT_PRIORITY << LR_PRIORITY_SHIFT)
        | ((intid as u64) << LR_VINTID_SHIFT);
    // SAFETY: `ICH_LR0_EL2` is an EL2 list register; writing a pending virtual interrupt is exactly its
    // purpose. `isb` so the injection is in effect before the following `eret` into the guest.
    unsafe {
        asm!(
            "msr ICH_LR0_EL2, {lr}",
            "isb",
            lr = in(reg) lr,
            options(nomem, nostack, preserves_flags),
        );
    }
}
