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

// ─── physical GICv3 (for receiving the virtual-timer PPI at EL2 — M5 Arc 5d) ─────────────────────────
//
// So far the vGIC only INJECTED. To deliver a real timer TICK, EL2 must RECEIVE the physical virtual-
// timer interrupt (the guest's `CNTV` fires PPI INTID 27, routed to EL2 by `HCR_EL2.IMO`) and inject the
// matching virtual interrupt. That requires the physical GICv3 distributor + this CPU's redistributor to
// be initialized, plus the EL2 physical CPU interface enabled. QEMU `virt` GICv3 memory map:

/// GICv3 distributor base (QEMU `virt`).
const GICD_BASE: u64 = 0x0800_0000;
/// GICv3 redistributor RD_base for CPU 0 (QEMU `virt`); the SGI/PPI frame is the next 64 KiB frame.
const GICR_RD_BASE: u64 = 0x080A_0000;
const GICR_SGI_BASE: u64 = GICR_RD_BASE + 0x1_0000;

/// `GICD_CTLR` — `ARE_NS` (bit 4, affinity routing) + `EnableGrp1NS` (bit 1).
const GICD_CTLR_ARE_GRP1: u32 = (1 << 4) | (1 << 1);
/// `GICR_WAKER.ProcessorSleep` (bit 1) and `.ChildrenAsleep` (bit 2).
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// The EL1 architected **virtual timer** interrupt — PPI 11 = INTID 27 (Arm ARM / GIC spec). This is the
/// interrupt the guest's `CNTV` raises; the guest also sees it as vINTID 27 after we inject.
pub(crate) const VTIMER_INTID: u32 = 27;

/// Initialize the physical GICv3 enough to receive the virtual-timer PPI at EL2: enable the distributor
/// (affinity routing + Group 1), wake this CPU's redistributor, and enable PPI [`VTIMER_INTID`] as a
/// Group 1 interrupt at a deliverable priority. MMIO at EL2 (MMU-off, direct physical addressing).
pub(crate) fn init_physical_vtimer() {
    // SAFETY: the GICD/GICR windows are device memory on the `virt` machine, addressed directly at EL2
    // (MMU off). Each write targets a documented GICv3 register at its fixed offset; the reads poll the
    // wake handshake. No Rust memory is aliased.
    unsafe {
        // Distributor: affinity routing + Group 1 enable. (On real silicon a write that changes ARE
        // should be followed by polling `GICD_CTLR.RWP` to observe the register-write completion; QEMU's
        // GICD completes synchronously from a reset-zeroed state, so it is sound to omit here — noted for
        // the real-HW port.)
        core::ptr::write_volatile(GICD_BASE as *mut u32, GICD_CTLR_ARE_GRP1);

        // Wake this CPU's redistributor: clear ProcessorSleep, wait for ChildrenAsleep to clear.
        let waker = (GICR_RD_BASE + 0x0014) as *mut u32;
        let w = core::ptr::read_volatile(waker) & !GICR_WAKER_PROCESSOR_SLEEP;
        core::ptr::write_volatile(waker, w);
        while core::ptr::read_volatile(waker) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
            core::hint::spin_loop();
        }

        // PPI 27 in the SGI/PPI frame: Group 1, a deliverable priority, then enable it.
        let igroupr0 = (GICR_SGI_BASE + 0x0080) as *mut u32;
        let g = core::ptr::read_volatile(igroupr0) | (1 << VTIMER_INTID);
        core::ptr::write_volatile(igroupr0, g);
        // IPRIORITYR is byte-addressed per INTID; write a mid priority (below the PMR mask 0xff).
        core::ptr::write_volatile(
            (GICR_SGI_BASE + 0x0400 + VTIMER_INTID as u64) as *mut u8,
            0x80,
        );
        // ISENABLER0: set the enable bit for INTID 27.
        core::ptr::write_volatile((GICR_SGI_BASE + 0x0100) as *mut u32, 1 << VTIMER_INTID);
    }
}

/// Enable the EL2 **physical** CPU interface so a physical IRQ (the timer PPI) is delivered to EL2:
/// priority mask wide open, Group 1 physical interrupts enabled. (Distinct from the guest's EL1 virtual
/// interface — at EL2 these `ICC_*` registers are the physical ones.)
///
/// Sets `ICC_SRE_EL2.SRE` first so the `ICC_*` system-register accesses are always legal — the function
/// is self-contained and does not rely on a prior phase having enabled the interface (which would be a
/// latent ordering trap if this path were reused standalone, e.g. at the real-Linux capstone).
pub(crate) fn enable_physical_cpu_interface_el2() {
    // SAFETY: `ICC_SRE_EL2`/`ICC_PMR_EL1`/`ICC_IGRPEN1_EL1` at EL2 are the physical CPU-interface
    // controls; we set SRE (system-register interface) then open the priority mask and enable Group 1.
    // `isb` after SRE (a later access depends on it) and before an interrupt can be taken. No memory.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "isb",
            "msr ICC_PMR_EL1, {pmr}",
            "msr ICC_IGRPEN1_EL1, {en}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE,
            pmr = in(reg) 0xffu64,
            en = in(reg) 1u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Acknowledge the highest-priority pending **physical** Group 1 interrupt at EL2 (`ICC_IAR1_EL1`) →
/// its INTID (1023 = spurious).
pub(crate) fn ack_physical() -> u32 {
    let intid: u64;
    // SAFETY: reading `ICC_IAR1_EL1` at EL2 acknowledges a physical interrupt; no memory effect.
    unsafe {
        asm!("mrs {i}, ICC_IAR1_EL1", i = out(reg) intid, options(nomem, nostack, preserves_flags));
    }
    intid as u32
}

/// End-of-interrupt the physical interrupt `intid` at EL2 (`ICC_EOIR1_EL1`).
pub(crate) fn eoi_physical(intid: u32) {
    // SAFETY: writing `ICC_EOIR1_EL1` at EL2 completes a physical interrupt; no memory effect.
    unsafe {
        asm!("msr ICC_EOIR1_EL1, {i}", i = in(reg) intid as u64, options(nomem, nostack, preserves_flags));
    }
}

/// Disable the guest's virtual timer (`CNTV_CTL_EL0 = 0`) from EL2 — used when EL2 fields the timer PPI,
/// so the level-triggered interrupt de-asserts and does not immediately re-fire (a one-shot; periodic
/// timer virtualization for Linux is a 5e concern).
pub(crate) fn disable_vtimer() {
    // SAFETY: `CNTV_CTL_EL0` is accessible at EL2; writing 0 clears ENABLE. No memory effect.
    unsafe {
        asm!(
            "msr CNTV_CTL_EL0, xzr",
            options(nomem, nostack, preserves_flags)
        );
    }
}
