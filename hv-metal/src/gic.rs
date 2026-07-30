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
/// `ICH_HCR_EL2.UIE` (bit 1) — **Underflow Interrupt Enable.** While set, the GIC asserts the EL2
/// **maintenance interrupt** ([`MAINT_INTID`]) whenever *zero or one* list register is in a non-Invalid
/// state, i.e. the LR bank has run down and can accept more. This is the hardware's "refill me" signal,
/// and it is what lets the software pending set drain into the bank **while the guest is still running**
/// (III-1) rather than only at the next EL2 exit.
///
/// **It is level-based, so it must be armed only while there is something to refill with.** With `UIE`
/// set and the pending set empty, an idle guest (0 LRs occupied) satisfies the underflow condition
/// permanently and the maintenance interrupt re-asserts immediately after every EOI — an interrupt storm
/// that livelocks EL2. [`set_underflow_interrupt`] is therefore driven from the emptiness of the pending
/// set, never enabled once and left on.
const ICH_HCR_EL2_UIE: u64 = 1 << 1;
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

/// `ICH_LR<n>_EL2.HW` (bit 61) — this virtual interrupt is **mapped to a physical one**, named by
/// [`LR_PINTID_SHIFT`]. Left 0 by [`inject`] (a pure virtual interrupt, deactivated entirely in the
/// virtual interface); set by [`inject_hw`], which is what a *forwarded* physical interrupt needs.
///
/// **Why the bit exists, and why ③-a2 cannot work without it.** A forwarded device interrupt has a
/// physical lifecycle (Pending → Active → Inactive) that only a *deactivate* ends, and for a
/// **level-triggered** source — the arch timer's PPI, asserted while `CNTV_CTL_EL0.ISTATUS` is set —
/// deactivating it while the level is still high makes the GIC re-assert immediately. So EL2 cannot
/// deactivate on the guest's behalf: it must wait until the guest has serviced the device and dropped
/// the level, and EL2 gets no signal when that happens. `HW=1` is the hardware's answer: the guest's
/// own EOI of the *virtual* interrupt deactivates the *physical* interrupt named by `pINTID`, with no
/// EL2 involvement at all. This is how KVM forwards the arch timer, for the same reason.
const LR_HW: u64 = 1 << 61;
/// `ICH_LR<n>_EL2.pINTID`, bits [41:32] — the **physical** INTID a `HW=1` list register is mapped to.
/// Ten bits, so it names INTIDs 0..=1023 (the SPI/PPI/SGI range); LPIs are out of its reach and out of
/// this port's scope.
const LR_PINTID_SHIFT: u64 = 32;
/// Width of the `pINTID` field — an INTID that does not fit cannot be named by a `HW=1` LR, so
/// [`inject_hw`] refuses rather than silently truncating into a *different* physical interrupt.
const LR_PINTID_BITS: u32 = 10;

/// `ICC_CTLR_EL1.EOImode` (bit 1) — **split priority-drop from deactivate.** With `EOImode=0` (the
/// reset value, and what the synthetic path uses) a write to `ICC_EOIR1_EL1` does both. With it set,
/// `ICC_EOIR1_EL1` drops the running priority ONLY, and deactivation must come from elsewhere.
///
/// **The real-Linux forwarding path requires it set at EL2**, and the requirement is not a style
/// choice: EL2 must return to a low running priority so *other* interrupts can be taken, while leaving
/// the forwarded interrupt **Active** so its still-asserted level cannot re-signal. Deactivation then
/// arrives from the guest through [`LR_HW`]. With `EOImode=0` those two needs are in direct conflict —
/// drop the priority and you deactivate; keep it Active and EL2 stays at the interrupt's priority.
#[cfg(feature = "real-linux")]
const ICC_CTLR_EL1_EOIMODE: u64 = 1 << 1;

/// A moderate priority for injected interrupts — below `ICC_PMR_EL1 = 0xff`, so it passes the mask.
const INJECT_PRIORITY: u64 = 0x80;

/// The LR **State** field, bits [63:62]: `0b00` Invalid (free), `0b01` Pending, `0b10` Active, `0b11`
/// Pending+Active. A free list register the allocator may reuse has State = Invalid (the whole field 0).
const LR_STATE_MASK: u64 = 0b11 << 62;

/// The architectural maximum number of list registers (GICv3 implements at most 16, `ICH_LR0..15`); the
/// per-vCPU LR store ([`crate::guest`]'s `GuestContext`) is sized to this, though only
/// [`num_list_registers`] are live on a given machine (4 on QEMU `virt`).
pub(crate) const MAX_LIST_REGISTERS: usize = 16;

/// A list register with State = Invalid holds no interrupt — a free slot [`inject`] may allocate.
pub(crate) fn lr_is_free(lr: u64) -> bool {
    lr & LR_STATE_MASK == 0
}

/// The vINTID a list register carries (bits [31:0]). (`selftest`-only: the LR-bank ownership witness
/// checks it; the switch and injector treat the LR as an opaque 64-bit value.)
#[cfg(feature = "selftest")]
pub(crate) fn lr_vintid(lr: u64) -> u32 {
    (lr & 0xffff_ffff) as u32
}

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

/// Arm or disarm the **underflow maintenance interrupt** ([`ICH_HCR_EL2_UIE`]) — read-modify-write so
/// the virtual-interface enable and every other `ICH_HCR_EL2` control is preserved (III-1).
///
/// Call with `true` exactly while the software pending set is non-empty and with `false` the moment it
/// drains; see [`ICH_HCR_EL2_UIE`] for why leaving it armed over an empty set storms. The write needs no
/// `isb` for correctness of the *state* — but one is issued anyway so the arming is in effect before a
/// following `eret` hands the CPU to a guest that may immediately underflow the bank.
pub(crate) fn set_underflow_interrupt(armed: bool) {
    // SAFETY: `ICH_HCR_EL2` is an EL2 control register for the virtual CPU interface. Read-modify-write
    // of the single UIE bit preserves `En` (and any IMPDEF bits); `isb` orders it before a dependent
    // `eret`. No memory effect.
    unsafe {
        if armed {
            asm!(
                "mrs {t}, ICH_HCR_EL2",
                "orr {t}, {t}, {uie}",
                "msr ICH_HCR_EL2, {t}",
                "isb",
                t = out(reg) _,
                uie = in(reg) ICH_HCR_EL2_UIE,
                options(nomem, nostack, preserves_flags),
            );
        } else {
            asm!(
                "mrs {t}, ICH_HCR_EL2",
                "bic {t}, {t}, {uie}",
                "msr ICH_HCR_EL2, {t}",
                "isb",
                t = out(reg) _,
                uie = in(reg) ICH_HCR_EL2_UIE,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

/// Whether the **underflow maintenance interrupt** is currently armed (`ICH_HCR_EL2.UIE`) — the
/// read-back the III-1 witness uses to assert the arming is driven by the pending set's emptiness and
/// not left latched on. (`selftest`-only; the real paths only ever *set* it.)
#[cfg(feature = "selftest")]
pub(crate) fn underflow_interrupt_armed() -> bool {
    let hcr: u64;
    // SAFETY: `ICH_HCR_EL2` is readable at EL2; read-only here, no memory effect.
    unsafe {
        asm!("mrs {h}, ICH_HCR_EL2", h = out(reg) hcr, options(nomem, nostack, preserves_flags));
    }
    hcr & ICH_HCR_EL2_UIE != 0
}

/// Inject virtual interrupt `intid`: place a *pending* Group-1 virtual interrupt in the **first free**
/// list register (M5 Arc 8b). Up to [`num_list_registers`] distinct interrupts can be simultaneously
/// pending, each in its own LR, so a new injection never overwrites one the guest has not yet taken.
/// The hardware CPU interface presents them to the guest (as a taken IRQ if `PSTATE.I` is unmasked, or
/// via `ICC_IAR1_EL1` if it polls).
///
/// Returns `false` if the bank is full. This is the **raw LR allocator**, and a `false` here is no
/// longer a delivery failure: since III-1 its caller
/// (`guest::ArmVcpu::inject_interrupt`) records the vINT in the vCPU's software **pending set** and arms
/// [`set_underflow_interrupt`], so the vINT is delivered when the bank next runs down. Callers that
/// bypass that wrapper (the LR-bank witness) still treat `false` as "the bank is full", which is all
/// this function claims.
#[must_use]
pub(crate) fn inject(intid: u32) -> bool {
    place(encode_lr(intid, None))
}

/// **The ONE list-register encoder** (#55). `hw` is `Some(pintid)` for a *forwarded* physical
/// interrupt — see [`LR_HW`] for why that case exists — and `None` for a purely virtual one.
fn encode_lr(vintid: u32, hw: Option<u32>) -> u64 {
    let base = LR_STATE_PENDING
        | LR_GROUP1
        | (INJECT_PRIORITY << LR_PRIORITY_SHIFT)
        | ((vintid as u64) << LR_VINTID_SHIFT);
    match hw {
        Some(pintid) => base | LR_HW | ((pintid as u64) << LR_PINTID_SHIFT),
        None => base,
    }
}

/// Place an encoded list-register value in the first free LR. `false` = the bank is full.
fn place(lr: u64) -> bool {
    for i in 0..num_list_registers() {
        if lr_is_free(read_lr(i)) {
            // `write_lr` `isb`s, so the injection is in effect before the following `eret`.
            write_lr(i, lr);
            return true;
        }
    }
    false
}

/// Inject `vintid` as a **hardware-mapped** virtual interrupt: the guest's EOI of it will deactivate
/// the physical interrupt `pintid` (see [`LR_HW`]). This is the ③-a2 forwarding primitive — EL2 takes
/// the guest's device interrupt because `HCR_EL2.IMO` routes it there, and hands it on without ever
/// having to decide *when* the device stopped asserting.
///
/// Returns `false` if the bank is full **or** if `pintid` does not fit [`LR_PINTID_BITS`]. The second
/// case is refused rather than truncated: a truncated `pINTID` would name a *different* physical
/// interrupt, so the guest's EOI would deactivate someone else's — silent, and far worse than a
/// refusal the caller reports.
#[must_use]
#[cfg(feature = "real-linux")]
pub(crate) fn inject_hw(vintid: u32, pintid: u32) -> bool {
    if pintid >= (1 << LR_PINTID_BITS) {
        return false;
    }
    place(encode_lr(vintid, Some(pintid)))
}

/// The SGI id a write to `ICC_SGI1R_EL1` requests — bits [27:24], so 0..=15 (the whole SGI range).
///
/// **Why EL2 sees this write at all.** `HCR_EL2.IMO=1` redirects EL1's *interrupt-handling* `ICC_*`
/// accesses to the virtual CPU interface, but `ICC_SGI1R_EL1` is not one of them: generating an SGI
/// names its targets by **physical affinity** (`Aff1..3` + a target list, or "all but self"), which is
/// a statement about real PEs that a guest must not be allowed to make. So the architecture traps it
/// to EL2 instead, and the hypervisor decides what it means. That trap is unavoidable under `IMO=1` —
/// it is not something this port opted into — and leaving it unhandled is a dead guest the moment the
/// kernel raises its first IPI.
///
/// **What ③-a2 does with it, and the honest bound.** One guest, one vCPU: every SGI a guest can
/// generate is addressed to itself, so the faithful emulation is to make that SGI pending as a purely
/// *virtual* interrupt ([`inject`], `HW=0` — the guest invented it, so there is no physical interrupt
/// to deactivate and a hardware mapping would be a lie). **The affinity fields are deliberately not
/// read**, because with a single vCPU there is no other target they could name; ③-b, which has a
/// second guest and may have a second vCPU, is where routing them becomes a real decision rather than
/// a degenerate one.
#[cfg(feature = "real-linux")]
pub(crate) fn sgi1r_intid(value: u64) -> u32 {
    ((value >> 24) & 0xf) as u32
}

/// Put EL2's **physical** CPU interface into split priority-drop/deactivate mode
/// ([`ICC_CTLR_EL1_EOIMODE`]), so [`eoi_physical`] drops the running priority without deactivating.
///
/// Real-Linux only, and deliberately not folded into [`enable_physical_cpu_interface_el2`]: the
/// synthetic path shares that function and *depends* on `EOImode=0`, because it deactivates the timer
/// PPI itself after [`disable_vtimer`] has already dropped the level. Two configurations, two
/// lifecycles, one explicit call — rather than a mode flip the synthetic arcs would inherit silently.
#[cfg(feature = "real-linux")]
pub(crate) fn set_eoi_mode_split() {
    // SAFETY: `ICC_CTLR_EL1` at EL2 is the physical CPU-interface control. Read-modify-write of the
    // single `EOImode` bit preserves every other control; `isb` orders it before an interrupt can be
    // taken and completed under the new mode. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_CTLR_EL1",
            "orr {t}, {t}, {m}",
            "msr ICC_CTLR_EL1, {t}",
            "isb",
            t = out(reg) _,
            m = in(reg) ICC_CTLR_EL1_EOIMODE,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Enable just enough of the EL2 virtual CPU interface to *access* the list registers as system
/// registers — `ICC_SRE_EL2.SRE` (turn on the system-register interface) and `ICH_HCR_EL2.En` (the
/// virtual interface operational) — WITHOUT `HCR_EL2.IMO`, so no physical IRQ is routed to EL2 and no
/// virtual IRQ is presented to a guest. Used by the Arc-7c LR-ownership self-test so it can read/write
/// `ICH_LR0_EL2` as plain registers without perturbing the interrupt routing the real phases set up.
/// (`selftest`-only: the real phases enable the full interface via [`enable_el2`].)
#[cfg(feature = "selftest")]
pub(crate) fn enable_lr_sysreg_access() {
    // SAFETY: `ICC_SRE_EL2`/`ICH_HCR_EL2` are EL2 controls; we set only SRE (RMW to preserve IMPDEF SRE
    // bits) and the virtual-interface enable, `isb` before a dependent `ICH_LR0_EL2` access follows. No
    // `HCR_EL2` change, so physical-IRQ routing is untouched. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "isb",
            "msr ICH_HCR_EL2, {en}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE,
            en = in(reg) ICH_HCR_EL2_EN,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// The number of implemented list registers, `ICH_VTR_EL2.ListRegs + 1` (bits [4:0]) — 4 on QEMU
/// `virt` GICv3, clamped to [`MAX_LIST_REGISTERS`]. Accesses to `ICH_LR<n>_EL2` for `n >=` this are
/// UNPREDICTABLE, so every LR loop bounds itself by this. `ICH_VTR_EL2` is an `ICH_*` register readable
/// at EL2 without the CPU-interface `ICC_SRE_EL2` gate (the same class as the LRs, which the Arc-7c
/// scheduler-phase save/restore already accessed with no phase enabling the interface).
pub(crate) fn num_list_registers() -> usize {
    let vtr: u64;
    // SAFETY: `ICH_VTR_EL2` is a RO EL2 identification register for the virtual interface; no effect.
    unsafe {
        asm!("mrs {v}, ICH_VTR_EL2", v = out(reg) vtr, options(nomem, nostack, preserves_flags));
    }
    (((vtr & 0x1f) as usize) + 1).min(MAX_LIST_REGISTERS)
}

// The `ICH_LR<n>_EL2` register encoding must be a string literal in `asm!`, so a runtime index `n`
// dispatches through the 16-arm matches below. `concat!` builds the register name at compile time.
macro_rules! read_one_lr {
    ($n:literal) => {{
        let v: u64;
        // SAFETY: `ICH_LR<n>_EL2` (n < num_list_registers()) is a RW EL2 list register; read-only here.
        unsafe {
            asm!(concat!("mrs {v}, ICH_LR", stringify!($n), "_EL2"),
                 v = out(reg) v, options(nomem, nostack, preserves_flags));
        }
        v
    }};
}
macro_rules! write_one_lr {
    ($n:literal, $v:expr) => {{
        // SAFETY: `ICH_LR<n>_EL2` (n < num_list_registers()) is a RW EL2 list register. `isb` so the
        // write is in effect before a following `eret` presents the interrupt state to the guest.
        unsafe {
            asm!(concat!("msr ICH_LR", stringify!($n), "_EL2, {v}"), "isb",
                 v = in(reg) $v, options(nomem, nostack, preserves_flags));
        }
    }};
}

/// Read list register `n` — the raw 64-bit value, pending-vINT State and all (`n < num_list_registers()`).
/// The LRs are per-vCPU state the hardware does not swap, so the context switch saves them (M5 Arc 7c/8b).
pub(crate) fn read_lr(n: usize) -> u64 {
    match n {
        0 => read_one_lr!(0),
        1 => read_one_lr!(1),
        2 => read_one_lr!(2),
        3 => read_one_lr!(3),
        4 => read_one_lr!(4),
        5 => read_one_lr!(5),
        6 => read_one_lr!(6),
        7 => read_one_lr!(7),
        8 => read_one_lr!(8),
        9 => read_one_lr!(9),
        10 => read_one_lr!(10),
        11 => read_one_lr!(11),
        12 => read_one_lr!(12),
        13 => read_one_lr!(13),
        14 => read_one_lr!(14),
        15 => read_one_lr!(15),
        _ => 0,
    }
}

/// Write list register `n` — the inverse of [`read_lr`], to restore a vCPU's saved bank on a switch
/// (writing 0 leaves the LR Invalid) or to inject (`n < num_list_registers()`).
pub(crate) fn write_lr(n: usize, v: u64) {
    match n {
        0 => write_one_lr!(0, v),
        1 => write_one_lr!(1, v),
        2 => write_one_lr!(2, v),
        3 => write_one_lr!(3, v),
        4 => write_one_lr!(4, v),
        5 => write_one_lr!(5, v),
        6 => write_one_lr!(6, v),
        7 => write_one_lr!(7, v),
        8 => write_one_lr!(8, v),
        9 => write_one_lr!(9, v),
        10 => write_one_lr!(10, v),
        11 => write_one_lr!(11, v),
        12 => write_one_lr!(12, v),
        13 => write_one_lr!(13, v),
        14 => write_one_lr!(14, v),
        15 => write_one_lr!(15, v),
        _ => {}
    }
}

// ─── physical GICv3 (for receiving the virtual-timer PPI at EL2 — M5 Arc 5d) ─────────────────────────
//
// So far the vGIC only INJECTED. To deliver a real timer TICK, EL2 must RECEIVE the physical virtual-
// timer interrupt (the guest's `CNTV` fires PPI INTID 27, routed to EL2 by `HCR_EL2.IMO`) and inject the
// matching virtual interrupt. That requires the physical GICv3 distributor + this CPU's redistributor to
// be initialized, plus the EL2 physical CPU interface enabled. QEMU `virt` GICv3 memory map:

/// GICv3 distributor base (QEMU `virt`).
///
/// `pub(crate)`: since ③-a1 the real-Linux guest's Stage-2 pass-through window is **derived from
/// the GIC region** rather than written out as its own pair of literals — the window exists to give
/// the guest the interrupt controller, so the interrupt controller's own addresses are what should
/// define it. `guest.dts`'s `intc@8000000` names the same base.
pub(crate) const GICD_BASE: u64 = 0x0800_0000;
/// GICv3 redistributor RD_base for CPU 0 (QEMU `virt`); the SGI/PPI frame is the next 64 KiB frame.
pub(crate) const GICR_RD_BASE: u64 = 0x080A_0000;
const GICR_SGI_BASE: u64 = GICR_RD_BASE + 0x1_0000;

/// Length of the whole GICv3 redistributor region (QEMU `virt`: 0xf60000, enough for every CPU's
/// RD + SGI frame pair), matching the second `reg` entry of `guest.dts`'s `intc@8000000`.
///
/// `real-linux` only: it exists to size the Stage-2 pass-through window, and only that build maps
/// one (the synthetic guests reach the GIC through EL2, never through their own Stage-2). Gated
/// rather than allowed, so each configuration lints exactly what it compiles (⑭/⑭b).
#[cfg(feature = "real-linux")]
pub(crate) const GICR_LEN: u64 = 0x00f6_0000;

/// Exclusive end of the GICv3 MMIO the guest is given — and, on QEMU `virt`, **exactly** the address
/// the PL011 starts at. That coincidence is what let ③-a1 drop the UART out of the pass-through
/// window without touching `guest.dts`: the window still ends where the GIC does.
#[cfg(feature = "real-linux")]
pub(crate) const GICR_END: u64 = GICR_RD_BASE + GICR_LEN;

/// `GICD_CTLR` — `ARE_NS` (bit 4, affinity routing) + `EnableGrp1NS` (bit 1).
const GICD_CTLR_ARE_GRP1: u32 = (1 << 4) | (1 << 1);
/// `GICR_WAKER.ProcessorSleep` (bit 1) and `.ChildrenAsleep` (bit 2).
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// The EL1 architected **virtual timer** interrupt — PPI 11 = INTID 27 (Arm ARM / GIC spec). This is the
/// interrupt the guest's `CNTV` raises; the guest also sees it as vINTID 27 after we inject.
pub(crate) const VTIMER_INTID: u32 = 27;

/// The STRUCTURAL half of ③-a2's witness, in a `const assert!` rather than a boot marker
/// (design-lesson #97): the timer PPI must be nameable in a `HW=1` list register's `pINTID` field, or
/// [`inject_hw`] would refuse it at run time and the forwarding path would be dead on arrival. A boot
/// marker can only witness what a boot exercises; this is true or the build fails.
const _: () = assert!(
    VTIMER_INTID < (1 << LR_PINTID_BITS),
    "the forwarded timer PPI must fit ICH_LR<n>_EL2.pINTID — a wider INTID cannot be hardware-mapped"
);

/// The GIC **maintenance interrupt** — PPI 9 = INTID 25 on QEMU `virt` (`ARCH_GIC_MAINT_IRQ`). The
/// virtual CPU interface raises it at EL2 when a condition enabled in `ICH_HCR_EL2` holds; III-1 enables
/// exactly one such condition, [`ICH_HCR_EL2_UIE`] (bank underflow), and uses it to refill the list
/// registers from the software pending set while the guest runs.
///
/// **This INTID is a QEMU `virt` platform fact, not architectural** — the maintenance signal is wired to
/// a PPI by the SoC integrator, so a real-hardware port must take it from the device tree
/// (`interrupts` on the `interrupt-controller` node) rather than from this constant.
pub(crate) const MAINT_INTID: u32 = 25;

/// Initialize the physical GICv3 enough to receive the EL2-bound PPIs: enable the distributor (affinity
/// routing + Group 1), wake this CPU's redistributor, and enable PPI [`VTIMER_INTID`] (the guest's
/// virtual timer) **and** PPI [`MAINT_INTID`] (the GIC maintenance interrupt — III-1's LR-refill signal)
/// as Group 1 interrupts at a deliverable priority. MMIO at EL2 (MMU-off, direct physical addressing).
///
/// Enabling the maintenance PPI here is safe *without* enabling III-1's refill machinery: the interrupt
/// only fires for a condition selected in `ICH_HCR_EL2`, and the sole condition this port ever sets is
/// `UIE`, which [`set_underflow_interrupt`] arms only while a pending set is non-empty. So on any path
/// that never overflows an LR bank, this enable is inert.
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

        // PPIs 27 (vtimer) and 25 (GIC maintenance — III-1) in the SGI/PPI frame: Group 1, a
        // deliverable priority, then enable both. Both are PPIs of this redistributor, so one
        // `IGROUPR0`/`ISENABLER0` word covers them; `IPRIORITYR` is byte-addressed per INTID.
        let igroupr0 = (GICR_SGI_BASE + 0x0080) as *mut u32;
        let g = core::ptr::read_volatile(igroupr0) | (1 << VTIMER_INTID) | (1 << MAINT_INTID);
        core::ptr::write_volatile(igroupr0, g);
        // IPRIORITYR is byte-addressed per INTID; write a mid priority (below the PMR mask 0xff).
        core::ptr::write_volatile(
            (GICR_SGI_BASE + 0x0400 + VTIMER_INTID as u64) as *mut u8,
            0x80,
        );
        core::ptr::write_volatile(
            (GICR_SGI_BASE + 0x0400 + MAINT_INTID as u64) as *mut u8,
            0x80,
        );
        // ISENABLER0: set the enable bits for INTID 27 and INTID 25.
        core::ptr::write_volatile(
            (GICR_SGI_BASE + 0x0100) as *mut u32,
            (1 << VTIMER_INTID) | (1 << MAINT_INTID),
        );
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

/// Whether the GIC has the **maintenance interrupt** ([`MAINT_INTID`]) asserted as pending at this CPU's
/// redistributor (`GICR_ISPENDR0` bit 25) — read WITHOUT acknowledging it (III-1's witness).
///
/// This is the difference between "we set `UIE`" and "the hardware agrees the bank has underflowed and is
/// asking to be refilled". `set_underflow_interrupt` only writes an EL2 control bit; whether the GIC turns
/// that into an actual interrupt request is the part the metal cannot assert by inspecting its own
/// bookkeeping, so it is read back from the interrupt controller instead. Reading the pending state rather
/// than `ICC_IAR1_EL1` keeps this side-effect-free — an ack would take the interrupt and leave it active.
#[cfg(feature = "selftest")]
pub(crate) fn maint_is_pending() -> bool {
    // SAFETY: `GICR_ISPENDR0` is a documented redistributor register in the SGI/PPI frame — device memory
    // on the `virt` machine, addressed directly at EL2 (MMU off). Read-only; aliases no Rust memory.
    unsafe {
        core::ptr::read_volatile((GICR_SGI_BASE + 0x0200) as *const u32) & (1 << MAINT_INTID) != 0
    }
}

/// Clear a stale pending [`MAINT_INTID`] at the redistributor (`GICR_ICPENDR0`), so the III-1 witness
/// leaves no phantom maintenance interrupt for the first real phase to field. (`selftest`-only.)
#[cfg(feature = "selftest")]
pub(crate) fn clear_maint_pending() {
    // SAFETY: `GICR_ICPENDR0` is the documented clear-pending register in the SGI/PPI frame; writing a
    // 1 clears that INTID's pending state. Device memory at EL2, aliases no Rust memory.
    unsafe {
        core::ptr::write_volatile((GICR_SGI_BASE + 0x0280) as *mut u32, 1 << MAINT_INTID);
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
