// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # M5 Arc 5e — the real-Linux capstone (feature `real-linux`)
//!
//! The documented drop-in from `docs/ARC-5-M5-GUEST-INTERFACE.md`: boot a **real** aarch64 Linux
//! kernel as a single EL1 guest that "owns the machine", on the interfaces the synthetic Arc 0–5
//! guests already proved sound. **No isolation content** — the thesis (Arcs 0–4) is proven on the
//! un-forgeable synthetic guests; this arc only demonstrates the already-proven hardware interface
//! carries an unmodified kernel. `hv-core`/`hv-hal` are untouched; this whole module is behind the
//! `real-linux` feature, so the default build (the CI boot-test) is byte-for-byte unchanged.
//!
//! ## The model — mostly pass-through, and one emulated device (③-a1)
//!
//! A *single* guest still owns most of the real hardware: hv-metal maps the guest RAM window and
//! the **GICv3** device pages through Stage-2, and lets the kernel drive the real GIC. Its
//! **interrupts are no longer its own** — ③-a2 sets `HCR_EL2.IMO=1`, so every physical IRQ the guest
//! would have taken is delivered to EL2 and handed on as a *virtual* interrupt through the list
//! registers ([`handle_linux_irq`]).
//!
//! **The PL011 is no longer among them.** Arc 5e passed a 32 MiB device window through
//! (`0x0800_0000 .. 0x0a00_0000`), which covered the UART at `0x0900_0000` — so the guest wrote its
//! console bytes straight to the hardware. That is the model this doc used to describe as
//! "pass-through, not virtualization", and it is also the reason a *second* guest could not exist:
//! two guests cannot both own one UART. ③-a1 shrank the window to 16 MiB (it now ends exactly where
//! the GIC redistributor region does, which on QEMU `virt` is exactly where the PL011 begins), so a
//! guest access to the UART faults to EL2 and is **trap-and-emulated** by [`crate::vpl011`].
//!
//! So three things reach EL2 now: `HVC` (PSCI — Linux's `method = "hvc"`), an `EC=0x24` **Stage-2
//! data abort**, which [`handle_linux_sync`] routes to the emulated PL011 or reports as a bring-up
//! fault, and — since ③-a2 — every **physical IRQ**, which [`handle_linux_irq`] forwards.
//!
//! ## ③-a2: the guest's interrupts stop being its own
//!
//! `IMO=1` is not a free addition; it **takes away something that worked**. Under `IMO=0` the kernel
//! took its arch-timer PPI (INTID 27) directly, and that is what drove its scheduler. Routing it to
//! EL2 makes hv-metal responsible for giving it back, and a guest that does not get its tick does not
//! boot — so the timer, not the UART, is the load-bearing half of this rung.
//!
//! **The mechanism is `ICH_LR<n>_EL2.HW`, and the synthetic path's answer does not carry over.**
//! `guest.rs` answers the timer PPI with `gic::disable_vtimer()` — a one-shot, which is all a
//! synthetic guest wants and is fatal to a kernel that needs a periodic tick. The arch timer's PPI is
//! **level-triggered**, so it stays asserted until the guest reprograms `CNTV_CVAL_EL0`; EL2 must
//! therefore leave the physical interrupt Active until the guest has done so, and EL2 has no way to
//! know when that is. A hardware-mapped list register makes the guest's own EOI deactivate the
//! physical interrupt (`gic::inject_hw`, with `ICC_CTLR_EL1.EOImode=1` at EL2 so EL2's own EOI drops
//! priority without deactivating). This is how KVM forwards the arch timer.
//!
//! **Still `IMO`-only.** The GICD/GICR remain pass-through, so the guest programs the *real*
//! distributor while EL2 injects through list registers. That is workable for one guest and cannot be
//! for two — two guests can no more share one interrupt controller than one UART — so ③-b needs the
//! GIC emulated, exactly as ③-a1 did for the PL011. The emulated UART is still transmit-only: its RX
//! path needs a forwarded SPI, which this rung's machinery now supports but does not yet wire (see
//! [`crate::vpl011`]'s module docs).
//!
//! ## The memory contract (shared with `cargo xtask qemu-linux`)
//!
//! QEMU `-device loader` deposits three blobs in guest DRAM before hv-metal runs; hv-metal never
//! copies them — it just points the kernel's boot registers at them. hv-metal owns the low 128 MiB
//! (its image is at `0x4008_0000`); the guest owns `0x4800_0000 .. 0x8000_0000` (needs `-m 1024`).
//!
//! | blob      | guest PA      | how the kernel finds it            |
//! |-----------|---------------|------------------------------------|
//! | `Image`   | `0x4800_0000` | `ELR_EL2` (entry, arm64 boot proto)|
//! | DTB       | `0x4b00_0000` | `x0`                               |
//! | initramfs | `0x4c00_0000` | DTB `/chosen` `linux,initrd-*`     |
//!
//! ## Unsafe
//!
//! As the rest of the metal: EL2 system-register setup, the vector-table `global_asm!`, and the
//! `eret` handoff. Every block carries its justification. The Stage-2 table **writes** are no longer
//! among them — since M5 Arc 4 the tables live in a [`crate::cell::BootCell`] (never `static mut`,
//! and no longer a bare `UnsafeCell` either), so building them is ordinary safe code and their
//! exclusivity is checked rather than commented; the same discipline as `stage2.rs`/`guest.rs`.

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use hv_core::hypervisor::DomId;
use hv_core::p2m::{Mfn, PtLevel};
use hv_core::{HvCall, Hypervisor};

use crate::abort::{self, DataAbort, EC_DATA_ABORT};
use crate::cell::BootCell;
use crate::gic;
use crate::pl011::Pl011;
use crate::stage2::{self, HCR_EL2_VM, LINUX_RAM_BASE, LINUX_RAM_END, VTCR_EL2};
use crate::vpl011::{self, VirtPl011};

/// The control domain.
const DOM0: DomId = 0;

// ─── the memory contract ─────────────────────────────────────────────────────────────────────────
//
// FOUR places have to agree about where guest RAM is: the emitter's window, this file, the DTB's
// `/memory` node, and xtask's `-device loader` addresses. Three of them are now ONE declaration —
// `crate::stage2::LINUX_RAM_BASE`/`LINUX_RAM_END`, which is what `build_stage2_from_p2m` actually
// maps. This file used to keep its own `GUEST_RAM_BASE`/`GUEST_RAM_END` literals, and by the time ⑭
// found them they reached nothing but a `writeln!` — a value in a diagnostic and in no boolean, the
// shape design-lesson #74 names.
//
// The FOURTH — xtask's loader addresses — is in a crate that cannot depend on `hv-metal` (this crate
// is workspace-excluded; it does not link for the host), so it CANNOT be folded in at compile time.
// It is bound at RUN time instead: the banner below prints these addresses, and
// `xtask::LINUX_MARKERS` asserts that whole line, so the gate fails if this file and xtask disagree.
// See `docs/ARC-5-M5-GUEST-INTERFACE.md` §5f.

use crate::stage2::{LINUX_RAM_BASE as GUEST_RAM_BASE, LINUX_RAM_END as GUEST_RAM_END};

/// Kernel `Image` load address — the base of guest RAM, per the arm64 boot protocol. `ELR_EL2` entry.
const KERNEL_ENTRY: u64 = GUEST_RAM_BASE;
/// Flattened device tree (DTB) load address — handed to the kernel in `x0`. The one address here
/// with no authoritative source under the fence: it names a spot inside guest RAM that xtask's
/// `-device loader` writes to, so it is asserted at run time (see the note above) rather than
/// derived.
const DTB_ADDR: u64 = 0x4b00_0000;

// The Stage-2 descriptor encodings, the device window and the translation regime used to be declared
// HERE, alongside a 40-line identity mapper. M5 Arc 6b deleted the mapper and moved the emission to
// `crate::stage2` — but only the mapper actually went: TEN constants (`DEV_BASE`, `DEV_END`,
// `DESC_TABLE`, `DESC_BLOCK`, `ADDR_2M`, `ADDR_4K`, `LEAF_AF_RW`, `BLOCK_NORMAL_RWX`,
// `BLOCK_DEVICE`, `GUEST_VMID`) outlived their last use, under a comment claiming they were gone.
// Nothing could catch that: `main.rs` carried a CRATE-WIDE `allow(dead_code)` for `real-linux`, the
// only configuration that compiles this file, so this was the one module no build ever linted for
// dead code (⑭). They are gone now, and the allow is per-item.
//
// The device window is `crate::stage2::windows().device_base`/`device_len`; the leaf attributes are
// `hv_s2`'s emit seams; `VTCR_EL2`/`HCR_EL2_VM` are `crate::stage2`'s.

/// `SPSR_EL2` to `eret` into the kernel: EL1h (`M[3:0]=0b0101`, uses `SP_EL1`), AArch64, `DAIF`
/// masked — the arm64 boot protocol enters with interrupts off; the kernel unmasks them itself.
const SPSR_EL2_LINUX: u64 = 0b0101 | (0b1111 << 6);

/// `SCTLR_EL1` enables the kernel must be entered with CLEAR (arm64 boot protocol: MMU off, D-cache
/// off): `M` (0), `A` (1), `C` (2), `SA` (3), `SA0` (4), `I` (12).
const SCTLR_EL1_ENABLES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);

// ─── Stage-2 tables ──────────────────────────────────────────────────────────────────────────────

// The Stage-2 tables live in `crate::stage2` now — the same storage the proven emitter uses for the
// synthetic guests. This file used to declare its own, alongside its own descriptor encodings and
// its own 40-line identity mapper; all three are gone (M5 Arc 6b). That duplication WAS the gap:
// the only real guest ran behind an emitter no proof touched.

/// Build this guest's model in `hv-core`, then emit its Stage-2 through the **proven emitter**.
///
/// **This is what M5 Arc 6b is for.** Until now the only real guest ran behind `build_stage2` — forty
/// lines of hand-rolled identity mapping in this file that no proof touched — while the emitter with
/// the ∀-N refinement theorem behind it could only address 2 MiB and so could not host a kernel. Arc
/// 6a gave that emitter superpages; this makes the kernel use it.
///
/// The model: one domain owning an `L2`-pinned page table, with one **leaf edge per 2 MiB of guest
/// RAM**. A leaf out of an `L2` table is a superpage (`hv_s2::Span::Super`), so the emitter writes
/// 2 MiB blocks — and because the super window's IPA and PA bases are both `LINUX_RAM_BASE`, the
/// mapping is identity, as the arm64 boot protocol and the DTB's `/memory` node require.
///
/// The device pass-through window is **infrastructure**, not model-driven — no `p2m` edge describes
/// MMIO — and the emitter maps it Device-nGnRnE + execute-never under its own checked invariant.
fn build_model_and_stage2(hv: &mut Hypervisor, uart: &mut Pl011) -> u64 {
    /// The domain the Linux guest runs as. `0` is the control domain.
    const GUEST: DomId = 1;
    /// The first model frame holding an `L2` page table — just above the super partition, in the
    /// base partition, and never mapped (a page table is model state, not a leaf).
    const FIRST_TABLE: Mfn = stage2::NUM_SUP_FRAMES as Mfn;

    let mut go = |caller: DomId, call: HvCall, what: &str| {
        if let Err(e) = crate::teardown::dispatch(hv, caller, call) {
            let _ = writeln!(
                uart,
                "baleen: linux model setup '{what}' failed: {e:?}; halting"
            );
            crate::park();
        }
    };

    go(
        DOM0,
        HvCall::DomainCreate {
            target: GUEST,
            may_create: false,
        },
        "create the linux domain",
    );

    // One super-span leaf per 2 MiB of guest RAM, spread across `NUM_LINUX_TABLES` `L2`-pinned
    // tables because `hv_core::TABLE_SLOTS` is 8 (see `crate::NUM_FRAMES`). Each table is allocated
    // and pinned before its leaves are linked.
    for t in 0..stage2::NUM_LINUX_TABLES {
        let table = FIRST_TABLE + t as Mfn;
        go(
            GUEST,
            HvCall::P2mAllocate { mfn: table },
            "allocate a table",
        );
        go(
            GUEST,
            HvCall::P2mPin {
                mfn: table,
                level: PtLevel::L2,
            },
            "pin a table at L2",
        );
        for slot in 0..hv_core::p2m::TABLE_SLOTS {
            let m = (t * hv_core::p2m::TABLE_SLOTS as u64 + slot as u64) as Mfn;
            if m >= stage2::NUM_SUP_FRAMES as Mfn {
                break;
            }
            go(
                GUEST,
                HvCall::P2mAllocate { mfn: m },
                "allocate a RAM frame",
            );
            go(
                GUEST,
                HvCall::P2mLink {
                    parent: table,
                    slot,
                    child: m,
                    writable: true,
                    leaf: true,
                    execute: false,
                },
                "link a RAM superpage",
            );
        }
    }

    let _ = writeln!(
        uart,
        "baleen: linux model built — {} super-span leaves ({} MiB of guest RAM) across {} L2-pinned tables",
        stage2::NUM_SUP_FRAMES,
        (LINUX_RAM_END - LINUX_RAM_BASE) / (1024 * 1024),
        stage2::NUM_LINUX_TABLES
    );

    stage2::build_stage2_from_p2m(hv, GUEST, 0)
}

/// Program + enable Stage-2: write `VTCR_EL2`/`VTTBR_EL2`, set `HCR_EL2.VM`, then TLB-invalidate for
/// the VMID and synchronize. Load-bearing on silicon, invisible under QEMU/TCG.
///
/// `IMO` is deliberately NOT set here — `gic::enable_el2` sets it at the very end of [`run`], after the
/// Linux vector table is installed, because it is the instruction that starts routing physical IRQs to
/// EL2 and they must have somewhere correct to land.
fn enable_stage2(vttbr: u64) {
    // SAFETY: all EL2-legal system registers; `HCR_EL2` read-modify-write adds `VM` while keeping the
    // Arc-3 `RW` bit and leaving `IMO`/`FMO` untouched (③-a2's `gic::enable_el2` adds `IMO` later, by
    // the same read-modify-write discipline). Stage-2 affects only EL1&0, never EL2's own
    // MMU-off/identity accesses.
    unsafe {
        asm!(
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "mrs {tmp}, hcr_el2",
            "orr {tmp}, {tmp}, {vm}",
            "msr hcr_el2, {tmp}",
            "dsb ish",
            "tlbi vmalls12e1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) VTCR_EL2,
            vttbr = in(reg) vttbr,
            vm = in(reg) HCR_EL2_VM,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Let the guest (EL1) use the GICv3 system-register CPU interface and the arch timer without
/// trapping to EL2: `ICC_SRE_EL2` = SRE + Enable (so `ICC_SRE_EL1` is accessible), and
/// `CNTHCTL_EL2` = EL1PCTEN|EL1PCEN (no physical counter/timer trap). The kernel drives the real GIC
/// and virtual timer directly; hv-metal does NOT pre-init the physical GIC (Linux does).
fn enable_guest_hw_access() {
    const ICC_SRE_EL2_SRE_EN: u64 = (1 << 0) | (1 << 3);
    const CNTHCTL_EL1_TIMER: u64 = (1 << 0) | (1 << 1);
    // SAFETY: `ICC_SRE_EL2` and `CNTHCTL_EL2` are EL2 control registers; we set only the documented
    // enable bits (read-modify-write for SRE to preserve IMPDEF bits), `isb` before the guest relies
    // on the interface. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "msr CNTHCTL_EL2, {cnt}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE_EN,
            cnt = in(reg) CNTHCTL_EL1_TIMER,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Clear the guest's `SCTLR_EL1` enables (MMU/caches off) so the kernel is entered Stage-1-off from a
/// known state, as the arm64 boot protocol requires. RES1 bits are preserved (read-modify-write).
fn init_guest_el1() {
    // SAFETY: `SCTLR_EL1` is writable from EL2; the read-modify-write clears exactly the enable bits
    // and preserves RES1. No memory effect.
    unsafe {
        asm!(
            "mrs {tmp}, sctlr_el1",
            "bic {tmp}, {tmp}, {en}",
            "msr sctlr_el1, {tmp}",
            en = in(reg) SCTLR_EL1_ENABLES,
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

// ─── the Linux-mode EL2 exception vectors ────────────────────────────────────────────────────────
// A dedicated vector table installed just before the `eret` into Linux — separate from the synthetic
// path's (`exceptions.rs`), so the synthetic code is untouched. Slot 8 (lower-EL sync) → the PSCI /
// abort handler below; every other slot → the diagnostic reporter (`handle_exception`, reused).
// With `IMO=0` the guest's device interrupts go straight to its EL1, so EL2 sees no guest IRQs.

global_asm!(
    r#"
    .section .text
    .balign 0x800
    .global __linux_vectors
__linux_vectors:
    .macro lventry index
    .balign 0x80
    mov     w0, #\index
    b       __linux_diag
    .endm

    lventry 0    // Current EL SP0 — Sync
    lventry 1
    lventry 2
    lventry 3
    lventry 4    // Current EL SPx — Sync (EL2's own faults land here)
    lventry 5
    lventry 6
    lventry 7
    // 0x400 Lower EL AArch64 — Sync: the guest's HVC (PSCI) and any Stage-2 abort. Straight to the
    // trampoline (must not clobber the guest's x0 = PSCI function id).
    .balign 0x80
    b       __linux_sync_entry
    // 0x480 Lower EL AArch64 — IRQ. ③-a2 made this live: `HCR_EL2.IMO` routes EVERY physical IRQ
    // the guest would have taken to EL2 instead, and this is where they arrive.
    .balign 0x80
    b       __linux_irq_entry
    lventry 10
    lventry 11
    lventry 12
    lventry 13
    lventry 14
    lventry 15

    .balign 0x80
__linux_diag:
    bl      handle_exception     // -> ! (reports EC/ELR/FAR/ESR and parks); w0 = slot index
0:  wfe
    b       0b
    "#
);

// The lower-EL sync trampoline: save x0..x30, call the Rust handler (which may set x0 = the PSCI
// return value), restore, and `eret` to resume the kernel past its `HVC`. Same save/restore
// discipline as `guest.rs`'s `__guest_sync_entry`.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __linux_sync_entry
__linux_sync_entry:
    sub     sp, sp, #(16 * 16)
    stp     x0, x1,   [sp, #(16 * 0)]
    stp     x2, x3,   [sp, #(16 * 1)]
    stp     x4, x5,   [sp, #(16 * 2)]
    stp     x6, x7,   [sp, #(16 * 3)]
    stp     x8, x9,   [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    str     x30,      [sp, #(16 * 15)]
    mov     x0, sp
    bl      handle_linux_sync
    ldp     x0, x1,   [sp, #(16 * 0)]
    ldp     x2, x3,   [sp, #(16 * 1)]
    ldp     x4, x5,   [sp, #(16 * 2)]
    ldp     x6, x7,   [sp, #(16 * 3)]
    ldp     x8, x9,   [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    ldr     x30,      [sp, #(16 * 15)]
    add     sp, sp, #(16 * 16)
    eret
    "#
);

// The lower-EL IRQ trampoline (③-a2). Same save/restore discipline as the sync one, and for the same
// reason — the Rust handler clobbers caller-saved registers the interrupted guest is still using. It
// differs from the sync path in one way that matters: an IRQ's preferred return address is the
// INTERRUPTED instruction, which `ELR_EL2` already holds, so there is no `advance_elr_past_fault`
// here. Advancing it would silently skip one guest instruction per timer tick.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __linux_irq_entry
__linux_irq_entry:
    sub     sp, sp, #(16 * 16)
    stp     x0, x1,   [sp, #(16 * 0)]
    stp     x2, x3,   [sp, #(16 * 1)]
    stp     x4, x5,   [sp, #(16 * 2)]
    stp     x6, x7,   [sp, #(16 * 3)]
    stp     x8, x9,   [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    str     x30,      [sp, #(16 * 15)]
    bl      handle_linux_irq
    ldp     x0, x1,   [sp, #(16 * 0)]
    ldp     x2, x3,   [sp, #(16 * 1)]
    ldp     x4, x5,   [sp, #(16 * 2)]
    ldp     x6, x7,   [sp, #(16 * 3)]
    ldp     x8, x9,   [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    ldr     x30,      [sp, #(16 * 15)]
    add     sp, sp, #(16 * 16)
    eret
    "#
);

extern "C" {
    fn __linux_sync_entry() -> !;
    fn __linux_irq_entry() -> !;
    static __linux_vectors: u8;
}
// `handle_exception` (the diagnostic reporter the vector stubs above `bl` into) is deliberately NOT
// declared here. It is `#[no_mangle]` in `exceptions.rs` and reached only from `global_asm!`, so the
// linker resolves it and a Rust `extern` declaration adds nothing — while being, to the compiler, an
// unused item. It was one of the things the crate-wide `allow(dead_code)` was hiding (⑭).

/// The saved GPR frame the sync trampoline hands the Rust handler: `x[i]` = `x<i>` for `i` in 0..=30.
#[repr(C)]
struct LinuxFrame {
    x: [u64; 31],
}

// PSCI function IDs (SMC Calling Convention) — the same set `guest.rs`'s Arc-5c handler services.
const PSCI_VERSION_FID: u64 = 0x8400_0000;
const PSCI_FEATURES_FID: u64 = 0x8400_000A;
const PSCI_SYSTEM_OFF_FID: u64 = 0x8400_0008;
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// The emulated PL011 the guest drives (③-a1). One instance: one guest. ③-b gives each guest its
/// own, which is the whole point of the device having become EL2 state instead of hardware.
static VPL011: BootCell<VirtPl011> = BootCell::new("VPL011", VirtPl011::new());

/// How many physical timer interrupts EL2 has forwarded to the guest as virtual ones (③-a2).
///
/// **This is the arc's ingress witness, and it exists because nothing else can see the change**
/// (design-lesson #99). A guest whose scheduler tick arrives by EL2 list-register injection prints
/// exactly what a guest taking the PPI directly prints — every kernel marker in the ⑬ gate is
/// satisfied identically either way, which is the same trap ③-a1 fell into and had to bring its own
/// witness for. Only EL2 can count what only EL2 now sees.
///
/// Plain atomic, not a [`BootCell`]: this is written from an asynchronous EL2 exception handler, which
/// is `crate::cell`'s class-3 hazard. An atomic has no borrow to overlap, so the hazard does not arise
/// — the same reasoning `guest.rs`'s `VCPU_PENDING` records.
static TIMER_FORWARDED: AtomicU64 = AtomicU64::new(0);

/// How many guest-generated SGIs EL2 has mediated and delivered (③-a2) — the second thing `IMO=1`
/// made EL2 responsible for. Same standing as [`TIMER_FORWARDED`]: written from a trap handler, so an
/// atomic rather than a [`BootCell`].
static SGIS_DELIVERED: AtomicU64 = AtomicU64::new(0);

/// The Linux-mode lower-EL **IRQ** handler (③-a2) — the guest's device interrupts, taken at EL2
/// because `HCR_EL2.IMO` routes them there, and handed on as *virtual* interrupts.
///
/// **The timer is the load-bearing case, and it is why this is not the synthetic path.**
/// `guest.rs`'s handler answers the arch-timer PPI with [`gic::disable_vtimer`] — a **one-shot**: it
/// clears `CNTV_CTL_EL0` so the level-triggered interrupt de-asserts and cannot immediately re-fire.
/// A synthetic guest wanting one tick is served by that; Linux, whose scheduler needs a *periodic*
/// tick it re-arms itself, is destroyed by it. So the level has to be dropped by the GUEST reprogramming
/// `CNTV_CVAL_EL0`, which means the physical interrupt must stay **Active** until it does — and EL2
/// gets no signal when that happens. [`gic::inject_hw`] is the answer: the guest's own EOI of the
/// virtual interrupt deactivates the physical one, with no EL2 involvement. See [`gic::LR_HW`].
///
/// Anything that is not the timer is a bring-up fault, reported with its INTID and parked, on the same
/// reasoning as [`handle_linux_data_abort`]: with `IMO=1` EVERY physical interrupt now arrives here, so
/// silently completing an unexpected one would hide exactly the routing bug this path can have.
///
/// # Safety
/// Called from the IRQ trampoline with the guest's registers saved; it takes no frame because it needs
/// no guest register (an interrupt, unlike a trapped instruction, carries no operands).
#[no_mangle]
extern "C" fn handle_linux_irq() {
    let intid = gic::ack_physical();

    if intid == gic::VTIMER_INTID {
        if !gic::inject_hw(gic::VTIMER_INTID, gic::VTIMER_INTID) {
            // Unreachable with one guest forwarding one interrupt into a bank of four — and reported
            // rather than dropped anyway, because a lost timer tick is a guest that stops scheduling,
            // which presents as a hang with no cause on the console.
            let mut uart = crate::uart();
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: the list-register bank is full — cannot forward the timer \
                 interrupt (INTID {intid}); halting"
            );
            crate::park();
        }
        TIMER_FORWARDED.fetch_add(1, Ordering::Relaxed);
        // Priority drop ONLY (`EOImode=1`): the interrupt stays Active, so its still-asserted level
        // cannot re-signal and storm EL2, while EL2's running priority returns to idle. The guest's
        // EOI of the virtual interrupt is what deactivates this one.
        gic::eoi_physical(intid);
        return;
    }

    // 1020..=1023 are the architectural special INTIDs; 1023 is "spurious" and must NOT be completed.
    if intid >= 1020 {
        return;
    }

    let mut uart = crate::uart();
    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: unexpected physical interrupt INTID {intid} routed to EL2 by \
         HCR_EL2.IMO — no forwarding rule; halting"
    );
    crate::park();
}

/// The Linux-mode lower-EL synchronous handler. `HVC` → service PSCI (Linux's `method = "hvc"`); an
/// `EC=0x24` **Stage-2 data abort** → the emulated PL011, if that is what the guest touched.
/// Anything else (an abort outside the emulated device, an unexpected trapped instruction) is a
/// bring-up bug: report it with full syndrome and park, so the fault is diagnosable rather than a
/// silent hang.
///
/// # Safety
/// `frame` is the valid `&mut LinuxFrame` the trampoline saved on the exception stack.
#[no_mangle]
extern "C" fn handle_linux_sync(frame: *mut LinuxFrame) {
    let (esr, elr, far) = read_syndrome();
    let ec = (esr >> 26) & 0x3f;
    let mut uart = crate::uart();

    // EC 0x24 = a Stage-2 data abort from EL1 — the trap-and-emulate transport. Before ③-a1 this
    // path did not exist at all and every non-`HVC` trap was fatal, which is why no mediated device
    // could work.
    if ec == EC_DATA_ABORT {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        handle_linux_data_abort(frame, esr, elr, far, &mut uart);
        return;
    }

    // EC 0x18 = a trapped MSR/MRS. Under `IMO=1` the guest's `ICC_SGI1R_EL1` writes land here (③-a2).
    if ec == EC_SYSREG {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        handle_linux_sysreg_trap(frame, esr, elr, far, &mut uart);
        return;
    }

    // EC 0x16 = HVC (AArch64).
    if ec == 0x16 {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        match frame.x[0] {
            PSCI_VERSION_FID => frame.x[0] = PSCI_VERSION_1_1,
            PSCI_FEATURES_FID => {
                frame.x[0] = if frame.x[1] == PSCI_SYSTEM_OFF_FID {
                    0
                } else {
                    PSCI_NOT_SUPPORTED
                };
            }
            PSCI_SYSTEM_OFF_FID => {
                report_vpl011(&mut uart);
                report_timer_forwarding(&mut uart);
                let _ = writeln!(
                    uart,
                    "baleen: linux guest issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut \
                     down on hv-metal's EL2 (M5 Arc 5e)"
                );
                semihosting_exit(); // clean QEMU exit (falls through to a fault→park if -semihosting off)
            }
            other => {
                frame.x[0] = PSCI_NOT_SUPPORTED;
                let _ = writeln!(
                    uart,
                    "baleen: linux PSCI FID 0x{other:08x} -> NOT_SUPPORTED"
                );
            }
        }
        return;
    }

    // Not an HVC: a genuine fault. Report and halt (the diagnostic that drives bring-up).
    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: EC=0x{ec:02x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting"
    );
    crate::park();
}

/// Route a guest **Stage-2 data abort** (`EC=0x24`). An access inside the emulated PL011's window is
/// trap-and-emulated; anything else is a real fault in a guest that is supposed to have everything
/// it touches either mapped or emulated, so it is reported with full syndrome and parked (the
/// `LINUX GUEST TRAP` string the gate forbids).
///
/// **The address arithmetic is not the synthetic path's.** `guest.rs` reads the whole faulting
/// address out of `FAR_EL2`, which is sound *there* because the synthetic guests run with stage-1
/// off, so VA == IPA. A real Linux kernel turns its MMU on within milliseconds of entry, and from
/// then on `FAR_EL2` holds a **guest virtual** address that has nothing to do with the device. The
/// IPA comes from `HPFAR_EL2`, which carries only `IPA[47:12]`; the in-page register offset comes
/// from `FAR_EL2[11:0]`, equal to the IPA's low bits because a 4 KiB granule does not translate
/// them ([`abort::full_ipa`]).
fn handle_linux_data_abort(frame: &mut LinuxFrame, esr: u64, elr: u64, far: u64, uart: &mut Pl011) {
    let a = DataAbort::decode(esr);
    let hpfar = read_hpfar();
    let ipa = abort::full_ipa(hpfar, far);

    if !vpl011::in_window(ipa) {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: EC=0x{ec:02x} data abort outside every emulated device — \
             IPA=0x{ipa:016x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting",
            ec = EC_DATA_ABORT
        );
        crate::park();
    }

    // Three ways an access can be undecodable. Each is fatal rather than guessed at: emulating the
    // wrong register, or writing a result into the wrong guest register, is far worse than halting
    // with the syndrome on the console. None of them is reachable from the PL011 accesses a Linux
    // driver actually makes (single-register `readw`/`writew`/`readl`/`writeb` at aligned offsets),
    // which is exactly why a silent fallback would be untested code on a live path.
    if !a.isv || a.fnv || a.s1ptw {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: undecodable PL011 access at IPA=0x{ipa:016x} \
             (ISV={} FnV={} S1PTW={}) ESR=0x{esr:08x} — halting",
            a.isv as u8, a.fnv as u8, a.s1ptw as u8
        );
        crate::park();
    }
    let offset = ipa - vpl011::VPL011_BASE;
    if !offset.is_multiple_of(a.access_bytes()) {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: misaligned PL011 access at IPA=0x{ipa:016x} \
             ({} bytes) — halting",
            a.access_bytes()
        );
        crate::park();
    }

    let mut dev = VPL011.borrow_mut();
    if a.wnr {
        // A store: the value is the guest's source register (`SRT` 31 is `XZR`, which reads zero).
        let value = if a.srt < 31 { frame.x[a.srt] } else { 0 } & a.value_mask();
        if let Some(byte) = dev.mmio_write(offset, value) {
            // The one place the emulated device meets the real one: the guest's transmitted byte
            // goes out of the machine's PL011 verbatim (no `\n` translation — the guest's own tty
            // layer already decided what bytes it wants on the wire).
            uart.put(byte);
        }
    } else {
        // A load: service the register and write the result into the guest's saved frame. `SF`
        // clear means the destination is a 32-bit view of the register, so the load zero-extends —
        // which is what storing the masked value into the 64-bit slot already does.
        let value = dev.mmio_read(offset, a.access_bytes());
        if a.srt < 31 {
            frame.x[a.srt] = if a.sf { value } else { value & 0xffff_ffff };
        }
    }
    drop(dev);

    // Unlike an `HVC`, a data abort's preferred return is the FAULTING instruction — resume past it
    // or the guest re-executes the access forever.
    crate::guest::advance_elr_past_fault();
}

/// `ESR_EL2.EC` for a **trapped MSR/MRS or System instruction** in AArch64 state.
const EC_SYSREG: u64 = 0x18;

/// The `ICC_SGI1R_EL1` system-register encoding as it appears in an `EC=0x18` ISS: `Op0=3, Op1=0,
/// CRn=12, CRm=11, Op2=5`, direction = write. Matched as one packed value rather than six field
/// comparisons, so a register this port has NOT thought about cannot fall through into the SGI path.
const ISS_SYSREG_FIELDS: u64 = 0x003f_ffff;
const ISS_ICC_SGI1R_EL1_WRITE: u64 = (3 << 20) | (5 << 17) | (12 << 10) | (11 << 1);

/// Route a guest **trapped system-register access** (`EC=0x18`) — a class of trap that did not exist
/// on this path before ③-a2, because `IMO=0` left the guest's GIC CPU interface untrapped.
///
/// The only member of the class this port has a rule for is a write to `ICC_SGI1R_EL1`: the guest
/// raising a software-generated interrupt. See [`gic::sgi1r_intid`] for why the architecture routes it
/// here and what the single-vCPU emulation is. Everything else is reported with the decoded register
/// encoding and parked — the same discipline as an abort outside every emulated device, and for the
/// same reason: a silently-ignored system-register write leaves the guest believing something took
/// effect that did not.
fn handle_linux_sysreg_trap(
    frame: &mut LinuxFrame,
    esr: u64,
    elr: u64,
    far: u64,
    uart: &mut Pl011,
) {
    let iss = esr & 0x01ff_ffff;

    if iss & ISS_SYSREG_FIELDS == ISS_ICC_SGI1R_EL1_WRITE && iss & 1 == 0 {
        // `Rt` is ISS[9:5]; 31 is `XZR`, which reads zero.
        let rt = ((iss >> 5) & 0x1f) as usize;
        let value = if rt < 31 { frame.x[rt] } else { 0 };
        let intid = gic::sgi1r_intid(value);
        if !gic::inject(intid) {
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: the list-register bank is full — cannot deliver the \
                 guest's SGI {intid}; halting"
            );
            crate::park();
        }
        SGIS_DELIVERED.fetch_add(1, Ordering::Relaxed);
        // A trapped instruction's preferred return is the instruction ITSELF; resume past it or the
        // guest re-executes the `msr` forever.
        crate::guest::advance_elr_past_fault();
        return;
    }

    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: unhandled system-register access (Op0={} Op1={} CRn={} CRm={} \
         Op2={} {}) ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting",
        (iss >> 20) & 0x3,
        (iss >> 14) & 0x7,
        (iss >> 10) & 0xf,
        (iss >> 1) & 0xf,
        (iss >> 17) & 0x7,
        if iss & 1 == 0 { "write" } else { "read" },
    );
    crate::park();
}

/// Read `HPFAR_EL2` — the architectural source of the faulting **IPA** for a Stage-2 abort.
fn read_hpfar() -> u64 {
    let hpfar: u64;
    // SAFETY: `HPFAR_EL2` is a read-only EL2 system register, readable at EL2; no memory effect.
    unsafe {
        asm!("mrs {0}, hpfar_el2", out(reg) hpfar, options(nomem, nostack, preserves_flags));
    }
    hpfar
}

/// Report what the emulated PL011 witnessed, at the guest's `SYSTEM_OFF` — the last moment EL2 gets
/// before the boot ends.
///
/// **Why this marker and not a simpler one.** Every other assertion in the real-Linux gate
/// (`Linux version`, `Machine model`, `Run /init`, `BALEEN-STEP0-OK`) is satisfied identically
/// whether the PL011 is emulated or passed through — they are statements about the kernel, and the
/// kernel neither knows nor cares which. So none of them could witness ③-a1. This one can: the
/// device counts the bytes it forwards and watches its own transmit stream for userspace's marker,
/// so the `OK` line is printed only by an emulator that actually carried the guest's console
/// (design-lesson #24f; #71 from the failure side — a check whose inputs cannot discriminate).
///
/// **It claims INGRESS, and says so.** A probe that deleted the `uart.put` — the emulator receiving
/// the guest's bytes and dropping them on the floor — left this line green while seven kernel
/// markers went red, because the needle is matched where the byte ARRIVES. That is the right split
/// (the seven markers are the egress half, and they are un-forgeable in their own way: the kernel
/// cannot print them without the emulator relaying them), but the wording had to stop implying it
/// covered both. A witness that overstates by one word is the same defect as one that cannot
/// discriminate, only harder to notice.
fn report_vpl011(uart: &mut Pl011) {
    let (ok, traps, dr_writes) = VPL011.borrow_mut().witness();
    if ok {
        let _ = writeln!(
            uart,
            "baleen: vpl011 OK: the guest's console is EMULATED — userspace's 'BALEEN-STEP0-OK' was \
             written to the emulated PL011's DR register in EL2 ({traps} register traps, \
             {dr_writes} bytes relayed to the real PL011)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vpl011 FAIL: the guest's console did not go through the emulator \
             ({traps} register traps, {dr_writes} bytes forwarded) — the PL011 is being passed \
             through, or the transmit path is broken"
        );
    }
}

/// Report ③-a2's forwarding witness at the guest's `SYSTEM_OFF`.
///
/// **The ingress half, and it is the only half EL2 can claim.** The count is incremented in
/// [`handle_linux_irq`], which runs *only* because `HCR_EL2.IMO` routed a physical interrupt to EL2 —
/// under `IMO=0` this function is unreachable and the count is zero. So a non-zero count cannot be
/// produced by a guest taking its timer directly, which is exactly what the twelve kernel markers
/// cannot distinguish (design-lesson #99).
///
/// **The EGRESS half is the kernel markers, and they are un-forgeable in their own way** — the same
/// split ③-a1 settled on, stated the same way. Forwarding an interrupt EL2 never delivers would leave
/// this line green and hang the boot: a Linux guest whose scheduler tick never arrives does not reach
/// `Run /init`, so `BALEEN-STEP0-OK` and every marker after it go red. Neither half claims the other's
/// ground.
fn report_timer_forwarding(uart: &mut Pl011) {
    let n = TIMER_FORWARDED.load(Ordering::Relaxed);
    if n > 0 {
        let _ = writeln!(
            uart,
            "baleen: vtimer OK: the guest's scheduler tick is FORWARDED — {n} physical timer \
             interrupts (INTID {}) taken at EL2 under HCR_EL2.IMO=1 and injected as hardware-mapped \
             virtual interrupts",
            gic::VTIMER_INTID
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vtimer FAIL: EL2 forwarded no timer interrupt — the guest is taking the PPI \
             directly (IMO=0), or the physical CPU interface never delivered one"
        );
    }

    // The SGI half is a SEPARATE mechanism reached by a separate trap (`EC=0x18`, not the IRQ
    // vector), so it gets its own line rather than being folded into the count above. A witness that
    // merged them could stay green with either path dead.
    let sgis = SGIS_DELIVERED.load(Ordering::Relaxed);
    if sgis > 0 {
        let _ = writeln!(
            uart,
            "baleen: vsgi OK: {sgis} guest SGIs MEDIATED at EL2 — ICC_SGI1R_EL1 writes trap under \
             HCR_EL2.IMO=1 and are delivered as virtual interrupts"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vsgi FAIL: EL2 mediated no SGI — the guest reached its own SGI generation \
             register, which HCR_EL2.IMO=1 is supposed to make impossible"
        );
    }
}

/// Cleanly exit QEMU via the ARM semihosting `SYS_EXIT` call (the `qemu-linux` target passes
/// `-semihosting`). Used on the guest's PSCI `SYSTEM_OFF` so the demo terminates instead of parking
/// until an external timeout. If `-semihosting` is not enabled, `hlt #0xf000` faults to EL2 and the
/// diagnostic vector parks — so this is safe either way.
fn semihosting_exit() -> ! {
    // AArch64 `SYS_EXIT` (op 0x18): `x1` -> `[reason, exit_code]`; `ADP_Stopped_ApplicationExit` =
    // 0x20026 → QEMU exits with the given code (0).
    static EXIT_BLOCK: [u64; 2] = [0x2_0026, 0];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; EL2 runs MMU-off/identity so
    // `&EXIT_BLOCK` is a physical address QEMU reads directly. Never returns (QEMU exits, or the
    // instruction faults to the EL2 vector, which parks).
    unsafe {
        asm!(
            "mov x0, #0x18",
            "mov x1, {b}",
            "hlt #0xf000",
            b = in(reg) core::ptr::addr_of!(EXIT_BLOCK),
            options(nostack, noreturn),
        );
    }
}

/// Read `(ESR_EL2, ELR_EL2, FAR_EL2)`.
fn read_syndrome() -> (u64, u64, u64) {
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: EL2 syndrome registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, elr_el2",
            "mrs {2}, far_el2",
            out(reg) esr, out(reg) elr, out(reg) far,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, elr, far)
}

// Install the Linux vector table and `eret` into the kernel. `x0` = DTB PA (arm64 boot protocol),
// `x1` = EL2 exception-stack top (becomes `SP_EL2` for later HVC/abort traps). `ELR_EL2`/`SPSR_EL2`
// are set by the caller before the `bl` here.
global_asm!(
    r#"
    .section .text
    .global __enter_linux
__enter_linux:
    // x0 = dtb_pa, x1 = exc_stack_top
    mov     sp, x1              // SP_EL2 for future traps
    mov     x1, xzr             // arm64 boot protocol: x1..x3 = 0
    mov     x2, xzr
    mov     x3, xzr
    dsb     sy
    isb
    eret                        // -> EL1 kernel entry (ELR_EL2), with x0 = DTB
    "#
);

extern "C" {
    fn __enter_linux(dtb_pa: u64, exc_stack_top: u64) -> !;
}

extern "C" {
    static __exc_stack_top: u8;
}

/// The Arc-5e entry: build the pass-through Stage-2, enable it (`IMO=0`), let the guest reach the
/// GIC/timer, point `ELR_EL2` at the loaded kernel `Image`, install the Linux vectors, and `eret`
/// into a real Linux kernel with `x0` = the DTB. Never returns (transfers to EL1).
pub(crate) fn run(uart: &mut Pl011) -> ! {
    let _ = writeln!(
        uart,
        "baleen: M5 Arc 5e — booting a REAL aarch64 Linux kernel as a single EL1 guest \
         (Image@0x{KERNEL_ENTRY:08x}, DTB@0x{DTB_ADDR:08x}, RAM 0x{GUEST_RAM_BASE:08x}..0x{GUEST_RAM_END:08x})"
    );

    // Build the guest's model and emit its Stage-2 through the PROVEN emitter (M5 Arc 6b).
    *crate::guest::GUEST_HV.borrow_mut() = Some(crate::build_hypervisor());
    let mut cell = crate::guest::GUEST_HV.borrow_mut();
    let hv = match cell.as_mut() {
        Some(hv) => hv,
        None => crate::park(),
    };
    let vttbr = build_model_and_stage2(hv, uart);
    drop(cell);
    enable_stage2(vttbr);
    enable_guest_hw_access();
    init_guest_el1();

    // Boot registers: SPSR = EL1h/DAIF-masked, ELR = kernel entry.
    // SAFETY: `SPSR_EL2`/`ELR_EL2` are RW at EL2; they seed the state `eret` restores.
    unsafe {
        asm!(
            "msr spsr_el2, {spsr}",
            "msr elr_el2, {elr}",
            spsr = in(reg) SPSR_EL2_LINUX,
            elr = in(reg) KERNEL_ENTRY,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Install the Linux vector table (VBAR_EL2), replacing the synthetic-path table for this boot.
    // SAFETY: `VBAR_EL2` is RW at EL2; `__linux_vectors` is the 2 KiB-aligned in-image table.
    unsafe {
        let vec = core::ptr::addr_of!(__linux_vectors) as u64;
        asm!("msr vbar_el2, {v}", "isb", v = in(reg) vec, options(nomem, nostack));
    }

    // ③-a2: take the guest's interrupts at EL2 and forward them. **Strictly after the vector install
    // above** — `enable_el2` sets `HCR_EL2.IMO`, and from that instruction on a physical IRQ lands on
    // whatever `VBAR_EL2` currently points at. Enabling first would put a window, however short,
    // where a timer PPI would be dispatched through the synthetic path's table.
    //
    // Note what is NOT called: `gic::init_physical_vtimer()`. The GICD/GICR are pass-through mapped,
    // so it is the KERNEL that enables PPI 27 at the redistributor — and with `IMO=1` that same
    // enable is what makes the interrupt reach EL2. Re-initializing the distributor here would fight
    // the guest for a device the guest owns. Only EL2's own CPU interface needs setting up.
    gic::enable_physical_cpu_interface_el2();
    gic::set_eoi_mode_split();
    gic::enable_el2();

    let _ = writeln!(
        uart,
        "baleen: EL2 takes the guest's interrupts — HCR_EL2.IMO=1, timer PPI {} forwarded by \
         hardware-mapped list-register injection",
        gic::VTIMER_INTID
    );

    let _ = writeln!(uart, "baleen: entering EL1 — the kernel takes the machine");

    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: transfers to EL1 via `eret`; `DTB_ADDR` is the loaded DTB, `exc_stack_top` the EL2
    // trap stack. Never returns.
    unsafe { __enter_linux(DTB_ADDR, exc_stack_top) }
}
