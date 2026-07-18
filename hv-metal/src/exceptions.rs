// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # EL2 exception vectors — making a fault diagnosable (Arc 2)
//!
//! Arc 2 of M3 (see `docs/ROADMAP.md`): confirm we are at EL2, install `VBAR_EL2`, and stand up
//! a default exception handler that **decodes and reports** a fault through the Arc-1 [`crate::pl011`]
//! console instead of letting the CPU triple-fault into a silent reset loop (which is exactly what
//! happens today, with `VBAR_EL2` unset).
//!
//! ## Contract
//!
//! - **Property:** after [`install_vectors`], every synchronous exception taken at EL2 is caught by
//!   an installed vector, decoded (`EC`/`ELR`/`FAR`/`ESR`), reported through the console, and the
//!   core halts cleanly — a fault is **never** silently lost.
//! - **Check:** the CI boot-test (`hv-metal/boot-test.sh`), when built `--features selftest`,
//!   deliberately executes `BRK #0` and asserts the handler prints the correct exception class
//!   (`EC=0x3c`) — end-to-end evidence the vectors + decode path fire (design-lesson #23: don't
//!   just install the mechanism, watch it catch a fault).
//! - **Scope:** *plumbing / refines* — EL2 configuration + diagnostics, **no isolation content**.
//!   Isolation starts at M4 (the first guest + the negative-isolation test). A green boot attests
//!   the vectors and `ESR` decode work; it says nothing about timing/DMA/isolation
//!   (`docs/QEMU-AND-METAL.md` — the exception model is one thing QEMU *is* architecturally faithful
//!   about, so this attestation is sound as far as it goes).
//!
//! ## Provenance
//!
//! The vector-table layout (16 entries × `0x80`, 2 KiB-aligned base), the `CurrentEL` / `ESR_EL2`
//! field encodings, and the `EC` (exception-class) values are taken from the **Arm Architecture
//! Reference Manual (Arm ARM), section D1 "The AArch64 System Level Programmers' Model"** — a
//! published architecture spec. This is the spec-not-implementation hygiene `CLEANROOM.md` requires,
//! applied to the architecture spec.
//!
//! ## Unsafe
//!
//! The `unsafe` here is system-register access (`mrs`/`msr` of `CurrentEL`, `VBAR_EL2`, `ESR_EL2`,
//! `ELR_EL2`, `FAR_EL2`) and the vector-table `global_asm!`. All are EL2-legal on the `virt`
//! machine and carry no memory effect beyond the named register; see each block.

use core::arch::{asm, global_asm};
use core::fmt::Write;

// AArch64 EL2 exception vector table. 16 entries, each 0x80 bytes; the table base is 2 KiB-aligned
// because VBAR_EL2[10:0] are RES0. Each entry loads its slot index into w0 and branches to the
// common trampoline, which calls the Rust decoder. The 16 slots are 4 exception types
// {Synchronous, IRQ, FIQ, SError} within each of 4 source groups {Current EL w/ SP0, Current EL w/
// SPx, Lower EL AArch64, Lower EL AArch32}. Offsets + meaning per the Arm ARM (D1, "AArch64
// exception vector table") — re-derive against the spec; a wrong offset compiles and may still boot.
global_asm!(
    r#"
    .section .vectors, "ax"
    .balign 0x800
    .global __exception_vectors
__exception_vectors:

    .macro ventry index
    .balign 0x80
    mov     w0, #\index
    b       __exception_common
    .endm

    ventry 0    // 0x000  Current EL with SP0 — Synchronous
    ventry 1    // 0x080  Current EL with SP0 — IRQ/vIRQ
    ventry 2    // 0x100  Current EL with SP0 — FIQ/vFIQ
    ventry 3    // 0x180  Current EL with SP0 — SError/vSError
    ventry 4    // 0x200  Current EL with SPx — Synchronous  <- EL2 faults land here (SPSel=1 at reset)
    ventry 5    // 0x280  Current EL with SPx — IRQ/vIRQ
    ventry 6    // 0x300  Current EL with SPx — FIQ/vFIQ
    ventry 7    // 0x380  Current EL with SPx — SError/vSError
    ventry 8    // 0x400  Lower EL, AArch64   — Synchronous
    ventry 9    // 0x480  Lower EL, AArch64   — IRQ/vIRQ
    ventry 10   // 0x500  Lower EL, AArch64   — FIQ/vFIQ
    ventry 11   // 0x580  Lower EL, AArch64   — SError/vSError
    ventry 12   // 0x600  Lower EL, AArch32   — Synchronous
    ventry 13   // 0x680  Lower EL, AArch32   — IRQ/vIRQ
    ventry 14   // 0x700  Lower EL, AArch32   — FIQ/vFIQ
    ventry 15   // 0x780  Lower EL, AArch32   — SError/vSError

    .balign 0x80
__exception_common:
    // Diagnostic-only handler: NO general-purpose-register save-frame, because we report the fault
    // and halt — we never `eret` back to the faulting context, so there is nothing to preserve.
    // (M4 Arc 4's trap-and-service will add a full save/restore frame when it must resume a guest.)
    // w0 already holds the vector slot index — the first C argument to `handle_exception`.
    bl      handle_exception
    // `handle_exception` is `-> !` and never returns; this is belt-and-suspenders if it ever does.
0:  wfe
    b       0b
    "#
);

/// The current Exception level (0–3), decoded from `CurrentEL[3:2]`.
///
/// Under QEMU `virt` with `virtualization=on` we boot at EL2, so this returns `2`. Reading it (and
/// checking it) before touching any EL2-only system register is a real "we are where we think we
/// are" check, not an assumption.
pub(crate) fn current_el() -> u64 {
    let raw: u64;
    // SAFETY: `CurrentEL` is readable at every EL; no memory effect.
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) raw, options(nomem, nostack, preserves_flags));
    }
    (raw >> 2) & 0b11
}

/// Point `VBAR_EL2` at the vector table and synchronize, so any subsequent exception is caught.
///
/// `VBAR_EL2` is UNKNOWN out of reset; until this runs, a fault at EL2 vectors to garbage and the
/// CPU triple-faults into a reset loop. The `isb` ensures the new `VBAR_EL2` is in effect before
/// control returns (and thus before any exception can be taken against the old value).
pub(crate) fn install_vectors() {
    // SAFETY: writing VBAR_EL2 is EL2-legal; `adrp`+`:lo12:` forms the PC-relative address of the
    // in-image (2 KiB-aligned) vector table. No memory is accessed; only the system register moves.
    unsafe {
        asm!(
            "adrp {t}, __exception_vectors",
            "add  {t}, {t}, :lo12:__exception_vectors",
            "msr  vbar_el2, {t}",
            "isb",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// The default exception handler, called from every vector slot with `vector` = the slot index.
///
/// Reads the syndrome/context registers, prints a decoded one-line report through a fresh console
/// handle, and halts. It never returns (`-> !`) — Arc 2 does not resume faults.
///
/// A fresh [`crate::uart`] handle (not re-`init`ed) mirrors the panic handler: on `virt` the PL011
/// transmits from reset, so a report survives even a fault taken before `rust_main`'s `init`.
#[no_mangle]
extern "C" fn handle_exception(vector: u64) -> ! {
    let (esr, elr, far) = read_syndrome();
    let ec = (esr >> 26) & 0x3f; // ESR_EL2[31:26] — exception class.

    let mut uart = crate::uart();
    let _ = writeln!(
        uart,
        "baleen: EXCEPTION caught: vector={vector} ({}) EC=0x{ec:02x} ({}) \
         ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x}",
        vector_name(vector),
        ec_name(ec),
    );
    crate::park()
}

/// Read the EL2 exception syndrome registers: `(ESR_EL2, ELR_EL2, FAR_EL2)`.
///
/// `ESR_EL2` = syndrome (class + ISS), `ELR_EL2` = the preferred return / faulting PC, `FAR_EL2` =
/// the faulting virtual address (meaningful only for aborts/alignment faults; UNKNOWN otherwise).
fn read_syndrome() -> (u64, u64, u64) {
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: these are RO/RW EL2 system registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, elr_el2",
            "mrs {2}, far_el2",
            out(reg) esr,
            out(reg) elr,
            out(reg) far,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, elr, far)
}

/// Human-readable name of a vector slot (which of the 16 table entries fired).
fn vector_name(vector: u64) -> &'static str {
    match vector {
        0 => "cur_el_sp0_sync",
        1 => "cur_el_sp0_irq",
        2 => "cur_el_sp0_fiq",
        3 => "cur_el_sp0_serror",
        4 => "cur_el_spx_sync",
        5 => "cur_el_spx_irq",
        6 => "cur_el_spx_fiq",
        7 => "cur_el_spx_serror",
        8 => "lower_el_a64_sync",
        9 => "lower_el_a64_irq",
        10 => "lower_el_a64_fiq",
        11 => "lower_el_a64_serror",
        12 => "lower_el_a32_sync",
        13 => "lower_el_a32_irq",
        14 => "lower_el_a32_fiq",
        15 => "lower_el_a32_serror",
        _ => "?",
    }
}

/// Human-readable name of an `ESR_ELx.EC` exception-class value (Arm ARM, ESR_ELx encoding). Covers
/// the classes we can plausibly hit at EL2 during bring-up; anything else prints as `other`.
fn ec_name(ec: u64) -> &'static str {
    match ec {
        0x00 => "unknown",
        0x01 => "trapped WFI/WFE",
        0x07 => "trapped SIMD/FP access",
        0x0e => "illegal execution state",
        0x15 => "SVC (AArch64)",
        0x16 => "HVC (AArch64)",
        0x17 => "SMC (AArch64)",
        0x18 => "trapped MSR/MRS/system insn",
        0x20 => "instruction abort (lower EL)",
        0x21 => "instruction abort (same EL)",
        0x22 => "PC alignment fault",
        0x24 => "data abort (lower EL)",
        0x25 => "data abort (same EL)",
        0x26 => "SP alignment fault",
        0x2c => "trapped FP exception (AArch64)",
        0x2f => "SError",
        0x30 => "breakpoint (lower EL)",
        0x31 => "breakpoint (same EL)",
        0x3c => "BRK (AArch64)",
        _ => "other",
    }
}
