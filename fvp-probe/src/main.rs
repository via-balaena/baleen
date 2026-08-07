// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

#![no_std]
#![no_main]

//! # `fvp-probe` — does the SMMU cache translations, and does invalidation matter?
//!
//! A standalone bare-metal instrument for Arm's **Base RevC AEM FVP**. It is **not** part of the
//! hypervisor, is **not** gated by CI, and deliberately shares no code with it — see `README.md`
//! for why that isolation is the point.
//!
//! ## The question it exists to answer
//!
//! Honest-ledger item 2(d): *the STE's VMID field and the stage-2 TLBI are not boot-witnessed*.
//! They cannot be witnessed on QEMU, and the reason is structural rather than a missing feature —
//! **QEMU's SMMU models no translation caching at all**, so there is nothing for an invalidation to
//! invalidate and nothing a VMID could tag. An observation that "the TLBI made no difference" would
//! be indistinguishable from "the TLBI is unimplemented".
//!
//! The AEM does model it, and — measured from `--list-params` — makes it a *knob*:
//!
//! ```text
//! pci.pci_smmuv3.mmu.size_of_tlb        = 0   "The number of entries in the TLB."
//! pci.pci_smmuv3.mmu.size_of_ste_cache  = 0   "...cache holding STE structures."
//! ```
//!
//! ★ **That default of zero is the gift, because it is a BUILT-IN CONTROL.** The same binary, run
//! twice, must give opposite answers: with caching off a stale mapping is impossible, with it on a
//! stale mapping is expected. A test that can only be run in the configuration where it passes is
//! the failure mode this project keeps finding (design-lesson #198); here the negative arm costs one
//! command-line flag.
//!
//! ## Status
//!
//! **Milestone 1 only: boot, identify the exception level, print over PL011, exit.** Nothing here
//! touches the SMMU yet. That is deliberate — this is the first code ever executed on this platform
//! from this project, so the toolchain (linker script, entry, load address, UART) is proven before
//! anything harder is written on top of it.

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

/// PL011 UART0 on the Base RevC.
///
/// `0x1c09_0000`, corroborated twice: TF-A's `V2M_IOFPGA_UART0_BASE`, and the running model's own
/// `bp.uart_base=470351872`. Two sources on purpose — a single one cannot distinguish an
/// architectural address from an integrator's choice, which is the whole reason the platform-fact
/// diff was done before this was written.
const UART0_BASE: usize = 0x1c09_0000;
/// PL011 register offsets.
const UART_DR: usize = 0x000;
/// Flag register; bit 5 is `TXFF` (transmit FIFO full).
const UART_FR: usize = 0x018;
/// Line control; `WLEN=8` is bits 6:5, `FEN` is bit 4.
const UART_LCR_H: usize = 0x02c;
/// Control register; `UARTEN` is bit 0, `TXE` is bit 8.
const UART_CR: usize = 0x030;

// The reset entry. The FVP is given this image with `-a` (an ELF), so it takes the entry point from
// the header rather than needing `--start`. Every core starts here; all but cpu0 are parked, because
// this instrument is single-threaded by design and a stray secondary would interleave its UART
// output with cpu0's and make the transcript unreadable.
global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    // Park every core but cluster0.cpu0: MPIDR_EL1[23:0] == 0.
    "   mrs   x0, mpidr_el1",
    "   and   x0, x0, #0xffffff",
    "   cbz   x0, 2f",
    "1: wfe",
    "   b     1b",
    "2:",
    // One stack, at the top of the image (see link.ld).
    "   adrp  x0, __stack_top",
    "   add   x0, x0, :lo12:__stack_top",
    "   mov   sp, x0",
    // Zero .bss before any Rust runs.
    "   adrp  x0, __bss_start",
    "   add   x0, x0, :lo12:__bss_start",
    "   adrp  x1, __bss_end",
    "   add   x1, x1, :lo12:__bss_end",
    "3: cmp   x0, x1",
    "   b.hs  4f",
    "   str   xzr, [x0], #8",
    "   b     3b",
    "4: bl    {main}",
    "5: wfe",
    "   b     5b",
    main = sym probe_main,
);

/// Bring the PL011 up for transmit.
///
/// ⚠ **MEASURED, and it is exactly the class of difference this instrument exists to expose.** The
/// first version of this file skipped initialisation entirely, reasoning that "the model's UART
/// accepts `DR` writes from reset". **That is true of QEMU `virt` and FALSE here** — the Base RevC
/// reports `bp.pl011_uart0.uart_enable=0`, and the run produced not one byte. An assumption carried
/// from one platform, silently wrong on another, with no symptom except silence: the precise failure
/// the platform-fact diff was done to prevent, arriving in the first forty lines of code written
/// after it.
///
/// No baud programming: `IBRD`/`FBRD` only matter to a real transceiver, and the model does not care.
fn uart_init() {
    // SAFETY: PL011 registers on this platform, MMU off, aliasing no Rust object.
    unsafe {
        // Quiesce, then 8n1 with FIFOs, then enable with transmit on. In that order because
        // `LCR_H` must not be written while the UART is enabled.
        write_volatile((UART0_BASE + UART_CR) as *mut u32, 0);
        write_volatile((UART0_BASE + UART_LCR_H) as *mut u32, (0b11 << 5) | (1 << 4));
        write_volatile((UART0_BASE + UART_CR) as *mut u32, (1 << 8) | (1 << 0));
    }
}

/// Write one byte, waiting for room in the transmit FIFO first so nothing is dropped.
fn putb(b: u8) {
    // SAFETY: as `uart_init`. `FR` is read-only; the `DR` write is the documented transmit path.
    unsafe {
        while read_volatile((UART0_BASE + UART_FR) as *const u32) & (1 << 5) != 0 {
            core::hint::spin_loop();
        }
        write_volatile((UART0_BASE + UART_DR) as *mut u32, u32::from(b));
    }
}

fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putb(b'\r');
        }
        putb(b);
    }
}

/// Print `v` as `0x`-prefixed, zero-padded hex — enough of a formatter to report a register.
fn puthex(v: u64) {
    puts("0x");
    for shift in (0..16).rev() {
        let nyb = ((v >> (shift * 4)) & 0xf) as u8;
        putb(if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 });
    }
}

/// Exit the simulation through semihosting, so a run ends with a status rather than spinning until
/// `--cyclelimit`. Confirmed supported on this platform: the FVP intercepts `HLT #0xF000`.
fn semihosting_exit() -> ! {
    // ADP_Stopped_ApplicationExit, the AArch64 SYS_EXIT convention: x0 = 0x18, x1 = a block of
    // { reason, subcode }.
    let block: [u64; 2] = [0x2_0026, 0];
    // SAFETY: the documented semihosting call. If semihosting were disabled the FVP would take an
    // exception instead, which the parked loop below turns into a harmless hang rather than UB.
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") 0x18_u64,
            in("x1") block.as_ptr(),
            options(nostack),
        );
    }
    loop {
        // SAFETY: architectural hint, no memory effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) }
    }
}

extern "C" fn probe_main() -> ! {
    uart_init();
    puts("\n@@ FVPPROBE-BEGIN\n");

    // Which exception level did the FVP drop us at? The Base RevC starts at EL3 by default, and
    // knowing it FIRST matters: the SMMU work later needs to know whether it can reach the secure
    // register bank, and guessing would be exactly the kind of unmeasured assumption this project
    // keeps being bitten by.
    let el: u64;
    // SAFETY: `CurrentEL` is readable at every exception level.
    unsafe { core::arch::asm!("mrs {0}, CurrentEL", out(reg) el, options(nomem, nostack)) };
    puts("@@ CurrentEL   = ");
    puthex(el >> 2);
    puts("\n");

    let mpidr: u64;
    // SAFETY: `MPIDR_EL1` is readable at EL1 and above.
    unsafe { core::arch::asm!("mrs {0}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
    puts("@@ MPIDR_EL1   = ");
    puthex(mpidr);
    puts("\n");

    // Prove we can read the SMMU's ID space before trying to drive it. `SMMU_IDR0` at
    // `0x2b40_0000` — TF-A's `PLAT_FVP_SMMUV3_BASE`, corroborated by the FVP guide's own table.
    // A wrong base reads as zeroes or faults, and either is worth knowing now rather than in the
    // middle of stream-table bring-up.
    const SMMU_BASE: usize = 0x2b40_0000;
    // SAFETY: SMMUv3 register space on this platform; MMU off, so a direct physical read. `IDR0`
    // is read-only and has no side effects.
    let idr0 = unsafe { core::ptr::read_volatile(SMMU_BASE as *const u32) };
    puts("@@ SMMU_IDR0   = ");
    puthex(u64::from(idr0));
    puts("\n");
    // `S2P` is IDR0 **bit 0** — "stage-2 translation supported". The whole instrument depends on it.
    //
    // ⚠ **THIS WAS WRONG AT MILESTONE 1 AND THE MEASUREMENT STILL LOOKED RIGHT.** The first version
    // read `(idr0 >> 1) & 1`, which is `S1P` (stage *one*), and reported it as `S2P`. It printed
    // `0x1` and was recorded as "stage-2 supported" — true, but not because this line established
    // it: `IDR0 = 0x080fe6bf` has bit 0 AND bit 1 set, so the two candidate readings are
    // indistinguishable on this machine.
    //
    // ★ **The same defect, with the same cause, was already found and fixed once** — SMMU rung 1
    // had `IDR0_S1P`/`IDR0_S2P` swapped, it changed no result because QEMU also sets both, and
    // `hv-metal/src/smmu.rs` carries the correction plus a note. It recurred here because this crate
    // deliberately shares no code with `hv-metal`, so the fix could not travel: **isolation from the
    // hypervisor's code is also isolation from its corrections.** That is a real cost of this
    // crate's design, and it is the right trade, but it has to be paid with attention rather than
    // assumed away. Design-lesson #71's shape: a check whose two inputs are both set cannot
    // discriminate between them.
    puts("@@ SMMU_S2P    = ");
    puthex(u64::from(idr0 & 1));
    puts("\n");
    // Reported alongside it, so the transcript records which bit is which rather than leaving a
    // reader to trust the label. On this platform both are set; on one where they differ, the pair
    // is what makes the reading falsifiable.
    puts("@@ SMMU_S1P    = ");
    puthex(u64::from((idr0 >> 1) & 1));
    puts("\n");

    puts("@@ FVPPROBE-END\n");
    semihosting_exit()
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    puts("\n@@ FVPPROBE-PANIC\n");
    semihosting_exit()
}
