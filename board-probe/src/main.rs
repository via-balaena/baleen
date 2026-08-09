// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

#![no_std]
#![no_main]

//! # `board-probe` — measure the platform facts `hv-metal` currently assumes
//!
//! A standalone bare-metal instrument. **Not** part of the hypervisor, **not** gated by CI, and it
//! deliberately shares no source with `hv-metal` — the same fence `fvp-probe` keeps, and for the
//! same reason: an instrument that imports the declarations of the thing it measures is a tautology.
//!
//! ## Why this exists BEFORE any port
//!
//! `hv-metal` has never run outside QEMU `virt`, and it holds **every platform fact as a `const`** —
//! it parses no device tree for itself. Porting it means replacing those constants, and each one is
//! a decision that depends on a number nobody has measured on the target. Design-lesson **#248**:
//! build the instrument before the code when nothing you run can grade the code. `fvp-probe` did
//! that for A2 and found a requirement the spec did not have.
//!
//! ★ **So this probe answers questions, it does not port anything.** Its output is a list of facts
//! and, for each, whether it MATCHES what `hv-metal` assumes today. A mismatch is not a failure —
//! it is the finding, and it is what the port's scope should be built from.
//!
//! ## ⚠ The two facts you must supply first, and why they cannot be measured
//!
//! * **The load address** — `link.ld`. Nothing can run before the image is where the boot chain
//!   jumps to.
//! * **[`UART0_BASE`]** — below. Nothing can be *reported* before there is somewhere to report to.
//!
//! Everything else here is read from the hardware. These two are chicken-and-egg and must come from
//! the board's own documentation. ⚠ **Both default to QEMU `virt`, so the probe self-tests on a
//! platform whose answers are already known.** An instrument that has never been run where you can
//! check it is not an instrument — run `qemu-probe.sh` first, every time.
//!
//! ## What it must survive
//!
//! ⚠⚠ **It must not fault on a board that hands off at EL1.** Reading `SCTLR_EL2` or `ICH_VTR_EL2`
//! from EL1 traps, and a probe that dies before printing is worse than no probe: you learn nothing
//! and cannot tell "the board is EL1-only" from "the image never ran". So `CurrentEL` is read
//! FIRST, on the only path that needs no privilege, and every EL2 register is gated behind it.
//!
//! ## Reading the output
//!
//! Lines are `@@ <key> = <value>` for raw facts and `@@ VERDICT <name>: <MATCH|DIFFERS|ABSENT> …`
//! for the comparisons against `hv-metal`'s assumptions. `@@ ` prefixes exist so a transcript can be
//! grepped out of a noisy boot log — `fvp-probe`'s convention.

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

// ─── The two supplied facts ─────────────────────────────────────────────────────────────────────

/// **PL011 UART base. ⚠ SUPPLY THIS FROM THE BOARD'S DOCUMENTATION.**
///
/// Default is QEMU `virt`'s, which is also what `hv-metal/src/pl011.rs` assumes. Two things can be
/// wrong on a real board and they fail differently:
///
/// * **Wrong address** — silent hang, because there is no UART to report the problem on. This is
///   why it is the first thing to check when nothing appears.
/// * **Not a PL011 at all** — many SoCs use 8250/16550-style or vendor UARTs with different
///   register offsets. [`uart_init`] and [`putc`] below are PL011-specific; a different controller
///   needs its own two functions, not a different base.
const UART0_BASE: usize = 0x0900_0000;

/// PL011 register offsets — architectural for the controller, not the board.
const UART_DR: usize = 0x000;
/// Flag register; `TXFF` (transmit FIFO full) is bit 5.
const UART_FR: usize = 0x018;
/// Line control; must not be written while the UART is enabled.
const UART_LCR_H: usize = 0x02c;
/// Control register; `UARTEN` is bit 0, `TXE` is bit 8.
const UART_CR: usize = 0x030;

// ─── What `hv-metal` assumes today, so each measurement has something to be compared against ────
//
// ⚠ These are the ASSUMPTIONS, restated here on purpose rather than imported. The probe shares no
// source with `hv-metal` (see the module doc), so this list is a deliberate second copy — and if it
// drifts from the real one, the verdicts below are about a hypervisor that no longer exists. That
// is the cost of the independence, and it is the right trade only because the list is short and
// each entry cites where it came from.

/// `hv-metal/src/cache.rs` measures `CTR_EL0.DminLine` and caps it at 64. Measured 64 on QEMU
/// `virt` AND on Arm's AEM, so a third value has never been seen by this project.
const ASSUMED_DMIN_LINE: u64 = 64;
/// `hv-metal/src/gic.rs` reads `ICH_VTR_EL2.ListRegs`; QEMU `virt` reports **4** list registers.
const ASSUMED_LIST_REGS: u64 = 4;
/// `ICH_VTR_EL2.PRIbits + 1` — QEMU `virt` reports **5**, i.e. only `ICH_AP0R0_EL2`/`AP1R0_EL2`.
const ASSUMED_PRI_BITS: u64 = 5;
/// `hv-metal/src/mmu.rs` pins `TCR_EL2.PS = 0b010` — 40-bit physical addresses.
const ASSUMED_PA_BITS: u64 = 40;
/// `hv-metal/src/stage2.rs` uses 8-bit VMIDs (`VTCR_EL2.VS = 0`).
const ASSUMED_VMID_BITS: u64 = 8;

// ─── Boot ───────────────────────────────────────────────────────────────────────────────────────
//
// Park every secondary, set a stack, zero `.bss`, and hand `x0` (whatever the boot chain passed —
// conventionally a DTB pointer) to Rust. Deliberately the smallest possible startup: this file's
// job is to survive long enough to print, on a platform where nothing is known.

global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    // Preserve the boot chain's x0 — it is data, and on most AArch64 boot protocols it is the DTB.
    "   mov   x19, x0",
    // Park secondaries: only the CPU whose MPIDR affinity bits are zero continues.
    "   mrs   x1, mpidr_el1",
    "   and   x1, x1, #0xff",
    "   cbz   x1, 2f",
    "1: wfe",
    "   b     1b",
    "2: ldr   x0, =__stack_top",
    "   mov   sp, x0",
    // Zero .bss. The linker aligns both ends to 16, so an 8-byte stride cannot overrun.
    "   ldr   x0, =__bss_start",
    "   ldr   x1, =__bss_end",
    "3: cmp   x0, x1",
    "   b.hs  4f",
    "   str   xzr, [x0], #8",
    "   b     3b",
    "4: mov   x0, x19",
    "   bl    probe_main",
    "5: wfe",
    "   b     5b",
);

// ─── UART ───────────────────────────────────────────────────────────────────────────────────────

/// Bring the PL011 up rather than assuming a boot chain left it usable.
///
/// ⚠ `fvp-probe` learned this the hard way: it first skipped initialisation on the reasoning that
/// "the model's UART is already on", which is true of some boot chains and not others. On an
/// unknown board, assuming is exactly the thing this file exists not to do.
fn uart_init() {
    // SAFETY: MMIO writes to a PL011's documented registers at the supplied base. If the base is
    // wrong this writes to something else — which is unavoidable for a bootstrap fact, and is why
    // `UART0_BASE`'s doc names a silent hang as the symptom.
    unsafe {
        // LCR_H must not be written while enabled, so disable first.
        write_volatile((UART0_BASE + UART_CR) as *mut u32, 0);
        // 8-N-1, FIFOs enabled (WLEN=0b11 at bits [6:5], FEN at bit 4).
        write_volatile((UART0_BASE + UART_LCR_H) as *mut u32, 0b0111_0000);
        // UARTEN | TXE. No baud programming: the divisor depends on the input clock, which is a
        // board fact this probe does not know. Every boot chain that produced output before us has
        // already set it, and the ones that have not will produce garbage rather than silence —
        // which is itself a readable result.
        write_volatile((UART0_BASE + UART_CR) as *mut u32, (1 << 8) | 1);
    }
}

/// Write one byte, spinning while the transmit FIFO is full.
fn putc(b: u8) {
    // SAFETY: as `uart_init`.
    unsafe {
        while read_volatile((UART0_BASE + UART_FR) as *const u32) & (1 << 5) != 0 {}
        write_volatile((UART0_BASE + UART_DR) as *mut u32, u32::from(b));
    }
}

/// A `core::fmt` sink over [`putc`], so the report can use `write!` rather than hand-rolled
/// formatting — the one place this probe trades size for the ability to print a table.
struct Uart;

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                putc(b'\r');
            }
            putc(b);
        }
        Ok(())
    }
}

// ─── System-register reads ──────────────────────────────────────────────────────────────────────

/// `CurrentEL[3:2]` — **the only register read on a path that needs no privilege**, and therefore
/// the first thing done. Everything EL2-specific below is gated on it.
fn current_el() -> u64 {
    let v: u64;
    // SAFETY: `CurrentEL` is readable at every exception level; no memory operand.
    unsafe { asm!("mrs {v}, CurrentEL", v = out(reg) v, options(nomem, nostack, preserves_flags)) };
    (v >> 2) & 0b11
}

/// Read one EL1-readable ID register by name.
///
/// A macro rather than a function per register: `mrs` needs the name as an assembly literal, so a
/// runtime parameter is impossible and the alternative is one near-identical function each.
macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        // SAFETY: a read of an EL1-readable ID/status register. No memory operand, no side effect.
        unsafe {
            asm!(concat!("mrs {v}, ", $name), v = out(reg) v, options(nomem, nostack, preserves_flags))
        };
        v
    }};
}

// ─── The report ─────────────────────────────────────────────────────────────────────────────────

/// Print a raw fact.
fn fact(u: &mut Uart, key: &str, value: u64) {
    let _ = writeln!(u, "@@ {key} = {value:#018x}");
}

/// Print a verdict: a measured value against what `hv-metal` assumes.
///
/// ★ **The verdict is the product, not the raw register.** A hex dump of `ICH_VTR_EL2` tells a
/// reader nothing about whether the vGIC's context layout survives the port; "DIFFERS (4 assumed,
/// 6 measured)" tells them exactly which code has to change. Mismatch is **not failure** — it is
/// the finding this probe exists to produce.
fn verdict(u: &mut Uart, name: &str, measured: u64, assumed: u64, unit: &str) {
    let tag = if measured == assumed { "MATCH " } else { "DIFFERS" };
    let _ = writeln!(
        u,
        "@@ VERDICT {name}: {tag} — hv-metal assumes {assumed} {unit}, measured {measured}"
    );
}

/// Print a CAPABILITY verdict: does the platform support **at least** what `hv-metal` asks for?
///
/// ⚠⚠ **The distinction from [`verdict`] is not cosmetic, and the QEMU self-test is what forced
/// it.** Three checks here first compared for EQUALITY — PA range, VMID width, granule — and all
/// three reported DIFFERS on the very platform `hv-metal` was written against, because `-cpu max`
/// offers 52-bit PAs and 16-bit VMIDs where `hv-metal` *chooses* 40 and 8.
///
/// ★ **`hv-metal` picking a smaller value than the hardware offers is not a mismatch, it is a
/// choice.** What would break a port is a platform that cannot reach the chosen value. So these ask
/// `measured >= required`, and a platform with room to spare reads SUPPORTS with the headroom
/// stated — which is also the number you would need if the choice were ever revisited.
fn capability(u: &mut Uart, name: &str, measured: u64, required: u64, unit: &str) {
    let tag = if measured >= required {
        "SUPPORTS"
    } else {
        "TOO SMALL"
    };
    let _ = writeln!(
        u,
        "@@ VERDICT {name}: {tag} — hv-metal needs {required} {unit}, platform offers {measured}"
    );
}

/// **The authoritative list of what this instrument does.** A flat sequence, so reading it costs
/// about what reading a summary would — and unlike a summary it cannot be wrong (`fvp-probe`'s
/// module doc records three status paragraphs that rotted before it adopted this rule).
///
/// # Safety
///
/// Called once from `_start` with the boot chain's `x0`. `extern "C"` so the assembly can call it.
#[no_mangle]
pub extern "C" fn probe_main(x0: u64) -> ! {
    uart_init();
    let u = &mut Uart;

    let _ = writeln!(u, "\n@@ BOARD-PROBE-BEGIN");
    let _ = writeln!(
        u,
        "@@ note: raw facts are `@@ key = value`; comparisons against hv-metal are `@@ VERDICT`."
    );

    // ── 1. The gate on everything else. ─────────────────────────────────────────────────────────
    let el = current_el();
    let _ = writeln!(u, "@@ CurrentEL = EL{el}");
    if el != 2 {
        let _ = writeln!(
            u,
            "@@ VERDICT el2: ABSENT — the boot chain handed off at EL{el}, not EL2."
        );
        let _ = writeln!(
            u,
            "@@ note: baleen is an EL2 hypervisor, so this board cannot host it as configured."
        );
        let _ = writeln!(
            u,
            "@@ note: check for a firmware option to enter at EL2 before concluding the board cannot."
        );
    } else {
        let _ = writeln!(u, "@@ VERDICT el2: MATCH  — entered at EL2, as hv-metal requires");
    }

    // ── 2. Who is this? ─────────────────────────────────────────────────────────────────────────
    fact(u, "MIDR_EL1", read_sysreg!("midr_el1"));
    fact(u, "MPIDR_EL1", read_sysreg!("mpidr_el1"));
    fact(u, "x0_at_entry", x0);
    let _ = writeln!(
        u,
        "@@ note: x0 is conventionally a DTB pointer; 0 means the boot chain passed none."
    );

    // ── 3. Cache geometry — `hv-metal/src/cache.rs`'s stride. ───────────────────────────────────
    let ctr = read_sysreg!("ctr_el0");
    fact(u, "CTR_EL0", ctr);
    let dmin = 4u64 << ((ctr >> 16) & 0xf);
    let imin = 4u64 << (ctr & 0xf);
    let _ = writeln!(u, "@@ CTR_EL0.IminLine bytes = {imin}");
    verdict(u, "dcache_line", dmin, ASSUMED_DMIN_LINE, "bytes");
    if dmin < ASSUMED_DMIN_LINE {
        let _ = writeln!(
            u,
            "@@ note: FINER than assumed — cache.rs takes min(64, DminLine), so this is the case it"
        );
        let _ = writeln!(
            u,
            "@@ note: was written for (#169). A stride WIDER than the true line would skip lines."
        );
    }

    // ── 4. Address translation limits — mmu.rs and stage2.rs pin these. ─────────────────────────
    let mmfr0 = read_sysreg!("id_aa64mmfr0_el1");
    fact(u, "ID_AA64MMFR0_EL1", mmfr0);
    // PARange is bits [3:0]; the encoding is a table, not a formula.
    let pa_bits = match mmfr0 & 0xf {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        _ => 0,
    };
    capability(u, "pa_range", pa_bits, ASSUMED_PA_BITS, "bits");
    if pa_bits < ASSUMED_PA_BITS && pa_bits != 0 {
        let _ = writeln!(
            u,
            "@@ note: SMALLER than assumed — mmu.rs pins TCR_EL2.PS=0b010 (40-bit) and would be"
        );
        let _ = writeln!(u, "@@ note: naming a physical address size this core cannot encode.");
    }
    // `TGran4` is bits [31:28]. ⚠ It is a SUPPORT code, not a size: `0b0000` = 4 KiB supported,
    // `0b0001` = supported *including* 52-bit output addresses, `0b1111` = NOT supported. The first
    // draft here tested `== 0` and reported DIFFERS on QEMU `-cpu max`, which answers `0b0001` — a
    // MORE capable core failing a check meant to catch a less capable one.
    let tgran4 = (mmfr0 >> 28) & 0xf;
    let tgran4_ok = tgran4 != 0b1111;
    let _ = writeln!(
        u,
        "@@ VERDICT granule_4k: {} — hv-metal emits only 4 KiB (TGran4 = {tgran4:#x})",
        if tgran4_ok { "SUPPORTS" } else { "TOO SMALL" }
    );

    let mmfr1 = read_sysreg!("id_aa64mmfr1_el1");
    fact(u, "ID_AA64MMFR1_EL1", mmfr1);
    // VMIDBits is bits [7:4]: 0b0000 = 8 bits, 0b0010 = 16 bits.
    let vmid_bits = if (mmfr1 >> 4) & 0xf == 2 { 16 } else { 8 };
    capability(u, "vmid_bits", vmid_bits, ASSUMED_VMID_BITS, "bits");

    // ── 5. The vGIC's shape — gic.rs reads this, and the context layout follows from it. ────────
    if el == 2 {
        let vtr = read_sysreg!("ich_vtr_el2");
        fact(u, "ICH_VTR_EL2", vtr);
        verdict(u, "list_registers", (vtr & 0x1f) + 1, ASSUMED_LIST_REGS, "LRs");
        verdict(u, "priority_bits", ((vtr >> 29) & 0x7) + 1, ASSUMED_PRI_BITS, "bits");
    } else {
        let _ = writeln!(
            u,
            "@@ VERDICT list_registers: ABSENT — ICH_VTR_EL2 needs EL2; not read"
        );
    }

    // ── 6. SCTLR_EL2's RESET value — the RES1 question. ─────────────────────────────────────────
    if el == 2 {
        let sctlr = read_sysreg!("sctlr_el2");
        fact(u, "SCTLR_EL2_at_reset", sctlr);
        let _ = writeln!(
            u,
            "@@ VERDICT sctlr_res1: {} — QEMU reports a flat 0x0; silicon should read RES1 bits back as 1",
            if sctlr == 0 { "MATCH " } else { "DIFFERS" }
        );
        let _ = writeln!(
            u,
            "@@ note: a non-zero value here is EXPECTED and is good news — it is the case mmu.rs's"
        );
        let _ = writeln!(
            u,
            "@@ note: read-modify-write of SCTLR_EL2 was written for and has never met."
        );
    }

    // ── 7. The timer — time.rs treats CNTFRQ_EL0 as advisory. ───────────────────────────────────
    fact(u, "CNTFRQ_EL0", read_sysreg!("cntfrq_el0"));
    let _ = writeln!(
        u,
        "@@ note: CNTFRQ_EL0 is firmware-programmed and documented as advisory; a wrong value gives"
    );
    let _ = writeln!(u, "@@ note: a slice of the wrong duration, not a lost guarantee.");

    let _ = writeln!(u, "@@ BOARD-PROBE-END");
    loop {
        // SAFETY: a hint instruction; no memory operand, no privilege requirement.
        unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}

/// Halt quietly. There is nothing to report a panic *to* that is more reliable than the UART this
/// probe may have failed to bring up, so it does not try.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        // SAFETY: as `probe_main`'s park loop.
        unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}
