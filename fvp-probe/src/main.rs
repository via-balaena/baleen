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
//! ⚠⚠ **"ZERO ENTRIES" IS NOT "NO CACHE", AND THIS FILE WAS FOUNDED ON THAT MISREADING.** It said
//! here that the default of zero was a *built-in control* giving opposite answers in two runs. The
//! model says otherwise — every `size_of_*` parameter's own description ends:
//!
//! > "If this is zero then it is treated as a large number ('infinite') but it is bounded"
//!
//! So the default is an **infinite** cache, and the arm first labelled "caching ON" (64 entries)
//! made it *smaller*. Both arms cached, which is why the first comparison returned identical columns
//! — the result that sent me to read the descriptions.
//!
//! ★ **The design principle outlived its premise, and that is why the error surfaced.** A witness
//! runnable only where it passes is design-lesson #198's failure mode, so `run-fvp.sh --both` makes
//! reporting one arm harder than reporting the pair; the comparison then falsified its own control
//! before any result was written up. The arms now contrast cache **capacity** (infinite vs one
//! entry), because no setting appears to disable the cache at all — and 2d is capacity-dependent,
//! which is what makes it evidence rather than an observation.
//!
//! ## Status
//!
//! **[`probe_main`] is the authoritative list of what this instrument does** — it is a flat
//! sequence of reports, so reading it takes about as long as reading a summary of it would.
//!
//! What holds across all of them, and is the part worth stating in prose: **everything here so far
//! only OBSERVES.** It reads registers and walks config space; it programs no stream table, drives
//! no queue, and issues no DMA. The first write to a device register will be milestone 2, and the
//! order is deliberate — the toolchain, the UART, the SMMU's base address and the presence of a bus
//! master are each established before anything is built on them.
//!
//! ⚠ **This section is deliberately NOT a feature list, because two consecutive ones rotted.** It
//! said "nothing here touches the SMMU yet" while `probe_main` was reading `SMMU_IDR0` — false the
//! day it was written. That was corrected to name the SMMU reads, and *that* went stale within the
//! same session when the PCIe scan landed and became the largest thing in the file. **A status
//! paragraph that enumerates what the code does is a second copy of the code, and the copy is what
//! drifts.** Both were caught by the standing rule that the full diff is read before every push,
//! which is evidence for the rule and against the paragraph.

mod smmu;

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
    puthex_w(v, 16)
}

/// [`puthex`] with an explicit digit count, so a 32-bit register does not print eight leading
/// zeroes. Readability is not cosmetic here: these transcripts are the entire result of the
/// instrument, and a wall of padding is how a wrong value hides in one.
fn puthex_w(v: u64, digits: u32) {
    puts("0x");
    for shift in (0..digits).rev() {
        let nyb = ((v >> (shift * 4)) & 0xf) as u8;
        putb(if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 });
    }
}

/// Print `v` in decimal. Only used for small counts.
fn putdec(mut v: u64) {
    if v == 0 {
        putb(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        putb(buf[n]);
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

/// PCIe ECAM base on the Base RevC.
///
/// `0x4000_0000`, 256 MiB, buses 0–0xff. Two sources: Linux's maintained `fvp-base-revc.dts`
/// (`pci@40000000`, `compatible = "pci-host-ecam-generic"`), corroborated by that node's 32-bit PCI
/// MEM window `0x5000_0000` matching TF-A's `PLAT_ARM_PCI_MEM_1_BASE`.
///
/// ⚠ Nothing like QEMU `virt`'s `0x40_1000_0000`, and note it is a *32-bit* address here. This was
/// the last unresolved row of the platform-fact diff — absent from TF-A's FVP `platform_def.h`,
/// which is where the rest of the table came from. "Not in the source I checked" was not
/// "unknowable"; one more source settled it.
const ECAM_BASE: u64 = 0x4000_0000;

/// ECAM address for a config-space register: `base + (bus << 20) + (dev << 15) + (fn << 12) + off`.
fn cfg_addr(bus: u8, dev: u8, func: u8, off: u16) -> u64 {
    ECAM_BASE
        + (u64::from(bus) << 20)
        + (u64::from(dev) << 15)
        + (u64::from(func) << 12)
        + u64::from(off)
}

fn cfg_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    // SAFETY: ECAM config space on this platform, MMU off, aliasing no Rust object. Reads of
    // config registers have no side effects.
    unsafe { read_volatile(cfg_addr(bus, dev, func, off) as *const u32) }
}

fn cfg_write32(bus: u8, dev: u8, func: u8, off: u16, v: u32) {
    // SAFETY: as `cfg_read32`. Callers restore any register they write for sizing.
    unsafe { write_volatile(cfg_addr(bus, dev, func, off) as *mut u32, v) }
}

/// Walk bus 0 and report every function that answers, with its BAR sizes.
///
/// ## Why this exists before any SMMU programming
///
/// Milestone 2 needs a bus master it can actually drive, and the candidate is Arm's own
/// `SMMUv3TestEngine` (vendor `0x13b5`, device `0xff80`). Before this scan existed, two sources
/// disagreed about whether it is usable as instantiated:
///
/// * the **FVP Reference Guide §12.5** documents the endpoint defaults as `bar0_64bit: true`,
///   `bar0_log2_size: 18` — a 256 KiB register window;
/// * **`--list-params`** reports `pci.pcie_rc.smmuv3testengine0.endpoint.bar0_log2_size=0` and
///   `bar0_64bit=0`, and that parameter's own description says *"zero is reserved means bar is not
///   used"*. A device with no BAR has no register window and cannot be programmed at all.
///
/// ## ★ THE SCAN SETTLED IT, AND AGAINST THE READING I HAD ALREADY WRITTEN DOWN
///
/// **The guide is right and my inference from the parameter list was wrong.** Two engines are live
/// and enumerable at `00:1e.0` and `00:1e.1`, each with **BAR0 = 256 KiB (64-bit)**, BAR2 = 32 KiB,
/// BAR4 = 4 KiB — matching §12.5's `bar0_log2_size: 18`, `bar2_log2_size: 15`, `bar4_log2_size: 12`
/// exactly. So the `smmuv3testengine0..9` parameter names are *available slots* whose defaults read
/// as unconfigured; they are not the two devices the platform actually instantiates.
///
/// **The reusable part is the method, not the fact.** I read a PARAMETER NAMESPACE and inferred a
/// HARDWARE fact — the same move that produced this project's `arm-smmuv3.stage` error, where an
/// unrequested capability was recorded as an absent one (design-lesson #196). The parameter list
/// said "no BAR"; the bus says "256 KiB". **Enumerating cost one run and settled what two documents
/// could not.** Ask the hardware.
///
/// ## What it deliberately is not
///
/// A plain enumeration, not a PCIe subsystem: no bridge configuration, no resource allocation, no
/// capability walking beyond the header. Bus 0 only — anything behind a root port needs bridges
/// programmed first, and the two engines are on bus 0, so that work is not needed and is not done.
/// Every BAR reads back base `0x0`, so milestone 2 must assign addresses itself, exactly as
/// `hv-metal/src/pcie.rs` hand-assigns one rather than growing an allocator.
fn pcie_scan() {
    puts("@@ --- PCIe bus 0 scan (ECAM ");
    puthex_w(ECAM_BASE, 8);
    puts(") ---\n");

    let mut found = 0u64;
    for dev in 0..32u8 {
        // Function 0 first: if it does not answer, the device is absent and the remaining
        // functions must not be probed (the architectural rule, and a stray probe on this model
        // is a fault rather than a read of all-ones).
        let id = cfg_read32(0, dev, 0, 0x00);
        if id == 0xffff_ffff || id == 0 {
            continue;
        }
        let header = (cfg_read32(0, dev, 0, 0x0c) >> 16) & 0xff;
        let multifunction = header & 0x80 != 0;
        let last_func = if multifunction { 7 } else { 0 };

        for func in 0..=last_func {
            let id = cfg_read32(0, dev, func, 0x00);
            if id == 0xffff_ffff || id == 0 {
                continue;
            }
            found += 1;
            let vendor = id & 0xffff;
            let device = id >> 16;
            let class = cfg_read32(0, dev, func, 0x08) >> 8;

            puts("@@ 00:");
            puthex_w(u64::from(dev), 2);
            putb(b'.');
            putdec(u64::from(func));
            puts("  vendor=");
            puthex_w(u64::from(vendor), 4);
            puts(" device=");
            puthex_w(u64::from(device), 4);
            puts(" class=");
            puthex_w(u64::from(class), 6);
            // The one device this whole instrument is shopping for.
            if vendor == 0x13b5 && device == 0xff80 {
                puts("  <-- SMMUv3TestEngine");
            }
            puts("\n");

            // Size each BAR the architectural way: write all-ones, read back, restore. A BAR that
            // reads back zero is unimplemented — which is the exact question §12.5 and the model
            // disagree about.
            let header_type = (cfg_read32(0, dev, func, 0x0c) >> 16) & 0x7f;
            let bar_count = if header_type == 0 { 6 } else { 2 };
            let mut bar = 0u16;
            while bar < bar_count {
                let off = 0x10 + bar * 4;
                let orig = cfg_read32(0, dev, func, off);
                cfg_write32(0, dev, func, off, 0xffff_ffff);
                let probe = cfg_read32(0, dev, func, off);
                cfg_write32(0, dev, func, off, orig);
                if probe == 0 {
                    bar += 1;
                    continue;
                }
                let is_io = orig & 1 != 0;
                let is_64 = !is_io && (orig >> 1) & 0x3 == 0x2;
                // Mask off the type bits before sizing: size = ~(masked) + 1.
                let mask = if is_io { !0x3u32 } else { !0xfu32 };
                let size = (!(probe & mask)).wrapping_add(1);
                puts("@@     BAR");
                putdec(u64::from(bar));
                puts(is_if_64(is_64));
                puts(" base=");
                puthex_w(u64::from(orig & mask), 8);
                puts(" size=");
                puthex_w(u64::from(size), 8);
                puts("\n");
                bar += if is_64 { 2 } else { 1 };
            }
        }
    }

    puts("@@ --- PCIe scan found ");
    putdec(found);
    puts(" function(s) ---\n");
}

/// Tiny helper so the BAR line reads `BAR0(64)` without a formatter.
fn is_if_64(is_64: bool) -> &'static str {
    if is_64 {
        "(64)"
    } else {
        "(32)"
    }
}

/// Report one ATOS answer on a single line, tagged with what the caller expected of it.
fn report_translation(label: &str, t: &smmu::Translation) {
    puts("@@ ");
    puts(label);
    if t.timeout {
        puts("  TIMEOUT (the SMMU never cleared GATOS_CTRL.RUN)\n");
        return;
    }
    if t.fault {
        puts("  FAULT   PAR=");
        puthex_w(t.par, 16);
        puts("\n");
        return;
    }
    puts("  PA=");
    puthex_w(t.pa, 16);
    puts(" size=");
    puthex_w(t.size, 8);
    puts("  PAR=");
    puthex_w(t.par, 16);
    puts("\n");
}

/// **Milestone 2a — the through-path positive control, and the deny control beside it.**
///
/// ## Why these two phases come before any staleness experiment
///
/// SMMU rung 2 recorded the trap this is avoiding, and it is worth restating because it is the
/// reason for the ordering rather than a general caution. **An ∀-StreamID deny result passes
/// trivially if nothing ever reaches the stream table at all.** A mis-sized `STRTAB_BASE_CFG`, a
/// wrong `SIDSIZE`, an STE at the wrong stride, a StreamID that is not the device's RequesterID, or
/// `SMMUEN` never taking — every one of those yields "the translation faulted", which is
/// indistinguishable from the property holding.
///
/// So the first thing that must work is a translation that **succeeds and lands where the TABLE
/// says**, not where the caller asked. `TEST_IPA` is `0x1000_0000` and the answer must be
/// `TARGET_A`; if the SMMU were bypassing, the answer would be `0x1000_0000` itself, which is why
/// the two addresses are deliberately unequal.
///
/// Only then does phase 2's fault mean anything: a second StreamID, one the stream table leaves at
/// `V=0`, must be refused *by the same SMMU in the same state that just answered phase 1*.
fn milestone_2a() {
    puts("@@ --- milestone 2a: ATOS through-path + deny control ---\n");

    smmu::build_tables(smmu::L1_A, smmu::L2_A, smmu::TARGET_A);

    if !smmu::bring_up() {
        puts("@@ 2a FAIL — the SMMU did not acknowledge bring-up; nothing below is meaningful\n");
        return;
    }
    puts("@@ SMMU_GERROR = ");
    puthex_w(u64::from(smmu::gerror()), 8);
    puts("\n");

    smmu::bind(smmu::SID_A, smmu::L1_A, smmu::VMID_A);
    puts("@@ STE[f0].S2TTB read back = ");
    puthex_w(smmu::ste_s2ttb(smmu::SID_A), 16);
    puts("\n");

    // What is actually in memory at the addresses the STE names. Read back, not recomputed:
    // recomputing would only show the same expression evaluating twice.
    let (l1a, l1d, l2a, l2d) = smmu::descriptors(smmu::L1_A, smmu::L2_A);
    puts("@@ L1[");
    puthex_w(l1a, 8);
    puts("] = ");
    puthex_w(l1d, 16);
    puts("\n@@ L2[");
    puthex_w(l2a, 8);
    puts("] = ");
    puthex_w(l2d, 16);
    puts("\n");

    // Phase 1 — the positive control. MUST succeed, and MUST answer TARGET_A.
    let t = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2a.1 bound   sid=f0 ipa=0x10000000 expect PA=0x82000000", &t);
    let (rsid, raddr) = smmu::atos_request_readback();
    puts("@@      request read back: GATOS_SID=");
    puthex_w(rsid, 16);
    puts(" GATOS_ADDR=");
    puthex_w(raddr, 16);
    puts("\n");

    // ★ THE WALK PROBE, and it is what proved the mechanism was right while the decode was wrong.
    // ATOS answers with the TRANSLATION, not with a byte address, so every IPA inside the mapped
    // 2 MiB block must return the SAME block — identical `PA` and `size`. The block boundary is
    // where the answer must change, and it must change to a fault, because nothing maps the next
    // block. If `+0x200000` did not fault, the walk would not be using this code's table at all and
    // every other reading would be worthless.
    let p1 = smmu::translate(smmu::SID_A, smmu::TEST_IPA + 0x1000);
    report_translation("2a.p +0x1000    (inside the block, expect the SAME block)", &p1);
    let p2 = smmu::translate(smmu::SID_A, smmu::TEST_IPA + 0x10_0000);
    report_translation("2a.p +0x100000  (inside the block, expect the SAME block)", &p2);
    let p3 = smmu::translate(smmu::SID_A, smmu::TEST_IPA + 0x20_0000);
    report_translation("2a.p +0x200000  (NEXT block, unmapped, expect FAULT)    ", &p3);
    let walk_ok = p1.pa == smmu::TARGET_A
        && p2.pa == smmu::TARGET_A
        && p1.size == 0x20_0000
        && p3.fault
        && !p3.timeout;

    // Phase 2 — the deny control, on a StreamID left at V=0.
    let d = smmu::translate(smmu::SID_B, smmu::TEST_IPA);
    report_translation("2a.2 unbound sid=f1 ipa=0x10000000 expect FAULT           ", &d);

    // The floor requires ALL of: the bound stream translates, to exactly the frame the table names,
    // at exactly the block size the descriptor programmed, with the block boundary in the right
    // place, and an unbound stream refused by the same SMMU in the same state.
    let ok = !t.fault
        && !t.timeout
        && t.pa == smmu::TARGET_A
        && t.size == 0x20_0000
        && walk_ok
        && d.fault
        && !d.timeout;
    puts(if ok {
        "@@ 2a OK — the SMMU translates to the frame the table names, at the size the descriptor \
         programmed, and refuses an unbound stream\n"
    } else {
        "@@ 2a FAIL — the floor is not established; do NOT interpret any staleness result\n"
    });
}

/// Report an experiment's outcome in a form the two-run comparison can read mechanically.
///
/// ★ The probe deliberately does NOT decide whether the outcome is correct. It cannot: whether "the
/// mapping went stale" is the right answer depends on the cache capacity the model was given, and
/// this binary is not told which arm it is running in. Deciding here would bake in an expectation
/// that holds for one configuration — which is how a witness ends up only runnable where it passes
/// (design-lesson #198). The comparison belongs to whatever ran both.
///
/// ⚠ That separation is what saved this milestone. The arms were originally believed to be
/// caching-off vs caching-on; they were not, and the probe reporting raw observations rather than
/// verdicts meant the identical columns were visible as data instead of being pre-judged into a
/// pass.
fn result(name: &str, value: &str) {
    puts("@@ RESULT ");
    puts(name);
    putb(b'=');
    puts(value);
    puts("\n");
}

/// Classify an answer against the two frames it could name.
fn which(t: &smmu::Translation) -> &'static str {
    if t.timeout {
        "TIMEOUT"
    } else if t.fault {
        "FAULT"
    } else if t.pa == smmu::TARGET_A {
        "A"
    } else if t.pa == smmu::TARGET_B {
        "B"
    } else {
        "OTHER"
    }
}

/// **2b — is the STE cached, and does `CMD_CFGI_STE` matter?**
///
/// Rewrite the STE to name a different table set *without* telling the SMMU. If the answer does not
/// move, the configuration cache is real. The third step is the control that makes the second
/// interpretable: after `CMD_CFGI_STE` the answer MUST move, which proves the rewrite was real and
/// reached memory. Without it, "no change" would also be consistent with the STE write having gone
/// nowhere at all.
fn milestone_2b() {
    puts("@@ --- 2b: STE caching / CMD_CFGI_STE ---\n");
    smmu::reset_all();
    smmu::bind(smmu::SID_A, smmu::L1_A, smmu::VMID_A);

    let base = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2b.1 baseline        (expect A)", &base);

    // ⚠ The new binding uses a DIFFERENT VMID, and that is the whole repair.
    //
    // The first version rebound to `L1_B` under the SAME `VMID_A` and reported INCONCLUSIVE: even
    // after `CMD_CFGI_STE` the answer stayed `A`. That was not a broken SMMU — **`CMD_CFGI_STE`
    // invalidates the CONFIGURATION cache, not the TRANSLATION cache.** The STE change was picked
    // up, and then the still-cached `(VMID_A, IPA)` translation shadowed it, so the walk never
    // reached `L1_B`. The experiment conflated two caches and measured their conjunction.
    //
    // Rebinding under `VMID_B` means no cached translation applies to the new configuration, so
    // what the answer depends on is exactly one thing: whether the SMMU re-read the STE.
    smmu::bind_silently(smmu::SID_A, smmu::L1_B, smmu::VMID_B);
    let quiet = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2b.2 STE->B, NO CFGI (A=stale)  ", &quiet);

    smmu::invalidate_ste(smmu::SID_A);
    let after = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2b.3 after CFGI_STE  (expect B) ", &after);

    let sane = which(&base) == "A" && which(&after) == "B";
    result("2b_ste_cache", if !sane { "INCONCLUSIVE" } else if which(&quiet) == "A" { "STALE" } else { "FRESH" });
}

/// **2c — is the stage-2 translation cached, and does `CMD_TLBI_*` matter?**
///
/// The same shape one level down: change the block descriptor in place, touching one 8-byte word,
/// and re-ask without invalidating. ★ This is the experiment SMMU rung 3's gotcha 4 could not run —
/// removing `CMD_TLBI_NSNH_ALL` on QEMU "changed nothing observable", and rung 4b re-probed it and
/// it refused to go red a second time. Both were recorded as findings rather than passes, because
/// QEMU models no caching and so cannot tell "the TLBI did nothing" from "there is nothing to
/// invalidate".
fn milestone_2c() {
    puts("@@ --- 2c: stage-2 TLB / CMD_TLBI ---\n");
    smmu::reset_all();
    smmu::bind(smmu::SID_A, smmu::L1_A, smmu::VMID_A);

    let base = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2c.1 baseline        (expect A)", &base);

    smmu::remap(smmu::L2_A, smmu::TARGET_B);
    let quiet = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2c.2 desc->B, NO TLBI (A=stale) ", &quiet);

    smmu::invalidate_all();
    let after = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    report_translation("2c.3 after TLBI      (expect B) ", &after);

    let sane = which(&base) == "A" && which(&after) == "B";
    result("2c_tlb", if !sane { "INCONCLUSIVE" } else if which(&quiet) == "A" { "STALE" } else { "FRESH" });
}

/// **2d — are cached translations tagged with the VMID?**
///
/// Two StreamIDs on **the same tables** under **different VMIDs**, then invalidate ONE VMID and ask
/// both.
///
/// ★ This is a better instrument than the one ledger 2(d) has been waiting on. Rung 3 asked "does a
/// wrong `STE.S2VMID` change anything observable?" and QEMU said no — but that was never evidence
/// about VMID tagging, only about a platform that tags nothing. Here the discriminator is
/// **VMID-scoped invalidation**: if entries carry a VMID, `CMD_TLBI_S2_IPA` for `VMID_A` must free
/// exactly one of the two streams and leave the other stale. A difference between two streams
/// reading the same descriptor cannot be explained by anything except the tag.
fn milestone_2d() {
    puts("@@ --- 2d: S2VMID tagging via scoped invalidation ---\n");
    smmu::reset_all();
    // The SAME table set for both, so any later difference is the VMID and nothing else.
    smmu::bind(smmu::SID_A, smmu::L1_A, smmu::VMID_A);
    smmu::bind(smmu::SID_B, smmu::L1_A, smmu::VMID_B);

    let a0 = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    let b0 = smmu::translate(smmu::SID_B, smmu::TEST_IPA);
    report_translation("2d.1 sid=f0 vmid=11 baseline (expect A)", &a0);
    report_translation("2d.1 sid=f1 vmid=22 baseline (expect A)", &b0);

    // One shared descriptor changes; neither stream is told.
    smmu::remap(smmu::L2_A, smmu::TARGET_B);
    let a1 = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    let b1 = smmu::translate(smmu::SID_B, smmu::TEST_IPA);
    report_translation("2d.2 sid=f0 after desc->B, no TLBI     ", &a1);
    report_translation("2d.2 sid=f1 after desc->B, no TLBI     ", &b1);

    // Invalidate ONLY VMID_A.
    smmu::invalidate_vmid(smmu::VMID_A);
    let a2 = smmu::translate(smmu::SID_A, smmu::TEST_IPA);
    let b2 = smmu::translate(smmu::SID_B, smmu::TEST_IPA);
    report_translation("2d.3 sid=f0 after TLBI(vmid=11) exp B  ", &a2);
    report_translation("2d.3 sid=f1 after TLBI(vmid=11) exp A  ", &b2);

    // The control: f1's staleness must be invalidatable too, or 2d.3 says nothing about scoping.
    smmu::invalidate_vmid(smmu::VMID_B);
    let b3 = smmu::translate(smmu::SID_B, smmu::TEST_IPA);
    report_translation("2d.4 sid=f1 after TLBI(vmid=22) exp B  ", &b3);

    let sane = which(&a0) == "A" && which(&b0) == "A" && which(&b3) == "B";
    let scoped = which(&a2) == "B" && which(&b2) == "A";
    result(
        "2d_vmid",
        if !sane {
            "INCONCLUSIVE"
        } else if scoped {
            "SCOPED"
        } else if which(&a2) == which(&b2) {
            "UNSCOPED"
        } else {
            "OTHER"
        },
    );
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

    // `SMMU_IDR1.SIDSIZE` (bits [5:0]) bounds the stream table milestone 2 has to build, and
    // `CMDQS`/`EVTQS` bound its queues. Read now rather than assumed from QEMU's `0x02730010`,
    // because every other number carried across from that platform has so far been wrong.
    // SAFETY: SMMUv3 register space, read-only ID register, no side effects.
    let idr1 = unsafe { read_volatile((SMMU_BASE + 0x4) as *const u32) };
    puts("@@ SMMU_IDR1   = ");
    puthex_w(u64::from(idr1), 8);
    puts("  SIDSIZE=");
    putdec(u64::from(idr1 & 0x3f));
    puts("\n");

    pcie_scan();
    milestone_2a();
    milestone_2b();
    milestone_2c();
    milestone_2d();

    puts("@@ FVPPROBE-END\n");
    semihosting_exit()
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    puts("\n@@ FVPPROBE-PANIC\n");
    semihosting_exit()
}
