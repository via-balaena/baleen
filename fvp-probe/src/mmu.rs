// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # A minimal EL3 MMU, for one purpose: making a **cacheable** store possible
//!
//! ## Why the probe needs an MMU at all
//!
//! With the MMU off, an AArch64 data access is **Device-nGnRnE** — architecturally non-cacheable.
//! So a probe that wants to ask *"does this model hold a dirty line?"* cannot even produce the
//! stimulus without turning translation on. That is the whole reason this file exists; it is not a
//! port of `hv-metal`'s MMU and does not want to be.
//!
//! ## What it maps, and why so little
//!
//! | VA | PA | attributes | why |
//! |---|---|---|---|
//! | `0x0000_0000`, 1 GiB block | identity | `Device-nGnRnE`, XN | the peripherals — PL011 at `0x1c09_0000`, SMMU at `0x2b40_0000` |
//! | `0x8000_0000`, 1 GiB block | identity | **Normal WB cacheable**, RWX | the image, the stack, and [`TEST_PA`] |
//! | [`NC_ALIAS_VA`] , one 4 KiB page | [`TEST_PA`] | **Normal Non-Cacheable**, XN | the observer |
//!
//! ★ **The last row is the instrument.** One physical page reachable two ways — once through a
//! write-back cacheable mapping, once through a non-cacheable one — is what lets the probe ask
//! whether a store through the first is visible through the second *without* cache maintenance.
//! That is precisely the hazard `hv-metal`'s `scrub_frame` guards against, and precisely the thing
//! QEMU cannot exhibit.
//!
//! ⚠ **Identity everywhere else, deliberately.** The alias is the ONLY non-identity mapping, so
//! every address this probe already knew about still means what it meant with the MMU off. A
//! general remap would make a failure ambiguous between "the model coalesces the aliases" and "the
//! probe broke its own addressing".
//!
//! ## Encodings
//!
//! Field positions are `hv-metal/src/mmu.rs`'s, which were derived against the Arm ARM for the EL2
//! regime. **EL3 is the same shape** — a single-exception-level regime with one `TTBR0`, the same
//! VMSAv8-64 descriptor layout, and `AP[2:1]` read as the single-EL form. What differs is only
//! which register the value is written to, so the constants are restated here rather than shared:
//! `fvp-probe` is workspace-excluded and cannot depend on `hv-metal`, and a wrong *silent* copy is
//! not a risk the way it would be for two shipped consumers — a mistake here does not boot.

use core::arch::asm;

/// A level-1 entry spans 1 GiB with a 4 KiB granule and a 39-bit VA.
const BLOCK_1G: u64 = 0x4000_0000;
const ENTRIES: usize = 512;

// ─── MAIR: the three memory types this probe needs ───────────────────────────────────────────────

/// `Device-nGnRnE` — the peripherals.
const ATTR_DEVICE: u64 = 0x00;
/// **Normal, Inner+Outer Write-Back, Read-Allocate, Write-Allocate.** The cacheable half of the
/// experiment: a store here is entitled to sit in a dirty line.
const ATTR_NORMAL_WB: u64 = 0xff;
/// **Normal, Inner+Outer Non-Cacheable.** The observer. A read here is not required to look in the
/// cache, so it sees what is actually in memory — which is the whole question.
const ATTR_NORMAL_NC: u64 = 0x44;

const MAIR_EL3_VALUE: u64 = ATTR_DEVICE | (ATTR_NORMAL_WB << 8) | (ATTR_NORMAL_NC << 16);

const ATTRIDX_DEVICE: u64 = 0 << 2;
const ATTRIDX_NORMAL_WB: u64 = 1 << 2;
const ATTRIDX_NORMAL_NC: u64 = 2 << 2;

// ─── descriptor bits ─────────────────────────────────────────────────────────────────────────────

const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const DESC_PAGE: u64 = 0b11;
/// Access flag. Without it every access takes an Access Flag fault.
const AF: u64 = 1 << 10;
/// Non-shareable. One core is running; nothing here is about inter-core coherency, and
/// non-shareable is the case least likely to be quietly made coherent by a broadcast.
const SH_NON_SHAREABLE: u64 = 0b00 << 8;
/// `AP[2:1] = 0b01` — read/write at this EL (single-EL regime).
const AP_RW: u64 = 0b01 << 6;
/// Execute-never (`XN`/`UXN` bit 54 in a single-EL regime).
const XN: u64 = 1 << 54;

const fn block(pa: u64, attr_idx: u64, xn: u64) -> u64 {
    pa | attr_idx | AP_RW | SH_NON_SHAREABLE | AF | xn | DESC_BLOCK
}

const fn page(pa: u64, attr_idx: u64, xn: u64) -> u64 {
    pa | attr_idx | AP_RW | SH_NON_SHAREABLE | AF | xn | DESC_PAGE
}

// ─── the tables ──────────────────────────────────────────────────────────────────────────────────

#[repr(C, align(4096))]
struct Table([u64; ENTRIES]);

static mut L1: Table = Table([0; ENTRIES]);
static mut L2: Table = Table([0; ENTRIES]);
static mut L3: Table = Table([0; ENTRIES]);

/// The physical page the experiment is about — 16 MiB into DRAM, clear of the image (loaded at
/// `0x8000_0000`) and its 64 KiB stack.
pub const TEST_PA: u64 = 0x8100_0000;

/// The virtual address that reaches [`TEST_PA`] **non-cacheably**. 4 GiB, so it lands in L1 entry
/// 4 — an index nothing else uses, which keeps the alias the only non-identity mapping.
pub const NC_ALIAS_VA: u64 = 0x1_0000_0000;

/// Build the tables and switch translation on, with **caches enabled**.
///
/// # Safety
///
/// Called once, on the boot core, before anything depends on translation. Every address the probe
/// already used stays identity-mapped, so no live pointer changes meaning.
pub unsafe fn enable() {
    // SAFETY: single-core, pre-MMU, exclusive access to the statics.
    unsafe {
        let l1 = &raw mut L1;
        let l2 = &raw mut L2;
        let l3 = &raw mut L3;

        // 0x0000_0000..0x4000_0000 — peripherals. Device, never executable.
        (*l1).0[0] = block(0, ATTRIDX_DEVICE, XN);
        // 0x8000_0000..0xC000_0000 — DRAM: this image, its stack, and TEST_PA. Cacheable, and
        // executable because the probe is running out of it.
        (*l1).0[2] = block(2 * BLOCK_1G, ATTRIDX_NORMAL_WB, 0);
        // The alias: L1[4] -> L2 -> L3 -> one non-cacheable page over TEST_PA.
        (*l1).0[4] = (&raw const (*l2).0 as u64) | DESC_TABLE;
        (*l2).0[0] = (&raw const (*l3).0 as u64) | DESC_TABLE;
        (*l3).0[0] = page(TEST_PA, ATTRIDX_NORMAL_NC, XN);

        asm!(
            "msr mair_el3, {mair}",
            "msr tcr_el3,  {tcr}",
            "msr ttbr0_el3,{ttbr}",
            // The tables are written through non-cacheable (MMU-off) stores and the walker is about
            // to read them; `dsb sy` orders those stores before the walk, `isb` before the enable.
            "dsb sy",
            "isb",
            mair = in(reg) MAIR_EL3_VALUE,
            tcr  = in(reg) tcr_el3(),
            ttbr = in(reg) &raw const (*l1).0 as u64,
            options(nostack, preserves_flags),
        );

        // ⚠ **READ-MODIFY-WRITE, for the reason `hv-metal`'s A1 rung recorded**: `SCTLR_EL3` has
        // RES1 bits, and a whole-register write of a hand-built value clears them. QEMU reads a
        // flat `0x0` and does not enforce them; a model that does would fault or misbehave.
        let mut sctlr: u64;
        asm!("mrs {0}, sctlr_el3", out(reg) sctlr, options(nomem, nostack));
        // M: translation on. C: **data caches on — the entire point of this probe.** I: i-cache.
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
        asm!(
            "msr sctlr_el3, {0}",
            "isb",
            in(reg) sctlr,
            options(nostack, preserves_flags),
        );
    }
}

const fn tcr_el3() -> u64 {
    // 39-bit VA — enough to reach the 4 GiB alias at L1 entry 4.
    const T0SZ: u64 = 25;
    const IRGN0_WB: u64 = 0b01 << 8;
    const ORGN0_WB: u64 = 0b01 << 10;
    const SH0_NON_SHAREABLE: u64 = 0b00 << 12;
    const TG0_4K: u64 = 0b00 << 14;
    const PS_40BIT: u64 = 0b010 << 16;
    // `TCR_EL3` is RES1 at bits 31 and 23, like `TCR_EL2`'s single-EL form.
    const RES1: u64 = (1 << 31) | (1 << 23);
    T0SZ | IRGN0_WB | ORGN0_WB | SH0_NON_SHAREABLE | TG0_4K | PS_40BIT | RES1
}

/// A bare `dsb sy` — **the negative control for [`clean_line`]**.
///
/// A barrier orders accesses; it does not push a dirty line to memory. If the observer still reads
/// stale data after this and fresh data after `DC CVAC`, then the maintenance *operation* is what
/// did the work, and not the barrier that happens to accompany it. Without this the probe would
/// only have shown that "something in `clean_line`" mattered.
///
/// # Safety
///
/// None beyond executing a barrier.
pub unsafe fn barrier_only() {
    // SAFETY: `dsb sy` is unconditionally executable at EL3.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) }
}

/// Clean one cache line to the Point of Coherency, by virtual address.
///
/// This is the operation `scrub_frame` would have to issue once EL2's own mappings become
/// cacheable. Phase 3 of the probe exists to show it is what makes the store visible — a stale read
/// alone would not distinguish "the model holds dirty data" from "that alias is simply broken".
///
/// # Safety
///
/// `va` must be mapped. `DC CVAC` is permitted at EL3.
pub unsafe fn clean_line(va: u64) {
    // SAFETY: caller guarantees the mapping; `dsb sy` completes the maintenance before we return.
    unsafe {
        asm!(
            "dc cvac, {va}",
            "dsb sy",
            va = in(reg) va,
            options(nostack, preserves_flags),
        );
    }
}

/// Cache line length in bytes, from `CTR_EL0.DminLine` — reported so a reader can tell whether the
/// model is describing a real geometry or a placeholder.
pub fn dcache_line_bytes() -> u64 {
    let ctr: u64;
    // SAFETY: `CTR_EL0` is readable at EL3.
    unsafe { asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    // DminLine is log2 of the number of WORDS in the smallest data cache line.
    4u64 << ((ctr >> 16) & 0xf)
}

/// One 8-byte cell of [`TEST_PA`], reached through the **cacheable** identity mapping.
///
/// # Safety
///
/// The MMU must be on ([`enable`]).
pub unsafe fn write_cacheable(value: u64) {
    // SAFETY: TEST_PA is inside the identity-mapped, cacheable 1 GiB DRAM block.
    unsafe { (TEST_PA as *mut u64).write_volatile(value) }
}

/// Read that same cell through the **non-cacheable** alias.
///
/// # Safety
///
/// The MMU must be on ([`enable`]).
pub unsafe fn read_noncacheable() -> u64 {
    // SAFETY: `NC_ALIAS_VA` maps `TEST_PA` as Normal Non-Cacheable.
    unsafe { (NC_ALIAS_VA as *const u64).read_volatile() }
}

/// Write that cell through the **non-cacheable** alias — used to put a known value in memory before
/// the cacheable store, so a stale read has a value the probe chose rather than whatever was there.
///
/// # Safety
///
/// The MMU must be on ([`enable`]).
pub unsafe fn write_noncacheable(value: u64) {
    // SAFETY: as `read_noncacheable`.
    unsafe {
        (NC_ALIAS_VA as *mut u64).write_volatile(value);
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}
