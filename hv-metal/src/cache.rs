// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! **Data-cache maintenance — the one place EL2 knows what a cache line is.**
//!
//! Ledger item 5's second rung (**A2**) made EL2's own DRAM mappings Normal Write-Back
//! Inner-Shareable. Before it, every EL2 data access was Device-nGnRnE and reached memory directly,
//! so "publish this to another agent" was a barrier and nothing else. After it, EL2's stores can sit
//! dirty in a cache that a **non-coherent observer does not see**, and its loads can be answered from
//! a cache line **older than what that observer wrote**. Both directions are real here, and they take
//! different instructions.
//!
//! ## The three operations, and why picking the wrong one is a silent defect
//!
//! | you are about to | use | because |
//! |---|---|---|
//! | let a non-coherent agent READ what EL2 wrote | [`clean`] (`DC CVAC`) | pushes EL2's dirty line out to the point of coherency |
//! | READ what a non-coherent agent wrote | [`invalidate`] (`DC IVAC`) | drops EL2's stale copy so the load goes to memory |
//! | hand DRAM to a new owner (confidentiality) | [`clean_invalidate`] (`DC CIVAC`) | kills a dirty line in both directions at once |
//!
//! ★★ **[`invalidate`] is `DC IVAC` and NOT `DC CIVAC`, and the difference is a defect this project
//! has already shipped once.** `DC CIVAC` **cleans before it invalidates**, so on a line EL2 holds dirty
//! it writes EL2's copy back — straight over what the device just put in memory. Reading back a
//! device's write with a clean-and-invalidate would therefore *republish the value being replaced*,
//! which is exactly the shape of the `scrub_frame` defect #168 found on Arm's AEM: maintenance
//! intended to erase a secret performed its resurrection instead. The call sites are annotated with
//! why EL2 can hold no dirty line there, because "IVAC discards" is only safe when nothing of ours
//! is in that line to discard.
//!
//! ## Why one module rather than a loop per call site
//!
//! The stride has to come from [`line_bytes`], and #169 is the reason: it was a hardcoded `64` whose
//! comment stated the *safe* direction (a smaller stride merely repeats within a line) and not the
//! dangerous one (**a larger stride SKIPS LINES**). Four consumers each writing their own loop is
//! four places for that to drift back. There is one loop, in [`maintain`], and the three public
//! entry points differ only in which instruction it emits.
//!
//! ## What this module does NOT do
//!
//! * **No instruction-cache maintenance, and that is a preserved invariant.** `hv-metal` contains
//!   zero `ic` instructions. A2 deliberately left `SCTLR_EL2.I == 0` and `.text` mapped Normal
//!   **Non-cacheable**, so there is no I-cache state for EL2's own image to keep in step. See
//!   `mmu`'s module doc for why that axis was held fixed while the data axis moved.
//! * **No maintenance by set/way.** Every operation here is by virtual address, which under EL2's
//!   identity mapping is the physical address. Set/way operations are for a cache being taken out of
//!   service, which nothing here does.
//! * **Nothing about the reset state of the caches.** A2 assumes EL2 is entered with no stale line
//!   covering its image; that is a bring-up/loader contract, recorded as a residual in `mmu`'s
//!   module doc rather than discharged here.

use core::arch::asm;

/// The **ceiling** on the maintenance stride, not the stride itself.
///
/// The safety argument is one-directional and worth stating in the direction that bites: a stride
/// **smaller** than the true line is always safe — it merely repeats the operation within a line —
/// while a stride **larger** than the true line **SKIPS LINES**, leaving whatever that line held
/// unmaintained. So the only dangerous case is a core whose minimum line is under 64 bytes.
///
/// ⚠ **This used to be the stride, justified as "64 bytes on every AArch64 core this targets".**
/// That is an assertion about the target set, and the architecture does not require it —
/// `CTR_EL0.DminLine` may report less. [`line_bytes`] MEASURES it and takes the smaller of the two,
/// so the assumption is gone rather than documented (#169).
const CACHE_LINE: u64 = 64;

/// The stride every maintenance loop uses: **the smaller of [`CACHE_LINE`] and the minimum data-cache
/// line this core reports**.
///
/// `CTR_EL0.DminLine` is log2 of the number of 4-byte words in the smallest data cache line, so the
/// size is `4 << DminLine`. Taking the minimum means the stride can only ever get *finer* than the
/// old constant — never coarser — so this cannot skip a line on any core, and does no extra work on
/// the ones the old constant was right about.
///
/// **MEASURED on both platforms this project runs on: 64 bytes** — QEMU `virt` (reported by the
/// `scrubline` marker on every boot) and Arm's AEM (`fvp-probe` milestone 3 prints the same
/// derivation).
///
/// ⚠ **Moved here from `stage2` by A2 and otherwise unchanged.** It had one consumer when the only
/// maintenance in the crate was `scrub_frame`'s; A2 gave it four, which is precisely when a private
/// helper becomes a shared one.
pub(crate) fn line_bytes() -> u64 {
    let ctr: u64;
    // SAFETY: `CTR_EL0` is a read-only ID register, readable at EL2. No memory operand.
    unsafe {
        asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let dmin = 4u64 << ((ctr >> 16) & 0xf);
    if dmin < CACHE_LINE {
        dmin
    } else {
        CACHE_LINE
    }
}

/// Which `DC` operation [`maintain`] emits. Private: the three public wrappers are the vocabulary,
/// because "clean or invalidate?" is a question that should be answered by the *name of the thing
/// you are doing*, not by an argument at the call site.
#[derive(Clone, Copy)]
enum Op {
    /// `DC CVAC` — clean to the point of coherency.
    Clean,
    /// `DC IVAC` — invalidate to the point of coherency, **discarding** any dirty line.
    Invalidate,
    /// `DC CIVAC` — clean *then* invalidate.
    CleanInvalidate,
}

/// Walk `[pa, pa + len)` in [`line_bytes`] steps applying `op`, then `dsb sy`.
///
/// `sy` rather than `ish`: the observers this exists for — the SMMU, a PCIe bus master — are outside
/// the inner-shareable domain, so an inner-shareable barrier would not order the maintenance against
/// their view of memory.
///
/// The loop starts at `pa` rather than at `pa & !(stride - 1)`. Every caller passes a naturally
/// aligned structure (a page, a 64-byte-aligned sentinel, a 16-byte queue slot inside an aligned
/// queue), so the first line is covered either way; and rounding *down* would maintain memory the
/// caller does not own, which for [`Invalidate`](Op::Invalidate) means discarding somebody else's
/// dirty line. Covering the tail is what matters, and `addr < end` does that.
fn maintain(pa: u64, len: u64, op: Op) {
    let stride = line_bytes();
    let end = pa + len;
    let mut addr = pa;
    while addr < end {
        // SAFETY: a `DC` operation takes a VA in a mapped region; EL2 is identity-mapped, so the PA
        // is that VA, and every caller passes a range inside memory this hypervisor owns. Cache
        // maintenance has no architectural memory effect beyond coherency — except for
        // `Op::Invalidate`, whose discard of a dirty line IS a memory effect and is justified at
        // each of its call sites rather than here.
        unsafe {
            match op {
                Op::Clean => asm!("dc cvac, {a}", a = in(reg) addr, options(nostack, preserves_flags)),
                Op::Invalidate => {
                    asm!("dc ivac, {a}", a = in(reg) addr, options(nostack, preserves_flags))
                }
                Op::CleanInvalidate => {
                    asm!("dc civac, {a}", a = in(reg) addr, options(nostack, preserves_flags))
                }
            }
        }
        addr += stride;
    }
    // SAFETY: a barrier instruction; no memory operand, no privilege requirement at EL2.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) }
}

/// **Publish `[pa, pa + len)` to an observer that does not snoop EL2's caches.**
///
/// `DC CVAC` over the range, then `dsb sy`. Use before telling the SMMU — or any bus master — to
/// read a structure EL2 just wrote.
///
/// ⚠ **A barrier alone is not this, and the difference is measured rather than argued.**
/// `fvp-probe` milestone 6 wrote a stream-table entry with EL2's mappings cacheable and the SMMU
/// fetching non-cacheably (`CR1 = 0`, which is what this hypervisor programs), then issued a bare
/// `dsb sy`: **the SMMU answered with the STALE binding.** `DC CVAC` released the new one. A `dsb`
/// orders accesses; it does not push a dirty line to the point of coherency the SMMU fetches from.
pub(crate) fn clean(pa: u64, len: u64) {
    maintain(pa, len, Op::Clean);
}

/// **Drop EL2's copy of `[pa, pa + len)` before reading what a non-snooping observer wrote there.**
///
/// `DC IVAC` over the range, then `dsb sy`.
///
/// ⚠⚠ **This DISCARDS a dirty line rather than writing it back, and every caller must be able to say
/// why EL2 holds none.** That is not a technicality: `DC CIVAC` in this position would write EL2's
/// stale copy back over the device's write, silently restoring the value the read was trying to
/// observe. `scrub_frame` shipped that exact inversion for months (#168) and no gate could see it,
/// because QEMU/TCG models no cache. The two call sites in this crate are the SMMU event queue and
/// the DMA witness's sentinels, and both are memory **only a device ever stores to**.
pub(crate) fn invalidate(pa: u64, len: u64) {
    maintain(pa, len, Op::Invalidate);
}

/// **Clean and invalidate `[pa, pa + len)`** — kill a dirty line in both directions at once.
///
/// `DC CIVAC` over the range, then `dsb sy`. This is `scrub_frame`'s operation: handing DRAM to a
/// new owner has to defeat both a dirty line that could be written back later and a stale clean line
/// that could answer a later read.
///
/// ⚠ **`DC CIVAC` cleans BEFORE it invalidates**, so on its own it *publishes* whatever the line
/// holds. That is why `scrub_frame` runs it on both sides of the zeroing rather than after it — see
/// that function for the measured table.
pub(crate) fn clean_invalidate(pa: u64, len: u64) {
    maintain(pa, len, Op::CleanInvalidate);
}
