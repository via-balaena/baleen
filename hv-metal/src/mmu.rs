// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! **EL2's own stage-1 MMU — identity-mapped, attributes unchanged, permissions added.**
//!
//! Ledger item 5's first rung. EL2 has run with `SCTLR_EL2.M == 0` since M3, which means it cannot
//! protect its own memory: its text is writable and its data is executable, because with no
//! translation there are no permissions to apply.
//!
//! ## The constraint that makes this safe, and it is the whole design
//!
//! ~50 places in this crate cite "EL2 runs MMU-off/identity" as a premise, 17 of them inside
//! `SAFETY` comments. **44 of those are ADDRESSING claims (VA == PA) and an identity mapping keeps
//! them true verbatim.** The remaining handful are ATTRIBUTE claims — that EL2's accesses are
//! uncached and strongly ordered — and this module keeps those true too, by mapping exactly what
//! MMU-off already gives rather than what would be conventional:
//!
//! | region | MMU-off behaviour (MEASURED: `SCTLR_EL2 = 0x0`, `I=0`) | mapped as |
//! |---|---|---|
//! | `.text`/`.vectors` | instruction fetch, Normal **Non-cacheable** (`SCTLR_EL2.I == 0`) | Normal-NC, **RO + X** |
//! | `.rodata` | data, Device-nGnRnE | Device-nGnRnE, **RO + XN** |
//! | everything else | data, Device-nGnRnE | Device-nGnRnE, **RW + XN** |
//!
//! **So the only thing that changes is permissions.** `scrub_frame`'s confidentiality argument —
//! which depends explicitly on EL2's stores being non-cacheable — is untouched, and `smmu::publish`'s
//! barrier stays a no-op for the same reason it is today.
//!
//! ⚠ **Making EL2's memory CACHEABLE is a separate rung and is deliberately not done here.** That is
//! where those arguments must be re-derived, and the re-derivation is unwitnessable on QEMU (which
//! models no cache), so a wrong version and a right one look identical. `smmu::publish` names the
//! hazard in its own words: the obligation *"would bite on silicon the moment the EL2 MMU brings
//! normal cacheable mappings with it"*.
//!
//! ★ **`SCTLR_EL2.C` is left at 0 as a structural backstop.** With `C == 0` every data access to
//! Normal memory is forced Non-cacheable *whatever the tables say*, so "nothing became cacheable"
//! does not depend on the descriptors below being right. A review-based guarantee would; this one
//! holds even if this module has a bug.
//!
//! ## What is NOT claimed
//!
//! * **Not a bound on the address space.** The whole low 4 GiB is mapped, because EL2 legitimately
//!   reaches DRAM outside its own image — `dmawitness::poke` takes "a Stage-2 leaf's output address
//!   or a guest IPA inside the model's data window", i.e. `0x8000_0000`+. Making a stray access
//!   fault is a separate property with its own blast radius.
//! * **No guest-isolation content.** A guest can reach exactly what it could before; Stage-2 is what
//!   confines it, and Stage-2 is untouched here. This rung protects the *hypervisor* from itself.

use core::arch::asm;

use crate::el2;

// Symbols from `linker.ld`. Taking the boundaries from the LINK rather than restating addresses in
// Rust means there is one declaration of where the text lives, not two that can drift.
extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
}

fn sym(s: &u8) -> u64 {
    core::ptr::from_ref::<u8>(s) as u64
}

/// 4 KiB granule, and the only granule this emits — matching `hv_s2`, which refuses the others
/// because `S2TG`'s large-granule encodings were never verified against hardware.
const PAGE: u64 = 0x1000;
const BLOCK_2M: u64 = 0x20_0000;
const ENTRIES: usize = 512;

// ─── MAIR_EL2 ───────────────────────────────────────────────────────────────────────────────────

/// Attribute 0 — **Device-nGnRnE**, the encoding `0x00`. What MMU-off gives every data access.
const ATTR_DEVICE: u64 = 0x00;
/// Attribute 1 — **Normal, inner and outer Non-cacheable**, the encoding `0x44`. What MMU-off gives
/// instruction fetches while `SCTLR_EL2.I == 0`, which is what it is here (measured).
const ATTR_NORMAL_NC: u64 = 0x44;
const MAIR_EL2_VALUE: u64 = ATTR_DEVICE | (ATTR_NORMAL_NC << 8);

const ATTRIDX_DEVICE: u64 = 0 << 2;
const ATTRIDX_NORMAL_NC: u64 = 1 << 2;

// ─── descriptor fields ──────────────────────────────────────────────────────────────────────────

const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const DESC_PAGE: u64 = 0b11;

/// `AF` — access flag. Without it the first touch takes an Access Flag fault, and this regime has no
/// handler that would set it.
const AF: u64 = 1 << 10;
/// `SH[9:8] = 0b00` — Non-shareable. Named rather than written as a bare 0 because "absent" and
/// "deliberately zero" are different things to a reader; Device memory ignores it, and nothing here
/// is cacheable, so there is no shareability domain to join.
const SH_NON_SHAREABLE: u64 = 0b00 << 8;

/// `AP[2:1]` at bits `[7:6]` for a **single-EL** stage-1 regime (EL2 without VHE).
///
/// `AP[1]` (bit 6) has no meaning where there is no EL0 and is RES1; `AP[2]` (bit 7) selects
/// writability. So read-write is `0b01` and read-only is `0b11` in these two bits.
///
/// ★ **If this encoding is wrong the rung fails LOUDLY, in one direction or the other**: too
/// permissive and the W^X witness does not fault (the marker is missing and the boot test goes red);
/// too restrictive and EL2 cannot write its own data and dies immediately. There is no reading of
/// these bits that silently half-works, which is why it is safe to pin them here and let the gate
/// adjudicate.
const AP_RW: u64 = 0b01 << 6;
const AP_RO: u64 = 0b11 << 6;

/// `XN` — execute-never, bit 54. (`PXN`, bit 53, is RES0 in a single-EL regime.)
const XN: u64 = 1 << 54;

// ─── the tables ─────────────────────────────────────────────────────────────────────────────────
//
// Static and page-aligned, in `.bss`. They are written before the MMU is enabled — while EL2 is
// still MMU-off, so the stores go straight to DRAM — and read afterwards by the table walker, which
// `TCR_EL2` configures as Non-cacheable for exactly that reason. No cache maintenance is needed or
// possible to get wrong.

#[repr(C, align(4096))]
struct Table([u64; ENTRIES]);

static mut L1: Table = Table([0; ENTRIES]);
/// Level 2 under `L1[1]`, covering `0x4000_0000..0x8000_0000` — the DRAM that holds the image.
static mut L2_IMAGE: Table = Table([0; ENTRIES]);
/// Level 3 under `L2_IMAGE[0]`, covering `0x4000_0000..0x4020_0000` in 4 KiB pages. This is the only
/// place permissions vary, because it is the only 2 MiB region the image's text and rodata live in.
static mut L3_IMAGE: Table = Table([0; ENTRIES]);

/// Build the identity mapping and enable the MMU. Returns the `SCTLR_EL2` read back afterwards.
///
/// # Safety
///
/// Must be called exactly once, at EL2, with the MMU off. Enabling translation changes how every
/// subsequent access is resolved; the mapping is identity, so the caller's own code, stack and
/// return address stay valid across the switch.
pub(crate) unsafe fn enable() -> u64 {
    build_tables();
    // SAFETY: caller's contract — EL2, MMU off, called once.
    unsafe { switch_on() }
}

/// A 1 GiB or 2 MiB **block** descriptor: `pa`, the given permissions, and the fields every entry
/// here shares.
///
/// A helper rather than five hand-written `|` chains — which is not only style. The first version
/// wrote `0x0000_0000 | ATTRIDX_DEVICE | …` for the entry at PA 0, so the address was *documentation
/// inside an expression*, and clippy correctly called the OR a no-op. Making `pa` a parameter keeps
/// the address visible at every call site while removing the dead operand, and means the shared
/// fields are stated once instead of five times where one could silently differ.
const fn block(pa: u64, attr_idx: u64, ap: u64, xn: u64) -> u64 {
    pa | attr_idx | ap | SH_NON_SHAREABLE | AF | xn | DESC_BLOCK
}

/// A 4 KiB **page** descriptor. Same shape as [`block`], different type field.
const fn page(pa: u64, attr_idx: u64, ap: u64, xn: u64) -> u64 {
    pa | attr_idx | ap | SH_NON_SHAREABLE | AF | xn | DESC_PAGE
}

/// Populate the three tables. Split out so the mapping is readable on its own, and so a future
/// reader can see that nothing here touches a system register.
fn build_tables() {
    let text_start = sym(unsafe { &*core::ptr::addr_of!(__text_start) });
    let text_end = sym(unsafe { &*core::ptr::addr_of!(__text_end) });
    let rodata_start = sym(unsafe { &*core::ptr::addr_of!(__rodata_start) });
    let rodata_end = sym(unsafe { &*core::ptr::addr_of!(__rodata_end) });

    let l1 = unsafe { &mut *core::ptr::addr_of_mut!(L1) };
    let l2 = unsafe { &mut *core::ptr::addr_of_mut!(L2_IMAGE) };
    let l3 = unsafe { &mut *core::ptr::addr_of_mut!(L3_IMAGE) };

    // ── L1: 1 GiB per entry, 39-bit VA (512 entries). ──────────────────────────────────────────
    //
    // [0]   0x0000_0000 device MMIO — GICD, GICR, UART, SMMU, virtio, PCIe MMIO
    // [1]   0x4000_0000 DRAM holding the image -> L2, so text/rodata can differ
    // [2]   0x8000_0000 DRAM — `DATA_IPA_BASE` read as a PA by the DMA witness
    // [3]   0xC000_0000 DRAM — `SUP_IPA_BASE`, likewise
    // [256] 0x40_1000_0000 ECAM. Needs 39 bits of VA, which is why T0SZ is 25 and not 32.
    l1.0[0] = block(0x0000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[1] = core::ptr::from_ref(l2) as u64 | DESC_TABLE;
    l1.0[2] = block(0x8000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[3] = block(0xC000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[256] = block(0x40_0000_0000, ATTRIDX_DEVICE, AP_RW, XN);

    // ── L2 under L1[1]: 2 MiB per entry. Entry 0 is a table (the image lives there); the rest are
    //    plain RW blocks covering the guest windows and everything else up to 0x8000_0000. ───────
    l2.0[0] = core::ptr::from_ref(l3) as u64 | DESC_TABLE;
    for i in 1..ENTRIES {
        let pa = 0x4000_0000 + (i as u64) * BLOCK_2M;
        l2.0[i] = block(pa, ATTRIDX_DEVICE, AP_RW, XN);
    }

    // ── L3 under L2[0]: 4 KiB pages over 0x4000_0000..0x4020_0000. The ONLY place permissions
    //    vary, and the reason the linker script page-aligns its boundaries. ──────────────────────
    for i in 0..ENTRIES {
        let va = 0x4000_0000 + (i as u64) * PAGE;
        let desc = if va >= text_start && va < text_end {
            // Executable and read-only. Normal-NC to match `SCTLR_EL2.I == 0`.
            page(va, ATTRIDX_NORMAL_NC, AP_RO, 0)
        } else if va >= rodata_start && va < rodata_end {
            page(va, ATTRIDX_DEVICE, AP_RO, XN)
        } else {
            page(va, ATTRIDX_DEVICE, AP_RW, XN)
        };
        l3.0[i] = desc;
    }
}

/// `TCR_EL2`, non-VHE format (a single `TTBR0_EL2`, no `TTBR1`).
///
/// `T0SZ = 25` gives a 39-bit VA — chosen because ECAM sits at `0x40_1000_0000` and a 32-bit space
/// would not reach it. Walk attributes are **Non-cacheable, Non-shareable**, matching the world the
/// tables were written in: EL2 wrote them with the MMU off, so they went straight to DRAM.
const fn tcr_el2() -> u64 {
    const T0SZ: u64 = 25;
    const IRGN0_NC: u64 = 0b00 << 8;
    const ORGN0_NC: u64 = 0b00 << 10;
    const SH0_NON_SHAREABLE: u64 = 0b00 << 12;
    const TG0_4K: u64 = 0b00 << 14;
    /// `PS[18:16] = 0b010` — 40-bit physical addresses, the same size `hv_s2`'s stage-2 regime uses.
    const PS_40BIT: u64 = 0b010 << 16;
    /// Bits 31 and 23 are **RES1** in the non-VHE `TCR_EL2`. Omitting them is the same class of
    /// error as writing `SCTLR_EL2` whole: it passes where the model does not enforce RES1 and is
    /// wrong where the hardware does.
    const RES1: u64 = (1 << 31) | (1 << 23);
    T0SZ | IRGN0_NC | ORGN0_NC | SH0_NON_SHAREABLE | TG0_4K | PS_40BIT | RES1
}

/// Install the tables and set `SCTLR_EL2.M`.
///
/// # Safety
///
/// EL2, MMU off, tables already built and identity.
unsafe fn switch_on() -> u64 {
    let ttbr = core::ptr::addr_of!(L1) as u64;
    let readback: u64;
    // SAFETY: system-register writes at EL2 installing an identity mapping, so the PC, SP and every
    // live pointer resolve to the same address after the switch as before it.
    //
    // ⚠ `SCTLR_EL2` is a READ-MODIFY-WRITE and must stay one: the register has RES1 bits that a
    // conforming implementation reads back as 1, and a full write of a hand-built value would clear
    // them. QEMU reports `SCTLR_EL2 = 0x0` (measured), so it does not enforce them and a whole-write
    // bug would pass here and be wrong on silicon. `C` is deliberately NOT set — see the module doc.
    //
    // The `dsb sy` orders the table stores before the walker can see them; the `isb` after the
    // `SCTLR_EL2` write context-synchronizes so the very next instruction is fetched through the
    // new mapping.
    unsafe {
        asm!(
            "msr mair_el2, {mair}",
            "msr tcr_el2,  {tcr}",
            "msr ttbr0_el2,{ttbr}",
            "dsb sy",
            "isb",
            "tlbi alle2",
            "dsb sy",
            "isb",
            "mrs {tmp}, sctlr_el2",
            "orr {tmp}, {tmp}, {m}",
            "msr sctlr_el2, {tmp}",
            "isb",
            "mrs {out}, sctlr_el2",
            mair = in(reg) MAIR_EL2_VALUE,
            tcr  = in(reg) tcr_el2(),
            ttbr = in(reg) ttbr,
            m    = in(reg) el2::SCTLR_EL2_M,
            tmp  = out(reg) _,
            out  = out(reg) readback,
            options(nostack, preserves_flags),
        );
    }
    readback
}

/// Whether `SCTLR_EL2.M` is set in a read-back value — the post-condition [`enable`] establishes.
pub(crate) fn mmu_is_on(sctlr: u64) -> bool {
    sctlr & el2::SCTLR_EL2_M != 0
}

/// **Read the descriptor back and report whether EL2's text really is read-only.**
///
/// ⚠ **This exists because the boot line was caught lying.** The report used to state "text RO+X" as
/// a literal string, and a remove-the-fix probe that mapped the text `AP_RW` — changing nothing
/// else — printed *exactly the same line* while the store to text succeeded. A message that asserts
/// a property it does not read is a second copy of the intent, and the copy is what drifts
/// (design-lesson #210). The witness caught it; nothing else would have.
///
/// So the claim is now derived from the same words the hardware walks: find the L3 entry covering
/// `__text_start` and check its `AP[2:1]`. This is the decode direction of `build_tables`'s emit,
/// the `hv-s2` emit-seam/decode-seam idiom applied to a table this crate writes itself.
///
/// ★ It also moves the evidence into EVERY configuration. The `wx-probe` build proves enforcement by
/// taking the fault; this proves the descriptor says so on the default, selftest, smmu and
/// real-Linux boots too — where deliberately faulting would be a terrible idea.
///
/// ⚠ **What it does NOT check, stated because the two checks are complementary and neither alone is
/// the property:** this reads the descriptor *this module wrote*, not the one the hardware walked.
/// A broken `L1[1] → L2_IMAGE → L3_IMAGE` chain would leave this returning `true` while the walker
/// resolved something else entirely. What rules that out is not this function but the machine
/// running at all — a text mapping that did not resolve would fault on the next instruction fetch —
/// and, end to end, the `wx-probe` config, whose fault arrives with `FAR` equal to `__text_start`.
pub(crate) fn text_is_read_only() -> bool {
    let text_start = sym(unsafe { &*core::ptr::addr_of!(__text_start) });
    let l3 = unsafe { &*core::ptr::addr_of!(L3_IMAGE) };
    // The L3 index of `text_start` within the 2 MiB region `L2_IMAGE[0]` covers.
    let idx = ((text_start - 0x4000_0000) / PAGE) as usize;
    if idx >= ENTRIES {
        return false;
    }
    let desc = l3.0[idx];
    // A page descriptor whose AP[2:1] is `AP_RO`, and which really is a page rather than absent.
    desc & 0b11 == DESC_PAGE && desc & (0b11 << 6) == AP_RO
}

/// Whether `SCTLR_EL2.C` is still clear — **the property that keeps this rung's blast radius small**.
///
/// With `C == 0` every data access to Normal memory is Non-cacheable regardless of the descriptors,
/// so `scrub_frame`'s confidentiality argument and `smmu::publish`'s barrier reasoning hold whatever
/// this module got wrong. Checked at boot rather than argued, because it is the difference between
/// this rung and the deferred one.
pub(crate) fn data_cache_still_off(sctlr: u64) -> bool {
    sctlr & el2::SCTLR_EL2_C == 0
}

/// **The W^X witness: write to EL2's own text and require the hardware to refuse.**
///
/// ## Why this exists, and why "MMU on" is not the property
///
/// The boot line reporting `SCTLR_EL2.M == 1` would be equally true of a mapping that made every
/// page RWX. What has to be shown is that the *permissions* took — and the one field this module
/// pinned from reading the architecture rather than from measuring it is `AP[2:1]`.
///
/// ★ **This probe discriminates in both directions, which is why it was safe to pin that encoding
/// and let the gate adjudicate:**
/// * too permissive — the store below SUCCEEDS, execution continues, and the forbidden marker
///   `W^X NOT ENFORCED` is printed, which fails the boot test;
/// * too restrictive — EL2 cannot write its own data and the boot dies long before here.
///
/// There is no reading of those bits that silently half-works.
///
/// ## The negative control is free, and it is the honest kind
///
/// **With the MMU off — every build before this rung — the same store succeeds silently.** So this
/// is a genuine remove-the-fix probe rather than a check that could only ever pass: the fix is
/// `SCTLR_EL2.M`, and removing it is what every prior commit already did.
///
/// The fault is terminal by design: EL2's vector 4 handler reports and halts (`exceptions.rs` —
/// "we report the fault and halt", and the report drains the UART first). So this config's EXPECTED
/// end is a fault, and the boot test asserts the report rather than a clean shutdown.
#[cfg(feature = "wx-probe")]
pub(crate) fn wx_probe(uart: &mut crate::pl011::Pl011) {
    use core::fmt::Write;

    let (text_start, _) = text_span();
    let _ = writeln!(
        uart,
        "baleen: W^X probe: storing to EL2 text at 0x{text_start:08x} — the hardware must refuse"
    );

    // SAFETY: `text_start` is this image's own `.text`, mapped RO+X by `build_tables`. The store is
    // EXPECTED to fault; if it does not, the write lands on the first instruction of `_start`, which
    // nothing executes again — the probe then reports the failure and halts rather than continuing
    // on a corrupted image.
    unsafe { core::ptr::write_volatile(text_start as *mut u32, 0xdead_beef) };

    // Reached only if the store was permitted, i.e. the mapping is not read-only.
    let _ = writeln!(
        uart,
        "baleen: W^X NOT ENFORCED — the store to EL2 text SUCCEEDED"
    );
    crate::park();
}

/// The size, in bytes, of the region mapped read-only and executable — reported so the boot witness
/// states what it protected rather than merely that it protected something.
pub(crate) fn text_span() -> (u64, u64) {
    (
        sym(unsafe { &*core::ptr::addr_of!(__text_start) }),
        sym(unsafe { &*core::ptr::addr_of!(__text_end) }),
    )
}
