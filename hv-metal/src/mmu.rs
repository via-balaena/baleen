// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! **EL2's own stage-1 MMU — identity-mapped, permissions added, and (since A2) its DRAM cacheable.**
//!
//! Ledger item 5, both rungs. **A1** gave EL2 translation at all: it had run with `SCTLR_EL2.M == 0`
//! since M3, which meant it could not protect its own memory — its text was writable and its data
//! executable, because with no translation there are no permissions to apply. **A2** is this
//! module's second half: EL2's DRAM is now **Normal Write-Back Inner-Shareable** and
//! `SCTLR_EL2.C == 1`.
//!
//! ## What A1 promised, and which half of it A2 kept
//!
//! ~50 places in this crate cite "EL2 runs MMU-off/identity" as a premise, 17 of them inside
//! `SAFETY` comments. They split cleanly, and the split is the reason A1 and A2 could be separate
//! rungs at all:
//!
//! * **44 are ADDRESSING claims (VA == PA).** An identity mapping keeps them true verbatim, and A2
//!   does not touch addressing. **These are unaffected by both rungs.**
//! * **The remaining handful are ATTRIBUTE claims** — that EL2's accesses are uncached and strongly
//!   ordered. A1 kept them by mapping exactly what MMU-off already gives. ⚠ **A2 is precisely the
//!   rung that breaks them**, which is why it is a rung and not a patch.
//!
//! ## The map, and A2's scope decision
//!
//! | region | A1 mapped it | **A2 maps it** | why |
//! |---|---|---|---|
//! | MMIO (`L1[0]`, ECAM `L1[256]`) | Device-nGnRnE | **unchanged** | it is not memory |
//! | IPA windows (`L1[2]`, `L1[3]`) | Device-nGnRnE | **unchanged** | not known to be backed; Normal memory may be read speculatively, Device may not |
//! | `.text`/`.vectors` | Normal-NC, RO + X | **unchanged** | `SCTLR_EL2.I` is still 0, so fetch is Non-cacheable regardless |
//! | `.rodata` | Device-nGnRnE, RO + XN | **Normal-WB ISH**, RO + XN | it is DRAM |
//! | `.data`, `.bss`, both stacks, all three guest windows | Device-nGnRnE, RW + XN | **Normal-WB ISH**, RW + XN | it is DRAM, and it is everything the hypervisor keeps |
//!
//! ★ **Inner Shareable, not merely cacheable** — see [`SH_INNER_SHAREABLE`]. And the same memory
//! type `hv-s2` already gives a guest, so EL2 and its guests now name the same DRAM the same way.
//!
//! ## ★★ A2 is a REPAIR as well as a change, and this is the part the roadmap had backwards
//!
//! The board carried A2 as pure cost for months. It is also the fix for a **live** mismatch:
//! `VTCR_EL2` is `0x8002_3559`, i.e. the **stage-2 table walker has always fetched Write-Back
//! Inner-Shareable** while EL2's own stores reached memory as Device-nGnRnE. Two agents, the same
//! stage-2 tables in `.bss`, different memory types — the mismatched-alias case `docs/ARC-4` item 2
//! names. A2 puts EL2 in the walker's domain. [`tcr_el2`] had to move for the identical reason one
//! level down, and *not* moving it would have re-created the same defect inside this rung.
//!
//! ## The obligations A2 creates, and the three that are SILENT when unmet
//!
//! | site | obligation | silent? |
//! |---|---|---|
//! | [`smmu::publish`](crate::smmu) | `DC CVAC`, not a bare `dsb` — the SMMU fetches non-coherently (`CR1 = 0`) | no: a stale STE fails a read-back |
//! | `smmu::submit` | ⚠ the command BYTES need publishing, not just the structure | **YES** — `CMD_SYNC` reports success either way |
//! | `smmu::take_event` | ⚠ `DC IVAC` before reading a record the SMMU wrote | **YES** — a stale queue reads as "no event" |
//! | `dmawitness::sentinel` | ⚠ `DC IVAC` before reading a sentinel a *device* wrote | **YES**, and it inverts an ISOLATION result — see below |
//! | `stage2::build_stage2_from_p2m` | publish the tables; the SMMU walks them too | no: the CPU's own walker is coherent, so a miss shows up on the device path |
//! | `stage2::scrub_frame` | already correct — its after-pass becomes load-bearing | no |
//!
//! ★★★ **The sharpest of these is `dmawitness`, and it is on the isolation path rather than the gate
//! path.** The witness reads a sentinel, lets a bus master write over it, and reads it again; a
//! surviving `SENTINEL_MAGIC` means "the SMMU aborted the DMA". Under A2 the first read pulls the
//! magic into a cache the device does not snoop, so **the second read returns it whether or not the
//! DMA landed** — every SMMU rung would report confinement it never observed. A2 had to fix that to
//! be correct, and the fix is one `DC IVAC`; the finding is that a rung about *performance and
//! coherency* reaches an *isolation verdict* through a function nobody would have thought to check.
//!
//! ## The instrument, and what it does and does not grade
//!
//! A2's re-derivations used to carry "and this is unwitnessable on QEMU, so a wrong version and a
//! right one look identical". **That was true of QEMU and was taken to mean no platform**, which is
//! a different claim and nobody had tested it (design-lesson #238/#245):
//!
//! | A2 re-derivation | graded by | result |
//! |---|---|---|
//! | `scrub_frame` | `fvp-probe` m3 → **m4** | the SHIPPED order **published the secret** — a real defect, fixed in #168 before A2 landed |
//! | `smmu::publish` | `fvp-probe` **m6** | a bare `dsb sy` left the SMMU reading the **stale** table; `DC CVAC` released it. And a second requirement nobody had recorded: **every submitted COMMAND must be published too**, silently, because `CMD_SYNC` succeeds either way |
//!
//! **What is still true** is the narrower sentence: *no gate this repository runs* can grade them.
//! `fvp-probe` shares no source with `hv-metal` and `hv-metal` has never run on the FVP, so the
//! mechanism is witnessed and the call site is not — the standing of honest-ledger 2(d). Every gate
//! in this repository was green before A2 and is green after it, and that is a statement about
//! QEMU's cache model rather than about this rung. ⚠ **A2's ATOMICS half is a different matter and
//! remains unwitnessable anywhere available**: m5 measured the AEM resolving `LDXR`/`STXR` on Device
//! memory benignly, so silicon is its only oracle, and this crate's release build contains 40
//! exclusive-monitor instructions across six modules.
//!
//! ## ⚠ The backstop A2 spent, and the residual it leaves
//!
//! **A1 left `SCTLR_EL2.C` at 0 as a structural backstop**: with `C == 0` every data access to
//! Normal memory is forced Non-cacheable *whatever the tables say*, so "nothing became cacheable"
//! held even if this module had a bug. **A2 spent that backstop, deliberately and irreversibly** —
//! descriptor correctness is now load-bearing, which is why [`coverage`] grew from `L3`'s
//! permissions to all three levels' permissions *and* memory types.
//!
//! ⚠ **RESIDUAL, undischarged and named rather than argued away: A2 assumes EL2 is entered with no
//! cache line covering its image.** Before A2 a stale line could never be *consumed* by EL2, because
//! `C == 0` forced every read to memory; now it can. Discharging it means invalidating the image's
//! range at entry, and the correct instruction differs by region (a loader's dirty lines hold our
//! `.text` and must be cleaned, while a stale line over `.bss` must be discarded), so it is a
//! **bring-up/loader contract** and belongs with the loader story a real board needs — not here,
//! where `-kernel` writes DRAM directly and there is no loader to contract with.
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

/// The address of a linker symbol.
///
/// Takes a raw pointer rather than a reference on purpose: `&*addr_of!(EXTERN_STATIC)` would
/// materialise a `&u8` to memory this code never reads, which is a stronger claim than needed and
/// an `unsafe` block per call site. Only the ADDRESS is wanted, and forming it is safe.
///
/// Not `const`: a pointer cannot be cast to an integer during const evaluation, and the addresses
/// are link-time values anyway.
fn sym(p: *const u8) -> u64 {
    p as u64
}

/// 4 KiB granule, and the only granule this emits — matching `hv_s2`, which refuses the others
/// because `S2TG`'s large-granule encodings were never verified against hardware.
const PAGE: u64 = 0x1000;
const BLOCK_2M: u64 = 0x20_0000;
const ENTRIES: usize = 512;

// ─── MAIR_EL2 ───────────────────────────────────────────────────────────────────────────────────

/// Attribute 0 — **Device-nGnRnE**, the encoding `0x00`. What MMU-off gives every data access, and
/// what MMIO and the two unbacked addressability windows keep.
const ATTR_DEVICE: u64 = 0x00;
/// Attribute 1 — **Normal, inner and outer Non-cacheable**, the encoding `0x44`. What MMU-off gives
/// instruction fetches while `SCTLR_EL2.I == 0`, which is what it is here (measured). `.text` keeps
/// this under A2 — see the module doc's "the axis A2 did not move".
const ATTR_NORMAL_NC: u64 = 0x44;
/// Attribute 2 — **Normal, inner and outer Write-Back, Read-Allocate Write-Allocate,
/// non-transient**, the encoding `0xff`. **A2's attribute**, and it is deliberately the same memory
/// type `hv-s2` gives a guest: `hv_s2::arm64::desc::LEAF_COMMON` is `MemAttr = 0b1111` with
/// `SH = 0b11`, i.e. Normal-WB Inner-Shareable. EL2 and its guests now name the same DRAM the same
/// way, which is what makes the alias between them well-defined rather than merely untested.
const ATTR_NORMAL_WB: u64 = 0xff;
const MAIR_EL2_VALUE: u64 = ATTR_DEVICE | (ATTR_NORMAL_NC << 8) | (ATTR_NORMAL_WB << 16);

const ATTRIDX_DEVICE: u64 = 0 << 2;
const ATTRIDX_NORMAL_NC: u64 = 1 << 2;
const ATTRIDX_NORMAL_WB: u64 = 2 << 2;
/// `AttrIndx[4:2]` — the whole field, so [`coverage`] can compare a descriptor's memory type for
/// EQUALITY rather than testing bits. `desc & ATTRIDX_NORMAL_WB != 0` would be satisfied by index 2
/// *and* by indices 3, 6 and 7, which is how an attribute check turns into no check at all.
const ATTRIDX_MASK: u64 = 0b111 << 2;
/// `SH[9:8]` — the whole field, for the same reason.
const SH_MASK: u64 = 0b11 << 8;

// ─── descriptor fields ──────────────────────────────────────────────────────────────────────────

const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const DESC_PAGE: u64 = 0b11;

/// `AF` — access flag. Without it the first touch takes an Access Flag fault, and this regime has no
/// handler that would set it.
const AF: u64 = 1 << 10;
/// `SH[9:8] = 0b00` — Non-shareable. Named rather than written as a bare 0 because "absent" and
/// "deliberately zero" are different things to a reader. Device memory ignores shareability, so this
/// is what the Device mappings carry; it is **not** a claim that nothing is cacheable, which is what
/// it used to be (see [`SH_INNER_SHAREABLE`]).
const SH_NON_SHAREABLE: u64 = 0b00 << 8;

/// `SH[9:8] = 0b11` — **Inner Shareable**, and A2 needs it to be this rather than merely cacheable.
///
/// ★ **Cacheable-but-Non-shareable would not have closed the hazard A2 exists to close.**
/// `VTCR_EL2` is `0x8002_3559`, whose `IRGN0`/`ORGN0` are Write-Back and whose **`SH0` is Inner
/// Shareable** — so the stage-2 table walker has been fetching coherently in the inner-shareable
/// domain the whole time, while EL2's own stores went to memory as Device-nGnRnE. That mismatch is
/// the live one `docs/ARC-4-TRAP-AND-SERVICE.md` item 2 names, and matching *cacheability* without
/// matching *shareability* would have left the walker and EL2 in different domains and the mismatch
/// intact under a new description.
///
/// The same argument holds for guests: `hv_s2::arm64::desc::LEAF_COMMON` carries `SH = 0b11`.
const SH_INNER_SHAREABLE: u64 = 0b11 << 8;

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
    // SAFETY: caller's contract — called exactly once, so the `&mut` references `build_tables`
    // forms to the three static tables cannot alias any other live reference to them.
    unsafe { build_tables() };
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
    pa | attr_idx | ap | shareability(attr_idx) | AF | xn | DESC_BLOCK
}

/// A 4 KiB **page** descriptor. Same shape as [`block`], different type field.
const fn page(pa: u64, attr_idx: u64, ap: u64, xn: u64) -> u64 {
    pa | attr_idx | ap | shareability(attr_idx) | AF | xn | DESC_PAGE
}

/// The shareability a memory type must carry — **derived from the attribute index rather than passed
/// alongside it**.
///
/// ★ A2 could have made `sh` a fifth parameter of [`block`]/[`page`]. It is a derivation instead
/// because the two are not independent facts: a cacheable EL2 mapping that is not Inner Shareable
/// fails to close the `VTCR_EL2` mismatch A2 exists for (see [`SH_INNER_SHAREABLE`]), so
/// "Normal-WB and Non-shareable" is not a configuration this hypervisor ever wants — it is a bug
/// with a spelling. Making it unspellable costs one `match` and removes eight call sites at which it
/// could have been written by hand and one of them differed.
const fn shareability(attr_idx: u64) -> u64 {
    if attr_idx == ATTRIDX_NORMAL_WB {
        SH_INNER_SHAREABLE
    } else {
        // Device memory ignores `SH` entirely, and `.text`'s Normal-Non-cacheable has no
        // coherency to maintain — a non-cacheable access is already visible to every observer.
        SH_NON_SHAREABLE
    }
}

/// Populate the three tables. Split out so the mapping is readable on its own, and so a future
/// reader can see that nothing here touches a system register.
///
/// # Safety
///
/// Must be called at most once. It forms `&mut` references to the three `static mut` tables, and a
/// second concurrent or re-entrant call would alias them. `unsafe` rather than a comment because
/// this crate's whole discipline is that the obligation is carried by the signature where it can be:
/// a safe function that hands out `&mut` to a `static mut` is unsound no matter how it is used, and
/// the fact that the single caller is correct is not a property of THIS function.
unsafe fn build_tables() {
    let text_start = sym(core::ptr::addr_of!(__text_start));
    let text_end = sym(core::ptr::addr_of!(__text_end));
    let rodata_start = sym(core::ptr::addr_of!(__rodata_start));
    let rodata_end = sym(core::ptr::addr_of!(__rodata_end));

    // SAFETY: caller's contract (at most one call), and these are three DISTINCT statics, so the
    // three `&mut` do not alias each other. Nothing else in the crate touches them — they exist
    // only to be walked by the hardware, which reads memory rather than Rust references.
    let (l1, l2, l3) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(L1),
            &mut *core::ptr::addr_of_mut!(L2_IMAGE),
            &mut *core::ptr::addr_of_mut!(L3_IMAGE),
        )
    };

    // ── L1: 1 GiB per entry, 39-bit VA (512 entries). ──────────────────────────────────────────
    //
    // ★ **A2's whole scope decision is these five lines, and it is per-entry on purpose** — a rule a
    // reader can check against the table by eye, with no derived boundary to drift:
    //
    // [0]   0x0000_0000 device MMIO — GICD, GICR, UART, SMMU, virtio, PCIe MMIO. **Device, always.**
    // [1]   0x4000_0000 the DRAM this image and its guests occupy -> L2. **A2's Normal-WB region.**
    // [2]   0x8000_0000 an ADDRESSABILITY window — `DATA_IPA_BASE` read as a PA by the DMA witness
    // [3]   0xC000_0000 likewise, `SUP_IPA_BASE`
    // [256] 0x40_1000_0000 ECAM. Needs 39 bits of VA, which is why T0SZ is 25 and not 32.
    //
    // ⚠ **[2] and [3] stay Device-nGnRnE, and the reason is not conservatism.** They exist so EL2
    // can *form* addresses in the model's IPA space, not because DRAM is known to be there: [2] is
    // backed only when the boot line passes `-m 2048` (the linker script says so), and [3] is above
    // that. **Normal memory may be accessed SPECULATIVELY; Device memory may not.** Mapping an
    // unbacked gigabyte Normal-WB would invite speculative reads of nothing, which on QEMU is
    // invisible and on silicon is an external abort with no faulting instruction to blame it on.
    l1.0[0] = block(0x0000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[1] = core::ptr::from_ref(l2) as u64 | DESC_TABLE;
    l1.0[2] = block(0x8000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[3] = block(0xC000_0000, ATTRIDX_DEVICE, AP_RW, XN);
    l1.0[256] = block(0x40_0000_0000, ATTRIDX_DEVICE, AP_RW, XN);

    // ── L2 under L1[1]: 2 MiB per entry. Entry 0 is a table (the image's text/rodata live there);
    //    the rest are Normal-WB Inner-Shareable RW blocks covering `.bss`, both stacks, all three
    //    guest windows and the rest of DRAM up to 0x8000_0000. ──────────────────────────────────
    //
    // ★ **This loop is where A2 actually happens.** Everything the hypervisor keeps at runtime is
    // here — `STAGE2_SETS`, the SMMU's stream table and both its queues, the heap, the DMA witness's
    // sentinels — and all of it was Device-nGnRnE until this rung. The obligations that creates are
    // enumerated in the module doc; the three that are *silent* when unmet are `smmu::publish`,
    // `smmu::take_event` and `dmawitness::sentinel`.
    l2.0[0] = core::ptr::from_ref(l3) as u64 | DESC_TABLE;
    for i in 1..ENTRIES {
        let pa = 0x4000_0000 + (i as u64) * BLOCK_2M;
        l2.0[i] = block(pa, ATTRIDX_NORMAL_WB, AP_RW, XN);
    }

    // ── L3 under L2[0]: 4 KiB pages over 0x4000_0000..0x4020_0000. The ONLY place permissions
    //    vary, and the reason the linker script page-aligns its boundaries. ──────────────────────
    for i in 0..ENTRIES {
        let va = 0x4000_0000 + (i as u64) * PAGE;
        let desc = if va >= text_start && va < text_end {
            // Executable and read-only, and **still Normal-NON-cacheable after A2** — because
            // `SCTLR_EL2.I` is still 0, which forces instruction fetch Non-cacheable whatever this
            // descriptor says. Mapping it Write-Back would make the descriptor describe something
            // the hardware does not do, and would put this crate's "zero `ic` instructions"
            // invariant in play for no benefit. A2 moved the data axis; this is the other one.
            page(va, ATTRIDX_NORMAL_NC, AP_RO, 0)
        } else if va >= rodata_start && va < rodata_end {
            page(va, ATTRIDX_NORMAL_WB, AP_RO, XN)
        } else {
            page(va, ATTRIDX_NORMAL_WB, AP_RW, XN)
        };
        l3.0[i] = desc;
    }
}

/// `TCR_EL2`, non-VHE format (a single `TTBR0_EL2`, no `TTBR1`).
///
/// `T0SZ = 25` gives a 39-bit VA — chosen because ECAM sits at `0x40_1000_0000` and a 32-bit space
/// would not reach it.
///
/// ★★ **A2 changed the walk attributes to Write-Back Inner-Shareable, and NOT changing them would
/// have re-created, one level down, the very mismatch A2 exists to remove.** They used to be
/// Non-cacheable/Non-shareable, "matching the world the tables were written in: EL2 wrote them with
/// the MMU off, so they went straight to DRAM". That was exactly right under A1. Under A2 the three
/// tables live in `.bss`, which `build_tables` now maps **Normal-WB Inner-Shareable** — so a
/// Non-cacheable walker would be a second agent reading, uncached, memory EL2's own data accesses
/// hold in cache. That is a mismatched alias on the same physical addresses, which is the same
/// defect class as the `VTCR_EL2` one (`SH_INNER_SHAREABLE`) and not a smaller one.
///
/// The transition is safe in the direction it has to be: the tables are written *before* `SCTLR_EL2`
/// is touched, so those stores are still Device-nGnRnE and land in DRAM, and a Write-Back walker
/// that misses simply fetches them from there.
const fn tcr_el2() -> u64 {
    const T0SZ: u64 = 25;
    /// `IRGN0[9:8] = 0b01` — inner Write-Back Read-Allocate Write-Allocate Cacheable.
    const IRGN0_WB: u64 = 0b01 << 8;
    /// `ORGN0[11:10] = 0b01` — outer Write-Back Read-Allocate Write-Allocate Cacheable.
    const ORGN0_WB: u64 = 0b01 << 10;
    /// `SH0[13:12] = 0b11` — Inner Shareable, the domain `VTCR_EL2.SH0` already names.
    const SH0_INNER_SHAREABLE: u64 = 0b11 << 12;
    const TG0_4K: u64 = 0b00 << 14;
    /// `PS[18:16] = 0b010` — 40-bit physical addresses, the same size `hv_s2`'s stage-2 regime uses.
    const PS_40BIT: u64 = 0b010 << 16;
    /// Bits 31 and 23 are **RES1** in the non-VHE `TCR_EL2`. Omitting them is the same class of
    /// error as writing `SCTLR_EL2` whole: it passes where the model does not enforce RES1 and is
    /// wrong where the hardware does.
    const RES1: u64 = (1 << 31) | (1 << 23);
    T0SZ | IRGN0_WB | ORGN0_WB | SH0_INNER_SHAREABLE | TG0_4K | PS_40BIT | RES1
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
    // bug would pass here and be wrong on silicon.
    //
    // ★★ **`M` and `C` are set in ONE write, and that is A2's ordering requirement, not a
    // shortcut.** Between setting `M` and setting `C` the mapping already says Normal-WB while
    // `SCTLR_EL2.C == 0` forces every data access Non-cacheable — the descriptors and the behaviour
    // disagree, and any store made in that window (a spill, an interrupt frame) goes to DRAM under
    // an address the very next instruction may read back through a cache. Setting both at once means
    // that window does not exist. It also means there is no build in which the tables are A2's and
    // the cache bit is A1's, which is precisely the "attributes without the rest of the rung"
    // configuration the roadmap forbids splitting into.
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
            "orr {tmp}, {tmp}, {mc}",
            "msr sctlr_el2, {tmp}",
            "isb",
            "mrs {out}, sctlr_el2",
            mair = in(reg) MAIR_EL2_VALUE,
            tcr  = in(reg) tcr_el2(),
            ttbr = in(reg) ttbr,
            mc   = in(reg) el2::SCTLR_EL2_M | el2::SCTLR_EL2_C,
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

/// The L3 descriptor covering `va`, if `va` is inside the 4 KiB-mapped region.
///
/// Gated to `xn-probe` because that is its only consumer: the boot-time verdict uses the
/// whole-range [`coverage`] sweep, and this single-address lookup exists solely so the execute-never
/// probe can confirm the page it is about to jump into really is mapped `XN`.
#[cfg(feature = "xn-probe")]
fn l3_descriptor(va: u64) -> Option<u64> {
    if !(0x4000_0000..0x4020_0000).contains(&va) {
        return None;
    }
    // SAFETY: a shared reference to a table written once before the MMU was enabled and never
    // mutated after; this runs afterwards, so no `&mut` to it is live.
    let l3 = unsafe { &*core::ptr::addr_of!(L3_IMAGE) };
    Some(l3.0[((va - 0x4000_0000) / PAGE) as usize])
}

/// Whether one specific `va` is mapped execute-never — the [`xn_probe`]'s self-validation.
///
/// ⚠ Not the boot-time check. [`coverage`] is, and it sweeps every page; this answers the narrower
/// question "is the address I am about to jump into actually `XN`", without which a fault would be
/// consistent with having jumped somewhere else entirely.
#[cfg(feature = "xn-probe")]
pub(crate) fn is_execute_never(va: u64) -> bool {
    l3_descriptor(va).is_some_and(|d| d & 0b11 == DESC_PAGE && d & XN != 0)
}

/// What a sweep of the whole 4 KiB-mapped range found: how many pages fell in each permission
/// region, and whether every one of them carried the permissions that region requires.
#[derive(Clone, Copy)]
pub(crate) struct Coverage {
    pub(crate) text_pages: usize,
    pub(crate) rodata_pages: usize,
    pub(crate) rw_pages: usize,
    /// `L2` blocks carrying Normal-WB Inner-Shareable — **A2's region**, counted because this is the
    /// memory the rung actually changed and nothing used to look at it at all.
    pub(crate) wb_blocks: usize,
    /// `L1` entries carrying Device-nGnRnE — MMIO and the two unbacked addressability windows.
    /// Counted for the same reason in the other direction: A2 must not have made these cacheable.
    pub(crate) device_gib: usize,
    /// Every descriptor at every level matched what its region requires.
    pub(crate) ok: bool,
}

/// **Check EVERY page in the mapped range against the region it belongs to.**
///
/// ## ⚠ Why this replaced two single-address checks
///
/// The first version of this rung claimed **W^X over three ranges** and tested **one address each**:
/// `text_is_read_only()` read the descriptor for `__text_start`, `data_is_execute_never()` the one
/// for `__rodata_end`, and the two boot probes faulted at one address apiece. Four checks, four
/// addresses, three ranges.
///
/// ★ **An off-by-one at `__text_end` would have left the last page of text WRITABLE and nothing
/// would have noticed** — not the read-backs, not the probes, not the gates. That is the same shape
/// as every other defect this rung produced: coverage narrower than the claim. A range is not
/// witnessed by a point inside it.
///
/// So this sweeps all [`ENTRIES`] descriptors and classifies each by the region its VA falls in.
/// The counts are returned as well as the verdict, because a mis-sized region is a *wrong count*
/// long before it is a wrong permission — `text_pages == 0` would mean the text range collapsed,
/// and a point-check at `__text_start` would still pass.
///
/// ## ★★ Why A2 had to widen it again — from one level to three, and from permissions to attributes
///
/// Under A1 this checked `L3`'s permissions and nothing else, and that was *sufficient*, because
/// `SCTLR_EL2.C == 0` forced every data access Non-cacheable whatever any descriptor said. The
/// memory type could not be got wrong in a way that mattered, and `L1`/`L2` carried no permission
/// variation worth sweeping.
///
/// **A2 removed both of those.** It cleared the backstop, and it put the change it makes in the two
/// levels this function never looked at: `L2`'s blocks are `.bss`, the stacks and all three guest
/// windows, and `L1`'s entries are what must have stayed Device. So the sweep now checks, at every
/// level, the **memory type and shareability** as well as the permissions — otherwise A2's central
/// change would be the one thing in this module with no witness, which is the shape of every defect
/// this function has already been widened for.
///
/// Shareability is checked rather than assumed even though [`shareability`] derives it, because this
/// reads back the *descriptors the hardware will walk*; a check that re-derived the value from the
/// same function would agree with itself and with nothing else.
pub(crate) fn coverage() -> Coverage {
    let text_start = sym(core::ptr::addr_of!(__text_start));
    let text_end = sym(core::ptr::addr_of!(__text_end));
    let rodata_start = sym(core::ptr::addr_of!(__rodata_start));
    let rodata_end = sym(core::ptr::addr_of!(__rodata_end));

    // SAFETY: shared references to tables written once, before the MMU was enabled, and never
    // mutated after; this runs afterwards, so no `&mut` to them is live.
    let (l1, l2, l3) = unsafe {
        (
            &*core::ptr::addr_of!(L1),
            &*core::ptr::addr_of!(L2_IMAGE),
            &*core::ptr::addr_of!(L3_IMAGE),
        )
    };

    let mut c = Coverage {
        text_pages: 0,
        rodata_pages: 0,
        rw_pages: 0,
        wb_blocks: 0,
        device_gib: 0,
        ok: true,
    };

    // ── L1: exactly the five entries `build_tables` writes, and nothing else. ──────────────────
    //
    // The four Device gigabytes are checked BY INDEX rather than by "everything that is not a
    // table", so an entry that silently became something else — a sixth mapping, a block where the
    // table should be — fails rather than being classified into whichever arm it happens to match.
    for (i, &desc) in l1.0.iter().enumerate() {
        let want = match i {
            0 | 2 | 3 | 256 => {
                c.device_gib += 1;
                desc & 0b11 == DESC_BLOCK
                    && desc & ATTRIDX_MASK == ATTRIDX_DEVICE
                    && desc & (0b11 << 6) == AP_RW
                    && desc & XN != 0
            }
            1 => desc & 0b11 == DESC_TABLE,
            _ => desc == 0,
        };
        c.ok &= want;
    }

    // ── L2: entry 0 is the table that carries the image's finer permissions; every other entry is
    //    A2's Normal-WB Inner-Shareable RW+XN block. ─────────────────────────────────────────────
    for (i, &desc) in l2.0.iter().enumerate() {
        let want = if i == 0 {
            desc & 0b11 == DESC_TABLE
        } else {
            c.wb_blocks += 1;
            desc & 0b11 == DESC_BLOCK
                && desc & ATTRIDX_MASK == ATTRIDX_NORMAL_WB
                && desc & SH_MASK == SH_INNER_SHAREABLE
                && desc & (0b11 << 6) == AP_RW
                && desc & XN != 0
        };
        c.ok &= want;
    }

    // ── L3: the image's own pages, where permissions AND memory type both vary. ────────────────
    for (i, &desc) in l3.0.iter().enumerate() {
        let va = 0x4000_0000 + (i as u64) * PAGE;
        let ap = desc & (0b11 << 6);
        let xn = desc & XN != 0;
        let is_page = desc & 0b11 == DESC_PAGE;
        let attr = desc & ATTRIDX_MASK;
        let sh = desc & SH_MASK;

        // Executable and read-only; XN must NOT be set or the text would not be fetchable. And
        // Normal-NON-cacheable, which is not a leftover: `SCTLR_EL2.I` is still 0, so an
        // instruction fetch is Non-cacheable regardless, and a Write-Back descriptor here would
        // describe something the hardware does not do.
        let want = if va >= text_start && va < text_end {
            c.text_pages += 1;
            is_page && ap == AP_RO && !xn && attr == ATTRIDX_NORMAL_NC && sh == SH_NON_SHAREABLE
        } else if va >= rodata_start && va < rodata_end {
            c.rodata_pages += 1;
            is_page && ap == AP_RO && xn && attr == ATTRIDX_NORMAL_WB && sh == SH_INNER_SHAREABLE
        } else {
            c.rw_pages += 1;
            is_page && ap == AP_RW && xn && attr == ATTRIDX_NORMAL_WB && sh == SH_INNER_SHAREABLE
        };
        c.ok &= want;
    }

    // A collapsed region passes every per-page test vacuously, so the counts are part of the
    // verdict rather than decoration: text and rodata are non-empty by construction of the link,
    // and the two whole-level counts are fixed by `build_tables` rather than by the link.
    c.ok &= c.text_pages > 0 && c.rodata_pages > 0 && c.rw_pages > 0;
    c.ok &= c.wb_blocks == ENTRIES - 1 && c.device_gib == 4;
    c
}

/// Whether `SCTLR_EL2.C` is **set** — the bit A2 turned on, and the reason the sweep above had to
/// grow to cover every level.
///
/// ⚠ **This used to be `data_cache_still_off`, and it asserted the exact opposite.** With `C == 0`
/// every data access to Normal memory is forced Non-cacheable *regardless of the descriptors*, which
/// made "nothing became cacheable" true even if this module had a bug — a structural backstop A1
/// leaned on deliberately. **A2 retired that backstop**, so descriptor correctness is now
/// load-bearing, which is why [`coverage`] audits all three levels instead of only `L3`'s
/// permissions.
///
/// ★ Checked, and named after the state it asserts rather than after a direction of change: a
/// predicate called `still_off` that returns `sctlr & C != 0` would read as a lie at every call
/// site, and a boot line that printed `C=0` while `C` was 1 is precisely the failure this rung had
/// to go looking for in `boot-test.sh` (see `main`'s report).
pub(crate) fn data_cache_on(sctlr: u64) -> bool {
    sctlr & el2::SCTLR_EL2_C != 0
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

/// A page of `.bss` used only as the execute-never probe's target. In the RW+XN region by
/// construction — `.bss` starts well past `__rodata_end`.
#[cfg(feature = "xn-probe")]
static mut XN_PROBE_SLOT: [u32; 2] = [0; 2];

/// **The X half of W^X: jump into EL2's own data and require the hardware to refuse.**
///
/// ## Why this is a separate boot from the W probe
///
/// Both faults are terminal — vector 4 reports and halts — so only one can run per boot. They are
/// two configurations, not two phases.
///
/// ## ATTRIBUTION — predicted over-determined, MEASURED not, and A2 then removed the confound
///
/// Under A1, EL2's data pages were `Device-nGnRnE` **and** `XN`, and Arm prohibits instruction fetch
/// from Device memory *independently of* `XN`. So this fault looked like it would be
/// over-determined — witnessing the property ("EL2's data is not executable") without attributing
/// which mechanism refused, the inputs-cannot-discriminate shape this project keeps finding.
///
/// ★ **Probed rather than assumed, and the prediction was wrong: mapping the page `Device-nGnRnE`
/// with `XN` CLEARED, the jump SUCCEEDS.** QEMU/TCG does not model the Device-memory instruction
/// fetch prohibition, so on that platform **`XN` alone is what refuses**, and the witness was sharp
/// rather than confounded.
///
/// ⚠ **That was a QEMU FIDELITY fact, not an architectural one**, and it carried the caveat that on
/// silicon the property would be doubly held and this probe would no longer isolate `XN`.
///
/// ★★ **A2 retired the caveat by removing its premise: this page is now Normal Write-Back, not
/// Device.** The Device-memory fetch prohibition does not apply to Normal memory on any
/// implementation, so `XN` is the only mechanism that can refuse — **on QEMU and on silicon alike**.
/// The attribution stopped depending on the model's fidelity, which is a strictly better standing
/// than the one this probe was written with, and it is a side effect of a rung about caches.
///
/// The probe self-validates before jumping: it reads the descriptor back and refuses to run if the
/// page it is about to jump into is not actually mapped `XN`. Without that, "it faulted" would be
/// consistent with having jumped somewhere else entirely.
#[cfg(feature = "xn-probe")]
pub(crate) fn xn_probe(uart: &mut crate::pl011::Pl011) {
    use core::fmt::Write;

    let slot = core::ptr::addr_of_mut!(XN_PROBE_SLOT) as u64;
    if !is_execute_never(slot) {
        let _ = writeln!(
            uart,
            "baleen: XN probe ABORTED — 0x{slot:08x} is not mapped execute-never; nothing to test"
        );
        crate::park();
    }

    // `ret` (0xd65f03c0). If the fetch is permitted, this returns cleanly and execution continues to
    // the failure report below — the same fail-loud shape the W probe uses.
    //
    // ⚠ **A2 made the publication real, and it is the FAILURE path that needs it.** This used to be
    // a bare `dsb`+`isb`, justified as "meaningful only because `SCTLR_EL2.I == 0` and the page is
    // non-cacheable, so there is no I-cache to maintain". Under A2 the page is Normal Write-Back, so
    // these two stores sit in the data cache while instruction fetch — still Non-cacheable, `I` is
    // unchanged — would read DRAM. If the mapping were wrong and the fetch were PERMITTED, it would
    // execute whatever DRAM held instead of the `ret` this probe put there, and the fail-loud shape
    // would become fail-arbitrary. `cache::clean` (`DC CVAC`, to the point of coherency, which is at
    // or beyond the point of unification) is what makes the bytes the ones that would run.
    //
    // No `IC` is needed and the crate's "zero `ic` instructions" invariant survives: an instruction
    // cache can hold no line for this address, because the page is `XN` and has never been fetched
    // from — which the `is_execute_never` check above has just confirmed.
    //
    // SAFETY: `XN_PROBE_SLOT` is a static this probe exclusively owns, in the RW+XN region. The
    // stores are ordinary data writes.
    unsafe {
        core::ptr::write_volatile(slot as *mut u32, 0xd65f_03c0);
        core::ptr::write_volatile((slot + 4) as *mut u32, 0xd65f_03c0);
    }
    crate::cache::clean(slot, core::mem::size_of::<[u32; 2]>() as u64);
    // SAFETY: barrier instructions; no memory operand, no privilege requirement at EL2.
    unsafe {
        asm!("dsb sy", "isb", options(nostack, preserves_flags));
    }

    let _ = writeln!(
        uart,
        "baleen: XN probe: jumping into EL2 data at 0x{slot:08x} — the hardware must refuse"
    );

    // SAFETY: transmuting a data address to a function pointer and calling it is EXPECTED to fault.
    // If it does not, the target holds `ret`, so control returns here and the failure is reported
    // rather than running off into arbitrary bytes.
    unsafe {
        let f: extern "C" fn() = core::mem::transmute::<u64, extern "C" fn()>(slot);
        f();
    }

    let _ = writeln!(
        uart,
        "baleen: XN NOT ENFORCED — the jump into EL2 data RETURNED"
    );
    crate::park();
}

/// The size, in bytes, of the region mapped read-only and executable — reported so the boot witness
/// states what it protected rather than merely that it protected something.
pub(crate) fn text_span() -> (u64, u64) {
    (
        sym(core::ptr::addr_of!(__text_start)),
        sym(core::ptr::addr_of!(__text_end)),
    )
}
