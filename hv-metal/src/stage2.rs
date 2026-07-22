// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Real `p2m` → Stage-2 — the proof touches reality (M4 Arc 5)
//!
//! Arc 4 ran a guest behind a *single 2 MiB identity block* — enough to run it, **no isolation
//! content**. Arc 5 (see `docs/ROADMAP.md`, `docs/AUDIT-2-P2M-STAGE2.md`) replaces that block with a
//! faithful translation of the **proven `hv-core` `p2m`** into real AArch64 Stage-2 descriptors, so
//! the hardware faults a guest that touches memory the model says it may not. This module is the
//! whole refinement — the target of **Architecture Audit #2**.
//!
//! ## The refinement relation (audited per dimension in `docs/AUDIT-2-P2M-STAGE2.md`)
//!
//! The `p2m` models *reachability + permission*: a domain `G` may access machine frame `m` iff `m`
//! is a **leaf-mapped child** in a page table `G` owns — freely for its own frames, and for a
//! *foreign* frame only because [`hv_core::Hypervisor`]'s `p2m_link` seam already required a matching
//! **grant** ([`hv_core::p2m::System::link_edges`] surfaces every such edge). The Stage-2 image is a
//! pure function of exactly that relation:
//!
//! > **Stage-2(G) maps IPA(m) → PA(m) at S2AP π  ⟺  `m` is a leaf child of a table `G` owns, at
//! > permission π.** A *writable* leaf → `S2AP=RW`; a *read-only* leaf → `S2AP=RO`; a foreign leaf is
//! > present **only** because a grant authorized it; a frame that is neither → **no descriptor** →
//! > the access faults to EL2.
//!
//! **Honest scope (named for the audit).** The model's leaves are a guest's *Stage-1* page-table
//! entries in the paravirtual worldview; on this HVM/Stage-2 metal we **reinterpret the same
//! authorize/deny relation as Stage-2 reachability**, because the proven property is layer-agnostic
//! (reachability + permission) and Stage-2 is how the metal enforces it for an unmodified guest. The
//! model's *interior-node sharing* (a foreign `L(k-1)` node grant — a shared address-space subtree)
//! is a Stage-1 concept and is **out of Stage-2's refinement scope**; Arc 5 refines the model's
//! **leaf-level frame reachability**. See the audit for the per-dimension verdict.
//!
//! ## The address layout (shared with [`GuestMem`], so both speak the same map)
//!
//! Two disjoint IPA regions keep the isolation surface auditable:
//!
//! - **Guest image** — the code + stack the guest runs from. Identity-mapped (IPA == PA) as one
//!   2 MiB RWX block over the linker's `__guest_ram_*` window. This is *infrastructure*, not
//!   model-driven: it is the guest's own private RAM (no other domain's memory), so mapping it is no
//!   more an isolation hole than a guest reaching its own pages.
//! - **Model data frames** — the isolation surface. Model frame `m` lives at host PA
//!   `__guest_data_start + m*4 KiB` and is mapped by Stage-2 at guest IPA [`DATA_IPA_BASE`]` + m*4 KiB`
//!   — a *distinct* IPA base, so the emitted table performs a real IPA≠PA translation, not an
//!   identity pass-through. A frame authorized as a leaf gets an `L3` page descriptor at its model
//!   permission; an unauthorized frame's `L3` slot stays zero (a translation-fault hole).
//!
//! ## The QEMU-vs-metal line (design-lesson #23; `docs/QEMU-AND-METAL.md`)
//!
//! QEMU/TCG models Stage-2 translation and fault semantics **faithfully** for CPU-initiated accesses
//! (read/write/execute/foreign) — `docs/QEMU-AND-METAL.md` names the negative-isolation test *the
//! single most valuable test QEMU can run*. It stays blind to timing, weak-memory ordering, and
//! DMA/SMMU — none of which Arc 5 tests. The descriptor-write barrier + TLB maintenance
//! ([`crate::guest`]'s `enable_stage2`) is load-bearing on silicon and invisible-but-correct under
//! TCG, as in Arc 4.
//!
//! ## Unsafe
//!
//! Building the Stage-2 tables (raw writes into linker-reserved, 4 KiB-aligned table storage) and the
//! `GuestMem` volatile copies into/out of the reserved data-frame window (EL2 runs MMU-off/identity,
//! so a host PA is directly addressable). Each block carries its justification; the tables live
//! behind `UnsafeCell` (never `static mut`), the same discipline as `guest.rs`/`heap.rs`.

use core::cell::UnsafeCell;

use hv_core::hypervisor::DomId;
use hv_core::p2m::Mfn;
use hv_core::Hypervisor;
use hv_hal::{Gpa, GuestMemory, MemError};

// ---------------------------------------------------------------------------------------------
// Address layout — the single map the Stage-2 builder AND `GuestMem` both derive from.
// ---------------------------------------------------------------------------------------------

/// Base guest **IPA** of the model-data-frame region. Deliberately distinct from the host PA the
/// frames are backed at (`__guest_data_start`), so the emitted Stage-2 does a real IPA→PA
/// translation rather than an identity pass-through — the negative test then faults an *unmapped
/// IPA*, not merely "nothing at this address." 2 MiB-aligned (its own Stage-2 `L2` region) and
/// `2 GiB` so it sits in a different `L1` entry from the guest image at `0x4000_0000`.
pub const DATA_IPA_BASE: u64 = 0x8000_0000;

/// Bytes per machine frame — the 4 KiB Stage-2 leaf granule.
pub const FRAME_SIZE: u64 = 0x1000;

/// The guest IPA a model frame `m` is mapped at (whether or not it is authorized — the guest probes
/// this address; a hole faults). `m` also indexes the `L3` data table, so `m` must be `< 512`.
pub fn frame_ipa(m: Mfn) -> u64 {
    DATA_IPA_BASE + m as u64 * FRAME_SIZE
}

/// The host PA a model frame `m` is backed at, inside the linker's reserved data window.
pub fn frame_pa(m: Mfn) -> u64 {
    data_ram_start() + m as u64 * FRAME_SIZE
}

extern "C" {
    static __guest_ram_start: u8;
    static __guest_data_start: u8;
    static __guest_data_end: u8;
}

fn guest_ram_start() -> u64 {
    core::ptr::addr_of!(__guest_ram_start) as u64
}
fn data_ram_start() -> u64 {
    core::ptr::addr_of!(__guest_data_start) as u64
}
fn data_ram_end() -> u64 {
    core::ptr::addr_of!(__guest_data_end) as u64
}

/// Number of independent per-domain Stage-2 table sets the metal can hold live at once. Two, for the
/// M5 Arc-2 concurrent-inter-domain-isolation test (two domains, each its own set + VMID); the
/// single-domain phases (Arc 0/5 isolation + lifecycle, Arc 1 scheduler) all use [`set`] `0`.
pub const NUM_STAGE2_SETS: usize = 2;

/// The `VMID` a Stage-2 set is tagged with — **`set + 1`**, stamped into `VTTBR_EL2[55:48]`. Distinct
/// per set (set 0 → VMID 1, set 1 → VMID 2) so two domains' TLB entries are VMID-tagged and cannot
/// alias — which is exactly what makes a context switch between them sound with **no `tlbi`** (M5
/// Arc 2). Nonzero to distinguish from the "no VMID" default; 8-bit, since `VTCR_EL2.VS=0`. The
/// single-domain callers on set 0 keep VMID 1, unchanged from Arc 1's `GUEST_VMID`.
pub const fn set_vmid(set: usize) -> u64 {
    set as u64 + 1
}

// ---------------------------------------------------------------------------------------------
// AArch64 Stage-2 descriptor encodings (4 KiB granule). Re-derived independently from the Arm ARM
// (VMSAv8-64 Stage-2 descriptor formats + the S2AP/MemAttr/SH/AF/XN fields) by a spec-blind auditor
// and converged (see `docs/AUDIT-2-P2M-STAGE2.md`); QEMU is the third oracle (a wrong permission =
// the guest either faults where it should not, or reaches what it should not).
// ---------------------------------------------------------------------------------------------
mod desc {
    /// Table descriptor low bits (`0b11`) — an `L1`/`L2` entry pointing at the next table. Rest is
    /// the next-table PA in bits [47:12].
    pub const TABLE: u64 = 0b11;
    /// A **page** descriptor's low bits (`0b11`) — a valid `L3` (4 KiB) leaf. (At `L3` the `0b01`
    /// "block" encoding is reserved/invalid; a leaf is `0b11`.)
    pub const PAGE: u64 = 0b11;
    /// A **block** descriptor's low bits (`0b01`) — a valid `L2` (2 MiB) leaf / superpage.
    pub const BLOCK: u64 = 0b01;

    /// Next-table / 4 KiB-page output-address mask (bits [47:12]).
    pub const ADDR_4K: u64 = 0x0000_ffff_ffff_f000;
    /// 2 MiB-block output-address mask (bits [47:21]).
    pub const ADDR_2M: u64 = 0x0000_ffff_ffe0_0000;

    /// Leaf lower attributes shared by every mapping we emit: `MemAttr=0b1111` (Stage-2 Normal
    /// Inner+Outer Write-Back cacheable, bits [5:2]), `SH=0b11` (Inner Shareable, bits [9:8]),
    /// `AF=1` (bit 10, else the first access faults). S2AP and the descriptor type are OR'd on per
    /// mapping.
    pub const LEAF_COMMON: u64 = (0b1111 << 2) | (0b11 << 8) | (1 << 10);

    /// `S2AP=0b11` (bits [7:6]) — read/write.
    pub const S2AP_RW: u64 = 0b11 << 6;
    /// `S2AP=0b01` (bits [7:6]) — read-only (a guest *write* to it faults with a permission fault).
    pub const S2AP_RO: u64 = 0b01 << 6;

    /// Execute-never for a Stage-2 leaf. Bit 54 is `XN` (the `XN[1]` of the `XN[1:0]` field when
    /// `FEAT_XNX` is present); setting it makes the page execute-never at EL1&0. Data frames get it
    /// (they are not code); the guest-image block does not (the guest fetches from it).
    pub const XN: u64 = 1 << 54;

    /// The guest-image block: 2 MiB, RWX, Normal WB IS — identity-mapping the guest's own code+stack.
    /// Equals Arc 4's `0x7FD` (block | Normal WB | S2AP=RW | SH=IS | AF) — kept bit-identical so the
    /// infra mapping is unchanged from the proven-good Arc-4 value.
    pub const BLOCK_RWX: u64 = BLOCK | LEAF_COMMON | S2AP_RW;

    /// A 4 KiB data leaf, read/write, execute-never.
    pub const PAGE_RW: u64 = PAGE | LEAF_COMMON | S2AP_RW | XN;
    /// A 4 KiB data leaf, read-only, execute-never.
    pub const PAGE_RO: u64 = PAGE | LEAF_COMMON | S2AP_RO | XN;
}

/// A 4 KiB Stage-2 translation table (512 × 8-byte descriptors), interior-mutable so it is built at
/// runtime without a `static mut`. `#[repr(C, align(4096))]`: the walk hardware requires a 4 KiB
/// aligned base.
#[repr(C, align(4096))]
struct Table(UnsafeCell<[u64; 512]>);

// SAFETY: single-CPU bring-up (only the boot CPU runs; secondaries stay PSCI-parked in `_start`).
// Each table is written once, before Stage-2 is enabled, then read only by the walk hardware. No two
// accesses race. Same discipline as `guest.rs`'s and `heap.rs`'s interior-mutable statics.
unsafe impl Sync for Table {}

/// One complete per-domain Stage-2 table set: an `L1` (one entry → the guest-image `1 GiB` region's
/// `L2`, one → the data `1 GiB` region's `L2`), an `L2` for the guest image (a single 2 MiB RWX
/// block), an `L2` for the data region (→ `L3`), and an `L3` for the data region (one 4 KiB page
/// descriptor per authorized model frame; the rest stay zero → translation-fault holes). Each domain
/// under concurrent isolation (M5 Arc 2) gets its own set, reached via a distinct VMID-tagged VTTBR.
struct Stage2Set {
    l1: Table,
    l2_code: Table,
    l2_data: Table,
    l3_data: Table,
}

/// The [`NUM_STAGE2_SETS`] independent per-domain table sets. Set 0 is the sole set the single-domain
/// phases use (byte-identical to Arc 1's single table set); set 1 is the second domain's, used only by
/// the Arc-2 concurrent-isolation phase. Distinct storage per set, so building one domain's Stage-2
/// never touches another's. Each set is built via an inline `const` block (an all-zero, interior-mutable
/// `Table` per level) — the same idiom as `guest.rs`'s `FAULT_DFSC` array, so no named
/// interior-mutable const is declared.
static STAGE2_SETS: [Stage2Set; NUM_STAGE2_SETS] = [const {
    Stage2Set {
        l1: Table(UnsafeCell::new([0; 512])),
        l2_code: Table(UnsafeCell::new([0; 512])),
        l2_data: Table(UnsafeCell::new([0; 512])),
        l3_data: Table(UnsafeCell::new([0; 512])),
    }
}; NUM_STAGE2_SETS];

/// Build the Stage-2 tables for `guest_dom` from the proven `p2m` into table `set`, and return the
/// `VTTBR_EL2` value (the set's `L1` table PA | its VMID = [`set_vmid`]`(set)`). Idempotent: every used
/// table slot is written afresh.
///
/// `set` selects which of the [`NUM_STAGE2_SETS`] independent table sets to emit into (and thus which
/// VMID the returned VTTBR carries). Single-domain phases pass `set 0`; the Arc-2 concurrent-isolation
/// phase emits each of its two domains into its own set (0 and 1 → VMID 1 and 2). Because the sets are
/// disjoint storage, building one domain's Stage-2 leaves the other domain's tables untouched — the
/// two live simultaneously, distinguished by VMID with no flush between them.
///
/// The guest-image region is mapped as infrastructure (identity 2 MiB RWX block). The data region is
/// the refinement: for every **leaf** page-table edge whose parent `guest_dom` owns, the leaf's
/// child frame is mapped at [`frame_ipa`] → [`frame_pa`] with the leaf's permission (`writable` →
/// `S2AP=RW`, else `S2AP=RO`, always execute-never). A foreign child appears here only because
/// `p2m_link` already required a grant, so the grant dimension is covered transitively; a frame
/// `guest_dom` may not reach has no leaf edge and so no descriptor — the hardware faults it.
pub fn build_stage2_from_p2m(hv: &Hypervisor, guest_dom: DomId, set: usize) -> u64 {
    let tables = &STAGE2_SETS[set];
    let l1 = tables.l1.0.get();
    let l2_code = tables.l2_code.0.get();
    let l2_data = tables.l2_data.0.get();
    let l3_data = tables.l3_data.0.get();

    let l1_pa = l1 as *const u8 as u64;
    let l2_code_pa = l2_code as *const u8 as u64;
    let l2_data_pa = l2_data as *const u8 as u64;
    let l3_data_pa = l3_data as *const u8 as u64;

    // The guest image sits at its linker address (identity IPA==PA); the data region at DATA_IPA_BASE.
    let ram = guest_ram_start();
    let code_l1 = ((ram >> 30) & 0x1ff) as usize;
    let code_l2 = ((ram >> 21) & 0x1ff) as usize;
    let data_l1 = ((DATA_IPA_BASE >> 30) & 0x1ff) as usize;
    let data_l2 = ((DATA_IPA_BASE >> 21) & 0x1ff) as usize;

    // SAFETY: single-CPU, one-time initialization before Stage-2 is enabled; every table is 4 KiB
    // aligned (`#[repr(align(4096))]`) with 512 entries, so all indices below are in range. The two
    // regions occupy distinct `L1` entries (guest image at `0x4000_0000` → index 1, data at
    // `0x8000_0000` → index 2), so the two `L1` writes never collide.
    unsafe {
        // Guest image: identity 2 MiB RWX block (infrastructure — the guest's own code+stack).
        (*l1)[code_l1] = (l2_code_pa & desc::ADDR_4K) | desc::TABLE;
        (*l2_code)[code_l2] = (ram & desc::ADDR_2M) | desc::BLOCK_RWX;

        // Data region: L1 → L2 → L3, with the L3 leaves emitted from the model below.
        (*l1)[data_l1] = (l2_data_pa & desc::ADDR_4K) | desc::TABLE;
        (*l2_data)[data_l2] = (l3_data_pa & desc::ADDR_4K) | desc::TABLE;

        // Clear any prior L3 leaves so a rebuild is a faithful snapshot of the current p2m (no stale
        // mapping survives). Only the low slots the model can use need clearing (Mfn < frame_count).
        for slot in 0..hv.p2m().frame_count().min(512) {
            (*l3_data)[slot] = 0;
        }

        // The refinement: one 4 KiB leaf per model leaf-edge owned by the guest, at model permission.
        for (parent, _slot, child, writable, leaf) in hv.p2m().link_edges() {
            if !leaf || hv.p2m().owner_of(parent) != Some(guest_dom) {
                continue;
            }
            let idx = child as usize;
            if idx >= 512 {
                continue; // unrepresentable in this single L3 table; the model stays far below it.
            }
            let attrs = if writable {
                desc::PAGE_RW
            } else {
                desc::PAGE_RO
            };
            (*l3_data)[idx] = (frame_pa(child) & desc::ADDR_4K) | attrs;
        }
    }

    l1_pa | (set_vmid(set) << 48)
}

// ---------------------------------------------------------------------------------------------
// `hv_hal::GuestMemory`, realized on ARM (M4 Arc 5) — deferred through Arc 4, landed here exactly as
// Audit #1 named ("accesses through the guest's Stage-2 translation when there is guest memory to
// read/write"). It translates a guest IPA to its host PA through the SAME data-region layout the
// Stage-2 builder emits, then does a direct volatile copy (EL2 runs MMU-off/identity, so a host PA is
// directly addressable). The fence stays neutral: the trait speaks only `Gpa`/bytes — no descriptor
// bit leaks into a signature (the standing constraint from `baleen-arm-target` / Audit #1).
// ---------------------------------------------------------------------------------------------

/// The metal realization of [`hv_hal::GuestMemory`] for the guest's data region.
///
/// Only the model-data-frame window is host-accessible through this map (the guest image is the
/// guest's private code+stack, which the hypervisor has no reason to touch). Access is *unconditional
/// on the guest's S2AP*: this is the trusted hypervisor reading/writing guest memory (e.g. seeding a
/// read-only frame the guest may then only read), not a guest access — permission enforcement is
/// Stage-2's job for the guest, not for the core's own trusted accesses.
pub struct GuestMem;

impl GuestMem {
    /// Translate a guest IPA + length to a host PA, bounds-checked to the reserved data-frame window.
    /// Returns [`MemError::OutOfBounds`] for an IPA outside the window or a span that runs off its
    /// end — the same "outside the guest's physical address space" the trait documents.
    fn ipa_to_pa(gpa: Gpa, len: usize) -> Result<u64, MemError> {
        let end = data_ram_end() - data_ram_start(); // window size in bytes
        let off = gpa
            .checked_sub(DATA_IPA_BASE)
            .ok_or(MemError::OutOfBounds)?;
        let last = off.checked_add(len as u64).ok_or(MemError::OutOfBounds)?;
        if last > end {
            return Err(MemError::OutOfBounds);
        }
        Ok(data_ram_start() + off)
    }
}

impl GuestMemory for GuestMem {
    fn read(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), MemError> {
        let pa = Self::ipa_to_pa(gpa, buf.len())?;
        // SAFETY: `pa` is a bounds-checked address inside the reserved, in-DRAM data window; EL2 runs
        // identity/MMU-off so it is directly addressable. `buf` is a distinct caller slice. Byte copy.
        unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    fn write(&mut self, gpa: Gpa, buf: &[u8]) -> Result<(), MemError> {
        let pa = Self::ipa_to_pa(gpa, buf.len())?;
        // SAFETY: as `read`, with the copy direction reversed — `pa` is the bounds-checked in-window
        // destination, `buf` the caller source. Non-overlapping distinct regions.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), pa as *mut u8, buf.len()) };
        Ok(())
    }
}
