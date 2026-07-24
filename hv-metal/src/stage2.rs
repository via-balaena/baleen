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
//! - **Guest image** — the code the guest runs from. Identity-mapped (IPA == PA) as one 2 MiB
//!   **read-only + executable** block over the linker's `__guest_ram_*` window. This is
//!   *infrastructure*, not model-driven. For a single-domain phase it is that domain's own private
//!   code; under **concurrent inter-domain isolation** (M5 Arc 2) BOTH domains identity-map the SAME
//!   host frames here — a *shared* code image, so it is mapped **read-only** so it cannot be a
//!   cross-domain write channel (the guest never writes its code; a store here faults loudly). The
//!   isolation surface under test is the per-domain *data* frames below, never this shared image; a
//!   private RW code+stack image per domain is deferred to the real-Linux capstone.
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
//! ## Where the refinement now lives (the factoring)
//!
//! The refinement itself — *which* frames a domain reaches and at what permission, and the
//! descriptor words that expresses — has moved OUT of this crate into [`hv_s2`], a pure `no_std`
//! library under the workspace `unsafe_code = "forbid"` fence: [`hv_s2::leaf_map`] (neutral: the
//! `p2m` relation → a per-frame leaf map) and [`hv_s2::arm64::encode`] (AArch64 descriptor words).
//! It is therefore host-testable, fuzzable, enumerable, and provable, where before it could only be
//! argued (Audit #2) and mutation-tested. What stays here is the **publish**: handing the encoder
//! `&mut` views of the table storage, then the barriers + TLB maintenance + `VTTBR_EL2`
//! ([`crate::guest`]'s `enable_stage2`). The refinement *relation* this module documents above is
//! unchanged — only its implementation site moved, and the boot-test's full isolation matrix is the
//! byte-identity witness that it did.
//!
//! ## Unsafe
//!
//! Two blocks: deriving `&mut` views of the interior-mutable table storage for the encoder (the
//! publish), and the `GuestMem` volatile copies into/out of the reserved data-frame window (EL2 runs
//! MMU-off/identity, so a host PA is directly addressable). Each carries its justification; the
//! tables live behind `UnsafeCell` (never `static mut`), the same discipline as `guest.rs`/`heap.rs`.

use core::cell::UnsafeCell;
use core::fmt::Write;

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
///
/// Delegates to [`hv_s2::arm64::frame_addr`], the single derivation of frame addressing shared with
/// the emitter — so this window can never drift from the one the descriptors are built against.
pub fn frame_ipa(m: Mfn) -> u64 {
    hv_s2::arm64::frame_addr(DATA_IPA_BASE, FRAME_SIZE, m)
}

// (The host PA a model frame is backed at is now derived inside the emitter, from the `Layout` it is
// handed — `hv_s2::arm64::frame_pa`. hv-metal no longer needs its own copy: the one derivation lives
// under the fence, where it is unit-tested.)

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
// The descriptor encodings moved to `hv_s2::arm64::desc` (M5 — the refinement arc): they are pure
// data, so they now live under the workspace `unsafe_code = "forbid"` fence where they are pinned by
// golden tests, instead of inside this crate's `unsafe`. Provenance is unchanged — the Arm ARM
// (VMSAv8-64 Stage-2 descriptor formats), converged three ways per `docs/AUDIT-2-P2M-STAGE2.md`.
// ---------------------------------------------------------------------------------------------

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
/// `L2`, one → the data `1 GiB` region's `L2`), an `L2` for the guest image (a single 2 MiB RO+X
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
/// The guest-image region is mapped as infrastructure (identity 2 MiB RO+X block). The data region is
/// the refinement: for every **leaf** page-table edge whose parent `guest_dom` owns, the leaf's
/// child frame is mapped at [`frame_ipa`] → [`frame_pa`] with the leaf's permission (`writable` →
/// `S2AP=RW`, else `S2AP=RO`, always execute-never). A foreign child appears here only because
/// `p2m_link` already required a grant, so the grant dimension is covered transitively; a frame
/// `guest_dom` may not reach has no leaf edge and so no descriptor — the hardware faults it.
pub fn build_stage2_from_p2m(hv: &Hypervisor, guest_dom: DomId, set: usize) -> u64 {
    // (1) THE REFINEMENT — which frames this domain reaches, at what permission. A pure decision,
    //     made under the workspace `unsafe_code = "forbid"` fence (`hv_s2::leaf_map`), so it is
    //     host-testable and (next arc) provable rather than merely argued. Every slot of `leaves`
    //     is written by the call, so no previous tenant's leaf can survive into this rebuild.
    let mut leaves = [None; hv_s2::arm64::TABLE_ENTRIES];
    if let Err(e) = hv_s2::leaf_map(hv.p2m(), guest_dom, &mut leaves) {
        // A frame the model authorized does not fit the table. Unreachable while the model stays far
        // below `TABLE_ENTRIES`, but the previous emitter dropped such a frame with a bare
        // `continue` — a SILENT under-map (the guest loses memory it is entitled to). Fail loudly.
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: Stage-2 emission: authorized frame {} exceeds table capacity {}; halting",
            e.mfn, e.capacity
        );
        crate::park();
    }

    // (2) THE ENCODING — descriptor values for that decision. Also pure, also under the fence; the
    //     Arm-ARM field layout and its golden values live in `hv_s2::arm64::desc`.
    let tables = &STAGE2_SETS[set];
    let layout = hv_s2::arm64::Layout {
        l1_pa: tables.l1.0.get() as *const u8 as u64,
        l2_code_pa: tables.l2_code.0.get() as *const u8 as u64,
        l2_data_pa: tables.l2_data.0.get() as *const u8 as u64,
        l3_data_pa: tables.l3_data.0.get() as *const u8 as u64,
        guest_image_pa: guest_ram_start(),
        data_ipa_base: DATA_IPA_BASE,
        data_pa_base: data_ram_start(),
        frame_size: FRAME_SIZE,
    };

    // Structural preconditions the encoder silently assumes: the guest-image and data regions must
    // occupy DISTINCT `L1` entries (else one write clobbers the other and a whole region vanishes),
    // and their windows must not overlap (else a domain's private data frames alias the SHARED,
    // read-only code image). Both were argued from the address layout + linker script (Audit #2's
    // composition finding); checked here, so a future layout change cannot reintroduce either
    // silently. Cheap — a handful of comparisons, once per Stage-2 build.
    if let Err(e) = layout.validate() {
        let mut uart = crate::uart();
        let _ = writeln!(uart, "baleen: Stage-2 layout invalid: {e:?}; halting");
        crate::park();
    }

    // (3) THE PUBLISH — the only `unsafe` left in Stage-2 emission: hand the encoder `&mut` views of
    //     the interior-mutable table storage. Everything about *what values* go in the tables is
    //     decided above, in safe code.
    //
    // SAFETY: single-CPU. The tables are rewritten while executing at EL2, where the EL1&0 Stage-2
    // regime performs no walks (no walker observes these stores mid-rebuild), so even though a *prior*
    // phase may have Stage-2 enabled (this fn is called once per phase, not only before the first
    // enable), the rewrite races no translation. `enable_stage2`'s subsequent `dsb`+`tlbi`+`isb`
    // fences the rewrite (and makes these Non-cacheable EL2 stores globally observable) before the
    // next `eret`, so a switched-in domain's walker reads correct, published descriptors. Each table
    // is 4 KiB aligned (`#[repr(align(4096))]`) with exactly `TABLE_ENTRIES` entries, matching the
    // `&mut [u64; TABLE_ENTRIES]` the encoder takes; the four `UnsafeCell`s are distinct storage, so
    // the four `&mut`s never alias.
    unsafe {
        hv_s2::arm64::encode(
            &leaves,
            &layout,
            hv_s2::arm64::Tables {
                l1: &mut *tables.l1.0.get(),
                l2_code: &mut *tables.l2_code.0.get(),
                l2_data: &mut *tables.l2_data.0.get(),
                l3_data: &mut *tables.l3_data.0.get(),
            },
        );
    }

    // (4) Under `selftest`, read the emitted tables BACK and assert they decode to exactly the leaf
    //     map — the ENCODER's half of the refinement, witnessed on the real hardware tables on every
    //     CI boot rather than only on unit-test fixtures. Also pins the shared guest-image block:
    //     read-only (never a cross-domain write channel) and executable (the guest runs from it),
    //     which until now rested on a comment. A witness produced BY the mechanism (design #24(f)).
    #[cfg(feature = "selftest")]
    {
        // SAFETY: the same table storage, borrowed read-only this time; single-CPU and no walker
        // observes it (see the publish block above), so these shared refs alias nothing live.
        let verdict = unsafe {
            hv_s2::arm64::verify_encoding(
                &leaves,
                &layout,
                hv_s2::arm64::TablesRef {
                    l1: &*tables.l1.0.get(),
                    l2_code: &*tables.l2_code.0.get(),
                    l2_data: &*tables.l2_data.0.get(),
                    l3_data: &*tables.l3_data.0.get(),
                },
            )
        };
        let mut uart = crate::uart();
        match verdict {
            Ok(()) => {
                let _ = writeln!(
                    uart,
                    "baleen: selftest: Stage-2 encoding verified (set {set}: tables decode to exactly the authorized leaf map; image block RO+X)"
                );
            }
            Err(e) => {
                let _ = writeln!(
                    uart,
                    "baleen: selftest: Stage-2 ENCODING VIOLATION: {e:?}; halting"
                );
                crate::park();
            }
        }
    }

    hv_s2::arm64::vttbr(layout.l1_pa, set_vmid(set))
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
