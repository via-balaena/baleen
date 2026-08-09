// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The probe's physical address map — **one declaration, checked by the compiler**
//!
//! ## Why this file exists, and it is a defect report
//!
//! Until this file, the probe had no address map. Each milestone picked its own addresses, in its
//! own module, and **three of them overlapped**:
//!
//! | CPU-side cell | SMMU region | overlap |
//! |---|---|---|
//! | m3/m4's cache cell `0x8100_0000` | `ARENA`/`STRTAB` `0x8100_0000` | **exact** — the cache experiment wrote its seed and its "secret" straight onto the stream table |
//! | m5's control cell `0x8200_0000` | `TARGET_A` `0x8200_0000` | **exact** |
//! | m5's Device cell `0x8201_0000` | inside `TARGET_A`'s 2 MiB block | **contained** |
//!
//! **Nothing ever failed**, because the SMMU milestones all complete before `mmu::enable()` and
//! nothing re-reads their structures afterwards. The collisions were invisible for exactly as long
//! as the running order held — which is the definition of a latent defect, and the running order was
//! about to change: the planned milestone 6 asks the SMMU to translate *after* the cache milestones
//! have run, which is what sent anyone looking at the map at all.
//!
//! ⚠ **The lesson is about the SAFETY comment, not the addresses.** m5's read *"neither overlaps the
//! image, its stack, or milestone 3/4's page"* — true as written, and it enumerated the wrong
//! universe. It checked the regions its author was thinking about rather than the regions that
//! exist. A non-overlap claim is only as good as the set it quantified over, so this file makes the
//! set explicit and hands the quantifying to the compiler.
//!
//! ## The map
//!
//! Everything lives in the 1 GiB DRAM block at `0x8000_0000` that `mmu` maps Normal write-back.
//! Regions are declared as `(base, size)` pairs and [`ASSERT_DISJOINT`] rejects any overlap at
//! compile time, so a future milestone cannot quietly reuse an address.

/// `(base, size, name)` for every region the probe claims. **Add a milestone's storage here, not in
/// the milestone.**
///
/// Order is by address so a reader can see the gaps; the disjointness check does not depend on it.
pub const REGIONS: &[(u64, u64, &str)] = &[
    (IMAGE_BASE, IMAGE_SIZE, "image + stack"),
    (SMMU_ARENA, SMMU_ARENA_SIZE, "SMMU tables and queues"),
    (CACHE_CELL, CELL_SIZE, "m3/m4 cache experiment"),
    (ATOMIC_WB_CELL, CELL_SIZE, "m5 control cell (Normal-WB)"),
    (ATOMIC_DEV_CELL, CELL_SIZE, "m5 cell under test (Device)"),
    (SMMU_TARGET_A, SMMU_TARGET_SIZE, "SMMU stage-2 target A"),
    (SMMU_TARGET_B, SMMU_TARGET_SIZE, "SMMU stage-2 target B"),
];

/// Where `link.ld` loads the probe, and where its stack lives.
///
/// The size is a **claim about the linker**, not a measurement: it is the room reserved before the
/// next region, and the image plus its 64 KiB stack is far smaller. It exists so the disjointness
/// check has something to quantify over.
pub const IMAGE_BASE: u64 = 0x8000_0000;
pub const IMAGE_SIZE: u64 = 0x0100_0000;

/// The SMMU's own structures: stream table, command queue, event queue, and two stage-2 table sets.
///
/// The sub-offsets stay in `smmu`, which owns their meaning; this declares the **extent** so nothing
/// else lands inside it. Actual use runs to `+0x06_1000`; the reservation is rounded well past that.
pub const SMMU_ARENA: u64 = 0x8100_0000;
pub const SMMU_ARENA_SIZE: u64 = 0x0010_0000;

/// One 4 KiB page is all any CPU-side cell needs; they are separate pages so a mapping can give each
/// its own attributes.
pub const CELL_SIZE: u64 = 0x1000;

/// Milestone 3/4's cell — the one reached both cacheably and non-cacheably.
///
/// ⚠ **Moved out of [`SMMU_ARENA`] while scoping milestone 6.** It used to be `0x8100_0000`, i.e.
/// the stream table's first bytes.
pub const CACHE_CELL: u64 = 0x8110_0000;

/// Milestone 5's control cell, reached identity as Normal write-back.
///
/// ⚠ **Moved out of [`SMMU_TARGET_A`] while scoping milestone 6.** It used to be `0x8200_0000`.
pub const ATOMIC_WB_CELL: u64 = 0x8111_0000;

/// Milestone 5's cell under test, reached only through its `Device-nGnRnE` alias.
///
/// ⚠ **Moved out of [`SMMU_TARGET_A`]'s 2 MiB block while scoping milestone 6.** It used to be
/// `0x8201_0000`.
pub const ATOMIC_DEV_CELL: u64 = 0x8112_0000;

/// The two physical targets an STE's stage-2 tables can point at. **2 MiB and 2 MiB-aligned**,
/// because the probe maps `TEST_IPA` with a single block descriptor.
pub const SMMU_TARGET_A: u64 = 0x8200_0000;
pub const SMMU_TARGET_B: u64 = 0x8240_0000;
pub const SMMU_TARGET_SIZE: u64 = 0x0020_0000;

/// Whether `[a, a+an)` and `[b, b+bn)` share a byte.
const fn overlaps(a: u64, an: u64, b: u64, bn: u64) -> bool {
    a < b + bn && b < a + an
}

/// Pairwise disjointness over [`REGIONS`], evaluated at compile time.
///
/// ★ **This is the point of the file.** The collisions above were all findable by reading, and were
/// not found by reading — twice, by the same author, one of them while writing a comment that
/// asserted the opposite. A `const` loop cannot be distracted.
const fn all_disjoint() -> bool {
    let mut i = 0;
    while i < REGIONS.len() {
        let mut j = i + 1;
        while j < REGIONS.len() {
            let (a, an, _) = REGIONS[i];
            let (b, bn, _) = REGIONS[j];
            if overlaps(a, an, b, bn) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Fails the build if any two regions overlap.
pub const ASSERT_DISJOINT: () = assert!(
    all_disjoint(),
    "fvp-probe: two regions in `layout::REGIONS` overlap — see the table in the module docs"
);

/// Every 2 MiB-block target must be 2 MiB aligned, or the stage-2 block descriptor `smmu` writes
/// names a different address than the constant does.
pub const ASSERT_TARGETS_ALIGNED: () = assert!(
    SMMU_TARGET_A.is_multiple_of(SMMU_TARGET_SIZE)
        && SMMU_TARGET_B.is_multiple_of(SMMU_TARGET_SIZE),
    "fvp-probe: a stage-2 target is not aligned to its block size"
);
