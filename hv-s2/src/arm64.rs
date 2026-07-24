// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # AArch64 Stage-2 encoding — the leaf map as descriptor words
//!
//! The architecture half of the split: take the neutral [`crate::leafmap`] result and produce the
//! actual AArch64 Stage-2 descriptor values. **Pure** — it writes only into caller-provided table
//! slices, touches no hardware, and performs no MMIO. Publishing those tables (the `dsb` /
//! `tlbi` / `isb` and the `VTTBR_EL2` write) stays in `hv-metal`, which is the only place that may
//! hold a raw pointer.
//!
//! ## Provenance
//!
//! The descriptor field layout (`S2AP`, `MemAttr`, `SH`, `AF`, `XN`, the table/block/page type
//! bits, and the output-address masks) is from the **Arm Architecture Reference Manual, VMSAv8-64
//! Stage-2 descriptor formats** — the same encodings `docs/AUDIT-2-P2M-STAGE2.md` converged on
//! three ways (spec-derived code, a spec-blind auditor, and a running QEMU). The values are pinned
//! by golden tests below so a re-encoding can never silently drift.
//!
//! ## The address layout
//!
//! Two disjoint IPA regions, unchanged from the in-metal emitter:
//!
//! - **Guest image** — one identity-mapped 2 MiB block, **read-only + executable**. Infrastructure,
//!   not model-driven: it is the guest's code. Read-only so a *shared* image (two domains
//!   identity-mapping the same host frames under M5 Arc 2) cannot be a cross-domain write channel.
//! - **Model data frames** — the isolation surface. Frame `m` sits at host PA
//!   `data_pa_base + m * frame_size` and is mapped at guest IPA `data_ipa_base + m * frame_size`,
//!   a *distinct* base so the emitted table performs a real IPA≠PA translation rather than an
//!   identity pass-through.

use crate::leafmap::Perm;

/// Entries in a 4 KiB AArch64 translation table (512 × 8-byte descriptors).
pub const TABLE_ENTRIES: usize = 512;

/// AArch64 Stage-2 descriptor encodings (4 KiB granule).
pub mod desc {
    /// Table descriptor low bits — an `L1`/`L2` entry pointing at the next-level table.
    pub const TABLE: u64 = 0b11;
    /// A **page** descriptor's low bits — a valid `L3` (4 KiB) leaf. (At `L3` the `0b01` block
    /// encoding is reserved/invalid, so a leaf is `0b11`.)
    pub const PAGE: u64 = 0b11;
    /// A **block** descriptor's low bits — a valid `L2` (2 MiB) leaf / superpage.
    pub const BLOCK: u64 = 0b01;

    /// Next-table / 4 KiB-page output-address mask (bits `[47:12]`).
    pub const ADDR_4K: u64 = 0x0000_ffff_ffff_f000;
    /// 2 MiB-block output-address mask (bits `[47:21]`).
    pub const ADDR_2M: u64 = 0x0000_ffff_ffe0_0000;

    /// Leaf lower attributes shared by every mapping emitted: `MemAttr=0b1111` (Stage-2 Normal
    /// Inner+Outer Write-Back cacheable, bits `[5:2]`), `SH=0b11` (Inner Shareable, bits `[9:8]`),
    /// `AF=1` (bit 10 — else the first access faults).
    pub const LEAF_COMMON: u64 = (0b1111 << 2) | (0b11 << 8) | (1 << 10);

    /// `S2AP=0b11` (bits `[7:6]`) — read/write.
    pub const S2AP_RW: u64 = 0b11 << 6;
    /// `S2AP=0b01` (bits `[7:6]`) — read-only; a guest *write* takes a permission fault.
    pub const S2AP_RO: u64 = 0b01 << 6;

    /// Execute-never for a Stage-2 leaf (bit 54). Data frames carry it; the guest image does not.
    pub const XN: u64 = 1 << 54;

    /// The guest-image block: 2 MiB, read-only + executable, Normal WB IS.
    pub const BLOCK_ROX: u64 = BLOCK | LEAF_COMMON | S2AP_RO;
    /// A 4 KiB data leaf, read/write, execute-never.
    pub const PAGE_RW: u64 = PAGE | LEAF_COMMON | S2AP_RW | XN;
    /// A 4 KiB data leaf, read-only, execute-never.
    pub const PAGE_RO: u64 = PAGE | LEAF_COMMON | S2AP_RO | XN;
}

/// Where the tables live and what they map — the physical facts the encoder cannot know.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// PA of the `L1` table.
    pub l1_pa: u64,
    /// PA of the `L2` covering the guest-image region.
    pub l2_code_pa: u64,
    /// PA of the `L2` covering the data region.
    pub l2_data_pa: u64,
    /// PA of the `L3` holding the data leaves.
    pub l3_data_pa: u64,
    /// Host PA (== IPA, identity) of the 2 MiB guest-image block.
    pub guest_image_pa: u64,
    /// Guest IPA base of the model-data-frame region.
    pub data_ipa_base: u64,
    /// Host PA backing model frame 0.
    pub data_pa_base: u64,
    /// Bytes per model frame — the Stage-2 leaf granule.
    pub frame_size: u64,
}

/// The four tables of one domain's Stage-2 set, as plain mutable slices.
pub struct Tables<'a> {
    /// The `L1` table.
    pub l1: &'a mut [u64; TABLE_ENTRIES],
    /// The `L2` for the guest-image region.
    pub l2_code: &'a mut [u64; TABLE_ENTRIES],
    /// The `L2` for the data region.
    pub l2_data: &'a mut [u64; TABLE_ENTRIES],
    /// The `L3` for the data region.
    pub l3_data: &'a mut [u64; TABLE_ENTRIES],
}

/// The address of model frame `m` in a linear frame window based at `base`. The single derivation
/// of frame addressing — every caller (the encoder, the metal's `GuestMem`, the negative-isolation
/// probe) goes through this, so a window can never drift between them (design-lesson #14c).
pub fn frame_addr(base: u64, frame_size: u64, m: u32) -> u64 {
    base + m as u64 * frame_size
}

/// The host PA backing model frame `m`.
pub fn frame_pa(layout: &Layout, m: u32) -> u64 {
    frame_addr(layout.data_pa_base, layout.frame_size, m)
}

/// The guest IPA model frame `m` is mapped at (whether or not it is mapped — an unmapped frame's
/// IPA is exactly what a negative-isolation probe faults on).
pub fn frame_ipa(layout: &Layout, m: u32) -> u64 {
    frame_addr(layout.data_ipa_base, layout.frame_size, m)
}

/// Encode `leaves` into `tables` per `layout`.
///
/// Writes the two-level skeleton (guest-image block + the data region's table chain) and then one
/// `L3` page descriptor per mapped frame at its permission. **Every** `L3` slot is written — the
/// whole table is cleared first — so no stale leaf can survive a rebuild for a different tenant.
///
/// Leaves beyond [`TABLE_ENTRIES`] are impossible: [`crate::leaf_map`] rejects them as
/// [`crate::FrameOutOfRange`] before an encode is ever attempted, so callers pass a map whose
/// length is already bounded by the table size.
pub fn encode(leaves: &[Option<Perm>], layout: &Layout, tables: Tables<'_>) {
    let Tables {
        l1,
        l2_code,
        l2_data,
        l3_data,
    } = tables;

    // Guest image: identity 2 MiB RO+X block (infrastructure — the guest's own code).
    let code_l1 = ((layout.guest_image_pa >> 30) & 0x1ff) as usize;
    let code_l2 = ((layout.guest_image_pa >> 21) & 0x1ff) as usize;
    l1[code_l1] = (layout.l2_code_pa & desc::ADDR_4K) | desc::TABLE;
    l2_code[code_l2] = (layout.guest_image_pa & desc::ADDR_2M) | desc::BLOCK_ROX;

    // Data region: L1 -> L2 -> L3.
    let data_l1 = ((layout.data_ipa_base >> 30) & 0x1ff) as usize;
    let data_l2 = ((layout.data_ipa_base >> 21) & 0x1ff) as usize;
    l1[data_l1] = (layout.l2_data_pa & desc::ADDR_4K) | desc::TABLE;
    l2_data[data_l2] = (layout.l3_data_pa & desc::ADDR_4K) | desc::TABLE;

    // Clear the WHOLE L3 (not a live frame count) — the no-stale-leaf property.
    for slot in l3_data.iter_mut() {
        *slot = 0;
    }
    for (m, leaf) in leaves.iter().enumerate().take(TABLE_ENTRIES) {
        if let Some(perm) = leaf {
            let attrs = match perm {
                Perm::Rw => desc::PAGE_RW,
                Perm::Ro => desc::PAGE_RO,
            };
            l3_data[m] = (frame_pa(layout, m as u32) & desc::ADDR_4K) | attrs;
        }
    }
}

/// The `VTTBR_EL2` value for a table set: the `L1` PA with the set's `VMID` in bits `[55:48]`.
pub fn vttbr(l1_pa: u64, vmid: u64) -> u64 {
    l1_pa | (vmid << 48)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The metal's layout, so the goldens below are the values that actually run.
    fn layout() -> Layout {
        Layout {
            l1_pa: 0x4010_0000,
            l2_code_pa: 0x4010_1000,
            l2_data_pa: 0x4010_2000,
            l3_data_pa: 0x4010_3000,
            guest_image_pa: 0x4040_0000,
            data_ipa_base: 0x8000_0000,
            data_pa_base: 0x4060_0000,
            frame_size: 0x1000,
        }
    }

    fn tables() -> (
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
    ) {
        (
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
        )
    }

    /// GOLDEN: the descriptor constants. These are the values Audit #2 converged on three ways; if
    /// a refactor changes one, isolation changes, so they are pinned literally.
    #[test]
    fn descriptor_constants_are_pinned() {
        assert_eq!(desc::LEAF_COMMON, 0x73c, "MemAttr=1111 | SH=11 | AF");
        assert_eq!(desc::PAGE_RW & 0xfff, 0x7ff, "4 KiB page, RW");
        assert_eq!(desc::PAGE_RO & 0xfff, 0x77f, "4 KiB page, RO");
        assert_eq!(
            desc::BLOCK_ROX & 0xfff,
            0x77d,
            "2 MiB block, RO + executable"
        );
        assert_ne!(desc::PAGE_RW & desc::XN, 0, "data leaves are execute-never");
        assert_ne!(desc::PAGE_RO & desc::XN, 0, "data leaves are execute-never");
        assert_eq!(
            desc::BLOCK_ROX & desc::XN,
            0,
            "the guest image must stay EXECUTABLE"
        );
    }

    #[test]
    fn skeleton_indices_and_descriptors() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3) = tables();
        encode(
            &[None; 8],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
            },
        );
        // guest image 0x4040_0000 -> L1 index 1, L2 index 2
        assert_eq!(l1[1], (l.l2_code_pa & desc::ADDR_4K) | desc::TABLE);
        assert_eq!(l2c[2], (l.guest_image_pa & desc::ADDR_2M) | desc::BLOCK_ROX);
        // data base 0x8000_0000 -> L1 index 2, L2 index 0
        assert_eq!(l1[2], (l.l2_data_pa & desc::ADDR_4K) | desc::TABLE);
        assert_eq!(l2d[0], (l.l3_data_pa & desc::ADDR_4K) | desc::TABLE);
        assert!(l3.iter().all(|d| *d == 0), "no leaves => an empty L3");
    }

    #[test]
    fn leaves_encode_at_their_permission_and_pa() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        leaves[5] = Some(Perm::Ro);
        encode(
            &leaves,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
            },
        );
        assert_eq!(l3[2], (0x4060_2000 & desc::ADDR_4K) | desc::PAGE_RW);
        assert_eq!(l3[5], (0x4060_5000 & desc::ADDR_4K) | desc::PAGE_RO);
        for (m, d) in l3.iter().enumerate() {
            if m != 2 && m != 5 {
                assert_eq!(*d, 0, "frame {m} must be a translation-fault hole");
            }
        }
    }

    /// Re-encoding into the SAME tables for a different tenant leaves no stale leaf.
    #[test]
    fn re_encode_clears_stale_leaves() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3) = tables();
        let mut first = [None; 8];
        first[2] = Some(Perm::Rw);
        encode(
            &first,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
            },
        );
        assert_ne!(l3[2], 0);

        let mut second = [None; 8];
        second[5] = Some(Perm::Ro);
        encode(
            &second,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
            },
        );
        assert_eq!(l3[2], 0, "the previous tenant's leaf survived");
        assert_ne!(l3[5], 0);
    }

    /// GOLDEN (literal): the exact 64-bit descriptor words, written out rather than recomputed from
    /// the same constants the encoder uses — so this test is an INDEPENDENT anchor, not a
    /// restatement. A change to any attribute bit shows up here as a diff, not a silent re-derivation.
    #[test]
    fn golden_descriptor_words_are_literal() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        leaves[5] = Some(Perm::Ro);
        encode(
            &leaves,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
            },
        );
        // table descriptors: next-table PA | 0b11
        assert_eq!(l1[1], 0x4010_1003, "L1 -> L2(code)");
        assert_eq!(l1[2], 0x4010_2003, "L1 -> L2(data)");
        assert_eq!(l2d[0], 0x4010_3003, "L2(data) -> L3");
        // guest image: 2 MiB block PA | RO | executable (no XN) => low bits 0x77d
        assert_eq!(l2c[2], 0x4040_077d, "guest image block, RO+X");
        // data leaves: 4 KiB page PA | RW/RO | XN(bit 54 = 0x0040_0000_0000_0000)
        assert_eq!(l3[2], 0x0040_0000_4060_27ff, "frame 2, RW, XN");
        assert_eq!(l3[5], 0x0040_0000_4060_577f, "frame 5, RO, XN");
    }

    #[test]
    fn vttbr_carries_the_vmid() {
        assert_eq!(vttbr(0x4010_0000, 1), 0x0001_0000_4010_0000);
        assert_eq!(vttbr(0x4010_0000, 2), 0x0002_0000_4010_0000);
    }

    #[test]
    fn frame_addresses_are_linear() {
        let l = layout();
        assert_eq!(frame_pa(&l, 0), 0x4060_0000);
        assert_eq!(frame_pa(&l, 3), 0x4060_3000);
        assert_eq!(frame_ipa(&l, 0), 0x8000_0000);
        assert_eq!(frame_ipa(&l, 3), 0x8000_3000);
    }
}
