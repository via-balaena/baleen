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
    /// A **data** 2 MiB block, read/write, execute-never (M5 Arc 6a). Distinct from
    /// [`BLOCK_ROX`], which is the *shared guest image* block and is deliberately RO **and
    /// executable** — data must never be executable, whatever its span.
    pub const BLOCK_RW: u64 = BLOCK | LEAF_COMMON | S2AP_RW | XN;
    /// A **data** 2 MiB block, read-only, execute-never (M5 Arc 6a).
    pub const BLOCK_RO: u64 = BLOCK | LEAF_COMMON | S2AP_RO | XN;
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
    /// PA of the `L2` holding the **super-span** leaves (2 MiB blocks) — M5 Arc 6a.
    pub l2_sup_pa: u64,
    /// Host PA (== IPA, identity) of the 2 MiB guest-image block.
    pub guest_image_pa: u64,
    /// Guest IPA base of the model-data-frame region.
    pub data_ipa_base: u64,
    /// Host PA backing model frame 0.
    pub data_pa_base: u64,
    /// Bytes per model frame — the Stage-2 leaf granule for a [`Perm`] at [`crate::Span::Base`].
    pub frame_size: u64,
    /// Guest IPA base of the **super-span** frame region (M5 Arc 6a).
    ///
    /// A separate window from `data_ipa_base` on purpose: giving each span its own window is what
    /// makes "no two emitted leaves overlap" **structural** rather than a runtime check. Within one
    /// span the map is a total function over an `Mfn`-indexed space, so overlap is unrepresentable;
    /// across spans, [`Layout::validate`] pins the windows disjoint and in distinct `L1` entries.
    pub sup_ipa_base: u64,
    /// Host PA backing super-span frame 0.
    pub sup_pa_base: u64,
    /// How many super-span frames are actually **backed** by reserved memory.
    ///
    /// Not `TABLE_ENTRIES`: a full super table would span 1 GiB, and the window is only as large as
    /// the memory behind it. [`Layout::validate`] checks the *backed* span for overlap, so declaring
    /// a window larger than its backing cannot pass validation and then alias something real.
    pub sup_frames: u64,
}

/// Bytes one [`crate::Span::Super`] leaf covers: a whole base-level table's worth of base frames
/// (2 MiB at a 4 KiB granule). **Derived, not a second constant** — a super leaf is by definition
/// one level up, so this cannot drift from `frame_size` (design-lesson #14c).
pub fn super_size(layout: &Layout) -> u64 {
    TABLE_ENTRIES as u64 * layout.frame_size
}

/// The host PA backing super-span frame `m`.
pub fn super_pa(layout: &Layout, m: u32) -> u64 {
    frame_addr(layout.sup_pa_base, super_size(layout), m)
}

/// The guest IPA super-span frame `m` is mapped at.
pub fn super_ipa(layout: &Layout, m: u32) -> u64 {
    frame_addr(layout.sup_ipa_base, super_size(layout), m)
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
    /// The `L2` holding super-span 2 MiB block leaves (M5 Arc 6a).
    pub l2_sup: &'a mut [u64; TABLE_ENTRIES],
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
pub fn encode(
    leaves: &[Option<Perm>],
    supers: &[Option<Perm>],
    layout: &Layout,
    tables: Tables<'_>,
) {
    let Tables {
        l1,
        l2_code,
        l2_data,
        l3_data,
        l2_sup,
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

    // Super-span region (M5 Arc 6a): its own `L1` entry -> its own `L2`, whose slots hold 2 MiB
    // BLOCK leaves directly (no `L3` beneath — that is what a superpage is). Its own window is what
    // keeps super leaves from ever overlapping base ones; `Layout::validate` enforces it.
    let sup_l1 = ((layout.sup_ipa_base >> 30) & 0x1ff) as usize;
    l1[sup_l1] = (layout.l2_sup_pa & desc::ADDR_4K) | desc::TABLE;
    // Clear the WHOLE table — the same no-stale-leaf totality the `L3` gets.
    for slot in l2_sup.iter_mut() {
        *slot = 0;
    }
    for (m, leaf) in supers.iter().enumerate().take(TABLE_ENTRIES) {
        if let Some(perm) = leaf {
            let attrs = match perm {
                Perm::Rw => desc::BLOCK_RW,
                Perm::Ro => desc::BLOCK_RO,
            };
            // Indexed by the block's own L2 slot, derived from its IPA — NOT by `m` directly, so the
            // window's base offset cannot silently shift the mapping.
            let idx = ((super_ipa(layout, m as u32) >> 21) & 0x1ff) as usize;
            l2_sup[idx] = (super_pa(layout, m as u32) & desc::ADDR_2M) | attrs;
        }
    }
}

// ─── the inverse: decoding, so the emitted table can be read back and checked ────────────────────
//
// `encode` is the only thing that decides what the hardware walks. Until now it was exercised solely
// by a handful of golden unit tests, while the *decision* feeding it (`leafmap`) was checked over
// every reachable state — so the weakest link in the chain
//
//     model  ->  leaf map  ->  descriptor words  ->  hardware
//
// was the third arrow, not the first. These decoders close it: they recover a descriptor's meaning
// from its bits, so [`verify_encoding`] can assert the emitted tables mean EXACTLY the leaf map they
// were built from — and nothing else.

/// What a Stage-2 leaf descriptor means, recovered from its bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decoded {
    /// The output address it maps to.
    pub pa: u64,
    /// The access permission it grants the guest.
    pub perm: Perm,
    /// Whether it is execute-never.
    pub xn: bool,
}

/// The `S2AP` field of a leaf, or `None` if it is a reserved encoding.
fn decode_perm(d: u64) -> Option<Perm> {
    match (d >> 6) & 0b11 {
        0b11 => Some(Perm::Rw),
        0b01 => Some(Perm::Ro),
        _ => None,
    }
}

/// Decode an `L3` 4 KiB **page** leaf. `None` if the slot is not a valid page (e.g. a zero hole).
///
/// Note the type bits `0b11` mean *page* at `L3` and *table* at `L1`/`L2` — the encoding is
/// level-dependent, so the caller must know which level it is reading. That ambiguity is in the
/// architecture, not this code.
pub fn decode_page(d: u64) -> Option<Decoded> {
    if d & 0b11 != desc::PAGE {
        return None;
    }
    Some(Decoded {
        pa: d & desc::ADDR_4K,
        perm: decode_perm(d)?,
        xn: d & desc::XN != 0,
    })
}

/// Decode an `L2` 2 MiB **block** leaf. `None` if the slot is not a valid block.
pub fn decode_block(d: u64) -> Option<Decoded> {
    if d & 0b11 != desc::BLOCK {
        return None;
    }
    Some(Decoded {
        pa: d & desc::ADDR_2M,
        perm: decode_perm(d)?,
        xn: d & desc::XN != 0,
    })
}

/// Decode an `L1`/`L2` **table** descriptor to the next-level table PA. `None` if not a table entry.
pub fn decode_table(d: u64) -> Option<u64> {
    if d & 0b11 != desc::TABLE {
        return None;
    }
    Some(d & desc::ADDR_4K)
}

/// The four tables, read-only — for [`verify_encoding`].
pub struct TablesRef<'a> {
    /// The `L1` table.
    pub l1: &'a [u64; TABLE_ENTRIES],
    /// The `L2` for the guest-image region.
    pub l2_code: &'a [u64; TABLE_ENTRIES],
    /// The `L2` for the data region.
    pub l2_data: &'a [u64; TABLE_ENTRIES],
    /// The `L3` for the data region.
    pub l3_data: &'a [u64; TABLE_ENTRIES],
    /// The `L2` holding super-span 2 MiB block leaves (M5 Arc 6a).
    pub l2_sup: &'a [u64; TABLE_ENTRIES],
}

/// A way the emitted tables can fail to mean what the leaf map said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncodingViolation {
    /// The guest-image and data regions land in the **same `L1` entry** — the second write would
    /// silently clobber the first and one whole region would vanish. Argued impossible by the
    /// address layout; now checked, because a future layout change could reintroduce it silently.
    RegionsCollide {
        /// The `L1` index both regions claim.
        l1_index: usize,
    },
    /// The guest-image window overlaps the data window, so a domain's private data frames would
    /// alias the **shared** read-only code image.
    WindowsOverlap {
        /// Which address space overlapped (`"ipa"` or `"pa"`).
        space: &'static str,
    },
    /// A table descriptor does not point at the table it should.
    BadTableEntry {
        /// Which table the bad entry is in.
        table: &'static str,
        /// The slot index.
        index: usize,
        /// What it decoded to.
        found: Option<u64>,
        /// What it should have been.
        expected: u64,
    },
    /// The guest-image block is not a read-only, **executable** identity mapping of the image.
    BadImageBlock {
        /// What it decoded to.
        found: Option<Decoded>,
        /// The image PA it should map.
        expected_pa: u64,
    },
    /// An `L3` slot does not decode to the leaf the map specified.
    BadLeaf {
        /// The frame whose slot is wrong.
        mfn: u32,
        /// What it decoded to.
        found: Option<Decoded>,
        /// What the leaf map called for.
        expected: Option<(u64, Perm)>,
    },
    /// A slot outside the intended set holds a live descriptor — the table would reach something
    /// the leaf map never authorized.
    SpuriousDescriptor {
        /// Which table.
        table: &'static str,
        /// The slot index.
        index: usize,
        /// The offending descriptor word.
        desc: u64,
    },
}

impl Layout {
    /// The `L1` index of the guest-image region.
    fn code_l1(&self) -> usize {
        ((self.guest_image_pa >> 30) & 0x1ff) as usize
    }
    /// The `L1` index of the data region.
    fn data_l1(&self) -> usize {
        ((self.data_ipa_base >> 30) & 0x1ff) as usize
    }
    /// The `L2` index of the guest-image block.
    fn code_l2(&self) -> usize {
        ((self.guest_image_pa >> 21) & 0x1ff) as usize
    }
    /// The `L2` index of the data region's `L3` table.
    fn data_l2(&self) -> usize {
        ((self.data_ipa_base >> 21) & 0x1ff) as usize
    }
    /// The `L1` index of the super-span region.
    fn sup_l1(&self) -> usize {
        ((self.sup_ipa_base >> 30) & 0x1ff) as usize
    }

    /// Structural preconditions [`encode`] silently assumes.
    ///
    /// Both were **argued** from the address layout and the linker script (Audit #2's composition
    /// finding: the data frames sit outside the guest's only identity mapping). A layout change
    /// could reintroduce either silently — a collided `L1` entry makes a whole region vanish, an
    /// overlapping window makes private data alias the *shared* code image — so they are checked.
    pub fn validate(&self) -> Result<(), EncodingViolation> {
        // THREE regions now, so the collision check is pairwise (M5 Arc 6a). A collision is not a
        // cosmetic clash: two regions in one `L1` entry means the second write clobbers the first
        // and a whole region silently vanishes.
        for (a, b) in [
            (self.code_l1(), self.data_l1()),
            (self.code_l1(), self.sup_l1()),
            (self.data_l1(), self.sup_l1()),
        ] {
            if a == b {
                return Err(EncodingViolation::RegionsCollide { l1_index: a });
            }
        }
        // The image block is 2 MiB; the data region spans at most one full L3 table.
        const IMAGE_SPAN: u64 = 0x20_0000;
        let data_span = TABLE_ENTRIES as u64 * self.frame_size;
        let overlaps = |a: u64, alen: u64, b: u64, blen: u64| a < b + blen && b < a + alen;
        if overlaps(
            self.guest_image_pa,
            IMAGE_SPAN,
            self.data_ipa_base,
            data_span,
        ) {
            return Err(EncodingViolation::WindowsOverlap { space: "ipa" });
        }
        if overlaps(
            self.guest_image_pa,
            IMAGE_SPAN,
            self.data_pa_base,
            data_span,
        ) {
            return Err(EncodingViolation::WindowsOverlap { space: "pa" });
        }
        // The super window versus both others, in BOTH address spaces (M5 Arc 6a). **This is the
        // property that replaces what uniform 4 KiB addressing used to make unrepresentable**: with
        // one span, two leaves could not overlap because the map was a total function over an
        // `Mfn`-indexed space. With two spans that is only true *within* a map, so non-overlap
        // ACROSS maps has to be pinned here — and it is pinned structurally (disjoint windows),
        // not re-checked per leaf.
        let sup_span = self.sup_frames * super_size(self);
        for (a, alen, b, blen, space) in [
            (
                self.sup_ipa_base,
                sup_span,
                self.data_ipa_base,
                data_span,
                "ipa",
            ),
            (
                self.sup_ipa_base,
                sup_span,
                self.guest_image_pa,
                IMAGE_SPAN,
                "ipa",
            ),
            (
                self.sup_pa_base,
                sup_span,
                self.data_pa_base,
                data_span,
                "pa",
            ),
            (
                self.sup_pa_base,
                sup_span,
                self.guest_image_pa,
                IMAGE_SPAN,
                "pa",
            ),
        ] {
            if overlaps(a, alen, b, blen) {
                return Err(EncodingViolation::WindowsOverlap { space });
            }
        }
        Ok(())
    }
}

/// Read the emitted tables back and assert they mean **exactly** `leaves` under `layout` — and
/// nothing more.
///
/// This is the encoder's half of the refinement. `hv_s2::check` verifies the *decision* (which
/// frames, at what permission); this verifies the *expression* of that decision in the words the
/// hardware actually walks: the table skeleton chains to the right tables, the guest-image block is
/// a read-only executable identity map, each `L3` slot decodes to its leaf's PA and permission, and
/// **every other slot in every table is dead** — so the table cannot reach anything the leaf map did
/// not authorize.
pub fn verify_encoding(
    leaves: &[Option<Perm>],
    supers: &[Option<Perm>],
    layout: &Layout,
    t: TablesRef<'_>,
) -> Result<(), EncodingViolation> {
    layout.validate()?;
    let (code_l1, data_l1, sup_l1) = (layout.code_l1(), layout.data_l1(), layout.sup_l1());
    let (code_l2, data_l2) = (layout.code_l2(), layout.data_l2());

    // L1: exactly THREE live entries now, pointing at the three L2s.
    for (idx, expected) in [
        (code_l1, layout.l2_code_pa & desc::ADDR_4K),
        (data_l1, layout.l2_data_pa & desc::ADDR_4K),
        (sup_l1, layout.l2_sup_pa & desc::ADDR_4K),
    ] {
        if decode_table(t.l1[idx]) != Some(expected) {
            return Err(EncodingViolation::BadTableEntry {
                table: "l1",
                index: idx,
                found: decode_table(t.l1[idx]),
                expected,
            });
        }
    }
    dead_except(t.l1, &[code_l1, data_l1, sup_l1], "l1")?;

    // L2(code): the guest image, read-only and EXECUTABLE (it is the guest's code).
    let want_image = Decoded {
        pa: layout.guest_image_pa & desc::ADDR_2M,
        perm: Perm::Ro,
        xn: false,
    };
    if decode_block(t.l2_code[code_l2]) != Some(want_image) {
        return Err(EncodingViolation::BadImageBlock {
            found: decode_block(t.l2_code[code_l2]),
            expected_pa: want_image.pa,
        });
    }
    dead_except(t.l2_code, &[code_l2], "l2_code")?;

    // L2(data): one entry, to the L3.
    let want_l3 = layout.l3_data_pa & desc::ADDR_4K;
    if decode_table(t.l2_data[data_l2]) != Some(want_l3) {
        return Err(EncodingViolation::BadTableEntry {
            table: "l2_data",
            index: data_l2,
            found: decode_table(t.l2_data[data_l2]),
            expected: want_l3,
        });
    }
    dead_except(t.l2_data, &[data_l2], "l2_data")?;

    // L3: one page descriptor per mapped frame, at its PA and permission, execute-never; every
    // other slot dead.
    for m in 0..TABLE_ENTRIES {
        let want = leaves.get(m).copied().flatten().map(|perm| Decoded {
            pa: frame_pa(layout, m as u32) & desc::ADDR_4K,
            perm,
            xn: true,
        });
        let found = decode_page(t.l3_data[m]);
        if found != want {
            // A dead slot must be *fully* dead, not merely an undecodable non-zero word.
            if want.is_none() && t.l3_data[m] != 0 {
                return Err(EncodingViolation::SpuriousDescriptor {
                    table: "l3_data",
                    index: m,
                    desc: t.l3_data[m],
                });
            }
            return Err(EncodingViolation::BadLeaf {
                mfn: m as u32,
                found,
                expected: want.map(|d| (d.pa, d.perm)),
            });
        }
    }

    // L2(sup): one 2 MiB BLOCK per mapped super-span frame, at its PA and permission, execute-never;
    // every other slot dead (M5 Arc 6a). The `xn: true` is load-bearing and is the reason data
    // blocks get their own descriptor constants: the ONLY executable mapping this emitter writes is
    // the shared guest image, and a data superpage that decoded as executable would hand a guest an
    // execute surface 512× the size of a page.
    for m in 0..TABLE_ENTRIES {
        let want = supers.get(m).copied().flatten().map(|perm| Decoded {
            pa: super_pa(layout, m as u32) & desc::ADDR_2M,
            perm,
            xn: true,
        });
        let idx = ((super_ipa(layout, m as u32) >> 21) & 0x1ff) as usize;
        let found = decode_block(t.l2_sup[idx]);
        if found != want {
            if want.is_none() && t.l2_sup[idx] != 0 {
                return Err(EncodingViolation::SpuriousDescriptor {
                    table: "l2_sup",
                    index: idx,
                    desc: t.l2_sup[idx],
                });
            }
            return Err(EncodingViolation::BadLeaf {
                mfn: m as u32,
                found,
                expected: want.map(|d| (d.pa, d.perm)),
            });
        }
    }
    Ok(())
}

/// Every slot of `table` except `live` must be zero — no descriptor the emitter did not intend.
fn dead_except(
    table: &[u64; TABLE_ENTRIES],
    live: &[usize],
    name: &'static str,
) -> Result<(), EncodingViolation> {
    for (i, d) in table.iter().enumerate() {
        if *d != 0 && !live.contains(&i) {
            return Err(EncodingViolation::SpuriousDescriptor {
                table: name,
                index: i,
                desc: *d,
            });
        }
    }
    Ok(())
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
            // The super-span window: its own L1 entry (0xC0000000 >> 30 = 3, distinct from the
            // image at 1 and the data region at 2) and its own PA window, clear of both. One L2 of
            // 512 x 2 MiB blocks covers exactly 1 GiB — exactly one L1 slot, by construction.
            l2_sup_pa: 0x4010_4000,
            sup_ipa_base: 0xC000_0000,
            sup_pa_base: 0x8000_0000,
            sup_frames: 8,
        }
    }

    /// The five tables of one Stage-2 set, all zeroed: `l1`, `l2_code`, `l2_data`, `l3_data`,
    /// `l2_sup`.
    type Blank = (
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
    );

    fn tables() -> Blank {
        (
            [0; TABLE_ENTRIES],
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
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        encode(
            &[None; 8],
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
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
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        leaves[5] = Some(Perm::Ro);
        encode(
            &leaves,
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
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
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut first = [None; 8];
        first[2] = Some(Perm::Rw);
        encode(
            &first,
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
            },
        );
        assert_ne!(l3[2], 0);

        let mut second = [None; 8];
        second[5] = Some(Perm::Ro);
        encode(
            &second,
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
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
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        leaves[5] = Some(Perm::Ro);
        encode(
            &leaves,
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
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

    /// A representative encoded fixture: `(leaves, layout, l1, l2_code, l2_data, l3_data)`.
    type Fixture = (
        [Option<Perm>; 8],
        Layout,
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
        [u64; TABLE_ENTRIES],
    );

    /// Encode a representative map and hand back the tables, for the verifier tests below.
    fn encoded() -> Fixture {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        leaves[5] = Some(Perm::Ro);
        encode(
            &leaves,
            &[None; 0],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
            },
        );
        (leaves, l, l1, l2c, l2d, l3, l2s)
    }

    fn refs<'a>(
        l1: &'a [u64; TABLE_ENTRIES],
        l2c: &'a [u64; TABLE_ENTRIES],
        l2d: &'a [u64; TABLE_ENTRIES],
        l3: &'a [u64; TABLE_ENTRIES],
        l2s: &'a [u64; TABLE_ENTRIES],
    ) -> TablesRef<'a> {
        TablesRef {
            l1,
            l2_code: l2c,
            l2_data: l2d,
            l3_data: l3,
            l2_sup: l2s,
        }
    }

    /// **M5 Arc 6a — a SUPER-span leaf round-trips as a 2 MiB BLOCK.** The model has had superpages
    /// since design-lesson #14; until this arc the emitter flattened them into 4 KiB page
    /// descriptors, mapping 1/512th of what the model authorized.
    #[test]
    fn super_leaf_encodes_as_a_block_and_verifies() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut sup = [None; 8];
        sup[1] = Some(Perm::Rw);
        sup[3] = Some(Perm::Ro);
        encode(
            &[None; 8],
            &sup,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
            },
        );
        // It is a BLOCK (2 MiB), not a page — and execute-never, unlike the shared image block.
        assert_eq!(
            decode_block(l2s[1]),
            Some(Decoded {
                pa: super_pa(&l, 1),
                perm: Perm::Rw,
                xn: true
            })
        );
        assert_eq!(
            decode_page(l2s[1]),
            None,
            "a block must not decode as a page"
        );
        assert_eq!(
            verify_encoding(&[None; 8], &sup, &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
            Ok(())
        );
    }

    /// A tampered super block is caught, and a stray word in the super table is caught — the same
    /// standard the `L3` leaves are held to, so the new table is not a hole in `verify_encoding`.
    #[test]
    fn verify_catches_a_tampered_or_spurious_super_block() {
        let l = layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s) = tables();
        let mut sup = [None; 8];
        sup[1] = Some(Perm::Ro);
        encode(
            &[None; 8],
            &sup,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
            },
        );

        let mut tampered = l2s;
        tampered[1] = (tampered[1] & !desc::S2AP_RO) | desc::S2AP_RW; // RO block escalated to RW
        assert!(
            matches!(
                verify_encoding(&[None; 8], &sup, &l, refs(&l1, &l2c, &l2d, &l3, &tampered)),
                Err(EncodingViolation::BadLeaf { .. })
            ),
            "a read-only superpage escalated to writable must be caught"
        );

        let mut spurious = l2s;
        spurious[7] = (0x8000_0000 & desc::ADDR_2M) | desc::BLOCK_RW; // an unauthorized 2 MiB block
        assert!(
            matches!(
                verify_encoding(&[None; 8], &sup, &l, refs(&l1, &l2c, &l2d, &l3, &spurious)),
                Err(EncodingViolation::SpuriousDescriptor {
                    table: "l2_sup",
                    ..
                }) | Err(EncodingViolation::BadLeaf { .. })
            ),
            "an unauthorized 2 MiB block reaches 512 pages' worth of memory"
        );
    }

    /// The super window must be structurally separate — its own `L1` entry and a disjoint address
    /// window. This is what replaces the non-overlap that uniform 4 KiB addressing made
    /// unrepresentable.
    #[test]
    fn super_window_must_not_collide_or_overlap() {
        let mut l = layout();
        l.sup_ipa_base = l.data_ipa_base; // same L1 entry as the data region
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::RegionsCollide { .. })
        ));

        let mut l = layout();
        l.sup_pa_base = l.data_pa_base; // distinct L1 entry, but the PA windows alias
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::WindowsOverlap { space: "pa" })
        ));
    }

    /// The decoders invert the encoders, bit for bit.
    #[test]
    fn decoders_invert_the_encoders() {
        for (perm, attrs) in [(Perm::Rw, desc::PAGE_RW), (Perm::Ro, desc::PAGE_RO)] {
            let d = (0x4060_3000 & desc::ADDR_4K) | attrs;
            assert_eq!(
                decode_page(d),
                Some(Decoded {
                    pa: 0x4060_3000,
                    perm,
                    xn: true
                })
            );
        }
        let blk = (0x4040_0000 & desc::ADDR_2M) | desc::BLOCK_ROX;
        assert_eq!(
            decode_block(blk),
            Some(Decoded {
                pa: 0x4040_0000,
                perm: Perm::Ro,
                xn: false
            })
        );
        assert_eq!(
            decode_table((0x4010_1000 & desc::ADDR_4K) | desc::TABLE),
            Some(0x4010_1000)
        );
        assert_eq!(decode_page(0), None, "a hole decodes to nothing");
        assert_eq!(decode_block(0), None);
        assert_eq!(decode_table(0), None);
    }

    /// THE ROUND TRIP: what `encode` wrote means exactly what the leaf map said, and nothing else.
    #[test]
    fn encode_then_verify_round_trips() {
        let (leaves, l, l1, l2c, l2d, l3, l2s) = encoded();
        assert_eq!(
            verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
            Ok(())
        );
    }

    /// NON-VACUITY: a tampered leaf is caught.
    #[test]
    fn verify_catches_a_tampered_leaf() {
        let (leaves, l, l1, l2c, l2d, mut l3, l2s) = encoded();
        l3[2] = (l3[2] & !desc::S2AP_RW) | desc::S2AP_RO; // silently downgrade RW -> RO
        assert!(matches!(
            verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
            Err(EncodingViolation::BadLeaf { mfn: 2, .. })
        ));
    }

    /// NON-VACUITY: a live descriptor in a slot the map never authorized is caught — the table must
    /// not reach anything extra.
    #[test]
    fn verify_catches_a_spurious_descriptor() {
        let (leaves, l, l1, l2c, l2d, mut l3, l2s) = encoded();
        l3[7] = (0x4060_7000 & desc::ADDR_4K) | desc::PAGE_RW; // a frame nobody authorized
        assert!(matches!(
            verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
            Err(EncodingViolation::BadLeaf { mfn: 7, .. })
                | Err(EncodingViolation::SpuriousDescriptor { .. })
        ));
    }

    /// NON-VACUITY: a broken skeleton (an `L1` entry pointing at the wrong table) is caught.
    #[test]
    fn verify_catches_a_broken_skeleton() {
        let (leaves, l, mut l1, l2c, l2d, l3, l2s) = encoded();
        l1[2] = (0xdead_0000u64 & desc::ADDR_4K) | desc::TABLE;
        assert!(matches!(
            verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
            Err(EncodingViolation::BadTableEntry { table: "l1", .. })
        ));
    }

    /// THE SHARED-IMAGE INVARIANT: the guest image is the one mapping two domains hold in common,
    /// so it must be READ-ONLY (never a cross-domain write channel) and EXECUTABLE (the guest runs
    /// from it). Both directions are caught — this used to rest on a comment.
    #[test]
    fn verify_catches_a_writable_or_non_executable_image() {
        let (leaves, l, l1, l2c_ok, l2d, l3, l2s) = encoded();

        let mut l2c = l2c_ok;
        l2c[2] = (l2c[2] & !desc::S2AP_RO) | desc::S2AP_RW; // shared image made WRITABLE
        assert!(
            matches!(
                verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
                Err(EncodingViolation::BadImageBlock { .. })
            ),
            "a writable shared image is a cross-domain write channel"
        );

        let mut l2c = l2c_ok;
        l2c[2] |= desc::XN; // image made non-executable
        assert!(
            matches!(
                verify_encoding(&leaves, &[None; 0], &l, refs(&l1, &l2c, &l2d, &l3, &l2s)),
                Err(EncodingViolation::BadImageBlock { .. })
            ),
            "the guest must still be able to fetch from its image"
        );
    }

    /// The layout preconditions `encode` silently assumed are now checked.
    #[test]
    fn layout_validate_catches_collisions_and_overlap() {
        assert_eq!(layout().validate(), Ok(()), "the real layout is sound");

        // Data region moved into the SAME 1 GiB as the guest image -> one L1 entry for both.
        let mut collide = layout();
        collide.data_ipa_base = 0x4060_0000;
        assert!(matches!(
            collide.validate(),
            Err(EncodingViolation::RegionsCollide { .. })
        ));

        // Data frames backed INSIDE the 2 MiB image block -> private data aliases the shared image.
        let mut overlap = layout();
        overlap.data_pa_base = overlap.guest_image_pa + 0x1000;
        assert!(matches!(
            overlap.validate(),
            Err(EncodingViolation::WindowsOverlap { space: "pa" })
        ));
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
