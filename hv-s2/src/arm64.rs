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

/// **What a region of memory IS — named once, encoded twice.**
///
/// ## Why this exists, and it is a defect report against the code below
///
/// Ledger 5's **A2** made EL2's own DRAM cacheable, and its safety argument is that **EL2 and its
/// guests name the same memory the same way**: a physical frame the guest maps through Stage-2 and
/// EL2 reaches directly is one address with two mappings, and that alias is well-defined only if
/// both mappings agree on the memory type. An alias whose two sides disagree is architecturally
/// UNPREDICTABLE, which is not a thing to leave resting on two people having typed compatible
/// numbers.
///
/// ⚠ **That is exactly what it rested on.** `hv-metal`'s EL2 stage-1 mapping said Normal-WB
/// Inner-Shareable as a `MAIR_EL2` byte (`0xff`) plus an attribute index; [`desc::LEAF_COMMON`] said
/// it as a Stage-2 `MemAttr` nibble (`0b1111`). **Two crates, two literals, no shared derivation**,
/// and the agreement between them was asserted in prose in a module doc — design-lesson #230's
/// defect sitting under A2's central safety claim.
///
/// ★ **And they are genuinely different encoding spaces, which is the whole reason this is not
/// pedantry.** A stage-1 MAIR byte is two 4-bit cacheability fields with their own encoding; a
/// Stage-2 `MemAttr` is a single 4-bit field with a *different* one. "They obviously match" is a
/// claim about two tables in the Arm ARM, not an observation about two numbers.
///
/// So the memory type is declared **once**, here, and each regime derives its own bits from it.
/// Neither consumer *derives from* a literal any more, so they cannot drift apart — and the values
/// are pinned to their golden literals in **two independent places** so they cannot drift *together*
/// either: `memory_types_are_pinned_in_both_regimes` below, and a `const` assertion on
/// `MAIR_EL2_VALUE` over in `hv-metal`'s `mmu`, deliberately far from this declaration because a pin
/// beside what it pins is one its author edits in the same commit.
///
/// **Both halves are needed.** A shared declaration alone would let one edit change both regimes at
/// once, silently and consistently — which is precisely the failure a shared declaration is usually
/// assumed to have removed (design-lesson #243).
///
/// ## Provenance
///
/// **Arm Architecture Reference Manual, VMSAv8-64.** Stage-2 `MemAttr[3:0]` (descriptor bits
/// `[5:2]`): all-zero is Device-nGnRnE; otherwise `[3:2]` is the *outer* and `[1:0]` the *inner*
/// attribute, with `0b01` Non-cacheable, `0b10` Write-Through, `0b11` Write-Back. Stage-1
/// `MAIR_ELx` attribute byte: `0x00` Device-nGnRnE, high nibble outer / low nibble inner, `0b0100`
/// Non-cacheable and `0b1111` Write-Back Read-Allocate Write-Allocate non-transient. `SH[9:8]`
/// carries the **same encoding at the same bit positions in both regimes**, which is why
/// [`memtype::MemoryType::shareability_bits`] is one function rather than a matched pair.
///
/// ## ⛔ What deliberately does NOT use this
///
/// **`fvp-probe` keeps its own copy of these encodings, and unifying it would destroy its value.**
/// The probe shares no source with `hv-metal` on purpose: it is the instrument that graded
/// `scrub_frame` and `smmu::publish` on Arm's AEM, and an instrument that imports the declarations
/// of the thing it measures is a tautology, not evidence. Its duplicate `0xff` is a *control*, not
/// drift.
pub mod memtype {
    /// A memory type this hypervisor maps something with — the architectural notion, independent of
    /// which translation regime is doing the mapping.
    ///
    /// Three variants because three is what the two regimes between them emit; see each variant.
    /// Shareability is part of the type rather than a separate axis, because the only Normal
    /// cacheable type this project maps **must** be Inner Shareable — cacheable-but-Non-shareable
    /// would leave EL2 and the Stage-2 walker in different domains and fail to close the very
    /// mismatch A2 exists to close. Making it a separate parameter would make that bug spellable.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum MemoryType {
        /// **Normal, Inner+Outer Write-Back, Inner Shareable.** What guests get for their RAM
        /// ([`super::desc::LEAF_COMMON`]) and, since A2, what EL2 gets for its own DRAM. These being
        /// the *same variant* is the machine-checked form of A2's safety argument.
        NormalWbIsh,
        /// **Normal, Inner+Outer Non-cacheable.** EL2's `.text` under A2 — mapped to match
        /// `SCTLR_EL2.I == 0`, which forces instruction fetch Non-cacheable whatever the descriptor
        /// says, so a Write-Back descriptor there would describe something the hardware does not do.
        /// ⚠ **The Stage-2 emitter emits this for nothing today.** Its encoding is derived and
        /// pinned anyway, so that a future device or non-cacheable Stage-2 mapping is taken from
        /// here rather than invented at a call site — which is how the duplicate this module removes
        /// came to exist in the first place.
        NormalNonCacheable,
        /// **Device-nGnRnE** — no gathering, no reordering, no early write acknowledgement. MMIO in
        /// both regimes, and the type EL2 gave *everything* before A2.
        DeviceNGnRnE,
    }

    impl MemoryType {
        /// The `MAIR_ELx` attribute **byte** for this type — the stage-1 encoding.
        ///
        /// Returns the byte, not a whole `MAIR` value: which attribute *index* a type occupies is a
        /// register-layout choice belonging to whoever programs `MAIR_ELx`, not a property of the
        /// memory. `hv-metal`'s `mmu` keeps that choice.
        pub const fn stage1_mair_byte(self) -> u8 {
            match self {
                Self::NormalWbIsh => 0xff,
                Self::NormalNonCacheable => 0x44,
                Self::DeviceNGnRnE => 0x00,
            }
        }

        /// The Stage-2 leaf descriptor bits for this type: `MemAttr[5:2]` **and** `SH[9:8]`.
        ///
        /// ⚠ **`AF` is deliberately not included.** The access flag is not a property of the memory
        /// type — it is about whether the mapping has been touched — and folding it in here would
        /// make it impossible to state a type without also asserting a flag. Callers add
        /// [`super::desc::AF`].
        pub const fn stage2_leaf_bits(self) -> u64 {
            let mem_attr: u64 = match self {
                Self::NormalWbIsh => 0b1111,
                Self::NormalNonCacheable => 0b0101,
                Self::DeviceNGnRnE => 0b0000,
            };
            (mem_attr << 2) | self.shareability_bits()
        }

        /// `SH[9:8]` — and **one function for both regimes**, because the field is at the same bits
        /// with the same encoding in a stage-1 and a Stage-2 descriptor alike.
        ///
        /// Device memory ignores shareability and Non-cacheable memory is treated as outer-shareable
        /// regardless, so `0b00` for those two is "deliberately zero" rather than "absent" — the
        /// distinction `hv-metal`'s `SH_NON_SHAREABLE` was named to preserve.
        pub const fn shareability_bits(self) -> u64 {
            const INNER_SHAREABLE: u64 = 0b11 << 8;
            const NON_SHAREABLE: u64 = 0b00 << 8;
            match self {
                Self::NormalWbIsh => INNER_SHAREABLE,
                Self::NormalNonCacheable | Self::DeviceNGnRnE => NON_SHAREABLE,
            }
        }
    }
}

/// AArch64 Stage-2 descriptor encodings (4 KiB granule).
pub mod desc {
    use super::memtype::MemoryType;
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

    /// The access flag, bit 10 — without it the first access takes an Access Flag fault, and this
    /// regime has no handler that would set it. Named rather than inlined so the two descriptors
    /// that need it say the same word; it is **not** part of a memory type
    /// ([`MemoryType::stage2_leaf_bits`] deliberately omits it).
    pub const AF: u64 = 1 << 10;

    /// Leaf lower attributes shared by every Normal-memory mapping emitted: `MemAttr=0b1111`
    /// (Stage-2 Normal Inner+Outer Write-Back cacheable, bits `[5:2]`), `SH=0b11` (Inner Shareable,
    /// bits `[9:8]`), `AF=1`.
    ///
    /// ⚠ **The memory type is no longer written here.** It is [`MemoryType::NormalWbIsh`], and it is
    /// **the same variant `hv-metal` maps EL2's own DRAM with** — which is A2's safety argument in
    /// the only form that cannot rot: the two regimes derive from one declaration instead of
    /// agreeing by inspection. See [`super::memtype`] for what that argument is and what it used to
    /// rest on. The literal is still pinned by `descriptor_constants_are_pinned`, because a shared
    /// declaration stops the two from diverging and does nothing about them moving together.
    pub const LEAF_COMMON: u64 = MemoryType::NormalWbIsh.stage2_leaf_bits() | AF;

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
    /// A 4 KiB **read-execute** leaf (guest code): read-only and an instruction source — the
    /// `Perm::Rx` case (Phase II-1b). Read-only, so it is never W+X; executability is the absent
    /// `XN`. Model-driven — emitted iff the model's leaf edge carries `execute`.
    pub const PAGE_RX: u64 = PAGE | LEAF_COMMON | S2AP_RO;
    /// A **data** 2 MiB block, read/write, execute-never (M5 Arc 6a). Distinct from
    /// [`BLOCK_ROX`], which is the *shared guest image* block and is deliberately RO **and
    /// executable** — data must never be executable, whatever its span.
    pub const BLOCK_RW: u64 = BLOCK | LEAF_COMMON | S2AP_RW | XN;
    /// A **data** 2 MiB block, read-only, execute-never (M5 Arc 6a).
    pub const BLOCK_RO: u64 = BLOCK | LEAF_COMMON | S2AP_RO | XN;
    /// A 2 MiB block that is **writable AND executable** — the one W+X descriptor this emitter
    /// produces. Emitted **only** for a writable super leaf inside the declared W^X-exemption window
    /// ([`super::Layout::sup_wx_exempt`]) — a real kernel's RAM, where code and data share frames
    /// and Stage-2 cannot tell them apart. Everywhere else W^X is enforced and this never appears.
    pub const BLOCK_RW_X: u64 = BLOCK | LEAF_COMMON | S2AP_RW;
    /// A 2 MiB **read-execute** block (guest code): read-only and an instruction source — the super
    /// `Perm::Rx` case. Read-only, so never W+X; model-driven (emitted iff the edge carries
    /// `execute`). Same bits as the guest-image block.
    pub const BLOCK_RX: u64 = BLOCK | LEAF_COMMON | S2AP_RO;
    /// A **device** 2 MiB block (M5 Arc 6b): Device-nGnRnE (no gathering, no reordering, no early
    /// write acknowledgement), read/write, **execute-never**. Getting the memory type wrong here
    /// turns MMIO into speculatively-accessible cacheable memory.
    ///
    /// ⚠ **This used to be written as the ABSENCE of `0b1111 << 2`**, with a comment explaining that
    /// the missing bits were the whole difference from a Normal-memory block. That is true and it is
    /// a bad way to say it: an encoding expressed as *what is not there* cannot be read back,
    /// compared, or got wrong loudly. It now names [`MemoryType::DeviceNGnRnE`] and contributes the
    /// same bits — zero, but zero **said out loud**.
    pub const BLOCK_DEVICE: u64 =
        BLOCK | MemoryType::DeviceNGnRnE.stage2_leaf_bits() | AF | S2AP_RW | XN;
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
    /// PA of the `L2` covering the device pass-through region — M5 Arc 6b.
    pub l2_dev_pa: u64,
    /// Host PA (== IPA, identity) of the 2 MiB guest-image block, or `None`.
    ///
    /// `None` for a guest whose code lives inside the mapped RAM rather than in a separate
    /// hypervisor-owned image — a real kernel, for instance, is deposited into guest RAM before the
    /// hypervisor runs and is therefore covered by the ordinary leaf mapping. Absent means the
    /// image `L1` entry must be **dead**, which `verify_encoding` checks; it does not mean
    /// "unchecked".
    pub guest_image_pa: Option<u64>,
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
    /// Base of the **device pass-through** window (identity, IPA == PA), and its length in bytes;
    /// `device_len == 0` means no device region — M5 Arc 6b.
    ///
    /// **Infrastructure, not model-driven** — the same standing as the guest-image block. A guest
    /// that drives real hardware (a GIC, a UART) needs those MMIO pages mapped, and no `p2m` edge
    /// describes them. Being infrastructure is exactly why it needs its own checked invariant
    /// rather than an argument: device memory is mapped **Device-nGnRnE and execute-never**, and
    /// its window must not overlap any RAM window — a device page that decoded as Normal memory or
    /// as executable would be a far worse surface than a mis-permissioned data page.
    pub device_base: u64,
    /// Length of the device window in bytes; `0` = absent. Must be a multiple of 2 MiB.
    pub device_len: u64,
    /// The declared **write-xor-execute exemption** for the super window (Phase II-1b): whether a
    /// *writable* super leaf may ALSO be emitted executable (a `BLOCK_RW_X` — the one W+X descriptor
    /// this emitter produces).
    ///
    /// **The single, declared place W^X is relaxed — not an oversight.** The model (hv-core `p2m`)
    /// enforces W^X universally: no frame is writable- and executable-mapped at once. But a *real
    /// kernel* runs from its own RAM, where code and data share writable frames and Stage-2 cannot
    /// tell them apart (that is Stage-1's job, which the hypervisor does not own under pass-through),
    /// so its RAM is intrinsically writable AND executable. This flag is that exemption, made a
    /// **declared, checked parameter** (design-lesson #44): `verify_encoding` proves the emitted
    /// blocks match it exactly, so a config that did not ask for W+X cannot silently get it, and the
    /// exemption window is the *only* source of an emitted writable-and-executable descriptor. It
    /// affects only **writable** (`Perm::Rw`) super leaves — read-only (`Ro`) and read-execute
    /// (`Rx`) leaves are emitted per the model (XN / not-XN) regardless. Base-span (4 KiB) leaves
    /// are never exempt: they follow the model's execute bit strictly.
    pub sup_wx_exempt: bool,
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
    /// The `L2` covering the device pass-through region (M5 Arc 6b).
    pub l2_dev: &'a mut [u64; TABLE_ENTRIES],
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
        l2_dev,
    } = tables;

    // Guest image: identity 2 MiB RO+X block (infrastructure — the guest's own code). Absent for a
    // guest whose code lives in the mapped RAM instead, in which case the entry stays dead.
    if let Some(image_pa) = layout.guest_image_pa {
        let code_l1 = ((image_pa >> 30) & 0x1ff) as usize;
        let code_l2 = ((image_pa >> 21) & 0x1ff) as usize;
        l1[code_l1] = (layout.l2_code_pa & desc::ADDR_4K) | desc::TABLE;
        l2_code[code_l2] = (image_pa & desc::ADDR_2M) | desc::BLOCK_ROX;
    }

    // Data region: L1 -> L2 -> L3.
    let data_l1 = ((layout.data_ipa_base >> 30) & 0x1ff) as usize;
    let data_l2 = ((layout.data_ipa_base >> 21) & 0x1ff) as usize;
    l1[data_l1] = (layout.l2_data_pa & desc::ADDR_4K) | desc::TABLE;
    l2_data[data_l2] = (layout.l3_data_pa & desc::ADDR_4K) | desc::TABLE;

    // Clear the WHOLE L3 (not a live frame count) — the no-stale-leaf property. Written as one
    // whole-table assignment rather than a slot loop: identical semantics, and it is a *bulk* store
    // both to the compiler and to the symbolic executor the proofs run under (measured — see
    // `docs/SMMU-DEVICE-PATH-COMPOSITION.md` §4a: the three clears were this rung's entire cost).
    *l3_data = [0; TABLE_ENTRIES];
    for (m, leaf) in leaves.iter().enumerate().take(TABLE_ENTRIES) {
        if let Some(perm) = leaf {
            // Base leaves follow the model's execute bit strictly — never exempt (only the super
            // window can be W^X-exempt). `Rx` is the model-driven read-execute leaf (not-`XN`). The
            // attribute selection routes through the named [`page_leaf_attrs`] emit-seam so it is
            // Kani-provable ∀ to decode back to `leaf_access_xn(perm, false)` (design-lesson #14c).
            let attrs = page_leaf_attrs(*perm);
            l3_data[m] = (frame_pa(layout, m as u32) & desc::ADDR_4K) | attrs;
        }
    }

    // Super-span region (M5 Arc 6a): its own `L1` entry -> its own `L2`, whose slots hold 2 MiB
    // BLOCK leaves directly (no `L3` beneath — that is what a superpage is). Its own window is what
    // keeps super leaves from ever overlapping base ones; `Layout::validate` enforces it.
    let sup_l1 = ((layout.sup_ipa_base >> 30) & 0x1ff) as usize;
    l1[sup_l1] = (layout.l2_sup_pa & desc::ADDR_4K) | desc::TABLE;
    // Clear the WHOLE table — the same no-stale-leaf totality the `L3` gets, and the same bulk form.
    *l2_sup = [0; TABLE_ENTRIES];
    for (m, leaf) in supers.iter().enumerate().take(TABLE_ENTRIES) {
        if let Some(perm) = leaf {
            // The W^X-exemption affects ONLY writable super leaves: `sup_wx_exempt` turns a `Rw`
            // leaf into the one W+X descriptor (`BLOCK_RW_X`), for a real kernel's writable+
            // executable RAM. Read-only (`Ro`, XN) and read-execute (`Rx`, model-driven not-XN)
            // leaves ignore the exemption — they follow the model's execute bit either way.
            // Same emit-seam routing as the base leaves — one derivation, no drift
            // (design-lesson #14c) — but the super window carries the declared W^X
            // exemption, so the attributes read `layout.sup_wx_exempt`.
            let attrs = block_leaf_attrs(*perm, layout.sup_wx_exempt);
            // Indexed by the block's own L2 slot, derived from its IPA — NOT by `m` directly, so the
            // window's base offset cannot silently shift the mapping.
            let idx = ((super_ipa(layout, m as u32) >> 21) & 0x1ff) as usize;
            l2_sup[idx] = (super_pa(layout, m as u32) & desc::ADDR_2M) | attrs;
        }
    }

    // Device pass-through region (M5 Arc 6b): identity 2 MiB Device-nGnRnE, execute-never blocks.
    // Infrastructure, like the image block — no `p2m` edge describes MMIO.
    *l2_dev = [0; TABLE_ENTRIES];
    if layout.device_len > 0 {
        let dev_l1 = ((layout.device_base >> 30) & 0x1ff) as usize;
        l1[dev_l1] = (layout.l2_dev_pa & desc::ADDR_4K) | desc::TABLE;
        let mut a = layout.device_base;
        while a < layout.device_base + layout.device_len {
            let idx = ((a >> 21) & 0x1ff) as usize;
            l2_dev[idx] = (a & desc::ADDR_2M) | desc::BLOCK_DEVICE;
            a += BLOCK_SIZE;
        }
    }
}

/// Bytes one 2 MiB block covers — the granule the image, super and device regions are all built
/// from. Derived from the table geometry so it cannot drift (design-lesson #14c).
pub const BLOCK_SIZE: u64 = 0x20_0000;

/// Bytes one `L3` page descriptor covers: 4 KiB, the granule this module emits leaves at.
///
/// **Derived from the block, not restated**, for the #14c reason the block itself is: one `L2` slot
/// is one `L3` table's worth of pages, so a change to either has to move both. It is also the
/// granule [`Layout::validate`] requires of `Layout::frame_size` — `encode` writes a *page*
/// descriptor for a base leaf and a *block* for a super one, so a `Layout` at any other granule
/// would have its descriptor kind and its address arithmetic describing different mappings.
pub const PAGE_SIZE: u64 = BLOCK_SIZE / TABLE_ENTRIES as u64;

/// Bytes a whole `L1` entry covers — 1 GiB. The unit a region must not straddle: [`encode`] writes
/// one `L1` entry per region and indexes that region's `L2` with `(addr >> 21) & 0x1ff`, which
/// **wraps** at this boundary rather than reaching the next `L1` entry.
pub const L1_ENTRY_SIZE: u64 = BLOCK_SIZE * TABLE_ENTRIES as u64;

/// The input-address space one emitted table set covers: 512 `L1` entries of 1 GiB — **512 GiB**.
///
/// A property of the table *shape*, not of a register field, and the ceiling a walker must fault
/// above: [`encode`] writes exactly one 512-entry `L1`, and every level of the walk indexes with
/// nine bits, so an address beyond this **wraps back into the same tables** rather than reaching
/// anything new. `walk` therefore refuses it and [`Layout::validate`] refuses a window that
/// straddles it. That an address above the addressable space faults is also what the hardware does:
/// the deployed regime's `T0SZ` gives a 39-bit input address, and the two numbers are pinned equal
/// at compile time below (design-lesson #14c — the table geometry and the declared regime are one
/// fact, not two).
pub const ADDRESSABLE: u64 = L1_ENTRY_SIZE * TABLE_ENTRIES as u64;

// The declared regime's input-address size IS the geometry above. If a future regime change moved
// one without the other, every emitted table would cover an address range the walkers do not agree
// on — so it is a build error rather than a comment.
const _: () = assert!(1u64 << BALEEN_STAGE2.ipa_bits == ADDRESSABLE);

/// The largest address `VTTBR_EL2.BADDR` and `STE.S2TTB` can both carry — bits `[47:0]`. A table
/// base above it is *truncated* by both registers, so both walkers would walk a table [`encode`]
/// never wrote, and would agree with each other while doing it.
pub const MAX_TABLE_PA: u64 = 1 << 48;

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
    /// The `S2AP` **access** the descriptor grants — [`Perm::Ro`] or [`Perm::Rw`] only. The
    /// descriptor's execute bit lives separately in [`Self::xn`]; the leaf-map's [`Perm::Rx`]
    /// (read-execute) decodes as `perm: Ro, xn: false`, and the exempt writable+executable block as
    /// `perm: Rw, xn: false`. So the `(perm, xn)` pair spans all four combinations the hardware can
    /// express, while the `Perm` enum alone keeps W+X unrepresentable.
    pub perm: Perm,
    /// Whether it is execute-never.
    pub xn: bool,
}

/// The `(S2AP access, XN)` a leaf of model permission `perm` must decode to, given whether its
/// window is W^X-exempt. The **single derivation** [`encode`] and [`verify_encoding`] share for the
/// execute bit (design-lesson #14c): `Rx` is read-execute (`Ro`, not-`XN`); a writable leaf is
/// executable (not-`XN`) ONLY in an exempt window — the `BLOCK_RW_X` relaxation; everything else is
/// execute-never. Returns the `S2AP` access ([`Perm::Ro`]/[`Perm::Rw`], never `Rx`) so it lines up
/// with what the descriptor actually encodes.
///
/// **Public as the fidelity seam** (design-lesson #14c, like [`Layout::regions`]): `hv-verify`'s
/// Kani harnesses drive it over every `(perm, wx_exempt)` to prove the emitted execute bit follows
/// the model — a writable+executable leaf arises IFF the declared exemption applies, and a
/// read-only leaf is never executable — so "no W+X except the one declared relaxation" is a
/// machine-checked property of the shipped derivation, not a comment.
pub fn leaf_access_xn(perm: Perm, wx_exempt: bool) -> (Perm, bool) {
    match perm {
        Perm::Ro => (Perm::Ro, true),
        Perm::Rw => (Perm::Rw, !wx_exempt),
        Perm::Rx => (Perm::Ro, false),
    }
}

/// The descriptor attribute bits [`encode`] writes for a 4 KiB **base leaf** (`L3` page) of model
/// permission `perm`. Base leaves are never W^X-exempt — only the super window can be (see
/// [`block_leaf_attrs`]).
///
/// **The emit-side seam, named so it is machine-checkable** (design-lesson #14c): `encode` selects
/// its descriptor constants by *calling this*, not through an inline `match`, so `hv-verify`'s Kani
/// harness can prove ∀ that `decode_page(pa | page_leaf_attrs(perm))` recovers exactly
/// [`leaf_access_xn`]`(perm, false)` — i.e. the descriptor words the MMU walks follow the model's
/// execute bit, not just the verifier's expectation. It stays a SEPARATE derivation from the decode
/// seam `leaf_access_xn` (the #36 independent-cross-check), and the harness proves the two coincide.
pub fn page_leaf_attrs(perm: Perm) -> u64 {
    match perm {
        Perm::Rw => desc::PAGE_RW,
        Perm::Ro => desc::PAGE_RO,
        Perm::Rx => desc::PAGE_RX,
    }
}

/// The descriptor attribute bits [`encode`] writes for a 2 MiB **super leaf** (`L2` block) of model
/// permission `perm` under the declared W^X exemption `wx_exempt`. The exemption turns ONLY a
/// writable leaf into the one W+X descriptor (`BLOCK_RW_X`); read-only and read-execute leaves
/// follow the model regardless. The emit-side counterpart of [`page_leaf_attrs`] for the super
/// window, and for the same reason: one derivation, no drift (design-lesson #14c).
pub fn block_leaf_attrs(perm: Perm, wx_exempt: bool) -> u64 {
    match (perm, wx_exempt) {
        (Perm::Rw, false) => desc::BLOCK_RW,
        (Perm::Rw, true) => desc::BLOCK_RW_X,
        (Perm::Ro, _) => desc::BLOCK_RO,
        (Perm::Rx, _) => desc::BLOCK_RX,
    }
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

// ─── The WALK — what a walker actually reaches, and what the layout says it should ───────────────
//
// Everything above answers "what does one descriptor mean?". Neither half of this crate had ever
// answered the question a *walker* asks: **given `l1_pa` and an IPA, which byte does the hardware
// touch, at what permission?** `verify_encoding` comes closest and is not it — it re-derives its
// expectation exactly as `encode` derives the descriptor, so the two agree even when both are
// wrong about the address arithmetic (design-lesson #36, seen from the failure side).
//
// That gap is why the SMMU arc's headline sentence was a citation: the step from "the leaf map
// says frame `m`" to "a device that issues frame `m`'s IPA lands on frame `m`'s bytes" was the one
// nobody had written down. [`walk`] is one reading of it (the descriptor words) and
// [`window_reach`] is a second, independent one (the layout's windows); `hv-verify` proves they
// agree for every IPA, and `docs/SMMU-DEVICE-PATH-COMPOSITION.md` §2 records the four silent
// preconditions writing them down exposed.

/// Where one IPA lands, and under what access — the result of a walk.
///
/// `perm` is the `S2AP` **access** ([`Perm::Ro`]/[`Perm::Rw`], never `Rx`) and `xn` the execute
/// bit, the same split [`Decoded`] makes and for the same reason: the pair spans all four
/// combinations the hardware can express while `Perm` alone keeps W+X unrepresentable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reach {
    /// The exact output byte — the leaf's PA with the offset within the leaf applied.
    pub pa: u64,
    /// The access the leaf grants.
    pub perm: Perm,
    /// Whether the leaf is execute-never.
    pub xn: bool,
}

impl Reach {
    /// Whether a write through this mapping is permitted. Named rather than open-coded so a
    /// witness asking "did the DMA have permission to land here?" reads the same seam the emitter
    /// wrote through.
    #[must_use]
    pub fn writable(self) -> bool {
        self.perm.writable()
    }
}

/// **Walk the emitted Stage-2 tables** rooted at `l1_pa` for `ipa`, reading descriptors through
/// `fetch(table_pa, index)`. `None` is a translation fault — the address reaches nothing.
///
/// **Generic over the fetch, which is the whole point of it living here.** `hv-metal` supplies a
/// volatile read of physical memory (a raw dereference is exactly what the metal is for); the
/// proofs and the unit tests supply an array read. So the walk the boot witness asserts against and
/// the walk the composition theorem is stated over are the *same function*, rather than two walks
/// that have to be kept in step.
///
/// Concrete to the deployed regime — start level 1, 4 KiB granule, three levels — with the 2 MiB
/// block arm for the super and device windows. A regime change would make this walk disagree with
/// the hardware's, which is exactly why [`BALEEN_STAGE2`] is one declaration; a `Layout` whose
/// granule is not the emitted one is refused by [`Layout::validate`].
pub fn walk(l1_pa: u64, ipa: u64, fetch: impl Fn(u64, u64) -> u64) -> Option<Reach> {
    // **The input-address ceiling, and it is not a formality.** Every level below indexes with nine
    // bits of the address and ignores everything above bit 38, so without this an address beyond
    // the tables' reach would **wrap back into the same tables** and resolve to a real mapping —
    // a walker reaching authorized memory from an address the layout never mapped. The hardware
    // takes a translation fault there (the regime's `T0SZ`), and so does this.
    //
    // Found by proof: `the_walk_lands_where_the_windows_say` produced exactly this counterexample
    // (`ipa = 0x0020_0000_C000_1007` aliasing the super window) the first time it was run, against
    // a walk transcribed from the one `hv-metal` had been using since rung 3.
    if ipa >= ADDRESSABLE {
        return None;
    }
    let l2_pa = decode_table(fetch(l1_pa, (ipa >> 30) & 0x1ff))?;
    let l2_desc = fetch(l2_pa, (ipa >> 21) & 0x1ff);
    // A block at `L2` is a 2 MiB leaf — the super window, the guest image and the device window.
    // Tested before the table arm because the two encodings differ only in their low bits.
    if let Some(block) = decode_block(l2_desc) {
        return Some(Reach {
            pa: block.pa | (ipa & (BLOCK_SIZE - 1)),
            perm: block.perm,
            xn: block.xn,
        });
    }
    let l3_pa = decode_table(l2_desc)?;
    let page = decode_page(fetch(l3_pa, (ipa >> 12) & 0x1ff))?;
    Some(Reach {
        pa: page.pa | (ipa & (PAGE_SIZE - 1)),
        perm: page.perm,
        xn: page.xn,
    })
}

/// **What the `Layout` says `ipa` must reach** — the specification seam, written from the windows
/// and the leaf maps with no reference to descriptor encoding at all.
///
/// Deliberately not derived from [`encode`] or from [`walk`], for the reason [`decode`](decode_page)
/// is not derived from the emitters (design-lesson #36): the composition theorem then relates
/// **three** independent readings — this one says what should be reachable, `encode` writes the
/// words, `walk` reads them back.
///
/// `None` means the address is a hole: outside every window, or inside one at a frame the leaf map
/// did not authorize. Assumes a layout [`Layout::validate`] has accepted — the four preconditions
/// it now checks are exactly the ones that would make this function and `encode` describe different
/// mappings.
pub fn window_reach(
    layout: &Layout,
    leaves: &[Option<Perm>],
    supers: &[Option<Perm>],
    ipa: u64,
) -> Option<Reach> {
    // The guest image: one identity 2 MiB block, read-only and EXECUTABLE. Infrastructure, not
    // model-driven — no `p2m` edge describes the guest's own code.
    if let Some(image_pa) = layout.guest_image_pa {
        if ipa >= image_pa && ipa - image_pa < BLOCK_SIZE {
            return Some(Reach {
                pa: ipa,
                perm: Perm::Ro,
                xn: false,
            });
        }
    }
    // The base-span window: one `L3` table's worth of `frame_size` frames.
    let data_span = TABLE_ENTRIES as u64 * layout.frame_size;
    if ipa >= layout.data_ipa_base && ipa - layout.data_ipa_base < data_span {
        let off = ipa - layout.data_ipa_base;
        let m = (off / layout.frame_size) as u32;
        // Beyond the caller's map is a hole, not an error: `encode` writes nothing there and
        // clears the whole table, so the descriptor really is dead.
        let perm = (*leaves.get(m as usize)?)?;
        let (access, xn) = leaf_access_xn(perm, false);
        return Some(Reach {
            pa: frame_pa(layout, m) + off % layout.frame_size,
            perm: access,
            xn,
        });
    }
    // The super-span window: `sup_frames` blocks, bounded by the BACKING rather than by the table.
    let sup_size = super_size(layout);
    if ipa >= layout.sup_ipa_base && ipa - layout.sup_ipa_base < layout.sup_frames * sup_size {
        let off = ipa - layout.sup_ipa_base;
        let m = (off / sup_size) as u32;
        let perm = (*supers.get(m as usize)?)?;
        // The one declared W^X relaxation applies here and nowhere else (Phase II-1b).
        let (access, xn) = leaf_access_xn(perm, layout.sup_wx_exempt);
        return Some(Reach {
            pa: super_pa(layout, m) + off % sup_size,
            perm: access,
            xn,
        });
    }
    // The device pass-through window: identity, read/write, execute-never.
    if layout.device_len > 0
        && ipa >= layout.device_base
        && ipa - layout.device_base < layout.device_len
    {
        return Some(Reach {
            pa: ipa,
            perm: Perm::Rw,
            xn: true,
        });
    }
    None
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
    /// The `L2` covering the device pass-through region (M5 Arc 6b).
    pub l2_dev: &'a [u64; TABLE_ENTRIES],
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
    /// The device window's length is not a whole number of 2 MiB blocks, so the loop that emits it
    /// would either under-map the tail or run past the window's end.
    DeviceWindowUnaligned {
        /// The window base.
        base: u64,
        /// The offending length.
        len: u64,
    },
    /// A window's base is not aligned to the granule its descriptors are emitted at, so the
    /// descriptor [`encode`] writes and the address a walker computes describe different mappings.
    ///
    /// **The sharpest case is the data window's IPA.** `encode` writes frame `m`'s descriptor at
    /// `l3_data[m]`, while a walker reads `l3_data[(ipa >> 12) & 0x1ff]`. Unless `data_ipa_base` is
    /// 2 MiB-aligned those indices differ by a constant, so frame `m`'s IPA resolves to *another
    /// frame's* PA and permission — and the frames past the wrap become reachable at addresses
    /// outside the window [`Layout::validate`] believed disjoint from every other region. Nothing
    /// faults; `verify_encoding` agrees, because it re-derives the expectation the same way.
    WindowUnaligned {
        /// Which window (`"guest image"`, `"data ipa"`, …).
        window: &'static str,
        /// The offending base.
        base: u64,
        /// The alignment it must have.
        align: u64,
    },
    /// A region's span crosses the `L1` entry its base sits in.
    ///
    /// [`encode`] writes **one** `L1` entry per region and indexes that region's `L2` by
    /// `(addr >> 21) & 0x1ff`, which wraps at 1 GiB instead of reaching the next `L1` entry. So a
    /// window that straddles the boundary maps its tail into the *low* slots of its own `L2` —
    /// addresses nothing authorized, reaching real memory. That direction fails **open**.
    RegionCrossesL1 {
        /// The `L1` index the region's base falls in.
        l1_index: usize,
        /// The span that overruns it.
        span: u64,
    },
    /// A table base cannot be named exactly by `VTTBR_EL2.BADDR` / `STE.S2TTB` — above bits
    /// `[47:0]`, or under-aligned.
    ///
    /// Both registers truncate rather than reject, so **both walkers would walk a table this
    /// emitter never wrote**, and rung 3's "one regime, two walkers" round-trip cannot see it: the
    /// CPU and the SMMU truncate identically and therefore agree. The premise
    /// `the_vttbr_seam_recovers_the_table_and_the_vmid` assumes is discharged here.
    TableUnnameable {
        /// Which table.
        table: &'static str,
        /// The offending PA.
        pa: u64,
    },
    /// `frame_size` is not the granule this module emits descriptors at ([`PAGE_SIZE`]).
    ///
    /// [`encode`] writes an `L3` **page** for a base leaf and an `L2` **block** for a super one,
    /// while [`frame_pa`]/[`frame_ipa`] scale by `frame_size`. At any other granule the descriptor
    /// kind and the address arithmetic describe different mappings.
    GranuleNotEmitted {
        /// The granule asked for.
        frame_size: u64,
    },
    /// A device block is missing, or is not a Device-nGnRnE execute-never identity block.
    BadDeviceBlock {
        /// The `L2(dev)` slot.
        index: usize,
        /// The descriptor found there.
        desc: u64,
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
    /// The `L1` index of the guest-image region, if present.
    fn code_l1(&self) -> Option<usize> {
        self.guest_image_pa.map(|pa| ((pa >> 30) & 0x1ff) as usize)
    }
    /// The `L2` index of the guest-image block, if present.
    fn code_l2(&self) -> Option<usize> {
        self.guest_image_pa.map(|pa| ((pa >> 21) & 0x1ff) as usize)
    }
    /// The `L1` index of the data region.
    fn data_l1(&self) -> usize {
        ((self.data_ipa_base >> 30) & 0x1ff) as usize
    }
    /// The `L2` index of the data region's `L3` table.
    fn data_l2(&self) -> usize {
        ((self.data_ipa_base >> 21) & 0x1ff) as usize
    }
    /// The `L1` index of the super-span region.
    fn sup_l1(&self) -> usize {
        ((self.sup_ipa_base >> 30) & 0x1ff) as usize
    }
    /// The `L1` index of the device region, if present.
    fn dev_l1(&self) -> Option<usize> {
        (self.device_len > 0).then_some(((self.device_base >> 30) & 0x1ff) as usize)
    }

    /// One window-alignment check — see [`EncodingViolation::WindowUnaligned`].
    fn aligned(window: &'static str, base: u64, align: u64) -> Result<(), EncodingViolation> {
        if base.is_multiple_of(align) {
            Ok(())
        } else {
            Err(EncodingViolation::WindowUnaligned {
                window,
                base,
                align,
            })
        }
    }

    /// One table-base check — see [`EncodingViolation::TableUnnameable`].
    fn nameable(table: &'static str, pa: u64) -> Result<(), EncodingViolation> {
        if pa < MAX_TABLE_PA && pa.is_multiple_of(PAGE_SIZE) {
            Ok(())
        } else {
            Err(EncodingViolation::TableUnnameable { table, pa })
        }
    }

    /// Every region actually present, as `(L1 index, IPA base, PA base, span)`.
    ///
    /// Building the list once and checking it pairwise is what keeps [`validate`](Self::validate)
    /// from being N² hand-written comparisons that a later region silently escapes — the failure
    /// mode when this was three open-coded pairs and a fourth region arrived (M5 Arc 6b).
    ///
    /// Public because it is the **disjointness seam** the ∀-value proof reads: `hv-verify`'s Kani
    /// harnesses drive the real [`validate`](Self::validate) over a symbolic [`Layout`] and then
    /// read this same list back to assert what validation *guarantees* — that a passing layout has
    /// every present region pairwise-disjoint in both IPA and PA and in distinct `L1` entries (M5
    /// Phase I-3). Proving over the shipped list, not a re-modelled copy, is design-lesson #14c.
    pub fn regions(&self) -> [Option<(usize, u64, u64, u64)>; 4] {
        let data_span = TABLE_ENTRIES as u64 * self.frame_size;
        [
            self.guest_image_pa
                .map(|pa| (((pa >> 30) & 0x1ff) as usize, pa, pa, BLOCK_SIZE)),
            Some((
                self.data_l1(),
                self.data_ipa_base,
                self.data_pa_base,
                data_span,
            )),
            Some((
                self.sup_l1(),
                self.sup_ipa_base,
                self.sup_pa_base,
                self.sup_frames * super_size(self),
            )),
            self.dev_l1()
                .map(|l1| (l1, self.device_base, self.device_base, self.device_len)),
        ]
    }

    /// Structural preconditions [`encode`] silently assumes.
    ///
    /// Argued from the address layout and the linker script in Audit #2, and checked ever since,
    /// because a layout change could reintroduce either failure silently: a **collided `L1` entry**
    /// makes a whole region vanish (the second write clobbers the first), and an **overlapping
    /// window** makes one region alias another — private data over the shared code image, or RAM
    /// over MMIO.
    ///
    /// Non-overlap here is also what carries the property that uniform 4 KiB addressing used to make
    /// unrepresentable (M5 Arc 6a): within one span a leaf map is a total function over an
    /// `Mfn`-indexed space, so two leaves cannot overlap — but *across* spans, and across the
    /// infrastructure regions, only disjoint windows guarantee it.
    pub fn validate(&self) -> Result<(), EncodingViolation> {
        if !self.device_len.is_multiple_of(BLOCK_SIZE) {
            return Err(EncodingViolation::DeviceWindowUnaligned {
                base: self.device_base,
                len: self.device_len,
            });
        }
        // ─── REPRESENTABILITY (the device-path composition) ────────────────────────────────────
        //
        // Everything below this comment and above the pairwise loop was added by the composition
        // rung, and every one of the four premises it checks was, until then, *silent*: `encode`
        // has always assumed them, nothing stated them, and violating any of them mis-maps without
        // faulting — `verify_encoding` re-derives its expectation exactly as `encode` derives the
        // descriptor, so the two agree on the wrong answer. Writing `window_reach` and `walk` as
        // two independent readings is what forced them into the open
        // (`docs/SMMU-DEVICE-PATH-COMPOSITION.md` §2). They are checked HERE, at the same gate the
        // metal already halts on, rather than at four separate call sites.

        // (c) The granule. `encode` emits a page at `L3` and a block at `L2`; the address
        //     derivations scale by `frame_size`. They must be talking about the same size.
        if self.frame_size != PAGE_SIZE {
            return Err(EncodingViolation::GranuleNotEmitted {
                frame_size: self.frame_size,
            });
        }

        // (a) Window alignment. The data window's IPA must be block-aligned or the `L3` index a
        //     walker computes is not the `m` the descriptor was written at; its PA must be
        //     page-aligned or the descriptor's own address mask drops bits `frame_pa` kept. The
        //     block-granule windows must be block-aligned for the same two reasons one level up.
        //
        //     Written as flat, sequential checks rather than a loop over a chained iterator: the
        //     `Chain<array::IntoIter, option::IntoIter>` machinery is opaque to the symbolic
        //     executor the proofs run under, and cost minutes where this costs nothing (§4a).
        Self::aligned("data ipa", self.data_ipa_base, BLOCK_SIZE)?;
        Self::aligned("data pa", self.data_pa_base, PAGE_SIZE)?;
        Self::aligned("super ipa", self.sup_ipa_base, BLOCK_SIZE)?;
        Self::aligned("super pa", self.sup_pa_base, BLOCK_SIZE)?;
        if let Some(pa) = self.guest_image_pa {
            Self::aligned("guest image", pa, BLOCK_SIZE)?;
        }
        if self.device_len > 0 {
            Self::aligned("device", self.device_base, BLOCK_SIZE)?;
        }

        // (d) The tables must be where both registers can name them. `l1_pa` is the one the
        //     walkers are handed; the rest are named by table descriptors, whose own output-address
        //     field (`ADDR_4K`) truncates identically.
        Self::nameable("l1", self.l1_pa)?;
        Self::nameable("l2_code", self.l2_code_pa)?;
        Self::nameable("l2_data", self.l2_data_pa)?;
        Self::nameable("l3_data", self.l3_data_pa)?;
        Self::nameable("l2_sup", self.l2_sup_pa)?;
        Self::nameable("l2_dev", self.l2_dev_pa)?;

        let regions = self.regions();

        // (b) No region may straddle its `L1` entry, because `encode` writes exactly one `L1`
        //     entry per region and the `L2` index wraps rather than carrying into the next.
        //     The same loop refuses a window that runs past the addressable space entirely: nine
        //     bits per level means an address beyond it wraps back into these tables rather than
        //     faulting, so a window up there is not a window at all.
        for (l1_index, ipa, _pa, span) in regions.into_iter().flatten() {
            if ipa >= ADDRESSABLE
                || span > ADDRESSABLE - ipa
                || ipa % L1_ENTRY_SIZE + span > L1_ENTRY_SIZE
            {
                return Err(EncodingViolation::RegionCrossesL1 { l1_index, span });
            }
        }

        for i in 0..regions.len() {
            for j in (i + 1)..regions.len() {
                let (Some((l1a, ipa_a, pa_a, span_a)), Some((l1b, ipa_b, pa_b, span_b))) =
                    (regions[i], regions[j])
                else {
                    continue;
                };
                if l1a == l1b {
                    return Err(EncodingViolation::RegionsCollide { l1_index: l1a });
                }
                let overlaps = |a: u64, alen: u64, b: u64, blen: u64| a < b + blen && b < a + alen;
                if overlaps(ipa_a, span_a, ipa_b, span_b) {
                    return Err(EncodingViolation::WindowsOverlap { space: "ipa" });
                }
                if overlaps(pa_a, span_a, pa_b, span_b) {
                    return Err(EncodingViolation::WindowsOverlap { space: "pa" });
                }
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
    let (data_l1, sup_l1, data_l2) = (layout.data_l1(), layout.sup_l1(), layout.data_l2());

    // L1: exactly one live entry per PRESENT region, each pointing at that region's L2.
    let mut live_l1 = [0usize; 4];
    let mut n_live = 0;
    for (idx, expected) in [
        Some((data_l1, layout.l2_data_pa & desc::ADDR_4K)),
        Some((sup_l1, layout.l2_sup_pa & desc::ADDR_4K)),
        layout
            .code_l1()
            .map(|i| (i, layout.l2_code_pa & desc::ADDR_4K)),
        layout
            .dev_l1()
            .map(|i| (i, layout.l2_dev_pa & desc::ADDR_4K)),
    ]
    .into_iter()
    .flatten()
    {
        if decode_table(t.l1[idx]) != Some(expected) {
            return Err(EncodingViolation::BadTableEntry {
                table: "l1",
                index: idx,
                found: decode_table(t.l1[idx]),
                expected,
            });
        }
        live_l1[n_live] = idx;
        n_live += 1;
    }
    dead_except(t.l1, &live_l1[..n_live], "l1")?;

    // L2(code): the guest image, read-only and EXECUTABLE (it is the guest's code). Absent for a
    // guest whose code lives in the mapped RAM — then the whole table must be DEAD, which is a
    // stronger statement than "we did not write it".
    match (layout.guest_image_pa, layout.code_l2()) {
        (Some(image_pa), Some(code_l2)) => {
            let want_image = Decoded {
                pa: image_pa & desc::ADDR_2M,
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
        }
        _ => dead_except(t.l2_code, &[], "l2_code")?,
    }

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

    // L3: one page descriptor per mapped frame, at its PA and the `(S2AP, XN)` the model's leaf
    // permission demands. Base leaves are never W^X-exempt (`false`), so a writable base leaf is
    // always XN and a read-execute (`Rx`) leaf is the only not-XN base leaf — the model's execute
    // bit, faithful to the descriptor. Every other slot dead.
    for m in 0..TABLE_ENTRIES {
        let want = leaves.get(m).copied().flatten().map(|perm| {
            let (access, xn) = leaf_access_xn(perm, false);
            Decoded {
                pa: frame_pa(layout, m as u32) & desc::ADDR_4K,
                perm: access,
                xn,
            }
        });
        let found = decode_page(t.l3_data[m]);
        if found != want {
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

    // L2(sup): one 2 MiB BLOCK per mapped super-span frame, at the `(S2AP, XN)` the model's leaf
    // permission demands under the declared W^X-exemption. A writable super leaf is executable
    // (not-XN) ONLY when `sup_wx_exempt` — the one declared W+X relaxation, checked here so execute
    // can be neither gained nor lost silently; read-only and read-execute leaves follow the model
    // regardless. Every other slot dead.
    for m in 0..TABLE_ENTRIES {
        let want = supers.get(m).copied().flatten().map(|perm| {
            let (access, xn) = leaf_access_xn(perm, layout.sup_wx_exempt);
            Decoded {
                pa: super_pa(layout, m as u32) & desc::ADDR_2M,
                perm: access,
                xn,
            }
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

    // L2(dev): identity Device-nGnRnE execute-never blocks over the window; every other slot dead
    // (M5 Arc 6b). Checked by DECODING rather than by re-deriving the word — a device block that
    // decoded as Normal memory, or as executable, is precisely the failure this exists to catch.
    for idx in 0..TABLE_ENTRIES {
        // The address this slot covers: an L2 spans 1 GiB, so slot `idx` is
        // `(the L1-aligned base of the window) + idx * 2 MiB`.
        let want = if layout.device_len > 0 {
            let l1_base = layout.device_base & !(BLOCK_SIZE * TABLE_ENTRIES as u64 - 1);
            let a = l1_base + idx as u64 * BLOCK_SIZE;
            (a >= layout.device_base && a < layout.device_base + layout.device_len).then_some(
                DecodedDevice {
                    pa: a & desc::ADDR_2M,
                    xn: true,
                },
            )
        } else {
            None
        };
        let found = decode_device_block(t.l2_dev[idx]);
        if found != want {
            if want.is_none() && t.l2_dev[idx] != 0 {
                return Err(EncodingViolation::SpuriousDescriptor {
                    table: "l2_dev",
                    index: idx,
                    desc: t.l2_dev[idx],
                });
            }
            return Err(EncodingViolation::BadDeviceBlock {
                index: idx,
                desc: t.l2_dev[idx],
            });
        }
    }
    Ok(())
}

/// What a **device** block descriptor means, recovered from its bits (M5 Arc 6b).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecodedDevice {
    /// The MMIO output address.
    pub pa: u64,
    /// Execute-never. Must always be true — device memory is never an instruction source.
    pub xn: bool,
}

/// Decode a device block, or `None` if it is not one — including a Normal-memory block, which is
/// exactly the confusion worth catching.
pub fn decode_device_block(d: u64) -> Option<DecodedDevice> {
    if d & 0b11 != desc::BLOCK {
        return None;
    }
    // `MemAttr` (bits [5:2]) must be 0b0000 = Device-nGnRnE. A Normal-memory block has 0b1111.
    if (d >> 2) & 0b1111 != 0 {
        return None;
    }
    Some(DecodedDevice {
        pa: d & desc::ADDR_2M,
        xn: d & desc::XN != 0,
    })
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

/// The start-level table base a `VTTBR_EL2` value names — `BADDR`, bits `[47:0]`.
///
/// The **decode seam** for [`vttbr`], and it exists for rung 3: the SMMU is handed a domain's table
/// through `STE.S2TTB`, and the only way to say "the *same* table the CPU walks" without a second
/// derivation is to read it back out of the `VTTBR_EL2` value the CPU would be given. A wrong answer
/// here is a device bound to some other domain's memory, so it is a seam, not an accessor.
#[must_use]
pub const fn vttbr_table(vttbr: u64) -> u64 {
    vttbr & 0x0000_ffff_ffff_ffff
}

/// The `VMID` a `VTTBR_EL2` value carries, **masked to the width the regime tags with**.
///
/// The masking is the point, not tidiness: this is how the device side gets its VMID, so the value
/// an STE is given is by construction the value the CPU is actually tagging with — see [`VmidBits`].
#[must_use]
pub const fn vttbr_vmid(vttbr: u64, bits: VmidBits) -> u16 {
    (((vttbr >> 48) as u32) & (bits.count() - 1)) as u16
}

// ─── The stage-2 translation REGIME — one derivation, two walkers (SMMU arc, rung 3) ─────────────
//
// Everything above this line is about the *table*. This section is about the **parameters a walker
// reads it under**: granule, input-address size, start level, output-address size, and the
// attributes the walk's own fetches use. Until rung 3 there was exactly one walker (the CPU, via
// `VTCR_EL2`) and those parameters could live as a magic constant in `hv-metal`. Rung 3 points the
// SMMU at the *same* tables, and the SMMU takes its parameters from the **STE**, not from
// `VTCR_EL2`.
//
// Two walkers reading one table under DIFFERENT parameters is not a degraded translation — it is a
// different translation. A start level one off makes the walker read leaf descriptors as table
// descriptors; a granule one off makes it index with the wrong field of the address. Either way the
// device reaches memory the table never authorized, which is exactly the failure this arc exists to
// exclude. So the parameters become ONE derivation ([`Stage2Regime`]) with two INDEPENDENT
// encodings — `VTCR_EL2` here, `STE` word 2 in [`crate::smmu`] — and `hv-verify` proves the two
// decode to the same regime (design-lesson #36, and GAP-A's repair of exactly this shape).

/// The translation granule — the leaf page size, and with it the number of address bits each level
/// of the walk consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    /// 4 KiB pages, 9 bits per level. **The only granule baleen emits**, and the only one whose
    /// `STE.S2TG` encoding this crate is willing to state (see [`crate::smmu::stage2_ste`]).
    K4,
    /// 16 KiB pages, 11 bits per level.
    K16,
    /// 64 KiB pages, 13 bits per level.
    K64,
}

impl Granule {
    /// Bits of the address consumed by the page offset: `log2(granule)`.
    #[must_use]
    pub const fn page_bits(self) -> u32 {
        match self {
            Self::K4 => 12,
            Self::K16 => 14,
            Self::K64 => 16,
        }
    }

    /// Bits of the address resolved by ONE level of the walk — a table holds `granule / 8`
    /// descriptors, so this is `page_bits - 3`.
    #[must_use]
    pub const fn level_bits(self) -> u32 {
        self.page_bits() - 3
    }

    /// `VTCR_EL2.TG0` — **the AArch64 `TG0` encoding**: `0b00` = 4 KiB, `0b01` = 64 KiB, `0b10` =
    /// 16 KiB. Note the order: 64 KiB before 16 KiB. `STE.S2TG` is a *different* field with its own
    /// encoding, which is the whole reason this type exists rather than a raw 2-bit value being
    /// copied from one register to the other.
    #[must_use]
    pub const fn tg0(self) -> u64 {
        match self {
            Self::K4 => 0b00,
            Self::K64 => 0b01,
            Self::K16 => 0b10,
        }
    }

    /// The inverse of [`tg0`](Self::tg0). `None` for the reserved `0b11`.
    #[must_use]
    pub const fn from_tg0(v: u64) -> Option<Self> {
        match v {
            0b00 => Some(Self::K4),
            0b01 => Some(Self::K64),
            0b10 => Some(Self::K16),
            _ => None,
        }
    }
}

/// The level the walk starts at. Numbered as the architecture does: level 0 is the coarsest, level 3
/// resolves the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartLevel {
    L0,
    L1,
    L2,
    L3,
}

impl StartLevel {
    /// The level as a number, so the span arithmetic reads like the architecture's.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::L0 => 0,
            Self::L1 => 1,
            Self::L2 => 2,
            Self::L3 => 3,
        }
    }

    /// `VTCR_EL2.SL0` / `STE.S2SL0` — the two fields share this encoding (`0b00` = level 2, `0b01` =
    /// level 1, `0b10` = level 0, `0b11` = level 3), and it is deliberately NOT the level number.
    #[must_use]
    pub const fn sl0(self) -> u64 {
        match self {
            Self::L2 => 0b00,
            Self::L1 => 0b01,
            Self::L0 => 0b10,
            Self::L3 => 0b11,
        }
    }

    /// The inverse of [`sl0`](Self::sl0). Total — every 2-bit value names a level.
    #[must_use]
    pub const fn from_sl0(v: u64) -> Option<Self> {
        match v {
            0b00 => Some(Self::L2),
            0b01 => Some(Self::L1),
            0b10 => Some(Self::L0),
            0b11 => Some(Self::L3),
            _ => None,
        }
    }

    /// How many address bits a walk starting here can resolve at `granule`: the page offset plus one
    /// level's worth of index for each level from here to the leaf.
    ///
    /// This is what makes "the start level must match the input-address size" checkable rather than
    /// conventional — see [`Stage2Regime::valid`].
    #[must_use]
    pub const fn span(self, granule: Granule) -> u32 {
        granule.page_bits() + (3 - self.number()) * granule.level_bits() + granule.level_bits()
    }
}

/// The output (physical) address size, as the shared `PARange` encoding both `VTCR_EL2.PS` and
/// `STE.S2PS` use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaSize {
    B32,
    B36,
    B40,
    B42,
    B44,
    B48,
    B52,
}

impl PaSize {
    /// The 3-bit `PARange` encoding, shared by `VTCR_EL2.PS` and `STE.S2PS`.
    #[must_use]
    pub const fn ps(self) -> u64 {
        match self {
            Self::B32 => 0b000,
            Self::B36 => 0b001,
            Self::B40 => 0b010,
            Self::B42 => 0b011,
            Self::B44 => 0b100,
            Self::B48 => 0b101,
            Self::B52 => 0b110,
        }
    }

    /// The inverse of [`ps`](Self::ps). `None` for the reserved `0b111`.
    #[must_use]
    pub const fn from_ps(v: u64) -> Option<Self> {
        match v {
            0b000 => Some(Self::B32),
            0b001 => Some(Self::B36),
            0b010 => Some(Self::B40),
            0b011 => Some(Self::B42),
            0b100 => Some(Self::B44),
            0b101 => Some(Self::B48),
            0b110 => Some(Self::B52),
            _ => None,
        }
    }
}

/// How many bits of `VMID` the CPU regime tags TLB entries with — `VTCR_EL2.VS`.
///
/// **Deliberately not part of [`Stage2Regime`], and the reason is a finding rather than a
/// preference.** The STE's `S2VMID` field is *always* 16 bits and the entry has no `VS` — so the
/// width is a property of the CPU's configuration that an STE cannot carry, and a `Stage2Regime`
/// containing it could not round-trip through an entry. The first draft did contain it, and the
/// ∀-regime agreement proof failed on exactly that: a 16-bit-VMID regime encoded into an STE decodes
/// back as an 8-bit one, so "the two walkers share one regime" was false as stated.
///
/// The coupling it was there to enforce — a hypervisor tagging 8-bit on the CPU must not hand the
/// SMMU a 16-bit VMID, or two domains alias under truncation — is instead enforced at the
/// *derivation*: [`vttbr_vmid`] masks to this width, and the metal obtains the VMID it binds by
/// reading it back out of the domain's `VTTBR_EL2`. A value that does not fit cannot be obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmidBits {
    B8,
    B16,
}

impl VmidBits {
    /// `VTCR_EL2.VS` — `0` = 8-bit VMIDs, `1` = 16-bit.
    #[must_use]
    pub const fn vs(self) -> u64 {
        match self {
            Self::B8 => 0,
            Self::B16 => 1,
        }
    }

    /// The number of distinct VMIDs the regime can express.
    #[must_use]
    pub const fn count(self) -> u32 {
        match self {
            Self::B8 => 1 << 8,
            Self::B16 => 1 << 16,
        }
    }
}

/// The full parameter set of an AArch64 **stage-2** translation regime — the thing a walker needs
/// besides the table itself.
///
/// One value, two encodings: [`vtcr_el2`] for the CPU and [`crate::smmu::stage2_ste`] for the SMMU.
/// Neither is derived from the other; `hv-verify` proves they agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2Regime {
    /// Leaf page size.
    pub granule: Granule,
    /// Input-address (IPA) size in bits — `T0SZ = 64 - ipa_bits`.
    pub ipa_bits: u32,
    /// The level the walk starts at.
    pub start_level: StartLevel,
    /// Output-address size.
    pub pa_size: PaSize,
    /// `SH0`/`S2SH0` — shareability of the walk's own table fetches. `0b11` = inner-shareable.
    pub walk_shareability: u64,
    /// `IRGN0`/`S2IR0` — inner cacheability of the walk's own fetches. `0b01` = write-back
    /// write-allocate.
    pub walk_inner: u64,
    /// `ORGN0`/`S2OR0` — outer cacheability of the walk's own fetches.
    pub walk_outer: u64,
}

impl Stage2Regime {
    /// Whether this regime is one a walker can actually be configured with.
    ///
    /// The interesting clause is the **start level**: a walk starting at a level that cannot span
    /// `ipa_bits` resolves the wrong address bits at the wrong level, and one that could have started
    /// lower means the top level's table is mostly empty — the architecture pins the pairing, and
    /// this is where the pairing becomes checkable. Baleen emits a single table per level (no
    /// **concatenated** start-level tables), so the requirement is exact: the start level must span
    /// the IPA size, and the next level down must NOT.
    #[must_use]
    pub const fn valid(&self) -> bool {
        let span = self.start_level.span(self.granule);
        let lower = span - self.granule.level_bits();
        // `T0SZ` is a 6-bit field and the architecture bounds stage-2 input sizes; the low bound is
        // what stops a "regime" whose start level is below the page offset.
        self.ipa_bits <= 48
            && self.ipa_bits > self.granule.page_bits()
            && self.ipa_bits <= span
            && self.ipa_bits > lower
            && self.walk_shareability <= 0b11
            && self.walk_inner <= 0b11
            && self.walk_outer <= 0b11
    }

    /// `T0SZ` / `S2T0SZ` — the shared "input size" encoding, as a *shrink* from 64 bits.
    #[must_use]
    pub const fn t0sz(&self) -> u64 {
        64 - self.ipa_bits as u64
    }

    /// The alignment the start-level table's base must have — and therefore the alignment `VTTBR_EL2`
    /// and `STE.S2TTB` must be handed.
    ///
    /// The start-level table holds one descriptor per address bit the start level resolves that the
    /// IPA size actually uses, so its size (and hence its alignment) follows from the regime rather
    /// than from a convention. An under-aligned base is *truncated* by both registers rather than
    /// rejected — the same silent failure `STRTAB_BASE` has (design-lesson #72) — so the requirement
    /// is stated here, where both consumers can check against it.
    #[must_use]
    pub const fn table_align(&self) -> u64 {
        let lower = self.start_level.span(self.granule) - self.granule.level_bits();
        // Entries needed at the start level: one per distinct value of the address bits above what
        // the next level down resolves. 8 bytes each.
        let entries = 1u64 << (self.ipa_bits - lower);
        let size = entries * 8;
        // The architecture floors the table (and so its alignment) at 64 bytes.
        if size < 64 {
            64
        } else {
            size
        }
    }
}

/// **The regime baleen runs.** 4 KiB granule, 39-bit IPA, start level 1, 40-bit output, inner-shareable
/// write-back walks, 8-bit VMIDs.
///
/// This is the single declaration of what used to be `hv-metal`'s `VTCR_EL2 = 0x8002_3559` literal.
/// It is here rather than there because rung 3 gave it a **second consumer**: the SMMU walks the same
/// tables under the STE's copy of these parameters, and a second literal would be a second
/// derivation of the thing that must not differ.
pub const BALEEN_STAGE2: Stage2Regime = Stage2Regime {
    granule: Granule::K4,
    ipa_bits: 39,
    start_level: StartLevel::L1,
    pa_size: PaSize::B40,
    walk_shareability: 0b11,
    walk_inner: 0b01,
    walk_outer: 0b01,
};

/// The VMID width baleen tags with — 8 bits (`VTCR_EL2.VS = 0`), as every phase since M5 Arc 2 has.
/// See [`VmidBits`] for why this is not inside [`BALEEN_STAGE2`].
pub const BALEEN_VMID_BITS: VmidBits = VmidBits::B8;

/// `VTCR_EL2.RES1` — bit 31, one on every implementation.
const VTCR_RES1: u64 = 1 << 31;

/// The `VTCR_EL2` value for `regime` — the **CPU's** encoding of it.
///
/// `None` for a regime no walker can be configured with ([`Stage2Regime::valid`]). Refusing rather
/// than encoding a truncated field is the same ruling as [`crate::smmu::strtab_base_cfg`]'s: a
/// silently-narrowed input size is a walker that reads a different table than the one intended.
///
/// `DS` (bit 32) stays clear, so the classic (non-LPA2) descriptor format the [`encode`] leaf
/// encodings assume is in force; `HA`/`HD` stay clear (no hardware access-flag management).
/// A `const fn` so the metal can resolve its `VTCR_EL2` at **compile time** from the shared regime:
/// a regime that cannot be encoded must break the build, not degrade into a runtime fallback that
/// configures the CPU with something nobody chose.
#[must_use]
pub const fn vtcr_el2(regime: &Stage2Regime, vmid_bits: VmidBits) -> Option<u64> {
    if !regime.valid() {
        return None;
    }
    Some(
        VTCR_RES1
            | (regime.pa_size.ps() << 16)
            | (vmid_bits.vs() << 19)
            | (regime.granule.tg0() << 14)
            | (regime.walk_shareability << 12)
            | (regime.walk_outer << 10)
            | (regime.walk_inner << 8)
            | (regime.start_level.sl0() << 6)
            | regime.t0sz(),
    )
}

/// Read a `VTCR_EL2` value back as a regime — the **decode seam**, written against the field
/// definitions and not derived from [`vtcr_el2`].
///
/// `None` if the value is not one this crate would have emitted: a reserved granule or `PARange`, a
/// missing `RES1`, an `LPA2` (`DS`) regime whose descriptor format the encoder does not speak, or an
/// input size the start level cannot span. Keeping the decode independent is what makes the
/// round-trip proof — and the STE-agrees-with-`VTCR` proof — statements about two seams rather than
/// one seam told twice.
#[must_use]
pub fn decode_vtcr_el2(v: u64) -> Option<(Stage2Regime, VmidBits)> {
    if v & VTCR_RES1 == 0 || v & (1 << 32) != 0 {
        return None;
    }
    let regime = Stage2Regime {
        granule: Granule::from_tg0((v >> 14) & 0b11)?,
        ipa_bits: 64 - ((v & 0x3f) as u32),
        start_level: StartLevel::from_sl0((v >> 6) & 0b11)?,
        pa_size: PaSize::from_ps((v >> 16) & 0b111)?,
        walk_shareability: (v >> 12) & 0b11,
        walk_outer: (v >> 10) & 0b11,
        walk_inner: (v >> 8) & 0b11,
    };
    let vmid_bits = if (v >> 19) & 1 == 0 {
        VmidBits::B8
    } else {
        VmidBits::B16
    };
    if regime.valid() {
        Some((regime, vmid_bits))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout that populates **every** emitted region at once — guest image, base-span data,
    /// super-span data, and the device pass-through window — so the goldens below cover every
    /// branch of `encode` in one fixture.
    ///
    /// **It deliberately mirrors NO shipped configuration, and the comment that used to claim it
    /// was "the metal's layout, so the goldens are the values that actually run" was false.** The
    /// two configurations that ship are disjoint from it and from each other
    /// (`hv-metal::stage2::windows()`): the **synthetic** build emits `device_len: 0` — no device
    /// window at all — and the **real-Linux** build emits `0x0800_0000 .. 0x0900_0000` (16 MiB,
    /// the GIC alone since ③-a1) over a completely different RAM window (`sup_ipa_base` at
    /// `0x4800_0000`, 448 super frames, not `0xC000_0000`/8). A fixture that exercises paths no
    /// single shipped config reaches is the RIGHT thing for a golden test — claiming it is the
    /// deployed one is not, and it is the shape design-lesson #92b names: a correspondence asserted
    /// in prose that nothing checks, which then drifts.
    ///
    /// **Where the shipped values ARE bound:** `hv-s2` cannot depend on `hv-metal` (it is
    /// workspace-excluded and does not link for the host), so this seam cannot be made
    /// compile-time — the same cross-crate seam ⑭ met with `xtask`, bound the same way, at RUN
    /// time. `hv-metal`'s `verify_encoding` re-decodes the descriptors the emitter actually wrote
    /// and prints the window it found; `xtask::LINUX_MARKERS` asserts that string
    /// (`device window 16 MiB`) in the required `real-linux boot (QEMU)` job. The theorems
    /// themselves quantify over `Layout` (`hv-verify`'s symbolic-layout harnesses), so nothing here
    /// rests on the fixture's particular numbers.
    fn every_region_layout() -> Layout {
        Layout {
            l1_pa: 0x4010_0000,
            l2_code_pa: 0x4010_1000,
            l2_data_pa: 0x4010_2000,
            l3_data_pa: 0x4010_3000,
            guest_image_pa: Some(0x4040_0000),
            data_ipa_base: 0x8000_0000,
            data_pa_base: 0x4060_0000,
            frame_size: 0x1000,
            // The super-span window: its own L1 entry (0xC0000000 >> 30 = 3, distinct from the
            // image at 1 and the data region at 2) and its own PA window, clear of both. One L2 of
            // 512 x 2 MiB blocks covers exactly 1 GiB — exactly one L1 slot, by construction.
            l2_sup_pa: 0x4010_4000,
            l2_dev_pa: 0x4010_5000,
            // Device pass-through window: its own L1 entry (0x0800_0000 >> 30 = 0), 32 MiB.
            device_base: 0x0800_0000,
            device_len: 0x0200_0000,
            sup_wx_exempt: false,
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
        [u64; TABLE_ENTRIES],
    );

    fn tables() -> Blank {
        (
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
            [0; TABLE_ENTRIES],
        )
    }

    /// GOLDEN: **the memory types, in both regimes.** The other half of the pin `memtype` needs.
    ///
    /// ★ **A shared declaration stops the two regimes DIVERGING and does nothing about them moving
    /// TOGETHER** — one edit to `MemoryType` would change `hv-metal`'s stage-1 mapping and this
    /// crate's Stage-2 emission at once, silently and consistently, which is the failure mode a
    /// shared declaration is usually assumed to have removed. These literals are what makes such an
    /// edit loud. Every value below is from the Arm ARM, restated here as a number so that the
    /// derivation and the number are two independent statements (design-lesson #243).
    #[test]
    fn memory_types_are_pinned_in_both_regimes() {
        use memtype::MemoryType::{DeviceNGnRnE, NormalNonCacheable, NormalWbIsh};

        // Stage-1: the `MAIR_ELx` attribute byte. `hv-metal`'s `mmu` builds `MAIR_EL2` from these.
        assert_eq!(NormalWbIsh.stage1_mair_byte(), 0xff, "outer+inner WB RA/WA");
        assert_eq!(
            NormalNonCacheable.stage1_mair_byte(),
            0x44,
            "outer+inner NC"
        );
        assert_eq!(DeviceNGnRnE.stage1_mair_byte(), 0x00, "Device-nGnRnE");

        // Stage-2: `MemAttr[5:2] | SH[9:8]`, a DIFFERENT encoding of the same three types — which is
        // the whole reason `memtype` exists rather than a shared constant.
        assert_eq!(
            NormalWbIsh.stage2_leaf_bits(),
            (0b1111 << 2) | (0b11 << 8),
            "MemAttr=1111, SH=11"
        );
        assert_eq!(
            NormalNonCacheable.stage2_leaf_bits(),
            0b0101 << 2,
            "MemAttr=0101 (outer NC, inner NC), SH=00"
        );
        assert_eq!(DeviceNGnRnE.stage2_leaf_bits(), 0, "MemAttr=0000, SH=00");

        // `SH[9:8]` is one function serving both regimes, so pin it on its own too: a change that
        // moved shareability out of `NormalWbIsh` would break A2's coherency argument at EL2 while
        // leaving every Stage-2 assertion above intact.
        assert_eq!(
            NormalWbIsh.shareability_bits(),
            0b11 << 8,
            "Inner Shareable"
        );
        assert_eq!(NormalNonCacheable.shareability_bits(), 0);
        assert_eq!(DeviceNGnRnE.shareability_bits(), 0);

        // The three types must be DISTINGUISHABLE in both regimes. A type whose encoding collides
        // with another's is a type that is lying, and the collision would be invisible at every call
        // site — each one would simply emit "the right bits" for the wrong thing.
        let all = [NormalWbIsh, NormalNonCacheable, DeviceNGnRnE];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.stage1_mair_byte(),
                    b.stage1_mair_byte(),
                    "{a:?} and {b:?} collide in stage 1"
                );
                assert_ne!(
                    a.stage2_leaf_bits(),
                    b.stage2_leaf_bits(),
                    "{a:?} and {b:?} collide in stage 2"
                );
            }
        }
    }

    /// GOLDEN: the descriptor constants. These are the values Audit #2 converged on three ways; if
    /// a refactor changes one, isolation changes, so they are pinned literally.
    #[test]
    fn descriptor_constants_are_pinned() {
        assert_eq!(desc::LEAF_COMMON, 0x73c, "MemAttr=1111 | SH=11 | AF");
        // ⚠ Unchanged by the `memtype` refactor, and that is the point of asserting it: the
        // derivation moved, the bits did not. `BLOCK_DEVICE` likewise — it used to express its
        // memory type as the ABSENCE of the Normal bits and now names `DeviceNGnRnE`, which must be
        // the identical word.
        assert_eq!(
            desc::BLOCK_DEVICE & 0xfff,
            0x4c1,
            "Device: MemAttr=0000, S2AP=RW, AF, block"
        );
        assert_ne!(desc::BLOCK_DEVICE & desc::XN, 0, "device memory is XN");
        assert_eq!(desc::PAGE_RW & 0xfff, 0x7ff, "4 KiB page, RW");
        assert_eq!(desc::PAGE_RO & 0xfff, 0x77f, "4 KiB page, RO");
        assert_eq!(
            desc::BLOCK_ROX & 0xfff,
            0x77d,
            "2 MiB block, RO + executable"
        );
        assert_ne!(
            desc::PAGE_RW & desc::XN,
            0,
            "writable data is execute-never"
        );
        assert_ne!(
            desc::PAGE_RO & desc::XN,
            0,
            "read-only data is execute-never"
        );
        assert_eq!(
            desc::BLOCK_ROX & desc::XN,
            0,
            "the guest image must stay EXECUTABLE"
        );
        // Phase II-1b: read-execute leaves (Rx) are RO and NOT execute-never. `PAGE_RX` differs
        // from `PAGE_RO` only in bit 54 (XN), so its low 12 bits match `PAGE_RO`'s 0x77f.
        assert_eq!(desc::PAGE_RX & 0xfff, 0x77f, "4 KiB page, RO + executable");
        assert_eq!(desc::PAGE_RX & desc::XN, 0, "an Rx page must be executable");
        assert_eq!(
            desc::PAGE_RX & desc::S2AP_RW,
            desc::S2AP_RO,
            "Rx is read-only"
        );
        assert_eq!(
            desc::BLOCK_RX & desc::XN,
            0,
            "an Rx block must be executable"
        );
        assert_eq!(
            desc::BLOCK_RX & desc::S2AP_RW,
            desc::S2AP_RO,
            "Rx block is read-only, never W+X"
        );
        // The one W+X descriptor — writable AND executable — the declared exemption only.
        assert_eq!(
            desc::BLOCK_RW_X & desc::XN,
            0,
            "the exempt block is executable"
        );
        assert_eq!(
            desc::BLOCK_RW_X & desc::S2AP_RW,
            desc::S2AP_RW,
            "the exempt block is writable"
        );
    }

    #[test]
    fn skeleton_indices_and_descriptors() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
            },
        );
        // guest image 0x4040_0000 -> L1 index 1, L2 index 2
        assert_eq!(l1[1], (l.l2_code_pa & desc::ADDR_4K) | desc::TABLE);
        assert_eq!(
            l2c[2],
            (l.guest_image_pa.unwrap() & desc::ADDR_2M) | desc::BLOCK_ROX
        );
        // data base 0x8000_0000 -> L1 index 2, L2 index 0
        assert_eq!(l1[2], (l.l2_data_pa & desc::ADDR_4K) | desc::TABLE);
        assert_eq!(l2d[0], (l.l3_data_pa & desc::ADDR_4K) | desc::TABLE);
        assert!(l3.iter().all(|d| *d == 0), "no leaves => an empty L3");
    }

    #[test]
    fn leaves_encode_at_their_permission_and_pa() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
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
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
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
                l2_dev: &mut l2dv,
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
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
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

    /// **The golden `VTCR_EL2`.** `0x8002_3559` is the literal `hv-metal` ran from Arc 4 until rung 3
    /// moved the parameters here. Pinned as a value, not re-derived from the encoder, so that
    /// factoring the constant into a `Stage2Regime` cannot have changed one bit of what the CPU is
    /// configured with — the refactor is required to be *behaviour-nil* on the CPU path.
    #[test]
    fn the_deployed_regime_encodes_to_the_vtcr_the_metal_has_always_run() {
        assert_eq!(
            vtcr_el2(&BALEEN_STAGE2, BALEEN_VMID_BITS),
            Some(0x8002_3559)
        );
        assert_eq!(
            decode_vtcr_el2(0x8002_3559),
            Some((BALEEN_STAGE2, BALEEN_VMID_BITS))
        );
    }

    #[test]
    fn the_regime_pins_the_start_level_to_the_input_size() {
        // 39-bit IPA at a 4 KiB granule is exactly a level-1 start: level 2 spans only 30 bits, and
        // level 0 would leave the top table with a single live entry.
        assert_eq!(StartLevel::L1.span(Granule::K4), 39);
        assert_eq!(StartLevel::L2.span(Granule::K4), 30);
        assert_eq!(StartLevel::L0.span(Granule::K4), 48);
        assert!(BALEEN_STAGE2.valid());
        let mut wrong = BALEEN_STAGE2;
        wrong.start_level = StartLevel::L2;
        assert!(!wrong.valid(), "a start level that cannot span the IPA");
        assert_eq!(vtcr_el2(&wrong, BALEEN_VMID_BITS), None);
        wrong.start_level = StartLevel::L0;
        assert!(!wrong.valid(), "a start level with a level to spare");
    }

    #[test]
    fn the_start_level_table_alignment_is_derived_not_conventional() {
        // The metal's `Table` is 4 KiB aligned; the regime is what says it must be.
        assert_eq!(BALEEN_STAGE2.table_align(), 4096);
        let mut narrow = BALEEN_STAGE2;
        narrow.ipa_bits = 31;
        assert!(narrow.valid());
        // A 31-bit IPA needs only two level-1 entries — but the architecture floors the table at 64 B.
        assert_eq!(narrow.table_align(), 64);
    }

    #[test]
    fn the_granule_and_level_encodings_are_not_the_numbers_they_name() {
        // The two traps this type exists to keep out of raw 2-bit copies.
        assert_eq!(Granule::K64.tg0(), 0b01);
        assert_eq!(Granule::K16.tg0(), 0b10);
        assert_eq!(StartLevel::L1.sl0(), 0b01);
        assert_eq!(StartLevel::L0.sl0(), 0b10);
        assert_eq!(Granule::from_tg0(0b11), None);
        assert_eq!(PaSize::from_ps(0b111), None);
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
        [u64; TABLE_ENTRIES],
    );

    /// Encode a representative map and hand back the tables, for the verifier tests below.
    fn encoded() -> Fixture {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
            },
        );
        (leaves, l, l1, l2c, l2d, l3, l2s, l2dv)
    }

    fn refs<'a>(
        l1: &'a [u64; TABLE_ENTRIES],
        l2c: &'a [u64; TABLE_ENTRIES],
        l2d: &'a [u64; TABLE_ENTRIES],
        l3: &'a [u64; TABLE_ENTRIES],
        l2s: &'a [u64; TABLE_ENTRIES],
        l2dv: &'a [u64; TABLE_ENTRIES],
    ) -> TablesRef<'a> {
        TablesRef {
            l1,
            l2_code: l2c,
            l2_data: l2d,
            l3_data: l3,
            l2_sup: l2s,
            l2_dev: l2dv,
        }
    }

    /// **M5 Arc 6a — a SUPER-span leaf round-trips as a 2 MiB BLOCK.** The model has had superpages
    /// since design-lesson #14; until this arc the emitter flattened them into 4 KiB page
    /// descriptors, mapping 1/512th of what the model authorized.
    #[test]
    fn super_leaf_encodes_as_a_block_and_verifies() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
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
            verify_encoding(
                &[None; 8],
                &sup,
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Ok(())
        );
    }

    /// **Phase II-1b — a read-execute (`Rx`) leaf encodes NOT execute-never**, at both spans, and
    /// round-trips. Executability follows the model's leaf permission, not a config flag.
    #[test]
    fn rx_leaves_encode_executable_and_verify() {
        let l = every_region_layout(); // sup_wx_exempt: false — Rx executability is model-driven, not the exemption
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        let mut leaves = [None; 8];
        leaves[4] = Some(Perm::Rx); // a base read-execute leaf
        let mut sup = [None; 8];
        sup[2] = Some(Perm::Rx); // a super read-execute leaf
        encode(
            &leaves,
            &sup,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        // A base Rx page: read-only S2AP, executable (not XN).
        assert_eq!(
            decode_page(l3[4]),
            Some(Decoded {
                pa: frame_pa(&l, 4) & desc::ADDR_4K,
                perm: Perm::Ro,
                xn: false
            })
        );
        // A super Rx block: read-only, executable.
        assert_eq!(
            decode_block(l2s[((super_ipa(&l, 2) >> 21) & 0x1ff) as usize]),
            Some(Decoded {
                pa: super_pa(&l, 2) & desc::ADDR_2M,
                perm: Perm::Ro,
                xn: false
            })
        );
        assert_eq!(
            verify_encoding(&leaves, &sup, &l, refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)),
            Ok(())
        );
    }

    /// **The declared W^X-exemption makes a WRITABLE super leaf executable — and only there.** With
    /// `sup_wx_exempt`, a `Rw` super leaf emits the one W+X descriptor (`BLOCK_RW_X`); without it,
    /// the same leaf is execute-never. Base leaves are never exempt.
    #[test]
    fn wx_exempt_makes_only_writable_super_leaves_executable() {
        let mut l = every_region_layout();
        l.sup_wx_exempt = true;
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        let mut leaves = [None; 8];
        leaves[5] = Some(Perm::Rw); // a base writable leaf — must stay XN even under the exemption
        let mut sup = [None; 8];
        sup[1] = Some(Perm::Rw); // a writable super leaf — exempt → W+X
        encode(
            &leaves,
            &sup,
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        let idx = ((super_ipa(&l, 1) >> 21) & 0x1ff) as usize;
        assert_eq!(
            decode_block(l2s[idx]),
            Some(Decoded {
                pa: super_pa(&l, 1) & desc::ADDR_2M,
                perm: Perm::Rw,
                xn: false // writable AND executable — the exemption
            })
        );
        // The base writable leaf is NOT exempt — it stays execute-never.
        assert_eq!(
            decode_page(l3[5]),
            Some(Decoded {
                pa: frame_pa(&l, 5) & desc::ADDR_4K,
                perm: Perm::Rw,
                xn: true
            }),
            "base leaves are never W^X-exempt"
        );
        assert_eq!(
            verify_encoding(&leaves, &sup, &l, refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)),
            Ok(())
        );

        // Without the exemption, the SAME writable super leaf is execute-never, and the exempt
        // descriptor is now spurious — `verify_encoding` catches the silently-gained execute.
        let mut plain = l;
        plain.sup_wx_exempt = false;
        assert!(
            matches!(
                verify_encoding(
                    &leaves,
                    &sup,
                    &plain,
                    refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
                ),
                Err(EncodingViolation::BadLeaf { .. })
            ),
            "a writable+executable super block must be rejected when the window is not exempt"
        );
    }

    /// A base data leaf that silently drops `XN` (gains execute) is caught — base leaves follow the
    /// model's execute bit strictly, with no exemption.
    #[test]
    fn verify_catches_a_base_data_leaf_that_gained_execute() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        let mut leaves = [None; 8];
        leaves[2] = Some(Perm::Rw);
        encode(
            &leaves,
            &[None; 8],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        let mut tampered = l3;
        tampered[2] &= !desc::XN; // a writable data page made executable — W+X
        assert!(
            matches!(
                verify_encoding(
                    &leaves,
                    &[None; 8],
                    &l,
                    refs(&l1, &l2c, &l2d, &tampered, &l2s, &l2dv)
                ),
                Err(EncodingViolation::BadLeaf { .. })
            ),
            "a data page that silently gained execute must be caught"
        );
    }

    /// A tampered super block is caught, and a stray word in the super table is caught — the same
    /// standard the `L3` leaves are held to, so the new table is not a hole in `verify_encoding`.
    #[test]
    fn verify_catches_a_tampered_or_spurious_super_block() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
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
                l2_dev: &mut l2dv,
            },
        );

        let mut tampered = l2s;
        tampered[1] = (tampered[1] & !desc::S2AP_RO) | desc::S2AP_RW; // RO block escalated to RW
        assert!(
            matches!(
                verify_encoding(
                    &[None; 8],
                    &sup,
                    &l,
                    refs(&l1, &l2c, &l2d, &l3, &tampered, &l2dv)
                ),
                Err(EncodingViolation::BadLeaf { .. })
            ),
            "a read-only superpage escalated to writable must be caught"
        );

        let mut spurious = l2s;
        spurious[7] = (0x8000_0000 & desc::ADDR_2M) | desc::BLOCK_RW; // an unauthorized 2 MiB block
        assert!(
            matches!(
                verify_encoding(
                    &[None; 8],
                    &sup,
                    &l,
                    refs(&l1, &l2c, &l2d, &l3, &spurious, &l2dv)
                ),
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
        let mut l = every_region_layout();
        l.sup_ipa_base = l.data_ipa_base; // same L1 entry as the data region
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::RegionsCollide { .. })
        ));

        let mut l = every_region_layout();
        l.sup_pa_base = l.data_pa_base; // distinct L1 entry, but the PA windows alias
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::WindowsOverlap { space: "pa" })
        ));
    }

    /// **M5 Arc 6b — the device region.** Identity Device-nGnRnE, execute-never blocks over the
    /// window; `verify_encoding` accepts, and the decoder confirms the attribute rather than
    /// re-deriving the word we just wrote.
    #[test]
    fn device_region_encodes_and_verifies() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        encode(
            &[None; 8],
            &[None; 8],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        // The FIXTURE's 32 MiB window = 16 blocks, starting at slot (0x0800_0000 >> 21) & 0x1ff =
        // 64. (Not a deployed size: the synthetic build has no device window and the real-Linux
        // build's is 16 MiB — see `every_region_layout`.)
        let first = ((l.device_base >> 21) & 0x1ff) as usize;
        assert_eq!(
            decode_device_block(l2dv[first]),
            Some(DecodedDevice {
                pa: l.device_base,
                xn: true
            })
        );
        assert_eq!(
            decode_device_block(l2dv[first + 15]),
            Some(DecodedDevice {
                pa: l.device_base + 15 * BLOCK_SIZE,
                xn: true
            })
        );
        assert_eq!(l2dv[first + 16], 0, "one past the window must be dead");
        assert_eq!(
            verify_encoding(
                &[None; 8],
                &[None; 8],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Ok(())
        );
    }

    /// A device block that is **Normal memory**, or that is **executable**, is caught. These are the
    /// two ways MMIO turns into something far worse than a mis-permissioned data page: cacheable and
    /// speculatively accessible, or an instruction source.
    #[test]
    fn verify_catches_a_normal_or_executable_device_block() {
        let l = every_region_layout();
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        encode(
            &[None; 8],
            &[None; 8],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        let first = ((l.device_base >> 21) & 0x1ff) as usize;

        let mut normal = l2dv;
        normal[first] |= 0b1111 << 2; // MemAttr = Normal WB — no longer device memory
        assert_eq!(decode_device_block(normal[first]), None);
        assert!(matches!(
            verify_encoding(
                &[None; 8],
                &[None; 8],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &normal)
            ),
            Err(EncodingViolation::BadDeviceBlock { .. })
        ));

        let mut exec = l2dv;
        exec[first] &= !desc::XN; // MMIO made executable
        assert!(matches!(
            verify_encoding(
                &[None; 8],
                &[None; 8],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &exec)
            ),
            Err(EncodingViolation::BadDeviceBlock { .. })
        ));
    }

    /// **An absent guest image means the image tables are DEAD, not merely unwritten.** A real
    /// kernel lives inside the mapped RAM, so there is no separate image block — and `None` must be
    /// a checked statement about the emitted tables, not a silent skip.
    #[test]
    fn absent_guest_image_leaves_its_tables_dead() {
        let mut l = every_region_layout();
        l.guest_image_pa = None;
        let (mut l1, mut l2c, mut l2d, mut l3, mut l2s, mut l2dv) = tables();
        encode(
            &[None; 8],
            &[None; 8],
            &l,
            Tables {
                l1: &mut l1,
                l2_code: &mut l2c,
                l2_data: &mut l2d,
                l3_data: &mut l3,
                l2_sup: &mut l2s,
                l2_dev: &mut l2dv,
            },
        );
        assert!(l2c.iter().all(|&d| d == 0), "no image => image L2 is dead");
        assert_eq!(l1[1], 0, "and its L1 entry is dead too");
        assert_eq!(
            verify_encoding(
                &[None; 8],
                &[None; 8],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Ok(())
        );

        // And a stray image block with no image declared is CAUGHT, not ignored.
        let mut stray = l2c;
        stray[2] = (0x4040_0000 & desc::ADDR_2M) | desc::BLOCK_ROX;
        assert!(matches!(
            verify_encoding(
                &[None; 8],
                &[None; 8],
                &l,
                refs(&l1, &stray, &l2d, &l3, &l2s, &l2dv)
            ),
            Err(EncodingViolation::SpuriousDescriptor {
                table: "l2_code",
                ..
            })
        ));
    }

    /// The device window is checked like every other region: distinct `L1` entry, disjoint window,
    /// and a length that is a whole number of blocks (else the emit loop under-maps the tail).
    #[test]
    fn device_window_must_be_aligned_and_disjoint() {
        let mut l = every_region_layout();
        l.device_len = BLOCK_SIZE + 1;
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::DeviceWindowUnaligned { .. })
        ));

        let mut l = every_region_layout();
        l.device_base = l.sup_ipa_base; // same L1 entry as the super window
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::RegionsCollide { .. })
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
        let (leaves, l, l1, l2c, l2d, l3, l2s, l2dv) = encoded();
        assert_eq!(
            verify_encoding(
                &leaves,
                &[None; 0],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Ok(())
        );
    }

    /// NON-VACUITY: a tampered leaf is caught.
    #[test]
    fn verify_catches_a_tampered_leaf() {
        let (leaves, l, l1, l2c, l2d, mut l3, l2s, l2dv) = encoded();
        l3[2] = (l3[2] & !desc::S2AP_RW) | desc::S2AP_RO; // silently downgrade RW -> RO
        assert!(matches!(
            verify_encoding(
                &leaves,
                &[None; 0],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Err(EncodingViolation::BadLeaf { mfn: 2, .. })
        ));
    }

    /// NON-VACUITY: a live descriptor in a slot the map never authorized is caught — the table must
    /// not reach anything extra.
    #[test]
    fn verify_catches_a_spurious_descriptor() {
        let (leaves, l, l1, l2c, l2d, mut l3, l2s, l2dv) = encoded();
        l3[7] = (0x4060_7000 & desc::ADDR_4K) | desc::PAGE_RW; // a frame nobody authorized
        assert!(matches!(
            verify_encoding(
                &leaves,
                &[None; 0],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Err(EncodingViolation::BadLeaf { mfn: 7, .. })
                | Err(EncodingViolation::SpuriousDescriptor { .. })
        ));
    }

    /// NON-VACUITY: a broken skeleton (an `L1` entry pointing at the wrong table) is caught.
    #[test]
    fn verify_catches_a_broken_skeleton() {
        let (leaves, l, mut l1, l2c, l2d, l3, l2s, l2dv) = encoded();
        l1[2] = (0xdead_0000u64 & desc::ADDR_4K) | desc::TABLE;
        assert!(matches!(
            verify_encoding(
                &leaves,
                &[None; 0],
                &l,
                refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
            ),
            Err(EncodingViolation::BadTableEntry { table: "l1", .. })
        ));
    }

    /// THE SHARED-IMAGE INVARIANT: the guest image is the one mapping two domains hold in common,
    /// so it must be READ-ONLY (never a cross-domain write channel) and EXECUTABLE (the guest runs
    /// from it). Both directions are caught — this used to rest on a comment.
    #[test]
    fn verify_catches_a_writable_or_non_executable_image() {
        let (leaves, l, l1, l2c_ok, l2d, l3, l2s, l2dv) = encoded();

        let mut l2c = l2c_ok;
        l2c[2] = (l2c[2] & !desc::S2AP_RO) | desc::S2AP_RW; // shared image made WRITABLE
        assert!(
            matches!(
                verify_encoding(
                    &leaves,
                    &[None; 0],
                    &l,
                    refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
                ),
                Err(EncodingViolation::BadImageBlock { .. })
            ),
            "a writable shared image is a cross-domain write channel"
        );

        let mut l2c = l2c_ok;
        l2c[2] |= desc::XN; // image made non-executable
        assert!(
            matches!(
                verify_encoding(
                    &leaves,
                    &[None; 0],
                    &l,
                    refs(&l1, &l2c, &l2d, &l3, &l2s, &l2dv)
                ),
                Err(EncodingViolation::BadImageBlock { .. })
            ),
            "the guest must still be able to fetch from its image"
        );
    }

    /// The layout preconditions `encode` silently assumed are now checked.
    #[test]
    fn layout_validate_catches_collisions_and_overlap() {
        assert_eq!(
            every_region_layout().validate(),
            Ok(()),
            "the fixture must be a VALID layout, or every negative case below is vacuous — \
             note this is the fixture's soundness, not the deployed layout's, which \
             `hv-metal`'s boot-time `verify_encoding` is what checks"
        );

        // Data region moved into the SAME 1 GiB as the guest image -> one L1 entry for both.
        let mut collide = every_region_layout();
        collide.data_ipa_base = 0x4060_0000;
        assert!(matches!(
            collide.validate(),
            Err(EncodingViolation::RegionsCollide { .. })
        ));

        // Data frames backed INSIDE the 2 MiB image block -> private data aliases the shared image.
        let mut overlap = every_region_layout();
        overlap.data_pa_base = overlap.guest_image_pa.unwrap() + 0x1000;
        assert!(matches!(
            overlap.validate(),
            Err(EncodingViolation::WindowsOverlap { space: "pa" })
        ));
    }

    #[test]
    fn frame_addresses_are_linear() {
        let l = every_region_layout();
        assert_eq!(frame_pa(&l, 0), 0x4060_0000);
        assert_eq!(frame_pa(&l, 3), 0x4060_3000);
        assert_eq!(frame_ipa(&l, 0), 0x8000_0000);
        assert_eq!(frame_ipa(&l, 3), 0x8000_3000);
    }

    // ─── The representability premises (the device-path composition) ─────────────────────────────
    //
    // Each of the four below was a SILENT precondition of `encode` until the composition forced it
    // into the open, and each test does the same two things: **exhibit the mis-map** the premise
    // prevents (so the new `validate` arm is demonstrably load-bearing rather than a check that
    // could not have failed — design-lesson #71), and then show `validate` refuses it.

    /// Emit into a blank set — the `Tables` plumbing, once.
    fn emit(l: &Layout, t: &mut Blank, leaves: &[Option<Perm>], supers: &[Option<Perm>]) {
        encode(
            leaves,
            supers,
            l,
            Tables {
                l1: &mut t.0,
                l2_code: &mut t.1,
                l2_data: &mut t.2,
                l3_data: &mut t.3,
                l2_sup: &mut t.4,
                l2_dev: &mut t.5,
            },
        );
    }

    /// Walk an emitted set for `ipa`, without going through `hv-metal`'s volatile read.
    fn walk_tables(l: &Layout, t: &Blank, ipa: u64) -> Option<Reach> {
        walk(l.l1_pa, ipa, |pa, i| {
            let i = i as usize;
            if pa == l.l1_pa {
                t.0[i]
            } else if pa == l.l2_code_pa {
                t.1[i]
            } else if pa == l.l2_data_pa {
                t.2[i]
            } else if pa == l.l3_data_pa {
                t.3[i]
            } else if pa == l.l2_sup_pa {
                t.4[i]
            } else if pa == l.l2_dev_pa {
                t.5[i]
            } else {
                0
            }
        })
    }

    /// **Premise (a): an unaligned data window silently maps frame `m`'s IPA to a *different
    /// frame's* memory.** `encode` writes frame `m` at `l3_data[m]`; the walker reads
    /// `l3_data[(ipa >> 12) & 0x1ff]`. Off by one page, those differ by one — so a domain issuing
    /// frame 0's address lands on frame 1's bytes, at frame 1's permission, with no fault anywhere.
    #[test]
    fn an_unaligned_data_window_mismaps_every_frame() {
        let mut l = every_region_layout();
        l.data_ipa_base = 0x8000_1000; // one page off the block boundary
        let mut t = tables();
        // Frame 0 read-only, frame 1 read/write: the mis-map is a *permission* escalation too.
        let leaves = [Some(Perm::Ro), Some(Perm::Rw)];
        emit(&l, &mut t, &leaves, &[]);

        let asked = frame_ipa(&l, 0);
        let landed = walk_tables(&l, &t, asked).expect("it maps — that is the problem");
        assert_eq!(
            landed.pa,
            frame_pa(&l, 1),
            "frame 0's IPA must land on frame 1's bytes for this test to be about anything"
        );
        assert_eq!(landed.perm, Perm::Rw, "…and at frame 1's permission");
        assert_ne!(
            Some(landed),
            window_reach(&l, &leaves, &[], asked),
            "the walk and the layout disagree — which is exactly what validate now refuses"
        );
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::WindowUnaligned { .. })
        ));
    }

    /// **Premise (b): a super window that crosses its `L1` entry maps memory at an address nothing
    /// authorized.** `encode` writes one `L1` entry per region and indexes its `L2` with nine bits,
    /// which wraps: the frames past the boundary land in the *low* slots of the same table.
    #[test]
    fn a_super_window_that_crosses_its_l1_entry_maps_an_unauthorized_address() {
        let mut l = every_region_layout();
        // 2 MiB below a 1 GiB boundary, in the one `L1` entry no other region of this fixture
        // occupies (the image is at 1, the data window at 2, the device window at 0).
        l.sup_ipa_base = 0xFFE0_0000;
        l.sup_frames = 2;
        let mut t = tables();
        let supers = [Some(Perm::Rw), Some(Perm::Rw)];
        emit(&l, &mut t, &[], &supers);

        // Super frame 1 sits at 0x1_0000_0000 — the *next* `L1` entry, which this region never
        // wrote — so its slot wrapped to index 0 of its own `L2`, which is reached at the bottom of
        // the region's own `L1` entry: 0xC000_0000, an address the window does not cover.
        let stray = 0xC000_0000;
        let landed = walk_tables(&l, &t, stray).expect("the wrapped slot maps real memory");
        assert_eq!(landed.pa, super_pa(&l, 1));
        assert!(
            window_reach(&l, &[], &supers, stray).is_none(),
            "…at an address the layout says is a hole"
        );
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::RegionCrossesL1 { .. })
        ));
    }

    /// **Premise (c): the granule `encode` emits and the granule the layout scales by must be one
    /// number.** At any other `frame_size` the descriptor kind (an `L3` page) and the address
    /// arithmetic (`base + m * frame_size`) describe different mappings.
    #[test]
    fn a_granule_the_emitter_does_not_write_is_refused() {
        let mut l = every_region_layout();
        l.frame_size = 0x4000; // 16 KiB
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::GranuleNotEmitted { frame_size: 0x4000 })
        ));
    }

    /// **Premise (d): a table base neither register can name exactly.** `VTTBR_EL2.BADDR` and
    /// `STE.S2TTB` both *truncate*, so an over-wide base leaves both walkers walking a table
    /// `encode` never wrote — and agreeing with each other while they do it.
    #[test]
    fn a_table_base_no_register_can_name_is_refused() {
        let mut l = every_region_layout();
        l.l1_pa = 1 << 48;
        assert!(matches!(
            l.validate(),
            Err(EncodingViolation::TableUnnameable { table: "l1", .. })
        ));
        let mut m = every_region_layout();
        m.l3_data_pa += 8; // not page-aligned: the table descriptor's own mask drops it
        assert!(matches!(
            m.validate(),
            Err(EncodingViolation::TableUnnameable {
                table: "l3_data",
                ..
            })
        ));
    }

    /// **The input-address ceiling.** Nine bits per level means an address past the tables' 512 GiB
    /// reach wraps back into them; the hardware faults there and so must the walk. This is the
    /// defect `the_walk_lands_where_the_windows_say` produced on its first run, pinned as a test.
    #[test]
    fn an_address_beyond_the_addressable_space_reaches_nothing() {
        let l = every_region_layout();
        let mut t = tables();
        let supers = [Some(Perm::Rw)];
        emit(&l, &mut t, &[], &supers);

        let real = l.sup_ipa_base;
        assert!(walk_tables(&l, &t, real).is_some(), "the control");
        // The same address plus a whole addressable space: the nine-bit indices are identical.
        let aliased = real + ADDRESSABLE;
        assert_eq!(
            walk_tables(&l, &t, aliased),
            None,
            "an address beyond the tables' reach must fault, not alias back into them"
        );
        assert_eq!(window_reach(&l, &[], &supers, aliased), None);
    }
}
