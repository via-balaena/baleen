// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The SMMUv3 **stream table** — the device path's first table (SMMU arc, rung 2)
//!
//! [`arm64`](crate::arm64) answers *"which frames does a domain's CPU reach?"*. This module answers
//! the question one step earlier on the **device** path: *"which devices reach anything at all, and
//! under what configuration?"* On SMMUv3 every incoming transaction carries a **StreamID** (on PCIe,
//! the RequesterID), the SMMU indexes a **stream table** with it, and the **Stream Table Entry**
//! (STE) it lands on decides everything downstream — abort, bypass, or translate, and if translate,
//! through whose tables.
//!
//! So the stream table is where the device-side isolation decision is *made*, and it is exactly the
//! kind of decision this crate exists to hold: a pure table-building function, out of `hv-metal`'s
//! `unsafe`, host-testable and Kani-provable, with the metal keeping only the register pokes and the
//! invalidation barriers.
//!
//! ## The property rung 2 is about — and why it needs a *total* decision function
//!
//! > **∀ StreamID: unless this hypervisor deliberately bound it, the SMMU aborts its traffic.**
//!
//! "Deny by default" on a stream table is not one condition but three, and a device escapes if *any*
//! of them is wrong:
//!
//! 1. the StreamID is **outside** the configured table (`STRTAB_BASE_CFG.LOG2SIZE`) — architecturally
//!    a `C_BAD_STREAMID` abort, but only if the table is sized *smaller* than the SMMU's `SIDSIZE`
//!    rather than larger-than-allocated, which would instead walk unallocated memory;
//! 2. the STE is **invalid** (`V == 0`) — `C_BAD_STE`. This is the state a zeroed table is in, which
//!    is why "allocate zeroed" is the fail-closed default and not merely tidy;
//! 3. the STE is valid but its **`Config[2]` is clear** — an explicit abort STE.
//!
//! [`verdict`] folds all three into one **total** function over an arbitrary `(table, log2size, sid)`,
//! so there is a single place to prove the disjunction covers every StreamID. That is the same idiom
//! as I-4's `SpanConflict` ruling: make the fail-closed answer the *only* answer a total function can
//! return outside the explicitly-permitted set, then prove totality rather than argue it.
//!
//! ## What is proven here, and what is emphatically NOT
//!
//! `hv-verify::smmu_stream_table` proves, over **all 2³² StreamIDs** and every word-0 value:
//! a zeroed table denies everything; binding one StreamID leaves every *other* StreamID denied and
//! that one permitted (so the harness cannot pass by `bind` doing nothing); `bind` refuses an
//! out-of-range StreamID and writes nothing; and no word 0 with `V == 0` — nor any `Config` with bit
//! 2 clear — ever permits.
//!
//! **That is a theorem about this table builder, not about the hardware.** It says the bits are what
//! this crate says they are; it cannot say the SMMU reads them the same way. That second arrow is the
//! metal's job, and rung 2 discharges it the way GAP-A did for the descriptor emitter — by keeping
//! **emit and decode independent** ([`bypass_ste`] writes, [`verdict`] reads, neither derived from the
//! other) and then witnessing on a real machine that a device whose STE says *bypass* gets **through**
//! and the same device with a zeroed STE is **aborted**. Without that through-path witness the deny
//! result would be indistinguishable from "no device ever reached the stream table", which is the
//! vacuity trap this whole rung is built around.
//!
//! ## Scope
//!
//! Rung 2 is **linear** stream tables only (`STRTAB_BASE_CFG.FMT == 0`). SMMUv3's 2-level format
//! exists for machines with a large `SIDSIZE` where a linear table would be prohibitive; baleen sizes
//! its table to cover PCIe bus 0 and lets the architecture's own range check abort everything above,
//! which is *stronger* than a sparse 2-level table and much less code.
//!
//! ## Rung 3 — and where the module's claim changes
//!
//! Everything above is rung 2, and it **confines nothing**: the entry it binds is a bypass entry, so
//! a permitted device still puts its own addresses on memory. The second half of this module (from
//! [`Stage2Binding`] down) is rung 3, which binds a stream to a **domain** — `STE.Config = 0b110`,
//! `S2TTB` at that domain's own [`arm64`](crate::arm64) Stage-2 tables, `S2VMID` its VMID — so the
//! device is held to exactly the relation the domain's CPU is held to. The ∀-address refinement
//! covers that walk verbatim (it constrains the *table*, not the *walker*); what is proven here is
//! the **binding**, whose failure mode is not a fault but a wrong domain's memory.
//!
//! ## Rung 4b — the table becomes a REFINEMENT rather than a configuration
//!
//! Rung 3 binds *one* stream, and the metal chooses which by hand. [`derive_stream_table`] (the
//! last section of this module) makes the whole table a **pure function of `hv-core`'s proven
//! device→domain relation**, the way `build_stage2_from_p2m` makes the Stage-2 image a pure
//! function of the `p2m`. The theorem is a **biconditional** — ∀ StreamID, the table binds it *iff*
//! an assigned device carries it, to exactly that domain — because the two halves fail differently:
//! losing soundness is a device in the wrong domain's memory, losing completeness is a relation
//! that quietly does nothing. See `docs/SMMU-STREAM-DERIVATION.md`.

/// Words in one Stream Table Entry. SMMUv3 STEs are 64 bytes — 8 × `u64` — in both the linear and
/// 2-level formats.
pub const STE_WORDS: usize = 8;

/// Bytes in one Stream Table Entry.
pub const STE_BYTES: usize = STE_WORDS * 8;

/// `STE.V` (word 0, bit 0) — entry valid. Clear means `C_BAD_STE`: the transaction is terminated and
/// an event is recorded. **This is the bit that makes a zeroed table deny**, so it is the load-bearing
/// half of "allocate the stream table in `.bss`".
const STE_V: u64 = 1 << 0;

/// `STE.Config` (word 0, bits `[3:1]`).
const STE_CONFIG_SHIFT: u32 = 1;
const STE_CONFIG_MASK: u64 = 0b111;

/// `STE.Config[2]` — set on every non-aborting encoding. With it clear the SMMU aborts regardless of
/// the other two bits, which is why [`decode`] tests it before decoding stage selection.
const CONFIG_NOT_ABORT: u8 = 0b100;
/// `STE.Config` = stage 1 bypass, stage 2 bypass.
const CONFIG_BYPASS: u8 = 0b100;
/// `STE.Config` = stage 1 translate, stage 2 bypass.
const CONFIG_S1: u8 = 0b101;
/// `STE.Config` = stage 1 bypass, stage 2 translate — **rung 3's encoding**.
const CONFIG_S2: u8 = 0b110;
/// `STE.Config` = nested.
const CONFIG_NESTED: u8 = 0b111;

/// `STE.SHCFG` (word 1, bits `[45:44]`) = `0b01`, "use incoming shareability". The value Linux writes
/// for a bypass STE; without it the SMMU substitutes its own attribute, which on a coherent machine is
/// harmless but on a real one is a correctness (not isolation) hazard.
const STE_SHCFG_INCOMING: u64 = 0b01 << 44;

/// `STRTAB_BASE.ADDR` — bits `[51:6]` of the register hold bits `[51:6]` of the physical address, so the
/// table base must be at least 64-byte aligned for the write to mean what it says (see
/// [`base_alignment`] for the stronger, size-derived requirement the architecture actually imposes).
const STRTAB_BASE_ADDR_MASK: u64 = 0x000f_ffff_ffff_ffc0;

/// `STRTAB_BASE_CFG.LOG2SIZE` — bits `[5:0]`; the table covers StreamIDs `0 .. 2^LOG2SIZE`.
const STRTAB_CFG_LOG2SIZE_MASK: u32 = 0x3f;
/// `STRTAB_BASE_CFG.FMT` — bits `[17:16]`; `0b00` is the linear format this module emits.
const STRTAB_CFG_FMT_LINEAR: u32 = 0b00 << 16;

/// The stream-table size baleen deploys: `2^8` = 256 entries.
///
/// On PCIe the SMMU's StreamID is the **RequesterID** — `(bus << 8) | (device << 3) | function` — so
/// 256 entries is exactly **every function on bus 0**, the bus baleen's devices sit on. Every
/// StreamID above it falls outside the table and is denied by the architecture's own range check
/// (`C_BAD_STREAMID`), which is a *stronger* denial than an entry that merely happens to be zero.
/// Sizing to the bus rather than to the SMMU's `IDR1.SIDSIZE` (16 on this machine — a 4 MiB linear
/// table) is therefore not a shortcut.
///
/// **Declared here rather than in `hv-metal` so the proofs and the metal cannot drift** (design-lesson
/// #14c — one derivation): `hv-verify::smmu_stream_table` proves the default-deny property *at this
/// size*, and `hv-metal` allocates and configures its table from this same constant with a `const _`
/// binding the two together. A size proven in the harness but not deployed, or deployed but not
/// proven, is the gap that phrasing prevents.
pub const BUS0_LOG2SIZE: u32 = 8;

/// The largest linear table this module will build: `2^16` entries — **the entire PCIe StreamID
/// space**, since a RequesterID is 16 bits and QEMU `virt`'s `iommu-map` is the identity over it
/// (`SMMU_IDR1.SIDSIZE` reads 16 on this machine, first-hand). There is no configuration in which
/// baleen needs a *linear* table larger than "every StreamID that can exist"; anything beyond it is
/// the 2-level format's problem, which rung 2 does not implement.
///
/// A caller asking for more is a programming error, not a runtime condition — [`strtab_base_cfg`]
/// refuses rather than truncating, because a silently-truncated `LOG2SIZE` is precisely a table that
/// covers fewer StreamIDs than the builder believes, i.e. the failure this module exists to exclude.
pub const MAX_LOG2SIZE: u32 = 16;

/// What the SMMU does with a transaction carrying a given StreamID, under a given stream table.
///
/// Every variant except the last four terminates the transaction; [`StreamVerdict::permits`] is the
/// single predicate the isolation property is stated over, so that "denied" is one concept rather
/// than a list of failure codes a future variant could quietly escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamVerdict {
    /// The StreamID lies outside the configured table (`sid >= 2^log2size`), or outside the storage
    /// actually provided for it. Architecturally `C_BAD_STREAMID`; the transaction aborts.
    ///
    /// The second half — storage shorter than `log2size` claims — is a *builder* condition, not an
    /// architectural one, and it is folded in here deliberately: a table configured larger than it
    /// was allocated is the one way this scheme fails **open** on real hardware (the SMMU would fetch
    /// an STE from whatever follows the allocation), so the pure layer refuses to model it as
    /// anything but a denial and [`bind`] refuses to create it.
    OutOfRange,
    /// `STE.V == 0` — the state of a zeroed table. `C_BAD_STE`; the transaction aborts.
    Invalid,
    /// Valid STE, `Config[2] == 0` — an explicitly-configured abort.
    ConfigAbort,
    /// `Config == 0b100`: no translation at either stage. The device's address is used as a physical
    /// address. **This permits**, and rung 2 uses it as its positive control precisely because it is
    /// the weakest permitting configuration to construct — it tests that the device reaches its STE
    /// without also testing translation-table correctness.
    Bypass,
    /// `Config == 0b101`: stage 1 translates, stage 2 bypasses. Never emitted by baleen (stage 1 is a
    /// guest's own concern); decoded so the verdict function is total over the field.
    Stage1Only,
    /// `Config == 0b110`: stage 1 bypasses, stage 2 translates through `STE.S2TTB` under `S2VMID` —
    /// rung 3's encoding, where the device path joins the CPU path on one proven `p2m`.
    Stage2Only,
    /// `Config == 0b111`: both stages translate.
    Nested,
}

impl StreamVerdict {
    /// Whether the transaction reaches memory **at all**. The isolation property is stated as
    /// `!permits()` for every unbound StreamID, so every denying variant must answer `false` here and
    /// a new variant must make a deliberate choice rather than inherit one.
    #[must_use]
    pub const fn permits(self) -> bool {
        match self {
            Self::OutOfRange | Self::Invalid | Self::ConfigAbort => false,
            Self::Bypass | Self::Stage1Only | Self::Stage2Only | Self::Nested => true,
        }
    }

    /// Whether a permitted transaction reaches memory with **no stage-2 translation** — i.e. the
    /// device's own address is the physical address, so the SMMU constrains nothing about *where* it
    /// lands. True for [`Bypass`](Self::Bypass) and [`Stage1Only`](Self::Stage1Only).
    ///
    /// Rung 2's through-STE control is deliberately one of these: it proves the *path* works while
    /// making no claim about confinement. Confinement is rung 3, and conflating the two is how a
    /// "the SMMU protects us" headline gets ahead of its artifacts.
    #[must_use]
    pub const fn stage2_unconfined(self) -> bool {
        matches!(self, Self::Bypass | Self::Stage1Only)
    }
}

/// Why a stream-table update was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTableError {
    /// `sid >= 2^log2size` — the StreamID is not covered by this table.
    SidOutOfRange,
    /// The caller's storage is smaller than `2^log2size` entries, or `log2size` exceeds
    /// [`MAX_LOG2SIZE`]. Refusing here is what keeps [`StreamVerdict::OutOfRange`]'s
    /// configured-larger-than-allocated case unreachable in a table this module built.
    TableTooSmall,
    /// The **binding** could not be encoded (rung 3) — see [`SteError`]. Kept as a distinct arm
    /// rather than folded into a generic failure so that "this StreamID is not in the table" and
    /// "this domain's table cannot be named by an STE" stay different facts.
    BadBinding(SteError),
}

/// Words of storage a linear stream table of `2^log2size` entries needs.
///
/// Returns `None` when `log2size` exceeds [`MAX_LOG2SIZE`] — the caller cannot be handed a size it
/// could not have configured.
#[must_use]
pub const fn table_words(log2size: u32) -> Option<usize> {
    if log2size > MAX_LOG2SIZE {
        return None;
    }
    Some((1usize << log2size) * STE_WORDS)
}

/// The alignment SMMUv3 requires of a linear stream table's base: the larger of the table size and
/// 64 bytes.
///
/// Stated here rather than in the metal because it is a property of the table format, and because
/// getting it wrong is silent: `STRTAB_BASE` carries only bits `[51:6]`, so an under-aligned base is
/// *truncated* to a different table rather than rejected — the SMMU would then walk 64-byte-aligned
/// garbage and, being garbage, most likely deny. A deny for the wrong reason is exactly the vacuity
/// this rung is guarding against.
#[must_use]
pub const fn base_alignment(log2size: u32) -> Option<usize> {
    match table_words(log2size) {
        Some(words) => {
            let size = words * 8;
            Some(if size > STE_BYTES { size } else { STE_BYTES })
        }
        None => None,
    }
}

/// The value to write to `SMMU_STRTAB_BASE` for a table at physical address `pa`.
///
/// Masks to the register's `ADDR` field rather than asserting alignment: the mask *is* the hardware's
/// behaviour, so a caller that passes an under-aligned address gets the address the SMMU would
/// actually use, and [`base_alignment`] is what callers check against beforehand.
#[must_use]
pub const fn strtab_base(pa: u64) -> u64 {
    pa & STRTAB_BASE_ADDR_MASK
}

/// The value to write to `SMMU_STRTAB_BASE_CFG` for a **linear** table of `2^log2size` entries.
///
/// `None` when `log2size` exceeds [`MAX_LOG2SIZE`] — see the const's note on why truncation is not an
/// acceptable fallback here.
#[must_use]
pub const fn strtab_base_cfg(log2size: u32) -> Option<u32> {
    if log2size > MAX_LOG2SIZE {
        return None;
    }
    Some(STRTAB_CFG_FMT_LINEAR | (log2size & STRTAB_CFG_LOG2SIZE_MASK))
}

/// The all-zero STE: `V == 0`, hence `C_BAD_STE`, hence **deny**.
///
/// Named rather than open-coded so the fail-closed default has a place to be documented and a symbol
/// the proofs can name. It is also what `.bss` already contains, which is the point: the metal's
/// stream table is deny-by-default *before any code runs*, not after an initialisation step that
/// could be skipped.
#[must_use]
pub const fn deny_ste() -> [u64; STE_WORDS] {
    [0; STE_WORDS]
}

/// A **bypass** STE: valid, `Config = 0b100` (no translation at either stage), incoming shareability.
///
/// This is rung 2's positive control and nothing more. It permits the device to place transactions at
/// physical addresses of its own choosing — i.e. it is *not* an isolation configuration — and exists
/// so that "the DMA was aborted" can be shown to be a decision about *this* STE rather than a device
/// that never reached the stream table at all.
#[must_use]
pub const fn bypass_ste() -> [u64; STE_WORDS] {
    let mut ste = [0u64; STE_WORDS];
    ste[0] = STE_V | ((CONFIG_BYPASS as u64) << STE_CONFIG_SHIFT);
    ste[1] = STE_SHCFG_INCOMING;
    ste
}

/// Decode an STE's word 0 into the verdict the SMMU would reach for it.
///
/// Deliberately **not** derived from [`bypass_ste`]/[`deny_ste`]: this is the *decode seam*, written
/// against the architecture's field definitions, and keeping it independent of the emit seam is what
/// makes the round-trip proofs meaningful rather than tautological (design-lesson #36, and GAP-A's
/// repair of exactly this shape on the descriptor emitter).
#[must_use]
pub const fn decode(word0: u64) -> StreamVerdict {
    if word0 & STE_V == 0 {
        return StreamVerdict::Invalid;
    }
    let config = ((word0 >> STE_CONFIG_SHIFT) & STE_CONFIG_MASK) as u8;
    if config & CONFIG_NOT_ABORT == 0 {
        return StreamVerdict::ConfigAbort;
    }
    match config {
        CONFIG_BYPASS => StreamVerdict::Bypass,
        CONFIG_S1 => StreamVerdict::Stage1Only,
        CONFIG_S2 => StreamVerdict::Stage2Only,
        CONFIG_NESTED => StreamVerdict::Nested,
        // Unreachable given the `CONFIG_NOT_ABORT` test above (bit 2 set pins the value to one of the
        // four), but written as a denial rather than an `unreachable!()`: a total function whose
        // fallthrough fails *closed* cannot be turned into a panic by a future edit to the constants.
        _ => StreamVerdict::ConfigAbort,
    }
}

/// The word offset of `sid`'s entry, or `None` if this table does not cover it.
///
/// The single place the range decision is made — both the architectural bound (`sid < 2^log2size`)
/// and the builder bound (the storage really holds that many entries). Everything else in this module
/// routes through it, so there is one predicate to prove total rather than several to keep in step.
const fn entry_offset(words_len: usize, log2size: u32, sid: u32) -> Option<usize> {
    // `match` rather than `let … else`: this is a `const fn`, and the plain match is unambiguously
    // const-evaluable on every toolchain in the MSRV window.
    let needed = match table_words(log2size) {
        Some(n) => n,
        None => return None,
    };
    if words_len < needed {
        return None;
    }
    // `log2size <= MAX_LOG2SIZE <= 63` here, so the shift cannot overflow and `1 << log2size` fits.
    if (sid as u64) >= (1u64 << log2size) {
        return None;
    }
    Some((sid as usize) * STE_WORDS)
}

/// **The total decision function.** What the SMMU does with a transaction carrying `sid`, given a
/// linear stream table of `2^log2size` entries in `words`.
///
/// Total over every `(words, log2size, sid)`, and denying outside the explicitly-permitted set. This
/// is the function the ∀-StreamID property is stated over.
#[must_use]
pub fn verdict(words: &[u64], log2size: u32, sid: u32) -> StreamVerdict {
    match entry_offset(words.len(), log2size, sid) {
        None => StreamVerdict::OutOfRange,
        Some(off) => decode(words[off]),
    }
}

/// Zero every entry — deny every StreamID the table covers.
///
/// A no-op on freshly-zeroed storage (which the metal's `.bss` table already is); called anyway so
/// the deny-by-default state is *established by this module*, not inherited from a linker script that
/// a future change could stop guaranteeing.
pub fn init_deny(words: &mut [u64]) {
    words.fill(0);
}

/// Install `ste` for `sid`.
///
/// Refuses — writing nothing — when `sid` is outside the table or the storage is smaller than
/// `log2size` claims. Refusing rather than growing or truncating is the fail-closed choice: a
/// silently-dropped bind leaves the STE denying, while a silently-relocated one would authorise some
/// *other* StreamID.
///
/// The caller must invalidate the SMMU's configuration cache (`CMD_CFGI_STE` + `CMD_SYNC`) before the
/// write takes effect for in-flight streams; that is a hardware-publication obligation and lives in
/// `hv-metal`, exactly as the Stage-2 tables' `dsb`/`tlbi` does.
pub fn bind(
    words: &mut [u64],
    log2size: u32,
    sid: u32,
    ste: [u64; STE_WORDS],
) -> Result<(), StreamTableError> {
    // The two refusals are distinguished on purpose: `TableTooSmall` is a build-time mistake in this
    // hypervisor, `SidOutOfRange` a legitimate answer about a StreamID the table does not cover.
    // Collapsing them would hide the first inside the second.
    match table_words(log2size) {
        Some(needed) if words.len() >= needed => {}
        _ => return Err(StreamTableError::TableTooSmall),
    }
    let Some(off) = entry_offset(words.len(), log2size, sid) else {
        return Err(StreamTableError::SidOutOfRange);
    };
    words[off..off + STE_WORDS].copy_from_slice(&ste);
    Ok(())
}

/// Restore `sid`'s entry to [`deny_ste`]. The exact inverse of [`bind`], including its refusals.
pub fn unbind(words: &mut [u64], log2size: u32, sid: u32) -> Result<(), StreamTableError> {
    bind(words, log2size, sid, deny_ste())
}

/// Whether `words`, read as a table of `2^log2size` entries, permits **no** StreamID at all.
///
/// A runtime companion to the Kani property, in the shape [`crate::arm64::verify_encoding`] set: read
/// the emitted table back through the *decode* seam and assert it means what the builder intended.
/// The metal calls it on the real table so a green boot witnesses the deny-by-default state of the
/// bytes the SMMU will actually walk — not of the bytes the builder believes it wrote.
#[must_use]
pub fn denies_every_stream(words: &[u64], log2size: u32) -> bool {
    match table_words(log2size) {
        None => false,
        Some(needed) => {
            if words.len() < needed {
                return false;
            }
            (0..(1u32 << log2size)).all(|sid| !verdict(words, log2size, sid).permits())
        }
    }
}

/// The StreamIDs this table permits, as a count. Used by the metal to witness "exactly one stream is
/// bound, and it is the one we bound" rather than merely "the one we bound is bound" — the difference
/// between a check that can fail and one that cannot.
#[must_use]
pub fn permitted_stream_count(words: &[u64], log2size: u32) -> usize {
    match table_words(log2size) {
        None => 0,
        Some(needed) if words.len() < needed => 0,
        Some(_) => (0..(1u32 << log2size))
            .filter(|&sid| verdict(words, log2size, sid).permits())
            .count(),
    }
}

// ─── Rung 3: binding a stream to a DOMAIN — `STE.Config = 0b110`, `S2TTB`, `S2VMID` ──────────────
//
// Rung 2 ends at "nothing reaches memory unless this hypervisor bound its StreamID". It confines
// nothing: the entry it binds is a BYPASS entry, and a bypassing device places its own addresses
// directly on memory. Rung 3 is where the device path gets a constraint at all, and the constraint
// is the one the CPU path already has — the domain's own [`crate::arm64`] Stage-2 tables, under the
// domain's VMID.
//
// **The new surface, stated precisely.** The ∀-address refinement carries over verbatim: it
// constrains the TABLE, not the WALKER, so a device walking a domain's table is covered by
// construction. What is NOT covered by anything before this rung is the **binding** — that the entry
// for StreamID X names domain D's table under D's VMID and nothing else. That is the exact analogue
// of the `VTTBR_EL2` install, and the failure mode is not a fault but a *wrong domain's memory*.

/// `STE.S2VMID` (word 2, bits `[15:0]`).
const STE2_S2VMID_MASK: u64 = 0xffff;
/// `STE.S2T0SZ` (word 2, bits `[37:32]`).
const STE2_S2T0SZ_SHIFT: u32 = 32;
/// `STE.S2SL0` (word 2, bits `[39:38]`).
const STE2_S2SL0_SHIFT: u32 = 38;
/// `STE.S2IR0` (word 2, bits `[41:40]`).
const STE2_S2IR0_SHIFT: u32 = 40;
/// `STE.S2OR0` (word 2, bits `[43:42]`).
const STE2_S2OR0_SHIFT: u32 = 42;
/// `STE.S2SH0` (word 2, bits `[45:44]`).
const STE2_S2SH0_SHIFT: u32 = 44;
/// `STE.S2TG` (word 2, bits `[47:46]`).
const STE2_S2TG_SHIFT: u32 = 46;
/// `STE.S2PS` (word 2, bits `[50:48]`).
const STE2_S2PS_SHIFT: u32 = 48;
/// `STE.S2AA64` (word 2, bit 51) — the stage-2 tables are AArch64 (VMSAv8-64) format. Clear would
/// mean AArch32 LPAE, which [`crate::arm64`] does not emit, so this bit is not optional.
const STE2_S2AA64: u64 = 1 << 51;
/// `STE.S2PTW` (word 2, bit 54) — fault rather than proceed if a stage-2 table walk lands on
/// Device memory. A walk that reads MMIO as descriptors is a walker following attacker-shaped bytes;
/// set, because the alternative is "whatever that device returned is now a page table".
const STE2_S2PTW: u64 = 1 << 54;
/// `STE.S2S` (word 2, bit 57) — stall on a stage-2 fault. **Left clear**: baleen has no
/// fault-resumption path (EL2's handler is `-> !` by design), a stalled transaction would wedge the
/// device, and QEMU's SMMUv3 rejects the bit outright.
#[allow(dead_code)]
const STE2_S2S: u64 = 1 << 57;
/// `STE.S2R` (word 2, bit 58) — **record** stage-2 faults on the event queue.
///
/// Load-bearing for the witness rather than for the isolation: with it clear a denied transaction is
/// still denied, but silently, and every rung-3 denial would have to be inferred from a sentinel that
/// did not change instead of attributed to a fault record naming its class and address
/// (design-lesson #70(d)).
const STE2_S2R: u64 = 1 << 58;
/// `STE.S2TTB` (word 3, bits `[51:4]`) — the stage-2 start-level table's physical base.
const STE3_S2TTB_MASK: u64 = 0x000f_ffff_ffff_fff0;

/// Which domain's memory a stream reaches: the domain's stage-2 table, its VMID, and the regime both
/// walkers read that table under.
///
/// A `Stage2Binding` is the device-side twin of a `VTTBR_EL2` value plus its `VTCR_EL2` — and it is
/// spelled as one value for the same reason the regime is: the three parts are only meaningful
/// together, and a mismatch between any two of them is a device reaching memory the table never
/// authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2Binding {
    /// Physical base of the domain's start-level stage-2 table — the same table `VTTBR_EL2` carries
    /// for that domain's CPU.
    pub s2ttb: u64,
    /// The domain's VMID — the same value `VTTBR_EL2[55:48]` carries, obtained by reading it back
    /// out of that register's value ([`crate::arm64::vttbr_vmid`]) so it is masked to the width the
    /// CPU actually tags with. `u16` because that is exactly what `STE.S2VMID` holds.
    pub vmid: u16,
    /// The translation regime, shared with the CPU ([`crate::arm64::Stage2Regime`]).
    pub regime: crate::arm64::Stage2Regime,
}

/// Why a stage-2 STE could not be built. Every variant is a **refusal to encode**, never a
/// truncation: each of these fields silently drops bits if written oversized, and a truncated
/// `S2TTB` names a *different table*, i.e. a different domain's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteError {
    /// The regime is not one a walker can be configured with
    /// ([`crate::arm64::Stage2Regime::valid`]).
    BadRegime,
    /// The granule is one whose `STE.S2TG` encoding this crate does not state — see
    /// [`stage2_ste`]'s note. Only 4 KiB is emitted.
    GranuleNotEmitted,
    /// `s2ttb` is not aligned as the regime requires
    /// ([`crate::arm64::Stage2Regime::table_align`]), so the field would name a different table.
    UnalignedTable,
    /// `s2ttb` has bits above the field, so the field would name a different table.
    TableAddressTooLarge,
}

/// **The stage-2 STE for a binding** — `Config = 0b110` (stage 1 bypass, stage 2 translate).
///
/// This is the emit seam. [`decode_stage2_binding`] is the decode seam, written from the field
/// definitions rather than from this function, so the round-trip proofs in
/// `hv-verify::smmu_stream_table` are statements about two independent readings of the architecture
/// (design-lesson #36).
///
/// **The granule refusal is deliberate, and it is a `#71` guard.** `VTCR_EL2.TG0` encodes
/// 4 K/64 K/16 K as `0b00/0b01/0b10`; `STE.S2TG`'s encoding for the two large granules is *not*
/// something this crate has verified against the hardware it runs on. At baleen's 4 KiB granule both
/// fields are `0b00`, so a copied-across encoding would be indistinguishable from a correct one — a
/// check whose inputs cannot discriminate. Rather than ship an unverified mapping under a proof that
/// would then be proving the wrong thing, the encoder **refuses** every granule but 4 KiB, and the
/// refusal is itself proven total.
pub fn stage2_ste(b: &Stage2Binding) -> Result<[u64; STE_WORDS], SteError> {
    use crate::arm64::Granule;

    if !b.regime.valid() {
        return Err(SteError::BadRegime);
    }
    if !matches!(b.regime.granule, Granule::K4) {
        return Err(SteError::GranuleNotEmitted);
    }
    // Order matters only for which error a doubly-wrong address reports; both refuse.
    if b.s2ttb >> 52 != 0 {
        return Err(SteError::TableAddressTooLarge);
    }
    // The regime's alignment is at least 64 bytes, so this subsumes the field's own 16-byte
    // granularity: an address that survives it loses no bits to `STE3_S2TTB_MASK`.
    if !b.s2ttb.is_multiple_of(b.regime.table_align()) {
        return Err(SteError::UnalignedTable);
    }
    let mut ste = [0u64; STE_WORDS];
    ste[0] = STE_V | ((CONFIG_S2 as u64) << STE_CONFIG_SHIFT);
    ste[1] = STE_SHCFG_INCOMING;
    ste[2] = (u64::from(b.vmid) & STE2_S2VMID_MASK)
        | (b.regime.t0sz() << STE2_S2T0SZ_SHIFT)
        | (b.regime.start_level.sl0() << STE2_S2SL0_SHIFT)
        | (b.regime.walk_inner << STE2_S2IR0_SHIFT)
        | (b.regime.walk_outer << STE2_S2OR0_SHIFT)
        | (b.regime.walk_shareability << STE2_S2SH0_SHIFT)
        // 4 KiB — the only granule this encoder emits (see the note above).
        | (0b00 << STE2_S2TG_SHIFT)
        | (b.regime.pa_size.ps() << STE2_S2PS_SHIFT)
        | STE2_S2AA64
        | STE2_S2PTW
        | STE2_S2R;
    ste[3] = b.s2ttb & STE3_S2TTB_MASK;
    Ok(ste)
}

/// Read an STE back as the binding it expresses — **the decode seam**.
///
/// `None` unless the entry really is a stage-2 translating entry whose fields name a regime this
/// crate recognizes. Total over arbitrary words, because the entry the SMMU walks is memory, and
/// "memory this hypervisor did not write" is exactly the case a fail-closed reading must cover.
#[must_use]
pub fn decode_stage2_binding(ste: &[u64]) -> Option<Stage2Binding> {
    use crate::arm64::{Granule, PaSize, Stage2Regime, StartLevel};

    if ste.len() < STE_WORDS {
        return None;
    }
    if decode(ste[0]) != StreamVerdict::Stage2Only {
        return None;
    }
    let w2 = ste[2];
    if w2 & STE2_S2AA64 == 0 {
        return None;
    }
    // Only the 4 KiB encoding is emitted, so only it is read back (see `stage2_ste`).
    if (w2 >> STE2_S2TG_SHIFT) & 0b11 != 0b00 {
        return None;
    }
    let regime = Stage2Regime {
        granule: Granule::K4,
        ipa_bits: 64 - (((w2 >> STE2_S2T0SZ_SHIFT) & 0x3f) as u32),
        start_level: StartLevel::from_sl0((w2 >> STE2_S2SL0_SHIFT) & 0b11)?,
        pa_size: PaSize::from_ps((w2 >> STE2_S2PS_SHIFT) & 0b111)?,
        walk_shareability: (w2 >> STE2_S2SH0_SHIFT) & 0b11,
        walk_inner: (w2 >> STE2_S2IR0_SHIFT) & 0b11,
        walk_outer: (w2 >> STE2_S2OR0_SHIFT) & 0b11,
    };
    if !regime.valid() {
        return None;
    }
    Some(Stage2Binding {
        s2ttb: ste[3] & STE3_S2TTB_MASK,
        vmid: (w2 & STE2_S2VMID_MASK) as u16,
        regime,
    })
}

/// The binding `sid` reaches memory through, or `None` if it reaches none.
///
/// The device-path analogue of "which `VTTBR_EL2` is installed", and the predicate the
/// stream→domain binding property is stated over: after binding `sid` to domain `D`, this must
/// answer `D` for `sid` and `None` for every other StreamID.
#[must_use]
pub fn stage2_binding_at(words: &[u64], log2size: u32, sid: u32) -> Option<Stage2Binding> {
    let off = entry_offset(words.len(), log2size, sid)?;
    decode_stage2_binding(&words[off..off + STE_WORDS])
}

/// Bind `sid` to a domain: install the stage-2 STE for `b`.
///
/// Refuses — writing nothing — for the same reasons [`bind`] does, plus every [`SteError`]. Both
/// classes are fail-closed and for one reason: a partially-written or truncated binding is not a
/// weaker permission, it is a **different domain's memory**.
pub fn bind_stage2(
    words: &mut [u64],
    log2size: u32,
    sid: u32,
    b: &Stage2Binding,
) -> Result<(), StreamTableError> {
    let ste = stage2_ste(b).map_err(StreamTableError::BadBinding)?;
    bind(words, log2size, sid, ste)
}

// ─── Rung 4b: DERIVING the whole table from the model's assignment relation ──────────────────────
//
// Rung 3 binds one stream to one domain, and the metal calls `bind_stage2` **by hand**. So the
// relation `hv-core` proves (`docs/SMMU-DEVICE-ASSIGNMENT.md` — which domain holds which device,
// swept on teardown, `assigned ⇒ Live`) has no consumer, and the hardware's answer to "whose memory
// may this bus master write?" is still a hand-written configuration that nothing checks against it.
//
// This is the arrow between them, and it is the device-axis twin of `build_stage2_from_p2m`: the
// whole stream table becomes a **pure function of the proven relation**, so the table is a
// REFINEMENT of it rather than a parallel copy. The theorem is stated as a **biconditional** —
// `check_authorized`'s shape one level out — because a one-directional theorem is the weaker rung:
//
// > ∀ StreamID: the table binds it **iff** an assigned device carries it, to exactly that domain.
//
// * **soundness** (⇐) is rung 2's ∀-StreamID default-deny surviving derivation: a StreamID no
//   assigned device carries reaches nothing, so building the table can only *narrow* the answer;
// * **completeness** (⇒) is that every assignment is realized: a device the model says belongs to
//   `d` really does walk `d`'s tables, so the relation is not quietly a no-op.

use hv_core::device::{DevId, DomId, System as DeviceSystem};

/// The largest device population the ∀-values proofs instantiate.
///
/// Declared here rather than in the harness so `hv-metal`'s `NUM_DEVICES` can be pinned against it
/// with a `const _` (design-lesson #71(c) — a size proven but not shipped, or shipped but not
/// proven, is a build error). Kani makes the whole assignment vector symbolic, which means the
/// device axis is the one it must unwind; two is enough for every property here to have content
/// (aliasing, "exactly one entry moved", one device swept while another is spared) and the metal
/// drives exactly one bus master.
pub const MAX_PROVEN_DEVICES: usize = 2;

/// Why a stream table could not be derived from the assignment relation.
///
/// Every variant is a **refusal**, and every refusal leaves the table **denying every StreamID** —
/// not merely denying the device that could not be represented. Two arms rather than N is what
/// makes the postcondition statable: either `Ok` and the biconditional holds exactly, or `Err` and
/// nothing reaches memory at all. The caller is expected to treat any of these as fatal (the metal
/// publishes the denying table and halts): a model that authorizes something the hardware cannot be
/// configured to express is not a weaker configuration, it is a *silent* divergence between the
/// relation and the machine — and the over-conservative direction is the one no invariant checks
/// (design-lesson #79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    /// `stream_of` does not cover every device the model carries — the metal cannot name the
    /// StreamID of a bus master the model can assign.
    StreamMapTooShort,
    /// `binding_of` does not cover every domain slot the model carries.
    BindingMapTooShort,
    /// Two devices present the **same** StreamID.
    ///
    /// This is the premise rung 4a's exclusivity rests on and does not itself establish. The model
    /// makes "two holders for one device" *unrepresentable* (one `Option<DomId>` per device), but
    /// that refines to exclusivity **in the hardware** only if the `DevId → StreamID` map is
    /// injective: two devices sharing a StreamID collapse onto one STE, so whichever is bound last
    /// silently decides where *both* land. Unreachable at one device, and exactly the kind of
    /// premise that goes unstated until a second bus master arrives.
    StreamAliased { a: DevId, b: DevId },
    /// A device is assigned to a domain for which no [`Stage2Binding`] is registered — the domain
    /// has no Stage-2 tables the device could be pointed at. Refused, never approximated: there is
    /// no "smaller permission" to fall back to, only a different domain's memory.
    NoBinding(DomId),
    /// An assigned device's StreamID lies outside the table this hypervisor built.
    SidOutOfRange(u32),
    /// The domain's binding cannot be named exactly by an STE — see [`SteError`].
    Unencodable(SteError),
    /// The storage is smaller than `log2size` claims.
    TableTooSmall,
}

/// **What the relation says StreamID `sid` must reach** — the *specification* seam.
///
/// Written as a search over the relation, deliberately **not** derived from
/// [`derive_stream_table`]'s loop, for the same reason [`decode`] is not derived from
/// [`bypass_ste`] (design-lesson #36): the biconditional is then a statement relating three
/// independent readings — this one says what *should* be there, `derive_stream_table` writes, and
/// [`stage2_binding_at`] reads the bytes back.
///
/// `None` means "no assigned device carries this StreamID", which the table must express as a
/// **denial**. At most one device can match once [`derive_stream_table`] has accepted the map
/// (it refuses a non-injective one), so the first match is the only match.
#[must_use]
pub fn intended_binding(
    devices: &DeviceSystem,
    stream_of: &[u32],
    binding_of: &[Option<Stage2Binding>],
    sid: u32,
) -> Option<Stage2Binding> {
    let mut dev = 0usize;
    while dev < devices.device_count() {
        if stream_of.get(dev).copied() == Some(sid) {
            if let Some(holder) = devices.holder_of(dev as DevId) {
                return binding_of.get(holder as usize).copied().flatten();
            }
            return None;
        }
        dev += 1;
    }
    None
}

/// **Derive the whole stream table from the assignment relation.** The device-axis twin of
/// `build_stage2_from_p2m`.
///
/// `stream_of` is the `DevId → StreamID` map and `binding_of` the `DomId → Stage2Binding` map: the
/// two things this layer must be *told* rather than compute. `hv-core` cannot name a StreamID (a
/// device is an opaque token there, exactly as a frame is), and this crate cannot compute one — it
/// only indexes with the number the metal hands it, which is what keeps one proven relation able to
/// serve an SMMU, an x86 IOMMU or a fixed device tree.
///
/// **Total, and fail-closed in one direction only.** The table is zeroed *first*, so every refusal
/// path below leaves it denying every StreamID; on `Ok` the biconditional in this section's header
/// holds exactly. It is deliberately all-or-nothing: a derivation that bound the devices it *could*
/// represent and quietly dropped the rest would leave a table nothing describes.
///
/// The caller owes the hardware-publication half (`CMD_CFGI_STE` + `CMD_SYNC`, and the stage-2 TLB
/// invalidation when a stream's tables change), exactly as [`bind`] does.
pub fn derive_stream_table(
    words: &mut [u64],
    log2size: u32,
    devices: &DeviceSystem,
    stream_of: &[u32],
    binding_of: &[Option<Stage2Binding>],
) -> Result<(), DeriveError> {
    // Deny FIRST: every `return Err` below is then already fail-closed, and there is no ordering in
    // which a refusal leaves a previously-derived entry standing.
    init_deny(words);

    match table_words(log2size) {
        Some(needed) if words.len() >= needed => {}
        _ => return Err(DeriveError::TableTooSmall),
    }

    let ndev = devices.device_count();
    if stream_of.len() < ndev {
        return Err(DeriveError::StreamMapTooShort);
    }
    if binding_of.len() < devices.domain_count() {
        return Err(DeriveError::BindingMapTooShort);
    }

    // Injectivity of the fence crossing — see [`DeriveError::StreamAliased`]. Checked over the
    // whole map rather than only over assigned devices: a map that aliases is a mistake in this
    // hypervisor's device table, not a runtime condition, and it should be refused before it
    // happens to matter.
    let mut a = 0usize;
    while a < ndev {
        let mut b = a + 1;
        while b < ndev {
            if stream_of[a] == stream_of[b] {
                init_deny(words);
                return Err(DeriveError::StreamAliased {
                    a: a as DevId,
                    b: b as DevId,
                });
            }
            b += 1;
        }
        a += 1;
    }

    let mut dev = 0usize;
    while dev < ndev {
        if let Some(holder) = devices.holder_of(dev as DevId) {
            let Some(binding) = binding_of[holder as usize] else {
                init_deny(words);
                return Err(DeriveError::NoBinding(holder));
            };
            if let Err(e) = bind_stage2(words, log2size, stream_of[dev], &binding) {
                init_deny(words);
                return Err(match e {
                    StreamTableError::BadBinding(e) => DeriveError::Unencodable(e),
                    StreamTableError::SidOutOfRange => DeriveError::SidOutOfRange(stream_of[dev]),
                    StreamTableError::TableTooSmall => DeriveError::TableTooSmall,
                });
            }
        }
        dev += 1;
    }
    Ok(())
}

/// Whether the bytes in `words` say **exactly** what the relation says, for every StreamID the
/// table covers — the runtime companion to the Kani biconditional, in the shape
/// [`denies_every_stream`] and `crate::arm64::verify_encoding` set.
///
/// Read back through the *decode* seam and compared against the *specification* seam, so a green
/// boot witnesses the derivation over the bytes the SMMU will actually walk rather than over the
/// builder's own bookkeeping. Both directions, in one predicate: an entry the relation does not
/// authorize is as much a failure as an assignment that was not realized.
#[must_use]
pub fn table_refines_the_relation(
    words: &[u64],
    log2size: u32,
    devices: &DeviceSystem,
    stream_of: &[u32],
    binding_of: &[Option<Stage2Binding>],
) -> bool {
    match table_words(log2size) {
        None => false,
        Some(needed) if words.len() < needed => false,
        Some(_) => (0..(1u32 << log2size)).all(|sid| {
            let want = intended_binding(devices, stream_of, binding_of, sid);
            // The binding must match — AND a table that permitted the stream by some *other*
            // encoding (a bypass entry, say) would satisfy `stage2_binding_at(..) == None` while
            // still letting the device reach memory unconfined, so permission is checked too.
            stage2_binding_at(words, log2size, sid) == want
                && verdict(words, log2size, sid).permits() == want.is_some()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table size the metal actually deploys.
    const LOG2: u32 = BUS0_LOG2SIZE;

    fn table() -> [u64; 256 * STE_WORDS] {
        [0; 256 * STE_WORDS]
    }

    #[test]
    fn zeroed_table_denies_everything_it_covers() {
        let t = table();
        assert!(denies_every_stream(&t, LOG2));
        assert_eq!(permitted_stream_count(&t, LOG2), 0);
    }

    #[test]
    fn bind_permits_exactly_one_stream() {
        let mut t = table();
        bind(&mut t, LOG2, 8, bypass_ste()).unwrap();
        assert_eq!(verdict(&t, LOG2, 8), StreamVerdict::Bypass);
        assert_eq!(verdict(&t, LOG2, 9), StreamVerdict::Invalid);
        assert_eq!(permitted_stream_count(&t, LOG2), 1);
        assert!(!denies_every_stream(&t, LOG2));
    }

    #[test]
    fn unbind_restores_the_deny() {
        let mut t = table();
        bind(&mut t, LOG2, 8, bypass_ste()).unwrap();
        unbind(&mut t, LOG2, 8).unwrap();
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn out_of_range_streams_are_denied_and_unbindable() {
        let mut t = table();
        let beyond = 1u32 << LOG2;
        assert_eq!(verdict(&t, LOG2, beyond), StreamVerdict::OutOfRange);
        assert_eq!(verdict(&t, LOG2, u32::MAX), StreamVerdict::OutOfRange);
        assert_eq!(
            bind(&mut t, LOG2, beyond, bypass_ste()),
            Err(StreamTableError::SidOutOfRange)
        );
        assert!(denies_every_stream(&t, LOG2));
    }

    /// Storage shorter than `log2size` claims is the one way this scheme could fail *open* on real
    /// hardware — the SMMU would fetch STEs from beyond the allocation. The pure layer refuses to
    /// model it as anything but a denial, and refuses to create it.
    #[test]
    fn a_table_smaller_than_its_configured_size_denies_and_refuses() {
        let mut small = [0u64; STE_WORDS]; // one entry, configured as 64
        assert_eq!(verdict(&small, LOG2, 0), StreamVerdict::OutOfRange);
        assert_eq!(
            bind(&mut small, LOG2, 0, bypass_ste()),
            Err(StreamTableError::TableTooSmall)
        );
        assert!(!denies_every_stream(&small, LOG2));
    }

    #[test]
    fn the_decode_seam_agrees_with_the_emit_seam() {
        assert_eq!(decode(deny_ste()[0]), StreamVerdict::Invalid);
        assert_eq!(decode(bypass_ste()[0]), StreamVerdict::Bypass);
        assert!(!decode(deny_ste()[0]).permits());
        assert!(decode(bypass_ste()[0]).permits());
        // A valid STE whose Config[2] is clear aborts — the third denial arm, which neither
        // constructor produces and which therefore has no other test.
        assert_eq!(decode(STE_V), StreamVerdict::ConfigAbort);
        assert_eq!(decode(STE_V | (0b011 << 1)), StreamVerdict::ConfigAbort);
    }

    /// The rung-3 binding: a domain's table, a domain's VMID, the CPU's own regime.
    fn binding(s2ttb: u64, vmid: u16) -> Stage2Binding {
        Stage2Binding {
            s2ttb,
            vmid,
            regime: crate::arm64::BALEEN_STAGE2,
        }
    }

    #[test]
    fn a_stage2_bind_names_exactly_one_domain() {
        let mut t = table();
        let d = binding(0x4010_0000, 1);
        bind_stage2(&mut t, LOG2, 8, &d).unwrap();
        assert_eq!(verdict(&t, LOG2, 8), StreamVerdict::Stage2Only);
        assert!(verdict(&t, LOG2, 8).permits());
        // The whole point of rung 3: permitted, and NOT unconfined.
        assert!(!verdict(&t, LOG2, 8).stage2_unconfined());
        assert_eq!(stage2_binding_at(&t, LOG2, 8), Some(d));
        // Every other stream still reaches nothing at all.
        assert_eq!(stage2_binding_at(&t, LOG2, 9), None);
        assert_eq!(verdict(&t, LOG2, 9), StreamVerdict::Invalid);
        assert_eq!(permitted_stream_count(&t, LOG2), 1);
    }

    #[test]
    fn rebinding_replaces_the_domain_completely() {
        let mut t = table();
        bind_stage2(&mut t, LOG2, 8, &binding(0x4010_0000, 1)).unwrap();
        let other = binding(0x4020_0000, 2);
        bind_stage2(&mut t, LOG2, 8, &other).unwrap();
        assert_eq!(stage2_binding_at(&t, LOG2, 8), Some(other));
        assert_eq!(permitted_stream_count(&t, LOG2), 1);
        // …and unbinding is still the true inverse.
        unbind(&mut t, LOG2, 8).unwrap();
        assert_eq!(stage2_binding_at(&t, LOG2, 8), None);
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn a_binding_that_cannot_be_named_exactly_is_refused() {
        let mut t = table();
        // Under-aligned: the field would name a DIFFERENT table.
        assert_eq!(
            bind_stage2(&mut t, LOG2, 8, &binding(0x4010_0040, 1)),
            Err(StreamTableError::BadBinding(SteError::UnalignedTable))
        );
        // Beyond the field.
        assert_eq!(
            bind_stage2(&mut t, LOG2, 8, &binding(1 << 52, 1)),
            Err(StreamTableError::BadBinding(SteError::TableAddressTooLarge))
        );
        // A granule whose `S2TG` encoding this crate does not state.
        let mut regime = crate::arm64::BALEEN_STAGE2;
        regime.granule = crate::arm64::Granule::K64;
        regime.ipa_bits = 43;
        regime.start_level = crate::arm64::StartLevel::L1;
        assert!(
            regime.valid(),
            "the regime itself is fine — the ENCODING is not"
        );
        assert_eq!(
            stage2_ste(&Stage2Binding {
                s2ttb: 0x4010_0000,
                vmid: 1,
                regime
            }),
            Err(SteError::GranuleNotEmitted)
        );
        // Every refusal left the table denying.
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn the_stage2_entry_carries_the_fields_the_smmu_reads() {
        let ste = stage2_ste(&binding(0x4010_0000, 1)).unwrap();
        // Config = 0b110, valid.
        assert_eq!(ste[0], 1 | (0b110 << 1));
        // Word 2's stage-2 configuration is the same 19-bit picture `VTCR_EL2[18:0]` paints, at
        // bit 32 — the agreement `hv-verify` proves for every regime.
        let vtcr =
            crate::arm64::vtcr_el2(&crate::arm64::BALEEN_STAGE2, crate::arm64::BALEEN_VMID_BITS)
                .unwrap();
        assert_eq!((ste[2] >> 32) & 0x7_ffff, vtcr & 0x7_ffff);
        assert_eq!(ste[2] & 0xffff, 1, "S2VMID");
        assert_ne!(ste[2] & (1 << 58), 0, "S2R: faults must be RECORDED");
        assert_eq!(ste[2] & (1 << 57), 0, "S2S: never stall");
        assert_eq!(ste[3], 0x4010_0000);
    }

    // ─── Rung 4b: derivation from the relation ────────────────────────────────────────────────

    /// Two devices, four domain slots — the fixture the derivation tests share.
    fn devices() -> DeviceSystem {
        DeviceSystem::new(4, 2)
    }

    /// StreamIDs the metal would hand over: device 0 at 8 (`edu`'s slot), device 1 at 16.
    const STREAMS: [u32; 2] = [8, 16];

    fn bindings() -> [Option<Stage2Binding>; 4] {
        [
            None,
            Some(binding(0x4010_0000, 1)),
            Some(binding(0x4020_0000, 2)),
            None,
        ]
    }

    #[test]
    fn an_unassigned_relation_derives_the_deny_table() {
        let mut t = table();
        let d = devices();
        let b = bindings();
        assert_eq!(derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b), Ok(()));
        assert!(denies_every_stream(&t, LOG2));
        assert!(table_refines_the_relation(&t, LOG2, &d, &STREAMS, &b));
    }

    #[test]
    fn an_assignment_becomes_exactly_one_binding() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        assert_eq!(derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b), Ok(()));
        assert_eq!(stage2_binding_at(&t, LOG2, 8), b[1]);
        assert_eq!(permitted_stream_count(&t, LOG2), 1);
        // The other device's StreamID is untouched — the derivation is per-assignment.
        assert_eq!(stage2_binding_at(&t, LOG2, 16), None);
        assert!(table_refines_the_relation(&t, LOG2, &d, &STREAMS, &b));
    }

    #[test]
    fn the_teardown_sweep_is_what_takes_the_binding_away() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        d.assign(1, 2).unwrap();
        derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b).unwrap();
        assert_eq!(permitted_stream_count(&t, LOG2), 2);

        // Domain 1 dies: `release_all_of` is the model's whole mechanism, and re-deriving is the
        // metal's whole mechanism. Together they are the property — and domain 2 keeps its device,
        // which is the over-sweep direction nothing else would notice (design-lesson #79).
        d.release_all_of(1);
        derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b).unwrap();
        assert_eq!(stage2_binding_at(&t, LOG2, 8), None);
        assert_eq!(stage2_binding_at(&t, LOG2, 16), b[2]);
        assert!(table_refines_the_relation(&t, LOG2, &d, &STREAMS, &b));
    }

    #[test]
    fn a_reassignment_leaves_no_trace_of_the_previous_domain() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b).unwrap();
        d.release(0, 1).unwrap();
        d.assign(0, 2).unwrap();
        derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b).unwrap();
        assert_eq!(stage2_binding_at(&t, LOG2, 8), b[2]);
        assert_eq!(permitted_stream_count(&t, LOG2), 1);
    }

    #[test]
    fn a_holder_with_no_stage2_binding_denies_everything_and_says_so() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        // Domain 3 is a live slot with no emitted Stage-2 tables.
        d.assign(0, 3).unwrap();
        d.assign(1, 2).unwrap();
        assert_eq!(
            derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b),
            Err(DeriveError::NoBinding(3))
        );
        // All-or-nothing: device 1's perfectly representable binding is gone too.
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn a_non_injective_stream_map_is_refused() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        assert_eq!(
            derive_stream_table(&mut t, LOG2, &d, &[8, 8], &b),
            Err(DeriveError::StreamAliased { a: 0, b: 1 })
        );
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn a_streamid_outside_the_table_is_refused_not_wrapped() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        let beyond = 1u32 << LOG2;
        assert_eq!(
            derive_stream_table(&mut t, LOG2, &d, &[beyond, 16], &b),
            Err(DeriveError::SidOutOfRange(beyond))
        );
        assert!(denies_every_stream(&t, LOG2));
    }

    #[test]
    fn a_short_stream_map_is_refused() {
        let mut t = table();
        let d = devices();
        let b = bindings();
        assert_eq!(
            derive_stream_table(&mut t, LOG2, &d, &[8], &b),
            Err(DeriveError::StreamMapTooShort)
        );
        assert_eq!(
            derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b[..1]),
            Err(DeriveError::BindingMapTooShort)
        );
    }

    /// The check the metal runs on the real table every derivation: it must be able to FAIL, or a
    /// green boot witnesses nothing (design-lesson #66).
    #[test]
    fn the_refinement_check_notices_a_table_that_does_not_match() {
        let mut t = table();
        let mut d = devices();
        let b = bindings();
        d.assign(0, 1).unwrap();
        derive_stream_table(&mut t, LOG2, &d, &STREAMS, &b).unwrap();
        assert!(table_refines_the_relation(&t, LOG2, &d, &STREAMS, &b));

        // An entry the relation does not authorize — the soundness direction.
        let mut extra = t;
        bind_stage2(&mut extra, LOG2, 16, &binding(0x4020_0000, 2)).unwrap();
        assert!(!table_refines_the_relation(&extra, LOG2, &d, &STREAMS, &b));

        // An assignment that was not realized — the completeness direction.
        let mut missing = t;
        unbind(&mut missing, LOG2, 8).unwrap();
        assert!(!table_refines_the_relation(
            &missing, LOG2, &d, &STREAMS, &b
        ));

        // Permitted, but UNCONFINED: a bypass entry has no binding to decode, so a check that only
        // compared bindings would call this a match. It permits and the relation does not.
        let mut bypassed = t;
        bind(&mut bypassed, LOG2, 16, bypass_ste()).unwrap();
        assert!(!table_refines_the_relation(
            &bypassed, LOG2, &d, &STREAMS, &b
        ));
    }

    #[test]
    fn register_encodings_are_what_the_fields_say() {
        assert_eq!(strtab_base_cfg(LOG2), Some(8));
        assert_eq!(strtab_base_cfg(MAX_LOG2SIZE + 1), None);
        assert_eq!(strtab_base(0x4000_1234), 0x4000_1200);
        assert_eq!(base_alignment(LOG2), Some(256 * STE_BYTES));
        assert_eq!(base_alignment(0), Some(STE_BYTES));
        assert_eq!(table_words(LOG2), Some(256 * STE_WORDS));
        assert_eq!(table_words(MAX_LOG2SIZE + 1), None);
    }
}
