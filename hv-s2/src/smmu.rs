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
//! which is *stronger* than a sparse 2-level table and much less code. The stage-2 STE fields
//! (`S2TTB`, `S2VMID`, `S2T0SZ` …) that bind a stream to a domain's [`arm64`](crate::arm64) tables are
//! rung 3; nothing here translates.

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
