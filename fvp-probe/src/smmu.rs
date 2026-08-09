// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Enough SMMUv3 to ask it a question: **does it cache translations, and does invalidation matter?**
//!
//! ## Why this drives no device
//!
//! The obvious instrument was Arm's own `SMMUv3TestEngine` — program a DMA, see where the bytes
//! land. **Its programming model could not be obtained from any source available here:** the bundled
//! Fast Models guide (§4.7.36) lists the component's ports and CADI targets and stops, Arm's web
//! documentation renders client-side so it cannot be fetched, and the model's own introspection
//! reports `numRegs=0` for every test-engine instance. Three sources, no register map.
//!
//! ★ **So this uses ATOS instead — the SMMU's Address Translation Operations interface** — and it is
//! not a consolation prize. Write a StreamID and an address, poll, read back the physical address:
//! the *translation itself* is the observable, rather than the downstream position of some bytes.
//! `SMMU_IDR0.ATOS == 1` here.
//!
//! The architecture says this is the same translation a device would get (IHI 0070D.a §9):
//!
//! > An ATOS translation interacts with configuration and TLB invalidation in the same way as a
//! > translation that is performed for a transaction.
//!
//! > An ATOS request is permitted to use and insert cached configuration structures and
//! > translations, consistent with any caches that are provided for transaction translation.
//!
//! ⚠ **"Permitted", not "required" — so a null result would prove nothing on its own.** The control
//! that was meant to cover this — run with the cache off, run with it on — **does not exist**: every
//! `size_of_*` parameter reads "if this is zero then it is treated as a large number ('infinite')",
//! so the default caches and no setting disables it.
//!
//! What each experiment rests on instead is its own **internal** control, which is stronger anyway
//! because it lives inside a single run:
//!
//! * the post-invalidation step must show the NEW mapping — that proves the write reached memory, so
//!   the staleness before it was genuinely a cached translation and not a failed store;
//! * 2d's difference is between **two streams in the same run**, so it needs no second run at all;
//! * and 2d is **capacity-dependent** — shrink the TLB to one entry and the two streams evict each
//!   other, no staleness survives to be scoped, and the result flips. A difference that disappears
//!   when the cache is too small to hold it is caused by the cache.
//!
//! ## Why it shares no code with `hv-s2`
//!
//! Same reason the crate does: an instrument that can break the product is worse than no instrument.
//! The STE and descriptor layouts here were written from IHI 0070D.a and then **cross-checked**
//! against `hv-s2::smmu::stage2_ste` — two independent readings that must agree. That is the same
//! emit-seam/decode-seam discipline `hv-s2` uses internally (design-lesson #36), applied across a
//! crate boundary. ⚠ It is also the boundary that let the `IDR0.S2P` bit-order fix fail to travel,
//! so agreement is checked deliberately rather than assumed.

// ⚠ TEMPORARY, and it must come off when milestone 2d lands. The second table set (`L1_B`/`L2_B`),
// the second target and VMID, and `CMD_TLBI_S2_IPA` are the machinery of the staleness and
// VMID-scoping phases, which are written but not yet wired up. They are declared here rather than
// added later so that the arena layout and the register list are settled in one reviewable place.
// If this attribute is still present once 2b–2d are running, it is hiding something.

use core::ptr::{read_volatile, write_volatile};

/// SMMUv3 register base on the Base RevC — TF-A `PLAT_FVP_SMMUV3_BASE`, the FVP guide's own table,
/// and `IDR0` read back from it.
pub const SMMU_BASE: u64 = 0x2b40_0000;

// ─── registers (architectural offsets, IHI 0070D.a §6.3) ────────────────────────────────────────

const IDR0: u64 = 0x0000;
const IDR1: u64 = 0x0004;
const CR0: u64 = 0x0020;
const CR0ACK: u64 = 0x0024;
const CR1: u64 = 0x0028;
const CR2: u64 = 0x002c;
const GBPA: u64 = 0x0044;
const GERROR: u64 = 0x0060;
const STRTAB_BASE: u64 = 0x0080;
const STRTAB_BASE_CFG: u64 = 0x0088;
const CMDQ_BASE: u64 = 0x0090;
const CMDQ_PROD: u64 = 0x0098;
const CMDQ_CONS: u64 = 0x009c;
const EVENTQ_BASE: u64 = 0x00a0;
/// ⚠ Page 1. `IDR1.REL == 0` puts the event-queue pointers 64 KiB up, not at `0xa8`/`0xac`.
const EVENTQ_PROD: u64 = 0x1_00a8;
const EVENTQ_CONS: u64 = 0x1_00ac;
/// ATOS. Present only because `IDR0.ATOS == 1`; offsets from §6.3.36–39.
const GATOS_CTRL: u64 = 0x0100;
const GATOS_SID: u64 = 0x0108;
const GATOS_ADDR: u64 = 0x0110;
const GATOS_PAR: u64 = 0x0118;

const CR0_SMMUEN: u32 = 1 << 0;
const CR0_EVENTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;
const GBPA_UPDATE: u32 = 1 << 31;
const GBPA_ABORT: u32 = 1 << 20;

const CMD_CFGI_STE: u64 = 0x03;
const CMD_TLBI_S2_IPA: u64 = 0x2a;
const CMD_TLBI_NSNH_ALL: u64 = 0x30;
const CMD_SYNC: u64 = 0x46;

// ─── the memory arena ───────────────────────────────────────────────────────────────────────────
//
// Fixed DRAM addresses well clear of the image (linked at 0x8000_0000) rather than `.bss`, so
// alignment is obvious by inspection rather than by trusting a linker script. DRAM is 4 GB from
// 0x8000_0000, so all of this is real memory.
//
// The walk attributes are programmed NON-CACHEABLE. A cacheable SMMU walk against non-cacheable CPU
// writes is a coherency mismatch that would show up as an inexplicably stale table, which is
// precisely the observable this instrument exists to measure. Removing that confound is worth more
// than the walk performance it costs.
//
// ⚠ **THIS COMMENT USED TO SAY "the MMU is OFF at EL3, so every access below is Device-nGnRnE …
// that is why there is no cache maintenance anywhere in this file". BOTH HALVES ARE NOW FALSE**,
// and by the same change: milestone 6 does SMMU work **after** [`crate::mmu::enable`], so its
// accesses to this arena are **Normal write-back cacheable**, and [`submit`] now issues `DC CVAC`
// for exactly that reason.
//
// ★ **Which is the whole point of milestone 6, so read the pairing rather than the halves.** The
// walk stays non-cacheable and the CPU side became cacheable — that mismatch is not a defect here,
// it is `hv-metal`'s ledger-5 **A2** configuration reproduced deliberately. Milestones 1–2 still run
// MMU-off and are unaffected; what changed is that this file is no longer used in only one memory
// regime, and a comment that names one regime for the whole file cannot stay true.

const ARENA: u64 = crate::layout::SMMU_ARENA;
const STRTAB: u64 = ARENA;
const CMDQ: u64 = ARENA + 0x01_0000;
const EVTQ: u64 = ARENA + 0x02_0000;
/// Two independent stage-2 table sets, so an STE can be repointed between them.
pub const L1_A: u64 = ARENA + 0x03_0000;
pub const L2_A: u64 = ARENA + 0x04_0000;
pub const L1_B: u64 = ARENA + 0x05_0000;
pub const L2_B: u64 = ARENA + 0x06_0000;

/// 256 entries covers every StreamID on bus 0, including the test engines' `0xf0`/`0xf1`.
/// ⚠ `IDR1.SIDSIZE` is **32** here against QEMU's 16; the table is sized by what we use, not by
/// what the SMMU could address.
const STRTAB_LOG2SIZE: u32 = 8;
const CMDQ_LOG2SIZE: u32 = 4;
const EVTQ_LOG2SIZE: u32 = 4;

/// The IPA every phase asks about.
pub const TEST_IPA: u64 = 0x1000_0000;
/// The two 2 MiB frames it can be pointed at. Distinct values are the whole point: "stale" means
/// the SMMU answered with the one that is no longer mapped.
pub const TARGET_A: u64 = crate::layout::SMMU_TARGET_A;
pub const TARGET_B: u64 = crate::layout::SMMU_TARGET_B;

/// The two StreamIDs, which are the test engines' RequesterIDs. The FVP guide states the rule
/// outright: *"The PCIe devices use a DeviceID that is the same as their RequestorID (BDF)"*, and
/// the bus scan puts the engines at `00:1e.0` and `00:1e.1`.
pub const SID_A: u32 = 0x00f0;
pub const SID_B: u32 = 0x00f1;

/// The VMIDs the two STEs are tagged with. Different on purpose: VMID-scoped invalidation is the
/// discriminator for ledger 2(d)'s VMID half, and it is a far better one than "does a wrong VMID
/// change anything", which QEMU answered "no" to for reasons that were never established.
pub const VMID_A: u16 = 0x11;
pub const VMID_B: u16 = 0x22;

// ─── raw access ─────────────────────────────────────────────────────────────────────────────────

fn r32(off: u64) -> u32 {
    // SAFETY: SMMUv3 register space on this platform, MMU off, aliasing no Rust object.
    unsafe { read_volatile((SMMU_BASE + off) as *const u32) }
}
fn w32(off: u64, v: u32) {
    // SAFETY: as `r32`; these are the architectural control registers.
    unsafe { write_volatile((SMMU_BASE + off) as *mut u32, v) }
}
fn r64(off: u64) -> u64 {
    // SAFETY: as `r32`.
    unsafe { read_volatile((SMMU_BASE + off) as *const u64) }
}
fn w64(off: u64, v: u64) {
    // SAFETY: as `r32`.
    unsafe { write_volatile((SMMU_BASE + off) as *mut u64, v) }
}
fn mem_w64(pa: u64, v: u64) {
    // SAFETY: DRAM in the arena above, which the image does not occupy. MMU off, so this is a
    // direct physical write.
    unsafe { write_volatile(pa as *mut u64, v) }
}
fn mem_r64(pa: u64) -> u64 {
    // SAFETY: as `mem_w64`.
    unsafe { read_volatile(pa as *const u64) }
}

fn zero(pa: u64, bytes: u64) {
    let mut off = 0;
    while off < bytes {
        mem_w64(pa + off, 0);
        off += 8;
    }
}

// ─── stage-2 tables ─────────────────────────────────────────────────────────────────────────────
//
// Regime: 4 KiB granule, 39-bit IPA (T0SZ = 25), start level 1, 40-bit PA. Identical to
// `hv_s2::arm64::BALEEN_STAGE2`, deliberately — the point is to exercise the configuration baleen
// actually ships, not a convenient one.
//
// Level 1 resolves IPA[38:30] (1 GiB per entry), level 2 resolves IPA[29:21] (2 MiB per entry).
// `TEST_IPA` = 0x1000_0000 lands at L1[0], L2[128], so one L1 entry and one L2 block suffice.

const T0SZ: u64 = 25;
const SL0: u64 = 0b01; // start at level 1
const PS_40BIT: u64 = 0b010;

/// Table descriptor: valid + table type, pointing at the next level.
const DESC_TABLE: u64 = 0b11;
/// Block descriptor: valid + block type.
const DESC_BLOCK: u64 = 0b01;
/// MemAttr `0b1111` (Normal, inner+outer write-back), SH `0b11` (inner shareable), AF.
const LEAF_COMMON: u64 = (0b1111 << 2) | (0b11 << 8) | (1 << 10);
/// `S2AP = 0b11` — read and write.
const S2AP_RW: u64 = 0b11 << 6;

const fn l1_index(ipa: u64) -> u64 {
    (ipa >> 30) & 0x1ff
}
const fn l2_index(ipa: u64) -> u64 {
    (ipa >> 21) & 0x1ff
}

/// Build a two-level stage-2 set mapping [`TEST_IPA`] to `target` as a 2 MiB block.
pub fn build_tables(l1: u64, l2: u64, target: u64) {
    zero(l1, 4096);
    zero(l2, 4096);
    mem_w64(l1 + l1_index(TEST_IPA) * 8, l2 | DESC_TABLE);
    remap(l2, target);
}

/// Repoint an already-built level-2 table at a different 2 MiB frame, changing nothing else.
///
/// This is the mutation the staleness phases perform. It touches ONE descriptor, so a difference in
/// the ATOS answer afterwards cannot be attributed to anything else having moved.
pub fn remap(l2: u64, target: u64) {
    mem_w64(l2 + l2_index(TEST_IPA) * 8, target | LEAF_COMMON | S2AP_RW | DESC_BLOCK);
}

// ─── stream table ───────────────────────────────────────────────────────────────────────────────

/// A stage-2 translating STE (`Config = 0b110`: stage 1 bypass, stage 2 translate).
///
/// ⚠ Cross-checked field-by-field against `hv_s2::smmu::stage2_ste`. Walk attributes are
/// **non-cacheable** here where `hv-s2` uses write-back — the deliberate difference explained in the
/// arena comment above, and the only intentional divergence.
fn write_ste(sid: u32, s2ttb: u64, vmid: u16) {
    let e = STRTAB + u64::from(sid) * 64;
    zero(e, 64);
    // Word 0: V | Config = 0b110.
    mem_w64(e, 1 | (0b110 << 1));
    // Word 1: SHCFG = incoming.
    mem_w64(e + 8, 0b01 << 44);
    // Word 2: the translation regime, S2VMID in [15:0].
    // Fields left at zero, named because "absent" and "deliberately zero" are not the same thing to
    // a reader: S2IR0[41:40], S2OR0[43:42], S2SH0[45:44] — non-cacheable, non-shareable, per the
    // MMU-off argument above — and S2TG[47:46] = 0b00, which is 4 KiB.
    //
    // ⚠ 4 KiB is the ONLY granule this writes, and that restriction is inherited on purpose:
    // `hv_s2::smmu::stage2_ste` REFUSES every other granule because `STE.S2TG`'s encoding for the
    // large granules was never verified against hardware, and at 4 KiB a copied-across encoding
    // would be indistinguishable from a correct one. Silently emitting one here would put the
    // unverified mapping back, in the crate whose job is to check things.
    let w2 = u64::from(vmid)
        | (T0SZ << 32)
        | (SL0 << 38)
        | (PS_40BIT << 48)
        | (1 << 51)             // S2AA64
        | (1 << 54)             // S2PTW
        | (1 << 58); // S2R
    mem_w64(e + 16, w2);
    // Word 3: S2TTB.
    mem_w64(e + 24, s2ttb & 0x000f_ffff_ffff_fff0);
}

/// Read an STE's `S2TTB` back out — the decode direction, so a phase can assert what it installed
/// is what is in memory, independently of what the SMMU then answers.
pub fn ste_s2ttb(sid: u32) -> u64 {
    mem_r64(STRTAB + u64::from(sid) * 64 + 24) & 0x000f_ffff_ffff_fff0
}

/// The address of `sid`'s STE — so a caller can aim cache maintenance at the exact line the SMMU
/// fetches, rather than at the whole arena.
///
/// Exists for milestone 6: reading [`ste_s2ttb`] tells you what the **CPU** thinks the STE says,
/// which is its own cache. Dropping that line first and re-reading is what tells you what **memory**
/// says, and the difference between those two is the entire subject of that milestone.
pub fn ste_addr(sid: u32) -> u64 {
    STRTAB + u64::from(sid) * 64
}

/// Point `sid` at a stage-2 table set under `vmid`, and tell the SMMU its configuration changed.
pub fn bind(sid: u32, s2ttb: u64, vmid: u16) {
    write_ste(sid, s2ttb, vmid);
    invalidate_ste(sid);
}

/// Point `sid` somewhere else **without** telling the SMMU — the STE-caching probe.
pub fn bind_silently(sid: u32, s2ttb: u64, vmid: u16) {
    write_ste(sid, s2ttb, vmid);
}

/// Return every structure to a known state: both table sets rebuilt at their own targets, both
/// StreamIDs denied, every cache invalidated.
///
/// ⚠ **Each experiment must start from this, not from whatever the previous one left behind.**
/// These phases deliberately create stale state; a phase that inherited it would report the
/// PREVIOUS experiment's staleness as its own, and the transcript would look exactly the same.
pub fn reset_all() {
    build_tables(L1_A, L2_A, TARGET_A);
    build_tables(L1_B, L2_B, TARGET_B);
    zero(STRTAB + u64::from(SID_A) * 64, 64);
    zero(STRTAB + u64::from(SID_B) * 64, 64);
    invalidate_ste(SID_A);
    invalidate_ste(SID_B);
    invalidate_all();
}

// ─── command queue ──────────────────────────────────────────────────────────────────────────────

fn submit(word0: u64, word1: u64) {
    let prod = r32(CMDQ_PROD);
    let idx = u64::from(prod & ((1 << CMDQ_LOG2SIZE) - 1));
    mem_w64(CMDQ + idx * 16, word0);
    mem_w64(CMDQ + idx * 16 + 8, word1);

    // ★★ **PUBLISH THE COMMAND BEFORE RINGING THE DOORBELL — and this is milestone 6's finding,
    // not a detail.**
    //
    // The doorbell (`CMDQ_PROD`) is an MMIO register write: Device memory, always visible. The
    // command *bytes* are DRAM, and once [`crate::mmu::enable`] has run they are written through a
    // **cacheable** mapping while the SMMU fetches them non-cacheably (`CR1 = 0`). So without this
    // the SMMU is told "there is a new command" and then reads whatever stale bytes that ring slot
    // last held — with 16 slots, usually a real command from an earlier round, which is worse than
    // garbage because it completes and `CMD_SYNC` reports success.
    //
    // ⚠ **This is why milestone 6 could not isolate the STE hazard at first.** The queue is how the
    // experiment *steers* — `CMD_CFGI_STE` is what tells the SMMU to re-read a table — so the
    // control mechanism was under the very hazard being measured. Memory held the new STE
    // (`DC IVAC` + re-read proved it) and the SMMU still answered the old binding, because the
    // invalidation it was supposed to act on never really arrived.
    //
    // ★ **The transferable part is for `hv-metal`, not this probe.** `smmu::publish()` cleans the
    // tables it is about to point the SMMU at; under ledger 5's **A2** it must also publish **every
    // command it submits**, and in this order — bytes, then maintenance, then doorbell. A `publish`
    // that covers only the tables leaves the SMMU acting on stale commands.
    //
    // Harmless before the MMU is on: EL3 is then Device-nGnRnE, nothing is cached, and the
    // maintenance has nothing to do.
    // SAFETY: the command slot is inside the identity-mapped arena; cache maintenance has no
    // architectural memory effect beyond coherency.
    unsafe {
        crate::mmu::clean_range(CMDQ + idx * 16, 16);
    }

    // Wrap is the bit above the index, which the SMMU compares against CONS's.
    let next = (prod + 1) & ((1 << (CMDQ_LOG2SIZE + 1)) - 1);
    w32(CMDQ_PROD, next);
}

/// Push `CMD_SYNC` and wait for the queue to drain. Returns false on timeout, which a caller must
/// treat as "the result that follows means nothing" rather than as a failed assertion.
#[must_use]
pub fn sync() -> bool {
    submit(CMD_SYNC, 0);
    let want = r32(CMDQ_PROD);
    for _ in 0..1_000_000 {
        if r32(CMDQ_CONS) == want {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

pub fn invalidate_ste(sid: u32) {
    submit(CMD_CFGI_STE | (u64::from(sid) << 32), 1 /* Leaf */);
    let _ = sync();
}

/// Invalidate stage-2 translations for one VMID only — the VMID discriminator.
pub fn invalidate_vmid(vmid: u16) {
    submit(CMD_TLBI_S2_IPA | (u64::from(vmid) << 32), TEST_IPA >> 12 << 12);
    let _ = sync();
}

/// The blunt instrument: every non-secure stage-2 translation, all VMIDs.
pub fn invalidate_all() {
    submit(CMD_TLBI_NSNH_ALL, 0);
    let _ = sync();
}

// ─── bring-up ───────────────────────────────────────────────────────────────────────────────────

fn set_cr0(bits: u32) -> bool {
    let want = r32(CR0) | bits;
    w32(CR0, want);
    for _ in 0..1_000_000 {
        if r32(CR0ACK) & bits == bits {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Bring the SMMU up with an all-deny stream table, both queues live, and translation enabled.
///
/// Returns false at the first step that does not acknowledge. **Order is a property here, not a
/// convenience**: `GBPA.ABORT` is set before anything else so that the window between reset (where
/// `GBPA` reset value is BYPASS) and `SMMUEN` is closed rather than open — the same ordering SMMU
/// rung 1 established, where reaching the same end state by a different order leaves the hole open
/// and no end-state check can tell.
#[must_use]
pub fn bring_up() -> bool {
    // Deny bypassed traffic first.
    w32(GBPA, GBPA_UPDATE | GBPA_ABORT);

    // An all-zero STE is V=0, which aborts. Every StreamID starts denied.
    zero(STRTAB, (1u64 << STRTAB_LOG2SIZE) * 64);
    zero(CMDQ, (1u64 << CMDQ_LOG2SIZE) * 16);
    zero(EVTQ, (1u64 << EVTQ_LOG2SIZE) * 32);

    // Linear format (FMT = 0b00), LOG2SIZE in [5:0].
    w64(STRTAB_BASE, STRTAB & 0x000f_ffff_ffff_ffc0);
    w32(STRTAB_BASE_CFG, STRTAB_LOG2SIZE);

    w64(CMDQ_BASE, (CMDQ & 0x000f_ffff_ffff_ffe0) | u64::from(CMDQ_LOG2SIZE));
    w32(CMDQ_PROD, 0);
    w32(CMDQ_CONS, 0);
    w64(EVENTQ_BASE, (EVTQ & 0x000f_ffff_ffff_ffe0) | u64::from(EVTQ_LOG2SIZE));
    w32(EVENTQ_PROD, 0);
    w32(EVENTQ_CONS, 0);

    // Non-cacheable, non-shareable fetches for tables and queues — see the arena note.
    w32(CR1, 0);
    w32(CR2, 0);

    if !set_cr0(CR0_CMDQEN) {
        return false;
    }
    if !set_cr0(CR0_EVENTQEN) {
        return false;
    }
    if !set_cr0(CR0_SMMUEN) {
        return false;
    }
    invalidate_all();
    true
}

// ─── ATOS ───────────────────────────────────────────────────────────────────────────────────────

/// What the SMMU answered for one `(StreamID, IPA)` question.
pub struct Translation {
    /// Raw `GATOS_PAR`, reported so a reader can check the decode rather than trust it. ★ Keeping
    /// this in the transcript is what made the decode bug below diagnosable at all.
    pub par: u64,
    /// `PAR.FAULT` — the SMMU refused. A refusal is a legitimate answer (an unconfigured StreamID
    /// must be refused), so this is data, not an error.
    pub fault: bool,
    /// Output address when `!fault`, with the size marker removed — see [`decode_par`].
    pub pa: u64,
    /// Size of the translation that produced `pa`, in bytes. `0x1000` for a page; `0x20_0000` for
    /// the 2 MiB block this instrument maps. **Reported because it is a check, not a detail**: a
    /// block-sized answer confirms the SMMU walked to the block descriptor this code wrote, and a
    /// 4 KiB answer to the same question would mean it walked somewhere else entirely.
    pub size: u64,
    /// The operation did not complete within the poll bound.
    pub timeout: bool,
}

/// Decode `GATOS_PAR`'s success format.
///
/// ## ⚠ The output address carries a SIZE MARKER, and missing it looks exactly like a wrong answer
///
/// IHI 0070D.a, on the no-fault format: *"The translated address is aligned to the translation size
/// (appropriate number of LSBs zeroed) and then, if the size is greater than 4KB, **a single bit is
/// set such that its position, N, denotes the translation size, where 2^(N+1) == size in bytes**."*
///
/// So a 2 MiB block at `0x8200_0000` is reported as `0x8210_0000` — the target with **bit 20** set.
/// The first version of this decode did not implement the rule and reported the raw field, which
/// read as "the SMMU answered 1 MiB past the frame I mapped": a plausible, structured, entirely
/// wrong-looking number that invited a hunt for a descriptor bug that did not exist. Clearing the
/// lowest set bit recovers the address; its position gives the size for free.
///
/// ## ⚠ And the field position disagrees with my reading of the register diagram
///
/// The field list reads `ADDR, bits [50:11]` / *"Result address, bits [51:12]"*, which would put
/// PA[12] at PAR[11]. **The model's behaviour is only consistent with PA[50:12] sitting at
/// PAR[50:12]**, with `Size` at bit 11 rather than 10 — under that reading, and only under it, the
/// answer decodes to exactly the frame this code mapped, the marker bit gives exactly the block size
/// this code programmed, and `SH` decodes to exactly the `0b11` this code put in the descriptor.
/// Three independent agreements are not a coincidence, so the empirical layout is what is
/// implemented here; the diagram was extracted from a PDF whose column alignment did not survive, so
/// the likeliest explanation is that I misread it rather than that Arm's own model misimplements its
/// own register. **Recorded rather than smoothed over, because a reader deserves to know this decode
/// was fitted to behaviour.**
fn decode_par(par: u64) -> (u64, u64) {
    // ADDR occupies [50:12] and is already position-aligned with the physical address.
    let raw = par & 0x0007_ffff_ffff_f000;
    let size_gt_4k = (par >> 11) & 1 != 0;
    if !size_gt_4k || raw == 0 {
        return (raw, 0x1000);
    }
    // The lowest set bit is the marker, not an address bit: clear it, and read the size off its
    // position. `raw & (raw - 1)` clears exactly the lowest set bit.
    let marker = raw.trailing_zeros();
    (raw & (raw - 1), 1u64 << (marker + 1))
}

/// Ask the SMMU to translate `ipa` as stage 2 for `sid`, exactly as a device transaction would be.
///
/// `ADDR.TYPE = 0b10` is "Stage 2 (IPA to PA)"; `RnW = 1` asks as a read, `PnU = 1` as privileged.
pub fn translate(sid: u32, ipa: u64) -> Translation {
    // RUN must only be set when SMMUEN == 1 and RUN == 0 (§6.3.36).
    for _ in 0..1_000_000 {
        if r32(GATOS_CTRL) & 1 == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    w64(GATOS_SID, u64::from(sid));
    w64(GATOS_ADDR, (ipa & !0xfff) | (0b10 << 10) | (1 << 9) | (1 << 8));
    w32(GATOS_CTRL, 1);

    for _ in 0..1_000_000 {
        if r32(GATOS_CTRL) & 1 == 0 {
            let par = r64(GATOS_PAR);
            let fault = par & 1 != 0;
            let (pa, size) = if fault { (0, 0) } else { decode_par(par) };
            return Translation { par, fault, pa, size, timeout: false };
        }
        core::hint::spin_loop();
    }
    Translation { par: 0, fault: true, pa: 0, size: 0, timeout: true }
}

/// `SMMU_GERROR` — reported after bring-up because a global error makes every later answer suspect,
/// and it is exactly the sort of thing that otherwise shows up as an unexplained fault.
pub fn gerror() -> u32 {
    r32(GERROR)
}

/// Read back what the SMMU thinks it was asked, so a wrong ANSWER can be told apart from a wrong
/// QUESTION. Without this the two are indistinguishable, which is the whole reason 2a.1 could not be
/// diagnosed from its result alone.
pub fn atos_request_readback() -> (u64, u64) {
    (r64(GATOS_SID), r64(GATOS_ADDR))
}

/// The descriptor words this code actually left in memory, read back rather than recomputed.
///
/// ⚠ Recomputing them would prove only that the same expression evaluates the same way twice. The
/// question is what is IN MEMORY at the address the STE names, because that is the only thing the
/// SMMU can walk.
pub fn descriptors(l1: u64, l2: u64) -> (u64, u64, u64, u64) {
    (
        l1 + l1_index(TEST_IPA) * 8,
        mem_r64(l1 + l1_index(TEST_IPA) * 8),
        l2 + l2_index(TEST_IPA) * 8,
        mem_r64(l2 + l2_index(TEST_IPA) * 8),
    )
}

pub fn id_registers() -> (u32, u32) {
    (r32(IDR0), r32(IDR1))
}
