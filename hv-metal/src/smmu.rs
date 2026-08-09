// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # SMMUv3 — closing the DMA window, the stream table, then translation (the SMMU arc, rungs 1–3)
//!
//! Stage-2 constrains the **CPU** and says nothing about **bus masters**. Every isolation property
//! baleen proves — the p2m refinement, the VMID-tagged address spaces, the whole Tier-D
//! non-interference argument — is about what a guest's *CPU accesses* can reach. A DMA-capable device
//! writes to physical memory without consulting `VTTBR_EL2` at all, so on real hardware a guest that
//! can program a device can write anywhere, and the thesis has a hole the size of the machine. This is
//! the ledger's "biggest REAL isolation hole", and the ARM answer to it is the **SMMU**: a second
//! translation regime, in front of the devices, walking the same kind of tables.
//!
//! ## What rung 1 does, and what it deliberately does not
//!
//! Rung 1 is **default-deny before functionality**, and nothing else. It establishes that a device
//! gets *nothing* before it is explicitly granted something — which is the right foundation to put
//! translation on top of, and is the same ordering as design-lesson #51's fail-closed ruling.
//!
//! The hole it closes is concrete and easy to miss. When `SMMU_CR0.SMMUEN == 0` the SMMU is not
//! translating, and what happens to a transaction is decided by **`SMMU_GBPA`** (Global ByPass
//! Attribute). Its reset value has `ABORT == 0` — i.e. **bypass**: on a machine that has just come out
//! of reset, with no firmware having touched the SMMU, *every device can DMA anywhere*. So there is a
//! window, from power-on until the hypervisor configures the SMMU, in which the IOMMU is an open door.
//! Rung 1 shuts it: set `GBPA.ABORT` early, before any device is enabled, and a device's DMA is
//! terminated rather than performed.
//!
//! ## What rung 2 adds: the stream table, and the trap it is built around
//!
//! `GBPA` only decides what happens while `CR0.SMMUEN == 0`. Once the SMMU is *translating*, every
//! transaction is decided by the **stream table**: the StreamID indexes it, and the Stream Table Entry
//! there says abort, bypass, or translate. Rung 2 installs one — a linear table covering every
//! StreamID on PCIe bus 0, every entry zeroed, i.e. `STE.V == 0`, i.e. **deny** — enables the command
//! and event queues, and turns `SMMUEN` on. The table-building decision itself is not here: it is
//! pure code in [`hv_s2::smmu`], where `hv-verify::smmu_stream_table` proves the ∀-StreamID property
//! over it. This module keeps only what must be `unsafe`: MMIO, the publication barrier, and the
//! configuration-cache invalidation.
//!
//! **The trap, named up front.** An ∀-StreamID deny passes *trivially* if no device ever reaches the
//! stream table at all — a wrong `LOG2SIZE`, a mis-aligned `STRTAB_BASE`, a StreamID that is not the
//! device's RequesterID, or an `SMMUEN` that never took all produce "the DMA was aborted", which is
//! indistinguishable from the property holding. So rung 2's first witness is a **through-STE positive
//! control**: the device's own StreamID bound to a [`bypass STE`](hv_s2::smmu::bypass_ste), and its
//! DMA must **land**. Only then does the deny half mean anything. See [`dmawitness`](crate::dmawitness)
//! for the three-phase witness this module's primitives serve.
//!
//! **Ordering, again, is the property.** The all-deny stream table is installed *before* `SMMUEN` is
//! written, and `GBPA.ABORT` covers everything before that — so there is no instant, from reset to
//! translating, in which a bus master would be let through.
//!
//! ## What rung 3 adds: the device is bound to a DOMAIN
//!
//! Everything rung 2 permits, it permits **unconfined** — a bypass STE is a path witness, never an
//! isolation configuration. [`bind_stream_stage2`] is the configuration: `STE.Config = 0b110` with
//! `S2TTB` pointing at the `p2m`-derived Stage-2 tables `crate::stage2` emitted for a domain, under
//! that domain's `S2VMID`, both read back out of the `VTTBR_EL2` value the domain's CPU would be
//! given. `hv-s2`'s ∀-address refinement then carries the device path for free (the theorem
//! constrains the *table*, not the *walker*), and this module keeps only the new hardware
//! obligation: a second invalidation ([`CMD_TLBI_NSNH_ALL`]) so a stream rebound to a different
//! domain cannot be answered from translations cached for the previous one. See
//! `docs/SMMU-TRANSLATION.md`.
//!
//! ## Unsafe
//!
//! Every access is a `read_volatile`/`write_volatile` to a documented SMMUv3 register offset in the
//! `virt` machine's SMMU window — device memory, aliasing no Rust object. EL2 runs MMU-off/identity,
//! so the window is reachable as a plain physical address, exactly as `gic.rs` reaches GICD.

/// SMMUv3 register window base on QEMU `virt` — device tree `smmuv3@9050000`,
/// `reg = <0x00 0x9050000 0x00 0x20000>` (128 KiB).
///
/// **A `virt` platform fact, not architectural** (same caveat as `gic::MAINT_INTID` and
/// `pcie::ECAM_BASE`): the SMMU's placement is chosen by the SoC integrator, so a real-hardware port
/// must take it from the device tree.
const SMMU_BASE: u64 = 0x0905_0000;

/// `SMMU_IDR0` — feature identification. **Bit 0 `S2P` (stage-2 translation)** — the capability the
/// whole arc depends on, since baleen's plan is to point the SMMU at the *same* `p2m`-derived Stage-2
/// tables the CPU walks — and bit 1 `S1P` (stage-1).
const SMMU_IDR0: u64 = 0x0000;
/// `SMMU_IDR1` — queue/table size parameters. `SIDSIZE` in bits `[5:0]` bounds the stream table;
/// `CMDQS`/`EVTQS` bound the queues; `REL` (bit 28) says where page 1 sits.
const SMMU_IDR1: u64 = 0x0004;
/// `SMMU_CR0` — global control; bit 0 is `SMMUEN`.
const SMMU_CR0: u64 = 0x0020;
/// `SMMU_CR0ACK` — the *acknowledged* value of [`SMMU_CR0`]. An SMMUv3 absorbs `CR0` writes
/// asynchronously, so `CR0` reads back what was requested while `CR0ACK` reads back what took effect.
/// Every enable here polls `CR0ACK`, never `CR0` — checking the request would be checking our own
/// bookkeeping, the distinction rung 1's `GBPA` read-back already turned on.
const SMMU_CR0ACK: u64 = 0x0024;
/// `SMMU_CR1` — memory attributes the SMMU uses for its **own** fetches of tables and queues.
const SMMU_CR1: u64 = 0x0028;
/// `SMMU_CR2` — bit 1 `RECINVSID`: record an event for a transaction whose StreamID is out of range.
const SMMU_CR2: u64 = 0x002c;
/// `SMMU_GBPA` — the **global bypass attribute**: what happens to a transaction while the SMMU is not
/// translating. Bit 31 `Update` (write 1 to commit, self-clearing), bit 20 `ABORT`.
const SMMU_GBPA: u64 = 0x0044;
/// `SMMU_GERROR` / `SMMU_GERRORN` — global error flags and their software acknowledgement. They are
/// equal exactly when no error is outstanding, which is how this module tells "the command queue
/// consumed my command" from "the command queue rejected it and stalled" — two states that otherwise
/// both look like a `CMD_SYNC` that never completes.
const SMMU_GERROR: u64 = 0x0060;
const SMMU_GERRORN: u64 = 0x0064;
/// `SMMU_STRTAB_BASE` (64-bit) — physical base of the stream table, bits `[51:6]`.
const SMMU_STRTAB_BASE: u64 = 0x0080;
/// `SMMU_STRTAB_BASE_CFG` — `LOG2SIZE` `[5:0]`, `SPLIT` `[10:6]`, `FMT` `[17:16]`.
const SMMU_STRTAB_BASE_CFG: u64 = 0x0088;
/// `SMMU_CMDQ_BASE` (64-bit) — `ADDR` `[51:5]`, `LOG2SIZE` `[4:0]`.
const SMMU_CMDQ_BASE: u64 = 0x0090;
const SMMU_CMDQ_PROD: u64 = 0x0098;
const SMMU_CMDQ_CONS: u64 = 0x009c;
/// `SMMU_EVENTQ_BASE` (64-bit) — same layout as `CMDQ_BASE`.
const SMMU_EVENTQ_BASE: u64 = 0x00a0;
/// `SMMU_EVENTQ_PROD` / `_CONS` live in the SMMU's **page 1**, not page 0 — at `base + 64 KiB + 0xa8`
/// when `IDR1.REL == 0` (the case on this machine, checked at setup rather than assumed). They are the
/// registers Linux calls `ARM_SMMU_EVTQ_PROD`/`_CONS` at `0x100a8`/`0x100ac`.
///
/// Getting this offset wrong is a silent failure — the reads would return some other register's value
/// and the event witness would report nothing — so the event evidence is deliberately **doubled**:
/// `PROD` advancing *and* a decodable record in the queue's own memory, which the CPU reads directly
/// and which no register offset can spoof.
const SMMU_EVENTQ_PROD: u64 = 0x1_00a8;
const SMMU_EVENTQ_CONS: u64 = 0x1_00ac;

/// `SMMU_IDR0.S2P` — **stage-2** translation supported (bit 0).
const IDR0_S2P: u32 = 1 << 0;
/// `SMMU_IDR0.S1P` — stage-1 translation supported (bit 1).
///
/// The bit positions are this way round in the architecture (`S2P` is bit 0) and were **swapped in
/// rung 1**. It changed no result there — QEMU's SMMU sets both, so `supports_stage2()` answered
/// `true` either way — which is exactly why it survived: a check whose two inputs are both set cannot
/// discriminate between them. Corrected here, and worth recording as the shape rather than the
/// instance.
const IDR0_S1P: u32 = 1 << 1;
/// `SMMU_IDR1.SIDSIZE` — bits `[5:0]`; the SMMU supports StreamIDs below `2^SIDSIZE`.
const IDR1_SIDSIZE_MASK: u32 = 0x3f;
/// `SMMU_IDR1.REL` — bit 28; clear means page 1 is at `base + 64 KiB` (the layout
/// [`SMMU_EVENTQ_PROD`] assumes).
const IDR1_REL: u32 = 1 << 28;
/// `SMMU_GBPA.Update` — writes to `GBPA` are ignored unless this is set; it self-clears when the
/// update has been absorbed, so it doubles as the completion signal.
const GBPA_UPDATE: u32 = 1 << 31;
/// `SMMU_GBPA.ABORT` — terminate bypassed transactions instead of passing them through untranslated.
const GBPA_ABORT: u32 = 1 << 20;
/// `SMMU_CR0.SMMUEN` — the SMMU is translating.
const CR0_SMMUEN: u32 = 1 << 0;
/// `SMMU_CR0.EVENTQEN` — the event queue is live; without it faults are silently dropped rather than
/// recorded, and the deny witness would lose its *reason*.
const CR0_EVENTQEN: u32 = 1 << 2;
/// `SMMU_CR0.CMDQEN` — the command queue is live; without it `CMD_CFGI_STE` is never consumed and an
/// STE edit would appear to have no effect.
const CR0_CMDQEN: u32 = 1 << 3;
/// `SMMU_CR2.RECINVSID` — record `C_BAD_STREAMID` for transactions outside the configured table.
const CR2_RECINVSID: u32 = 1 << 1;

/// Command opcodes (`CMD_*[7:0]`).
const CMD_CFGI_STE: u64 = 0x03;
/// `CMD_TLBI_NSNH_ALL` — invalidate every non-secure, non-hyp TLB entry, all VMIDs.
///
/// The device path's analogue of `enable_stage2`'s `tlbi vmalls12e1is`, and rung 3's reason for
/// existing: an STE rebound to a *different* domain's tables while the SMMU still holds translations
/// cached from the previous one would answer with the old domain's memory. The blunt all-VMIDs form
/// is chosen deliberately over `CMD_TLBI_S2_IPA` — baleen rebinds whole streams rather than editing
/// live tables, so there is no per-address invalidation to be precise about, and a *narrower*
/// invalidation that missed would be indistinguishable from correct behaviour on a machine that
/// caches nothing.
const CMD_TLBI_NSNH_ALL: u64 = 0x30;
const CMD_SYNC: u64 = 0x46;

/// Event-record types this module names. `C_BAD_STE` is what a zeroed (`V == 0`) entry produces and
/// is therefore the deny witness's expected reason; `C_BAD_STREAMID` is the out-of-range arm.
pub(crate) const EVT_C_BAD_STREAMID: u8 = 0x02;
pub(crate) const EVT_C_BAD_STE: u8 = 0x04;
/// `F_TRANSLATION` — a stage-2 walk found no descriptor for the address the device asked for. The
/// rung-3 confinement arm's expected reason: the domain's table does not map that IPA.
pub(crate) const EVT_F_TRANSLATION: u8 = 0x10;
/// `F_PERMISSION` — the walk found a descriptor and its `S2AP` refused the access. The rung-3
/// permission arm: the proven emitter's read-only leaf governs the DEVICE too.
pub(crate) const EVT_F_PERMISSION: u8 = 0x13;

fn read32(off: u64) -> u32 {
    // SAFETY: a documented SMMUv3 register offset inside the `virt` machine's 128 KiB SMMU window —
    // device memory at EL2 (MMU off). Read-only; aliases no Rust memory.
    unsafe { core::ptr::read_volatile((SMMU_BASE + off) as *const u32) }
}

fn write32(off: u64, v: u32) {
    // SAFETY: as `read32`; the written offsets (`GBPA`, `CR0`–`CR2`, the queue pointers and the table
    // base configuration) are RW.
    unsafe { core::ptr::write_volatile((SMMU_BASE + off) as *mut u32, v) }
}

fn write64(off: u64, v: u64) {
    // SAFETY: as `write32`; the 64-bit registers written here (`STRTAB_BASE`, `CMDQ_BASE`,
    // `EVENTQ_BASE`) are RW and 64-bit accessible.
    unsafe { core::ptr::write_volatile((SMMU_BASE + off) as *mut u64, v) }
}

fn read64(off: u64) -> u64 {
    // SAFETY: as `read32`.
    unsafe { core::ptr::read_volatile((SMMU_BASE + off) as *const u64) }
}

/// Publish `[pa, pa + len)` — a table or a queue slot EL2 has just written — before the SMMU is told
/// to look at it.
///
/// ## ★★ This was a bare `dsb sy` until A2, and the specification for changing it was MEASURED first
///
/// Under A1, EL2's data accesses were Device-nGnRnE — already strongly ordered and uncached — so a
/// barrier was the whole obligation and on QEMU it was a no-op. The doc here predicted the barrier
/// "would bite on silicon the moment the EL2 MMU brings normal cacheable mappings with it".
/// `fvp-probe` milestone 6 then reproduced this exact sequence on Arm's AEM with the CPU side
/// cacheable and the SMMU fetching non-cacheably (`CR1 = 0`), which is what A2 creates:
///
/// | after | SMMU answered |
/// |---|---|
/// | writing the STE, then a bare `dsb sy` | the **STALE** binding |
/// | `DC CVAC` over the structure | the new one |
///
/// So the prediction was right and the barrier was not enough, in **two** ways — and A2 discharges
/// both here:
///
/// 1. **The barrier became maintenance.** A `dsb` orders accesses; it does not push a dirty line to
///    the point of coherency the SMMU fetches from. Hence [`crate::cache::clean`], which is
///    `DC CVAC` over the range *followed by* `dsb sy` — the ordering obligation did not go away, it
///    gained a prerequisite.
/// 2. ⚠ **Every SUBMITTED COMMAND is published too, and that half is silent when it is wrong.** The
///    doorbell (`CMDQ_PROD`) is MMIO and always visible, but the command *bytes* are DRAM. Told
///    "there is a new command", the SMMU reads whatever that ring slot last held — with 16 slots,
///    usually a real command from an earlier round — so **`CMD_SYNC` reports success while the
///    invalidation never happened.** Milestone 6 spent three runs inside that failure: memory held
///    the new STE (proved by `DC IVAC` + re-read) and the SMMU kept answering the old binding,
///    because the `CMD_CFGI_STE` telling it to look again had itself gone stale.
///    **Order: bytes → maintenance → doorbell**, which is what [`submit`] does.
///
/// ★ **Taking a range is the change that makes this checkable.** A no-argument `publish()` was
/// exactly right when the operation was a global barrier and exactly wrong for maintenance, which
/// is addressed: a reviewer can now ask of each call site "is that the memory you just wrote?",
/// which is a question the old signature could not even be asked.
///
/// `sy` rather than `ish` throughout: the SMMU is not in the inner-shareable domain.
fn publish(pa: u64, len: u64) {
    crate::cache::clean(pa, len);
}

/// The whole stream table, as a range for [`publish`].
///
/// ★ Callers that edit **one** STE publish the **whole** table anyway, and that is deliberate.
/// `st::bind` and friends take the table and an index; asking each call site to re-derive the byte
/// offset of the entry it just changed would put a second copy of the STE stride next to every one
/// of them, and a publication that cleans the wrong 64 bytes fails exactly like no publication at
/// all — silently, on a platform CI does not have. 16 KiB is 256 lines; the cost is not worth a
/// derivation that can drift.
fn strtab_range(smmu: &Smmu) -> (u64, u64) {
    (
        core::ptr::addr_of!(smmu.strtab.0) as u64,
        core::mem::size_of_val(&smmu.strtab.0) as u64,
    )
}

/// Whether an SMMUv3 appears to be present at [`SMMU_BASE`].
///
/// A real SMMU always reports at least one translation stage, so a zero `IDR0` would mean "absent".
///
/// **This is a consistency check, not a probe.** Unassigned MMIO on `virt` takes a *synchronous
/// external abort* rather than reading as zero (measured — `EC=0x25 FAR=0x9050000` — after assuming
/// otherwise), and EL2's fault handler is `-> !` by design, so calling this on a machine without an
/// SMMU ends the boot. That is why the whole SMMU half is a cargo feature rather than a runtime
/// probe: the boot that touches these registers is only ever launched with `iommu=smmuv3`. See the
/// `smmu` feature's note in `Cargo.toml`.
pub(crate) fn present() -> bool {
    read32(SMMU_IDR0) & (IDR0_S1P | IDR0_S2P) != 0
}

/// `(IDR0, IDR1)` — reported so the boot witness records the machine's actual capabilities rather than
/// this port's assumptions about them.
pub(crate) fn id_registers() -> (u32, u32) {
    (read32(SMMU_IDR0), read32(SMMU_IDR1))
}

/// Whether the SMMU reports **stage-2** translation support (`IDR0.S2P`).
///
/// Read directly from the device rather than inferred: the arc's feasibility was first established by
/// reading a guest Linux driver's decoded feature word, which is a second-hand source. This is the
/// first-hand one.
pub(crate) fn supports_stage2() -> bool {
    read32(SMMU_IDR0) & IDR0_S2P != 0
}

/// Whether the SMMU is currently translating (`CR0.SMMUEN`).
pub(crate) fn translating() -> bool {
    read32(SMMU_CR0) & CR0_SMMUEN != 0
}

/// Whether bypassed transactions are currently **aborted** (`GBPA.ABORT`).
pub(crate) fn bypass_aborts() -> bool {
    read32(SMMU_GBPA) & GBPA_ABORT != 0
}

/// **Close the pre-enable DMA window: abort bypassed transactions** (`GBPA.ABORT`).
///
/// This is rung 1's whole content. Until it runs, `GBPA`'s reset value leaves `ABORT` clear, so any
/// bus master that comes up — before the hypervisor has built a stream table, before it has decided
/// anything about which device belongs to which domain — can read and write all of physical memory.
/// Calling this early, before any device is given `Bus Master Enable`, means the default answer to a
/// device transaction is *no*.
///
/// Returns whether the update was absorbed. `GBPA.Update` self-clears, so it is both the commit bit
/// and the completion signal; the spin is bounded so a machine without an SMMU (or one that never
/// absorbs the write) reports failure instead of hanging the boot.
pub(crate) fn abort_bypassed_traffic() -> bool {
    // Preserve the other GBPA fields (`SHCFG` etc. carry a nonzero reset value) — set only ABORT.
    let cur = read32(SMMU_GBPA) & !GBPA_UPDATE;
    write32(SMMU_GBPA, cur | GBPA_ABORT | GBPA_UPDATE);
    for _ in 0..100_000 {
        if read32(SMMU_GBPA) & GBPA_UPDATE == 0 {
            return read32(SMMU_GBPA) & GBPA_ABORT != 0;
        }
        core::hint::spin_loop();
    }
    false
}

// ─── Rung 2: the stream table, the command queue, the event queue ────────────────────────────────

use crate::cell::BootCell;
use hv_s2::smmu as st;

/// The stream table covers StreamIDs `0 .. 256` — every function on PCIe bus 0.
///
/// Taken from [`hv_s2::smmu::BUS0_LOG2SIZE`] rather than written here, because that is the size the
/// Kani default-deny property is proven at: a size chosen independently in the metal could be a size
/// nothing proves anything about. See that constant for why the bus, and not `IDR1.SIDSIZE`.
pub(crate) const STRTAB_LOG2SIZE: u32 = st::BUS0_LOG2SIZE;
const STRTAB_ENTRIES: usize = 1 << STRTAB_LOG2SIZE;
const STRTAB_WORDS: usize = STRTAB_ENTRIES * st::STE_WORDS;

/// The command queue: 16 entries × 16 bytes. Rung 2 issues at most three commands between syncs, so
/// the queue never comes close to wrapping; it is sized to its alignment requirement, not its load.
const CMDQ_LOG2SIZE: u32 = 4;
const CMDQ_ENTRIES: usize = 1 << CMDQ_LOG2SIZE;
/// The event queue: 16 entries × 32 bytes.
const EVENTQ_LOG2SIZE: u32 = 4;
const EVENTQ_ENTRIES: usize = 1 << EVENTQ_LOG2SIZE;

/// The linear stream table. Alignment is **the larger of the table size and 64 bytes** — an
/// architectural requirement, and a silent one: `STRTAB_BASE` carries only bits `[51:6]`, so an
/// under-aligned base is *truncated* to a different address, the SMMU walks whatever is there, and
/// every StreamID denies for a reason that has nothing to do with the property under test. That is
/// the vacuity failure in its purest form, so the requirement is bound to the type by a `const _`
/// against `hv-s2`'s own statement of it rather than restated as a literal here.
#[repr(C, align(16384))]
struct StreamTable([u64; STRTAB_WORDS]);

const _: () = assert!(
    core::mem::align_of::<StreamTable>() == st::base_alignment(STRTAB_LOG2SIZE).unwrap(),
    "the stream table's alignment must be the architectural one for its size"
);
const _: () = assert!(core::mem::size_of::<StreamTable>() == STRTAB_WORDS * 8);
// The table must be big enough for the size it will be *configured* with, or the SMMU fetches STEs
// from past the allocation — the one way this scheme fails open, and the case `hv-s2`'s
// `TableTooSmall` refusal exists to make unreachable. Pinned at compile time as well, since the
// runtime refusal cannot help a table that was declared too small in the first place.
const _: () = assert!(STRTAB_WORDS >= st::table_words(STRTAB_LOG2SIZE).unwrap());

/// The `STRTAB_BASE_CFG` value for this table, resolved at **compile time**.
///
/// A `const` rather than a runtime `unwrap_or(0)`: falling back to `0` would announce a *one-entry*
/// table, which denies everything and would therefore look exactly like the property holding while
/// meaning the configuration never happened. A size this module cannot encode must break the build,
/// not degrade into a silent success.
const STRTAB_CFG: u32 = match st::strtab_base_cfg(STRTAB_LOG2SIZE) {
    Some(cfg) => cfg,
    None => panic!("STRTAB_LOG2SIZE exceeds what STRTAB_BASE_CFG.LOG2SIZE can encode"),
};

/// The command queue. Aligned to its size (`CMDQ_BASE.ADDR` is bits `[51:5]`, and the architecture
/// requires queue-size alignment).
#[repr(C, align(256))]
struct CmdQueue([u64; CMDQ_ENTRIES * 2]);
const _: () = assert!(core::mem::align_of::<CmdQueue>() >= core::mem::size_of::<CmdQueue>());

/// The event queue. 32-byte records.
#[repr(C, align(512))]
struct EventQueue([u64; EVENTQ_ENTRIES * 4]);
const _: () = assert!(core::mem::align_of::<EventQueue>() >= core::mem::size_of::<EventQueue>());

/// Scratch storage the derivation builds into before it is compared with the live table.
///
/// Deriving into scratch and copying on difference is what lets the **hardware** be touched only
/// when the table actually changed, while the *words* are re-derived after every single dispatch.
/// That matters twice: the invalidation stays load-bearing at the moments a stream really is bound
/// or dropped (so a remove-the-fix probe on `CMD_CFGI_STE` can still go red), and a boot's worth of
/// unrelated hypercalls costs no command-queue traffic.
#[repr(C, align(16384))]
struct ScratchTable([u64; STRTAB_WORDS]);

/// Everything the SMMU reads out of RAM, plus the software queue indices.
///
/// One [`BootCell`] over all of it, for the same reason [`crate::stage2`]'s `STAGE2_SETS` is one cell
/// over all the Stage-2 sets: the second agent here is **the SMMU**, not another CPU, so the
/// obligation is *publication* (discharged by [`publish`] and `CMD_CFGI_STE`/`CMD_SYNC`) rather than
/// mutual exclusion — and what the cell adds is the *aliasing* half, so the table and the queues come
/// out as disjoint field borrows the compiler checks.
#[repr(C)]
struct Smmu {
    strtab: StreamTable,
    scratch: ScratchTable,
    cmdq: CmdQueue,
    eventq: EventQueue,
    /// Software's view of `CMDQ_PROD`, including the wrap bit at bit [`CMDQ_LOG2SIZE`].
    cmdq_prod: u32,
    /// Software's view of `EVENTQ_CONS`, including the wrap bit at bit [`EVENTQ_LOG2SIZE`].
    eventq_cons: u32,
    /// Whether a stream table exists to derive into (set by [`install_stream_table`]).
    ///
    /// Before it does, the answer to a bus master is rung 1's `GBPA.ABORT` — so this flag does not
    /// open a window, it names which of the two mechanisms is answering. A derivation attempted
    /// before the table is installed would poke registers on a machine whose queues are not enabled.
    armed: bool,
    /// The `DevId → StreamID` map — **the rung's fence crossing**, and the one place the model's
    /// opaque device token may meet a hardware identifier.
    ///
    /// `hv-core` cannot name a StreamID for the same reason it cannot name a physical address
    /// (design-lesson #14e), and `hv-s2` is only ever *told* one; the derivation therefore takes
    /// this as data. Supplied to [`install_stream_table`] rather than set separately, so a stream
    /// table cannot exist without the map that gives its indices meaning.
    stream_of: [u32; crate::NUM_DEVICES],
    /// The `DomId → Stage2Binding` map: which Stage-2 tables (and VMID) each domain's image was
    /// emitted at. Written by [`register_domain_binding`], from the `VTTBR_EL2` value that domain's
    /// CPU would be given — so the device and the CPU cannot be pointed at different tables.
    binding_of: [Option<st::Stage2Binding>; crate::NUM_DOMAINS],
    /// How many derivations reached the hardware. Read by the witness so a phase can require that
    /// the derivation **ran**, rather than passing because nothing happened at all (#66).
    published: u32,
}

static SMMU: BootCell<Smmu> = BootCell::new(
    "SMMU",
    Smmu {
        strtab: StreamTable([0; STRTAB_WORDS]),
        scratch: ScratchTable([0; STRTAB_WORDS]),
        cmdq: CmdQueue([0; CMDQ_ENTRIES * 2]),
        eventq: EventQueue([0; EVENTQ_ENTRIES * 4]),
        cmdq_prod: 0,
        eventq_cons: 0,
        armed: false,
        stream_of: [0; crate::NUM_DEVICES],
        binding_of: [None; crate::NUM_DOMAINS],
        published: 0,
    },
);

// The device population the metal models must be one the ∀-values proofs actually instantiate: the
// derivation's aliasing, sweep-exactness and biconditional harnesses unwind the device axis, so a
// metal that grew a third bus master would be running a builder nothing had proven at that size.
// Pinned to `hv-s2`'s own statement of it rather than restated here (design-lesson #71(c)).
const _: () = assert!(crate::NUM_DEVICES <= st::MAX_PROVEN_DEVICES);

/// A queue index register's wrap-inclusive mask: `log2size + 1` bits, the low `log2size` of which are
/// the index and the top one the wrap flag.
const fn queue_mask(log2size: u32) -> u32 {
    (1u32 << (log2size + 1)) - 1
}

/// What [`install_stream_table`] observed — every field read back from the device, never inferred
/// from what was written.
pub(crate) struct StreamTableReport {
    /// `IDR1.SIDSIZE` — the SMMU's own StreamID width.
    pub(crate) sidsize: u32,
    /// `IDR1.REL == 0`, i.e. page 1 (and so [`SMMU_EVENTQ_PROD`]) is where this module expects it.
    pub(crate) page1_at_64k: bool,
    /// Physical base of the stream table, as the CPU sees it.
    pub(crate) strtab_pa: u64,
    /// `STRTAB_BASE` read back — equal to what `hv-s2` says should have been written.
    pub(crate) strtab_base_ok: bool,
    /// `STRTAB_BASE_CFG` read back — linear format, the configured `LOG2SIZE`.
    pub(crate) strtab_cfg_ok: bool,
    /// Every requested `CR0` bit is set in **`CR0ACK`**: the SMMU acknowledged the enable.
    pub(crate) enabled: bool,
    /// The initial `CMD_CFGI_STE_RANGE` + `CMD_SYNC` was **consumed** (`CMDQ_CONS` reached `PROD`)
    /// and left `GERROR == GERRORN`. Both halves matter: a malformed command stalls the queue with a
    /// global error, and a stalled queue makes every later `CMD_CFGI_STE` silently do nothing — so an
    /// STE edit would appear to take effect when the SMMU never saw it.
    pub(crate) gerror_clean: bool,
    /// The freshly-built table, read back through `hv-s2`'s *decode* seam, permits no StreamID.
    pub(crate) denies_every_stream: bool,
}

impl StreamTableReport {
    /// Every fact that must hold for a later deny result to be about the stream table at all.
    pub(crate) fn ok(&self) -> bool {
        self.page1_at_64k
            && self.strtab_base_ok
            && self.strtab_cfg_ok
            && self.enabled
            && self.gerror_clean
            && self.denies_every_stream
            && STRTAB_LOG2SIZE <= self.sidsize
    }
}

/// Build an all-deny stream table, enable the queues, and turn the SMMU on.
///
/// The order is load-bearing at both ends. The table is fully zeroed and its base published *before*
/// `SMMUEN`, so the SMMU never translates against a table that does not exist; and `GBPA.ABORT`
/// (rung 1, already set by the time this runs) governs everything before `SMMUEN` takes. There is no
/// instant in which a bus master is admitted.
///
/// Nothing here is a claim about isolation yet — an all-deny table is trivially satisfiable by an
/// SMMU that is not looking at it. That is what the caller's through-STE control is for.
///
/// `stream_of` is the `DevId → StreamID` map (rung 4b) and is taken **here** rather than through a
/// setter of its own: it is what gives the table's indices meaning, so a stream table that exists
/// without one should not be constructible.
pub(crate) fn install_stream_table(stream_of: [u32; crate::NUM_DEVICES]) -> StreamTableReport {
    let idr1 = read32(SMMU_IDR1);
    let sidsize = idr1 & IDR1_SIDSIZE_MASK;
    let page1_at_64k = idr1 & IDR1_REL == 0;

    let mut smmu = SMMU.borrow_mut();

    // (1) The table itself — deny by construction, established by `hv-s2` rather than inherited from
    //     `.bss` being zero (a linker property this code should not depend on).
    st::init_deny(&mut smmu.strtab.0);
    let strtab_pa = core::ptr::addr_of!(smmu.strtab.0) as u64;

    // (2) The SMMU's own fetch attributes. `CR1 = 0` is non-cacheable, non-shareable for both tables
    //     and queues. Written explicitly rather than left at its reset value: rung 1's entire
    //     content was a reset value that happened to be wrong.
    //
    // ⚠⚠ **A2 KILLED THIS VALUE'S ORIGINAL JUSTIFICATION AND KEPT THE VALUE. Read the new one.**
    //     It used to be justified as matching "an EL2 running MMU-off, where every CPU store is
    //     Device-nGnRnE and reaches memory directly", and noted that Linux writes
    //     write-back/inner-shareable here "because *its* CPU mappings are cacheable; copying that
    //     value would be copying a premise baleen does not have". **Baleen now has that premise** —
    //     A2 made EL2's DRAM Normal-WB Inner-Shareable — and both SMMU platforms report
    //     `IDR0.COHACC = 1` (measured: AEM `0x080fe6bf`, QEMU `0x0d44101b`), so the coherent
    //     configuration is available and would be correct.
    //
    // ★ **It is deliberately NOT taken, and the reason is which arm the instrument graded.**
    //     `fvp-probe` milestone 6 measured the **non-coherent** arm: CPU cacheable, `CR1 = 0`,
    //     maintenance required — and found both of `publish`'s requirements there. Setting
    //     `CR1 = WB/ISH` would discharge every one of those obligations at a stroke by making the
    //     SMMU snoop, and would be the *ungraded* configuration on both platforms, defended by an ID
    //     register rather than by a measurement. Explicit maintenance is correct under EITHER value
    //     (cleaning to the point of coherency is redundant for a snooping observer, never wrong),
    //     so this keeps the arm with evidence and pays a few hundred cache operations for it.
    //     Flipping it is a rung with its own witness, not a one-line optimisation.
    write32(SMMU_CR1, 0);
    // Record an event for a StreamID outside the table, so the out-of-range denial is observable
    // rather than merely silent.
    write32(SMMU_CR2, CR2_RECINVSID);

    // (3) Publish the table, then point the SMMU at it.
    let (strtab_base_va, strtab_len) = strtab_range(&smmu);
    publish(strtab_base_va, strtab_len);
    write64(SMMU_STRTAB_BASE, st::strtab_base(strtab_pa));
    write32(SMMU_STRTAB_BASE_CFG, STRTAB_CFG);
    // Read back through the SAME masking function that produced the written value, rather than
    // against a copy of the ADDR mask: a duplicated field literal that drifts would make this check
    // agree with itself and with nothing else.
    let strtab_base_ok = st::strtab_base(read64(SMMU_STRTAB_BASE)) == st::strtab_base(strtab_pa);
    let strtab_cfg_ok = read32(SMMU_STRTAB_BASE_CFG) == STRTAB_CFG;

    // (4) The queues, then the enables. `CMDQ`/`EVENTQ` come up before `SMMUEN` so that the first
    //     configuration invalidation can be issued while nothing is translating.
    let cmdq_pa = core::ptr::addr_of!(smmu.cmdq.0) as u64;
    let eventq_pa = core::ptr::addr_of!(smmu.eventq.0) as u64;
    smmu.cmdq_prod = 0;
    smmu.eventq_cons = 0;
    // Both queues, not just the command queue: the SMMU reads one and WRITES the other, and under
    // A2 an event-queue line EL2 holds would be a line the SMMU's records have to displace.
    publish(cmdq_pa, core::mem::size_of_val(&smmu.cmdq.0) as u64);
    publish(eventq_pa, core::mem::size_of_val(&smmu.eventq.0) as u64);
    write64(SMMU_CMDQ_BASE, cmdq_pa | u64::from(CMDQ_LOG2SIZE));
    write32(SMMU_CMDQ_PROD, 0);
    write32(SMMU_CMDQ_CONS, 0);
    write64(SMMU_EVENTQ_BASE, eventq_pa | u64::from(EVENTQ_LOG2SIZE));

    // The event queue's producer/consumer indices live in the SMMU's **page 1**, and `IDR1.REL` is
    // what says where page 1 is. Gate the writes on it rather than merely reporting it afterwards:
    // if `REL` disagreed, these offsets would name some *other* register, and writing an index into
    // an unidentified register is a worse failure than not having an event queue. The boot fails
    // either way (`StreamTableReport::ok` requires `page1_at_64k`), but it fails without having
    // poked something unknown.
    let mut enabled = page1_at_64k;
    if page1_at_64k {
        write32(SMMU_EVENTQ_PROD, 0);
        write32(SMMU_EVENTQ_CONS, 0);
        enabled = set_cr0_bits(CR0_CMDQEN | CR0_EVENTQEN);
    }

    // (5) Invalidate the whole configuration cache before enabling translation: the SMMU may hold
    //     STEs from before this table existed (on QEMU it does not, on silicon after a warm reset it
    //     may), and an enable that inherited a stale permissive entry is precisely the window rung 1
    //     closed at the `GBPA` level.
    let gerror_clean = invalidate_all_config(&mut smmu);

    enabled &= set_cr0_bits(CR0_SMMUEN);

    // (6) Read the table back through `hv-s2`'s DECODE seam — not the builder's own bookkeeping — and
    //     assert it permits nothing. The Kani property says the builder writes a denying table; this
    //     says the bytes at the address the SMMU was handed are one.
    let denies_every_stream = st::denies_every_stream(&smmu.strtab.0, STRTAB_LOG2SIZE);

    // (7) Rung 4b: the fence crossing, and the arming of the post-dispatch derivation. From here on
    //     the stream table is a function of `hv-core`'s assignment relation, re-derived after every
    //     dispatch; before here the answer to a bus master was rung 1's `GBPA.ABORT`.
    smmu.stream_of = stream_of;
    smmu.armed = true;

    StreamTableReport {
        sidsize,
        page1_at_64k,
        strtab_pa,
        strtab_base_ok,
        strtab_cfg_ok,
        enabled,
        gerror_clean,
        denies_every_stream,
    }
}

/// Set `bits` in `CR0` and wait for **`CR0ACK`** to show them. Returns whether the SMMU acknowledged.
///
/// Bounded, and reports failure rather than spinning: an SMMU that never acknowledges must not hang a
/// CI boot, and "the enable did not take" is exactly the fact a vacuous deny would otherwise hide.
fn set_cr0_bits(bits: u32) -> bool {
    let want = read32(SMMU_CR0) | bits;
    write32(SMMU_CR0, want);
    for _ in 0..100_000 {
        if read32(SMMU_CR0ACK) & bits == bits {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Push one 16-byte command and ring the doorbell.
///
/// ★ **The three statements below were already in the right ORDER before A2 — bytes, publish,
/// doorbell — and that is why A2's silent half cost nothing here.** [`publish`]'s requirement 2 says
/// a command whose bytes are not published lets `CMD_SYNC` report success over a stale ring slot;
/// the structure that prevents it is this sequence, and it only had to be given a range to keep
/// working once `publish` stopped being a global barrier.
fn submit(smmu: &mut Smmu, word0: u64, word1: u64) {
    let idx = (smmu.cmdq_prod as usize) & (CMDQ_ENTRIES - 1);
    smmu.cmdq.0[idx * 2] = word0;
    smmu.cmdq.0[idx * 2 + 1] = word1;
    // The command must be visible to the SMMU *before* `PROD` tells it to look. The range is this
    // one slot: `CMDQ_PROD` names the slot, so publishing the slot is publishing exactly what the
    // doorbell is about to point at.
    publish(
        core::ptr::addr_of!(smmu.cmdq.0[idx * 2]) as u64,
        2 * core::mem::size_of::<u64>() as u64,
    );
    smmu.cmdq_prod = smmu.cmdq_prod.wrapping_add(1) & queue_mask(CMDQ_LOG2SIZE);
    write32(SMMU_CMDQ_PROD, smmu.cmdq_prod);
}

/// Issue `CMD_SYNC` and wait for `CMDQ_CONS` to reach `CMDQ_PROD`.
///
/// Returns whether the queue drained *and* no global error appeared. The second half matters: a
/// malformed command makes the SMMU raise `GERROR.CMDQ_ERR` and **stall** the queue, which otherwise
/// looks identical to a sync that is merely slow — and a stalled queue means every later
/// `CMD_CFGI_STE` silently does nothing, so an STE edit would appear to have no effect and the deny
/// phase would "pass" without the SMMU ever having seen the change.
fn sync(smmu: &mut Smmu) -> bool {
    submit(smmu, CMD_SYNC, 0);
    for _ in 0..1_000_000 {
        if read32(SMMU_CMDQ_CONS) & queue_mask(CMDQ_LOG2SIZE) == smmu.cmdq_prod {
            return read32(SMMU_GERROR) == read32(SMMU_GERRORN);
        }
        core::hint::spin_loop();
    }
    false
}

/// `CMD_CFGI_STE` for every StreamID the table covers, via the range form (`Range = 31` is "all").
fn invalidate_all_config(smmu: &mut Smmu) -> bool {
    // Opcode 0x04 is `CMD_CFGI_STE_RANGE`; word 1's `Range` field [4:0] = 31 invalidates everything.
    submit(smmu, 0x04, 31);
    sync(smmu)
}

/// Re-announce the table's size to the SMMU as `2^log2size` entries, leaving its **contents**
/// untouched.
///
/// Exists for one witness: the architecture denies a StreamID outside the configured table
/// (`C_BAD_STREAMID`) *before* it ever fetches an entry, which is what makes "size the table to PCIe
/// bus 0" a stronger denial than a zeroed entry rather than a coverage gap. Shrinking the announced
/// size below a StreamID whose STE is still **permissive** isolates that arm exactly: the entry says
/// yes, the range check says no, and only one of them can be the reason the DMA fails.
///
/// **Refuses to announce a size larger than the allocation.** That is the one way a linear stream
/// table fails *open* — the SMMU would fetch STEs from past the table — and it is the state
/// `hv-s2`'s `TableTooSmall` refusal exists to keep unreachable. A test helper is exactly the sort of
/// path that would otherwise create it.
pub(crate) fn set_announced_table_size(log2size: u32) -> bool {
    if log2size > STRTAB_LOG2SIZE {
        return false;
    }
    let Some(cfg) = st::strtab_base_cfg(log2size) else {
        return false;
    };
    write32(SMMU_STRTAB_BASE_CFG, cfg);
    let mut smmu = SMMU.borrow_mut();
    let synced = invalidate_all_config(&mut smmu);
    synced && read32(SMMU_STRTAB_BASE_CFG) == cfg
}

/// Invalidate one StreamID's cached configuration and wait for the invalidation to complete.
///
/// This is the SMMU's analogue of the Stage-2 path's `dsb`+`tlbi`+`isb`: without it the SMMU may keep
/// serving a *cached* STE, so an edit to the table in RAM would not be the edit the hardware is
/// acting on — and a deny phase following a bypass phase would be testing the wrong bytes.
fn invalidate_ste(smmu: &mut Smmu, sid: u32) -> bool {
    submit(
        smmu,
        CMD_CFGI_STE | (u64::from(sid) << 32),
        1, /* Leaf */
    );
    sync(smmu)
}

/// Install a **bypass** STE for `sid` — rung 2's positive control.
///
/// Returns whether the entry was written, the invalidation completed, and the table now reads back
/// (through the decode seam) as permitting exactly this one StreamID and no other. That last clause
/// is what makes this a check rather than a report: a bind that also permitted a neighbour would pass
/// a "the bound stream is permitted" test and fail this one.
pub(crate) fn bind_stream_bypass(sid: u32) -> bool {
    let mut smmu = SMMU.borrow_mut();
    if st::bind(&mut smmu.strtab.0, STRTAB_LOG2SIZE, sid, st::bypass_ste()).is_err() {
        return false;
    }
    let (strtab_va, strtab_len) = strtab_range(&smmu);
    publish(strtab_va, strtab_len);
    let synced = invalidate_ste(&mut smmu, sid);
    let permits_only_this = st::permitted_stream_count(&smmu.strtab.0, STRTAB_LOG2SIZE) == 1
        && st::verdict(&smmu.strtab.0, STRTAB_LOG2SIZE, sid).permits();
    synced && permits_only_this
}

/// **Bind `sid` to a DOMAIN** — install the stage-2 STE for `binding` (SMMU rung 3).
///
/// The device now reaches memory only through the domain's own `p2m`-derived Stage-2 tables, under
/// the domain's VMID: one proven `p2m`, two consumers. Where [`bind_stream_bypass`] permits a device
/// to place its own addresses on memory, this constrains every one of them to the same relation the
/// domain's CPU is held to.
///
/// Returns whether the entry was written, both invalidations completed, and the table reads back —
/// **through the decode seam, not from the caller's copy** — as binding exactly this StreamID, to
/// exactly this table, under exactly this VMID. That last clause is the check that can fail: a bind
/// that truncated the table pointer or the VMID would satisfy "the stream is permitted" and fail
/// this.
pub(crate) fn bind_stream_stage2(sid: u32, binding: &st::Stage2Binding) -> bool {
    let mut smmu = SMMU.borrow_mut();
    if st::bind_stage2(&mut smmu.strtab.0, STRTAB_LOG2SIZE, sid, binding).is_err() {
        return false;
    }
    let (strtab_va, strtab_len) = strtab_range(&smmu);
    publish(strtab_va, strtab_len);
    // Both invalidations, in this order: the configuration cache (which STE this stream uses) and
    // then the stage-2 TLB (what that STE's tables translated to last time).
    let synced = invalidate_ste(&mut smmu, sid) && invalidate_s2_tlb(&mut smmu);
    let reads_back = st::stage2_binding_at(&smmu.strtab.0, STRTAB_LOG2SIZE, sid) == Some(*binding);
    let only_this = st::permitted_stream_count(&smmu.strtab.0, STRTAB_LOG2SIZE) == 1;
    synced && reads_back && only_this
}

/// Invalidate every cached stage-2 translation. See [`CMD_TLBI_NSNH_ALL`].
fn invalidate_s2_tlb(smmu: &mut Smmu) -> bool {
    submit(smmu, CMD_TLBI_NSNH_ALL, 0);
    sync(smmu)
}

/// Restore `sid`'s entry to the all-zero deny, and confirm the whole table denies again.
pub(crate) fn unbind_stream(sid: u32) -> bool {
    let mut smmu = SMMU.borrow_mut();
    if st::unbind(&mut smmu.strtab.0, STRTAB_LOG2SIZE, sid).is_err() {
        return false;
    }
    let (strtab_va, strtab_len) = strtab_range(&smmu);
    publish(strtab_va, strtab_len);
    let synced = invalidate_ste(&mut smmu, sid);
    synced && st::denies_every_stream(&smmu.strtab.0, STRTAB_LOG2SIZE)
}

// ─── Rung 4b: the table is DERIVED from the model, after every dispatch ──────────────────────────

/// Record the Stage-2 tables domain `dom`'s image was emitted at.
///
/// Called by [`crate::stage2::build_stage2_from_p2m`] itself — the emission seam, not its callers —
/// so a domain whose image is built can never be a domain the device side has not heard of.
///
/// **It no longer derives anything.** The binding arrives already minted by
/// [`hv_s2::smmu::stage2_handles`] from the same `Layout` the encoder was handed, alongside the
/// `VTTBR_EL2` the CPU is given. Until the device-path composition this function computed the
/// `S2TTB` itself, by reading it back out of the register value — a second derivation of the table
/// base, boot-witnessed and proven nowhere, and unsound above 2⁴⁸ because the two register fields
/// are not the same width (`docs/SMMU-DEVICE-PATH-COMPOSITION.md` §3b).
pub(crate) fn register_domain_binding(dom: hv_core::hypervisor::DomId, binding: st::Stage2Binding) {
    let mut smmu = SMMU.borrow_mut();
    if let Some(slot) = smmu.binding_of.get_mut(dom as usize) {
        *slot = Some(binding);
    }
}

/// What one re-derivation did.
pub(crate) enum Derived {
    /// No stream table yet — rung 1's `GBPA.ABORT` is the answer at this point in the boot.
    NotArmed,
    /// The relation still says exactly what the published table says; the hardware was not touched.
    Unchanged,
    /// The table changed and was republished (invalidated, and read back as refining the relation).
    Published,
    /// The relation names something the hardware cannot be configured to express. The table has
    /// been left **denying every stream** and published; the caller must stop the machine.
    Refused(st::DeriveError),
    /// The derivation succeeded but the bytes at the address the SMMU walks do **not** refine the
    /// relation — an emit/decode disagreement, and a fail-loud one.
    Unfaithful,
}

/// **Re-derive the stream table from `hv`'s assignment relation, and publish it if it changed.**
///
/// The device-axis twin of [`crate::stage2::build_stage2_from_p2m`], and the consumer rung 4a's
/// proven relation was missing. Called from [`crate::teardown::dispatch`]'s post-dispatch funnel,
/// unconditionally, for the reason the module docs give: a stream table is a **pure function of
/// state**, not an action hanging off a transition, so re-deriving it is simply correct where the
/// frame scrub had to diff for an *edge*. What is diffed here is the derived artifact — the words —
/// which is not a soundness question at all: equal words mean the hardware already holds the right
/// configuration.
///
/// **What it deliberately does NOT check.** It does not re-test that the holder is `Live`, and the
/// metal does not withdraw a domain's binding when that domain dies. Both are obvious
/// defence-in-depth and both would **mask the model's own mechanism**: with either in place,
/// deleting `device::System::release_all_of` from `domain_destroy` would leave the device denied for
/// the *metal's* reason, and the probe that shows the proven sweep is load-bearing could not go red.
/// The metal consumes `assigned ⇒ Live` (proven ∀-values, ∀-size and over every reachable state in
/// rung 4a) instead of duplicating it — which is what it means for this table to *refine* the
/// relation rather than to run beside it.
pub(crate) fn rederive(hv: &hv_core::Hypervisor) -> Derived {
    let mut smmu = SMMU.borrow_mut();
    if !smmu.armed {
        return Derived::NotArmed;
    }
    // Copied out so the derivation can borrow the scratch table mutably; both are a handful of
    // words, and taking them by value keeps the maps immutable for the duration of a derivation.
    let streams = smmu.stream_of;
    let bindings = smmu.binding_of;

    let outcome = st::derive_stream_table(
        &mut smmu.scratch.0,
        STRTAB_LOG2SIZE,
        hv.device(),
        &streams,
        &bindings,
    );

    if smmu.scratch.0 == smmu.strtab.0 {
        // The relation has not changed the table. Note this is reached on a refusal too — a second
        // refused dispatch after the table is already all-deny — so the error is still reported.
        return match outcome {
            Ok(()) => Derived::Unchanged,
            Err(e) => Derived::Refused(e),
        };
    }

    {
        // Disjoint field borrows, checked rather than argued (the `Stage2Set` idiom).
        let Smmu {
            strtab, scratch, ..
        } = &mut *smmu;
        strtab.0.copy_from_slice(&scratch.0);
    }
    let (strtab_va, strtab_len) = strtab_range(&smmu);
    publish(strtab_va, strtab_len);
    // The whole table was rebuilt, so the whole configuration cache is invalidated — the range form
    // of the same `CMD_CFGI_STE` rung 3 probed load-bearing — and then the stage-2 TLB, because a
    // stream whose STE now names a different domain's tables must not be answered from translations
    // cached for the previous one.
    let synced = invalidate_all_config(&mut smmu) && invalidate_s2_tlb(&mut smmu);
    smmu.published = smmu.published.wrapping_add(1);

    if let Err(e) = outcome {
        return Derived::Refused(e);
    }
    // Read the published bytes back through the DECODE seam and compare against what the RELATION
    // asks for — the two directions at once, over the table the SMMU will actually walk rather than
    // over the builder's bookkeeping. `hv-s2`'s unit tests confirm this predicate can answer `false`
    // for an extra entry, a missing one, and a merely-permitting one.
    if !synced
        || !st::table_refines_the_relation(
            &smmu.strtab.0,
            STRTAB_LOG2SIZE,
            hv.device(),
            &streams,
            &bindings,
        )
    {
        return Derived::Unfaithful;
    }
    Derived::Published
}

/// The binding StreamID `sid`'s entry currently expresses, read back through the decode seam.
/// The witness's window onto the derived table.
pub(crate) fn published_binding(sid: u32) -> Option<st::Stage2Binding> {
    let smmu = SMMU.borrow_mut();
    st::stage2_binding_at(&smmu.strtab.0, STRTAB_LOG2SIZE, sid)
}

/// Whether the derived table currently permits no StreamID at all.
pub(crate) fn denies_everything() -> bool {
    let smmu = SMMU.borrow_mut();
    st::denies_every_stream(&smmu.strtab.0, STRTAB_LOG2SIZE)
}

/// How many derivations have reached the hardware. A phase that asserts a *change* asserts against
/// this, so "the table says what I expect" cannot pass because no derivation ever ran.
pub(crate) fn derivations_published() -> u32 {
    SMMU.borrow_mut().published
}

/// One decoded SMMU event record.
pub(crate) struct SmmuEvent {
    /// The record's type field — see [`EVT_C_BAD_STE`] / [`EVT_C_BAD_STREAMID`].
    pub(crate) kind: u8,
    /// The StreamID the faulting transaction carried.
    pub(crate) sid: u32,
    /// The **input address** the faulting transaction carried (record word 2), i.e. the address the
    /// device asked for.
    ///
    /// Only meaningful for the translation-fault classes (`F_TRANSLATION`, `F_PERMISSION`); a
    /// configuration fault such as `C_BAD_STE` is raised before any address is translated. Collected
    /// because it is the sharpest attribution rung 3 can get: the SMMU stating *which address* it
    /// refused turns "the sentinel did not change" into "the walk of this domain's table refused
    /// exactly the address the device put on the bus" (design-lesson #70(d)).
    pub(crate) addr: u64,
    /// `EVENTQ_PROD` as read from the device, so a caller can tell "the queue produced nothing" from
    /// "the queue produced something this code failed to decode".
    pub(crate) prod: u32,
}

/// Discard every record currently in the event queue, returning how many there were.
///
/// Called **before** each observed DMA so that whatever the queue then holds was produced by *that*
/// transaction. Without it the queue is a running log and [`take_event`] returns the oldest record in
/// it — which measurably is not the one under test: a single aborted 8-byte `edu` transfer produces
/// **two** records here (QEMU translates the access more than once), so by the third phase the "first
/// event" was two phases old. That mistake was live and the event assertion caught it, which is the
/// argument for asserting the event's *type and StreamID* rather than merely that one exists.
pub(crate) fn drain_events() -> u32 {
    let mut n = 0;
    while take_event().is_some() {
        n += 1;
        // The queue is 16 entries; a bound rather than a `while` on a device-driven condition.
        if n >= EVENTQ_ENTRIES as u32 {
            break;
        }
    }
    n
}

/// Pop the oldest event record, if the queue holds one.
///
/// Deliberately reads the record out of the **queue's own memory** (a plain CPU load of RAM the SMMU
/// wrote) and takes only the *count* from `EVENTQ_PROD`. If [`SMMU_EVENTQ_PROD`]'s page-1 offset were
/// wrong, the count would be wrong but the record would not — so the two pieces of evidence fail
/// independently, which is the point of collecting both.
///
/// ## ⚠⚠ A2: this is the only place in the SMMU path where the data flows the OTHER way
///
/// Every other structure here is EL2 writing and the SMMU reading, discharged by [`publish`]. **This
/// is the SMMU writing and EL2 reading**, and under A2 a plain load is answered from a cache the
/// SMMU (`CR1 = 0`) never wrote to. The record would be whatever that ring slot held before — for a
/// queue whose entries start zeroed, a **zeroed record**, which decodes to event kind 0 and would be
/// read as "the queue produced nothing this code could decode".
///
/// So the record is invalidated before it is read. [`crate::cache::invalidate`] is `DC IVAC`, which
/// **discards** rather than writes back, and that is safe here for a reason specific to this
/// structure: **EL2 never stores into an event record.** The queue is zeroed as part of `.bss` while
/// the MMU is off, published once in `install_stream_table`, and thereafter written only by the
/// device. There is no EL2 dirty line to lose. A `DC CIVAC` here would be the #168 inversion —
/// cleaning EL2's stale copy back over the SMMU's record on the way to reading it.
pub(crate) fn take_event() -> Option<SmmuEvent> {
    let mut smmu = SMMU.borrow_mut();
    let prod = read32(SMMU_EVENTQ_PROD) & queue_mask(EVENTQ_LOG2SIZE);
    if prod == smmu.eventq_cons {
        return None;
    }
    let idx = (smmu.eventq_cons as usize) & (EVENTQ_ENTRIES - 1);
    crate::cache::invalidate(
        core::ptr::addr_of!(smmu.eventq.0[idx * 4]) as u64,
        4 * core::mem::size_of::<u64>() as u64,
    );
    let word0 = smmu.eventq.0[idx * 4];
    // Word 2 of a 32-byte fault record is the transaction's input address (`InputAddr`).
    let word2 = smmu.eventq.0[idx * 4 + 2];
    smmu.eventq_cons = smmu.eventq_cons.wrapping_add(1) & queue_mask(EVENTQ_LOG2SIZE);
    write32(SMMU_EVENTQ_CONS, smmu.eventq_cons);
    Some(SmmuEvent {
        kind: (word0 & 0xff) as u8,
        sid: (word0 >> 32) as u32,
        addr: word2,
        prod,
    })
}
