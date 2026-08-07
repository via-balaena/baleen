// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The DMA witness — a real bus master, whether the SMMU stops it, and where it lands (rungs 1–3)
//!
//! Every isolation result baleen has is about **CPU** accesses. To say anything about DMA there has to
//! be a device that actually performs it, so this module builds the smallest possible one and then
//! observes whether its writes land.
//!
//! ⚠ **⑲-1 — "rungs 1–3" IS NOW CONFIGURATION-DEPENDENT, and the title is kept only because the
//! `smmu` configuration is still where this module is fully exercised.** Rungs 1 and 2 are about the
//! SMMU itself and run everywhere the feature is on, including alongside real Linux guests. **Rungs 3
//! and 4 are about a DOMAIN's `p2m` and run only under `not(real-linux)`** — they must own the
//! machine's domains and frames, and in a real-Linux build both collide (model frames land inside the
//! 448-frame super partition; `DOM_A`/`DOM_B` are the real guests' own ids). The full reasoning, and
//! the measurement that forced it, is on the `rung3` call in `witness` below.
//!
//! ✅ **⑲-2 — and do not read the paragraph above as "no domain-`p2m` confinement under
//! real-linux". There is; it just is not rungs 3/4.** `witness_real_guest` binds the same bus
//! master to a REAL guest's own Stage-2 image — `S2TTB` = the table `VTTBR_EL2` carries for a domain
//! running an unmodified Alpine kernel — and shows it reaches that guest and is ABORTED on its
//! peer's memory. It is called from `linux::run`, not from [`witness`], because it needs the guests'
//! emitted images to exist first. So under `real-linux` the module contributes rungs 1–2 **plus**
//! ⑲-2; what it does not contribute there is rung 3's non-identity translation claim, which its
//! own doc explains is unreachable on identity-mapped guests.
//!
//! ## Why QEMU's `edu` device
//!
//! The natural candidate was `virtio-blk-pci`, but driving virtio means a virtqueue, descriptor rings,
//! and feature negotiation — hundreds of lines of driver before a single DMA happens, none of it
//! isolation content. QEMU's `edu` device (`hw/misc/edu.c`) is a teaching device whose entire DMA
//! engine is four registers: source, destination, count, command. Six MMIO writes and it is a bus
//! master. That keeps rung 1's cost in the part that matters (the SMMU) rather than in PCIe driver
//! plumbing.
//!
//! ## The witness, and why it needs TWO boots
//!
//! The device is told to write over a sentinel in EL2 RAM. Its internal buffer is zero at reset, so:
//!
//! * **DMA landed** ⟹ the sentinel reads back zero.
//! * **DMA was aborted** ⟹ the sentinel still holds its magic value.
//!
//! A single boot cannot establish anything, and this is the trap worth naming (design-lesson #66): a
//! run in which the sentinel survives proves the SMMU blocked the write *only if* the write would
//! otherwise have happened. If the BAR were misassigned, or bus mastering never enabled, or the device
//! absent, the sentinel would survive for entirely uninteresting reasons and the "isolation" result
//! would be vacuous. So the arc is witnessed across two machine configurations:
//!
//! | boot | machine | expectation |
//! |---|---|---|
//! | **positive control** | `virt` (no `iommu=`) | no SMMU present; the DMA **lands** — the sentinel is zeroed |
//! | **default-deny** | `virt,iommu=smmuv3` | the metal sets `GBPA.ABORT` first; the DMA is **aborted** — the sentinel survives |
//!
//! The positive control is the load-bearing half. It is what makes the negative result mean "the SMMU
//! stopped a write that was really about to happen".
//!
//! ## Rung 2: the same idea, one boot, five phases
//!
//! Rung 1's control differs from its deny in the **machine** (SMMU or no SMMU), which leaves a lot
//! unexplained between the two runs. `rung2` tightens that to the smallest possible difference: one
//! boot, one machine, one device, and phases that differ only in the contents of a single 64-byte
//! Stream Table Entry — or, in the last phase, only in the table *size* announced to the SMMU. See
//! `rung2` for the phase table and what each one rules out.
//!
//! **What the phases are for** is the whole design. Every one of them exists because some *other*
//! explanation of "the DMA was aborted" had to be excluded, and each was confirmed able to fail by
//! deliberately breaking the thing it tests:
//!
//! * skip the bypass bind, and phase 1 stops landing — so the through-path is caused by the STE;
//! * skip the unbind, and phase 2 lands — so the denial is caused by zeroing the STE;
//! * bind the device's own StreamID instead of the neighbour, and phase 3 lands — so the permit is
//!   per-StreamID;
//! * bind the **wrong** StreamID throughout, and *every* phase loses its outcome — so the whole
//!   result rests on `pcie::stream_id` being the RequesterID the hardware really presents;
//! * never write `CR0.SMMUEN`, and every phase reports "aborted" — which is exactly the vacuous deny
//!   this rung is built to exclude, and exactly what phase 1 catches.
//!
//! ## Rung 3: the same idea again, and the sentinel that must NOT change
//!
//! Rung 2 could only show the device reaches its STE — everything it permits, it permits unconfined.
//! `rung3` binds the device to a **domain's own Stage-2 tables** and asks the sharper question: not
//! "did something land?" but "did it land where the **table** says, rather than where the **device**
//! asked?" Two sentinels at two different addresses, both seeded and read back, and the
//! discriminator is which one moved. Probed: swap the stage-2 STE for a bypass STE and the two
//! sentinels swap roles exactly.

use crate::pcie;
use crate::pl011::Pl011;
#[cfg(feature = "smmu")]
use crate::smmu;
use core::fmt::Write;
#[cfg(feature = "smmu")]
use hv_core::hypervisor::DomId;
#[cfg(feature = "smmu")]
use hv_core::p2m::{Mfn, PtLevel};
#[cfg(feature = "smmu")]
use hv_core::{HvCall, Hypervisor};

/// QEMU `edu` PCI identity (`hw/misc/edu.c`): QEMU's vendor id and the `edu` device id.
const EDU_VENDOR: u16 = 0x1234;
const EDU_DEVICE: u16 = 0x11e8;

/// `edu` BAR0 register offsets. Only the identification register and the DMA engine are used.
/// Identification reads `0x010000ed` (major 1, minor 0) — the "the device is really there and decoding
/// its BAR" check, so a misassigned BAR is caught here rather than misread later as an SMMU abort.
const EDU_REG_ID: u64 = 0x00;
/// DMA source address (8 bytes).
const EDU_REG_DMA_SRC: u64 = 0x80;
/// DMA destination address (8 bytes).
const EDU_REG_DMA_DST: u64 = 0x88;
/// DMA transfer length in bytes (8 bytes).
const EDU_REG_DMA_CNT: u64 = 0x90;
/// DMA command: bit 0 `RUN` (self-clearing on completion), bit 1 direction, bit 2 raise interrupt.
const EDU_REG_DMA_CMD: u64 = 0x98;

/// The expected `edu` identification value.
const EDU_ID_VALUE: u32 = 0x0100_00ed;

/// `edu`'s DMA command bits.
const EDU_DMA_RUN: u64 = 1 << 0;
/// Direction bit set = **device → RAM** (`pci_dma_write`), which is the direction that leaves visible
/// evidence in memory. Clear would be RAM → device, whose effect is only observable by asking the
/// device, and so a weaker witness.
const EDU_DMA_TO_RAM: u64 = 1 << 1;

/// Base of `edu`'s internal 4 KiB buffer in its own address space (`EDU_DMA_START` in `edu.c`). A
/// device→RAM transfer reads from here; it is zero-filled at reset, which is what lets a landed DMA be
/// detected as "the sentinel became zero" with no prior transfer needed to populate it.
const EDU_DMA_BUF: u64 = 0x4_0000;

/// The magic a sentinel holds before the DMA. Survives ⟹ the write was aborted.
const SENTINEL_MAGIC: u64 = 0xD11A_5EED_D11A_5EED;

/// One sentinel per DMA attempt across the whole witness — rung 1's, and one for each of rung 2's
/// five phases.
///
/// A sentinel **per attempt** rather than one re-seeded between them, deliberately: re-seeding would
/// mean every phase's "before" value was written by *this* code moments earlier, so a phase that
/// silently ran twice, or one whose write landed after the read, would still look clean. Distinct
/// statics make each phase's evidence independent of every other phase's, and the count of them is
/// checked at compile time against the phases that exist.
const NSENTINELS: usize = 6;

/// The DMA targets: sentinels in EL2 RAM, each in its own cache-line-aligned slot so no neighbouring
/// state is perturbed if a transfer *does* land. `static mut` rather than an atomic because the write
/// under observation comes from a **device**, not a CPU — the whole point is that it bypasses every
/// CPU-side mechanism, so the interesting accesses are not Rust's to order.
#[repr(align(64))]
struct Sentinel(u64);
static mut DMA_SENTINELS: [Sentinel; NSENTINELS] = [const { Sentinel(SENTINEL_MAGIC) }; NSENTINELS];

fn mmio_write64(base: u64, off: u64, v: u64) {
    // SAFETY: `base` is the BAR0 window `pcie::enable_with_bar0` assigned inside the `virt` 32-bit
    // PCIe MMIO range, and `off` a documented `edu` register — device memory at EL2 (MMU off),
    // aliasing no Rust object.
    unsafe { core::ptr::write_volatile((base + off) as *mut u64, v) }
}

fn mmio_read64(base: u64, off: u64) -> u64 {
    // SAFETY: as `mmio_write64`; read-only.
    unsafe { core::ptr::read_volatile((base + off) as *const u64) }
}

fn mmio_read32(base: u64, off: u64) -> u32 {
    // SAFETY: as `mmio_write64`; read-only.
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

/// Read sentinel `i` back after the device has (or has not) written to it.
fn sentinel(i: usize) -> u64 {
    // SAFETY: `DMA_SENTINELS` is written only by the DEVICE under test (via DMA) and read here; no
    // Rust code holds a reference to it across this read, and the metal is single-threaded with the
    // secondaries parked. A volatile read is used because the value can change without any CPU store,
    // which is precisely what is being detected.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DMA_SENTINELS[i].0)) }
}

/// Sentinel `i`'s physical address — what the device is told to write to. Identity, since EL2 runs
/// MMU-off.
fn sentinel_pa(i: usize) -> u64 {
    // SAFETY: taking the address of a static is sound; no dereference here.
    unsafe { core::ptr::addr_of!(DMA_SENTINELS[i].0) as u64 }
}

/// Ask `edu` to DMA `8` bytes from its zeroed internal buffer over the sentinel, and wait (bounded)
/// for the engine to report completion. Returns whether the command retired.
///
/// The bound matters: `edu` runs its transfer off a QEMU timer, and when the SMMU aborts the write the
/// engine still completes (an aborted transaction is terminated, not stalled) — but a machine that
/// never retires the command must not hang a CI boot test. A timeout is reported, not waited out.
fn trigger_dma(bar0: u64, dst: u64) -> bool {
    mmio_write64(bar0, EDU_REG_DMA_SRC, EDU_DMA_BUF);
    mmio_write64(bar0, EDU_REG_DMA_DST, dst);
    mmio_write64(bar0, EDU_REG_DMA_CNT, 8);
    mmio_write64(bar0, EDU_REG_DMA_CMD, EDU_DMA_RUN | EDU_DMA_TO_RAM);
    for _ in 0..20_000_000u64 {
        if mmio_read64(bar0, EDU_REG_DMA_CMD) & EDU_DMA_RUN == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// One DMA attempt at sentinel `i`: what it held before, what it holds after, and whether the engine
/// retired the command.
struct Attempt {
    before: u64,
    after: u64,
    retired: bool,
}

impl Attempt {
    /// Whether the device's write reached memory.
    fn landed(&self) -> bool {
        self.after != self.before
    }

    /// Whether this attempt is *interpretable at all*: the sentinel started at its magic and the
    /// engine reported completion. An attempt that fails this says nothing about the SMMU either way,
    /// so both the "landed" and the "aborted" verdicts are gated on it.
    fn well_formed(&self) -> bool {
        self.before == SENTINEL_MAGIC && self.retired
    }

    /// The full aborted verdict: the transfer really ran, and nothing arrived.
    ///
    /// Only the SMMU boot can expect an abort — the SMMU-less positive-control boot has nothing that
    /// could produce one — so this is gated rather than `allow`ed, keeping the dead-code lint able to
    /// notice if a phase stops being reachable.
    #[cfg(feature = "smmu")]
    fn aborted(&self) -> bool {
        self.well_formed() && !self.landed()
    }

    /// The full landed verdict: the transfer ran and the device's zeroed buffer overwrote the magic.
    fn arrived(&self) -> bool {
        self.well_formed() && self.landed() && self.after == 0
    }
}

/// Point the device at sentinel `i` and run one transfer, with the SMMU's event queue emptied first
/// so that whatever it then holds was produced by **this** transfer.
///
/// Every rung-2 phase goes through here, including the two that expect the DMA to *land*: "a permitted
/// transaction records no fault" is as much a discriminator as the faults themselves, and it is free.
#[cfg(feature = "smmu")]
fn attempt_watched(bar0: u64, i: usize) -> (Attempt, Option<smmu::SmmuEvent>) {
    smmu::drain_events();
    let a = attempt(bar0, i);
    let e = smmu::take_event();
    (a, e)
}

/// Point the device at sentinel `i` and run one transfer.
fn attempt(bar0: u64, i: usize) -> Attempt {
    let before = sentinel(i);
    let retired = trigger_dma(bar0, sentinel_pa(i));
    Attempt {
        before,
        after: sentinel(i),
        retired,
    }
}

/// **SMMU rung 1 — the DMA default-deny witness.**
///
/// One code path drives the device; the SMMU half is compile-time gated (`feature = "smmu"`), because
/// the boot that touches SMMU registers must only ever run on a machine that has an SMMU — see the
/// feature's note in `Cargo.toml`. The two boots are:
///
/// * **without `smmu`** — the *positive control*. No SMMU register is read. The DMA must **land**.
/// * **with `smmu`** — `GBPA.ABORT` is set **before** the device is given bus mastering, so there is
///   no interval in which a bus master exists and the SMMU would have let it through. The DMA must be
///   **aborted**.
///
/// Ordering is the property, not an implementation detail: closing the window after enabling the
/// device would reach the same end state while leaving the hole open, and no end-state marker could
/// tell the two apart. Hence the sequencing here, and the claim in the report.
pub(crate) fn witness(uart: &mut Pl011) {
    // Close the window FIRST — before any device can originate a transaction.
    #[cfg(feature = "smmu")]
    let smmu_state = {
        // Two independent facts, deliberately: that the update was absorbed (`GBPA.Update`
        // self-cleared) AND that the register reads back with `ABORT` set. The second is the one that
        // matters — trusting the write path's own return value would be checking our bookkeeping
        // rather than the device's state, the distinction ⑦ and III-1 both turned on.
        let absorbed = smmu::abort_bypassed_traffic();
        let aborting = absorbed && smmu::bypass_aborts();
        let (idr0, idr1) = smmu::id_registers();
        (
            aborting,
            smmu::supports_stage2(),
            idr0,
            idr1,
            smmu::present(),
        )
    };

    let Some(bdf) = pcie::find(EDU_VENDOR, EDU_DEVICE) else {
        let _ = writeln!(
            uart,
            "baleen: smmu rung1: no DMA device present (edu {EDU_VENDOR:#06x}:{EDU_DEVICE:#06x}) — DMA witness SKIPPED"
        );
        return;
    };
    let bar0 = pcie::enable_with_bar0(bdf);

    // The device is really there and decoding BAR0 — so a surviving sentinel later cannot be blamed on
    // a misassigned BAR (the vacuity trap this witness is built to avoid).
    let device_live = mmio_read32(bar0, EDU_REG_ID) == EDU_ID_VALUE;

    let a = attempt(bar0, 0);
    let (before, after, retired, landed) = (a.before, a.after, a.retired, a.landed());

    #[cfg(feature = "smmu")]
    {
        let (aborting, s2, idr0, idr1, present) = smmu_state;
        // `s2` is REQUIRED, not merely reported. It was reported-only from rung 1 until rung 3 found
        // out the hard way: CI's QEMU 8.2 advertises `IDR0.S2P = 0`, the boot printed `stage2=false`
        // for two rungs, and nothing cared — a check whose result changed nothing (design-lesson
        // #71). The whole arc rests on the SMMU being able to translate through a domain's own
        // Stage-2 tables, so a machine that cannot is a machine this witness must not report on.
        //
        // ★★ **⑲-1b — THE OBSERVATION ABOVE IS CORRECT AND ITS EXPLANATION WAS INCOMPLETE, WHICH
        //    COST NINE DAYS.** `IDR0.S2P = 0` was never a property of the runner's QEMU. QEMU's
        //    SMMUv3 advertises stage-2 **only when asked**: `arm-smmuv3.stage` is `"1"` — stage-1
        //    only — BY DEFAULT, and has existed since QEMU 8.1. The runner has 8.2.2. **The
        //    capability was there the whole time and no invocation was requesting it.**
        //
        // Recorded here rather than only at the fix, because this comment is what a reader meets
        // first and it reads as "CI's machine is incapable". It is not. `xtask` now passes
        // `-global arm-smmuv3.stage=2` and the SMMU boot is a REQUIRED check; see
        // `LINUX_SMMU_MARKERS`. **The lesson is not "we measured wrong" — the measurement was
        // right. It is that a correct observation with a MISSING WHY hardens into a constraint:**
        // this note is why the SMMU boot was assumed un-CI-gateable for nine days, and why ⑲-1
        // reached for a staleness tripwire instead of a command-line flag.
        let ok = present && aborting && s2 && device_live && a.aborted();
        if ok {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 DEFAULT-DENY OK: SMMUv3 present (IDR0={idr0:#010x} IDR1={idr1:#010x} stage2={s2} translating={}), GBPA.ABORT set BEFORE bus-master enable, a live edu device's DMA to {:#x} was ABORTED (sentinel intact {before:#x})",
                smmu::translating(),
                sentinel_pa(0)
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 DEFAULT-DENY FAIL (present={present} aborting={aborting} stage2={s2} idr0={idr0:#010x} live={device_live} retired={retired} landed={landed} before={before:#x} after={after:#x}); halting"
            );
            crate::park();
        }
    }

    #[cfg(not(feature = "smmu"))]
    {
        // Positive control: with no SMMU the very same DMA must succeed, or the abort result in the
        // other boot would be meaningless (design-lesson #66 — a green check over a surface that
        // cannot exhibit the flow).
        let ok = device_live && a.arrived();
        if ok {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 POSITIVE CONTROL OK: no SMMU in this machine, a live edu device DMA'd over the sentinel at {:#x} ({before:#x} -> {after:#x}) — the flow the default-deny boot blocks is REAL",
                sentinel_pa(0)
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 POSITIVE CONTROL FAIL (live={device_live} retired={retired} landed={landed} before={before:#x} after={after:#x}); halting"
            );
            crate::park();
        }
    }

    #[cfg(feature = "smmu")]
    rung2(uart, bdf, bar0);
}

/// **SMMU rung 2 — the stream table, witnessed in three phases that discriminate against each other.**
///
/// Rung 1's two boots differed in the *machine* (SMMU or no SMMU). Rung 2's three phases run in **one
/// boot, on one machine, with one device**, and differ only in the contents of a single 64-byte Stream
/// Table Entry. That is a much sharper instrument: there is no configuration difference left to
/// explain a change in outcome except the STE itself.
///
/// | phase | `STE[sid]` | table announced as | required outcome |
/// |---|---|---|---|
/// | 1 — through-STE control | bypass (`V=1`, `Config=0b100`) | 256 entries | the DMA **lands** |
/// | 2 — default-deny | zeroed (`V=0`) | 256 entries | **aborted**, `C_BAD_STE` for `sid` |
/// | 3 — StreamID-specific | zeroed, a *neighbour* bound to bypass | 256 entries | **aborted** |
/// | 4 — re-permit | bypass again | 256 entries | the DMA **lands** again |
/// | 5 — out-of-range | still bypass | **1 entry** | **aborted**, `C_BAD_STREAMID` for `sid` |
///
/// **Phase 1 is the one that makes the rung mean anything**, and it is first for that reason. An
/// ∀-StreamID deny is satisfied trivially by a device that never reaches the stream table — a wrong
/// `LOG2SIZE`, a mis-aligned base, an `SMMUEN` that did not take, or a StreamID that is not the
/// device's RequesterID all yield "aborted". Phase 1 rules out every one of them at once, because a
/// DMA that gets *through* a deliberately-configured entry could only have got through *that* entry.
///
/// **Phase 3 is the ∀-StreamID claim's on-metal half.** Kani proves the builder permits exactly the
/// StreamID it was asked to; phase 3 shows the *hardware* agrees — a permissive entry one StreamID
/// away does not admit this device, so the permit is per-stream and not per-table.
///
/// **Phase 4 is what keeps phases 2 and 3 from being about a wedged SMMU.** Every "aborted" result is
/// also consistent with the device having died, the queue having stalled, or the SMMU having stopped
/// permitting anything at all — and a sequence that only ever tightens can never tell. Re-permitting
/// the *same* StreamID and requiring the DMA to land again closes that: the mechanism is demonstrably
/// still willing to say yes, so the two denials in between were decisions and not failures.
///
/// **Phase 5 witnesses the range arm with a permissive entry in place.** Sizing the table to bus 0
/// means every StreamID above 255 is denied by the architecture's range check rather than by a zeroed
/// entry — a *stronger* denial, but a different mechanism, and one nothing else here exercises. So the
/// announced size is shrunk below the device's StreamID while its STE still says **bypass**: the entry
/// says yes and the range check says no, and only one of them can explain the abort. `C_BAD_STREAMID`
/// rather than `C_BAD_STE` on the event queue is the SMMU stating which one it was.
///
/// Everything phase 1 permits, it permits **unconfined**: a bypass STE places no constraint on where
/// the device writes. Rung 2's claim is exactly "nothing reaches memory unless this hypervisor bound
/// its StreamID", not "a bound device is confined" — that is rung 3, and conflating them is how a
/// headline gets ahead of its artifacts.
#[cfg(feature = "smmu")]
fn rung2(uart: &mut Pl011, bdf: pcie::Bdf, bar0: u64) {
    let sid = pcie::stream_id(bdf);
    // **The rung-4b fence crossing, and the only place it exists.** `hv-core` names this bus master
    // `DevId 0` and can say nothing else about it — no BDF, no RequesterID, no StreamID — for the
    // same reason it cannot name a physical address (design-lesson #14e). This one line is the
    // device-axis twin of `stage2::frame_ipa`, and it is handed to the stream table rather than
    // recomputed anywhere, so there is one derivation of it (design-lesson #14c).
    let mut stream_of = [0u32; crate::NUM_DEVICES];
    stream_of[DEV_EDU as usize] = sid;
    let setup = smmu::install_stream_table(stream_of);

    // ── Phase 1: through-STE positive control ────────────────────────────────────────────────────
    let bound = smmu::bind_stream_bypass(sid);
    let (through, through_event) = attempt_watched(bar0, 1);

    // ── Phase 2: the same device, the same DMA, a zeroed STE ─────────────────────────────────────
    let unbound = smmu::unbind_stream(sid);
    // The reason, not just the absence of an effect. A translation fault leaves a record naming the
    // event class and the StreamID, so the deny is *attributed* rather than inferred from a sentinel
    // that did not change.
    let (denied, event) = attempt_watched(bar0, 2);

    // ── Phase 3: a permissive entry at a NEIGHBOURING StreamID ───────────────────────────────────
    // One StreamID away — the same PCIe device slot, a function that does not exist — so the only
    // difference from phase 1 is *which* entry is permissive.
    let neighbour = if sid + 1 < (1 << smmu::STRTAB_LOG2SIZE) {
        sid + 1
    } else {
        sid - 1
    };
    let bound_elsewhere = smmu::bind_stream_bypass(neighbour);
    let (wrong_stream, wrong_stream_event) = attempt_watched(bar0, 3);
    let cleared_neighbour = smmu::unbind_stream(neighbour);

    // ── Phase 4: re-permit the device's own StreamID ─────────────────────────────────────────────
    // Without this the three "aborted" results above are equally consistent with a device that died
    // or an SMMU that stopped permitting anything.
    let rebound = smmu::bind_stream_bypass(sid);
    let (again, again_event) = attempt_watched(bar0, 4);

    // ── Phase 5: the RANGE arm, with the entry still saying bypass ───────────────────────────────
    // Announce a one-entry table: StreamID `sid` is now outside it, while `STE[sid]` still permits.
    // A device whose StreamID is 0 has no range arm to witness (StreamID 0 is inside *every* table
    // size), so this phase would be unrunnable there. It is left to FAIL LOUDLY in that case rather
    // than skipped: a check that reports OK because it did not run is the exact failure this rung is
    // built to exclude, and the report names `sid` so the cause is unambiguous.
    let shrunk = smmu::set_announced_table_size(0);
    let (out_of_range, range_event) = attempt_watched(bar0, 5);
    let regrown = smmu::set_announced_table_size(smmu::STRTAB_LOG2SIZE);

    // Leave the machine denying everything again, and witness that it does.
    let restored = smmu::unbind_stream(sid);

    // A denial is only credited when the SMMU says WHY, and with WHICH StreamID: a zeroed entry is
    // `C_BAD_STE`, an out-of-range StreamID is `C_BAD_STREAMID`, and a permitted transaction records
    // nothing at all. Requiring the specific type is what makes these checks able to fail — one of
    // them already did, catching a stale-record bug in the queue handling.
    let bad_ste = |e: &Option<smmu::SmmuEvent>| matches!(e, Some(e) if e.kind == smmu::EVT_C_BAD_STE && e.sid == sid);

    let phase1 = setup.ok() && bound && through.arrived() && through_event.is_none();
    let phase2 = unbound && denied.aborted() && bad_ste(&event);
    let phase3 = bound_elsewhere
        && wrong_stream.aborted()
        && bad_ste(&wrong_stream_event)
        && cleared_neighbour;
    let phase4 = rebound && again.arrived() && again_event.is_none();
    let phase5 = shrunk
        && out_of_range.aborted()
        && matches!(&range_event, Some(e) if e.kind == smmu::EVT_C_BAD_STREAMID && e.sid == sid)
        && regrown
        && restored;

    if phase1 && phase2 && phase3 && phase4 && phase5 {
        let _ = writeln!(
            uart,
            "baleen: smmu rung2 THROUGH-STE POSITIVE CONTROL OK: SMMUEN took (CR0ACK), a {}-entry linear stream table at {:#x} (SIDSIZE={}), and the edu device at StreamID {sid} DMA'd THROUGH its own bypass STE to {:#x} ({:#x} -> {:#x}) — the device really does reach the stream table",
            1 << smmu::STRTAB_LOG2SIZE,
            setup.strtab_pa,
            setup.sidsize,
            sentinel_pa(1),
            through.before,
            through.after
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung2 STREAM-TABLE DEFAULT-DENY OK: the SAME device, the SAME DMA, with StreamID {sid}'s STE zeroed (V=0) was ABORTED (sentinel intact {:#x}) and the SMMU recorded C_BAD_STE for StreamID {sid} on EVENTQ (PROD={})",
            denied.before,
            event.as_ref().map_or(u32::MAX, |e| e.prod)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung2 STREAMID-SPECIFIC OK: a permissive bypass STE at the NEIGHBOURING StreamID {neighbour} did NOT admit StreamID {sid} (sentinel intact {:#x}), and re-binding StreamID {sid} let the SAME DMA land again ({:#x} -> {:#x}) — so the denials were decisions, not a wedged SMMU",
            wrong_stream.before,
            again.before,
            again.after
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung2 OUT-OF-RANGE STREAMID OK: with StreamID {sid}'s STE still saying BYPASS, announcing a 1-entry table put it outside the range and the DMA was ABORTED (sentinel intact {:#x}) with C_BAD_STREAMID — the range check denies, not the entry; table restored, denies every stream — ∀-StreamID default-deny, machine-checked over the builder in hv-verify::smmu_stream_table and witnessed here on the hardware",
            out_of_range.before
        );
    } else {
        let evt = |e: &Option<smmu::SmmuEvent>| match e {
            Some(e) => (e.kind, e.sid, e.prod),
            None => (0xff, u32::MAX, u32::MAX),
        };
        let (ek, es, ep) = evt(&event);
        let (wk, ws, _) = evt(&wrong_stream_event);
        let (rk, rs, rp) = evt(&range_event);
        let (t1, t4) = (through_event.is_none(), again_event.is_none());
        let _ = writeln!(
            uart,
            "baleen: smmu rung2 FAIL (sid={sid} setup: page1={} base={} cfg={} en={} gerror={} deny={} sidsize={} | p1 bound={bound} retired={} landed={} | p2 unbound={unbound} retired={} landed={} | p3 other={bound_elsewhere} retired={} landed={} cleared={cleared_neighbour} | p4 rebound={rebound} retired={} landed={} | p5 shrunk={shrunk} retired={} landed={} regrown={regrown} restored={restored} | evt {ek:#04x}/{es}/{ep} p3evt {wk:#04x}/{ws} range_evt {rk:#04x}/{rs}/{rp} quiet={t1}/{t4}); halting",
            setup.page1_at_64k,
            setup.strtab_base_ok,
            setup.strtab_cfg_ok,
            setup.enabled,
            setup.gerror_clean,
            setup.denies_every_stream,
            setup.sidsize,
            through.retired,
            through.landed(),
            denied.retired,
            denied.landed(),
            wrong_stream.retired,
            wrong_stream.landed(),
            again.retired,
            again.landed(),
            out_of_range.retired,
            out_of_range.landed(),
        );
        crate::park();
    }

    // ★★ ⑲-1 — **RUNGS 3 AND 4 ARE SYNTHETIC-CONFIGURATION APPARATUS, AND SAYING SO IS THE RUNG.**
    //
    // Rungs 1 and 2 above are about the SMMU ITSELF — it aborts before `SMMUEN`, its stream table
    // default-denies, its range check denies, and a neighbouring StreamID does not admit this one.
    // None of that mentions a domain, so it holds in every configuration and now runs in the
    // real-Linux one too.
    //
    // Rungs 3 and 4 are different in kind: they are about a DOMAIN's `p2m`, and to say anything they
    // must **own the machine's domains and frames**. In a `real-linux` build they cannot, and it is
    // two collisions rather than one:
    //
    //   * **FRAMES.** They place base leaves at model frames 1..6. `NUM_SUP_FRAMES` is 1 by default
    //     but **448** under `real-linux`, so every one of those falls inside the super partition and
    //     `build_stage2_from_p2m` refuses — *"frame 2 is a BASE leaf inside the super partition
    //     [0, 448); its backing and its scrub would disagree"*. MEASURED: that is exactly where the
    //     combined boot halted, and the emitter's own guard is what caught it. There is nowhere to
    //     renumber them TO: at `real-linux` the base frames are `[448, 476)` and all 28 are the
    //     guests' page tables.
    //   * **DOMAIN IDs.** `DOM_A`/`DOM_B` are 1 and 2 — the same ids `linux::slot_dom` gives the two
    //     real guests. Rung 4 ends by DESTROYING domain A, which in a combined build would destroy
    //     an id a real guest is about to be created with.
    //
    // ⚠ **This is a SCOPING statement, not a weakening — but the distinction has to be earned, so
    // here is what is and is not still checked.** Rungs 3 and 4 run in full in the `smmu`
    // configuration, which `boot-test.sh` boots and gates; nothing they proved has been dropped.
    // What the real-Linux configuration does NOT yet have is confinement of a device to a REAL
    // guest's `p2m` — the synthetic apparatus cannot give it, by the two collisions above, and the
    // honest way to get it is to bind the device to a real guest's own domain and tables. That is
    // ⑲-2, and this rung exists to make the machine it needs boot at all.
    #[cfg(not(feature = "real-linux"))]
    rung3(uart, bdf, bar0);
    // The two parameters are rung 3's alone; under `real-linux` nothing downstream consumes them.
    #[cfg(feature = "real-linux")]
    let _ = (bdf, bar0);
}

// ─── SMMU rung 3 — TRANSLATION: the device walks the DOMAIN's own Stage-2 tables ─────────────────

/// The two domains the device is bound to in turn. Two, because the property is not "the device is
/// translated" but "the device reaches **this** domain's memory and no other" — which a single
/// domain cannot witness at all.
#[cfg(feature = "smmu")]
const DOM0: DomId = 0;
#[cfg(feature = "smmu")]
const DOM_A: DomId = 1;
#[cfg(feature = "smmu")]
const DOM_B: DomId = 2;

/// A's page table, its writable frame, and its **read-only** frame; B's page table and its writable
/// frame; and one model frame nobody ever allocates.
///
/// Every index is `>= 1` because model frame 0 is the metal's super-span partition
/// ([`crate::stage2::NUM_SUP_FRAMES`]) and a base leaf there is rejected by the emitter.
#[cfg(feature = "smmu")]
const F_A_ROOT: Mfn = 1;
#[cfg(feature = "smmu")]
const F_A_RW: Mfn = 2;
#[cfg(feature = "smmu")]
const F_A_RO: Mfn = 3;
#[cfg(feature = "smmu")]
const F_B_ROOT: Mfn = 4;
#[cfg(feature = "smmu")]
const F_B_RW: Mfn = 5;
/// Allocated by nobody, so no domain's table has a descriptor for it — the confinement arm's target.
#[cfg(feature = "smmu")]
const F_HOLE: Mfn = 6;

/// The model's token for the one bus master this machine has. `hv-core` knows it as an opaque
/// index and nothing more; [`rung2`] maps it to [`pcie::stream_id`]'s StreamID exactly once.
#[cfg(feature = "smmu")]
const DEV_EDU: hv_core::device::DevId = 0;

/// The magic at the address the device **asks for** (the IPA, read as a raw physical address).
///
/// Survives ⟹ the transaction did not go there. That is the half rung 2 could not have: a bypassing
/// device writes to the address it issued, a translated one does not, and the difference is visible
/// only if both addresses are real memory that can be read back.
#[cfg(feature = "smmu")]
const SENT_ASKED: u64 = 0x5A5A_A5A5_5A5A_A5A5;
/// The magic at the address **the table says** the transaction lands at. Becomes zero when the
/// device's (zeroed) buffer arrives.
#[cfg(feature = "smmu")]
const SENT_TABLE: u64 = 0xBEEF_D00D_BEEF_D00D;
/// The magic at an address that must **not** be touched — the other domain's landing site for the
/// very same IPA. Distinct from both of the above so a mix-up is visible rather than plausible.
#[cfg(feature = "smmu")]
const SENT_FORBIDDEN: u64 = 0x600D_600D_600D_600D;

/// Read/write a physical address directly. EL2 runs MMU-off/identity, so this is the same premise
/// every other access in the metal rests on — and the accesses under observation come from a
/// *device*, so a volatile access is what is wanted: the value can change with no CPU store.
#[cfg(feature = "smmu")]
fn poke(pa: u64, v: u64) {
    // SAFETY: `pa` is either a Stage-2 leaf's output address (obtained by decoding the descriptor
    // this hypervisor emitted) or a guest IPA inside the model's data window, both of which name
    // ordinary DRAM on this machine; EL2 is identity-mapped. Aliases no Rust object — the model's
    // frame backing is reached only through raw addresses.
    unsafe { core::ptr::write_volatile(pa as *mut u64, v) }
}

#[cfg(feature = "smmu")]
fn peek(pa: u64) -> u64 {
    // SAFETY: as `poke`; read-only.
    unsafe { core::ptr::read_volatile(pa as *const u64) }
}

/// One rung-3 DMA attempt: what the device was told, where the table said that would land, and what
/// every observed address held before and after.
#[cfg(feature = "smmu")]
struct Landing {
    /// Where a walk of the bound domain's tables says `issued` resolves — `None` when that domain's
    /// table maps it nowhere.
    landing: Option<u64>,
    /// A physical address that must be unchanged afterwards: the *other* domain's landing site for
    /// the same IPA. Present only in the binding phases, where "did not reach A" is the claim.
    forbidden: Option<u64>,
    /// Every seeded address read its magic back before the transfer. Without this the "unchanged"
    /// verdicts are vacuous — an address that is not memory never changes.
    seeds_took: bool,
    asked_after: u64,
    landing_after: Option<u64>,
    forbidden_after: Option<u64>,
    retired: bool,
}

#[cfg(feature = "smmu")]
impl Landing {
    /// Every "must not have changed" address still holds its magic.
    fn nothing_else_moved(&self) -> bool {
        self.asked_after == SENT_ASKED && self.forbidden_after.is_none_or(|v| v == SENT_FORBIDDEN)
    }

    /// **The rung's headline verdict**: the transfer ran, it arrived at the address the *table*
    /// names, and it did not arrive at the address the *device* named.
    fn translated(&self) -> bool {
        self.seeds_took
            && self.retired
            && self.landing_after == Some(0)
            && self.nothing_else_moved()
    }

    /// The transfer ran and reached nothing: not the table's address (if it had one), not the
    /// device's own, not the other domain's.
    fn refused(&self) -> bool {
        self.seeds_took
            && self.retired
            && self.landing_after.is_none_or(|v| v == SENT_TABLE)
            && self.nothing_else_moved()
    }
}

/// Seed every observed address, run one DMA at `issued`, and read them all back.
///
/// The seeds are three *different* magics and each is read back before the transfer. That read-back
/// is not paranoia: the address the device asks for is a guest IPA interpreted as a physical address,
/// and on a machine whose RAM does not extend that far it would be unbacked — in which case "the
/// device did not write there" would be true no matter what the SMMU did. Failing loudly there is the
/// difference between a control and a decoration.
#[cfg(feature = "smmu")]
fn attempt_stage2(
    bar0: u64,
    issued: u64,
    landing: Option<u64>,
    forbidden: Option<u64>,
) -> (Landing, Option<smmu::SmmuEvent>) {
    poke(issued, SENT_ASKED);
    if let Some(pa) = landing {
        poke(pa, SENT_TABLE);
    }
    if let Some(pa) = forbidden {
        poke(pa, SENT_FORBIDDEN);
    }
    let seeds_took = peek(issued) == SENT_ASKED
        && landing.is_none_or(|pa| peek(pa) == SENT_TABLE)
        && forbidden.is_none_or(|pa| peek(pa) == SENT_FORBIDDEN);

    smmu::drain_events();
    let retired = trigger_dma(bar0, issued);
    let event = smmu::take_event();

    (
        Landing {
            landing,
            forbidden,
            seeds_took,
            asked_after: peek(issued),
            landing_after: landing.map(peek),
            forbidden_after: forbidden.map(peek),
            retired,
        },
        event,
    )
}

/// Drive the proven model into two domains with disjoint memory, entirely through the real
/// `Hypervisor::dispatch` (and through the metal's teardown funnel, so the content obligations stay
/// discharged) — so the Stage-2 tables the SMMU then walks are a translation of state the *proven
/// transitions* produced, exactly as the CPU-side phases are.
#[cfg(feature = "smmu")]
fn setup_two_domains(hv: &mut Hypervisor, uart: &mut Pl011) {
    let mut expect = |hv: &mut Hypervisor, caller: DomId, call: HvCall, what: &str| {
        if let Err(e) = crate::teardown::dispatch(hv, caller, call) {
            let _ = writeln!(
                uart,
                "baleen: smmu rung3 model setup '{what}' failed: {e:?}; halting"
            );
            crate::park();
        }
    };

    for (dom, root, data, ro) in [
        (DOM_A, F_A_ROOT, F_A_RW, Some(F_A_RO)),
        (DOM_B, F_B_ROOT, F_B_RW, None),
    ] {
        expect(
            hv,
            DOM0,
            HvCall::DomainCreate {
                target: dom,
                may_create: false,
            },
            "create domain",
        );
        expect(hv, dom, HvCall::P2mAllocate { mfn: root }, "alloc root");
        expect(hv, dom, HvCall::P2mAllocate { mfn: data }, "alloc data");
        expect(
            hv,
            dom,
            HvCall::P2mPin {
                mfn: root,
                level: PtLevel::L1,
            },
            "pin root",
        );
        expect(
            hv,
            dom,
            HvCall::P2mLink {
                parent: root,
                slot: 0,
                child: data,
                writable: true,
                leaf: true,
                execute: false,
            },
            "link data",
        );
        if let Some(ro) = ro {
            expect(hv, dom, HvCall::P2mAllocate { mfn: ro }, "alloc ro");
            expect(
                hv,
                dom,
                HvCall::P2mLink {
                    parent: root,
                    slot: 1,
                    child: ro,
                    writable: false,
                    leaf: true,
                    execute: false,
                },
                "link ro",
            );
        }
    }
}

/// **SMMU rung 3 — the device is bound to a DOMAIN, and reaches exactly its memory.**
///
/// Rung 2 ends at "nothing reaches memory unless this hypervisor bound its StreamID", and everything
/// it binds, it binds **unconfined**: a bypass STE places no constraint at all on where a permitted
/// device writes. Rung 3 is the constraint, and it is deliberately not a *new* one — `STE.S2TTB`
/// points at the very Stage-2 tables `build_stage2_from_p2m` emitted for a domain from the proven
/// `p2m`, under that domain's VMID, walked under the same regime `VTCR_EL2` gives the CPU. **One
/// proven `p2m`, two consumers.**
///
/// | phase | STE names | device asks for | required outcome |
/// |---|---|---|---|
/// | 1 — translation control | A's tables, VMID 1 | A's writable frame's IPA | lands at **the PA the table says**, not at the IPA |
/// | 2 — confinement | A's tables | an IPA A does not own | **aborted**, `F_TRANSLATION` naming that address |
/// | 3 — permission | A's tables | A's **read-only** frame's IPA | **aborted**, `F_PERMISSION` |
/// | 4 — wrong domain | B's tables, VMID 2 | A's writable frame's IPA | **aborted**, and A's memory untouched |
/// | 5 — right domain | B's tables | B's writable frame's IPA | lands in **B's** frame |
/// | 6 — back to A | A's tables | A's writable frame's IPA | lands in A's frame again |
/// | 7 — restore | nothing (unbound) | A's writable frame's IPA | **aborted**, `C_BAD_STE`; table denies every stream |
///
/// **Phase 1 is the control, and it is stronger than rung 2's.** Rung 2's control could only show
/// that the device reaches its STE; this one shows that *translation happened*, because the address
/// the device issued and the address the data arrived at are different addresses and both are read
/// back. "Something landed" would not have been enough — a bypass STE also lands. Two sentinels, and
/// the discriminator is which one moved.
///
/// **Phases 4 and 5 are the isolation content**, and they are the reason the rung needs two domains.
/// The same device, the same StreamID, the same *issued address* — and whether it reaches memory at
/// all, and whose, is decided by one field of one entry. That is the `VTTBR_EL2` install seen from
/// the device side, and a wrong STE there is not a fault but a **wrong domain's memory**.
///
/// **Phase 3 is where the proven emitter's permission bits govern the device.** Nothing new was
/// built for it: the read-only leaf is the one `hv-s2` emits for a model leaf with `writable: false`,
/// and the SMMU refuses the write for the same reason the CPU would.
#[cfg(feature = "smmu")]
// ⑲-1 — **ALLOW THE ROOT, not the twenty-seven items under it.** Under `real-linux` this function is
// not called (see `witness`), so it and everything reachable only from it — `DOM_A`/`DOM_B`, the
// `F_*` model frames, the Stage-2 STE builders in `crate::smmu` — become dead, and `-D warnings`
// rejects the build. `allow(dead_code)` on an item marks it a live root for reachability, so
// allowing THIS one silences exactly its subtree and nothing else: dead code elsewhere in this file
// is still caught. That is `main.rs`'s own idiom for `guest::run`, for the same reason and in the
// same words — a blanket allow is a lint gate whose inputs cannot discriminate (design-lesson #71),
// while allowing a displaced entry point says the true thing.
//
// ⚠ It is `cfg_attr`-gated so the allow exists ONLY in the configuration where the displacement is
// real. In the `smmu` configuration this function is called and its subtree is live, so an item that
// genuinely stopped being used there still fails the build.
#[cfg_attr(feature = "real-linux", allow(dead_code))]
fn rung3(uart: &mut Pl011, bdf: pcie::Bdf, bar0: u64) {
    use hv_s2::arm64::{vttbr_table, vttbr_vmid, BALEEN_STAGE2, BALEEN_VMID_BITS};
    use hv_s2::smmu::Stage2Binding;

    let sid = pcie::stream_id(bdf);

    // (1) THE MODEL, then THE TABLES. Two domains with disjoint memory, driven through the proven
    //     transitions; two independent Stage-2 table sets emitted from that `p2m` by the same
    //     `build_stage2_from_p2m` every CPU-side phase uses, each with its own VMID.
    let mut hv = crate::build_hypervisor();
    setup_two_domains(&mut hv, uart);
    let vttbr_a = crate::stage2::build_stage2_from_p2m(&hv, DOM_A, 0);
    let vttbr_b = crate::stage2::build_stage2_from_p2m(&hv, DOM_B, 1);

    // (2) THE BINDINGS, DERIVED FROM THE VTTBRs — not from the table storage, and not from a second
    //     computation of where the tables live. `vttbr_table`/`vttbr_vmid` read back the value the
    //     CPU would be given, so "the device walks the same table as the domain's CPU, under the same
    //     VMID" holds by construction rather than by agreement between two derivations.
    let bind_a = Stage2Binding {
        s2ttb: vttbr_table(vttbr_a),
        vmid: vttbr_vmid(vttbr_a, BALEEN_VMID_BITS),
        regime: BALEEN_STAGE2,
    };
    let bind_b = Stage2Binding {
        s2ttb: vttbr_table(vttbr_b),
        vmid: vttbr_vmid(vttbr_b, BALEEN_VMID_BITS),
        regime: BALEEN_STAGE2,
    };
    let l1_a = bind_a.s2ttb;
    let l1_b = bind_b.s2ttb;

    // A distinct 64-byte slot per phase, so no phase's evidence is a re-seeding of another's: a
    // transfer that silently ran twice, or one that landed after its read, cannot hide behind a
    // freshly-written "before" value (the rung-2 sentinel discipline, applied inside one frame).
    let slot = |phase: u64| phase * 64;
    let ipa_a_rw = crate::stage2::frame_ipa(F_A_RW);
    let ipa_a_ro = crate::stage2::frame_ipa(F_A_RO);
    let ipa_b_rw = crate::stage2::frame_ipa(F_B_RW);
    let ipa_hole = crate::stage2::frame_ipa(F_HOLE);
    // Where a walk of the emitted DESCRIPTORS says an address lands. Never layout arithmetic: the
    // expectation has to come from the table, or the control asserts only that two copies of the
    // same derivation agree.
    let walk = crate::stage2::walk_stage2;

    // ── Phase 1: the TRANSLATION positive control ────────────────────────────────────────────────
    let bound_a = smmu::bind_stream_stage2(sid, &bind_a);
    let asked1 = ipa_a_rw + slot(1);
    let landed1 = walk(l1_a, asked1);
    let (p1, e1) = attempt_stage2(bar0, asked1, landed1.as_ref().map(|r| r.pa), None);
    // The whole point: the table's answer is a DIFFERENT address from the one the device issued.
    let translation_is_real = landed1
        .as_ref()
        .is_some_and(|r| r.pa != asked1 && r.writable());
    let phase1 = bound_a && translation_is_real && p1.translated() && e1.is_none();

    // ── Phase 2: CONFINEMENT — an IPA this domain does not own ───────────────────────────────────
    let asked2 = ipa_hole + slot(2);
    let landed2 = walk(l1_a, asked2);
    let (p2, e2) = attempt_stage2(bar0, asked2, None, None);
    let phase2 =
        landed2.is_none() && p2.refused() && fault_at(&e2, smmu::EVT_F_TRANSLATION, sid, asked2);

    // ── Phase 3: PERMISSION — the emitter's read-only leaf, enforced against a DEVICE ────────────
    let asked3 = ipa_a_ro + slot(3);
    let landed3 = walk(l1_a, asked3);
    let read_only = landed3.as_ref().is_some_and(|r| !r.writable());
    let (p3, e3) = attempt_stage2(bar0, asked3, landed3.as_ref().map(|r| r.pa), None);
    let phase3 = read_only && p3.refused() && fault_at(&e3, smmu::EVT_F_PERMISSION, sid, asked3);

    // ── Phase 4: the WRONG DOMAIN — same device, same address, B's tables ────────────────────────
    // The forbidden address is A's landing site for this very IPA: "did not reach A's memory" is the
    // claim, so it is asserted directly rather than inferred from the absence of a change elsewhere.
    let bound_b = smmu::bind_stream_stage2(sid, &bind_b);
    let asked4 = ipa_a_rw + slot(4);
    let landed4_b = walk(l1_b, asked4);
    let forbidden4 = walk(l1_a, asked4).map(|r| r.pa);
    let (p4, e4) = attempt_stage2(bar0, asked4, landed4_b.as_ref().map(|r| r.pa), forbidden4);
    let phase4 = bound_b
        && landed4_b.is_none()
        && forbidden4.is_some()
        && p4.refused()
        && fault_at(&e4, smmu::EVT_F_TRANSLATION, sid, asked4);

    // ── Phase 5: the RIGHT domain — B's own frame, through the same STE ──────────────────────────
    let asked5 = ipa_b_rw + slot(5);
    let landed5 = walk(l1_b, asked5);
    let (p5, e5) = attempt_stage2(bar0, asked5, landed5.as_ref().map(|r| r.pa), None);
    let phase5 =
        landed5.as_ref().is_some_and(|r| r.pa != asked5) && p5.translated() && e5.is_none();

    // ── Phase 6: rebind to A, and require A's memory to be reachable again ───────────────────────
    // Without this, phases 2–4 are equally consistent with an SMMU that stopped translating anything.
    let rebound_a = smmu::bind_stream_stage2(sid, &bind_a);
    let asked6 = ipa_a_rw + slot(6);
    let landed6 = walk(l1_a, asked6);
    let (p6, e6) = attempt_stage2(bar0, asked6, landed6.as_ref().map(|r| r.pa), None);
    let phase6 = rebound_a && p6.translated() && e6.is_none();

    // ── Phase 7: restore the machine's deny-everything state, and witness it ─────────────────────
    let unbound = smmu::unbind_stream(sid);
    let asked7 = ipa_a_rw + slot(7);
    let landed7 = walk(l1_a, asked7);
    let (p7, e7) = attempt_stage2(bar0, asked7, landed7.as_ref().map(|r| r.pa), None);
    let phase7 = unbound
        && p7.refused()
        && matches!(&e7, Some(e) if e.kind == smmu::EVT_C_BAD_STE && e.sid == sid);

    if phase1 && phase2 && phase3 && phase4 && phase5 && phase6 && phase7 {
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 TRANSLATION POSITIVE CONTROL OK: StreamID {sid} bound to domain {DOM_A}'s OWN Stage-2 tables (S2TTB={:#x} = VTTBR_EL2's table, S2VMID={}), the device asked for IPA {asked1:#x} and the DMA landed at PA {:#x} — where the TABLE says, not where the device asked (the sentinel at {asked1:#x} is intact {:#x})",
            bind_a.s2ttb,
            bind_a.vmid,
            p1.landing.unwrap_or(0),
            p1.asked_after
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 CONFINEMENT OK: the same device, the same STE, asking for IPA {asked2:#x} — a frame domain {DOM_A} does not own, so its table has no descriptor for it — was ABORTED with F_TRANSLATION naming that address ({:#x}); one proven p2m, two consumers",
            e2.as_ref().map_or(0, |e| e.addr)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 PERMISSION OK: the READ-ONLY leaf hv-s2 emitted for domain {DOM_A} (IPA {asked3:#x} -> PA {:#x}, S2AP=RO) refused the DEVICE's write with F_PERMISSION — the proven emitter's permission bits govern the device path, not only the CPU's",
            p3.landing.unwrap_or(0)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 STREAM-TO-DOMAIN BINDING OK: with StreamID {sid}'s STE naming domain {DOM_B} (S2TTB={:#x} VMID={}) instead, the SAME device asking for the SAME IPA {asked4:#x} was ABORTED and domain {DOM_A}'s memory at PA {:#x} was untouched ({:#x}); the same STE then reached domain {DOM_B}'s own frame at PA {:#x}, and rebinding to {DOM_A} reached A's again — which domain a device's DMA lands in is decided by the STE",
            bind_b.s2ttb,
            bind_b.vmid,
            p4.forbidden.unwrap_or(0),
            p4.forbidden_after.unwrap_or(0),
            p5.landing.unwrap_or(0)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 RESTORED OK: StreamID {sid} unbound, the stream table denies every StreamID again, and the same DMA is back to C_BAD_STE"
        );
    } else {
        let ev = |e: &Option<smmu::SmmuEvent>| match e {
            Some(e) => (e.kind, e.sid, e.addr),
            None => (0xff, u32::MAX, u64::MAX),
        };
        let l = |r: &Option<crate::stage2::Resolved>| r.as_ref().map_or(u64::MAX, |r| r.pa);
        let _ = writeln!(
            uart,
            "baleen: smmu rung3 FAIL (sid={sid} a_ttb={:#x}/{} b_ttb={:#x}/{} | p1 bound={bound_a} walk={:#x} seeds={} retired={} asked_after={:#x} landing_after={:?} evt={:x?} | p2 walk={:#x} seeds={} retired={} landing_after={:?} evt={:x?} | p3 ro={read_only} walk={:#x} seeds={} landing_after={:?} evt={:x?} | p4 bound_b={bound_b} walk_b={:#x} forbidden={:#x} seeds={} forbidden_after={:?} evt={:x?} | p5 walk={:#x} seeds={} landing_after={:?} | p6 rebound={rebound_a} seeds={} landing_after={:?} | p7 unbound={unbound} landing_after={:?} evt={:x?}); halting",
            bind_a.s2ttb, bind_a.vmid, bind_b.s2ttb, bind_b.vmid,
            l(&landed1), p1.seeds_took, p1.retired, p1.asked_after, p1.landing_after, ev(&e1),
            l(&landed2), p2.seeds_took, p2.retired, p2.landing_after, ev(&e2),
            l(&landed3), p3.seeds_took, p3.landing_after, ev(&e3),
            l(&landed4_b), forbidden4.unwrap_or(u64::MAX), p4.seeds_took, p4.forbidden_after, ev(&e4),
            l(&landed5), p5.seeds_took, p5.landing_after,
            p6.seeds_took, p6.landing_after,
            p7.landing_after, ev(&e7),
        );
        crate::park();
    }

    rung4(uart, bdf, bar0);
}

// ─── SMMU rung 4b — the table is DERIVED, and the LIFECYCLE runs on the device path ─────────────

/// Drive `hv` into a live domain `dom` owning one writable frame, then emit its Stage-2 image.
///
/// Returns the `VTTBR_EL2` value, whose table base the device's STE must end up naming. **Emission
/// registers the domain's binding** (`stage2::build_stage2_from_p2m` → `smmu::register_domain_binding`),
/// which is why it has to happen before the device is assigned: the derivation refuses — loudly —
/// to bind a device to a domain that has no Stage-2 image to be pointed at.
#[cfg(feature = "smmu")]
fn birth_domain_with_one_frame(hv: &mut Hypervisor, uart: &mut Pl011, dom: DomId) -> u64 {
    expect(
        hv,
        uart,
        DOM0,
        HvCall::DomainCreate {
            target: dom,
            may_create: false,
        },
        "create",
    );
    expect(
        hv,
        uart,
        dom,
        HvCall::P2mAllocate { mfn: F_A_ROOT },
        "alloc root",
    );
    expect(
        hv,
        uart,
        dom,
        HvCall::P2mAllocate { mfn: F_A_RW },
        "alloc data",
    );
    expect(
        hv,
        uart,
        dom,
        HvCall::P2mPin {
            mfn: F_A_ROOT,
            level: PtLevel::L1,
        },
        "pin root",
    );
    expect(
        hv,
        uart,
        dom,
        HvCall::P2mLink {
            parent: F_A_ROOT,
            slot: 0,
            child: F_A_RW,
            writable: true,
            leaf: true,
            execute: false,
        },
        "link data",
    );
    crate::stage2::build_stage2_from_p2m(hv, dom, 0)
}

/// Drive one hypercall through the metal's funnel and stop the machine if the **model** refused it.
///
/// Every rung-4b phase is a hypercall, so a phase that silently failed to issue would leave the
/// table in its previous state and the next assertion would be about the wrong thing entirely.
#[cfg(feature = "smmu")]
fn expect(hv: &mut Hypervisor, uart: &mut Pl011, caller: DomId, call: HvCall, what: &str) {
    if let Err(e) = crate::teardown::dispatch(hv, caller, call) {
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 '{what}' was refused by the model: {e:?}; halting"
        );
        crate::park();
    }
}

/// **SMMU rung 4b — the stream table is a REFINEMENT of the model's device assignment, and it
/// survives a domain's whole lifecycle.**
///
/// Rung 3 bound a stream to a domain by calling `bind_stream_stage2` **by hand**, so rung 4a's
/// proven device→domain relation had no consumer and the hardware's answer to *"whose memory may
/// this bus master write?"* was still a configuration nothing checked. Nothing here binds anything
/// by hand. Every entry in the table below is produced by `hv_s2::smmu::derive_stream_table` out of
/// the relation, from `teardown::dispatch`'s post-dispatch funnel, as a consequence of a hypercall
/// this witness issues through the **proven** `Hypervisor::dispatch`.
///
/// | phase | the hypercall | what the derivation must do | required outcome |
/// |---|---|---|---|
/// | 1 — derivation control | `DeviceAssign{dev 0 → A}` | bind StreamID `sid` to **A's** tables | the DMA lands **where the table says**, not at the IPA |
/// | 2 — release | `DeviceRelease{dev 0 from A}` | leave every stream denied | **aborted**, `C_BAD_STE` |
/// | 3 — re-permit | `DeviceAssign{dev 0 → A}` | bind it again | lands again — so phase 2 was a decision |
/// | 4 — **teardown** | `DomainDestroy{A}` | the model's sweep removes the assignment ⇒ the table denies | **aborted**, and A's old landing PA untouched |
/// | 5 — **rebirth** | `DomainCreate{A}` + fresh tables | *nothing* — the device is not assigned to the reborn slot | still **aborted**, and the reborn tenant's memory intact |
/// | 6 — re-assign | `DeviceAssign{dev 0 → A}` | bind the **reborn** domain's tables | lands in the reborn domain's frame |
///
/// **Phase 1 is the control and it is first** (design-lesson #70), and it is stronger than rung 3's:
/// it witnesses the *derivation* as well as the translation, because the STE it lands through was
/// never written by this file. Two sentinels, as in rung 3 (design-lesson #75) — the address the
/// device asked for must be untouched.
///
/// **Phases 4 and 5 are the rung's isolation content**, and they are the confused deputy in the
/// flavour every CPU-side proof in the repository is structurally blind to: a stale assignment is
/// not a capability the reborn tenant would have to *use*, it is a bus master already pointed at its
/// memory, writing with no hypercall and no vCPU. The headline probe is exactly that — delete
/// `device::System::release_all_of` from `domain_destroy` and phases 4 and 5 both go red, with the
/// dead tenant's device writing into the reborn tenant's frame.
///
/// **Phase 6 is what keeps 2, 4 and 5 from being about a wedged mechanism**, the same re-permit
/// rungs 2 and 3 end on (#70c) — and it is sharper here, because the domain it re-permits into is a
/// *different incarnation* with freshly emitted tables.
#[cfg(feature = "smmu")]
fn rung4(uart: &mut Pl011, bdf: pcie::Bdf, bar0: u64) {
    use hv_s2::arm64::{vttbr_table, vttbr_vmid, BALEEN_VMID_BITS};

    let sid = pcie::stream_id(bdf);
    let walk = crate::stage2::walk_stage2;
    let slot = |phase: u64| phase * 64;
    let ipa = crate::stage2::frame_ipa(F_A_RW);

    // A fresh model, and domain A born into it. The device is UNASSIGNED at boot — `hv-core`'s
    // fail-closed default — and the derived table therefore denies every stream before the first
    // hypercall, which is the same default rung 2 installs by hand.
    let mut hv = crate::build_hypervisor();
    let vttbr_a = birth_domain_with_one_frame(&mut hv, uart, DOM_A);
    let l1_a = vttbr_table(vttbr_a);
    let vmid_a = vttbr_vmid(vttbr_a, BALEEN_VMID_BITS);
    let denied_at_boot = smmu::denies_everything();

    // ── Phase 1: THE DERIVATION CONTROL ──────────────────────────────────────────────────────────
    // One hypercall, no hardware call at all — and the device is now confined to A's memory.
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DeviceAssign {
            dev: DEV_EDU,
            to: DOM_A,
        },
        "assign",
    );
    let derived1 = smmu::published_binding(sid);
    let asked1 = ipa + slot(1);
    let landed1 = walk(l1_a, asked1);
    let (p1, e1) = attempt_stage2(bar0, asked1, landed1.as_ref().map(|r| r.pa), None);
    // The entry the funnel derived must name A's own tables, under A's VMID — the same two values
    // rung 3 had to be handed by hand.
    let names_a = derived1.is_some_and(|b| b.s2ttb == l1_a && b.vmid == vmid_a);
    let translation_is_real = landed1
        .as_ref()
        .is_some_and(|r| r.pa != asked1 && r.writable());
    let phase1 =
        denied_at_boot && names_a && translation_is_real && p1.translated() && e1.is_none();

    // ── Phase 2: RELEASE — the relation says no, so the table says no ────────────────────────────
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DeviceRelease {
            dev: DEV_EDU,
            from: DOM_A,
        },
        "release",
    );
    let denied_after_release = smmu::denies_everything();
    let asked2 = ipa + slot(2);
    let (p2, e2) = attempt_stage2(bar0, asked2, walk(l1_a, asked2).map(|r| r.pa), None);
    let phase2 = denied_after_release
        && p2.refused()
        && matches!(&e2, Some(e) if e.kind == smmu::EVT_C_BAD_STE && e.sid == sid);

    // ── Phase 3: RE-PERMIT — so phase 2 was a decision, not a wedged SMMU ────────────────────────
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DeviceAssign {
            dev: DEV_EDU,
            to: DOM_A,
        },
        "re-assign",
    );
    let asked3 = ipa + slot(3);
    let landed3 = walk(l1_a, asked3);
    let (p3, e3) = attempt_stage2(bar0, asked3, landed3.as_ref().map(|r| r.pa), None);
    let phase3 = p3.translated() && e3.is_none();

    // ── Phase 4: TEARDOWN — the model's sweep, seen from the bus ─────────────────────────────────
    // A dies **holding the device**. Nothing here unbinds anything: `domain_destroy`'s
    // `device::System::release_all_of` takes the assignment, and the funnel's re-derivation is what
    // turns that into a denying entry. The forbidden address is A's landing site for the very IPA
    // the device is about to ask for — seeded AFTER the destroy, because the teardown funnel scrubs
    // a freed frame, and a sentinel written before the scrub would be zero either way (a check that
    // could not have failed).
    let old_landing = walk(l1_a, ipa + slot(4)).map(|r| r.pa);
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DomainDestroy {
            target: DOM_A,
            now: 0,
        },
        "destroy",
    );
    let denied_after_destroy = smmu::denies_everything();
    let asked4 = ipa + slot(4);
    let (p4, e4) = attempt_stage2(bar0, asked4, None, old_landing);
    let phase4 = denied_after_destroy
        && old_landing.is_some()
        && p4.refused()
        && matches!(&e4, Some(e) if e.kind == smmu::EVT_C_BAD_STE && e.sid == sid);

    // ── Phase 5: REBIRTH — a fresh tenant in the same slot, with the same frame ──────────────────
    // The reborn domain re-allocates the SAME model frame, so it is backed by the SAME machine
    // frame at the SAME physical address the dead tenant's device was reaching. If anything of the
    // old assignment survived, this is where it writes into a live tenant's memory.
    let published_before_rebirth = smmu::derivations_published();
    let vttbr_reborn = birth_domain_with_one_frame(&mut hv, uart, DOM_A);
    let l1_reborn = vttbr_table(vttbr_reborn);
    let no_churn = smmu::derivations_published() == published_before_rebirth;
    let denied_after_rebirth = smmu::denies_everything();
    let asked5 = ipa + slot(5);
    let reborn_landing = walk(l1_reborn, asked5).map(|r| r.pa);
    let (p5, e5) = attempt_stage2(bar0, asked5, None, reborn_landing);
    let phase5 = denied_after_rebirth
        && no_churn
        && reborn_landing.is_some()
        && p5.refused()
        && matches!(&e5, Some(e) if e.kind == smmu::EVT_C_BAD_STE && e.sid == sid);

    // ── Phase 6: RE-ASSIGN to the REBORN domain ──────────────────────────────────────────────────
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DeviceAssign {
            dev: DEV_EDU,
            to: DOM_A,
        },
        "assign to the reborn domain",
    );
    let derived6 = smmu::published_binding(sid);
    let asked6 = ipa + slot(6);
    let landed6 = walk(l1_reborn, asked6);
    let (p6, e6) = attempt_stage2(bar0, asked6, landed6.as_ref().map(|r| r.pa), None);
    let phase6 = derived6.is_some_and(|b| b.s2ttb == l1_reborn) && p6.translated() && e6.is_none();

    // Leave the machine denying every stream again, through the model — the same restore rung 3
    // ends on, but issued as a hypercall rather than as a hardware poke.
    expect(
        &mut hv,
        uart,
        DOM0,
        HvCall::DeviceRelease {
            dev: DEV_EDU,
            from: DOM_A,
        },
        "restore",
    );
    let restored = smmu::denies_everything();

    if phase1 && phase2 && phase3 && phase4 && phase5 && phase6 && restored {
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 DERIVATION POSITIVE CONTROL OK: nothing in this phase touched the SMMU — ONE HvCall DeviceAssign{{dev {DEV_EDU} -> domain {DOM_A}}} through the proven dispatch, and teardown::dispatch DERIVED StreamID {sid}'s entry from the model's assignment relation (S2TTB={:#x} = domain {DOM_A}'s own VTTBR_EL2 table, S2VMID={vmid_a}); the device asked for IPA {asked1:#x} and the DMA landed at PA {:#x} — where the TABLE says, not where the device asked ({asked1:#x} intact {:#x})",
            derived1.map_or(0, |b| b.s2ttb),
            p1.landing.unwrap_or(0),
            p1.asked_after
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 RELEASE OK: HvCall DeviceRelease made the derived table deny EVERY StreamID and the same DMA to IPA {asked2:#x} was ABORTED with C_BAD_STE (sentinel intact); re-assigning let the SAME DMA land again at PA {:#x} — the denial was a decision the RELATION made, not a wedged SMMU",
            p3.landing.unwrap_or(0)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 TEARDOWN OK: domain {DOM_A} was destroyed while HOLDING the device — nothing unbound the stream, hv-core's release_all_of took the assignment and the re-derivation turned that into a denying entry: the SAME device asking for the SAME IPA {asked4:#x} was ABORTED with C_BAD_STE and domain {DOM_A}'s old landing PA {:#x} was untouched ({:#x})",
            old_landing.unwrap_or(0),
            p4.forbidden_after.unwrap_or(0)
        );
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 REBIRTH OK: a fresh domain {DOM_A} in the same slot re-allocated the same model frame at the same PA {:#x} and its memory is INTACT ({:#x}) — the dead tenant's bus master reaches NOTHING of the reborn tenant's; re-assigning to the reborn domain then landed in ITS frame at PA {:#x} (S2TTB={:#x}), and releasing left the table denying every StreamID again — the stream table is a REFINEMENT of hv-core's proven device assignment, biconditional and machine-checked in hv-verify::smmu_stream_derivation",
            reborn_landing.unwrap_or(0),
            p5.forbidden_after.unwrap_or(0),
            p6.landing.unwrap_or(0),
            derived6.map_or(0, |b| b.s2ttb)
        );
    } else {
        let ev = |e: &Option<smmu::SmmuEvent>| match e {
            Some(e) => (e.kind, e.sid, e.addr),
            None => (0xff, u32::MAX, u64::MAX),
        };
        let _ = writeln!(
            uart,
            "baleen: smmu rung4 FAIL (sid={sid} boot_denied={denied_at_boot} a_ttb={l1_a:#x}/{vmid_a} reborn_ttb={l1_reborn:#x} | p1 derived={:x?} names_a={names_a} real={translation_is_real} seeds={} landing_after={:?} evt={:x?} | p2 denied={denied_after_release} refused={} evt={:x?} | p3 seeds={} landing_after={:?} evt={:x?} | p4 denied={denied_after_destroy} old={:?} forbidden_after={:?} evt={:x?} | p5 denied={denied_after_rebirth} churn={} reborn={:?} forbidden_after={:?} evt={:x?} | p6 derived={:x?} landing_after={:?} evt={:x?} | restored={restored}); halting",
            derived1.map(|b| b.s2ttb), p1.seeds_took, p1.landing_after, ev(&e1),
            p2.refused(), ev(&e2),
            p3.seeds_took, p3.landing_after, ev(&e3),
            old_landing, p4.forbidden_after, ev(&e4),
            !no_churn, reborn_landing, p5.forbidden_after, ev(&e5),
            derived6.map(|b| b.s2ttb), p6.landing_after, ev(&e6),
        );
        crate::park();
    }
}

/// Whether the SMMU recorded exactly this fault class, for this StreamID, naming the page the device
/// asked for.
///
/// **Attributed, not inferred** (design-lesson #70(d)). Comparing the record's input address is what
/// separates "some transaction of this device faulted" from "the walk of *this* domain's table
/// refused *this* address" — and it is what makes phases 2 and 4 different facts rather than two
/// spellings of "the sentinel did not change".
///
/// **Exact, not page-granular.** The architecture permits the record's address field to name the
/// faulting page rather than the byte, and the weaker comparison was written first; this machine
/// reports the exact address, and the stronger check is the one that can fail — a phase whose
/// transfer went to a *neighbouring offset in the same frame* would still pass a page comparison, and
/// every rung-3 phase deliberately uses a different offset in the same frame.
#[cfg(feature = "smmu")]
fn fault_at(e: &Option<smmu::SmmuEvent>, kind: u8, sid: u32, asked: u64) -> bool {
    matches!(e, Some(e) if e.kind == kind && e.sid == sid && e.addr == asked)
}

// ─── ⑲-2 — CONFINEMENT TO A **REAL GUEST'S** `p2m` ───────────────────────────────────────────────

/// ★★ **⑲-2 — a bus master bound to a REAL Linux guest's own Stage-2 image: it reaches that guest's
/// memory and is REFUSED its peer's.**
///
/// ## What this adds over rung 3, which already proved confinement
///
/// Rung 3 bound the device to a **synthetic** domain built for the purpose. This binds it to
/// `S2TTB` = the very table `VTTBR_EL2` carries for a domain running an **unmodified Alpine
/// kernel**, under that domain's own VMID — the same image the CPU walks, emitted by
/// `build_stage2_from_p2m` from the same proven `p2m`. *"One proven `p2m`, two consumers"* stops
/// being a statement about apparatus and becomes one about the machine that boots.
///
/// ⚠ **Rung 3's apparatus could not be reused, and that is measured, not asserted** — see the
/// scoping note on [`witness`]. Its model frames land inside the 448-frame super partition under
/// `real-linux`, and its `DOM_A`/`DOM_B` **are** the real guests' domain ids. This is a separate
/// path for that reason.
///
/// ## Where the expectation comes from, and the CEILING identity mapping imposes
///
/// **From a walk of the emitted descriptors, never from layout arithmetic.** `walk_stage2` reads the
/// table the device is about to walk, and the addresses below come from it.
///
/// ⚠ **But a real guest's RAM is IDENTITY-mapped, and that costs this rung one of rung 3's
/// discriminators — MEASURED, not foreseen.** Rung 3's headline verdict is *"it landed where the
/// TABLE says and NOT where the DEVICE asked"*, which is only a distinction when IPA ≠ PA. Its
/// synthetic domains were built that way; a real guest's are not, so for these arms the two
/// addresses are the same one and [`Landing::translated`] is structurally inapplicable — its two
/// halves contradict each other at identity. The first boot of this rung reported
/// `seeds1=false … seeds2=false` for exactly that reason: [`attempt_stage2`] seeds `issued` and then
/// `landing` over the top of it.
///
/// **So this rung claims less on the positive arm and exactly as much on the negative one:**
///
/// | arm | claim | strength here |
/// |---|---|---|
/// | positive | the device bound to this guest **reaches** the guest's own memory | a CONTROL — it rules out a wedged SMMU refusing everything, but at identity it cannot separate "translated" from "passed through". **That separation is rung 3's, on a non-identity map, and is not re-proved here.** |
/// | confinement | the same device asking for the PEER's IPA is **ABORTED**, peer's landing site intact | full — identity changes nothing about it, and it is the isolation content |
///
/// ## Timing: after emission, BEFORE the guests are entered — and this is a scope boundary
///
/// Called once `VTTBR` holds both images and before the `eret` into guest A. The tables are real and
/// final; nothing is executing yet.
///
/// ⚠ **So this is CONFINEMENT, not SIMULTANEITY.** Honest-ledger item 2(b) — *"the two consumers are
/// not simultaneous; no vCPU runs while the device DMAs"* — is **NOT** closed by this rung and must
/// not be read as closed. What is closed is that the device is confined by a *real guest's* proven
/// map rather than a synthetic one.
///
/// ## Why the targets are where they are, and the hazard that chose them
///
/// Both land **above every blob loaded into the guest's window**: dom 1's Image/DTB/initramfs end
/// around `0x4c3d_6000` and dom 2's around `0x683d_6000`, so `0x5000_0000` and `0x6c00_0000` are
/// untouched RAM at this point in the boot.
///
/// ⚠ **The peer target had to move, and the reason is easy to miss:** [`attempt_stage2`] SEEDS the
/// `forbidden` address before the transfer, so aiming the refusal arm at dom 2's window *base* would
/// have written eight bytes over **dom 2's kernel image** — the control would have corrupted the
/// thing it was protecting. Caught by reading what the helper does rather than what it is called.
#[cfg(all(feature = "smmu", feature = "real-linux"))]
pub(crate) fn witness_real_guest(
    uart: &mut Pl011,
    vttbr_own: u64,
    vttbr_peer: u64,
    ipa_own: u64,
    ipa_peer: u64,
) {
    use hv_s2::arm64::{vttbr_table, vttbr_vmid, BALEEN_STAGE2, BALEEN_VMID_BITS};
    use hv_s2::smmu::Stage2Binding;

    let Some(bdf) = pcie::find(EDU_VENDOR, EDU_DEVICE) else {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest FAIL: no edu bus master on this machine, so the confinement arms would be vacuous; halting"
        );
        crate::park();
    };
    let bar0 = pcie::enable_with_bar0(bdf);
    let sid = pcie::stream_id(bdf);

    // The binding is DERIVED FROM THE VTTBR, exactly as rung 3 does it: `vttbr_table`/`vttbr_vmid`
    // read back the value the CPU is given, so "the device walks the same table as this guest's
    // vCPUs, under the same VMID" holds by construction rather than by two derivations agreeing.
    let bind_own = Stage2Binding {
        s2ttb: vttbr_table(vttbr_own),
        vmid: vttbr_vmid(vttbr_own, BALEEN_VMID_BITS),
        regime: BALEEN_STAGE2,
    };
    let l1_own = bind_own.s2ttb;
    let l1_peer = vttbr_table(vttbr_peer);

    // Where the TABLES say these addresses live. The peer's is the address that must stay intact:
    // "the device bound to this guest did not reach where the PEER's table puts that IPA".
    let Some(landing_own) = crate::stage2::walk_stage2(l1_own, ipa_own).map(|r| r.pa) else {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest FAIL: this guest's own image maps nothing at {ipa_own:#x}, so the positive control would be vacuous; halting"
        );
        crate::park();
    };
    let Some(forbidden_peer) = crate::stage2::walk_stage2(l1_peer, ipa_peer).map(|r| r.pa) else {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest FAIL: the PEER's image maps nothing at {ipa_peer:#x}, so 'did not reach the peer' would be vacuous; halting"
        );
        crate::park();
    };
    // The refusal arm's premise: this guest's own image maps NOTHING at the peer's IPA.
    let own_maps_peer = crate::stage2::walk_stage2(l1_own, ipa_peer).is_some();

    // One transfer, seeded and read back at a SINGLE address — the shape `Attempt` uses, applied to
    // a guest address instead of EL2's own static. Deliberately NOT `attempt_stage2`: its
    // three-address discipline collides with itself at identity (see the ceiling note above).
    let probe = |issued: u64, watch_pa: u64| -> (u64, u64, bool) {
        poke(watch_pa, SENTINEL_MAGIC);
        let before = peek(watch_pa);
        let retired = trigger_dma(bar0, issued);
        (before, peek(watch_pa), retired)
    };

    if !smmu::bind_stream_stage2(sid, &bind_own) {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest FAIL: could not bind StreamID {sid} to the guest's own Stage-2 image; halting"
        );
        crate::park();
    }

    // ⑲-3 TEMPORARY BASELINE PROBE — reverted before the rung lands. ⑲-3 wants to kick a DMA, `eret`
    // into a guest, and observe the transfer land WHILE the guest executes. That is only possible if
    // the engine retires the command asynchronously; if QEMU performs the copy inside the MMIO write
    // then the transfer is over before the `eret` and the whole shape is unreachable. Measure it
    // rather than reasoning about `edu.c`.
    {
        poke(landing_own, SENTINEL_MAGIC);
        mmio_write64(bar0, EDU_REG_DMA_SRC, EDU_DMA_BUF);
        mmio_write64(bar0, EDU_REG_DMA_DST, ipa_own);
        mmio_write64(bar0, EDU_REG_DMA_CNT, 8);
        mmio_write64(bar0, EDU_REG_DMA_CMD, EDU_DMA_RUN | EDU_DMA_TO_RAM);
        // Read back BEFORE spinning: if RUN is already clear here, the engine is synchronous.
        let run_now = mmio_read64(bar0, EDU_REG_DMA_CMD) & EDU_DMA_RUN;
        let mem_now = peek(landing_own);
        let mut polls: u64 = 0;
        while polls < 20_000_000 && mmio_read64(bar0, EDU_REG_DMA_CMD) & EDU_DMA_RUN != 0 {
            polls += 1;
            core::hint::spin_loop();
        }
        let mem_after = peek(landing_own);
        // A second scale, in units that do NOT exit to QEMU on every step: how many plain CPU
        // iterations a retirement costs. The poll count above is inflated by one MMIO trap each.
        poke(landing_own, SENTINEL_MAGIC);
        mmio_write64(bar0, EDU_REG_DMA_CMD, EDU_DMA_RUN | EDU_DMA_TO_RAM);
        let mut spins: u64 = 0;
        while spins < 200_000_000 && peek(landing_own) == SENTINEL_MAGIC {
            spins += 1;
            core::hint::spin_loop();
        }
        let _ = writeln!(
            uart,
            "baleen: 19-3 PROBE: run_after_kick={run_now} mem_after_kick={mem_now:#x} polls_to_retire={polls} mem_after_spin={mem_after:#x} cpu_spins_to_land={spins}"
        );
    }

    // ── Arm 1 — the POSITIVE control. Without it the refusal below is vacuous: a wedged SMMU
    //    refuses everything and looks like flawless isolation.
    let (own_before, own_after, own_retired) = probe(ipa_own, landing_own);
    let reached_own = own_before == SENTINEL_MAGIC && own_retired && own_after != own_before;

    // ── Arm 2 — CONFINEMENT, and the isolation content. Same device, same binding, an IPA in the
    //    PEER's window: this guest's image maps it nowhere, so the walk must fault and the peer's
    //    landing site must be untouched.
    let (peer_before, peer_after, peer_retired) = probe(ipa_peer, forbidden_peer);
    let refused_peer = peer_before == SENTINEL_MAGIC && peer_retired && peer_after == peer_before;

    let restored = smmu::unbind_stream(sid);

    let ok = reached_own && refused_peer && !own_maps_peer && restored;
    if ok {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest OK: a bus master bound to a REAL guest's own Stage-2 image (S2TTB={l1_own:#x}, VMID={}) reached that guest's memory at IPA {ipa_own:#x} (table says {landing_own:#x}), and the SAME device asking for {ipa_peer:#x} in the PEER's window was ABORTED with the peer's landing site {forbidden_peer:#x} intact — one proven p2m, two consumers, on the image an unmodified Linux kernel is about to run under (positive arm is a control only: these guests are identity-mapped)",
            bind_own.vmid
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: smmu realguest FAIL: reached_own={reached_own} (before={own_before:#x} after={own_after:#x} retired={own_retired}) refused_peer={refused_peer} (before={peer_before:#x} after={peer_after:#x} retired={peer_retired}) own_maps_peer={own_maps_peer} restored={restored}; halting"
        );
        crate::park();
    }
}
