// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The DMA witness — a real bus master, and whether the SMMU stops it (SMMU arc, rungs 1–2)
//!
//! Every isolation result baleen has is about **CPU** accesses. To say anything about DMA there has to
//! be a device that actually performs it, so this module builds the smallest possible one and then
//! observes whether its writes land.
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
//! unexplained between the two runs. [`rung2`] tightens that to the smallest possible difference: one
//! boot, one machine, one device, and phases that differ only in the contents of a single 64-byte
//! Stream Table Entry — or, in the last phase, only in the table *size* announced to the SMMU. See
//! [`rung2`] for the phase table and what each one rules out.
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
//!   result rests on [`pcie::stream_id`] being the RequesterID the hardware really presents;
//! * never write `CR0.SMMUEN`, and every phase reports "aborted" — which is exactly the vacuous deny
//!   this rung is built to exclude, and exactly what phase 1 catches.

use crate::pcie;
use crate::pl011::Pl011;
#[cfg(feature = "smmu")]
use crate::smmu;
use core::fmt::Write;

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
        let ok = present && aborting && device_live && a.aborted();
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
                "baleen: smmu rung1 DEFAULT-DENY FAIL (present={present} aborting={aborting} live={device_live} retired={retired} landed={landed} before={before:#x} after={after:#x}); halting"
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
    let setup = smmu::install_stream_table();

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
}
