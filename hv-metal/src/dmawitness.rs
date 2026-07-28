// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The DMA witness — a real bus master, and whether the SMMU stops it (SMMU arc, rung 1)
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

/// The magic the sentinel holds before the DMA. Survives ⟹ the write was aborted.
const SENTINEL_MAGIC: u64 = 0xD11A_5EED_D11A_5EED;

/// The DMA target: a sentinel in EL2 RAM, in a dedicated cache-line-aligned static so no neighbouring
/// state is perturbed if a transfer *does* land. `static mut` rather than an atomic because the write
/// under observation comes from a **device**, not a CPU — the whole point is that it bypasses every
/// CPU-side mechanism, so the interesting accesses are not Rust's to order.
#[repr(align(64))]
struct Sentinel(u64);
static mut DMA_SENTINEL: Sentinel = Sentinel(SENTINEL_MAGIC);

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

/// Read the sentinel back after the device has (or has not) written to it.
fn sentinel() -> u64 {
    // SAFETY: `DMA_SENTINEL` is written only by the DEVICE under test (via DMA) and read here; no
    // Rust code holds a reference to it across this read, and the metal is single-threaded with the
    // secondaries parked. A volatile read is used because the value can change without any CPU store,
    // which is precisely what is being detected.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DMA_SENTINEL.0)) }
}

/// The sentinel's physical address — what the device is told to write to. Identity, since EL2 runs
/// MMU-off.
fn sentinel_pa() -> u64 {
    // SAFETY: taking the address of a static is sound; no dereference here.
    unsafe { core::ptr::addr_of!(DMA_SENTINEL.0) as u64 }
}

/// Ask `edu` to DMA `8` bytes from its zeroed internal buffer over the sentinel, and wait (bounded)
/// for the engine to report completion. Returns whether the command retired.
///
/// The bound matters: `edu` runs its transfer off a QEMU timer, and when the SMMU aborts the write the
/// engine still completes (an aborted transaction is terminated, not stalled) — but a machine that
/// never retires the command must not hang a CI boot test. A timeout is reported, not waited out.
fn trigger_dma(bar0: u64) -> bool {
    mmio_write64(bar0, EDU_REG_DMA_SRC, EDU_DMA_BUF);
    mmio_write64(bar0, EDU_REG_DMA_DST, sentinel_pa());
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

    let before = sentinel();
    let retired = trigger_dma(bar0);
    let after = sentinel();
    let landed = after != before;

    #[cfg(feature = "smmu")]
    {
        let (aborting, s2, idr0, idr1, present) = smmu_state;
        let ok =
            present && aborting && device_live && retired && !landed && before == SENTINEL_MAGIC;
        if ok {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 DEFAULT-DENY OK: SMMUv3 present (IDR0={idr0:#010x} IDR1={idr1:#010x} stage2={s2} translating={}), GBPA.ABORT set BEFORE bus-master enable, a live edu device's DMA to {:#x} was ABORTED (sentinel intact {before:#x})",
                smmu::translating(),
                sentinel_pa()
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
        let ok = device_live && retired && landed && before == SENTINEL_MAGIC && after == 0;
        if ok {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 POSITIVE CONTROL OK: no SMMU in this machine, a live edu device DMA'd over the sentinel at {:#x} ({before:#x} -> {after:#x}) — the flow the default-deny boot blocks is REAL",
                sentinel_pa()
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: smmu rung1 POSITIVE CONTROL FAIL (live={device_live} retired={retired} landed={landed} before={before:#x} after={after:#x}); halting"
            );
            crate::park();
        }
    }
}
