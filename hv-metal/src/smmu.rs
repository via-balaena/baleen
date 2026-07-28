// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # SMMUv3 — closing the DMA window (the SMMU arc, rung 1)
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
//! **Not here (rung 2+):** the stream table (`STRTAB_BASE`, per-`StreamID` STEs, `STE.Config` abort vs
//! bypass — the ∀-StreamID default-deny after `SMMUEN`), the command and event queues
//! (`CMD_CFGI_STE` / `CMD_SYNC`, and reading translation faults off `EVENTQ`), and translation proper
//! (`STE.S2TTB` pointing at the `p2m`-derived Stage-2 tables with the domain's VMID, which is where
//! `hv-s2`'s existing ∀-address refinement starts carrying the device path for free — the theorem
//! constrains the *table*, not the *walker*).
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

/// `SMMU_IDR0` — feature identification. Bit 0 `S1P` (stage-1 translation), **bit 1 `S2P` (stage-2
/// translation)** — the capability the whole arc depends on, since baleen's plan is to point the SMMU
/// at the *same* `p2m`-derived Stage-2 tables the CPU walks.
const SMMU_IDR0: u64 = 0x0000;
/// `SMMU_IDR1` — queue/table size parameters (`SIDSIZE` in bits [5:0] is the one rung 2 needs, to size
/// the stream table).
const SMMU_IDR1: u64 = 0x0004;
/// `SMMU_CR0` — global control; bit 0 is `SMMUEN`.
const SMMU_CR0: u64 = 0x0020;
/// `SMMU_GBPA` — the **global bypass attribute**: what happens to a transaction while the SMMU is not
/// translating. Bit 31 `Update` (write 1 to commit, self-clearing), bit 20 `ABORT`.
const SMMU_GBPA: u64 = 0x0044;

/// `SMMU_IDR0.S1P` — stage-1 translation supported.
const IDR0_S1P: u32 = 1 << 0;
/// `SMMU_IDR0.S2P` — stage-2 translation supported.
const IDR0_S2P: u32 = 1 << 1;
/// `SMMU_GBPA.Update` — writes to `GBPA` are ignored unless this is set; it self-clears when the
/// update has been absorbed, so it doubles as the completion signal.
const GBPA_UPDATE: u32 = 1 << 31;
/// `SMMU_GBPA.ABORT` — terminate bypassed transactions instead of passing them through untranslated.
const GBPA_ABORT: u32 = 1 << 20;
/// `SMMU_CR0.SMMUEN` — the SMMU is translating.
const CR0_SMMUEN: u32 = 1 << 0;

fn read32(off: u64) -> u32 {
    // SAFETY: a documented SMMUv3 register offset inside the `virt` machine's 128 KiB SMMU window —
    // device memory at EL2 (MMU off). Read-only; aliases no Rust memory.
    unsafe { core::ptr::read_volatile((SMMU_BASE + off) as *const u32) }
}

fn write32(off: u64, v: u32) {
    // SAFETY: as `read32`; the written offsets (`GBPA`) are RW.
    unsafe { core::ptr::write_volatile((SMMU_BASE + off) as *mut u32, v) }
}

/// Whether an SMMUv3 appears to be present at [`SMMU_BASE`].
///
/// QEMU only instantiates the SMMU with `-machine virt,iommu=smmuv3`, and the metal must run on both
/// configurations — the SMMU-less one is the arc's **positive control** (the boot where the device's
/// DMA is expected to *land*, proving the witness is not vacuous). Unassigned MMIO on `virt` reads as
/// zero rather than faulting, and a real SMMU always reports at least one translation stage, so a zero
/// `IDR0` is a sound "absent" test here.
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
