// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # PCIe — the minimum config-space access a DMA witness needs (SMMU rung 1)
//!
//! Baleen has been virtio-**mmio** throughout: devices at fixed physical windows, no enumeration, no
//! bus master other than EL2 itself. That is exactly why the DMA/SMMU hole stayed abstract — with no
//! third-party bus master in the machine, there was nothing whose DMA could bypass Stage-2.
//!
//! The SMMU arc needs a real one, and on QEMU `virt` the SMMU mediates **PCIe only** (`iommu-map`
//! lives on the `pcie@10000000` node, nothing on the virtio-mmio nodes). So this module exists to
//! reach one PCIe device and turn it into a DMA source. It is deliberately the *smallest* thing that
//! does that — not a PCIe subsystem:
//!
//! * **ECAM config access only.** No capability walking, no MSI, no bridges, no bus renumbering.
//! * **Bus 0 only**, and a linear scan of its 32 device slots. QEMU `virt` puts directly-attached
//!   devices on bus 0, which is all a witness needs.
//! * **One 32-bit BAR, assigned by hand.** There is no firmware here — no UEFI, no BIOS — so BARs
//!   come up unassigned (zero) and nothing has laid out the MMIO window. We place BAR0 at a fixed
//!   address inside the `virt` machine's 32-bit PCIe MMIO range and stop there.
//!
//! ## Why no MMU concerns
//!
//! EL2 runs MMU-off / identity (the standing metal position), so ECAM and the assigned BAR window are
//! reachable as plain physical addresses, exactly as `gic.rs` reaches GICD at `0x0800_0000`. When the
//! EL2 MMU is eventually brought up, these windows join the set that needs device mappings.
//!
//! ## Unsafe
//!
//! Every access here is a `read_volatile`/`write_volatile` to a documented offset in the `virt`
//! machine's ECAM or PCIe MMIO window — device memory, aliasing no Rust object.

/// PCIe **ECAM** base on QEMU `virt` — device tree `pcie@10000000`, `reg = <0x40 0x10000000 …>`, i.e.
/// `0x40_1000_0000`, 256 MiB. ECAM maps config space as
/// `base + (bus << 20) + (dev << 15) + (fn << 12) + off`.
///
/// **A `virt` platform fact, not architectural** — a real-hardware port must take it from the device
/// tree, the same caveat as `gic::MAINT_INTID`.
const ECAM_BASE: u64 = 0x40_1000_0000;

/// The 32-bit PCIe MMIO window on QEMU `virt` (device tree `ranges`, the `0x2000000` entry: child
/// `0x1000_0000`, size `0x2eff_0000`).
const PCIE_MMIO_BASE: u32 = 0x1000_0000;

/// How far apart consecutive devices' BAR0s are placed.
///
/// ㉑ put a SECOND bus master on this bus, and the single-device arrangement this file used to
/// describe — "BAR0 is placed at the window's base, there is exactly one device" — would have given
/// both of them the same MMIO address. **The fix is not an allocator but a function of the BDF**:
/// `dev` is unique on the bus by construction, so basing the address on it makes a collision
/// *unrepresentable* rather than merely avoided by whoever calls next. 16 MiB is far above `edu`'s
/// 1 MiB BAR (BARs must be naturally aligned to their size, so the stride must dominate it), and
/// even slot 31 lands at `0x2f00_0000`, inside the 752 MiB window.
const PCIE_MMIO_STRIDE: u32 = 0x0100_0000;

/// Config-space offsets used here (PCI 3.0 header type 0).
const CFG_VENDOR_DEVICE: u64 = 0x00;
const CFG_COMMAND: u64 = 0x04;
const CFG_BAR0: u64 = 0x10;

/// `PCI_COMMAND.Memory Space Enable` (bit 1) — decode BAR0.
const CMD_MEM_ENABLE: u32 = 1 << 1;
/// `PCI_COMMAND.Bus Master Enable` (bit 2) — **the bit that lets the device originate DMA at all.**
/// Nothing in this witness works without it, and it is worth naming: BME is the device's own gate on
/// being a bus master, and it is *not* an isolation mechanism — it is set by whoever drives the
/// device, so a compromised driver simply sets it. Constraining where that DMA may land is the SMMU's
/// job, which is the whole point of the arc.
const CMD_BUS_MASTER: u32 = 1 << 2;

/// A bus/device/function address on bus 0.
#[derive(Clone, Copy)]
pub(crate) struct Bdf {
    pub(crate) dev: u8,
}

impl Bdf {
    /// The ECAM address of `off` in this function's config space (bus 0, function 0).
    fn cfg(self, off: u64) -> u64 {
        ECAM_BASE + ((self.dev as u64) << 15) + off
    }
}

/// The **StreamID** this function's transactions carry into the SMMU.
///
/// On PCIe the SMMU's stream identifier is the **RequesterID** — `(bus << 8) | (device << 3) |
/// function` — mapped through the `iommu-map` property of the host bridge. On QEMU `virt` that
/// property is `<0 &smmuv3 0 0x10000>`, i.e. the identity over the whole 16-bit RequesterID space, so
/// StreamID *is* RequesterID here.
///
/// **The mapping is a platform fact, and it is the single most likely way an ∀-StreamID deny goes
/// vacuous**: bind the wrong StreamID and the device's transactions land on a different (zeroed) STE,
/// abort, and look exactly like the property holding. That is why rung 2 binds this StreamID to a
/// *permitting* entry first and requires the DMA to get through — the through-path is what proves this
/// function returns the number the hardware actually presents.
/// Gated to the SMMU boot: on a machine with no SMMU there is no stream table to index, and leaving
/// the lint able to see that keeps an unreachable phase from going unnoticed.
#[cfg(feature = "smmu")]
pub(crate) fn stream_id(bdf: Bdf) -> u32 {
    // Bus 0, function 0 — the same two assumptions `cfg` makes.
    u32::from(bdf.dev) << 3
}

/// Read a 32-bit config-space register.
fn cfg_read32(bdf: Bdf, off: u64) -> u32 {
    // SAFETY: ECAM is device memory on the `virt` machine, addressed directly at EL2 (MMU off). The
    // offset is a documented header-type-0 register; reads of config space have no side effects on
    // the registers this module touches. Aliases no Rust memory.
    unsafe { core::ptr::read_volatile(bdf.cfg(off) as *const u32) }
}

/// Write a 32-bit config-space register.
fn cfg_write32(bdf: Bdf, off: u64, v: u32) {
    // SAFETY: as `cfg_read32`; the written offsets (COMMAND, BAR0) are RW in header type 0.
    unsafe { core::ptr::write_volatile(bdf.cfg(off) as *mut u32, v) }
}

/// Find the first device on bus 0 matching `(vendor, device)`.
///
/// An absent slot reads `0xffff_ffff` (all ones) for vendor/device — the architectural "no device
/// responded" value, which is why the scan tests it rather than trusting a device count.
pub(crate) fn find(vendor: u16, device: u16) -> Option<Bdf> {
    find_nth(vendor, device, 0)
}

/// The `n`th function on bus 0 matching `vendor`/`device`, in ascending slot order.
///
/// ㉑ needs two of the SAME model of device — two `edu`s, which is what gives two distinct
/// StreamIDs off one driver — so matching by ID alone stopped being enough to name one. Ascending
/// slot order is a stable enumeration, so "device 0" and "device 1" mean the same two functions on
/// every boot, which is what lets the model's `DevId` axis be pinned to them.
pub(crate) fn find_nth(vendor: u16, device: u16, n: usize) -> Option<Bdf> {
    let want = (u32::from(device) << 16) | u32::from(vendor);
    (0..32u8)
        .map(|dev| Bdf { dev })
        .filter(|&bdf| {
            let id = cfg_read32(bdf, CFG_VENDOR_DEVICE);
            id != 0xffff_ffff && id == want
        })
        .nth(n)
}

/// Assign BAR0 at this device's own slot in the window, enable memory decode, and enable **bus
/// mastering** so the device can originate DMA. Returns the BAR0 base as a physical address.
///
/// No size negotiation: the caller knows the device, and the `virt` 32-bit window (752 MiB) dwarfs
/// any BAR a witness device asks for, so [`PCIE_MMIO_BASE`] plus a [`PCIE_MMIO_STRIDE`]-sized slot
/// per BDF is sufficient. A general allocator is deliberately out of scope — ㉑ needed two devices
/// not to collide, which is a weaker requirement than allocating, and one the BDF already answers.
pub(crate) fn enable_with_bar0(bdf: Bdf) -> u64 {
    // Derived from the BDF, not from a counter the caller keeps: see `PCIE_MMIO_STRIDE`.
    let base = PCIE_MMIO_BASE + u32::from(bdf.dev) * PCIE_MMIO_STRIDE;
    cfg_write32(bdf, CFG_BAR0, base);
    let cmd = cfg_read32(bdf, CFG_COMMAND);
    cfg_write32(bdf, CFG_COMMAND, cmd | CMD_MEM_ENABLE | CMD_BUS_MASTER);
    u64::from(base)
}
