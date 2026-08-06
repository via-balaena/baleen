// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Deploying the emulated GICv3 on *this* machine (③-b1, feature `real-linux`)
//!
//! ③-a1 took the guest's console. ③-a2 took its interrupt *delivery*. ③-b1 took the **interrupt
//! controller itself** — the last real device the real-Linux guest was still driving.
//!
//! **After that rung the real-Linux guest has NO Stage-2 device pass-through window at all** —
//! `stage2::windows().device_len == 0`, asserted at compile time below. Every device it touches is
//! EL2 state. That is the property ③-b needs, and it is structural rather than argued.
//!
//! ## What is here, after ⑯ moved the model out
//!
//! The **register file itself now lives in [`hv_vdev::gicv3`]**, under the workspace's
//! `unsafe_code = "forbid"` fence where `hv-verify` can reach it. What stays here is everything that
//! is a claim about *this board*:
//!
//! - **[`LAYOUT`]** — the four addresses the model used to import directly from [`crate::gic`].
//!   Under the fence they are a parameter, because re-declaring them there would be a *second
//!   derivation* of the board's address map (design-lesson #74, the defect ⑭ spent a rung removing).
//! - **The three `const assert!`s** below: that the layout is one the decode can honour, that the
//!   forwarded timer's INTID exists in the emulated distributor, and ③-b1's headline — that the
//!   Stage-2 device pass-through window is zero.
//! - **The witness** ([`DeployedGic`]) — trap and enable tallies, wrapped around the model rather
//!   than living inside it, so the model's "a failed write changes nothing" stays stateable.
//! - **The physical mirror.** `linux.rs` reads [`DeployedGic::is_enabled`] and mirrors the guest's
//!   timer enable onto the *real* redistributor via [`crate::gic::set_ppi_enabled`]. That is the one
//!   place the emulation meets the machine, and it is `unsafe` MMIO, which the fence forbids.
//!
//! ## Unsafe
//!
//! **None in this module.** The emulation is a pure register file over EL2-owned memory; the one
//! place it meets the machine is EL2's own enable of a *physical* interrupt it intends to forward,
//! which lives in [`crate::gic`] where the rest of the `unsafe` MMIO already is.

use hv_vdev::gicv3::{GicLayout, Unhandled, VirtGic, NUM_INTIDS};

use crate::gic::{GICD_BASE, GICD_LEN, GICR_END, GICR_RD_BASE};

/// Where the emulated distributor and redistributor sit in **this** guest's address space.
///
/// Deliberately the same addresses the real GIC occupies: the guest is offered *the device it had*,
/// so `guest.dts` needs no edit — the same "unmodified guest description" property ③-a1 preserved
/// for the PL011.
pub(crate) const LAYOUT: GicLayout = GicLayout::new(GICD_BASE, GICD_LEN, GICR_RD_BASE, GICR_END);

// ─── the three structural facts this rung rests on, checked by the COMPILER ──────────────────────
//
// A boot marker can only witness what a boot exercises. These are true or the build fails.

/// The layout must be one the decode can honour — the distributor's window ending at or before the
/// redistributor's, both frames present, no wrapping.
///
/// **This precondition was unwritten before ⑯.** It was true of this board and would have failed
/// silently on a second one; the decode is memory-safe for any layout at all, so nothing would have
/// crashed — the frames would simply have stopped meaning what their names say.
const _: () = assert!(
    LAYOUT.validate(crate::role::VCPUS_PER_GUEST),
    "the emulated GIC's layout is one the decode cannot honour"
);

// ⑱-3a: `VCPUS_PER_GUEST` moved to `crate::role`, which owns the vCPU axis and its types, so there
// is one statement of how many vCPUs a guest has rather than one per consumer. The `const assert!`
// above is what makes the pairing checkable from here: raise the count past what the redistributor
// region can hold and the build stops, rather than the guest discovering a frame outside the window
// its own device tree describes.

/// The interrupt EL2 forwards on the guest's behalf must exist in the distributor the guest sees.
const _: () = assert!(
    (crate::gic::VTIMER_INTID as usize) < NUM_INTIDS,
    "the forwarded timer INTID must exist in the emulated distributor"
);

/// **The ③-b1 headline, as a compile-time fact.** The real-Linux guest gets NO Stage-2 device
/// pass-through window: every device it touches — the PL011 (③-a1) and the GIC (③-b1) — is emulated
/// in EL2. A non-zero window means some guest MMIO reaches real hardware again.
///
/// This **subsumes** [`crate::vpl011`]'s narrower assertion (that the window must not cover the
/// PL011); that one is kept because it records ③-a1's specific failure story, which this does not.
const _: () = assert!(
    crate::stage2::windows().device_len == 0,
    "the real-Linux guest must have no Stage-2 device pass-through window — every device it touches \
     is emulated in EL2 (vgic, vpl011)"
);

/// `true` iff `ipa` falls in the emulated GIC's windows, so the real-Linux data-abort handler routes
/// it here rather than reporting an unexpected fault.
pub(crate) fn in_window(ipa: u64) -> bool {
    LAYOUT.in_window(ipa)
}

/// The emulated GICv3 **as deployed**: the register file, plus the evidence that it ran.
///
/// The split is the point. [`VirtGic`] is what a guest driver can observe and is provable in
/// isolation; the tallies here are what the boot gate reads and mean nothing to a driver.
pub(crate) struct DeployedGic {
    /// The model, under the fence.
    dev: VirtGic<{ crate::role::VCPUS_PER_GUEST }>,
    /// How many register accesses the guest has made — the witness counter.
    traps: u64,
    /// How many INTIDs the guest has ever newly enabled — the witness's discriminating half.
    ///
    /// Accumulated here from what [`VirtGic::mmio_write`] *reports*, rather than counted inside the
    /// model. A pass-through configuration could not produce a non-zero value, because the writes
    /// would never have been seen.
    enables: u64,
}

/// **A guest's distributor is per-GUEST, and ⑱-2 is why that stays true with more than one vCPU:**
/// the per-vCPU part of a GICv3 — the redistributors, with their banked INTIDs 0..31 — lives INSIDE
/// [`VirtGic`] as `VirtGic<VCPUS_PER_GUEST>`, not as a second axis out here. Declaring only
/// [`PerGuestState`] makes a `PerVcpu<DeployedGic, ..>` a build error, which is the right answer: it
/// would give each vCPU its own copy of the SPIs the guest shares.
impl crate::role::PerGuestState for DeployedGic {}

impl DeployedGic {
    /// A distributor out of reset, with an unfired witness.
    pub(crate) const fn new() -> Self {
        Self {
            dev: VirtGic::new(LAYOUT),
            traps: 0,
            enables: 0,
        }
    }

    /// **Is `intid` enabled for `vcpu`, in the guest's own interrupt controller?** The mediation
    /// seam: EL2 forwards a physical interrupt only when the guest has asked for it, rather than
    /// whenever one arrives.
    ///
    /// ⑱-2 added `vcpu` because INTIDs 0..31 — which include the timer PPI this seam is mostly asked
    /// about — are banked per redistributor. Call sites name the vCPU explicitly so ⑱-3 changes an
    /// argument rather than having to find them.
    ///
    /// ⚠ **⑱-3b-i: that plan was right about the mechanics and wrong about the risk.** All three
    /// call sites did name the vCPU explicitly — and all three named the *boot* vCPU, because at one
    /// vCPU per guest that is the only correct answer and nothing distinguishes "the vCPU that is
    /// running" from "vCPU 0". Finding them was never the hard part; noticing that finding them was
    /// not enough was. So the parameter is a [`VcpuIdx`](crate::role::VcpuIdx), which can only come
    /// from a role or from an explicit [`VcpuIdx::boot`](crate::role::VcpuIdx::boot) — and
    /// `BOOT_VCPU` is no longer a name `linux.rs` can resolve at all.
    ///
    /// [`VirtGic`]'s own parameter stays a `usize`: it is under the fence, it is a Kani target, and
    /// its harnesses quantify over the index. The narrowing belongs to the *deployment*, which is
    /// where the role types live.
    pub(crate) fn is_enabled(&self, vcpu: crate::role::VcpuIdx, intid: u32) -> bool {
        self.dev.is_enabled(vcpu.get(), intid)
    }

    /// `(register traps, INTIDs ever newly enabled)` — the ③-b1 witness.
    pub(crate) fn witness(&self) -> (u64, u64) {
        (self.traps, self.enables)
    }

    /// Service a guest **read** of the emulated GIC at `ipa`, `size` bytes wide.
    pub(crate) fn mmio_read(&mut self, ipa: u64, size: u64) -> Result<u64, Unhandled> {
        self.traps += 1;
        self.dev.mmio_read(ipa, size)
    }

    /// Service a guest **write** of the emulated GIC at `ipa`, `size` bytes wide.
    pub(crate) fn mmio_write(&mut self, ipa: u64, size: u64, value: u64) -> Result<(), Unhandled> {
        self.traps += 1;
        let newly = self.dev.mmio_write(ipa, size, value)?;
        self.enables += u64::from(newly);
        Ok(())
    }
}
