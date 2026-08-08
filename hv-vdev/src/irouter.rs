// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `GICD_IROUTER<n>` — which vCPU an SPI is delivered to (⑱-6)
//!
//! ## The residue this closes, and the condition that expired
//!
//! [`gicv3`](crate::gicv3)'s module docs have carried this since ⑱-2:
//!
//! > **`IROUTER` is recorded, not honoured** — every SPI can only land in one place.
//!
//! and gave the reason it was right to leave it there: *"it needs a second vCPU per guest to
//! matter, so implementing it now would add unexercised code to the guest's device surface"* —
//! design-lesson #71's rule, and III-2's "deferred for want of a consumer".
//!
//! **`VCPUS_PER_GUEST` is 2 and both vCPUs run.** The condition the deferral named has expired, so
//! the rule that justified the deferral now demands the opposite. That is the whole reason this
//! module exists now rather than earlier, and it is why the deferral was written with its expiry
//! condition attached rather than as a bare "later".
//!
//! ## Why this is the same shape as [`sgi`](crate::sgi), deliberately
//!
//! ⑱-5 decided the *other* routing axis — which vCPU an **SGI** names — and everything hard about
//! this rung was solved there: a pure decode of a guest-written `u64` under the fence, a `targets`
//! **predicate** taking a packed affinity so this module never learns baleen's vCPU→affinity
//! mapping, and a caller that offers it only the vCPUs of the issuing guest. This module is that
//! shape again for SPIs. Reading the two side by side is intended.
//!
//! The one structural difference is worth stating, because it is what makes this the *easier* of
//! the two: an SGI names a **set** (a 16-bit target list, or "all but me"), while `IROUTER` names
//! **exactly one PE**. So [`SpiRoute::targets`] is an equality against a single recorded affinity,
//! and *"an SPI is delivered to at most one vCPU"* is true **by the shape of the type** — there is
//! no list to have two bits set in. Same move as `sgi`'s "no index to get wrong".
//!
//! ## ★ `IRM` (1-of-N), and why the answer is a DECLARATION rather than a policy
//!
//! Bit 31 is `Interrupt_Routing_Mode`: 1 means *"route to any PE participating in 1-of-N
//! distribution"*, with the choice left to the implementation. That is a genuine fork, and picking
//! a PE would be inventing hypervisor policy that no guest asked for and nothing could check.
//!
//! So this port does not pick. It **declares 1-of-N unsupported** — `GICD_TYPER.No1N` (bit 25) is
//! set — which is the architecture's own provision for exactly this, and then the decode is total
//! over everything a *conforming* guest can ask for. Design-lesson #202: prefer a declaration to a
//! guess, and it hands you a second, independently-produced witness — here the guest reads `No1N`
//! and never sets `IRM`, so the declaration and the decode are checked against each other by a real
//! kernel rather than only by us.
//!
//! A guest that sets `IRM` anyway has been told not to. [`SpiRoute::targets`] then names **no**
//! vCPU, which is the same failure mode as an affinity naming a PE that does not exist, and is the
//! safe direction: an undelivered interrupt is visible to the guest that asked for it, while a
//! guessed target would be a silently wrong delivery. ⚠ It must NOT become a halt — `hv-metal`
//! counts it and reports it. A guest reaching a halt takes its peer down with it, which is the
//! defect ⑱-5 removed from the SGI path and must not be reintroduced here.
//!
//! ## Bounds
//!
//! Same as `sgi`: [`SpiRoute::targets`] is a predicate, the caller iterates the vCPUs it *has*, so
//! "a target is always a vCPU that exists" holds by the shape of the call rather than as a proof
//! obligation. There is no indexing in this file.

/// `GICD_IROUTER<n>.Interrupt_Routing_Mode`, bit 31 — 1 = "any PE participating in 1-of-N".
///
/// Note the offset: it sits *between* `Aff2` and `Aff3`, which is why `Aff3` is at `[39:32]` rather
/// than continuing the byte-per-level run. That gap is this register's, and it stops here.
const IRM_BIT: u64 = 1 << 31;
/// `Aff2:Aff1:Aff0`, bits `[23:0]` — already one byte per level, and already in the layout
/// [`vcpu_affinity`](crate::gicv3::vcpu_affinity) uses.
const AFF_LOW_MASK: u64 = 0x00ff_ffff;
/// `Aff3`, bits `[39:32]`.
const AFF3_SHIFT: u32 = 32;
const AFF_BYTE: u64 = 0xff;
/// Where `Aff3` lands once repacked into [`vcpu_affinity`]'s layout — one byte per level, `Aff0`
/// lowest, so `Aff3` is the fourth byte.
const PACKED_AFF3_SHIFT: u32 = 24;

/// **Which vCPU one `GICD_IROUTER<n>` value names**, decoded once and then asked about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpiRoute {
    /// `IRM` — the guest asked for 1-of-N, which this port declares unsupported.
    any_of_n: bool,
    /// `Aff3:Aff2:Aff1:Aff0` repacked into [`vcpu_affinity`](crate::gicv3::vcpu_affinity)'s layout.
    affinity: u64,
}

/// Decode one `GICD_IROUTER<n>` value.
///
/// Takes no `sender` and no INTID: unlike an SGI, the register says nothing about who raised the
/// interrupt, and the INTID is which register this is rather than a field inside it.
#[must_use]
pub const fn decode(value: u64) -> SpiRoute {
    SpiRoute {
        any_of_n: value & IRM_BIT != 0,
        // Repacked into `vcpu_affinity`'s layout for the same reason `sgi::decode` repacks: `targets`
        // compares against what that function returns, and the register's own field offsets are the
        // register's business.
        affinity: (value & AFF_LOW_MASK)
            | (((value >> AFF3_SHIFT) & AFF_BYTE) << PACKED_AFF3_SHIFT),
    }
}

impl SpiRoute {
    /// Whether the guest asked for 1-of-N routing (`IRM`).
    ///
    /// [`Self::targets`] already accounts for it, so this is for the **caller and the harness**, not
    /// for a second routing decision: `hv-metal` counts these so an undelivered SPI is reported
    /// rather than silent, and `an_any_of_n_route_names_no_vcpu` asserts the mode was *recognised*
    /// before asserting what it means — so a decode that never looked at bit 31 could not satisfy
    /// the property vacuously. Same guard as `SgiTargets::is_broadcast`.
    #[must_use]
    pub const fn is_any_of_n(&self) -> bool {
        self.any_of_n
    }

    /// **Does this route name the vCPU whose packed affinity is `aff`?**
    ///
    /// Pass [`vcpu_affinity(v)`](crate::gicv3::vcpu_affinity) — never a bare vCPU index, for the
    /// reason in the module docs of [`sgi`](crate::sgi): the vCPU→affinity mapping has exactly one
    /// derivation and this must not become a second.
    ///
    /// Isolation falls out rather than being checked, exactly as it does for an SGI: a routing value
    /// naming a cluster no vCPU of this guest is in — any non-zero `Aff1`/`Aff2`/`Aff3` — equals no
    /// `vcpu_affinity` value, so it targets nothing rather than something wrong.
    #[must_use]
    pub const fn targets(&self, aff: u64) -> bool {
        // `IRM` first: when it is set the affinity fields are meaningless, so comparing them would be
        // reading a value the architecture does not define.
        !self.any_of_n && aff == self.affinity
    }
}
