// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Device assignment — which domain a bus master belongs to
//!
//! Every other subsystem here answers a question about what a domain may reach *through the
//! CPU*. This one answers the question a DMA-capable device makes urgent: **whose memory may a
//! bus master write?** The hardware answer is an SMMU stream-table entry pointing at a domain's
//! Stage-2 tables (`docs/SMMU-TRANSLATION.md`); this module is the *relation that entry
//! refines* — the device-axis twin of what [`crate::p2m`] is to the Stage-2 descriptors.
//!
//! ## A device is a token, exactly as a frame is
//!
//! [`DevId`] is an opaque index and nothing else. The core does not know what a StreamID, a
//! PCIe RequesterID or a BDF is, for precisely the reason it does not know what a machine frame
//! address is: the token→hardware map is the fence's business (design-lesson #14e), and keeping
//! it out is what lets one proven relation serve an SMMU, an x86 IOMMU, or a platform with a
//! fixed device tree. What the core owns is **who holds which device**, which is the whole of
//! the isolation content.
//!
//! ## Assignment is ownership-shaped, not consent-shaped
//!
//! A grant is the right shape when two principals must agree about something *one of them
//! owns*. No domain owns a device: it is a platform resource, and assignment is a capability
//! handed *down* the authority axis by a controller — Xen's `XEN_DOMCTL_assign_device`, a
//! domctl issued about a target, not a peer-to-peer permit. Modelling it as a grant would need
//! an invented owner, a two-step offer/accept protocol, and a second kind of inbound reference
//! to sweep, to express a sharing the hardware cannot represent anyway: one STE, one `S2TTB`.
//! **The refinement target is exclusive, so the relation is exclusive.**
//!
//! ## Exclusivity is unrepresentable, not checked
//!
//! "At most one domain per device" is not an invariant of this module — it is a property of its
//! *type*. The state is `Option<DomId>` per device, not a set, so a second simultaneous holder
//! cannot be written down. That is the same move III-1 made for the pending-interrupt overflow:
//! a check that could never fail is worse than no check, because it reads as evidence.
//!
//! What *is* a real invariant needs two subsystems and therefore lives at the seam, not here:
//!
//! > `holder_of(dev) == Some(d)` ⟹ `d` is `Live`.
//!
//! An assignment is a bare [`DomId`] recorded in a table that is *not* the domain's own, which
//! outlives the transition that wrote it and is honoured later by whoever occupies that slot —
//! the same shape as a grant naming a grantee, or a half-open port awaiting a peer. So it is
//! kept standing the same way (design-lesson #15): a **mint gate** refusing assignment to a
//! non-`Live` target, plus an **eager teardown sweep** ([`System::release_all_of`]), with
//! [`crate::hypervisor::CrossViolation::DeadDomainReferenced`] as the standing check that both
//! did their job. Without the sweep a reborn slot inherits a bus master aimed at its memory —
//! the confused deputy, in the one flavour the CPU-side proofs cannot see.
//!
//! ## What this module deliberately does NOT model
//!
//! It says **who holds a device**, never **what memory that device reaches**. Reachability is
//! already a proven relation ([`crate::p2m`] → `hv-s2`'s leaf map); restating it on the device
//! axis would be a second copy to keep in step. The composition — *a device assigned to `d`
//! walks `d`'s Stage-2 tables* — is the metal's refinement obligation, discharged where the
//! table is built, exactly as `build_stage2_from_p2m` discharges the frame axis.
//!
//! Provenance: assignment-as-a-domctl and the exclusive device→domain relation are informed by
//! the public Xen device-assignment semantics and general OS knowledge — not `xen/`'s GPL
//! implementation. See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

/// A domain identifier — an index into the domain table, as everywhere else in the core.
pub type DomId = u16;

/// A device identifier: an opaque index naming one DMA-capable bus master.
///
/// Opaque on purpose. The core never learns the StreamID, RequesterID or BDF behind it — the
/// token→hardware map belongs below the fence, the same discipline that keeps
/// [`crate::p2m::Mfn`] from naming a physical address. `u16` mirrors [`DomId`]: a platform has
/// few enough bus masters that a wider index would model nothing extra.
pub type DevId = u16;

/// Why a device operation was refused. Every variant leaves the assignment table untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The device index is out of range.
    BadDevice,
    /// The named domain index is out of range.
    BadDomain,
    /// The device is already assigned to a **different** domain. Assignment is exclusive
    /// because the hardware is: an STE names one `S2TTB`, so a device reaching two domains'
    /// memory is not expressible, and a model that permitted it would be refined by nothing.
    ///
    /// Re-assigning a device to the domain that already holds it is **not** this error — it is
    /// an idempotent success, the [`crate::HvCall::ControlGrant`] precedent, and it is also
    /// what keeps this refusal from disclosing anything the caller could not already ask for
    /// directly.
    Busy,
    /// The release named a holder that does not hold this device — either it is unassigned, or
    /// some other domain holds it. One error for both, deliberately: telling them apart would
    /// hand the caller a bit about a domain it may have no authority over.
    NotAssigned,
}

/// The system-wide device→domain assignment relation.
///
/// One `Option<DomId>` per device: `None` is unassigned (the state a device boots in, and the
/// one the metal refines to a *denying* stream-table entry), `Some(d)` is held by `d`.
#[derive(Clone)]
pub struct System {
    /// Per [`DevId`]: the domain holding it, if any.
    assign: Vec<Option<DomId>>,
    /// Domain count, so a bad holder is refused here rather than trusted from the seam — the
    /// same self-sufficiency [`crate::p2m::System`] has.
    num_domains: usize,
}

impl System {
    /// A system of `num_devices` devices over `num_domains` domain slots, every device
    /// **unassigned**. Fail-closed at boot: until a controller assigns one, no device is any
    /// domain's, and the table the metal derives from this denies every stream (#51).
    pub fn new(num_domains: usize, num_devices: usize) -> Self {
        System {
            assign: alloc::vec![None; num_devices],
            num_domains,
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Assign `dev` to `to`.
    ///
    /// **Idempotent** when `to` already holds it. Refused with [`DeviceError::Busy`] when
    /// another domain does — never silently re-pointed, because a re-pointed device is a bus
    /// master aimed at a different domain's memory and the previous holder is given no chance
    /// to be quiesced.
    ///
    /// This function knows nothing about authority or liveness: both are the integrated core's
    /// (the caller must control `to`, and `to` must be `Live`), because both need state no
    /// subsystem here can see. Every subsystem stays authority-agnostic.
    pub fn assign(&mut self, dev: DevId, to: DomId) -> Result<(), DeviceError> {
        if to as usize >= self.num_domains {
            return Err(DeviceError::BadDomain);
        }
        let slot = self
            .assign
            .get_mut(dev as usize)
            .ok_or(DeviceError::BadDevice)?;
        match *slot {
            None => {
                *slot = Some(to);
                Ok(())
            }
            Some(h) if h == to => Ok(()),
            Some(_) => Err(DeviceError::Busy),
        }
    }

    /// Release `dev` from `from`, returning it to the unassigned pool.
    ///
    /// `from` is named rather than looked up, so the integrated core can settle authority
    /// *before* reading the table — a caller with no claim on `from` is refused without
    /// learning whether `dev` is held at all.
    pub fn release(&mut self, dev: DevId, from: DomId) -> Result<(), DeviceError> {
        if from as usize >= self.num_domains {
            return Err(DeviceError::BadDomain);
        }
        let slot = self
            .assign
            .get_mut(dev as usize)
            .ok_or(DeviceError::BadDevice)?;
        if *slot != Some(from) {
            return Err(DeviceError::NotAssigned);
        }
        *slot = None;
        Ok(())
    }

    /// Release **every** device `holder` holds — the device half of domain teardown.
    ///
    /// The inbound-reference sweep (design-lesson #15) for a third kind of reference. An
    /// assignment survives its holder's death as a bare `DomId`, and the core has no
    /// generation counter by design (an unbounded incarnation would break the enumerator's
    /// finite-state search), so a reborn slot would inherit a device pointed at its memory.
    /// Eager clearing is what makes
    /// [`crate::hypervisor::CrossViolation::DeadDomainReferenced`] standing rather than a
    /// once-checked postcondition, and it is total by construction: there is no refusal path.
    pub fn release_all_of(&mut self, holder: DomId) {
        for slot in &mut self.assign {
            if *slot == Some(holder) {
                *slot = None;
            }
        }
    }

    // ─── queries ─────────────────────────────────────────────────────────────

    /// Which domain holds `dev`, or `None` if it is unassigned (or out of range).
    ///
    /// The predicate the metal's stream table is a refinement of: an entry permits exactly the
    /// streams this answers `Some` for, naming exactly that domain's tables.
    pub fn holder_of(&self, dev: DevId) -> Option<DomId> {
        *self.assign.get(dev as usize)?
    }

    /// Whether any device is assigned to `holder` — the read side of the device half of
    /// [`crate::hypervisor::CrossViolation::DeadDomainReferenced`], and of the clean-shell
    /// precondition [`crate::HvCall::DomainCreate`] asserts before reviving a slot.
    pub fn any_device_of(&self, holder: DomId) -> bool {
        self.assign.contains(&Some(holder))
    }

    /// Number of devices.
    pub fn device_count(&self) -> usize {
        self.assign.len()
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.num_domains
    }

    /// How many devices are currently assigned to some domain.
    pub fn assigned_count(&self) -> usize {
        self.assign.iter().filter(|a| a.is_some()).count()
    }
}

// NOTE: there is deliberately no `invariants_hold` here, and its absence is a design statement.
// The one property a device subsystem would want to assert — that no device has two holders —
// is discharged by the *representation* (`Option<DomId>`, not a set), so a method returning it
// could never return `false`, and a check that cannot fail reads as evidence when it is none
// (design-lesson #71). The only genuine device invariant couples this table to the domain
// lifecycle, which needs state this module cannot see, so it lives at the integrated seam as
// `CrossViolation::DeadDomainReferenced`.

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> System {
        System::new(4, 3)
    }

    #[test]
    fn devices_boot_unassigned() {
        let s = sys();
        assert_eq!(s.device_count(), 3);
        assert_eq!(s.assigned_count(), 0);
        assert!((0..3).all(|d| s.holder_of(d).is_none()));
    }

    #[test]
    fn assign_then_holder_is_the_assignee() {
        let mut s = sys();
        assert_eq!(s.assign(1, 2), Ok(()));
        assert_eq!(s.holder_of(1), Some(2));
        assert_eq!(s.assigned_count(), 1);
        // Untouched neighbours — assignment is per-device, not a mode.
        assert_eq!(s.holder_of(0), None);
        assert_eq!(s.holder_of(2), None);
    }

    #[test]
    fn assigning_to_the_same_domain_is_idempotent() {
        let mut s = sys();
        s.assign(1, 2).unwrap();
        assert_eq!(s.assign(1, 2), Ok(()));
        assert_eq!(s.holder_of(1), Some(2));
    }

    #[test]
    fn assigning_a_held_device_to_another_domain_is_refused_and_changes_nothing() {
        let mut s = sys();
        s.assign(1, 2).unwrap();
        assert_eq!(s.assign(1, 3), Err(DeviceError::Busy));
        assert_eq!(
            s.holder_of(1),
            Some(2),
            "a refused assign must not re-point"
        );
    }

    #[test]
    fn release_requires_the_named_holder() {
        let mut s = sys();
        s.assign(1, 2).unwrap();
        assert_eq!(s.release(1, 3), Err(DeviceError::NotAssigned));
        assert_eq!(s.holder_of(1), Some(2));
        assert_eq!(s.release(1, 2), Ok(()));
        assert_eq!(s.holder_of(1), None);
        // ... and releasing an unassigned device is the same error, not a distinguishable one.
        assert_eq!(s.release(1, 2), Err(DeviceError::NotAssigned));
    }

    #[test]
    fn out_of_range_indices_are_refused() {
        let mut s = sys();
        assert_eq!(s.assign(3, 0), Err(DeviceError::BadDevice));
        assert_eq!(s.assign(0, 4), Err(DeviceError::BadDomain));
        assert_eq!(s.release(3, 0), Err(DeviceError::BadDevice));
        assert_eq!(s.release(0, 4), Err(DeviceError::BadDomain));
        assert_eq!(s.holder_of(3), None);
        assert_eq!(s.assigned_count(), 0);
    }

    #[test]
    fn release_all_of_takes_exactly_that_holders_devices() {
        let mut s = sys();
        s.assign(0, 1).unwrap();
        s.assign(1, 2).unwrap();
        s.assign(2, 1).unwrap();
        assert!(s.any_device_of(1));
        s.release_all_of(1);
        assert!(!s.any_device_of(1));
        assert!(s.any_device_of(2), "the sweep must spare other holders");
        assert_eq!(s.holder_of(1), Some(2));
        assert_eq!(s.assigned_count(), 1);
    }

    #[test]
    fn release_all_of_a_holder_with_nothing_is_a_no_op() {
        let mut s = sys();
        s.assign(0, 1).unwrap();
        s.release_all_of(3);
        assert_eq!(s.holder_of(0), Some(1));
        assert_eq!(s.assigned_count(), 1);
    }
}
