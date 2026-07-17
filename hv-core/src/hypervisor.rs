// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The integrated core
//!
//! Everything before this module was a subsystem in isolation: the credit account
//! ([`crate::HvCore`]), event channels ([`crate::evtchn`]), grant tables
//! ([`crate::grant`]), the scheduler ([`crate::sched`]). [`Hypervisor`] is the brain
//! that owns them all and routes a single, typed hypercall vocabulary ([`HvCall`])
//! into them — so `hv-sim` drives one integrated core, and one invariant check
//! ([`Hypervisor::invariants_hold`]) covers the whole thing.
//!
//! **This is the dispatch seam, for real.** [`HvCall`] is *ABI-neutral*: it names
//! operations, not wire encodings. At M5 the Xen personality (`baleen-xenabi`)
//! decodes guest register state into an `HvCall` and hands it here — exactly the
//! split flagged back at M1, where the toy `decode` lived in the core only for
//! convenience. The core owns the *operation*; the personality owns the *format*.
//!
//! Each call carries an explicit `caller: DomId` — the domain making the hypercall.
//! The core never trusts a domain to name itself as someone else: `caller` is the
//! acting domain for every routed operation, which is what makes cross-domain
//! permission checks (grant grantee identity, event-channel binding) meaningful.

extern crate alloc;

use alloc::vec::Vec;

use hv_hal::Ticks;

use crate::evtchn::{self, Port, Vcpu, Virq};
use crate::grant::{self, Frame, GrantHandle, GrantRef};
use crate::p2m::{self, Mfn, PageType};
use crate::sched::{self, Pcpu};
use crate::{HError, HvCore};

/// A domain identifier, shared across all subsystems.
pub type DomId = u16;

/// The core's typed, ABI-neutral hypercall vocabulary. A personality decodes a
/// guest's wire-format call into one of these; the core never sees raw registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvCall {
    /// Deposit credits into the caller's account.
    CreditGrant { amount: u32 },
    /// Withdraw credits from the caller's account.
    CreditSpend { amount: u32 },

    /// Allocate a half-open event-channel port awaiting `remote`.
    EvtchnAllocUnbound { remote: DomId },
    /// Bind an event-channel port to `remote`'s waiting `remote_port`.
    EvtchnBindInterdomain { remote: DomId, remote_port: Port },
    /// Bind an event-channel port to a per-vCPU virtual IRQ.
    EvtchnBindVirq { vcpu: Vcpu, virq: Virq },
    /// Bind an event-channel port to a vCPU for IPIs.
    EvtchnBindIpi { vcpu: Vcpu },
    /// Close one of the caller's event-channel ports.
    EvtchnClose { port: Port },
    /// Signal an event-channel port.
    EvtchnSend { port: Port },
    /// Mask an event-channel port.
    EvtchnMask { port: Port },
    /// Unmask an event-channel port.
    EvtchnUnmask { port: Port },
    /// Consume (acknowledge) an event-channel port's pending bit.
    EvtchnConsume { port: Port },

    /// Offer `frame` to `grantee` at the caller's grant slot `gref`.
    GrantAccess {
        gref: GrantRef,
        grantee: DomId,
        frame: Frame,
        readonly: bool,
    },
    /// Revoke one of the caller's grants.
    GrantEndAccess { gref: GrantRef },
    /// Map a grant that `grantor` offered to the caller.
    GrantMap {
        grantor: DomId,
        gref: GrantRef,
        writable: bool,
    },
    /// Unmap one of the caller's mappings.
    GrantUnmap { handle: GrantHandle },
    /// Transient grant-checked copy access (no reference taken).
    GrantCopy {
        grantor: DomId,
        gref: GrantRef,
        write: bool,
    },

    /// Bring one of the caller's vCPUs online (`Offline` → `Runnable`).
    SchedAdmit { vcpu: Vcpu },
    /// Dispatch one of the caller's runnable vCPUs onto physical CPU `pcpu`, starting
    /// its on-CPU interval at `now`. `now` is a plain operation input: the core owns
    /// no clock, so whoever builds the call reads [`hv_hal::TimeSource`] and stamps it.
    SchedRun { vcpu: Vcpu, pcpu: Pcpu, now: Ticks },
    /// Preempt one of the caller's running vCPUs back to `Runnable`, closing its
    /// on-CPU interval at `now`.
    SchedPreempt { vcpu: Vcpu, now: Ticks },
    /// Block one of the caller's vCPUs on an event, closing any on-CPU interval at
    /// `now`.
    SchedBlock { vcpu: Vcpu, now: Ticks },
    /// Wake one of the caller's blocked vCPUs (`Blocked` → `Runnable`).
    SchedWake { vcpu: Vcpu },
    /// Take one of the caller's vCPUs offline, closing any on-CPU interval at `now`.
    SchedOffline { vcpu: Vcpu, now: Ticks },

    /// Allocate a free machine frame to the caller.
    ///
    /// Allocate and free are the *only* guest-facing page operations. The reference
    /// and type counts a frame carries are moved solely by higher-level operations
    /// (grant maps, later page-table pins) whose release is gated on proof of the
    /// acquire — never by a raw guest hypercall, which could drop a reference another
    /// domain holds. See [`crate::p2m`] for why that keeps the scalar count sound.
    P2mAllocate { mfn: Mfn },
    /// Free one of the caller's machine frames back to the pool (refused while anything
    /// still references it).
    P2mFree { mfn: Mfn },
    /// Pin one of the caller's frames as a page table — a persistent page-table type
    /// reference held until unpinned. Refused if the frame is referenced writable. This
    /// and unpin are balanced by the pin bit (unpin proves the pin), so they are sound
    /// as guest calls where the raw type primitives are not.
    P2mPin { mfn: Mfn },
    /// Unpin one of the caller's page-table frames, dropping the pin's reference.
    P2mUnpin { mfn: Mfn },
}

/// The success value of a routed hypercall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvOutcome {
    /// Completed with no interesting value.
    Done,
    /// A credit balance (credit ops).
    Balance(u64),
    /// A freshly allocated event-channel port.
    Port(Port),
    /// A grant map handle.
    Handle(GrantHandle),
    /// Whether a consumed port had been pending.
    Pending(bool),
}

/// A routed hypercall's failure, tagged by the subsystem that rejected it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvError {
    /// The caller domain id is out of range.
    BadDomain,
    /// The credit subsystem rejected the call.
    Credit(HError),
    /// The event-channel subsystem rejected the call.
    Evtchn(evtchn::EvtchnError),
    /// The grant subsystem rejected the call.
    Grant(grant::GrantError),
    /// The scheduler subsystem rejected the call.
    Sched(sched::SchedError),
    /// The page-type subsystem rejected the call.
    P2m(p2m::P2mError),
    /// A grant map named a frame the grantor no longer owns — a stale grant, left
    /// pointing at a frame that was freed and reallocated after the grant was written.
    /// Refused at the seam so it can never reference another domain's page. Not a
    /// single subsystem's error: it is the grant↔page-type join that catches it.
    StaleGrant,
}

/// A breach of a *cross-subsystem* invariant — one that relates grant tables to the
/// page-type counts and so belongs to neither subsystem alone. This is the seam's own
/// safety net: it catches a grant mapping that the page-type accounting is not backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossViolation {
    /// A grant with live mappings whose frame is not backed by matching page
    /// references — freed, or holding too few existence or writable references for the
    /// mappings that stand over it. The cross-domain use-after-free / type-confusion
    /// shape the seam exists to prevent.
    UnbackedGrantMap { grantor: DomId, gref: GrantRef },
    /// A grant with live mappings whose frame is no longer owned by the grantor — the
    /// confused-deputy shape (a stale grant that slipped past the map-time owner check).
    MisownedGrantMap { grantor: DomId, gref: GrantRef },
}

/// The integrated hypervisor core: per-domain credit plus the whole-system subsystems,
/// behind one dispatch entry point.
pub struct Hypervisor {
    credit: Vec<HvCore>,
    evtchn: evtchn::System,
    grant: grant::System,
    sched: sched::System,
    p2m: p2m::System,
}

impl Hypervisor {
    /// A hypervisor of `num_domains` domains, each with `ports_per_domain`
    /// event-channel ports, `grants_per_domain` grant slots, and `vcpus_per_domain`
    /// virtual CPUs, scheduled over `num_pcpus` shared physical CPUs, with `num_frames`
    /// machine frames in the shared page pool. Every subsystem shares the same domain
    /// count; the physical CPUs and machine frames are system-wide.
    pub fn new(
        num_domains: usize,
        ports_per_domain: usize,
        grants_per_domain: usize,
        vcpus_per_domain: usize,
        num_pcpus: usize,
        num_frames: usize,
    ) -> Self {
        Hypervisor {
            credit: (0..num_domains).map(|_| HvCore::new()).collect(),
            evtchn: evtchn::System::new(num_domains, ports_per_domain),
            grant: grant::System::new(num_domains, grants_per_domain),
            sched: sched::System::new(num_domains, vcpus_per_domain, num_pcpus),
            p2m: p2m::System::new(num_domains, num_frames),
        }
    }

    /// Route one hypercall from `caller` to the owning subsystem, with `caller` as
    /// the acting domain throughout. Errors are the subsystem's own, tagged.
    ///
    /// Each subsystem re-establishes its own invariant inside every transition; this
    /// wrapper adds the one check no single subsystem can make — that the grant↔page-type
    /// seam is still consistent after the call. Like the rest, it is a `debug_assert!`,
    /// so it costs nothing on the metal yet fires on every simulated interleaving.
    pub fn dispatch(&mut self, caller: DomId, call: HvCall) -> Result<HvOutcome, HvError> {
        let outcome = self.route(caller, call);
        debug_assert!(
            self.first_cross_violation().is_none(),
            "grant↔page-type cross-invariant violated after dispatch: {:?}",
            self.first_cross_violation()
        );
        outcome
    }

    fn route(&mut self, caller: DomId, call: HvCall) -> Result<HvOutcome, HvError> {
        match call {
            HvCall::CreditGrant { amount } => self
                .credit_of(caller)?
                .grant_credit(amount)
                .map(HvOutcome::Balance)
                .map_err(HvError::Credit),
            HvCall::CreditSpend { amount } => self
                .credit_of(caller)?
                .spend_credit(amount)
                .map(HvOutcome::Balance)
                .map_err(HvError::Credit),

            HvCall::EvtchnAllocUnbound { remote } => self
                .evtchn
                .alloc_unbound(caller, remote)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindInterdomain {
                remote,
                remote_port,
            } => self
                .evtchn
                .bind_interdomain(caller, remote, remote_port)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindVirq { vcpu, virq } => self
                .evtchn
                .bind_virq(caller, vcpu, virq)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindIpi { vcpu } => self
                .evtchn
                .bind_ipi(caller, vcpu)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnClose { port } => self
                .evtchn
                .close(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnSend { port } => self
                .evtchn
                .send(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnMask { port } => self
                .evtchn
                .mask(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnUnmask { port } => self
                .evtchn
                .unmask(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnConsume { port } => self
                .evtchn
                .consume(caller, port)
                .map(HvOutcome::Pending)
                .map_err(HvError::Evtchn),

            HvCall::GrantAccess {
                gref,
                grantee,
                frame,
                readonly,
            } => self
                .grant
                .grant_access(caller, gref, grantee, frame, readonly)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
            HvCall::GrantEndAccess { gref } => self
                .grant
                .end_access(caller, gref)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
            HvCall::GrantMap {
                grantor,
                gref,
                writable,
            } => self.grant_map(caller, grantor, gref, writable),
            HvCall::GrantUnmap { handle } => self.grant_unmap(caller, handle),
            HvCall::GrantCopy {
                grantor,
                gref,
                write,
            } => self
                .grant
                .copy(caller, grantor, gref, write)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),

            HvCall::SchedAdmit { vcpu } => self
                .sched
                .admit(caller, vcpu)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
            HvCall::SchedRun { vcpu, pcpu, now } => self
                .sched
                .run(caller, vcpu, pcpu, now)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
            HvCall::SchedPreempt { vcpu, now } => self
                .sched
                .preempt(caller, vcpu, now)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
            HvCall::SchedBlock { vcpu, now } => self
                .sched
                .block(caller, vcpu, now)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
            HvCall::SchedWake { vcpu } => self
                .sched
                .wake(caller, vcpu)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
            HvCall::SchedOffline { vcpu, now } => self
                .sched
                .offline(caller, vcpu, now)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),

            HvCall::P2mAllocate { mfn } => self
                .p2m
                .allocate(caller, mfn)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
            HvCall::P2mFree { mfn } => self
                .p2m
                .free(caller, mfn)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
            HvCall::P2mPin { mfn } => self
                .p2m
                .pin(caller, mfn)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
            HvCall::P2mUnpin { mfn } => self
                .p2m
                .unpin(caller, mfn)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
        }
    }

    /// Map a grant, taking the backing page reference the mapping needs — the grant
    /// side of the seam. A *writable* map pins the frame's writable **type** (so it can
    /// never simultaneously be a page table); a *read-only* map takes only an existence
    /// reference (a reader is type-agnostic, but the page still must not be freed under
    /// it). Both are released again by [`Self::grant_unmap`].
    fn grant_map(
        &mut self,
        caller: DomId,
        grantor: DomId,
        gref: GrantRef,
        writable: bool,
    ) -> Result<HvOutcome, HvError> {
        // The frame this grant offers — `None` is the same rejection grant.map gives
        // for an inactive grant, so surface it identically.
        let frame = self
            .grant
            .granted_frame(grantor, gref)
            .ok_or(HvError::Grant(grant::GrantError::WrongState))?;
        // The grant must still name a frame its grantor owns. A stale grant — the frame
        // freed and reallocated to someone else after the grant was written — is
        // refused here, before anything is touched, so a map can never take a reference
        // on a third party's page under the grantor's name (a confused deputy).
        if self.p2m.owner_of(frame) != Some(grantor) {
            return Err(HvError::StaleGrant);
        }
        // Record the mapping first: grant.map validates grantee identity and the
        // read-only/writable permission, so its (precise) error is never shadowed by a
        // page-type one. Then take the backing reference; on the rare p2m rejection
        // (a writable map of a page-table frame) roll the grant map back — unmapping
        // the handle we just made always succeeds — so a rejected call mutates nothing.
        let handle = self
            .grant
            .map(caller, grantor, gref, writable)
            .map_err(HvError::Grant)?;
        let acquire = if writable {
            self.p2m.get_type(frame, PageType::Writable)
        } else {
            self.p2m.get(frame)
        };
        match acquire {
            Ok(()) => Ok(HvOutcome::Handle(handle)),
            Err(e) => {
                let _ = self.grant.unmap(caller, handle);
                Err(HvError::P2m(e))
            }
        }
    }

    /// Unmap a grant, releasing the backing page reference — the reverse of
    /// [`Self::grant_map`]. Grant tables record which frame and whether it was writable,
    /// so the mirror into the page-type counts is exact. The release is always valid:
    /// the map took this reference and only this unmap gives it back.
    fn grant_unmap(&mut self, caller: DomId, handle: GrantHandle) -> Result<HvOutcome, HvError> {
        let unmapped = self.grant.unmap(caller, handle).map_err(HvError::Grant)?;
        let released = if unmapped.writable {
            self.p2m.put_type(unmapped.frame, PageType::Writable)
        } else {
            self.p2m.put(unmapped.frame)
        };
        debug_assert!(
            released.is_ok(),
            "grant unmap could not release its page reference: {released:?}"
        );
        Ok(HvOutcome::Done)
    }

    /// The first grant↔page-type cross-invariant breach, or `None` if the seam is
    /// consistent. For every grant with live mappings, the frame it offers must be
    /// owned by the grantor and carry at least as many existence references as it has
    /// mappings, and at least as many writable-type references as it has writable
    /// mappings — so no mapping outlives, or out-types, its backing.
    pub fn first_cross_violation(&self) -> Option<CrossViolation> {
        for grantor in 0..self.grant.domain_count() as DomId {
            for gref in 0..self.grant.entry_count(grantor) as GrantRef {
                let maps = match self.grant.map_count(grantor, gref) {
                    Some(m) if m > 0 => m,
                    _ => continue, // inactive grant, or no live mappings — nothing to back
                };
                // Active with live maps ⟹ `granted_frame` is `Some`.
                let frame = self.grant.granted_frame(grantor, gref).unwrap();
                if self.p2m.owner_of(frame) != Some(grantor) {
                    return Some(CrossViolation::MisownedGrantMap { grantor, gref });
                }
                let writable_maps = self.grant.writable_map_count(grantor, gref).unwrap_or(0);
                let refs = self.p2m.refs(frame).unwrap_or(0);
                let writable_refs = self.p2m.type_refs(frame, PageType::Writable).unwrap_or(0);
                if refs < maps || writable_refs < writable_maps {
                    return Some(CrossViolation::UnbackedGrantMap { grantor, gref });
                }
            }
        }
        None
    }

    /// Whether every subsystem's invariants hold *and* the grant↔page-type seam is
    /// consistent — the one check that covers the integrated core. Evaluated in release
    /// too.
    pub fn invariants_hold(&self) -> bool {
        self.evtchn.invariants_hold()
            && self.grant.invariants_hold()
            && self.sched.invariants_hold()
            && self.p2m.invariants_hold()
            && self.credit.iter().all(HvCore::invariants_hold)
            && self.first_cross_violation().is_none()
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.credit.len()
    }

    /// A domain's credit balance, if it exists.
    pub fn balance(&self, dom: DomId) -> Option<u64> {
        self.credit.get(dom as usize).map(HvCore::balance)
    }

    /// The event-channel subsystem, for inspection.
    pub fn evtchn(&self) -> &evtchn::System {
        &self.evtchn
    }

    /// The grant subsystem, for inspection.
    pub fn grant(&self) -> &grant::System {
        &self.grant
    }

    /// The scheduler subsystem, for inspection.
    pub fn sched(&self) -> &sched::System {
        &self.sched
    }

    /// The page-type subsystem, for inspection.
    pub fn p2m(&self) -> &p2m::System {
        &self.p2m
    }

    fn credit_of(&mut self, dom: DomId) -> Result<&mut HvCore, HvError> {
        self.credit.get_mut(dom as usize).ok_or(HvError::BadDomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv() -> Hypervisor {
        Hypervisor::new(3, 8, 6, 2, 2, 8)
    }

    #[test]
    fn credit_routes_to_the_callers_account() {
        let mut h = hv();
        assert_eq!(
            h.dispatch(1, HvCall::CreditGrant { amount: 100 }),
            Ok(HvOutcome::Balance(100))
        );
        // The deposit landed on domain 1, not domain 0.
        assert_eq!(h.balance(0), Some(0));
        assert_eq!(h.balance(1), Some(100));
        assert_eq!(
            h.dispatch(1, HvCall::CreditSpend { amount: 40 }),
            Ok(HvOutcome::Balance(60))
        );
    }

    #[test]
    fn a_full_interdomain_handshake_through_dispatch() {
        let mut h = hv();
        // Domain 1 opens a port for domain 0; domain 0 binds it; domain 0 signals.
        let unbound = match h.dispatch(1, HvCall::EvtchnAllocUnbound { remote: 0 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        let local = match h.dispatch(
            0,
            HvCall::EvtchnBindInterdomain {
                remote: 1,
                remote_port: unbound,
            },
        ) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        h.dispatch(0, HvCall::EvtchnSend { port: local }).unwrap();
        // The peer (domain 1's port) is now pending.
        assert!(h.evtchn().is_pending(1, unbound));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_full_grant_map_unmap_through_dispatch() {
        let mut h = hv();
        // Domain 0 must own the frame it grants, so allocate it first.
        h.dispatch(0, HvCall::P2mAllocate { mfn: 2 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 2,
                grantee: 1,
                frame: 2,
                readonly: false,
            },
        )
        .unwrap();
        let handle = match h.dispatch(
            1,
            HvCall::GrantMap {
                grantor: 0,
                gref: 2,
                writable: true,
            },
        ) {
            Ok(HvOutcome::Handle(x)) => x,
            other => panic!("expected a handle, got {other:?}"),
        };
        // Grantor cannot revoke while domain 1 holds the mapping.
        assert_eq!(
            h.dispatch(0, HvCall::GrantEndAccess { gref: 2 }),
            Err(HvError::Grant(grant::GrantError::InUse))
        );
        h.dispatch(1, HvCall::GrantUnmap { handle }).unwrap();
        assert!(h.dispatch(0, HvCall::GrantEndAccess { gref: 2 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_writable_grant_map_pins_the_frame_type_and_blocks_free() {
        let mut h = hv();
        // Domain 0 owns frame 2 and grants it writable to domain 1, which maps it.
        h.dispatch(0, HvCall::P2mAllocate { mfn: 2 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 1,
                frame: 2,
                readonly: false,
            },
        )
        .unwrap();
        let handle = match h.dispatch(
            1,
            HvCall::GrantMap {
                grantor: 0,
                gref: 0,
                writable: true,
            },
        ) {
            Ok(HvOutcome::Handle(x)) => x,
            other => panic!("expected a handle, got {other:?}"),
        };
        // The writable map pinned the frame's *type* — it is now writable in p2m.
        assert_eq!(h.p2m().current_type(2), Some(PageType::Writable));
        assert!(h.p2m().refs(2).unwrap() >= 1);
        // The owner cannot free the frame out from under the foreign mapping — the
        // cross-domain use-after-free the seam closes. (p2m alone enforces this now.)
        assert_eq!(
            h.dispatch(0, HvCall::P2mFree { mfn: 2 }),
            Err(HvError::P2m(p2m::P2mError::InUse))
        );
        assert!(h.invariants_hold());
        // Unmapping releases the type and existence reference; then the owner can free.
        h.dispatch(1, HvCall::GrantUnmap { handle }).unwrap();
        assert_eq!(h.p2m().current_type(2), None);
        assert_eq!(h.p2m().refs(2), Some(0));
        assert!(h.dispatch(0, HvCall::P2mFree { mfn: 2 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_readonly_grant_map_pins_existence_but_not_type() {
        let mut h = hv();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 1,
                grantee: 2,
                frame: 3,
                readonly: true,
            },
        )
        .unwrap();
        let handle = match h.dispatch(
            2,
            HvCall::GrantMap {
                grantor: 0,
                gref: 1,
                writable: false,
            },
        ) {
            Ok(HvOutcome::Handle(x)) => x,
            other => panic!("expected a handle, got {other:?}"),
        };
        // A read-only map pins existence (can't be freed) but imposes no type — a
        // reader is type-agnostic, so the frame stays untyped.
        assert_eq!(h.p2m().current_type(3), None);
        assert_eq!(h.p2m().refs(3), Some(1));
        assert_eq!(
            h.dispatch(0, HvCall::P2mFree { mfn: 3 }),
            Err(HvError::P2m(p2m::P2mError::InUse))
        );
        h.dispatch(2, HvCall::GrantUnmap { handle }).unwrap();
        assert_eq!(h.p2m().refs(3), Some(0));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_stale_grant_cannot_be_mapped() {
        let mut h = hv();
        // Domain 0 allocates frame 4, grants it, then frees it (allowed — no live map).
        h.dispatch(0, HvCall::P2mAllocate { mfn: 4 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 1,
                frame: 4,
                readonly: false,
            },
        )
        .unwrap();
        h.dispatch(0, HvCall::P2mFree { mfn: 4 }).unwrap();
        // Domain 2 now owns frame 4. Domain 0's grant is stale — pointing at a frame it
        // no longer owns. The map is refused before it can reference domain 2's page.
        h.dispatch(2, HvCall::P2mAllocate { mfn: 4 }).unwrap();
        assert_eq!(
            h.dispatch(
                1,
                HvCall::GrantMap {
                    grantor: 0,
                    gref: 0,
                    writable: false
                }
            ),
            Err(HvError::StaleGrant)
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn pinning_a_frame_blocks_a_foreign_writable_grant_map() {
        let mut h = hv();
        // Domain 0 owns frame 2 and pins it as a page table.
        h.dispatch(0, HvCall::P2mAllocate { mfn: 2 }).unwrap();
        h.dispatch(0, HvCall::P2mPin { mfn: 2 }).unwrap();
        assert_eq!(h.p2m().current_type(2), Some(PageType::PageTable));
        // It grants that frame read-write to domain 1.
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 1,
                frame: 2,
                readonly: false,
            },
        )
        .unwrap();
        // A writable map is refused: the frame is a live page table. This exercises the
        // seam's rollback — grant.map committed, p2m.get_type(Writable) hit TypePinned,
        // and the grant map was undone, so nothing is left half-done.
        assert_eq!(
            h.dispatch(
                1,
                HvCall::GrantMap {
                    grantor: 0,
                    gref: 0,
                    writable: true
                }
            ),
            Err(HvError::P2m(p2m::P2mError::TypePinned))
        );
        assert_eq!(h.grant().map_count(0, 0), Some(0)); // rolled back — no live map
        assert!(h.invariants_hold());
        // A read-only map of the same page table is fine — a reader is type-agnostic.
        assert!(matches!(
            h.dispatch(
                1,
                HvCall::GrantMap {
                    grantor: 0,
                    gref: 0,
                    writable: false
                }
            ),
            Ok(HvOutcome::Handle(_))
        ));
        assert_eq!(h.p2m().current_type(2), Some(PageType::PageTable));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_writably_mapped_frame_cannot_be_pinned() {
        let mut h = hv();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 1,
                grantee: 1,
                frame: 3,
                readonly: false,
            },
        )
        .unwrap();
        match h.dispatch(
            1,
            HvCall::GrantMap {
                grantor: 0,
                gref: 1,
                writable: true,
            },
        ) {
            Ok(HvOutcome::Handle(_)) => {}
            other => panic!("expected a handle, got {other:?}"),
        }
        assert_eq!(h.p2m().current_type(3), Some(PageType::Writable));
        // The owner cannot pin a page someone is writing.
        assert_eq!(
            h.dispatch(0, HvCall::P2mPin { mfn: 3 }),
            Err(HvError::P2m(p2m::P2mError::TypePinned))
        );
        assert!(!h.p2m().is_pinned(3));
        assert!(h.invariants_hold());
    }

    #[test]
    fn pin_and_unpin_through_dispatch() {
        let mut h = hv();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 4 }).unwrap();
        // Only the owner may pin.
        assert_eq!(
            h.dispatch(1, HvCall::P2mPin { mfn: 4 }),
            Err(HvError::P2m(p2m::P2mError::NotYours))
        );
        h.dispatch(0, HvCall::P2mPin { mfn: 4 }).unwrap();
        assert!(h.p2m().is_pinned(4));
        // A pinned frame cannot be freed until unpinned.
        assert_eq!(
            h.dispatch(0, HvCall::P2mFree { mfn: 4 }),
            Err(HvError::P2m(p2m::P2mError::InUse))
        );
        h.dispatch(0, HvCall::P2mUnpin { mfn: 4 }).unwrap();
        assert!(!h.p2m().is_pinned(4));
        assert!(h.dispatch(0, HvCall::P2mFree { mfn: 4 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_vcpu_runs_and_deschedules_through_dispatch() {
        let mut h = hv();
        // Domain 2 admits vCPU 0, runs it on pCPU 1, then preempts it back.
        h.dispatch(2, HvCall::SchedAdmit { vcpu: 0 }).unwrap();
        h.dispatch(
            2,
            HvCall::SchedRun {
                vcpu: 0,
                pcpu: 1,
                now: 100,
            },
        )
        .unwrap();
        assert_eq!(h.sched().occupant(1), Some((2, 0)));
        // Another domain cannot take that physical CPU while it is occupied.
        h.dispatch(0, HvCall::SchedAdmit { vcpu: 0 }).unwrap();
        assert_eq!(
            h.dispatch(
                0,
                HvCall::SchedRun {
                    vcpu: 0,
                    pcpu: 1,
                    now: 100
                }
            ),
            Err(HvError::Sched(sched::SchedError::PcpuBusy))
        );
        h.dispatch(2, HvCall::SchedPreempt { vcpu: 0, now: 130 })
            .unwrap();
        assert_eq!(h.sched().occupant(1), None);
        assert_eq!(h.sched().runtime(2, 0), Some(30));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_frame_allocates_and_frees_through_dispatch() {
        let mut h = hv();
        // Domain 1 allocates frame 3 — ownership only, no outstanding references.
        h.dispatch(1, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        assert_eq!(h.p2m().owner_of(3), Some(1));
        // A different domain cannot free frame 3 — it is not the owner.
        assert_eq!(
            h.dispatch(0, HvCall::P2mFree { mfn: 3 }),
            Err(HvError::P2m(p2m::P2mError::NotYours))
        );
        // The owner frees it. (References are taken only by the grant seam, so a bare
        // allocation is freeable straight away.)
        assert!(h.dispatch(1, HvCall::P2mFree { mfn: 3 }).is_ok());
        assert!(!h.p2m().is_allocated(3));
        assert!(h.invariants_hold());
    }

    #[test]
    fn errors_are_tagged_by_subsystem() {
        let mut h = hv();
        assert_eq!(
            h.dispatch(9, HvCall::CreditGrant { amount: 1 }),
            Err(HvError::BadDomain)
        );
        assert_eq!(
            h.dispatch(0, HvCall::EvtchnSend { port: 0 }),
            Err(HvError::Evtchn(evtchn::EvtchnError::WrongState))
        );
        assert_eq!(
            h.dispatch(
                0,
                HvCall::GrantMap {
                    grantor: 1,
                    gref: 0,
                    writable: false
                }
            ),
            Err(HvError::Grant(grant::GrantError::WrongState))
        );
        // Running a vCPU that was never admitted is a scheduler WrongState.
        assert_eq!(
            h.dispatch(
                0,
                HvCall::SchedRun {
                    vcpu: 0,
                    pcpu: 0,
                    now: 0
                }
            ),
            Err(HvError::Sched(sched::SchedError::WrongState))
        );
        // Freeing an unallocated frame is a page-type WrongState.
        assert_eq!(
            h.dispatch(0, HvCall::P2mFree { mfn: 0 }),
            Err(HvError::P2m(p2m::P2mError::WrongState))
        );
    }
}
