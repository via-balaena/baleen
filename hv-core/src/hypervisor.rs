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
use crate::p2m::{self, Mfn, PageType, PtLevel};
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
    /// Pin one of the caller's frames as a page table at `level` — a persistent
    /// page-table type reference held until unpinned. Refused if the frame is referenced
    /// writable, or already a page table at another level. This and unpin are balanced by
    /// the pin bit (unpin proves the pin), so they are sound as guest calls where the raw
    /// type primitives are not.
    P2mPin { mfn: Mfn, level: PtLevel },
    /// Unpin one of the caller's page-table frames, dropping the pin's reference.
    P2mUnpin { mfn: Mfn },
    /// Install a page-table entry: link `parent`'s `slot` to `child`, one paging level
    /// down. Refused unless `child` is (or can become) exactly the level below `parent`
    /// — the hierarchy guard. Both frames must be the caller's.
    P2mLink { parent: Mfn, slot: u32, child: Mfn },
    /// Remove the caller's page-table entry at `parent`'s `slot`, dropping the references
    /// the link held.
    P2mUnlink { parent: Mfn, slot: u32 },

    /// Tear down domain `target` completely: close its every event-channel port,
    /// offline its every vCPU (closing on-CPU intervals at `now`), unmap its every
    /// grant map, revoke its every grant, unpin and free its every frame — leaving an
    /// empty but still-existent domain shell. Atomic and all-or-nothing: refused with
    /// [`HvError::DomainBusy`], mutating nothing, if any *foreign* domain still holds a
    /// live grant map of one of `target`'s frames (that map holds a page reference
    /// teardown cannot revoke without yanking it out from under the mapper). `now` is a
    /// plain operation input, as for the scheduler ops: the core owns no clock, so
    /// whoever builds the call stamps it. Privilege is deferred — any caller may issue
    /// it for now.
    DomainDestroy { target: DomId, now: Ticks },
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
    /// A [`HvCall::DomainDestroy`] was refused because the target is still busy: a
    /// *foreign* domain holds a live grant map of one of the target's frames. Teardown
    /// is all-or-nothing and never force-unmaps a live mapping, so it refuses rather
    /// than tear a page out from under another domain — and mutates nothing. Whole-domain,
    /// spanning grant tables and page-type accounting, so it belongs to the seam, not one
    /// subsystem.
    DomainBusy,
    /// A page-table entry into a frame another domain owns was refused: the caller holds
    /// no read-write grant of that frame from its owner (or tried to share a page-table
    /// node rather than map a leaf). Cross-domain page-table sharing needs the owner's
    /// consent, which a grant expresses — the isolation guard on the page-table↔grant
    /// join, so it belongs to the seam.
    Unauthorized,
}

/// A breach of a *cross-subsystem* invariant — one that relates two subsystems and so
/// belongs to neither alone. This is the seams' own safety net, spanning both joins the
/// `Hypervisor` owns: grant tables ↔ page-type accounting, and event channels ↔ the
/// scheduler.
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
    /// A vCPU left `Blocked` while a *deliverable* (pending, unmasked) event
    /// notify-targets it — the lost-wakeup shape the event→scheduler seam exists to
    /// prevent. No future signal edge will wake a vCPU that is already asleep with the
    /// pending bit set, so the event would never be observed.
    LostWakeup { dom: DomId, vcpu: Vcpu },
    /// A cross-domain page-table entry — a table maps a frame *another* domain owns —
    /// stands with no read-write grant from that owner to the mapping domain authorizing
    /// it. The isolation breach the page-table↔grant join exists to prevent: a domain
    /// reaching into another's memory through its page tables without consent (or holding
    /// the mapping after the grant was revoked).
    UnauthorizedForeignLink { parent: Mfn, child: Mfn },
}

/// The integrated hypervisor core: per-domain credit plus the whole-system subsystems,
/// behind one dispatch entry point.
#[derive(Clone)]
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
    /// wrapper adds the checks no single subsystem can make — that both cross-subsystem
    /// seams are still consistent after the call (grant↔page-type, and event↔scheduler).
    /// Like the rest, it is a `debug_assert!`, so it costs nothing on the metal yet fires
    /// on every simulated interleaving.
    pub fn dispatch(&mut self, caller: DomId, call: HvCall) -> Result<HvOutcome, HvError> {
        let outcome = self.route(caller, call);
        debug_assert!(
            self.first_cross_violation().is_none(),
            "cross-subsystem invariant violated after dispatch: {:?}",
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
            HvCall::EvtchnBindVirq { vcpu, virq } => {
                self.check_bind_vcpu(caller, vcpu)?;
                self.evtchn
                    .bind_virq(caller, vcpu, virq)
                    .map(HvOutcome::Port)
                    .map_err(HvError::Evtchn)
            }
            HvCall::EvtchnBindIpi { vcpu } => {
                self.check_bind_vcpu(caller, vcpu)?;
                self.evtchn
                    .bind_ipi(caller, vcpu)
                    .map(HvOutcome::Port)
                    .map_err(HvError::Evtchn)
            }
            HvCall::EvtchnClose { port } => self
                .evtchn
                .close(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnSend { port } => self.evtchn_send(caller, port),
            HvCall::EvtchnMask { port } => self
                .evtchn
                .mask(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnUnmask { port } => self.evtchn_unmask(caller, port),
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
            HvCall::GrantEndAccess { gref } => self.grant_end_access(caller, gref),
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
            } => self.grant_copy(caller, grantor, gref, write),

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
            HvCall::SchedBlock { vcpu, now } => self.sched_block(caller, vcpu, now),
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
            HvCall::P2mPin { mfn, level } => self
                .p2m
                .pin(caller, mfn, level)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
            HvCall::P2mUnpin { mfn } => self
                .p2m
                .unpin(caller, mfn)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),
            HvCall::P2mLink {
                parent,
                slot,
                child,
            } => self.p2m_link(caller, parent, slot, child),
            HvCall::P2mUnlink { parent, slot } => self
                .p2m
                .unlink(caller, parent, slot)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),

            HvCall::DomainDestroy { target, now } => self.domain_destroy(target, now),
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

    /// Install a page-table entry, authorizing it if it crosses a domain boundary — the
    /// page-table↔grant half of cross-domain sharing. An entry into the caller's *own*
    /// frame is a plain [`crate::p2m::System::link`]. An entry into a frame *another
    /// domain owns* is only permitted when that owner has granted the frame to the caller
    /// read-write ([`grant::System::authorizes`]): a domain cannot map a foreign page into
    /// its address space without the owner's consent. Foreign entries are leaves (an `L1`
    /// table maps a data page), so a foreign child must go under an `L1` — sharing whole
    /// page-table *subtrees* across domains is a later refinement. `p2m` enforces the type
    /// discipline; this seam adds the authorization it is deliberately blind to.
    fn p2m_link(
        &mut self,
        caller: DomId,
        parent: Mfn,
        slot: u32,
        child: Mfn,
    ) -> Result<HvOutcome, HvError> {
        if let Some(owner) = self.p2m.owner_of(child) {
            if owner != caller {
                // A foreign entry: it must be an authorized L1 leaf. Check the grant and
                // the level *before* touching p2m, so an unauthorized link is a no-op.
                if self.p2m.current_type(parent) != Some(PageType::PageTable(PtLevel::L1)) {
                    return Err(HvError::Unauthorized);
                }
                if !self.grant.authorizes(owner, caller, child, true) {
                    return Err(HvError::Unauthorized);
                }
            }
        }
        self.p2m
            .link(caller, parent, slot, child)
            .map(|()| HvOutcome::Done)
            .map_err(HvError::P2m)
    }

    /// A grant-checked copy (Xen's `GNTTABOP_copy`): authorizes an access to the grant's
    /// frame without taking a reference. Like [`Self::grant_map`], it refuses a *stale*
    /// grant — one whose frame the grantor no longer owns (freed and reallocated after the
    /// grant was written) — so a copy can never be authorized against a third party's page
    /// (a confused deputy). Without this the copy path would trust `grant.copy`'s
    /// grantee/readonly checks alone, which the map path deliberately does not.
    fn grant_copy(
        &self,
        caller: DomId,
        grantor: DomId,
        gref: GrantRef,
        write: bool,
    ) -> Result<HvOutcome, HvError> {
        if let Some(frame) = self.grant.granted_frame(grantor, gref) {
            if self.p2m.owner_of(frame) != Some(grantor) {
                return Err(HvError::StaleGrant);
            }
        }
        self.grant
            .copy(caller, grantor, gref, write)
            .map(|()| HvOutcome::Done)
            .map_err(HvError::Grant)
    }

    /// Reject an event-channel bind to a vCPU the caller does not have. Event channels
    /// model no vCPU table of their own, so a `bind_virq`/`bind_ipi` to an out-of-range
    /// vCPU would otherwise create a port whose notify-target can never exist (a wasted
    /// port with a permanently-stuck pending bit). The scheduler owns the vCPU space, so
    /// the seam cross-checks it here — mirroring Xen's `vcpu_id` validation at bind time.
    /// A bad *caller* is left to the subsystem to report as its own `BadDomain`.
    fn check_bind_vcpu(&self, caller: DomId, vcpu: Vcpu) -> Result<(), HvError> {
        if (caller as usize) < self.sched.domain_count()
            && (vcpu as usize) >= self.sched.vcpu_count(caller)
        {
            return Err(HvError::Sched(sched::SchedError::BadVcpu));
        }
        Ok(())
    }

    /// Revoke a grant — unless a *foreign page-table entry* still relies on it. A grant is
    /// the authorization behind a cross-domain page-table link; revoking it while the
    /// grantee still maps the frame would strand that mapping unauthorized, so the seam
    /// refuses (the grant's frame is still in use), exactly as `grant.end_access` already
    /// refuses while a live grant *map* stands. The block is keyed on *this grant's
    /// grantee*: a different domain's grant of the same frame may still be revoked freely
    /// (its grantee's mapping — if any — is authorized by its own grant, not this one). No
    /// foreign link depending, and the grant subsystem's own checks apply unchanged.
    fn grant_end_access(&mut self, caller: DomId, gref: GrantRef) -> Result<HvOutcome, HvError> {
        if let (Some(frame), Some(grantee)) = (
            self.grant.granted_frame(caller, gref),
            self.grant.grantee_of(caller, gref),
        ) {
            if self.p2m.is_foreign_linked_by(frame, grantee) {
                return Err(HvError::Grant(grant::GrantError::InUse));
            }
        }
        self.grant
            .end_access(caller, gref)
            .map(|()| HvOutcome::Done)
            .map_err(HvError::Grant)
    }

    /// Signal a port, then wake its target if the signal made it deliverable — the
    /// event→scheduler half of the seam. `evtchn::send` sets the pending bit on the
    /// port's *target* (the peer for an interdomain port, the port itself for an IPI);
    /// if that target is now deliverable, the vCPU it notify-targets must not stay
    /// `Blocked`. A *masked* target is pending but not deliverable, so its wake is
    /// deferred to the later [`Self::evtchn_unmask`].
    fn evtchn_send(&mut self, caller: DomId, port: Port) -> Result<HvOutcome, HvError> {
        self.evtchn.send(caller, port).map_err(HvError::Evtchn)?;
        // `send` leaves the source port's state untouched, so its target is unchanged;
        // resolve it now to find whose pending bit was just set, and wake if deliverable.
        if let Some((tdom, tport)) = self.evtchn.send_target(caller, port) {
            self.wake_if_deliverable(tdom, tport);
        }
        Ok(HvOutcome::Done)
    }

    /// Unmask a port, then deliver the wake it may have deferred. Unmasking an
    /// already-pending port is the *other* edge into deliverability (besides `send`):
    /// a vCPU that blocked while this port was pending-but-masked is stranded until the
    /// unmask, so the unmask must wake it.
    fn evtchn_unmask(&mut self, caller: DomId, port: Port) -> Result<HvOutcome, HvError> {
        self.evtchn.unmask(caller, port).map_err(HvError::Evtchn)?;
        self.wake_if_deliverable(caller, port);
        Ok(HvOutcome::Done)
    }

    /// Wake the vCPU that port `(dom, port)` notify-targets, if the port is deliverable
    /// now and that vCPU is `Blocked`. The scheduler half of event delivery: a signal
    /// that makes a port deliverable must not leave its target asleep. Only a `Blocked`
    /// target is a lost wakeup — `sched::wake` rejects any other state, which we ignore;
    /// *injecting* the interrupt into an already-running vCPU is the HAL's job, past the
    /// fence. The core moves the scheduler; the metal does the upcall.
    fn wake_if_deliverable(&mut self, dom: DomId, port: Port) {
        if self.evtchn.deliverable(dom, port) {
            if let Some(vcpu) = self.evtchn.notify_target(dom, port) {
                let _ = self.sched.wake(dom, vcpu);
            }
        }
    }

    /// Block a vCPU — unless it already has work waiting. The scheduler→event half of
    /// the seam: if a deliverable event already notify-targets this vCPU, blocking it
    /// would strand that event (no future signal edge wakes an already-asleep vCPU), so
    /// the block is a no-op and the vCPU keeps running. This is Xen's `SCHEDOP_block`
    /// re-check, and it is the second half of maintaining "no deliverable event rests on
    /// a `Blocked` vCPU": `evtchn_send`/`evtchn_unmask` keep it true from the event side,
    /// this keeps it true from the scheduler side. Only a `Runnable`/`Running` vCPU — one
    /// the block would otherwise accept — short-circuits; a bad id or an
    /// `Offline`/`Blocked` vCPU still gets the scheduler's own precise error.
    fn sched_block(&mut self, caller: DomId, vcpu: Vcpu, now: Ticks) -> Result<HvOutcome, HvError> {
        match self.sched.state_of(caller, vcpu) {
            Some(sched::RunState::Running { .. }) | Some(sched::RunState::Runnable)
                if self.evtchn.has_deliverable_for(caller, vcpu) =>
            {
                Ok(HvOutcome::Done)
            }
            _ => self
                .sched
                .block(caller, vcpu, now)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Sched),
        }
    }

    /// Tear a domain down across all four subsystems — the whole-system operation that
    /// welds every seam. **Atomic, all-or-nothing, refuse-if-busy.** One precondition
    /// gates everything: no *foreign* domain may hold a live grant map of one of
    /// `target`'s frames ([`grant::System::has_foreign_map`]). If one does, teardown
    /// would have to yank a page out from under the mapper, so it refuses with
    /// [`HvError::DomainBusy`] and mutates nothing. Otherwise every step below succeeds
    /// by construction — each is a bulk form of an existing invariant-safe transition —
    /// so there is nothing to roll back.
    ///
    /// The order matters, and only for making each step's precondition hold in turn:
    ///
    /// 1. **close** every port (evtchn) and **offline** every vCPU (sched) — stop the
    ///    domain talking and running; peers fall back to `Unbound`, pCPUs are freed.
    /// 2. **drain** every grant map `target` holds (grant), mirroring each released page
    ///    reference back into the page-type counts exactly as [`Self::grant_unmap`]
    ///    does — this is the one cross-subsystem step, and it clears `target`'s *own*
    ///    maps (its self-grants included) so the next step's grants are unmapped.
    /// 3. **revoke** every grant `target` offers (grant) — now all unmapped.
    /// 4. **unlink** its page-table entries, then **unpin** and **free** every frame it
    ///    owns (p2m) — every reference into them is gone (own maps drained, page-table
    ///    entries torn down, pins dropped, foreign maps excluded by the precondition), so
    ///    each free succeeds.
    ///
    /// What remains is an empty but still-existent shell: domain slots are fixed-size
    /// and never removed, so peers left `Unbound { remote: target }` stay valid.
    /// Verification rides on the existing invariant net (a mis-ordered teardown trips
    /// grant↔p2m or evtchn↔sched, caught by the `dispatch` cross-check) plus a
    /// debug-time postcondition that nothing live points into `target` any more.
    ///
    /// Provenance: the refuse-if-busy lifecycle (rather than force-unmap, or Xen's
    /// deferred dying-domain RCU teardown) is a design decision informed by the public
    /// Xen domain-destroy semantics and general OS knowledge — not `xen/`'s GPL
    /// implementation. See `CLEANROOM.md`.
    fn domain_destroy(&mut self, target: DomId, now: Ticks) -> Result<HvOutcome, HvError> {
        if target as usize >= self.domain_count() {
            return Err(HvError::BadDomain);
        }
        // The precondition. Checked before any mutation, so a refusal is a true no-op. No
        // *foreign* domain may hold one of `target`'s frames — neither a live grant map
        // nor a live cross-domain page-table entry — since teardown would then have to
        // yank a page out from under it. (`target`'s own foreign links, into *other*
        // domains' frames, are fine: `unlink_all` releases them.)
        if self.grant.has_foreign_map(target) || self.p2m.has_foreign_link_into(target) {
            return Err(HvError::DomainBusy);
        }

        // 1. Stop it talking and running.
        self.evtchn.close_all(target);
        self.sched.offline_all(target, now);

        // 2. Release every grant map it holds, mirroring each page-reference drop into
        //    the page-type accounting — the reverse of what the map acquired, exactly as
        //    grant_unmap does for a single mapping. These releases cannot fail: a live
        //    map always took the reference this now returns.
        for released in self.grant.drain_maps_of(target) {
            let mirror = if released.writable {
                self.p2m.put_type(released.frame, PageType::Writable)
            } else {
                self.p2m.put(released.frame)
            };
            debug_assert!(
                mirror.is_ok(),
                "teardown could not release a drained map's page reference: {mirror:?}"
            );
        }

        // 3. Revoke every grant it offers (all unmapped now), then 4. reclaim its frames:
        //    tear down its page-table structure (each entry pins its table, so this must
        //    precede unpin/free), drop its pins, and free every frame it owns.
        self.grant.revoke_all(target);
        self.p2m.unlink_all(target);
        self.p2m.unpin_all(target);
        self.p2m.free_all(target);

        debug_assert!(
            self.is_torn_down(target),
            "domain {target} is not an empty shell after teardown"
        );
        Ok(HvOutcome::Done)
    }

    /// Whether `target` has been reduced to an empty shell: it holds no event-channel
    /// port, no online vCPU, offers or holds no grant, and owns no frame. The teardown
    /// postcondition — "nothing live points into `target`" — checked in debug builds
    /// after [`Self::domain_destroy`], riding atop the standing invariant net which
    /// already catches the ordering bugs (a freed port with a live peer, a freed on-CPU
    /// vCPU, a foreign-mapped freed frame, a deliverable event on an offlined vCPU).
    fn is_torn_down(&self, target: DomId) -> bool {
        let no_ports = (0..self.evtchn.port_count(target) as Port)
            .all(|p| self.evtchn.state_of(target, p) == Some(evtchn::PortState::Free));
        let no_vcpus = (0..self.sched.vcpu_count(target) as Vcpu)
            .all(|v| self.sched.state_of(target, v) == Some(sched::RunState::Offline));
        let no_grants = (0..self.grant.entry_count(target) as GrantRef)
            .all(|g| !self.grant.is_granted(target, g));
        let no_maps = !self.grant.holds_any_map(target);
        let no_frames =
            (0..self.p2m.frame_count() as Mfn).all(|m| self.p2m.owner_of(m) != Some(target));
        no_ports && no_vcpus && no_grants && no_maps && no_frames
    }

    /// The first cross-subsystem invariant breach, or `None` if both seams are
    /// consistent.
    ///
    /// Grant↔page-type: for every grant with live mappings, the frame it offers must be
    /// owned by the grantor and carry at least as many existence references as it has
    /// mappings, and at least as many writable-type references as it has writable
    /// mappings — so no mapping outlives, or out-types, its backing.
    ///
    /// Event↔scheduler: no deliverable (pending, unmasked) event may rest on a `Blocked`
    /// vCPU — a signal that made a port deliverable must have woken the vCPU it
    /// notify-targets, so a still-`Blocked` target is a lost wakeup.
    ///
    /// Page-table↔grant: every cross-domain page-table entry (a table mapping a frame
    /// another domain owns) must be authorized by a read-write grant from that owner — no
    /// domain reaches into another's memory through its page tables without consent.
    /// The total live grant mappings, and writable ones, standing over `frame` — summed
    /// across every grant that names it. In a consistent state all such grants share the
    /// frame's owner (the misowned check enforces that), so this is the exact count of
    /// grant references the frame must carry.
    fn maps_over_frame(&self, frame: Frame) -> (u32, u32) {
        let mut maps = 0u32;
        let mut writable = 0u32;
        for grantor in 0..self.grant.domain_count() as DomId {
            for gref in 0..self.grant.entry_count(grantor) as GrantRef {
                if self.grant.granted_frame(grantor, gref) == Some(frame) {
                    maps = maps.saturating_add(self.grant.map_count(grantor, gref).unwrap_or(0));
                    writable = writable
                        .saturating_add(self.grant.writable_map_count(grantor, gref).unwrap_or(0));
                }
            }
        }
        (maps, writable)
    }

    pub fn first_cross_violation(&self) -> Option<CrossViolation> {
        for grantor in 0..self.grant.domain_count() as DomId {
            for gref in 0..self.grant.entry_count(grantor) as GrantRef {
                match self.grant.map_count(grantor, gref) {
                    Some(m) if m > 0 => {}
                    _ => continue, // inactive grant, or no live mappings — nothing to back
                }
                // Active with live maps ⟹ `granted_frame` is `Some`.
                let frame = self.grant.granted_frame(grantor, gref).unwrap();
                if self.p2m.owner_of(frame) != Some(grantor) {
                    return Some(CrossViolation::MisownedGrantMap { grantor, gref });
                }
                // The frame's references must back *every* mapping standing over it, not
                // just this grant's — several grants (they share this owner) may map one
                // frame, so compare against the summed totals. Page-table links and pins
                // only add references, so `refs`/`writable_refs >= the summed maps` is the
                // tightest a single-frame check can be.
                let (total_maps, total_writable) = self.maps_over_frame(frame);
                let refs = self.p2m.refs(frame).unwrap_or(0);
                let writable_refs = self.p2m.type_refs(frame, PageType::Writable).unwrap_or(0);
                if refs < total_maps || writable_refs < total_writable {
                    return Some(CrossViolation::UnbackedGrantMap { grantor, gref });
                }
            }
        }
        // Event↔scheduler: a deliverable event must never rest on a `Blocked` vCPU.
        for dom in 0..self.evtchn.domain_count() as DomId {
            for port in 0..self.evtchn.port_count(dom) as Port {
                if !self.evtchn.deliverable(dom, port) {
                    continue;
                }
                if let Some(vcpu) = self.evtchn.notify_target(dom, port) {
                    if self.sched.state_of(dom, vcpu) == Some(sched::RunState::Blocked) {
                        return Some(CrossViolation::LostWakeup { dom, vcpu });
                    }
                }
            }
        }
        // Page-table↔grant: every *cross-domain* page-table entry must be authorized by a
        // read-write grant from the child frame's owner to the domain whose table maps it.
        // An unauthorized foreign entry is a domain reaching into another's memory without
        // consent — the isolation breach this join exists to prevent.
        for (parent, _slot, child) in self.p2m.link_edges() {
            let (Some(child_owner), Some(parent_owner)) =
                (self.p2m.owner_of(child), self.p2m.owner_of(parent))
            else {
                continue;
            };
            if child_owner != parent_owner
                && !self
                    .grant
                    .authorizes(child_owner, parent_owner, child, true)
            {
                return Some(CrossViolation::UnauthorizedForeignLink { parent, child });
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
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 2,
                level: PtLevel::L1,
            },
        )
        .unwrap();
        assert_eq!(
            h.p2m().current_type(2),
            Some(PageType::PageTable(PtLevel::L1))
        );
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
        assert_eq!(
            h.p2m().current_type(2),
            Some(PageType::PageTable(PtLevel::L1))
        );
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
            h.dispatch(
                0,
                HvCall::P2mPin {
                    mfn: 3,
                    level: PtLevel::L1
                }
            ),
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
            h.dispatch(
                1,
                HvCall::P2mPin {
                    mfn: 4,
                    level: PtLevel::L4
                }
            ),
            Err(HvError::P2m(p2m::P2mError::NotYours))
        );
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 4,
                level: PtLevel::L4,
            },
        )
        .unwrap();
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

    // Bind an interdomain channel and block the receiver's vCPU, returning the
    // (receiver_dom, receiver_port, sender_dom, sender_port) needed to signal it. The
    // receiver here is domain 1, vCPU 0 (the interdomain notify-target default).
    fn blocked_interdomain_receiver(h: &mut Hypervisor) -> (u16, Port, u16, Port) {
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
        h.dispatch(1, HvCall::SchedAdmit { vcpu: 0 }).unwrap();
        h.dispatch(1, HvCall::SchedBlock { vcpu: 0, now: 10 })
            .unwrap();
        assert_eq!(h.sched().state_of(1, 0), Some(sched::RunState::Blocked));
        (1, unbound, 0, local)
    }

    #[test]
    fn a_send_wakes_a_blocked_interdomain_peer() {
        let mut h = hv();
        let (rdom, _rport, sdom, sport) = blocked_interdomain_receiver(&mut h);
        // The sender signals; the peer goes deliverable, so the blocked receiver vCPU
        // must be woken to Runnable — the lost-wakeup gap, now closed at the seam.
        h.dispatch(sdom, HvCall::EvtchnSend { port: sport })
            .unwrap();
        assert_eq!(h.sched().state_of(rdom, 0), Some(sched::RunState::Runnable));
        assert!(h.invariants_hold());
    }

    #[test]
    fn an_ipi_send_wakes_its_bound_vcpu() {
        let mut h = hv();
        // Domain 0 binds an IPI port to vCPU 1, which then blocks.
        let p = match h.dispatch(0, HvCall::EvtchnBindIpi { vcpu: 1 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        h.dispatch(0, HvCall::SchedAdmit { vcpu: 1 }).unwrap();
        h.dispatch(0, HvCall::SchedBlock { vcpu: 1, now: 5 })
            .unwrap();
        assert_eq!(h.sched().state_of(0, 1), Some(sched::RunState::Blocked));
        // The IPI targets its bound vCPU, so sending it wakes vCPU 1 specifically.
        h.dispatch(0, HvCall::EvtchnSend { port: p }).unwrap();
        assert_eq!(h.sched().state_of(0, 1), Some(sched::RunState::Runnable));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_masked_send_defers_the_wake_until_unmask() {
        let mut h = hv();
        let p = match h.dispatch(0, HvCall::EvtchnBindIpi { vcpu: 1 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        // Mask the port, then signal it: pending is set but the event is not
        // deliverable, so blocking vCPU 1 is legal and it stays asleep.
        h.dispatch(0, HvCall::EvtchnMask { port: p }).unwrap();
        h.dispatch(0, HvCall::SchedAdmit { vcpu: 1 }).unwrap();
        h.dispatch(0, HvCall::EvtchnSend { port: p }).unwrap();
        h.dispatch(0, HvCall::SchedBlock { vcpu: 1, now: 5 })
            .unwrap();
        assert_eq!(
            h.sched().state_of(0, 1),
            Some(sched::RunState::Blocked),
            "a masked (undeliverable) event must not wake, and must permit the block"
        );
        assert!(h.invariants_hold());
        // Unmasking is the deferred deliverable edge — it must now wake vCPU 1.
        h.dispatch(0, HvCall::EvtchnUnmask { port: p }).unwrap();
        assert_eq!(h.sched().state_of(0, 1), Some(sched::RunState::Runnable));
        assert!(h.invariants_hold());
    }

    #[test]
    fn blocking_with_a_deliverable_event_pending_is_a_noop() {
        let mut h = hv();
        // Domain 0's vCPU 1 has an IPI port and is running on a physical CPU.
        let p = match h.dispatch(0, HvCall::EvtchnBindIpi { vcpu: 1 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        h.dispatch(0, HvCall::SchedAdmit { vcpu: 1 }).unwrap();
        h.dispatch(
            0,
            HvCall::SchedRun {
                vcpu: 1,
                pcpu: 0,
                now: 100,
            },
        )
        .unwrap();
        // Signal it while it runs — a running vCPU is not a lost wakeup (delivery to it
        // is the HAL's job), so nothing changes but the pending bit.
        h.dispatch(0, HvCall::EvtchnSend { port: p }).unwrap();
        assert!(h.evtchn().deliverable(0, p));
        assert_eq!(
            h.sched().state_of(0, 1),
            Some(sched::RunState::Running { pcpu: 0 })
        );
        // Now it tries to block with that event already deliverable: the block is a
        // no-op (Xen's SCHEDOP_block re-check), so it keeps running rather than sleeping
        // on work it already has — the block-race half of the invariant.
        h.dispatch(0, HvCall::SchedBlock { vcpu: 1, now: 130 })
            .unwrap();
        assert_eq!(
            h.sched().state_of(0, 1),
            Some(sched::RunState::Running { pcpu: 0 }),
            "a vCPU with a deliverable event must not block onto it"
        );
        assert!(h.invariants_hold());
    }

    // Map a grant, returning the handle (panicking on any other outcome).
    fn map_handle(
        h: &mut Hypervisor,
        grantee: DomId,
        grantor: DomId,
        gref: u32,
        writable: bool,
    ) -> GrantHandle {
        match h.dispatch(
            grantee,
            HvCall::GrantMap {
                grantor,
                gref,
                writable,
            },
        ) {
            Ok(HvOutcome::Handle(x)) => x,
            other => panic!("expected a handle, got {other:?}"),
        }
    }

    #[test]
    fn domain_destroy_is_refused_while_a_foreign_map_is_live_and_mutates_nothing() {
        let mut h = hv();
        // Domain 0 owns frame 2, grants it writable to domain 1, which maps it.
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
        let handle = map_handle(&mut h, 1, 0, 0, true);

        // Destroying domain 0 must be refused: domain 1 holds a live map of its frame.
        // Any caller may issue it (privilege deferred) — here a third party, domain 2.
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 0, now: 0 }),
            Err(HvError::DomainBusy)
        );
        // A refusal mutates nothing: the frame, grant, and map all stand.
        assert_eq!(h.p2m().owner_of(2), Some(0));
        assert!(h.grant().is_granted(0, 0));
        assert_eq!(h.grant().map_count(0, 0), Some(1));
        assert_eq!(h.p2m().current_type(2), Some(PageType::Writable));
        assert!(h.invariants_hold());

        // Once domain 1 unmaps, the frame is no longer foreign-held and teardown runs.
        h.dispatch(1, HvCall::GrantUnmap { handle }).unwrap();
        assert!(h
            .dispatch(2, HvCall::DomainDestroy { target: 0, now: 0 })
            .is_ok());
        assert!(!h.p2m().is_allocated(2));
        assert!(!h.grant().is_granted(0, 0));
        assert!(h.invariants_hold());
    }

    #[test]
    fn domain_destroy_is_not_blocked_by_the_targets_own_self_map() {
        let mut h = hv();
        // Domain 0 grants its own frame to *itself* and maps it — map_count is 1, but a
        // self-map is the domain's own to release, not a foreign hold. Teardown unmaps
        // it itself, so this must NOT count as busy.
        h.dispatch(0, HvCall::P2mAllocate { mfn: 1 }).unwrap();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 0,
                frame: 1,
                readonly: false,
            },
        )
        .unwrap();
        let _self_handle = map_handle(&mut h, 0, 0, 0, true);
        assert_eq!(h.grant().map_count(0, 0), Some(1));
        assert!(
            !h.grant().has_foreign_map(0),
            "a self-map is not a foreign hold"
        );

        // So teardown is not refused — it drains its own map, revokes, and frees.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 0, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_torn_down(0));
        assert!(!h.p2m().is_allocated(1));
        assert!(h.invariants_hold());
    }

    #[test]
    fn domain_destroy_sweeps_all_four_subsystems_and_spares_others() {
        let mut h = hv();
        // Build domain 1 up across every subsystem, then tear it all down at once.

        // evtchn: an interdomain channel to domain 0, and an IPI port.
        let unbound = match h.dispatch(0, HvCall::EvtchnAllocUnbound { remote: 1 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        h.dispatch(
            1,
            HvCall::EvtchnBindInterdomain {
                remote: 0,
                remote_port: unbound,
            },
        )
        .unwrap();
        h.dispatch(1, HvCall::EvtchnBindIpi { vcpu: 1 }).unwrap();

        // sched: vCPU 0 running on a pCPU, vCPU 1 blocked.
        h.dispatch(1, HvCall::SchedAdmit { vcpu: 0 }).unwrap();
        h.dispatch(
            1,
            HvCall::SchedRun {
                vcpu: 0,
                pcpu: 0,
                now: 100,
            },
        )
        .unwrap();
        h.dispatch(1, HvCall::SchedAdmit { vcpu: 1 }).unwrap();
        h.dispatch(1, HvCall::SchedBlock { vcpu: 1, now: 100 })
            .unwrap();

        // p2m + grant: domain 1 owns frame 2 pinned as a page table; owns frame 3 which
        // it self-grants read-only and self-maps; and holds a writable map of domain 0's
        // frame 4 (a map it holds over *another* domain's frame — legal, must be drained).
        h.dispatch(1, HvCall::P2mAllocate { mfn: 2 }).unwrap();
        h.dispatch(
            1,
            HvCall::P2mPin {
                mfn: 2,
                level: PtLevel::L2,
            },
        )
        .unwrap();
        h.dispatch(1, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        h.dispatch(
            1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 1,
                frame: 3,
                readonly: true,
            },
        )
        .unwrap();
        let _self_map = map_handle(&mut h, 1, 1, 0, false);
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
        let _foreign_map = map_handle(&mut h, 1, 0, 0, true);
        // Domain 0's frame 4 now carries domain 1's writable reference.
        assert_eq!(h.p2m().current_type(4), Some(PageType::Writable));
        assert_eq!(h.sched().occupant(0), Some((1, 0)));

        // Tear domain 1 down.
        assert_eq!(
            h.dispatch(
                1,
                HvCall::DomainDestroy {
                    target: 1,
                    now: 160
                }
            ),
            Ok(HvOutcome::Done)
        );

        // Domain 1 is an empty shell across every subsystem.
        assert!(h.is_torn_down(1));
        assert_eq!(h.sched().occupant(0), None, "its pCPU is freed");
        assert!(!h.p2m().is_allocated(2), "its pinned frame is freed");
        assert!(!h.p2m().is_allocated(3), "its self-granted frame is freed");
        assert!(!h.grant().holds_any_map(1), "it holds no maps");

        // Everything else is spared. Domain 0 keeps frame 4 (its reference dropped when
        // domain 1's map was drained), its grant of it survives (unmapped now), and its
        // interdomain peer fell back to a valid, re-bindable Unbound port.
        assert_eq!(h.p2m().owner_of(4), Some(0));
        assert_eq!(h.p2m().refs(4), Some(0));
        assert!(h.grant().is_granted(0, 0));
        assert_eq!(h.grant().map_count(0, 0), Some(0));
        assert_eq!(
            h.evtchn().state_of(0, unbound),
            Some(evtchn::PortState::Unbound { remote: 1 })
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn domain_destroy_of_a_nonexistent_target_is_bad_domain() {
        let mut h = hv();
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 9, now: 0 }),
            Err(HvError::BadDomain)
        );
    }

    #[test]
    fn a_page_table_tree_builds_and_dismantles_through_dispatch() {
        let mut h = hv();
        // Domain 0 allocates five frames and builds L4→L3→L2→L1→leaf, pinning the root.
        for mfn in 0..5 {
            h.dispatch(0, HvCall::P2mAllocate { mfn }).unwrap();
        }
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 0,
                level: PtLevel::L4,
            },
        )
        .unwrap();
        for (parent, child) in [(0, 1), (1, 2), (2, 3), (3, 4)] {
            h.dispatch(
                0,
                HvCall::P2mLink {
                    parent,
                    slot: 0,
                    child,
                },
            )
            .unwrap();
        }
        assert_eq!(
            h.p2m().current_type(1),
            Some(PageType::PageTable(PtLevel::L3))
        );
        assert_eq!(h.p2m().current_type(4), Some(PageType::Writable));
        assert!(h.invariants_hold());

        // A mis-levelled link is refused at the seam: frame 4 is a writable leaf, so
        // pointing the L4 root at it (which would demand it be an L3) fails.
        assert_eq!(
            h.dispatch(
                0,
                HvCall::P2mLink {
                    parent: 0,
                    slot: 1,
                    child: 4
                }
            ),
            Err(HvError::P2m(p2m::P2mError::TypePinned))
        );
        // Unlink the leaf, and it becomes an ordinary freeable frame again.
        h.dispatch(0, HvCall::P2mUnlink { parent: 3, slot: 0 })
            .unwrap();
        assert_eq!(h.p2m().current_type(4), None);
        assert!(h.dispatch(0, HvCall::P2mFree { mfn: 4 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn destroying_a_domain_tears_down_its_page_table_tree() {
        let mut h = hv();
        // Domain 1 builds a small L2→L1→leaf tree, then is destroyed wholesale.
        for mfn in 0..3 {
            h.dispatch(1, HvCall::P2mAllocate { mfn }).unwrap();
        }
        h.dispatch(
            1,
            HvCall::P2mPin {
                mfn: 0,
                level: PtLevel::L2,
            },
        )
        .unwrap();
        h.dispatch(
            1,
            HvCall::P2mLink {
                parent: 0,
                slot: 0,
                child: 1,
            },
        )
        .unwrap();
        h.dispatch(
            1,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
            },
        )
        .unwrap();
        assert_eq!(h.p2m().active_links(), 2);

        // Teardown unlinks the whole tree, unpins, and frees every frame — no entry pins
        // a frame the free step then chokes on.
        assert_eq!(
            h.dispatch(1, HvCall::DomainDestroy { target: 1, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert_eq!(h.p2m().active_links(), 0);
        assert!(!h.p2m().is_allocated(0));
        assert!(!h.p2m().is_allocated(1));
        assert!(!h.p2m().is_allocated(2));
        assert!(h.is_torn_down(1));
        assert!(h.invariants_hold());
    }

    // Domain 1 owns frame 5 and grants it read-write to domain 0; domain 0 owns frame 0
    // and pins it as an L1 table. The stage for cross-domain page-table sharing.
    fn foreign_link_stage(h: &mut Hypervisor) {
        h.dispatch(1, HvCall::P2mAllocate { mfn: 5 }).unwrap();
        h.dispatch(
            1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 0,
                frame: 5,
                readonly: false,
            },
        )
        .unwrap();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 0,
                level: PtLevel::L1,
            },
        )
        .unwrap();
    }

    fn link5(h: &mut Hypervisor) -> Result<HvOutcome, HvError> {
        h.dispatch(
            0,
            HvCall::P2mLink {
                parent: 0,
                slot: 0,
                child: 5,
            },
        )
    }

    #[test]
    fn a_grant_authorized_foreign_leaf_maps_and_unmaps() {
        let mut h = hv();
        foreign_link_stage(&mut h);
        // Domain 0 maps domain 1's granted frame into its own L1 table.
        assert_eq!(link5(&mut h), Ok(HvOutcome::Done));
        assert_eq!(h.p2m().child_at(0, 0), Some(5));
        // The foreign frame is now writable-typed and pinned alive by the entry — its
        // owner can neither free nor re-type it while domain 0's table maps it.
        assert_eq!(h.p2m().current_type(5), Some(PageType::Writable));
        assert_eq!(
            h.dispatch(1, HvCall::P2mFree { mfn: 5 }),
            Err(HvError::P2m(p2m::P2mError::InUse))
        );
        assert!(h.invariants_hold());
        // Unlinking releases it, and domain 1 can reclaim its frame.
        h.dispatch(0, HvCall::P2mUnlink { parent: 0, slot: 0 })
            .unwrap();
        assert_eq!(h.p2m().current_type(5), None);
        assert!(h.dispatch(1, HvCall::P2mFree { mfn: 5 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn an_unauthorized_foreign_link_is_refused() {
        let mut h = hv();
        // Domain 1 owns frame 5 but grants nothing; domain 0 pins an L1 table.
        h.dispatch(1, HvCall::P2mAllocate { mfn: 5 }).unwrap();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 0,
                level: PtLevel::L1,
            },
        )
        .unwrap();
        // No grant → no authority to map domain 1's page.
        assert_eq!(link5(&mut h), Err(HvError::Unauthorized));
        assert_eq!(h.p2m().child_at(0, 0), None);
        assert_eq!(h.p2m().current_type(5), None);

        // Even *with* a grant, a foreign child may only be a leaf under an L1 — sharing a
        // page-table node is not allowed. Grant it, but make domain 0's table an L2.
        h.dispatch(
            1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 0,
                frame: 5,
                readonly: false,
            },
        )
        .unwrap();
        h.dispatch(0, HvCall::P2mAllocate { mfn: 1 }).unwrap();
        h.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 1,
                level: PtLevel::L2,
            },
        )
        .unwrap();
        assert_eq!(
            h.dispatch(
                0,
                HvCall::P2mLink {
                    parent: 1,
                    slot: 0,
                    child: 5
                }
            ),
            Err(HvError::Unauthorized)
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_grant_cannot_be_revoked_while_a_foreign_link_relies_on_it() {
        let mut h = hv();
        foreign_link_stage(&mut h);
        link5(&mut h).unwrap();
        // Domain 1 cannot revoke the grant out from under domain 0's live mapping — that
        // would strand the entry unauthorized.
        assert_eq!(
            h.dispatch(1, HvCall::GrantEndAccess { gref: 0 }),
            Err(HvError::Grant(grant::GrantError::InUse))
        );
        assert!(h.invariants_hold());
        // Once domain 0 unlinks, the grant is free to revoke.
        h.dispatch(0, HvCall::P2mUnlink { parent: 0, slot: 0 })
            .unwrap();
        assert!(h.dispatch(1, HvCall::GrantEndAccess { gref: 0 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn revoking_an_unrelated_grant_of_a_foreign_linked_frame_is_allowed() {
        let mut h = hv();
        foreign_link_stage(&mut h); // domain 1 grants frame 5 (gref 0) to domain 0
                                    // Domain 1 *also* grants the same frame to domain 2 at gref 1.
        h.dispatch(
            1,
            HvCall::GrantAccess {
                gref: 1,
                grantee: 2,
                frame: 5,
                readonly: false,
            },
        )
        .unwrap();
        // Only domain 0 maps the frame into its table.
        link5(&mut h).unwrap();

        // Domain 2's grant does not back any live entry, so revoking it is allowed even
        // though the frame is foreign-linked — the block is keyed on the grantee, not the
        // frame. (The over-conservative version wrongly refused this.)
        assert!(h.dispatch(1, HvCall::GrantEndAccess { gref: 1 }).is_ok());
        // Domain 0's grant — the one that authorizes the live entry — is still refused.
        assert_eq!(
            h.dispatch(1, HvCall::GrantEndAccess { gref: 0 }),
            Err(HvError::Grant(grant::GrantError::InUse))
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn destroying_a_domain_whose_frame_is_foreign_linked_is_refused() {
        let mut h = hv();
        foreign_link_stage(&mut h);
        link5(&mut h).unwrap();
        // Domain 1's frame is mapped into domain 0's table, so domain 1 cannot be torn
        // down — the same refuse-if-busy rule as a live foreign grant map.
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 1, now: 0 }),
            Err(HvError::DomainBusy)
        );
        // But the *linker* can be destroyed: teardown unlinks its foreign entry, freeing
        // domain 1's frame, and spares domain 1.
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 0, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_torn_down(0));
        assert_eq!(h.p2m().owner_of(5), Some(1), "domain 1 keeps its frame");
        assert_eq!(h.p2m().current_type(5), None, "no longer foreign-mapped");
        assert!(h.invariants_hold());
        // With the link gone, domain 1 can now be destroyed too.
        assert!(h
            .dispatch(2, HvCall::DomainDestroy { target: 1, now: 0 })
            .is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn one_frame_mapped_by_two_grants_stays_backed() {
        let mut h = hv();
        // Domain 0 owns frame 3 and grants it read-write to domains 1 and 2 separately.
        h.dispatch(0, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        for (gref, grantee) in [(0u32, 1u16), (1, 2)] {
            h.dispatch(
                0,
                HvCall::GrantAccess {
                    gref,
                    grantee,
                    frame: 3,
                    readonly: false,
                },
            )
            .unwrap();
        }
        // Both map it writably — the frame now carries two writable references, and the
        // seam's summed backing check must see both, not just one grant's.
        let h1 = match h.dispatch(
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
        h.dispatch(
            2,
            HvCall::GrantMap {
                grantor: 0,
                gref: 1,
                writable: true,
            },
        )
        .unwrap();
        assert_eq!(h.p2m().type_refs(3, PageType::Writable), Some(2));
        assert!(h.invariants_hold());
        // Dropping one leaves the other still backed.
        h.dispatch(1, HvCall::GrantUnmap { handle: h1 }).unwrap();
        assert_eq!(h.p2m().type_refs(3, PageType::Writable), Some(1));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_stale_grant_cannot_be_copied() {
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
        // Domain 2 now owns frame 4; domain 0's grant is stale. A copy must be refused
        // for the same reason a map is — it would authorize access to domain 2's page.
        h.dispatch(2, HvCall::P2mAllocate { mfn: 4 }).unwrap();
        assert_eq!(
            h.dispatch(
                1,
                HvCall::GrantCopy {
                    grantor: 0,
                    gref: 0,
                    write: false
                }
            ),
            Err(HvError::StaleGrant)
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn binding_an_event_channel_to_a_nonexistent_vcpu_is_refused() {
        let mut h = hv(); // 2 vCPUs per domain, so vCPU 2 does not exist
        assert_eq!(
            h.dispatch(0, HvCall::EvtchnBindIpi { vcpu: 2 }),
            Err(HvError::Sched(sched::SchedError::BadVcpu))
        );
        assert_eq!(
            h.dispatch(0, HvCall::EvtchnBindVirq { vcpu: 5, virq: 1 }),
            Err(HvError::Sched(sched::SchedError::BadVcpu))
        );
        // No port was created, and a real vCPU still binds fine.
        assert_eq!(h.evtchn().state_of(0, 0), Some(evtchn::PortState::Free));
        assert!(matches!(
            h.dispatch(0, HvCall::EvtchnBindIpi { vcpu: 1 }),
            Ok(HvOutcome::Port(_))
        ));
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
