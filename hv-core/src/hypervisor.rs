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
    /// — the hierarchy guard. `writable` is the entry's read/write bit for a *leaf* (an
    /// entry under an `L1`): a writable leaf maps its child read-write, a read-only one
    /// read-only (which may even point at a page table — the linear-map view). The caller
    /// must own `parent`; `child` may be a frame *another domain owns*, if that owner has
    /// granted it to the caller with matching permission (a read-write grant for a
    /// writable entry, any grant for a read-only one).
    P2mLink {
        parent: Mfn,
        slot: u32,
        child: Mfn,
        writable: bool,
    },
    /// Remove the caller's page-table entry at `parent`'s `slot`, dropping the references
    /// the link held.
    P2mUnlink { parent: Mfn, slot: u32 },

    /// Bring the `Dead` domain slot `target` to life as a fresh, empty `Live` domain. The
    /// caller becomes `target`'s controller (`controls[caller][target]`), and `may_create`
    /// stamps whether the new domain itself holds the creation capability. The birth half of
    /// the domain lifecycle, the mirror of [`HvCall::DomainDestroy`].
    ///
    /// **Authority:** creation requires the *creation capability* — only a caller with
    /// `may_create` may create a domain, else [`HvError::Denied`], mutating nothing. This is
    /// what gives that capability a provenance: the sole way a domain gains `may_create` is a
    /// domain that already has it creating it so (`may_create: true`), so none can
    /// self-elevate. **Control:** on success the creator gains control of the child — the
    /// root of every control edge — from which control is delegable (a later refinement).
    /// **Lifecycle:** `target` must currently be `Dead`, else
    /// [`HvError::AlreadyAlive`]. A `Dead` slot is a provably-clean shell (owns no frame,
    /// offers or holds no grant, has no bound port or online vCPU — the standing
    /// [`CrossViolation::DeadDomainNotClean`] invariant), so a freshly created domain
    /// always starts empty; creation adds no resources, only lifts the slot to `Live` and
    /// records its authority. Self-creation cannot arise — the caller is `Live` and the
    /// target `Dead`, so they are never the same domain.
    DomainCreate { target: DomId, may_create: bool },

    /// Tear down domain `target` completely: close its every event-channel port,
    /// offline its every vCPU (closing on-CPU intervals at `now`), unmap its every
    /// grant map, revoke its every grant, unpin and free its every frame — leaving an
    /// empty but still-existent domain shell. Atomic and all-or-nothing: refused with
    /// [`HvError::DomainBusy`], mutating nothing, if any *foreign* domain still holds a
    /// live grant map of one of `target`'s frames (that map holds a page reference
    /// teardown cannot revoke without yanking it out from under the mapper). `now` is a
    /// plain operation input, as for the scheduler ops: the core owns no clock, so
    /// whoever builds the call stamps it. **Authority:** a domain may tear *itself* down,
    /// but destroying a *peer* requires the caller *control* that peer
    /// (`controls[caller][target]`); otherwise [`HvError::Denied`], mutating nothing. A
    /// `Dead` domain has no controller, so a peer destroy of one is always `Denied`, never
    /// distinguishable from a live-but-uncontrolled target. **Lifecycle:** the death half of
    /// the domain lifecycle (the mirror of [`HvCall::DomainCreate`]) — the slot drops to
    /// `Dead` and loses all authority (its `may_create` and every control edge into or out
    /// of it), leaving a clean, authority-free shell that only a later `DomainCreate` can
    /// revive.
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
    /// no grant of that frame from its owner of the permission the entry needs — a
    /// read-write grant for a writable entry, any grant for a read-only one — or tried to
    /// share a page-table node rather than map a leaf. Cross-domain page-table sharing
    /// needs the owner's consent, which a grant expresses — the isolation guard on the
    /// page-table↔grant join, so it belongs to the seam.
    Unauthorized,
    /// A whole-domain *control* operation was refused for want of authority. Two axes:
    /// creating a domain ([`HvCall::DomainCreate`]) requires the global `may_create`
    /// capability; destroying **another** domain ([`HvCall::DomainDestroy`]) requires a
    /// *per-target* control capability over that specific peer (`controls[caller][target]`) —
    /// a domain may always tear *itself* down. The **authority** guard — the third axis after
    /// ownership and consent — enforced at the dispatch seam, which is where cross-domain
    /// authorization lives. Since a `Dead` domain has no controller, destroying one is always
    /// this error, never a liveness one.
    Denied,
    /// A `Dead` domain issued a hypercall — the caller-liveness gate. A `Dead` slot can do
    /// nothing (which is what keeps [`CrossViolation::DeadDomainNotClean`] a standing
    /// invariant); only [`HvCall::DomainCreate`] by a live `may_create` domain can revive it.
    /// The lifecycle guard on the *caller*, enforced at the dispatch seam. (Destroying a
    /// `Dead` *target* is not this error — a `Dead` domain has no controller, so it is
    /// [`Self::Denied`].)
    NotAlive,
    /// A [`HvCall::DomainCreate`] targeted a slot that is already `Live`. Creation is
    /// `Dead` → `Live`; an already-live domain must be torn down before its slot can be
    /// reborn. The lifecycle guard's create-side twin of [`Self::NotAlive`].
    AlreadyAlive,
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
    /// stands with no grant of matching permission from that owner to the mapping domain
    /// authorizing it (a read-write grant for a writable entry, any grant for a read-only
    /// one). The isolation breach the page-table↔grant join exists to prevent: a domain
    /// reaching into another's memory through its page tables without consent (or holding
    /// the mapping after the grant was revoked).
    UnauthorizedForeignLink { parent: Mfn, child: Mfn },
    /// A `Dead` domain that is not a clean shell — it still owns a frame, offers or holds a
    /// grant, has a non-`Free` port, or an online vCPU. A `Dead` slot must be provably
    /// empty (nothing live points into it), so this is the domain lifecycle's standing
    /// invariant: the postcondition domain teardown used to check once is now maintained
    /// forever, across every subsystem at once. Whole-domain and cross-subsystem, so it
    /// belongs to the integrated core, not any one subsystem.
    DeadDomainNotClean { dom: DomId },
    /// A `Dead` domain that still holds the `may_create` capability. It must imply `Live`:
    /// the only way a domain gains `may_create` is a `may_create` domain creating it so, and
    /// teardown strips it on death — so a `Dead` slot holding it would mean authority
    /// materialised without provenance. The state-predicate teeth of "no domain
    /// self-elevated": creation authority can only ride a `Live` domain a creator raised.
    DeadDomainMayCreate { dom: DomId },
    /// A control edge `controls[holder][target]` with a `Dead` endpoint — a `holder` that
    /// cannot act or a `target` that no longer exists. A control capability must relate two
    /// `Live` domains: it is rooted in creation and delegation (both requiring live
    /// endpoints) and teardown clears every edge touching a domain, so a `Dead` endpoint
    /// would mean a capability outlived the domain it named. The per-target authority's
    /// standing invariant, the finer cousin of [`Self::DeadDomainMayCreate`].
    ControlEdgeDeadEndpoint { holder: DomId, target: DomId },
}

/// Where a domain slot sits in its lifecycle. A slot is not a domain that always exists;
/// it is either a live domain or an empty, reusable shell awaiting creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLife {
    /// An empty, provably-clean shell — no domain lives here yet (or one was torn down).
    /// A `Dead` slot can issue no hypercall and holds no resource; only
    /// [`HvCall::DomainCreate`] can lift it to [`Self::Live`].
    Dead,
    /// A live domain: it may issue hypercalls and hold resources across every subsystem.
    /// Domain 0 boots `Live`; every other slot is born `Dead`.
    Live,
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
    /// Each domain slot's lifecycle state — the explicit `Dead`/`Live` machine that makes
    /// "doesn't exist yet" a first-class state. Domain 0 boots `Live` (the primordial
    /// control domain); every other slot starts `Dead` and only a `may_create` domain's
    /// [`HvCall::DomainCreate`] brings it to life. Every hypercall requires a `Live`
    /// caller (the gate in [`Self::route`]), which is what keeps a `Dead` slot a provably
    /// clean shell — it can never acquire a resource to hold.
    life: Vec<DomainLife>,
    /// Which domains hold the **creation** capability — may issue [`HvCall::DomainCreate`]
    /// to bring a `Dead` slot to life. Domain 0 boots with it (the primordial control
    /// domain, Xen's dom0); a creator decides whether each child inherits it. This is the
    /// global half of the **authority** axis (the third alongside *ownership* and
    /// *consent*): it gates only creation, and it has a provenance — the sole way to gain it
    /// is a domain that already has it creating you so, so no domain can self-elevate.
    /// Invariant: `may_create ⇒ Live` ([`CrossViolation::DeadDomainMayCreate`]).
    may_create: Vec<bool>,
    /// The per-target **control** relation — the *finer* half of authority. `controls[h][t]`
    /// means domain `h` may issue whole-domain control operations against domain `t`
    /// specifically ([`HvCall::DomainDestroy`], and delegating/revoking control of `t`) — a
    /// capability over one named domain, not a blanket privilege over all. It is **rooted in
    /// creation**: creating `t` gives the creator `controls[creator][t]`; from there it is
    /// delegable. Pure least-privilege — there is no implicit transitivity, so a domain
    /// controls exactly the domains it created or was delegated, and dom0 holds no blanket
    /// power over domains it did not build. A control edge requires *both* endpoints `Live`
    /// ([`CrossViolation::ControlEdgeDeadEndpoint`]); teardown clears every edge into and out
    /// of a domain, so no capability outlives its target's (or holder's) life. `controls[d][d]`
    /// is unused — a domain's authority over *itself* is inherent, not an edge.
    controls: Vec<Vec<bool>>,
}

impl Hypervisor {
    /// A hypervisor of `num_domains` domains, each with `ports_per_domain`
    /// event-channel ports, `grants_per_domain` grant slots, and `vcpus_per_domain`
    /// virtual CPUs, scheduled over `num_pcpus` shared physical CPUs, with `num_frames`
    /// machine frames in the shared page pool. Every subsystem shares the same domain
    /// count; the physical CPUs and machine frames are system-wide. **Domain 0 boots
    /// `Live` with the creation capability** (the control domain, Xen's dom0); **every other
    /// slot boots `Dead`** — an empty shell that a `may_create` domain's
    /// [`HvCall::DomainCreate`] must bring to life before it can act. No control edges exist
    /// at boot: dom0 gains `controls` over each domain only by creating it.
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
            // Domain 0 is the boot control domain: it may create. The rest cannot.
            may_create: (0..num_domains).map(|d| d == 0).collect(),
            // No control edges at boot — dom0 gains control of a domain by creating it.
            controls: (0..num_domains)
                .map(|_| alloc::vec![false; num_domains])
                .collect(),
            // Domain 0 boots Live; every other slot is a Dead shell awaiting creation.
            life: (0..num_domains)
                .map(|d| {
                    if d == 0 {
                        DomainLife::Live
                    } else {
                        DomainLife::Dead
                    }
                })
                .collect(),
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
        // The lifecycle gate, applied to *every* hypercall before it reaches a subsystem:
        // only a `Live`, in-range domain may act. An out-of-range caller is `BadDomain`
        // (unchanged); an in-range but `Dead` slot is `NotAlive`. This single central check
        // is what keeps "a `Dead` domain owns nothing" (`DeadDomainNotClean`) a standing
        // invariant — a slot that can issue no hypercall can never acquire a resource to
        // hold, so cleanliness is maintained by construction rather than re-swept. It also
        // makes target-liveness free downstream: a `Dead` domain offers no grant and owns
        // no frame, so any op naming one as grantor/remote/child already fails naturally.
        if caller as usize >= self.domain_count() {
            return Err(HvError::BadDomain);
        }
        if self.life[caller as usize] != DomainLife::Live {
            return Err(HvError::NotAlive);
        }
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
                writable,
            } => self.p2m_link(caller, parent, slot, child, writable),
            HvCall::P2mUnlink { parent, slot } => self
                .p2m
                .unlink(caller, parent, slot)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::P2m),

            HvCall::DomainCreate { target, may_create } => {
                self.domain_create(caller, target, may_create)
            }
            HvCall::DomainDestroy { target, now } => self.domain_destroy(caller, target, now),
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
    /// with *matching* permission ([`grant::System::authorizes`]): a **writable** foreign
    /// leaf needs a read-write grant, a **read-only** one only a read-only grant — a
    /// domain cannot map a foreign page into its address space, at a given access, without
    /// the owner's consent to that access. Foreign entries are leaves (an `L1` table maps
    /// a data page), so a foreign child must go under an `L1` — sharing whole page-table
    /// *subtrees* across domains is a later refinement. `p2m` enforces the type discipline;
    /// this seam adds the authorization it is deliberately blind to.
    fn p2m_link(
        &mut self,
        caller: DomId,
        parent: Mfn,
        slot: u32,
        child: Mfn,
        writable: bool,
    ) -> Result<HvOutcome, HvError> {
        if let Some(owner) = self.p2m.owner_of(child) {
            if owner != caller {
                // A foreign entry: it must be an authorized L1 leaf. Check the grant and
                // the level *before* touching p2m, so an unauthorized link is a no-op. The
                // grant must cover the entry's access — a writable entry needs a
                // read-write grant, a read-only entry any grant of the frame.
                if self.p2m.current_type(parent) != Some(PageType::PageTable(PtLevel::L1)) {
                    return Err(HvError::Unauthorized);
                }
                if !self.grant.authorizes(owner, caller, child, writable) {
                    return Err(HvError::Unauthorized);
                }
            }
        }
        self.p2m
            .link(caller, parent, slot, child, writable)
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

    /// Bring a `Dead` slot to life — the birth half of the domain lifecycle, the mirror of
    /// [`Self::domain_destroy`].
    ///
    /// **Authority gate first.** Creation requires the *creation capability*: only a caller
    /// with `may_create` (the liveness gate already guaranteed the caller is `Live` and in
    /// range) may create a domain, else [`HvError::Denied`], a true no-op. This gate is the
    /// whole of `may_create`'s *provenance* — the only transition that ever sets a domain's
    /// `may_create` bit is this one, and it is itself gated on `may_create`, so a domain can
    /// never self-elevate.
    ///
    /// **Control rooted here.** On success the caller becomes `target`'s controller
    /// (`controls[caller][target]`), the root of every control edge: a domain controls what
    /// it creates, and delegation flows from there. `may_create` stamps whether the child
    /// may itself create.
    ///
    /// **Lifecycle guard.** `target` must be a `Dead` slot, else [`HvError::AlreadyAlive`].
    /// A `Dead` slot is a clean shell by the [`CrossViolation::DeadDomainNotClean`]
    /// standing invariant (owns no frame, offers or holds no grant, has no bound port or
    /// online vCPU) — teardown's postcondition, now maintained forever — so a created
    /// domain always begins empty. That is the whole elegance: creation records authority
    /// and lifts the slot to `Live`, but adds *no* resources, because the invariant
    /// guarantees there is nothing to clear. Self-creation cannot occur: the caller is
    /// `Live` and the target `Dead`, so `caller != target` always — so the control edge it
    /// records is never the unused self-edge.
    fn domain_create(
        &mut self,
        caller: DomId,
        target: DomId,
        may_create: bool,
    ) -> Result<HvOutcome, HvError> {
        if target as usize >= self.domain_count() {
            return Err(HvError::BadDomain);
        }
        // Authority: only a domain with the creation capability may create. A refusal
        // mutates nothing — this is what gives may_create its provenance (no self-elevation).
        if !self.may_create[caller as usize] {
            return Err(HvError::Denied);
        }
        // Lifecycle: the slot must be Dead. An already-live domain must be torn down first.
        if self.life[target as usize] != DomainLife::Dead {
            return Err(HvError::AlreadyAlive);
        }
        // A Dead slot is a clean shell by standing invariant, so there is nothing to
        // clear — creation only lifts it to Live and stamps its authority.
        debug_assert!(
            self.is_clean_shell(target),
            "domain {target} was Dead but not a clean shell before creation"
        );
        self.life[target as usize] = DomainLife::Live;
        self.may_create[target as usize] = may_create;
        // The creator controls what it creates — the root of every control edge.
        self.controls[caller as usize][target as usize] = true;
        Ok(HvOutcome::Done)
    }

    /// Tear a domain down across all four subsystems — the whole-system operation that
    /// welds every seam. **Atomic, all-or-nothing, refuse-if-busy.**
    ///
    /// **Authority gate first.** A domain may tear *itself* down, but destroying a *peer*
    /// requires the caller *control* that peer specifically (`controls[caller][target]` — a
    /// capability rooted in having created it, or delegated to the caller); otherwise the
    /// call is refused with [`HvError::Denied`] before anything is inspected or touched, so
    /// an unauthorized destroy is a true no-op. This is the *finer* authority axis — the
    /// third after ownership and consent — per-target rather than a blanket privilege, and
    /// it lives at the seam because only the integrated core sees both the acting `caller`
    /// and the `target`. Teardown then clears every control edge into *and* out of `target`
    /// (and its `may_create`), so no capability outlives the domain it named.
    ///
    /// Then one precondition gates the rest: no *foreign* domain may hold a live grant map
    /// of one of `target`'s frames ([`grant::System::has_foreign_map`]). If one does, teardown
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
    /// What remains is a `Dead`, authority-free, empty shell: domain slots are fixed-size
    /// and never removed, so peers left `Unbound { remote: target }` stay valid, and only a
    /// later [`Self::domain_create`] can revive it. Verification rides on the existing
    /// invariant net (a mis-ordered teardown trips grant↔p2m or evtchn↔sched, caught by the
    /// `dispatch` cross-check). The old debug-time postcondition — "nothing live points into
    /// `target`" — has *graduated*: it is now the standing
    /// [`CrossViolation::DeadDomainNotClean`] invariant, which `dispatch` checks after this
    /// returns (the slot is `Dead` now, so the invariant demands it be clean) and which
    /// holds forever, not just at this instant. The local `debug_assert!` below is kept only
    /// as a precise, localized failure message for teardown; the standing invariant is what
    /// actually guarantees it.
    ///
    /// Provenance: the refuse-if-busy lifecycle (rather than force-unmap, or Xen's
    /// deferred dying-domain RCU teardown) is a design decision informed by the public
    /// Xen domain-destroy semantics and general OS knowledge — not `xen/`'s GPL
    /// implementation. See `CLEANROOM.md`.
    fn domain_destroy(
        &mut self,
        caller: DomId,
        target: DomId,
        now: Ticks,
    ) -> Result<HvOutcome, HvError> {
        if caller as usize >= self.domain_count() || target as usize >= self.domain_count() {
            return Err(HvError::BadDomain);
        }
        // The authority gate, before anything is inspected: a domain may destroy itself, but
        // destroying a peer needs a control capability over *that* peer specifically. A
        // refusal here mutates nothing. Checked before liveness, so a caller that lacks
        // control cannot even probe whether a peer is alive — a denial reveals nothing.
        if caller != target && !self.controls[caller as usize][target as usize] {
            return Err(HvError::Denied);
        }
        // Past the authority gate the target is provably Live, so there is no NotAlive path
        // here: a self-destroy has a Live caller (the dispatch gate), and a control edge
        // requires a Live target (the ControlEdgeDeadEndpoint invariant). A Dead domain has
        // no controller — its edges were cleared on death — so a peer destroy of it never
        // gets past the gate: it is Denied, not NotAlive, which also means a caller that
        // lacks control cannot tell a Dead target from a Live one.
        debug_assert!(
            self.life[target as usize] == DomainLife::Live,
            "domain_destroy reached a Dead target {target} past the authority gate"
        );
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

        // The slot drops to Dead and loses all authority — a clean, unprivileged shell that
        // only a later DomainCreate can revive. Clearing `may_create` keeps "may_create ⇒
        // Live" (DeadDomainMayCreate) standing; clearing every control edge into and out of
        // `target` keeps "a control edge needs both endpoints Live" (ControlEdgeDeadEndpoint)
        // standing — so a capability never outlives the domain it named, and a reborn slot
        // gets fresh authority, never a stale one inherited from a dead tenant.
        self.life[target as usize] = DomainLife::Dead;
        self.may_create[target as usize] = false;
        for h in 0..self.domain_count() {
            self.controls[h][target as usize] = false; // edges *into* target (its controllers)
            self.controls[target as usize][h] = false; // edges *out of* target (what it controlled)
        }

        debug_assert!(
            self.is_clean_shell(target),
            "domain {target} is not an empty shell after teardown"
        );
        Ok(HvOutcome::Done)
    }

    /// Whether `target` is a clean shell: it holds no event-channel port, no online vCPU,
    /// offers or holds no grant, and owns no frame — nothing live points into it. This is
    /// the predicate shared by three roles: domain teardown's debug postcondition, domain
    /// creation's precondition (a `Dead` slot is always clean, so a created domain starts
    /// empty), and — for every `Dead` domain — the standing
    /// [`CrossViolation::DeadDomainNotClean`] invariant that graduates the one-shot
    /// postcondition into a forever-maintained one. It rides atop the standing invariant
    /// net which already catches the ordering bugs (a freed port with a live peer, a freed
    /// on-CPU vCPU, a foreign-mapped freed frame, a deliverable event on an offlined vCPU).
    fn is_clean_shell(&self, target: DomId) -> bool {
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
    ///
    /// Domain lifecycle & authority: every `Dead` slot is a provably-clean, authority-free
    /// shell — it owns no frame, offers or holds no grant, has no bound port or online vCPU,
    /// holds no `may_create`, and sits on no control edge; and every control edge relates two
    /// `Live` domains. The whole-domain invariants that close the create/destroy loop and
    /// keep the per-target authority tied to life.
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
        // grant from the child frame's owner to the domain whose table maps it, of
        // permission matching the entry's — a read-write grant for a writable entry, any
        // grant for a read-only one. An unauthorized foreign entry is a domain reaching
        // into another's memory without consent — the isolation breach this join exists to
        // prevent.
        for (parent, _slot, child, writable) in self.p2m.link_edges() {
            let (Some(child_owner), Some(parent_owner)) =
                (self.p2m.owner_of(child), self.p2m.owner_of(parent))
            else {
                continue;
            };
            if child_owner != parent_owner
                && !self
                    .grant
                    .authorizes(child_owner, parent_owner, child, writable)
            {
                return Some(CrossViolation::UnauthorizedForeignLink { parent, child });
            }
        }
        // Domain lifecycle: a `Dead` slot must be a provably-clean, authority-free shell.
        // These graduate teardown's one-shot postcondition into standing invariants: the
        // liveness gate guarantees a `Dead` domain can never acquire a resource, so
        // cleanliness holds forever, and clearing authority on death keeps it tied to life.
        // `DeadDomainNotClean` is cross-subsystem (it reads all four subsystems); together
        // with the create/destroy guards they give the lifecycle its full safety content.
        for dom in 0..self.domain_count() as DomId {
            if self.life[dom as usize] == DomainLife::Dead {
                if !self.is_clean_shell(dom) {
                    return Some(CrossViolation::DeadDomainNotClean { dom });
                }
                if self.may_create[dom as usize] {
                    return Some(CrossViolation::DeadDomainMayCreate { dom });
                }
            }
        }
        // Authority: every control edge must relate two `Live` domains. Rooted in creation
        // and delegation (both requiring live endpoints) and cleared by teardown, so a
        // `Dead` endpoint means a capability outlived the domain it named.
        for holder in 0..self.domain_count() as DomId {
            for target in 0..self.domain_count() as DomId {
                if self.controls[holder as usize][target as usize]
                    && (self.life[holder as usize] != DomainLife::Live
                        || self.life[target as usize] != DomainLife::Live)
                {
                    return Some(CrossViolation::ControlEdgeDeadEndpoint { holder, target });
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

    /// Whether `dom` holds the **creation** capability — may issue [`HvCall::DomainCreate`].
    /// Domain 0 boots with it; a domain gains it only by a `may_create` domain creating it
    /// so, and loses it on teardown. Out-of-range domains read as `false`. Always implies
    /// `Live` (the [`CrossViolation::DeadDomainMayCreate`] invariant).
    pub fn may_create(&self, dom: DomId) -> bool {
        self.may_create.get(dom as usize).copied().unwrap_or(false)
    }

    /// Whether `holder` holds a **control** capability over `target` — may destroy it and
    /// (later) delegate/revoke control of it. Rooted in creation (`holder` created `target`)
    /// or delegation; cleared when either domain is torn down. A domain's authority over
    /// *itself* is inherent and not represented as an edge, so `controls(d, d)` is always
    /// `false`. Out-of-range domains read as `false`. Every `true` edge relates two `Live`
    /// domains (the [`CrossViolation::ControlEdgeDeadEndpoint`] invariant).
    pub fn controls(&self, holder: DomId, target: DomId) -> bool {
        self.controls
            .get(holder as usize)
            .and_then(|row| row.get(target as usize))
            .copied()
            .unwrap_or(false)
    }

    /// Whether `dom` is a `Live` domain — one that has been created (or booted, for dom0)
    /// and not yet torn down. A `Live` domain may issue hypercalls and hold resources; a
    /// `Dead` slot can do neither. Out-of-range domains read as `Dead` (not live).
    pub fn is_live(&self, dom: DomId) -> bool {
        self.life.get(dom as usize).copied() == Some(DomainLife::Live)
    }

    /// The lifecycle state of `dom`, or `None` if out of range.
    pub fn life_of(&self, dom: DomId) -> Option<DomainLife> {
        self.life.get(dom as usize).copied()
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

    // A 3-domain hypervisor with domains 1 and 2 brought to life by dom0, so the subsystem
    // tests below have live domains to drive. (Only dom0 boots Live; every other slot must
    // be created before it can act — that is the lifecycle. Lifecycle-specific tests build
    // straight on `Hypervisor::new` to observe the raw boot state.)
    fn hv() -> Hypervisor {
        let mut h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: false,
            },
        )
        .unwrap();
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 2,
                may_create: false,
            },
        )
        .unwrap();
        h
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
        // Domain 0 tears *itself* down (always authorized), so this isolates the busy
        // refusal from the authority gate.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 0, now: 0 }),
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
            .dispatch(0, HvCall::DomainDestroy { target: 0, now: 0 })
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
        assert!(h.is_clean_shell(0));
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
        assert!(h.is_clean_shell(1));
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
                    writable: true,
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
                    child: 4,
                    writable: true
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
                writable: true,
            },
        )
        .unwrap();
        h.dispatch(
            1,
            HvCall::P2mLink {
                parent: 1,
                slot: 0,
                child: 2,
                writable: true,
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
        assert!(h.is_clean_shell(1));
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
                writable: true,
            },
        )
    }

    fn link5_ro(h: &mut Hypervisor) -> Result<HvOutcome, HvError> {
        h.dispatch(
            0,
            HvCall::P2mLink {
                parent: 0,
                slot: 0,
                child: 5,
                writable: false,
            },
        )
    }

    // Domain 1 owns frame 5 and grants it *read-only* to domain 0; domain 0 owns frame 0
    // and pins it as an L1 table. The stage for a read-only cross-domain leaf.
    fn foreign_ro_link_stage(h: &mut Hypervisor) {
        h.dispatch(1, HvCall::P2mAllocate { mfn: 5 }).unwrap();
        h.dispatch(
            1,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 0,
                frame: 5,
                readonly: true,
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

    #[test]
    fn a_readonly_grant_authorizes_a_readonly_foreign_leaf_but_not_a_writable_one() {
        let mut h = hv();
        foreign_ro_link_stage(&mut h);
        // A read-only grant does NOT authorize a *writable* entry — that would let domain
        // 0 write a page domain 1 only consented to share for reading.
        assert_eq!(link5(&mut h), Err(HvError::Unauthorized));
        assert_eq!(h.p2m().child_at(0, 0), None);

        // But a read-only entry is authorized. It takes only an existence reference, so
        // the frame is pinned against reuse yet stays untyped (a reader is type-agnostic).
        assert_eq!(link5_ro(&mut h), Ok(HvOutcome::Done));
        assert_eq!(h.p2m().child_at(0, 0), Some(5));
        assert_eq!(h.p2m().current_type(5), None);
        assert!(h.p2m().refs(5).unwrap() >= 1);
        assert_eq!(
            h.dispatch(1, HvCall::P2mFree { mfn: 5 }),
            Err(HvError::P2m(p2m::P2mError::InUse))
        );
        assert!(h.invariants_hold());

        // The revoke-block covers a read-only entry just as it does a writable one: domain
        // 1 cannot end the grant while domain 0's read-only entry relies on it.
        assert_eq!(
            h.dispatch(1, HvCall::GrantEndAccess { gref: 0 }),
            Err(HvError::Grant(grant::GrantError::InUse))
        );
        // Unlink, and the grant is revocable and the frame reclaimable again.
        h.dispatch(0, HvCall::P2mUnlink { parent: 0, slot: 0 })
            .unwrap();
        assert_eq!(h.p2m().current_type(5), None);
        assert!(h.dispatch(1, HvCall::GrantEndAccess { gref: 0 }).is_ok());
        assert!(h.dispatch(1, HvCall::P2mFree { mfn: 5 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_readwrite_grant_authorizes_a_readonly_foreign_leaf_too() {
        let mut h = hv();
        // The read-write stage grants frame 5 *read-write* to domain 0.
        foreign_link_stage(&mut h);
        // A read-only entry is permitted under a read-write grant — any grant covers
        // read. And read-only, it leaves the frame untyped rather than writable-typed.
        assert_eq!(link5_ro(&mut h), Ok(HvOutcome::Done));
        assert_eq!(h.p2m().child_at(0, 0), Some(5));
        assert_eq!(
            h.p2m().current_type(5),
            None,
            "a read-only leaf does not type its child, even under a read-write grant"
        );
        assert!(h.invariants_hold());
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
                    child: 5,
                    writable: true
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
        // down — the same refuse-if-busy rule as a live foreign grant map. Issued by the
        // privileged control domain (dom0), so the busy refusal is what bites, not authority.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 }),
            Err(HvError::DomainBusy)
        );
        // But the *linker* (domain 0) can tear itself down: teardown unlinks its foreign
        // entry, freeing domain 1's frame, and spares domain 1.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 0, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_clean_shell(0));
        assert_eq!(h.p2m().owner_of(5), Some(1), "domain 1 keeps its frame");
        assert_eq!(h.p2m().current_type(5), None, "no longer foreign-mapped");
        assert!(h.invariants_hold());
        // With the link gone, domain 1 can now tear itself down too.
        assert!(h
            .dispatch(1, HvCall::DomainDestroy { target: 1, now: 0 })
            .is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn only_a_privileged_domain_or_the_target_itself_may_destroy_a_domain() {
        let mut h = hv();
        // Domain 0 boots as the control domain (dom0); 1 and 2 are ordinary.
        assert!(h.may_create(0));
        assert!(!h.may_create(1));
        assert!(!h.may_create(2));

        // Give domain 1 some state, so a denied teardown can be shown to touch nothing.
        h.dispatch(1, HvCall::P2mAllocate { mfn: 3 }).unwrap();
        h.dispatch(
            1,
            HvCall::P2mPin {
                mfn: 3,
                level: PtLevel::L1,
            },
        )
        .unwrap();

        // An unprivileged peer (domain 2) may not destroy domain 1 — Denied, and a no-op.
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 1, now: 0 }),
            Err(HvError::Denied)
        );
        assert_eq!(
            h.p2m().owner_of(3),
            Some(1),
            "a denied destroy mutates nothing"
        );
        assert!(h.p2m().is_pinned(3));
        assert!(h.invariants_hold());

        // The privileged control domain (dom0) may destroy the peer.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_clean_shell(1));
        assert!(!h.p2m().is_allocated(3));
        assert!(h.invariants_hold());
    }

    #[test]
    fn an_unprivileged_domain_may_still_tear_itself_down() {
        let mut h = hv();
        // Domain 2 is unprivileged, but a domain always has authority over *itself* —
        // self-teardown never needs privilege.
        assert!(!h.may_create(2));
        h.dispatch(2, HvCall::P2mAllocate { mfn: 4 }).unwrap();
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 2, now: 0 }),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_clean_shell(2));
        assert!(!h.p2m().is_allocated(4));
        assert!(h.invariants_hold());
    }

    #[test]
    fn only_dom0_boots_live_the_rest_are_dead_shells() {
        // The raw boot state: domain 0 is the primordial Live control domain; every other
        // slot is a Dead, unprivileged, clean shell awaiting creation.
        let h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        assert!(h.is_live(0));
        assert!(h.may_create(0));
        assert_eq!(h.life_of(0), Some(DomainLife::Live));
        for d in 1..3 {
            assert!(!h.is_live(d), "domain {d} should boot Dead");
            assert!(!h.may_create(d));
            assert_eq!(h.life_of(d), Some(DomainLife::Dead));
        }
        assert_eq!(
            h.life_of(9),
            None,
            "out-of-range slot has no lifecycle state"
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_dead_domain_can_issue_no_hypercall() {
        // A Dead slot must be inert: every op it attempts is NotAlive and a no-op, which is
        // exactly what keeps it a clean shell. Sample one op per subsystem.
        let mut h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        for call in [
            HvCall::CreditGrant { amount: 100 },
            HvCall::P2mAllocate { mfn: 0 },
            HvCall::SchedAdmit { vcpu: 0 },
            HvCall::EvtchnBindIpi { vcpu: 0 },
            HvCall::EvtchnAllocUnbound { remote: 0 },
        ] {
            assert_eq!(
                h.dispatch(1, call),
                Err(HvError::NotAlive),
                "a Dead domain must not be able to {call:?}"
            );
        }
        // None of those touched anything: domain 1 owns no frame, has no port/vcpu, and the
        // shell is still clean and Dead.
        assert!(!h.p2m().is_allocated(0));
        assert!(h.is_clean_shell(1));
        assert!(!h.is_live(1));
        assert!(h.invariants_hold());
    }

    #[test]
    fn create_brings_a_dead_slot_to_life_and_then_it_can_act() {
        let mut h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        // dom0 (privileged) creates domain 1 as an ordinary (unprivileged) domain.
        assert_eq!(
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: 1,
                    may_create: false,
                },
            ),
            Ok(HvOutcome::Done)
        );
        assert!(h.is_live(1));
        assert!(!h.may_create(1));
        // Now — and only now — domain 1 can act: what was NotAlive a moment ago succeeds.
        assert!(h.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).is_ok());
        assert_eq!(h.p2m().owner_of(0), Some(1));
        assert!(h.invariants_hold());
    }

    #[test]
    fn only_a_privileged_domain_may_create_and_a_denial_is_a_noop() {
        let mut h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        // dom0 brings up an *unprivileged* domain 1.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: false,
            },
        )
        .unwrap();
        // Domain 1 is Live but unprivileged, so it cannot create domain 2 — Denied, no-op.
        assert_eq!(
            h.dispatch(
                1,
                HvCall::DomainCreate {
                    target: 2,
                    may_create: false,
                },
            ),
            Err(HvError::Denied)
        );
        assert!(
            !h.is_live(2),
            "a denied create must not bring the slot to life"
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn privilege_has_provenance_only_a_privileged_creator_confers_it() {
        // The provenance chain: dom0 (privileged) can mint another privileged control
        // domain, which can in turn create; but no unprivileged domain can confer privilege
        // — not on a peer (Denied) and not on itself (it can never be a create target).
        let mut h = Hypervisor::new(4, 4, 4, 1, 1, 4);
        // dom0 creates domain 1 *privileged*.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: true,
            },
        )
        .unwrap();
        assert!(
            h.may_create(1),
            "privilege was conferred by a privileged creator"
        );
        // Domain 1, now privileged, can itself create domain 2 (unprivileged).
        assert!(h
            .dispatch(
                1,
                HvCall::DomainCreate {
                    target: 2,
                    may_create: false,
                },
            )
            .is_ok());
        assert!(h.is_live(2) && !h.may_create(2));
        // Domain 2, unprivileged, cannot create domain 3 privileged — no self-elevation by
        // proxy: the authority to confer privilege is itself gated on privilege.
        assert_eq!(
            h.dispatch(
                2,
                HvCall::DomainCreate {
                    target: 3,
                    may_create: true,
                },
            ),
            Err(HvError::Denied)
        );
        assert!(!h.is_live(3));
        // The only privileged domains in reach are dom0 and the one it minted — privilege
        // never materialised without a privileged creator behind it.
        assert!(h.may_create(0) && h.may_create(1));
        assert!(!h.may_create(2) && !h.may_create(3));
        assert!(h.invariants_hold());
    }

    #[test]
    fn creating_an_already_live_domain_is_already_alive() {
        let mut h = hv(); // domains 0,1,2 all Live
        assert_eq!(
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: 1,
                    may_create: false,
                },
            ),
            Err(HvError::AlreadyAlive)
        );
        // A create out of range is BadDomain, checked before authority.
        assert_eq!(
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: 9,
                    may_create: false,
                },
            ),
            Err(HvError::BadDomain)
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn destroying_a_dead_peer_is_denied_no_one_controls_a_dead_domain() {
        let mut h = Hypervisor::new(3, 8, 6, 2, 2, 8);
        // Domain 1 is Dead — never created, so no domain controls it (control edges only
        // exist between live domains). Even dom0, which *may create*, does not control a
        // slot it never brought up, so destroying it is Denied by the authority gate — not
        // NotAlive. A caller without control can't even tell a Dead target from a live one.
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 }),
            Err(HvError::Denied)
        );
        // Bring it up (dom0 now controls it), and the destroy goes through.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: false,
            },
        )
        .unwrap();
        assert!(h.controls(0, 1));
        assert!(h
            .dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 })
            .is_ok());
        assert!(!h.controls(0, 1), "teardown cleared the control edge");
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_domain_cycles_dead_live_dead_and_privilege_resets_on_rebirth() {
        // The whole lifecycle loop, and privilege provenance across a slot's reuse: a
        // torn-down slot returns to a clean, *unprivileged* shell, so a later create decides
        // its authority afresh — a reborn domain never inherits a dead tenant's privilege.
        let mut h = Hypervisor::new(3, 4, 4, 1, 1, 4);
        // Create domain 1 privileged; give it a frame.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: true,
            },
        )
        .unwrap();
        h.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        assert!(h.is_live(1) && h.may_create(1));

        // Destroy it: the slot drops to Dead, loses its frame *and* its privilege.
        h.dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 })
            .unwrap();
        assert!(!h.is_live(1));
        assert!(!h.may_create(1), "a torn-down domain loses privilege");
        assert!(h.is_clean_shell(1));
        assert_eq!(h.p2m().owner_of(0), None);
        assert!(h.invariants_hold());

        // Recreate the slot, this time unprivileged — the fresh authority is what create
        // stamps now, not the privilege the dead tenant had.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: false,
            },
        )
        .unwrap();
        assert!(h.is_live(1) && !h.may_create(1));
        assert!(h.invariants_hold());
    }

    #[test]
    fn control_is_per_target_a_creator_controls_only_what_it_made() {
        // Least-privilege: control is a per-target capability rooted in creation, with no
        // implicit transitivity — so a creation "grandparent" does NOT control its
        // grandchildren, and having `may_create` is not a blanket licence to destroy.
        let mut h = Hypervisor::new(4, 4, 4, 1, 1, 4);
        // dom0 creates domain 1 as a control domain (may_create), and domain 2 directly.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: true,
            },
        )
        .unwrap();
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 2,
                may_create: false,
            },
        )
        .unwrap();
        // Domain 1 creates domain 3. Now dom0 controls {1, 2}; domain 1 controls {3}.
        h.dispatch(
            1,
            HvCall::DomainCreate {
                target: 3,
                may_create: false,
            },
        )
        .unwrap();
        assert!(h.controls(0, 1) && h.controls(0, 2));
        assert!(h.controls(1, 3));
        // dom0 does NOT control its grandchild (domain 3) — it did not create it, and there
        // is no blanket power. Even though dom0 may_create, destroying domain 3 is Denied.
        assert!(!h.controls(0, 3));
        assert_eq!(
            h.dispatch(0, HvCall::DomainDestroy { target: 3, now: 0 }),
            Err(HvError::Denied)
        );
        assert!(h.is_live(3), "the denied destroy was a no-op");
        // Domain 1, the actual controller, can destroy domain 3.
        assert!(h
            .dispatch(1, HvCall::DomainDestroy { target: 3, now: 0 })
            .is_ok());
        assert!(!h.is_live(3));
        // A domain with no control of a peer and no may_create obviously cannot destroy it:
        // domain 2 cannot destroy domain 1.
        assert_eq!(
            h.dispatch(2, HvCall::DomainDestroy { target: 1, now: 0 }),
            Err(HvError::Denied)
        );
        assert!(h.invariants_hold());
    }

    #[test]
    fn teardown_clears_control_edges_into_and_out_of_the_domain() {
        // A capability must not outlive the domain it names, in either direction: destroying
        // a domain drops both the edges by which others controlled it and the edges by which
        // it controlled others.
        let mut h = Hypervisor::new(4, 4, 4, 1, 1, 4);
        // dom0 → domain 1 (a control domain); domain 1 → domain 2 and domain 3.
        h.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: true,
            },
        )
        .unwrap();
        for t in [2u16, 3] {
            h.dispatch(
                1,
                HvCall::DomainCreate {
                    target: t,
                    may_create: false,
                },
            )
            .unwrap();
        }
        assert!(h.controls(0, 1) && h.controls(1, 2) && h.controls(1, 3));

        // Destroy domain 1. The edge *into* it (dom0→1) and the edges *out of* it (1→2, 1→3)
        // all vanish; domains 2 and 3 survive but are now orphaned (no controller).
        h.dispatch(0, HvCall::DomainDestroy { target: 1, now: 0 })
            .unwrap();
        assert!(!h.controls(0, 1), "edge into the destroyed domain cleared");
        assert!(
            !h.controls(1, 2) && !h.controls(1, 3),
            "edges out of the destroyed domain cleared"
        );
        assert!(!h.may_create(1), "and it lost may_create");
        assert!(h.is_live(2) && h.is_live(3), "peers it controlled survive");
        // An orphaned domain has no controller, but always retains authority over itself.
        assert!(h
            .dispatch(2, HvCall::DomainDestroy { target: 2, now: 0 })
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
