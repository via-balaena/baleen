// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D — the non-interference bridge (enumerator check on real code)
//!
//! Tiers A–C prove the checked invariants hold in every reachable state, deductively and
//! for arbitrary size. Tier D asks the *next* question: do those invariants **collectively
//! imply real isolation** — is domain A's observable state affected only by A itself and by
//! principals A has *authorized*, and never by an unrelated domain? That is the "are we
//! checking the **right** things" capstone (seL4-infoflow / CertiKOS style), and it is
//! stated as **non-interference** via the standard *unwinding* approach.
//!
//! This module is the **bridge** — the Tier-D analogue of the Kani spike that opened Tier C.
//! Before the hard ∀-N Verus *unwinding proof*, it validates the **property definition** on
//! the **real** `Hypervisor` at small size: for every reachable state, every transition, and
//! every observer domain, it checks the core **local-respect** condition
//!
//! > if the actor `b` has **no authorized channel** to observer `a`, then the transition
//! > leaves `a`'s observable state [`obs`] unchanged.
//!
//! If the property definition is wrong (`obs` too fine, or the channel relation too coarse)
//! this produces a concrete counterexample rather than a false proof — exactly how the Kani
//! bridge de-risked Tier C's obligations (design-lesson #20). See
//! `docs/TIER-D-NONINTERFERENCE.md` for the full definition and the reasoning behind every
//! granularity call.
//!
//! ## `obs(a)` — domain `a`'s isolation surface
//!
//! The projection of the whole-system state onto the entities that belong to `a`: its
//! credit, its event-channel ports (state/pending/masked), its grant table rows *and their
//! live-map counts*, the grant mappings it holds, its vCPUs (run-state and affinity), the
//! machine frames it owns (references, type, pin), and the page-table edges rooted in its
//! own tables, plus its liveness. This is a **filter of `enumerate::Snapshot`** — the same
//! read-once projection symmetry reduction already built — down to one domain.
//!
//! Two deliberate exclusions, each a real granularity decision (documented in the design
//! doc): the **global pCPU-occupancy vector** (pcpu contention is a timing/availability
//! covert channel the model abstracts, like `runtime`; `a` observes only its *own* vCPUs'
//! placement), and **authority** (`may_create`, the `controls` matrix — that is `a`'s *power
//! over others*, governed by the Tier-C control-forest invariants, not part of `a`'s own
//! isolation surface; a delegation *to* `a` touches none of `a`'s resources).
//!
//! ## The authorized-channel relation `b ⇝ a`
//!
//! State-dependent and **intransitive** (correct for a capability system — least-privilege,
//! no implicit transitivity). A step by `b` may legitimately move `obs(a)` iff a **direct**
//! relationship holds — and each is exactly the safety content of one of the three seams:
//!
//! * **self** — `b == a`;
//! * **consent (grant)** — `a` has an active grant with grantee `b` (`b` may map/unmap/copy
//!   it, moving `a`'s frame references and grant map-counts);
//! * **signal (evtchn)** — `a` holds a port `Interdomain{b}` or `Unbound{b}` (`b` may
//!   send/close/bind, moving `a`'s port state and pending bit);
//! * **authority (control)** — `controls[b][a]` (`b` may set `a`'s vCPU affinity, or destroy
//!   `a` outright);
//! * **creation** — `may_create[b]` and `a` is `Dead` (`b` may bring the slot to life).
//!
//! Plus one **teardown-reach** term for the single multi-domain transition, `DomainDestroy`
//! (see [`Channels::teardown_reach`]): destroying `c` cleans up `c`'s inbound references,
//! which are *`a`'s* outbound references naming `c` (a grant `a` offered `c`, a port `a`
//! opened toward `c`), so `b` controlling `c` reaches `a` through `c`. This is the classic
//! intransitive-non-interference structure, and the bridge is what *found* it (the check
//! flags it precisely when the term is omitted — see `docs/TIER-D-NONINTERFERENCE.md` §4).
//!
//! ## The confidentiality dual — step consistency and the read direction
//!
//! Local respect ([`check`]) is the **integrity** half: an unauthorized actor can't *affect*
//! `obs(a)`. The **confidentiality** half — can `a` *learn* anything unauthorized? — is
//! **step consistency** ([`check_step_consistency`]), the counterpart of
//! `noninterference_instantiation.rs::step_consistent_holds`: `obs⁺(a)` after a step is a
//! *function of* `(obs⁺(a), obs⁺(actor))` before it (two states `a` and the actor can't tell
//! apart go to the same successor). It needs no channel relation — it is pure determinism.
//!
//! Note the quantification: `a` ranges over **every** domain, *including the actor*. The
//! self-observer case is a real obligation — the actor's own successor observation must be a
//! function of its own observation — and it is where every guard whose refusal the caller reads
//! back lives. It used to be skipped here (while the Verus obligation it bridges to always
//! quantified over it), which hid four defects at depth 2–5; see [`Surface`] and ⑥ in
//! `docs/TIER-D-NONINTERFERENCE.md` §4b.
//!
//! It is checked over a wider surface [`obs_plus`] (`obs⁺`) with several additions the integrity
//! `obs` deliberately omits:
//!
//! * the **read-closure** — the grants `a` is a *grantee* of, with each grantor, frame, and the
//!   **StaleGrant status** (`owner_of(frame) == grantor`, the boolean `a`'s `grant_map` reads —
//!   *not* the owner's identity): what `a` can *read* through a grant it holds. This is where the
//!   **`DomainDestroy` read direction** lives — destroying `a`'s grantor `c` revokes `c`'s
//!   outgoing grants (`grant::revoke_all`), dropping `a`'s read-cap. (These read-caps are
//!   *not* in the local-respect `obs`: a grantor freely *creating* an offer to `a` moves them,
//!   and that is not integrity interference — a domain can't stop others revealing themselves
//!   to it. So the read direction is confidentiality, not integrity.)
//! * `a`'s own **authority** (`may_create[a]`, the `controls` rows) — a guard reads it, so
//!   step consistency is *false* without it. The bridge surfaces this exactly as the
//!   instantiation's `step_consistent` did (its **finding #1**): strip authority from `obs⁺`
//!   and the sweep finds a `DomainCreate` (or destroy/affinity) counterexample. `a`'s
//!   **outgoing** edges carry their `Root`/`Via` **provenance**, not bare presence, since that is
//!   what decides whether the destroy cascade strips them (⑥).
//! * **every domain's liveness** (⑥) — four guards read a named peer's liveness and report it to
//!   the caller (`AlreadyAlive` on `DomainCreate`; `NotAlive` on `GrantAccess{grantee}`,
//!   `EvtchnAllocUnbound{remote}`, `ControlGrant{to}`), so it is factually public and `obs⁺` must
//!   say so. A *declared disclosure* rather than a closed channel — the state belongs to a third
//!   principal, but none of the four guards can be removed without breaking domid-reuse soundness.
//! * the **inbound invitation closure** (⑥) — the half-open ports other domains have opened toward
//!   `a`, which `EvtchnBindInterdomain` refuses on. The event-channel twin of the read-closure, and
//!   confidentiality-only for the same reason.
//!
//! Over three domains the read direction is live and step consistency **holds**, non-vacuously
//! (see the tests). The four-domain edge that used to be declared here — a fourth domain `m`
//! mapping `c`'s frame made `DomainBusy` (which *refused* the destroy) depend on state neither
//! `a` nor the actor observes, so step consistency there rested on the instantiation's
//! over-approximation of `DomainBusy` — is **closed** as of ②′-(c): teardown no longer refuses,
//! it force-reclaims (`grant::drain_foreign_maps_of` + `p2m::unlink_all_into`), so the destroy is
//! a total function of the actor's own `obs⁺` and `m` has nothing to modulate. The real code now
//! *coincides with* the instantiation's drain carrier instead of being over-approximated by it.
//! Pinned directly by `force_reclaim_closes_the_busy_channel_grant_map_direction` and its
//! page-table twin (targeted, not swept: the configuration sits at ~depth 9).

use std::collections::HashMap;

use hv_core::evtchn::PortState;
use hv_core::p2m::PageType;
use hv_core::sched::RunState;
use hv_core::{Hypervisor, Transition, TransitionOutcome};

use crate::enumerate::{state_key, transitions, Config};

/// A domain id (matches [`hv_core`]'s `DomId`).
type Dom = u16;

/// Which authorized-channel terms are enabled — so the bridge can demonstrate the property
/// definition *empirically*: run with a term dropped and watch the check flag the flow it
/// governs (proving that term load-bearing), then restore it and watch the check pass. The
/// full relation is [`Channels::full`]; the non-vacuity tests drop one term at a time.
#[derive(Clone, Copy, Debug)]
pub struct Channels {
    /// The consent (grant) channel: `a` granted to `b`.
    pub grant: bool,
    /// The signal (event-channel) channel: `a` holds a port toward `b`.
    pub evtchn: bool,
    /// The authority (control) channel: `b` controls `a`.
    pub control: bool,
    /// The creation channel: `b` may create and `a` is `Dead`.
    pub create: bool,
    /// The teardown-reach term for `DomainDestroy` (the one multi-domain transition):
    /// `b` controls some `c` that `a` holds an **outbound** reference to (a grant `a` offered
    /// `c`, a port `a` opened toward `c`) — the references `c`'s teardown *clears*.
    pub teardown_reach: bool,
    /// The **inbound** half of the teardown-reach term, forced by ②′-(c)'s force-reclaim:
    /// `b` controls some `c` that `a` holds a *borrowed* reference **into** (a live grant map
    /// over one of `c`'s frames, or a page-table edge into one). Before force-reclaim these
    /// could not be reached past a proceeding destroy — a foreign hold made the teardown
    /// *refuse* — so the term was unnecessary. Now teardown breaks the borrow instead, which
    /// `a` observes, so the channel is real. Split from [`Self::teardown_reach`] so the
    /// non-vacuity test can drop exactly this sub-term and watch the flow it governs surface.
    pub teardown_borrow: bool,
}

impl Channels {
    /// The complete authorized-channel relation — every term on. This is the relation the
    /// property is *stated* with; the bridge validates it holds on real code.
    pub fn full() -> Self {
        Channels {
            grant: true,
            evtchn: true,
            control: true,
            create: true,
            teardown_reach: true,
            teardown_borrow: true,
        }
    }

    /// Whether, in state `hv`, an action by `b` is authorized to affect `obs(a)`.
    fn authorized(self, hv: &Hypervisor, b: Dom, a: Dom) -> bool {
        if b == a {
            return true;
        }
        // Consent: `a` offered `b` a grant (`b` may map/unmap/copy it → moves `a`'s frame
        // refs and grant map-counts). The grant *stays active* as long as `b` holds a
        // mapping (grant's no-end-while-mapped rule), so the channel is present exactly as
        // long as `b` can act through it — the invariant keeps the relation honest.
        if self.grant && a_grants_to(hv, a, b) {
            return true;
        }
        // Signal: `a` holds a port bound to / awaiting `b` (`b`'s send/close/bind moves
        // `a`'s port state and pending bit — the evtchn↔sched seam's channel).
        if self.evtchn && a_port_toward(hv, a, b) {
            return true;
        }
        // Authority: `b` controls `a` (may set affinity, may destroy).
        if self.control && hv.controls(b, a) {
            return true;
        }
        // Creation: a `may_create` domain may bring a `Dead` slot to life.
        if self.create && hv.may_create(b) && !hv.is_live(a) {
            return true;
        }
        // Teardown reach: `DomainDestroy(c)` by a controller `b` cleans up `c`'s inbound
        // references — which are `a`'s *outbound* references naming `c` (a grant `a` offered
        // `c`; a port `a` opened toward `c`) — so it can move `obs(a)`. Two hops (b ⇝ c,
        // a ↔ c); the one place the relation is not purely direct.
        if self.teardown_reach && self.teardown_reach_to(hv, b, a) {
            return true;
        }
        // Teardown borrow (②′-(c)): the inbound mirror of the above. Destroying `c` also
        // force-reclaims what `a` *borrowed from* `c` — the maps and page-table edges `a` holds
        // over `c`'s frames — which moves `obs(a)` just as clearing `a`'s outbound references
        // does.
        if self.teardown_borrow && self.teardown_borrow_from(hv, b, a) {
            return true;
        }
        false
    }

    /// `∃ c: b controls c ∧ a holds an outbound reference naming c` — the `DomainDestroy`
    /// two-hop term. `a`'s outbound references to `c` are exactly what `c`'s teardown clears
    /// (`revoke_grants_to` frees grants with grantee `c`; `clear_unbound_into` frees ports
    /// awaiting `c`; `close_all` returns `c`'s interdomain peers, i.e. `a`, to `Unbound`).
    fn teardown_reach_to(self, hv: &Hypervisor, b: Dom, a: Dom) -> bool {
        let n = hv.domain_count() as Dom;
        (0..n).any(|c| hv.controls(b, c) && (a_grants_to(hv, a, c) || a_port_toward(hv, a, c)))
    }

    /// `∃ c: b controls c ∧ a holds a borrowed reference *into* c's frames` — the inbound half
    /// of the two-hop teardown term, and the one ②′-(c) forced into existence.
    ///
    /// Teardown now force-reclaims every foreign hold on `c`'s frames
    /// (`grant::drain_foreign_maps_of` + `p2m::unlink_all_into`) rather than refusing over it.
    /// When the holder is `a`, that is a write to `obs(a)`: `a`'s handle-indexed held-maps lose
    /// an entry, or `a`'s own page-table edges lose one. Under the old refuse-if-busy design
    /// this was *unreachable* — a live foreign hold made the destroy a no-op — which is exactly
    /// why the term did not exist before. The design change made the flow real, so the relation
    /// has to name it: the same intransitive `b ⇝ c ↔ a` shape, with the `a↔c` reference
    /// pointing the other way.
    ///
    /// **The quantifier includes `c == b` — the self-destroy case — and that is not a widening
    /// for convenience.** [`Self::teardown_reach_to`] can omit it because when `b` tears *itself*
    /// down, `a`'s outbound reference to `b` is a grant `a` offered `b` or a port `a` opened
    /// toward `b` — already authorized by the *direct* consent and signal terms. The borrow
    /// direction has no such direct term: `a` borrowing from `b` means **`b` granted to `a`**,
    /// which is the opposite of the `grant` channel's `a_grants_to(a, b)`. So a domain
    /// force-reclaiming, by dying, the page it had lent out would be an unauthorized flow with
    /// nothing to name it. (The deep two-domain sweep found exactly this: `1` destroys itself
    /// while `0` holds a map of `1`'s frame.) Self-authority is inherent rather than an edge —
    /// `controls[b][b]` is always `Absent` — so it has to be spelled out here.
    fn teardown_borrow_from(self, hv: &Hypervisor, b: Dom, a: Dom) -> bool {
        let n = hv.domain_count() as Dom;
        (0..n).any(|c| (c == b || hv.controls(b, c)) && a_borrows_from(hv, a, c))
    }
}

/// Whether `a` has an active grant entry whose grantee is `b`.
fn a_grants_to(hv: &Hypervisor, a: Dom, b: Dom) -> bool {
    let g = hv.grant();
    (0..g.entry_count(a) as u32)
        .any(|gref| matches!(g.grant_entry(a, gref), Some((grantee, ..)) if grantee == b))
}

/// Whether `a` holds a live *borrowed* reference into one of `b`'s frames — a grant map whose
/// grantor is `b`, or a page-table edge of `a`'s own rooted at a frame `b` owns. These are
/// precisely what `b`'s teardown force-reclaims (②′-(c)), and both are in `obs(a)`: the first as
/// `a`'s handle-indexed held-maps, the second as `a`'s own edge set.
fn a_borrows_from(hv: &Hypervisor, a: Dom, b: Dom) -> bool {
    let g = hv.grant();
    let p = hv.p2m();
    let mapped = (0..g.handle_slots(a) as u32)
        .any(|h| matches!(g.mapping_at(a, h), Some((grantor, ..)) if grantor == b));
    let linked = p.link_edges().into_iter().any(|(parent, _, child, ..)| {
        p.owner_of(parent) == Some(a) && p.owner_of(child) == Some(b)
    });
    mapped || linked
}

/// Whether `a` holds an event-channel port bound to or awaiting `b`.
fn a_port_toward(hv: &Hypervisor, a: Dom, b: Dom) -> bool {
    let e = hv.evtchn();
    (0..e.port_count(a) as u32).any(|port| match e.state_of(a, port) {
        Some(PortState::Unbound { remote }) => remote == b,
        Some(PortState::Interdomain { remote, .. }) => remote == b,
        _ => false,
    })
}

/// The page-type tag used in the frame projection (mirror of `enumerate::level_tag`).
fn level_tag(ty: Option<PageType>) -> u64 {
    use hv_core::p2m::PtLevel::*;
    match ty {
        None => 0,
        Some(PageType::Writable) => 1,
        Some(PageType::PageTable(L1)) => 2,
        Some(PageType::PageTable(L2)) => 3,
        Some(PageType::PageTable(L3)) => 4,
        Some(PageType::PageTable(L4)) => 5,
    }
}

/// `obs(a)` — a canonical fingerprint of domain `a`'s **observable isolation surface**: the
/// projection of the whole state onto the entities that belong to `a`. Two states share an
/// `obs(a)` iff they are indistinguishable to `a`. See the module docs for the two
/// deliberate exclusions (global pCPU occupancy; authority).
pub fn obs(hv: &Hypervisor, a: Dom) -> Vec<u64> {
    let e = hv.evtchn();
    let g = hv.grant();
    let s = hv.sched();
    let p = hv.p2m();
    let mut k = Vec::new();

    // Liveness + credit — purely local (credit ops are caller-only).
    k.push(hv.is_live(a) as u64);
    k.push(hv.balance(a).unwrap_or(0));
    k.push(0xD_0000);

    // `a`'s event-channel ports.
    for port in 0..e.port_count(a) as u32 {
        let (tag, x, y) = match e.state_of(a, port) {
            Some(PortState::Unbound { remote }) => (1, u64::from(remote), 0),
            Some(PortState::Interdomain {
                remote,
                remote_port,
            }) => (2, u64::from(remote), u64::from(remote_port)),
            Some(PortState::Virq { vcpu, virq }) => (3, u64::from(vcpu), u64::from(virq)),
            Some(PortState::Ipi { vcpu }) => (4, u64::from(vcpu), 0),
            _ => (0, 0, 0), // Free / out of range
        };
        k.extend([
            tag,
            x,
            y,
            e.is_pending(a, port) as u64,
            e.is_masked(a, port) as u64,
        ]);
    }
    k.push(0xD_0001);

    // `a`'s grant table rows (`a` as grantor) — including the *live-map counts*, which peers
    // `a` has granted to legitimately move. Their movement under an authorized peer is
    // exactly what the channel relation permits.
    //
    // The last component is the row's **foreign-linked status** — whether this grant's grantee
    // currently has a page-table entry into the granted frame (`p2m::is_foreign_linked_by`).
    // It is here because `a` genuinely *learns* it: that predicate is exactly what
    // `hypervisor::grant_end_access` refuses on, so `a` reads it off `InUse` vs `Done` when it
    // tries to revoke. Leaving it out makes step consistency **false** — two states in which
    // *different* grantees of the same frame have linked it are `obs`-equal without it (the
    // frame's aggregate `refs` moves identically), yet `GrantEndAccess{gref}` refuses in one
    // and succeeds in the other. Same shape as the `DomainBusy` residual ②′-(c) closed, but
    // resolved the other way: the destroy guard read *another* domain's frames and had to go,
    // whereas this guard reads `a`'s **own** frame, so it is legitimate — it just has to be
    // *observed*. (Design-lesson #59: record what the principal LEARNS. Only a domain `a` has
    // granted to can move this bit, which the consent channel already authorizes, so local
    // respect is unaffected.)
    for gref in 0..g.entry_count(a) as u32 {
        match g.grant_entry(a, gref) {
            Some((grantee, frame, ro, maps, wmaps)) => k.extend([
                1,
                u64::from(grantee),
                u64::from(frame),
                ro as u64,
                u64::from(maps),
                u64::from(wmaps),
                p.is_foreign_linked_by(frame, grantee) as u64,
            ]),
            None => k.extend([0, 0, 0, 0, 0, 0, 0]),
        }
    }
    k.push(0xD_0002);

    // The grant mappings `a` holds (`a` as grantee), **indexed by `a`'s own handle slot** — the
    // handle namespace is per-domain (Xen-style maptrack), so this is `a`'s private state: only
    // `a`'s own map/unmap moves it, and no other domain's activity shifts `a`'s handle numbers.
    // `GrantUnmap{handle}` acts on a specific slot, so keeping the slot→map binding (not a set) is
    // what makes it deterministic w.r.t. `obs` — two states holding the same maps in different
    // slots (e.g. a writable and a read-only map of one grant, mapped in opposite order) are
    // correctly distinct, so `GrantUnmap{handle:0}` no longer looks non-deterministic. This is
    // faithful precisely *because* handles are per-domain: under the old global pool the slot index
    // leaked the global allocation order (another domain's activity), which would break local
    // respect; per-domain, the slot is `a`'s alone. (Design-lesson #7: the handle is behaviourally
    // live; `obs` keeps it, as `state_key` always has.)
    for h in 0..g.handle_slots(a) as u32 {
        match g.mapping_at(a, h) {
            Some((grantor, gref, w)) => {
                k.extend([1, u64::from(grantor), u64::from(gref), w as u64])
            }
            None => k.extend([0, 0, 0, 0]),
        }
    }
    k.push(0xD_0003);

    // `a`'s vCPUs — run state (with its chosen pcpu) and affinity mask. The *global* pcpu
    // occupancy vector is deliberately NOT here (see module docs).
    for vcpu in 0..s.vcpu_count(a) as u32 {
        let (tag, pc) = match s.state_of(a, vcpu) {
            Some(RunState::Runnable) => (1, 0),
            Some(RunState::Running { pcpu }) => (2, u64::from(pcpu)),
            Some(RunState::Blocked) => (3, 0),
            _ => (0, 0), // Offline / out of range
        };
        k.extend([tag, pc, s.affinity_of(a, vcpu).unwrap_or(0)]);
    }
    k.push(0xD_0004);

    // The machine frames `a` owns — references (which authorized peers move via grant maps /
    // foreign links), type, and pin. Keyed by mfn so a change in *which* frames `a` owns is
    // visible.
    for mfn in 0..p.frame_count() as u32 {
        if p.owner_of(mfn) == Some(a) {
            let ty = p.current_type(mfn);
            let pt_refs = match ty {
                Some(pt @ PageType::PageTable(_)) => p.type_refs(mfn, pt).unwrap_or(0),
                _ => 0,
            };
            k.extend([
                1,
                u64::from(mfn),
                u64::from(p.refs(mfn).unwrap_or(0)),
                u64::from(p.type_refs(mfn, PageType::Writable).unwrap_or(0)),
                // Write-xor-execute count (Phase II-1a): behaviourally live for `a`, since it
                // gates whether `a` may take a writable reference on its own frame. An authorized
                // peer can bump it via a foreign read-execute leaf, so it must be observed or such
                // a change would be invisible to the non-interference check (design-lesson #16).
                u64::from(p.executable_refs(mfn).unwrap_or(0)),
                u64::from(pt_refs),
                level_tag(ty),
                p.is_pinned(mfn) as u64,
            ]);
        }
    }
    k.push(0xD_0005);

    // The page-table edges rooted in `a`'s own tables (parent owned by `a`). Only `a`'s own
    // link/unlink touches these. A canonical (sorted) set.
    let mut edges: Vec<[u64; 6]> = p
        .link_edges()
        .into_iter()
        .filter(|&(parent, ..)| p.owner_of(parent) == Some(a))
        .map(|(par, slot, ch, w, leaf, execute)| {
            [
                u64::from(par),
                u64::from(slot),
                u64::from(ch),
                w as u64,
                leaf as u64,
                // The write-xor-execute edge bit (Phase II-1a) — behaviourally live for the same
                // reason `leaf` is: it selects what `a`'s own `unlink` gives back.
                execute as u64,
            ]
        })
        .collect();
    edges.sort_unstable();
    k.push(edges.len() as u64);
    for ed in edges {
        k.extend(ed);
    }
    k.push(0xD_0006);

    // The DMA-capable devices `a` holds (the SMMU arc's rung 4). This belongs in the **integrity**
    // surface, not merely the confidentiality one, and for a reason no other resource here has: a
    // device assigned to `a` is a bus master that writes `a`'s memory *with no hypercall and no
    // vCPU*. Excluding it would leave the one channel into `a`'s frames that the whole CPU-side
    // surface above is blind to (design-lesson #66 — a green proof can mean the surface cannot see
    // the flow).
    //
    // Only `a`'s own holdings, keyed by device id, so a change in *which* devices `a` holds is
    // visible. Who holds the ones `a` does not is a confidentiality question and lives in `obs⁺`.
    for dev in 0..hv.device().device_count() as u16 {
        if hv.device().holder_of(dev) == Some(a) {
            k.push(u64::from(dev));
        }
    }

    k
}

/// `obs⁺(a)` — `a`'s **read-closure** observation: [`obs`] extended with the grants `a` is a
/// *grantee* of, across every grantor's table, each with its grantor, frame, read-only flag, and
/// the **StaleGrant status** `owner_of(frame) == grantor`. This is the confidentiality surface
/// `read_closure.rs` proved step-consistency over: what `a` can *learn* through a grant it holds (a
/// cross-domain map/copy succeeds iff the grantor still owns the frame — the `StaleGrant` check in
/// `hypervisor::grant_map`), which the *read direction* of the `DomainDestroy` cascade moves
/// (destroying `a`'s grantor revokes `c`'s outgoing grants — `grant::revoke_all` — dropping `a`'s
/// read-cap). The ownership component is what the instantiation's `step_consistent` forced.
///
/// **The observable is the boolean, not the owner's identity.** `a` never reads *who* owns the
/// frame — only whether its map succeeds. The Verus instantiation (`noninterference_instantiation.rs`,
/// `read_closure.rs`) carries the raw `owner`, which is sound *there* because that abstract model
/// has **static** frame ownership (no transition re-owns a frame) — so the raw owner is a stable,
/// faithful super-observable. The real code has **dynamic** ownership (`P2mAllocate`/`GrantAccess`
/// of an unowned frame), under which the raw owner leaks a third domain's identity into `a`'s
/// read-cap and breaks step consistency; the bridge therefore records the tighter, faithful boolean.
/// The bridge surfacing an observable the abstract model does not need is the bridge doing its job —
/// tying the composition proof to what actually runs (`docs/TIER-D-NONINTERFERENCE.md` §4a/§5g).
///
/// This is deliberately **not** the local-respect surface: a grantor freely *creating* an offer to
/// `a` changes these read-caps, and that is not integrity interference (a domain cannot stop others
/// revealing themselves to it), so the read direction is a *confidentiality* property, checked by
/// [`check_step_consistency`] — not [`check`]'s local respect. See `docs/TIER-D-NONINTERFERENCE.md`.
pub fn obs_plus(hv: &Hypervisor, a: Dom) -> Vec<u64> {
    obs_plus_impl(hv, a, Surface::full())
}

/// Which optional components of the confidentiality surface [`obs_plus`] carries. Each is
/// **load-bearing** — dropping it makes step consistency *false* — and each has a non-vacuity test
/// that drops exactly it and watches the sweep produce a counterexample. (The mandatory core is
/// [`obs`] plus the read-closure, which have no toggle.)
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    /// `a`'s **own authority** — `may_create[a]`, `controls[·][a]`, `controls[a][·]`. The
    /// instantiation's findings #1 and #4.
    pub authority: bool,
    /// The **provenance** (`Root` vs `Via`) of `a`'s outgoing control edges rather than their bare
    /// presence — what decides whether the destroy cascade strips them (⑥). Only meaningful with
    /// [`Self::authority`] on. See [`obs_plus`].
    pub provenance: bool,
    /// **Every domain's liveness** — the bit the four peer-liveness guards read (⑥). See
    /// [`obs_plus`].
    pub peer_liveness: bool,
    /// **The inbound invitation closure** — the half-open ports *other* domains have opened
    /// toward `a`, which `EvtchnBindInterdomain`'s guard reads (⑥). The event-channel twin of the
    /// grant read-closure. See [`obs_plus`].
    pub invitations: bool,
    /// **The acquire outcome on each read-cap's frame** — what `hypervisor::grant_map`'s backing
    /// `p2m` acquire would return, which the grantee reads off its own map (⑥). Carries the
    /// grantor's frame *type* state to the grantee. See [`obs_plus`].
    pub acquire_guard: bool,
    /// **Each device's assignment status, as far as `a` can resolve it** — the bit
    /// `DeviceAssign`'s exclusivity guard reports (SMMU rung 4). See [`obs_plus`].
    pub devices: bool,
}

impl Surface {
    /// The complete confidentiality surface — the one [`obs_plus`] uses.
    pub fn full() -> Self {
        Surface {
            authority: true,
            provenance: true,
            peer_liveness: true,
            invitations: true,
            acquire_guard: true,
            devices: true,
        }
    }
}

/// A device's observation tag **as far as `a` can resolve it** (SMMU rung 4):
///
/// | tag | meaning |
/// |---|---|
/// | `0` | unassigned |
/// | `1` | held by a domain `a` neither is nor controls — *taken*, holder not named |
/// | `2 + h` | held by `h`, where `h` is `a` itself or a domain `a` controls |
///
/// **This is the tightest faithful projection, and each of the three arms is forced by a different
/// outcome `a` can actually produce.** `DeviceAssign{dev, to}` is idempotent when `to` already
/// holds `dev`, refused with `Busy` when a third party does, and succeeds when it is free — so a
/// two-valued free/taken bit is *not* enough: two states in which `dev` is taken, once by a domain
/// `a` controls and once by a stranger, are `obs⁺`-equal under that projection yet take the same
/// hypercall to `Ok` and to `Busy`. Naming the holder in arm `2 + h` is likewise forced, since
/// `a` may assign to any of several domains it controls and the outcome differs per holder.
///
/// Equally, the holder in arm `1` is deliberately **not** named: no outcome of any hypercall `a`
/// can issue distinguishes one uncontrolled holder from another (`Busy` and `Denied` are the same
/// whoever it is), so recording it would over-approximate the observable exactly as ②′-(a)'s raw
/// frame owner did. The honest reading of the arm-`0`/arm-`1` distinction is that **Baleen's device
/// namespace is free/taken-public to any domain holding a control edge** — a declared disclosure
/// beside domain liveness (⑥/F1), not a closed channel.
fn device_tag(hv: &Hypervisor, dev: u16, a: Dom) -> u64 {
    match hv.device().holder_of(dev) {
        None => 0,
        Some(h) if h == a || hv.controls(a, h) => 2 + u64::from(h),
        Some(_) => 1,
    }
}

/// A control edge's observation tag: `0` absent, `1` present-as-`Root`, `2` present-as-`Via`. With
/// `provenance` off it degrades to bare presence (`0`/`1`) — the pre-⑥ projection the non-vacuity
/// test uses. Never records the delegator's *identity* inside `Via(d)`: a domain is passive in a
/// `ControlGrant` naming it and learns no `d` from any outcome, so that would over-approximate the
/// observable exactly as ②′-(a)'s raw frame owner did.
fn control_tag(hv: &Hypervisor, holder: Dom, target: Dom, provenance: bool) -> u64 {
    match (provenance, hv.control_edge(holder, target)) {
        (_, hv_core::hypervisor::Control::Absent) => 0,
        (false, _) => 1, // presence only
        (true, hv_core::hypervisor::Control::Root) => 1,
        (true, hv_core::hypervisor::Control::Via(_)) => 2,
    }
}

/// The **acquire outcome** a grantee learns by mapping a grant over `frame` — `0` for `Ok`, and a
/// distinct tag per rejection, since `hypervisor::grant_map` hands the caller the specific
/// `P2mError` back. Read straight off `p2m::can_acquire`, the seam the acquire itself routes
/// through, so the observable cannot drift from the guard (#55).
fn acquire_tag(hv: &Hypervisor, frame: u32, ty: Option<PageType>) -> u64 {
    use hv_core::p2m::P2mError;
    match hv.p2m().can_acquire(frame, ty) {
        Ok(()) => 0,
        Err(P2mError::WrongState) => 1,
        Err(P2mError::TypePinned) => 2,
        Err(P2mError::WxConflict) => 3,
        Err(P2mError::Overflow) => 4,
        Err(_) => 5,
    }
}

/// [`obs_plus`] with its optional components toggleable — so each non-vacuity test can drop exactly
/// one and watch step consistency *break*.
fn obs_plus_impl(hv: &Hypervisor, a: Dom, surface: Surface) -> Vec<u64> {
    let e = hv.evtchn();
    let g = hv.grant();
    let p = hv.p2m();
    let n = hv.domain_count() as Dom;
    let mut k = obs(hv, a);

    // `a`'s **own authority** — excluded from the local-respect `obs` (it is `a`'s power over
    // *others*, not `a`'s protected state), but the confidentiality surface must carry it, or step
    // consistency is *false*: a guard reads it, so two `obs`-equal states with different authority
    // fire the guarded transition differently. Exactly the instantiation's forced corrections —
    // `may_create[a]` (creation), `controls[·][a]` (who controls `a`; affinity/destroy of `a`), and
    // `controls[a][·]` (whom `a` controls; `a`'s own destroy authority — the outgoing analogue).
    if surface.authority {
        k.push(0xD_0007);
        k.push(hv.may_create(a) as u64);
        // Incoming: who controls `a` — **also with provenance**. The first cut of ⑥ recorded
        // provenance for the outgoing row only, on the argument that `a` knows whether it created
        // `c` itself but is passive in a delegation *to* it. That was wrong, and the depth-4
        // delegation sweep proved it: the orphan-sweep cascades away an incoming `Via(d)` edge when
        // `d` is destroyed, while an incoming `Root` survives — so two states whose incoming rows
        // agree as booleans take `DomainDestroy{target: d}` to different successors. `a` observes
        // the difference (it is `a`'s own controller set, in `obs`), so the faithful record is the
        // provenance, on **both** rows. Same aggregate-projection trap as ②′-(e), made twice.
        for b in 0..n {
            k.push(control_tag(hv, b, a, surface.provenance));
        }
        for c in 0..n {
            // Outgoing: whom `a` controls — and **with what provenance** (⑥). Presence alone is
            // too coarse: a `Root` edge (`a` created `c`) survives its delegator's teardown,
            // while a `Via` edge (`a` was delegated control of `c`) is cascaded away when the
            // delegator dies or revokes (`sweep_orphaned_control_edges`). Two states in which `a`
            // holds a present-but-differently-rooted edge over `c` are otherwise `obs⁺`-equal,
            // yet `DomainDestroy{target: delegator}` strips the edge in one and not the other —
            // a step-consistency violation the boolean projection hid. `a` genuinely knows the
            // difference: it either created `c` itself or did not. Same shape as ②′-(e), where
            // the frame's aggregate `refs` hid *which* grantee had linked.
            //
            // The delegator's **identity** inside `Via(d)` is deliberately *not* recorded — `a`
            // is passive in `ControlGrant{to: a}` and learns no `d` from any outcome, so
            // recording it would over-approximate the observable exactly as the raw frame owner
            // did in ②′-(a). `Root` vs `Via` is the tightest faithful projection.
            k.push(control_tag(hv, a, c, surface.provenance));
        }
    }

    // **Every domain's liveness** (⑥, the guard-observability audit). `obs(a)` carries only `a`'s
    // *own* liveness — correct for the integrity surface, since a peer's birth or death touches
    // none of `a`'s resources. But four guards read a *named peer's* liveness and report the
    // result to the caller, so `a` genuinely **learns** it, and the confidentiality surface must
    // say so or step consistency is *false*:
    //
    // * `DomainCreate{target}` → `AlreadyAlive` (the target must be `Dead`);
    // * `GrantAccess{grantee}` → `NotAlive` (`reject_dead_target`);
    // * `EvtchnAllocUnbound{remote}` → `NotAlive` (`reject_dead_target`);
    // * `ControlGrant{to}` → `NotAlive` (a capability cannot rest on a `Dead` holder).
    //
    // Each is a one-hypercall probe of an arbitrary slot's liveness, gated by **no** capability —
    // so domain liveness is, factually, *public* in Baleen, and `obs⁺` is the upper bound on what
    // `a` can learn. None of the four can be *removed* the way ②′-(c) removed `DomainBusy`: each
    // is what keeps `DeadDomainReferenced` / `ControlEdgeDeadEndpoint` standing invariants, so
    // force-completing would let a reference outlive the incarnation it named (domid-reuse
    // unsoundness) or, for `AlreadyAlive`, silently reincarnate a *live* peer. Refusal also
    // strands nothing — the caller keeps every resource and may retry. So by design-lesson #62
    // this is the observe case, not the remove case; what is new here is that the state observed
    // belongs to a **third** principal, which is why it is a declared disclosure rather than a
    // closed channel (`docs/TIER-D-NONINTERFERENCE.md` §4b/F1).
    if surface.peer_liveness {
        k.push(0xD_0008);
        for b in 0..n {
            k.push(hv.is_live(b) as u64);
        }
    }

    // **The inbound invitation closure** (⑥) — for every *other* domain's port, whether it stands
    // `Unbound{remote: a}`: a half-open invitation addressed to `a`. This is the exact predicate
    // `evtchn::bind_interdomain` refuses on ("half-open and waiting for exactly us"), so `a` learns
    // it by trying to bind (`Ok` vs `WrongState`) — and without it step consistency is *false* (two `obs⁺(a)`-equal
    // states, one where a created peer has opened a port toward `a` and one where it has not, take
    // `EvtchnBindInterdomain{remote, remote_port}` to different successors, since success writes an
    // `Interdomain` port into `obs(a)`).
    //
    // This is the **event-channel twin of the grant read-closure** below, and it is *not* a
    // third-party leak: the observed state is an invitation the peer deliberately addressed to `a`,
    // exactly as a grant row naming `a` as grantee is. Its exclusion from the integrity `obs` is
    // the same call for the same reason — a peer freely offering itself to `a` moves it, and a
    // domain cannot stop others revealing themselves to it (design-lesson #58: the confidentiality
    // surface is strictly wider than the integrity one). Only the invited port's `(owner, port)`
    // identity is recorded, which is all `bind_interdomain` names.
    if surface.invitations {
        k.push(0xD_0009);
        let mut invites: Vec<[u64; 2]> = Vec::new();
        for b in 0..n {
            if b == a {
                continue; // `a`'s own ports are already in `obs(a)`.
            }
            for port in 0..e.port_count(b) as u32 {
                if e.state_of(b, port) == Some(PortState::Unbound { remote: a }) {
                    invites.push([u64::from(b), u64::from(port)]);
                }
            }
        }
        invites.sort_unstable();
        k.push(invites.len() as u64);
        for iv in invites {
            k.extend(iv);
        }
    }

    k.push(0xD_0006);
    let mut rcaps: Vec<[u64; 7]> = Vec::new();
    for grantor in 0..n {
        for gref in 0..g.entry_count(grantor) as u32 {
            if let Some((grantee, frame, ro, ..)) = g.grant_entry(grantor, gref) {
                if grantee == a {
                    // The **StaleGrant status** — the boolean `owner_of(frame) == grantor` — is
                    // exactly what `a` learns by mapping/copying (`hypervisor::grant_map` returns
                    // `Ok` iff it holds, `Err(StaleGrant)` otherwise). NOT the owner's *identity*:
                    // `a` never reads who owns the frame, only whether its map succeeds. Exposing
                    // the raw owner over-approximates the observable and leaks a *third* domain's
                    // identity into `a`'s read-cap when a grant names a frame that domain owns —
                    // which, under dynamic frame ownership (`P2mAllocate`/`GrantAccess` of an
                    // unowned frame), breaks step consistency (a peer's invisible allocation flips
                    // the owner). The boolean is the faithful confidentiality surface.
                    let owns = (p.owner_of(frame) == Some(grantor)) as u64;
                    // The **acquire outcome** on the grantor's frame — the second half of what a
                    // `GrantMap` tells `a`, and the one the first cut of ⑥ missed (the depth-4
                    // page-table sweep found it). `hypervisor::grant_map` takes the backing page
                    // reference on the **grantor's** frame — `get_type(frame, Writable)` for a
                    // writable map, `get(frame)` for a read-only one — and hands `a` the resulting
                    // `P2mError` verbatim. So `a` learns whether that frame is currently a live
                    // page table, executable, or free, *without owning it*: pin the grantor's frame
                    // as an L1 table and `a`'s writable map flips from `Ok` to `TypePinned`.
                    //
                    // Both variants are recorded because `a` chooses `writable` per call and so can
                    // read either. The tags come from `p2m::can_acquire`, the seam `get`/`get_type`
                    // themselves route through, so the observable cannot drift from the guard (#55)
                    // — and it is the *outcome*, not the frame's counts, keeping this the tightest
                    // faithful projection (②′-(a)).
                    //
                    // **Gated on `owns`, because `grant_map` short-circuits.** The `StaleGrant`
                    // check runs *before* the acquire, so on a stale grant `a` is told `StaleGrant`
                    // and learns nothing whatever about the frame's type. Recording the acquire
                    // outcome unconditionally therefore over-approximates — and breaks step
                    // consistency in the other direction, by leaking whether some *third* domain
                    // has allocated that frame yet (a free frame acquires `WrongState`, an
                    // allocated one `Ok`). Exactly ②′-(a)'s trap, reached from the opposite side:
                    // under-recording hides a channel, over-recording invents one.
                    let (acq_w, acq_r) = if owns == 1 && surface.acquire_guard {
                        (
                            acquire_tag(hv, frame, Some(PageType::Writable)),
                            acquire_tag(hv, frame, None),
                        )
                    } else {
                        (0, 0)
                    };
                    rcaps.push([
                        u64::from(grantor),
                        u64::from(gref),
                        u64::from(frame),
                        ro as u64,
                        owns,
                        acq_w,
                        acq_r,
                    ]);
                }
            }
        }
    }
    rcaps.sort_unstable();
    k.push(rcaps.len() as u64);
    for rc in rcaps {
        k.extend(rc);
    }

    // **The device namespace, as far as `a` can resolve it** (SMMU rung 4). `obs(a)` carries only
    // the devices `a` *holds* — correct for integrity, since a device someone else holds writes
    // none of `a`'s memory. But `DeviceAssign`'s exclusivity guard reads a device's holder and
    // reports the result to the caller, so a controller genuinely **learns** it, and the
    // confidentiality surface must say so or step consistency is *false*.
    //
    // This is the ⑥/F1 repair (record the disclosure), not the ⑥/F4 one (partition the resource),
    // and the difference between the two cases is worth naming because it decides which is
    // honest. `sched::run`'s `PcpuBusy` reads *which domain* occupies a pCPU — an identity `obs⁺`
    // could only carry by declaring the entire schedule public, so ⑥ partitioned instead.
    // `DeviceAssign`'s `Busy` reads something `obs⁺` can carry **in full and exactly**
    // ([`device_tag`]): free, taken-by-a-stranger, or taken-by-a-named-domain-`a`-controls. There
    // is no residue left over to abstract away, so recording it is the complete repair rather than
    // a declaration standing in for one.
    //
    // The guard cannot be *removed* the way ②′-(c) removed `DomainBusy`: re-pointing a held device
    // instead of refusing would aim a live bus master at a different domain's memory with the
    // previous holder never quiesced — so by design-lesson #62 this is the observe case, not the
    // remove case. What the honest reading amounts to: **Baleen's device namespace is
    // free/taken-public to any domain that holds a control edge**, alongside the public domid
    // namespace (⑥/F1). Note it is strictly *narrower* than that one — a domain controlling
    // nothing is refused at the authority gate and learns nothing at all — which is a consequence
    // of `DeviceAssign` naming its assignee and `DeviceRelease` its holder, so both gates settle
    // before the device table is read.
    if surface.devices {
        k.push(0xD_000A);
        for dev in 0..hv.device().device_count() as u16 {
            k.push(device_tag(hv, dev, a));
        }
    }
    k
}

/// A local-respect counterexample: actor `actor` had no authorized channel to observer
/// `observer`, yet `transition` changed `obs(observer)`.
#[derive(Clone, Debug)]
pub struct NiViolation {
    /// The domain the transition is attributed to (its `caller`, or for the async agent the
    /// domain it raises into — the `transition_actor` projection).
    pub actor: Dom,
    /// The domain whose observation changed without authorization.
    pub observer: Dom,
    /// The transition that caused it.
    pub transition: Transition,
    /// The transition path from `new()` to the pre-state where it happened.
    pub trace: Vec<Transition>,
}

/// The domain a [`Transition`] is **attributed to** for the local-respect check — the actor
/// `b` in `¬(b ⇝ a) ⟹ obs(a)` unchanged.
///
/// A guest hypercall is attributed to its `caller`. The async EL2 agent
/// ([`Transition::RaiseVcpuVirq`]) is not guest-issued, but for the isolation question the
/// bridge asks — *can this transition move some other domain's observation?* — the domain
/// whose state it touches is the right principal: it raises a virq on `dom`'s own port, so
/// attributing it to `dom` and checking every observer `a ≠ dom` is exactly the test that the
/// raise leaks into no *other* domain. (Whether `dom` "authorized" its own timer is not an
/// isolation concern — a domain observing its own state move is definitionally fine.)
fn transition_actor(t: &Transition) -> Dom {
    match t {
        Transition::Guest { caller, .. } => *caller,
        Transition::RaiseVcpuVirq { dom, .. } => *dom,
    }
}

/// The result of a non-interference sweep.
#[derive(Clone, Debug)]
pub struct NiOutcome {
    /// Distinct reachable states swept.
    pub states: usize,
    /// `(state, transition, observer)` triples checked.
    pub checks: u64,
    /// Of those, how many actually exercised the property — the actor had **no** authorized
    /// channel to the observer (so a change *would* be a violation). A sweep whose
    /// `unauthorized_checks` is 0 proved nothing; this is the anti-vacuity witness.
    pub unauthorized_checks: u64,
    /// The first local-respect violation found, or `None` if the property holds.
    pub violation: Option<NiViolation>,
}

/// Enumerate the reachable states of `cfg` (BFS, dedup on [`state_key`]), returning each as
/// a concrete [`Hypervisor`] together with the shortest hypercall trace that reaches it — so
/// the non-interference sweep can drive every transition from every reachable state and
/// report a reproducible counterexample. Mirrors [`crate::enumerate::enumerate`]'s frontier
/// loop; stops at `cfg.max_states`.
fn reachable(cfg: &Config) -> Vec<(Hypervisor, Vec<Transition>)> {
    let universe = transitions(cfg);
    let init = Hypervisor::new(
        cfg.domains,
        cfg.ports,
        cfg.grants,
        cfg.vcpus,
        cfg.pcpus,
        cfg.frames,
        cfg.devices,
    );
    let mut seen: HashMap<Vec<u64>, Vec<Transition>> = HashMap::new();
    seen.insert(state_key(&init), Vec::new());
    let mut frontier = vec![(init, Vec::new())];
    for _ in 0..cfg.depth {
        let mut next = Vec::new();
        for (hv, trace) in &frontier {
            for &transition in &universe {
                let mut h = hv.clone();
                let _: Result<TransitionOutcome, _> = h.apply(transition);
                let key = state_key(&h);
                if !seen.contains_key(&key) {
                    if seen.len() >= cfg.max_states {
                        continue;
                    }
                    let mut t = trace.clone();
                    t.push(transition);
                    seen.insert(key, t.clone());
                    next.push((h, t));
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    // `seen` holds a shortest trace to every reachable state; materialize each concrete
    // `Hypervisor` by replaying its trace from `new()`. Replay (rather than retaining every
    // layer's states in memory during BFS) keeps the sweep's footprint the frontier, not the
    // whole reachable set — the states are cheap to rebuild at these sizes.
    seen.into_values()
        .map(|trace| {
            let mut h = Hypervisor::new(
                cfg.domains,
                cfg.ports,
                cfg.grants,
                cfg.vcpus,
                cfg.pcpus,
                cfg.frames,
                cfg.devices,
            );
            for &transition in &trace {
                let _: Result<TransitionOutcome, _> = h.apply(transition);
            }
            (h, trace)
        })
        .collect()
}

/// Run the non-interference bridge over `cfg` with the channel relation `ch`: for every
/// reachable state, every transition in the op universe, and every observer `a` distinct
/// from the actor `b`, check **local respect** — `¬(b ⇝ a) ⟹ obs(a)` unchanged by the step.
///
/// Returns the first counterexample (with a reproducing trace) or `None`, plus coverage
/// counters. With `ch = Channels::full()` on a sound model this returns `violation: None`
/// and a positive `unauthorized_checks` (the property held, non-vacuously). Dropping a term
/// from `ch` makes the check *find* the flow that term governs — the non-vacuity discipline.
pub fn check(cfg: &Config, ch: Channels) -> NiOutcome {
    let universe = transitions(cfg);
    let states = reachable(cfg);
    let n = cfg.domains as Dom;
    let mut checks = 0u64;
    let mut unauthorized_checks = 0u64;

    for (hv, trace) in &states {
        for &transition in &universe {
            let actor = transition_actor(&transition);
            // Project every observer's pre-image once, then compare against the post-image.
            let before: Vec<Vec<u64>> = (0..n).map(|a| obs(hv, a)).collect();
            let mut h = hv.clone();
            let _: Result<TransitionOutcome, _> = h.apply(transition);
            for a in 0..n {
                if a == actor {
                    continue;
                }
                checks += 1;
                if ch.authorized(hv, actor, a) {
                    continue;
                }
                unauthorized_checks += 1;
                let after = obs(&h, a);
                if after != before[a as usize] {
                    return NiOutcome {
                        states: states.len(),
                        checks,
                        unauthorized_checks,
                        violation: Some(NiViolation {
                            actor,
                            observer: a,
                            transition,
                            trace: trace.clone(),
                        }),
                    };
                }
            }
        }
    }
    NiOutcome {
        states: states.len(),
        checks,
        unauthorized_checks,
        violation: None,
    }
}

/// A step-consistency counterexample: two reachable states agree on `obs⁺(observer)` and
/// `obs⁺(actor)`, yet `transition` drives them to *different* `obs⁺(observer)`. The witness that
/// the observation is **not** a function of the observed inputs — an unobserved dependence.
#[derive(Clone, Debug)]
pub struct ScViolation {
    /// The acting principal.
    pub actor: Dom,
    /// The observer whose successor observation was not determined.
    pub observer: Dom,
    /// The transition applied to both states.
    pub transition: Transition,
    /// Traces to the two pre-states that share an `obs⁺(observer)`/`obs⁺(actor)` but diverge.
    pub trace_a: Vec<Transition>,
    pub trace_b: Vec<Transition>,
}

/// The result of a step-consistency sweep.
#[derive(Clone, Debug)]
pub struct ScOutcome {
    /// Distinct reachable states swept.
    pub states: usize,
    /// `(state, transition, observer)` triples checked.
    pub checks: u64,
    /// How many checks landed in an already-populated `(obs⁺(observer), obs⁺(actor))` class — the
    /// cases where consistency has teeth (a second genuinely distinct state had to agree). A sweep
    /// with none proved nothing.
    pub witnessed_classes: u64,
    /// The first step-consistency violation, or `None` if the property holds.
    pub violation: Option<ScViolation>,
}

/// Run the **step-consistency** sweep over `cfg` — the confidentiality dual of [`check`], and the
/// real-code counterpart of `noninterference_instantiation.rs`'s `step_consistent_holds`. For every
/// transition and **every** observer `a` — *including the actor itself* — it verifies that `obs⁺(a)`
/// after the step is a **function of** `(obs⁺(a), obs⁺(actor))` before it: two reachable states that
/// `a` and the actor cannot tell apart are driven to the same successor observation. (This is exactly
/// the unwinding *step-consistency* condition; unlike local respect it needs no channel relation — it
/// is a pure determinism property, and unlike local respect it does **not** exclude the actor: `a`
/// learns most of all from its own hypercall results, so `a == actor` is where every guard whose
/// refusal the caller reads back lives. That case was skipped until ⑥, which is how four defects
/// stayed hidden at depth 2–5 — see `docs/TIER-D-NONINTERFERENCE.md` §4b/F0.) This is also where the
/// `DomainDestroy` **read direction** lives: destroying
/// `a`'s grantor revokes `a`'s read-cap, and step consistency asks that two `obs⁺(a)`-equal states
/// lose it *together*.
///
/// Implemented by grouping: for each `(transition, a)`, map each pre-state to the key
/// `(obs⁺(a), obs⁺(actor))` and require every state in a key-class to yield the same
/// `obs⁺(step, a)`. `O(states × transitions × observers)` — no quadratic pairing. Returns the first
/// key-class that maps to two successors, with both reproducing traces.
pub fn check_step_consistency(cfg: &Config) -> ScOutcome {
    check_step_consistency_with(cfg, obs_plus)
}

/// An **interner** for observation vectors: each distinct `obs⁺` value is stored once and
/// thereafter referred to by a `u32` id. Purely a memory optimization with **no effect on what is
/// checked** — ids compare equal exactly when the vectors do, so every class and every comparison
/// is identical to the `Vec`-keyed form.
///
/// It matters because the sweep is grouping-based: the class map holds one key per *state*, and a
/// key is two whole observations, with a third as the value — `O(states × |obs⁺|)` **per
/// (transition, observer) pair**. Interning collapses that to one copy per *distinct* observation,
/// and distinct observations are far fewer than states (a populated class is precisely several
/// states sharing one — what `witnessed_classes` counts). ⑥ widened `obs⁺` by four components, so
/// this is what keeps the class map from growing with the surface.
///
/// It does **not** address the sweep's actual memory ceiling, which is [`reachable`] materialising
/// every reachable `Hypervisor` at once (~13 GB at the deep four-domain config, unchanged by ⑥ and
/// unchanged by this) — that is a separate, pre-existing cost, recorded here so the next person
/// profiling this looks in the right place.
#[derive(Default)]
struct ObsInterner {
    ids: HashMap<Vec<u64>, u32>,
}

impl ObsInterner {
    /// The id of `v`, assigning a fresh one if unseen. Equal vectors always get equal ids.
    fn intern(&mut self, v: Vec<u64>) -> u32 {
        let next = self.ids.len() as u32;
        *self.ids.entry(v).or_insert(next)
    }
}

/// A step-consistency equivalence class: `(obs⁺(observer), obs⁺(actor))` before → the observed
/// `(obs⁺(observer) after, reproducing trace)`, all three interned. Every state in a class must
/// share the successor.
type ScClass = HashMap<(u32, u32), (u32, Vec<Transition>)>;

/// [`check_step_consistency`] over an arbitrary observation projection — so the non-vacuity test
/// can supply an authority-stripped `obs⁺` and watch the property fail.
fn check_step_consistency_with(
    cfg: &Config,
    proj: impl Fn(&Hypervisor, Dom) -> Vec<u64>,
) -> ScOutcome {
    let universe = transitions(cfg);
    let states = reachable(cfg);
    let n = cfg.domains as Dom;
    let mut checks = 0u64;
    let mut witnessed_classes = 0u64;

    for &transition in &universe {
        let actor = transition_actor(&transition);
        for a in 0..n {
            // key: (obs⁺(a), obs⁺(actor)) before → value: (obs⁺(a) after, trace) — all three
            // interned to ids, so the map holds `u32`s rather than whole observations. Equal ids
            // iff equal vectors, so this changes nothing about what is compared.
            let mut class: ScClass = HashMap::new();
            let mut interner = ObsInterner::default();
            for (hv, trace) in &states {
                let key = (
                    interner.intern(proj(hv, a)),
                    interner.intern(proj(hv, actor)),
                );
                let mut h = hv.clone();
                let _: Result<TransitionOutcome, _> = h.apply(transition);
                let after = interner.intern(proj(&h, a));
                checks += 1;
                match class.get(&key) {
                    None => {
                        class.insert(key, (after, trace.clone()));
                    }
                    Some((prev_after, prev_trace)) => {
                        witnessed_classes += 1;
                        if *prev_after != after {
                            return ScOutcome {
                                states: states.len(),
                                checks,
                                witnessed_classes,
                                violation: Some(ScViolation {
                                    actor,
                                    observer: a,
                                    transition,
                                    trace_a: prev_trace.clone(),
                                    trace_b: trace.clone(),
                                }),
                            };
                        }
                    }
                }
            }
        }
    }
    ScOutcome {
        states: states.len(),
        checks,
        witnessed_classes,
        violation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hv_core::p2m::PtLevel;

    /// A small integrated **two-domain** config that forms cross-domain channels: dom0 boots
    /// Live and can create dom1, with grant + evtchn + sched + p2m + create/destroy so
    /// grants, event channels, control edges, and teardown all arise. Kept shallow enough to
    /// sweep the whole `states × transitions × observers` product in CI time. (Two domains
    /// exercise every *direct* channel; the intransitive teardown-reach term needs a third
    /// observer — see [`ni_cfg3`].)
    fn ni_cfg(depth: u32) -> Config {
        Config {
            domains: 2,
            devices: 0,
            ports: 2,
            grants: 2,
            vcpus: 1,
            pcpus: 1,
            frames: 2,
            levels: vec![PtLevel::L1, PtLevel::L2],
            handles: 3,
            evtchn: true,
            grant: true,
            sched: true,
            p2m: true,
            create: true,
            destroy: true,
            delegate: false,
            device: false,
            async_agent: false,
            drive_execute: false,
            mediated_frames: false,
            mediated_pcpus: false,
            depth,
            max_states: 200_000,
            symmetry: false,
        }
    }

    /// A **three-domain** config, lean (grant + evtchn + create/destroy, `may_create`
    /// mintable so a created domain can itself create a third) — the smallest universe that
    /// builds the **intransitive** teardown-reach witness: dom0 creates dom1 with
    /// `may_create`, dom1 creates dom2 (so dom1 controls dom2 but *not* dom0), dom0 opens a
    /// grant/port toward dom2, and dom1 destroys dom2 — whose teardown clears dom0's outbound
    /// reference, moving `obs(dom0)` though dom1 has no *direct* channel to dom0. Three
    /// domains is where local respect stops being a one-hop property.
    fn ni_cfg3(depth: u32) -> Config {
        Config {
            domains: 3,
            devices: 0,
            ports: 1,
            grants: 1,
            vcpus: 0,
            pcpus: 0,
            frames: 1,
            levels: vec![],
            handles: 2,
            evtchn: true,
            grant: true,
            sched: false,
            p2m: false,
            create: true,
            destroy: true,
            delegate: false,
            device: false,
            async_agent: false,
            drive_execute: false,
            mediated_frames: false,
            mediated_pcpus: false,
            depth,
            max_states: 400_000,
            symmetry: false,
        }
    }

    /// `ni_cfg` with the async EL2 agent folded into the swept universe (Phase I-1c).
    fn ni_cfg_async(depth: u32) -> Config {
        Config {
            async_agent: true,
            ..ni_cfg(depth)
        }
    }

    /// **The async agent respects isolation (closes ledger 6c's NI half).** With
    /// `Transition::RaiseVcpuVirq` in the swept universe — attributed to the domain it touches
    /// ([`transition_actor`]) — local respect still holds under the full channel relation: the
    /// raise moves only its own domain's port, so no observer `a ≠ dom` sees a change. This is
    /// the machine-checked form of "same-domain-only, no cross-domain flow", and it is
    /// non-vacuous (the raise is checked against unauthorized observers over every state where a
    /// guest has bound a virq). Had the async path leaked into another domain, this would catch
    /// it — the point of driving it through the bridge rather than asserting it by construction.
    #[test]
    fn local_respect_holds_with_the_async_agent_in_the_universe() {
        assert!(
            transitions(&ni_cfg_async(3))
                .iter()
                .any(|t| matches!(t, Transition::RaiseVcpuVirq { .. })),
            "the async agent transition is not in the NI universe"
        );
        let out = check(&ni_cfg_async(3), Channels::full());
        assert!(
            out.violation.is_none(),
            "the async agent created an unauthorized cross-domain flow: {:?}",
            out.violation.unwrap()
        );
        assert!(
            out.unauthorized_checks > 1_000,
            "async NI sweep near-vacuous: only {} unauthorized checks over {} states",
            out.unauthorized_checks,
            out.states
        );
    }

    /// **The bridge, green (CI size).** Over every reachable state of the two-domain
    /// integrated config, every transition, and every observer, the full authorized-channel
    /// relation makes local respect hold: no domain's observation moves without an authorized
    /// channel from the actor — non-interference on the *real* code at small size.
    /// Non-vacuously: the property was exercised on thousands of *unauthorized* (state,
    /// transition, observer) triples (actor had no channel to the observer, yet obs held).
    #[test]
    fn local_respect_holds_on_real_code() {
        let out = check(&ni_cfg(3), Channels::full());
        assert!(
            out.violation.is_none(),
            "local-respect violation: {:?}",
            out.violation.unwrap()
        );
        // Anti-vacuity: the sweep must actually test the unauthorized case, or a
        // trivially-true channel relation would "pass".
        assert!(
            out.unauthorized_checks > 1_000,
            "sweep was near-vacuous: only {} unauthorized checks over {} states",
            out.unauthorized_checks,
            out.states
        );
    }

    /// **Non-vacuity — the grant channel is load-bearing.** Drop the consent term and the
    /// check must *find* a flow: a peer mapping a grant `a` offered it moves `a`'s frame
    /// references / grant map-counts, which without the grant term now looks unauthorized.
    /// Proves the check has teeth (it detects real interference) and that the grant term is
    /// exactly the authorization for that flow — the Tier-C "remove the fix → counterexample"
    /// discipline applied to a channel term.
    #[test]
    fn dropping_grant_channel_is_caught() {
        let ch = Channels {
            grant: false,
            ..Channels::full()
        };
        assert!(
            check(&ni_cfg(3), ch).violation.is_some(),
            "dropping the grant channel should surface an interference flow, but none was found"
        );
    }

    /// **Non-vacuity — the evtchn channel is load-bearing.** Drop the signal term and a peer
    /// sending/binding on a channel `a` is party to moves `a`'s port state — now flagged.
    #[test]
    fn dropping_evtchn_channel_is_caught() {
        let ch = Channels {
            evtchn: false,
            ..Channels::full()
        };
        assert!(
            check(&ni_cfg(3), ch).violation.is_some(),
            "dropping the evtchn channel should surface an interference flow, but none was found"
        );
    }

    /// **Non-vacuity — the control channel is load-bearing.** Drop the authority term and a
    /// controller destroying / setting affinity on the domain it controls moves that domain's
    /// observation — now flagged.
    #[test]
    fn dropping_control_channel_is_caught() {
        let ch = Channels {
            control: false,
            ..Channels::full()
        };
        assert!(
            check(&ni_cfg(3), ch).violation.is_some(),
            "dropping the control channel should surface an interference flow, but none was found"
        );
    }

    /// **The intransitive finding — the teardown-reach term is real and load-bearing.** In
    /// three domains, dropping *only* the `DomainDestroy` two-hop term surfaces a
    /// counterexample: a domain destroying a peer it controls clears a *third* domain's
    /// outbound reference to that peer, moving the third domain's observation though the
    /// actor has no direct channel to it. This is exactly the intransitive
    /// non-interference structure — the bridge *finding* the one place the channel relation
    /// cannot be purely direct, on real code, before the Verus proof. Returns on the first
    /// counterexample, so it is fast despite the three-domain universe.
    #[test]
    fn dropping_teardown_reach_is_caught() {
        let ch = Channels {
            teardown_reach: false,
            ..Channels::full()
        };
        // Depth 4 already reaches the witness (dom0 creates dom1 with `may_create`; dom1
        // creates dom2; dom0 opens a reference toward dom2 — a depth-3 pre-state — then dom1
        // destroys dom2), so the counterexample surfaces without the full deep sweep.
        let out = check(&ni_cfg3(4), ch);
        assert!(
            out.violation.is_some(),
            "dropping the teardown-reach term should surface the intransitive DomainDestroy \
             flow, but none was found"
        );
    }

    /// **②′-(c)'s forced finding — the teardown-*borrow* term, and it is load-bearing.**
    /// Force-reclaim created an integrity channel that refuse-if-busy had made unreachable:
    /// destroying `c` yanks the map `a` held over one of `c`'s frames, and `a` observes the
    /// loss (its handle-indexed held-maps move). The actor `b` need have no direct channel to
    /// `a` at all — only control of `c`. Dropping *only* this sub-term surfaces the flow.
    ///
    /// Built directly rather than swept: the witness needs four domains, a delegation (so the
    /// actor controls `c` but *not* `a`), an allocation, a grant, a map and a destroy — deeper
    /// than the sweep reaches. It was originally recorded as the integrity twin of PR #80's
    /// finding (3) ("teardown reach extends to the read direction"); ⑦ **retracted that finding** —
    /// it was an artifact of the Verus carrier using one read-closed `obs` for both unwinding
    /// conditions, and a read-cap movement is a `step_consistent` obligation, not an integrity one.
    /// This term is what genuinely survives on the integrity side, and Verus now forces it
    /// independently over its own carrier (`noninterference_instantiation.rs::teardown_borrow`,
    /// docs §5h) — so the two artifacts agree on it for the same reason rather than by analogy.
    #[test]
    fn dropping_teardown_borrow_is_caught() {
        use hv_core::HvCall;
        let (a, b, c) = (1u16, 3u16, 2u16);
        let mut h = Hypervisor::new(4, 1, 2, 1, 1, 2, 2);
        for t in 1..4u16 {
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: t,
                    may_create: false,
                },
            )
            .unwrap();
        }
        // `c` lends `a` a frame; `a` maps it — `a` now borrows *from* `c`.
        h.dispatch(c, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        h.dispatch(
            c,
            HvCall::GrantAccess {
                gref: 0,
                grantee: a,
                frame: 0,
                readonly: true,
            },
        )
        .unwrap();
        h.dispatch(
            a,
            HvCall::GrantMap {
                grantor: c,
                gref: 0,
                writable: false,
            },
        )
        .unwrap();
        // dom0 delegates control of `c` to `b`, so `b` controls `c` but has no edge to `a`.
        h.dispatch(0, HvCall::ControlGrant { target: c, to: b })
            .unwrap();

        // The relation *without* the new sub-term does not authorize `b` to move `obs(a)` —
        // neither directly (no grant, port, control or creation edge b→a) nor through the
        // outbound teardown term (`a` offered `c` nothing; `c` offered `a`).
        let without = Channels {
            teardown_borrow: false,
            ..Channels::full()
        };
        assert!(
            !without.authorized(&h, b, a),
            "the outbound-only relation should not authorize b ⇝ a here"
        );
        // ...yet the destroy moves `obs(a)`. That is the violation the term must cover.
        let before = obs(&h, a);
        h.dispatch(b, HvCall::DomainDestroy { target: c, now: 0 })
            .unwrap();
        assert_ne!(
            before,
            obs(&h, a),
            "force-reclaim should have moved obs(a) by yanking a's map of c's frame"
        );
    }

    /// The positive half of the above: in the pre-state, the full relation *does* authorize
    /// the flow — so widening the term is what restores local respect rather than merely
    /// hiding the counterexample.
    #[test]
    fn teardown_borrow_authorizes_the_flow_it_names() {
        use hv_core::HvCall;
        let (a, b, c) = (1u16, 3u16, 2u16);
        let mut h = Hypervisor::new(4, 1, 2, 1, 1, 2, 2);
        for t in 1..4u16 {
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: t,
                    may_create: false,
                },
            )
            .unwrap();
        }
        h.dispatch(c, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        h.dispatch(
            c,
            HvCall::GrantAccess {
                gref: 0,
                grantee: a,
                frame: 0,
                readonly: true,
            },
        )
        .unwrap();
        h.dispatch(
            a,
            HvCall::GrantMap {
                grantor: c,
                gref: 0,
                writable: false,
            },
        )
        .unwrap();
        h.dispatch(0, HvCall::ControlGrant { target: c, to: b })
            .unwrap();
        assert!(
            Channels::full().authorized(&h, b, a),
            "the full relation must authorize the teardown-borrow flow"
        );
        // And it is not authorizing everything: an unrelated peer that borrows nothing from
        // any domain `b` controls is still unreachable.
        assert!(
            !Channels::full().authorized(&h, a, b),
            "the term should not authorize the reverse, unrelated direction"
        );
    }

    /// **The bridge, green on three domains (deep sweep).** With the *full* relation —
    /// including the teardown-reach term — local respect holds over the three-domain
    /// universe too, where the intransitive teardown flow is live. Ignored by default
    /// (minutes to sweep the whole product); run in the deep-verification workflow.
    #[test]
    #[ignore = "deep non-interference sweep — run in deep-verify.yml"]
    fn local_respect_holds_three_domains() {
        let out = check(&ni_cfg3(6), Channels::full());
        assert!(
            out.violation.is_none(),
            "local-respect violation (3 domains): {:?}",
            out.violation.unwrap()
        );
        assert!(out.unauthorized_checks > 1_000);
    }

    /// **The bridge, green deeper on two domains (deep sweep).** The CI test runs the
    /// two-domain integrated config at depth 3; this pushes it to depth 6, a far larger
    /// reachable set, still green. Ignored by default; run in the deep-verification workflow.
    #[test]
    #[ignore = "deep non-interference sweep — run in deep-verify.yml"]
    fn local_respect_holds_deep() {
        let out = check(&ni_cfg(6), Channels::full());
        assert!(
            out.violation.is_none(),
            "local-respect violation (deep): {:?}",
            out.violation.unwrap()
        );
        assert!(out.unauthorized_checks > 1_000);
    }

    // ===================================================================================
    // Step consistency (the confidentiality dual) — validating the `DomainDestroy` read
    // direction on real code (the counterpart of `step_consistent_holds`, `obs⁺`).
    // ===================================================================================

    /// How many grants `a` is a *grantee* of (across every grantor's table) — the size of `a`'s
    /// read-closure. Destroying `a`'s grantor (`grant::revoke_all`) drops this.
    fn reads_count(hv: &Hypervisor, a: Dom) -> usize {
        let g = hv.grant();
        let n = hv.domain_count() as Dom;
        (0..n)
            .map(|grantor| {
                (0..g.entry_count(grantor) as u32)
                    .filter(|&gref| {
                        matches!(g.grant_entry(grantor, gref), Some((grantee, ..)) if grantee == a)
                    })
                    .count()
            })
            .sum()
    }

    /// **Step consistency holds on real code — the confidentiality dual, incl. the read direction.**
    /// Over the three-domain universe (where the intransitive read flow is live), `obs⁺(a)` after
    /// any step is a function of `(obs⁺(a), obs⁺(actor))` before it: two states `a` and the actor
    /// cannot distinguish are driven to the same successor observation. This is the real-code form
    /// of `noninterference_instantiation.rs::step_consistent_holds` — and it is **non-vacuous**
    /// (tens of thousands of key-classes hold two or more genuinely distinct states that must, and
    /// do, agree). The `DomainDestroy` **read direction** is inside this sweep: destroying `a`'s
    /// grantor drops `a`'s read-cap, and the sweep confirms two `obs⁺(a)`-equal states lose it
    /// together.
    #[test]
    fn step_consistency_holds_on_real_code() {
        let out = check_step_consistency(&ni_cfg3(3));
        assert!(
            out.violation.is_none(),
            "step-consistency violation: {:?}",
            out.violation.unwrap()
        );
        assert!(
            out.witnessed_classes > 1_000,
            "step-consistency sweep near-vacuous: only {} witnessed classes over {} states",
            out.witnessed_classes,
            out.states
        );
    }

    /// **The read direction is genuinely exercised (non-vacuity of the sweep for it).** Over the
    /// swept product, some `DomainDestroy` by an actor `b` shrinks a *third* domain `a`'s
    /// read-closure — `a` reads from the destroyed `c` (a grant `c` offered `a`), and `revoke_all`
    /// drops it. So the step-consistency sweep is not vacuously true for the read direction: it
    /// really does test that destroying `a`'s grantor moves `obs⁺(a)`, and does so consistently.
    #[test]
    fn the_destroy_read_direction_is_exercised() {
        use hv_core::HvCall;
        let cfg = ni_cfg3(4);
        let states = reachable(&cfg);
        let universe = transitions(&cfg);
        let n = cfg.domains as Dom;
        let mut read_moves = 0u64;
        for (hv, _) in &states {
            for &t in &universe {
                if !matches!(
                    t,
                    Transition::Guest {
                        call: HvCall::DomainDestroy { .. },
                        ..
                    }
                ) {
                    continue;
                }
                let actor = transition_actor(&t);
                for a in 0..n {
                    if a == actor {
                        continue;
                    }
                    let before = reads_count(hv, a);
                    let mut h = hv.clone();
                    if h.apply(t).is_ok() && reads_count(&h, a) < before {
                        read_moves += 1;
                    }
                }
            }
        }
        assert!(
            read_moves > 0,
            "the DomainDestroy read direction was never exercised — the step-consistency sweep \
             is vacuous for it (no destroy shrank a third domain's read-closure)"
        );
    }

    /// **Non-vacuity — the read-closure `obs⁺` must carry the observer's own authority (finding
    /// #1, on real code).** Strip authority (`may_create[a]`, the `controls` rows) back out of
    /// `obs⁺` and step consistency **breaks**: a guarded transition (create / destroy / affinity)
    /// reads authority the projection no longer shows, so two now-"equal" states fire it
    /// differently. This is the enumerator's independent confirmation of the correction the
    /// instantiation's `step_consistent` forced — the confidentiality theorem is *false* under the
    /// authority-excluding observation.
    #[test]
    fn dropping_authority_from_obs_plus_breaks_step_consistency() {
        let out = check_step_consistency_with(&ni_cfg3(3), |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    authority: false,
                    ..Surface::full()
                },
            )
        });
        assert!(
            out.violation.is_some(),
            "stripping authority from obs⁺ should break step consistency (finding #1), but it held"
        );
    }

    /// **Step consistency, green deeper on three domains (deep sweep).** Ignored by default (the
    /// larger reachable set takes longer); run in the deep-verification workflow.
    #[test]
    #[ignore = "deep step-consistency sweep — run in deep-verify.yml"]
    fn step_consistency_holds_three_domains_deep() {
        let out = check_step_consistency(&ni_cfg3(5));
        assert!(
            out.violation.is_none(),
            "step-consistency violation (deep): {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 100_000);
    }

    /// **The read-cap records the StaleGrant *status*, not the owner's identity (the read-closure
    /// real-code fidelity refinement).** `a`'s cross-domain map/copy of a grant it holds learns
    /// exactly whether the grantor still owns the frame (`Ok` vs `Err(StaleGrant)` in
    /// `hypervisor::grant_map`) — never *who* owns it. So `obs⁺(a)`'s read-cap carries the boolean
    /// `owner == grantor`, not the raw owner. This pins the refinement directly (no sweep, so it is
    /// independent of the allocation-contention edge): two states differing *only* in which **third**
    /// domain owns a granted frame — invisible to both grantor and grantee — yield **equal**
    /// `obs⁺(grantee)`. The raw-owner form leaked that identity and broke step consistency (the
    /// depth-4 `GrantAccess` counterexample the four-domain sweep found). The boolean still
    /// distinguishes a *valid* grant from a *stale* one — which is what `a` genuinely observes.
    #[test]
    fn read_cap_records_stale_status_not_owner_identity() {
        use hv_core::HvCall;
        // dom0 = grantor, dom1 = grantee/observer, dom2 & dom3 = candidate third-party owners.
        fn stale_owned_by(third_owner: Dom) -> Hypervisor {
            let mut h = Hypervisor::new(4, 1, 1, 0, 0, 1, 2); // 4 domains, 1 frame
            for t in 1..4u16 {
                // dom0 boots live + privileged; bring the peers up so they can own a frame.
                h.dispatch(
                    0,
                    HvCall::DomainCreate {
                        target: t,
                        may_create: false,
                    },
                )
                .unwrap();
            }
            // dom0 offers dom1 a grant naming frame 0 — offering requires no ownership.
            h.dispatch(
                0,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 1,
                    frame: 0,
                    readonly: false,
                },
            )
            .unwrap();
            // A *third* domain grabs frame 0 (invisible to dom0/dom1): the grant is now stale.
            h.dispatch(third_owner, HvCall::P2mAllocate { mfn: 0 })
                .unwrap();
            h
        }
        let owned_by_2 = stale_owned_by(2);
        let owned_by_3 = stale_owned_by(3);
        // The boolean collapses the third party's identity: dom1 observes the same obs⁺ either way.
        assert_eq!(
            obs_plus(&owned_by_2, 1),
            obs_plus(&owned_by_3, 1),
            "obs⁺(grantee) leaked which third domain owns the granted frame"
        );

        // Non-vacuity: the boolean is not constant — a grant the grantor still backs is observably
        // different (valid vs stale is exactly what `a` learns by mapping).
        let mut valid = Hypervisor::new(4, 1, 1, 0, 0, 1, 2);
        for t in 1..4u16 {
            valid
                .dispatch(
                    0,
                    HvCall::DomainCreate {
                        target: t,
                        may_create: false,
                    },
                )
                .unwrap();
        }
        valid.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap(); // the grantor owns the frame
        valid
            .dispatch(
                0,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 1,
                    frame: 0,
                    readonly: false,
                },
            )
            .unwrap();
        assert_ne!(
            obs_plus(&valid, 1),
            obs_plus(&owned_by_2, 1),
            "obs⁺(grantee) failed to distinguish a valid grant from a stale one"
        );
    }

    fn ni_cfg4_mediated(depth: u32) -> Config {
        // Lean: create + p2m + one grant, no teardown — the allocation-contention channel needs
        // only create (bring domains live) + allocate + grant, so dropping `destroy` and extra grant
        // slots keeps the committed sweep debug-fast while still exercising the read-closure.
        Config {
            domains: 4,
            devices: 0,
            ports: 0,
            grants: 1,
            vcpus: 0,
            pcpus: 0,
            frames: 2,
            levels: vec![],
            handles: 1,
            evtchn: false,
            grant: true,
            sched: false,
            p2m: true,
            create: true,
            destroy: false,
            delegate: false,
            device: false,
            async_agent: false,
            drive_execute: false,
            mediated_frames: true,
            mediated_pcpus: false,
            depth,
            max_states: 2_000_000,
            symmetry: false,
        }
    }

    /// **Step consistency holds with a host-mediated allocator (②′-(b), the read-closure's last
    /// real-code fidelity edge).** With `mediated_frames` on — each domain draws frames from its own
    /// disjoint pool (`P2mAllocate{mfn}` emitted only for `mfn % domains == caller`), modelling the
    /// host that assigns machine frames rather than letting guests race for them — step consistency
    /// **holds** over four domains with dynamic p2m, grants, and create/destroy, non-vacuously (tens
    /// of millions of key-classes). This is where the unmediated model has a counterexample:
    /// `P2mAllocate{mfn}` whose success depends on whether an *invisible* peer already grabbed the
    /// shared frame (see [`an_unmediated_allocator_breaks_step_consistency`]). Baleen's
    /// guest-chosen-`mfn` allocator is a model looseness vs a real gfn→mfn-mediating hypervisor (the
    /// gfn=mfn fence, design-lesson #14e); the contention is the storage-side analogue of the
    /// pcpu-occupancy channel `obs` already abstracts (§2.1). See `docs/TIER-D-NONINTERFERENCE.md`.
    #[test]
    fn step_consistency_holds_with_a_mediated_allocator() {
        let out = check_step_consistency(&ni_cfg4_mediated(3));
        assert!(
            out.violation.is_none(),
            "step-consistency violation under a mediated allocator: {:?}",
            out.violation.unwrap()
        );
        assert!(
            out.witnessed_classes > 100_000,
            "mediated sc sweep near-vacuous: only {} witnessed classes over {} states",
            out.witnessed_classes,
            out.states
        );
    }

    /// **Non-vacuity — the mediation is load-bearing (remove the fix → counterexample).** Turn
    /// `mediated_frames` off and the *same* four-domain config breaks step consistency: some
    /// `P2mAllocate{mfn}` succeeds in one state and fails in another that the actor and observer
    /// cannot distinguish, because an unobserved third domain already owns the contended frame —
    /// flipping a grantee's StaleGrant read-cap. This is the enumerator's confirmation that
    /// guest-chosen-`mfn` allocation contention is a real channel *in the model as written*, and
    /// that mediating it (not merely the (a) boolean read-cap) is what closes the read-closure's
    /// real-code fidelity. The CE transition is a `P2mAllocate`. Ignored by default (the CE needs
    /// four live domains + an allocation + a grant, so it lives at depth 4 — ~25s); run in
    /// deep-verify, like the other deep sweeps.
    #[test]
    #[ignore = "deep — the unmediated contention CE (depth 4); run in deep-verify.yml"]
    fn an_unmediated_allocator_breaks_step_consistency() {
        use hv_core::HvCall;
        let cfg = Config {
            mediated_frames: false,
            mediated_pcpus: false,
            ..ni_cfg4_mediated(4)
        };
        let out = check_step_consistency(&cfg);
        let v = out
            .violation
            .expect("unmediated allocation should break step consistency (the ②′-(b) contention)");
        assert!(
            matches!(
                v.transition,
                Transition::Guest {
                    call: HvCall::P2mAllocate { .. },
                    ..
                }
            ),
            "expected a P2mAllocate counterexample, got {:?}",
            v.transition
        );
    }

    /// Deeper mediated sc sweep — ignored by default (larger reachable set), run in deep-verify.
    #[test]
    #[ignore = "deep mediated step-consistency sweep — run in deep-verify.yml"]
    fn step_consistency_holds_with_a_mediated_allocator_deep() {
        let out = check_step_consistency(&ni_cfg4_mediated(5));
        assert!(
            out.violation.is_none(),
            "step-consistency violation under a mediated allocator (deep): {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 1_000_000);
    }

    /// **The grant-handle read direction, per-domain (the ②′ read-closure fidelity — grant-handle
    /// layer).** With handles a per-domain maptrack, `obs` records the mappings `a` holds indexed by
    /// `a`'s own handle slot, so `GrantUnmap{handle}` is deterministic w.r.t. `obs` — mediated
    /// four-domain step consistency holds with dynamic p2m + grants + create + **destroy**, over the
    /// depth where the *global*-handle model had a `GrantUnmap` counterexample (two maps of one
    /// grant in swapped slots). Non-vacuous (hundreds of millions of key-classes at depth 5).
    #[test]
    #[ignore = "deep — per-domain-handle step consistency with destroy; run in deep-verify.yml"]
    fn step_consistency_holds_per_domain_handles_with_destroy() {
        let cfg = Config {
            destroy: true,
            ..ni_cfg4_mediated(5)
        };
        let out = check_step_consistency(&cfg);
        assert!(
            out.violation.is_none(),
            "per-domain-handle step-consistency violation (destroy on): {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 10_000_000);
    }

    // ─── ⑥ THE GUARD-OBSERVABILITY AUDIT ────────────────────────────────────────────────
    //
    // Every guard is checked against the rule ②′-(c)/(e) established (design-lesson #62): a
    // refusal conditioned on state the caller CAN observe is a legitimate error; one conditioned
    // on state it CANNOT observe is a covert channel, and the repair follows from which. The
    // audit's first act was to fix the *checker*: `check_step_consistency_with` used to skip the
    // `observer == actor` case, while the obligation it bridges to
    // (`noninterference_instantiation.rs::step_consistent`) quantifies over **every** `a`,
    // including the actor. That skip hid four defects, all at depth 2–5 — not past the sweep, but
    // invisible to it. Each is now closed and pinned below.

    /// The delegation forest in a **step-consistency** config — `ControlGrant`/`ControlRevoke`
    /// had `delegate: false` in every NI config, so the delegation guards had never been swept at
    /// all (⑥). Three domains so a delegated `Via` edge and its delegator's teardown coexist.
    fn ni_cfg3_delegate(depth: u32) -> Config {
        Config {
            delegate: true,
            ..ni_cfg3(depth)
        }
    }

    /// A **device-assignment** config (SMMU rung 4). Three domains, because assignment is
    /// authority-gated with **no self-exemption**: dom0 must create 1 and 2 to control them, and
    /// the interesting confidentiality question — a device held by a domain the observer does
    /// *not* control — needs a third principal to hold it. One device, since the guard is
    /// per-device and a second squares the state space without adding a case.
    ///
    /// `delegate` is on so a delegated controller can assign too, and `destroy` so the teardown
    /// sweep is in the swept universe — the sweep is the transition that moves `obs(a)` for the
    /// *holder*, and local respect has to be true of it as much as of the assign.
    fn ni_cfg_device(depth: u32) -> Config {
        Config {
            device: true,
            devices: 1,
            delegate: true,
            ..ni_cfg3(depth)
        }
    }

    /// **Local respect holds with device assignment in the universe (SMMU rung 4).** A device
    /// changing hands moves `obs` of the domain that gains or loses it — and every transition that
    /// can do so is issued by that domain itself, by a domain that *controls* it, or is that
    /// domain's own teardown. All three are already authorized channels (`control` covers the
    /// controller; a domain is always authorized to itself), so **no new `Channels` term is
    /// needed** — recorded as a result rather than assumed, since the alternative (a device flow
    /// with no channel behind it) is exactly the shape this sweep exists to catch.
    ///
    /// The non-vacuity floor matters more than usual here: a device the observer does not hold
    /// contributes nothing to `obs`, so most triples are trivially satisfied, and a sweep that
    /// never reached a *held* device would prove nothing at all.
    #[test]
    fn local_respect_holds_with_device_assignment() {
        let cfg = ni_cfg_device(4);
        assert!(
            transitions(&cfg).iter().any(|t| matches!(
                t,
                Transition::Guest {
                    call: hv_core::HvCall::DeviceAssign { .. },
                    ..
                }
            )),
            "device assignment is not in the NI universe"
        );
        let out = check(&cfg, Channels::full());
        assert!(
            out.violation.is_none(),
            "device assignment created an unauthorized cross-domain flow: {:?}",
            out.violation.unwrap()
        );
        assert!(
            out.unauthorized_checks > 1_000,
            "device NI sweep near-vacuous: only {} unauthorized checks over {} states",
            out.unauthorized_checks,
            out.states
        );
    }

    /// **Step consistency holds with device assignment in the universe.** Every `obs⁺(a)`-equal
    /// pair takes every transition `a` can issue to `obs⁺(a)`-equal successors — including the
    /// exclusivity guard, whose refusal reads a device's holder.
    #[test]
    fn step_consistency_holds_with_device_assignment() {
        let out = check_step_consistency(&ni_cfg_device(4));
        assert!(
            out.violation.is_none(),
            "device assignment broke step consistency: {:?}",
            out.violation.unwrap()
        );
    }

    /// **The `Busy` guard is observed, not leaked (depth-independent).** The two worlds below
    /// differ only in *who* holds the device — in one, a domain dom0 controls; in the other, a
    /// domain it does not — and in both the device is *taken*, so a two-valued free/taken bit
    /// cannot separate them. Yet the same hypercall succeeds in one (idempotent re-assignment)
    /// and returns `Busy` in the other.
    ///
    /// This is why [`device_tag`] has three arms rather than two, and the test is written directly
    /// rather than left to the sweep because it pins the *shape* of the observable, not merely its
    /// presence: collapse arm `2 + h` to a bare "taken" and this fails while every ∀-N sweep in
    /// the file stays green at the depths CI runs.
    #[test]
    fn the_device_busy_guard_is_observed() {
        use hv_core::HvCall;
        // dom0 creates 1 and 2 (controlling both), then delegates control of 2 away to 1 and
        // renounces its own edge — so dom0 controls 1 but *not* 2, while both are Live.
        fn world(held_by_controlled: bool) -> Hypervisor {
            let mut h = Hypervisor::new(3, 1, 1, 1, 1, 2, 1);
            for target in [1u16, 2] {
                h.dispatch(
                    0,
                    HvCall::DomainCreate {
                        target,
                        may_create: false,
                    },
                )
                .unwrap();
            }
            // Give the device to 1 (which dom0 controls) or to 2 (which it will not).
            let holder = if held_by_controlled { 1 } else { 2 };
            h.dispatch(0, HvCall::DeviceAssign { dev: 0, to: holder })
                .unwrap();
            // dom0 hands control of 2 to 1 and drops its own edge, so 2 becomes a domain dom0
            // neither is nor controls — while remaining Live, so peer-liveness cannot separate
            // the worlds either.
            h.dispatch(0, HvCall::ControlGrant { target: 2, to: 1 })
                .unwrap();
            h.dispatch(0, HvCall::ControlRevoke { target: 2, from: 0 })
                .unwrap();
            h
        }
        let mut mine = world(true);
        let mut theirs = world(false);

        // Without the device component the two worlds are indistinguishable to dom0: the device
        // is held in both, dom0 holds it in neither, and its authority rows agree.
        let blind = Surface {
            devices: false,
            ..Surface::full()
        };
        assert_eq!(
            obs_plus_impl(&mine, 0, blind),
            obs_plus_impl(&theirs, 0, blind),
            "the two worlds must be indistinguishable to dom0 without the device component"
        );
        // With it, they separate.
        assert_ne!(
            obs_plus(&mine, 0),
            obs_plus(&theirs, 0),
            "obs⁺ must resolve who holds a device as far as the observer's authority reaches"
        );
        // And the guard really does diverge on exactly that difference.
        let assign = HvCall::DeviceAssign { dev: 0, to: 1 };
        assert_eq!(mine.dispatch(0, assign), Ok(hv_core::HvOutcome::Done));
        assert_eq!(
            theirs.dispatch(0, assign),
            Err(hv_core::HvError::Device(hv_core::device::DeviceError::Busy))
        );
    }

    /// **Non-vacuity: `obs⁺` must carry the device namespace (SMMU rung 4).** Drop it and step
    /// consistency **breaks** — `DeviceAssign`'s exclusivity guard reports a device's holder to a
    /// caller whose observation no longer shows it.
    ///
    /// This is the remove-the-fix teeth for the whole `obs⁺` widening: without it, a green
    /// step-consistency sweep would be equally consistent with "the surface is right" and "the
    /// surface cannot see the flow" (design-lesson #66).
    #[test]
    fn dropping_the_device_namespace_from_obs_plus_breaks_step_consistency() {
        let out = check_step_consistency_with(&ni_cfg_device(4), |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    devices: false,
                    ..Surface::full()
                },
            )
        });
        assert!(
            out.violation.is_some(),
            "dropping the device namespace left step consistency holding — the component is not \
             load-bearing, or the sweep does not reach the exclusivity guard"
        );
    }

    /// A **scheduler** step-consistency config — `sched: false` in every NI config until ⑥, so
    /// `SchedRun`'s `PcpuBusy` guard had never been swept. Two domains, one vCPU each, and **two**
    /// pCPUs so the partition (`mediated_pcpus`) is not vacuous — with one pCPU, partitioning
    /// would let only dom0 ever run. Depth 5 is the shallowest that builds contention (create the
    /// peer, admit both vCPUs, run one, then have the other try the same pCPU).
    fn ni_cfg_sched(depth: u32, mediated_pcpus: bool) -> Config {
        Config {
            evtchn: false,
            grant: false,
            p2m: false,
            destroy: false,
            sched: true,
            pcpus: 2,
            mediated_pcpus,
            ..ni_cfg(depth)
        }
    }

    /// **`AlreadyAlive` is observed, not leaked (⑥'s headline, depth-independent).** The guard
    /// `DomainCreate` refuses on reads the **target's** liveness — another principal's state — and
    /// the caller has no other window onto it: `obs⁺(caller)` carries `caller`'s own liveness, its
    /// ports, grants, frames and authority, none of which move when an unrelated creator raises an
    /// unrelated slot. Two such worlds are `obs⁺(0)`-equal, yet `DomainCreate{target: 1}` succeeds
    /// in one (writing `controls[0][1]`, which `obs⁺(0)` *does* carry) and returns `AlreadyAlive`
    /// in the other — so without the peer-liveness component the caller's own successor
    /// observation is not a function of its own observation, and step consistency is false.
    ///
    /// The repair is **observe**, not remove (design-lesson #62's two dimensions): the guard is
    /// what keeps `DomainCreate` a `Dead` → `Live` transition, so force-completing it would
    /// silently reincarnate a *live* peer — an integrity catastrophe, not a repair — and refusal
    /// strands nothing (the caller keeps every resource and may retry). What is new versus (c)/(e)
    /// is the quadrant: the observed state belongs to a **third** principal, so this is a
    /// *declared disclosure* — domain liveness is public in Baleen, probeable by any domain with
    /// one uncapability-gated hypercall — rather than a channel closed by construction.
    ///
    /// Depth-independent by construction: the two worlds are built directly, so this pins the
    /// property whether or not any sweep configuration happens to reach the configuration.
    #[test]
    fn the_already_alive_guard_is_observed() {
        use hv_core::HvCall;
        // dom0 = the caller (boots Live with `may_create`). dom2 = a second creator dom0 raises.
        // dom1 = the probed slot: left Dead in one world, created *by dom2* in the other — an act
        // dom0 has no window onto (it touches none of dom0's resources or authority).
        fn world(dom2_creates_dom1: bool) -> Hypervisor {
            let mut h = Hypervisor::new(3, 1, 1, 1, 1, 2, 2);
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: 2,
                    may_create: true,
                },
            )
            .unwrap();
            if dom2_creates_dom1 {
                h.dispatch(
                    2,
                    HvCall::DomainCreate {
                        target: 1,
                        may_create: false,
                    },
                )
                .unwrap();
            }
            h
        }
        let mut dead = world(false);
        let mut alive = world(true);

        // The states really are the awkward pair: *every* component of `obs⁺(0)` other than the
        // peer-liveness vector agrees, so nothing but the new component separates them.
        assert_eq!(
            obs_plus_impl(
                &dead,
                0,
                Surface {
                    peer_liveness: false,
                    ..Surface::full()
                }
            ),
            obs_plus_impl(
                &alive,
                0,
                Surface {
                    peer_liveness: false,
                    ..Surface::full()
                }
            ),
            "the two worlds must be indistinguishable to the caller without peer liveness"
        );
        // With it, `obs⁺(0)` separates them — so the differing guard outcome is determined by the
        // observation, which is step consistency for this transition.
        assert_ne!(
            obs_plus(&dead, 0),
            obs_plus(&alive, 0),
            "obs⁺(caller) must record the target's liveness, or AlreadyAlive leaks it"
        );
        let create = HvCall::DomainCreate {
            target: 1,
            may_create: false,
        };
        assert_eq!(dead.dispatch(0, create), Ok(hv_core::HvOutcome::Done));
        assert_eq!(
            alive.dispatch(0, create),
            Err(hv_core::HvError::AlreadyAlive)
        );
        // And the outcomes really do diverge in `obs⁺(0)` — the success writes `controls[0][1]`,
        // so the guard is not behaviour-nil for the caller.
        assert_ne!(obs_plus(&dead, 0), obs_plus(&alive, 0));
    }

    /// **Non-vacuity: `obs⁺` must carry every domain's liveness (⑥ / F1).** Drop it and step
    /// consistency **breaks** — the four peer-liveness guards (`AlreadyAlive` on `DomainCreate`,
    /// `NotAlive` on `GrantAccess{grantee}` / `EvtchnAllocUnbound{remote}` / `ControlGrant{to}`)
    /// all report a named peer's liveness to a caller whose observation no longer shows it.
    ///
    /// The counterexample is asserted to be a **self-observer** one (`observer == actor`), which
    /// pins the checker fix too: reinstate the old `a == actor` skip and this test goes green with
    /// no violation, failing the assertion.
    #[test]
    fn dropping_peer_liveness_from_obs_plus_breaks_step_consistency() {
        let out = check_step_consistency_with(&ni_cfg3(3), |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    peer_liveness: false,
                    ..Surface::full()
                },
            )
        });
        let v = out
            .violation
            .expect("dropping peer liveness from obs⁺ should break step consistency (⑥ / F1)");
        assert_eq!(
            v.observer, v.actor,
            "the peer-liveness channel is a SELF-observer violation — the case the sweep used to \
             skip; got observer {} vs actor {}",
            v.observer, v.actor
        );
    }

    /// **Non-vacuity: `obs⁺` must carry the inbound invitation closure (⑥ / F2).** Drop it and
    /// step consistency **breaks**: `EvtchnBindInterdomain{remote, remote_port}` refuses unless
    /// that port stands `Unbound{remote: caller}`, so a peer's half-open invitation decides
    /// whether the caller gains an `Interdomain` port — state `obs(caller)` cannot show, since the
    /// port belongs to the peer. The event-channel twin of the grant read-closure, and like it a
    /// *confidentiality*-only component (a peer offering itself to `a` is not integrity
    /// interference), so it stays out of the local-respect `obs`.
    #[test]
    fn dropping_invitations_from_obs_plus_breaks_step_consistency() {
        let out = check_step_consistency_with(&ni_cfg3(3), |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    invitations: false,
                    ..Surface::full()
                },
            )
        });
        let v = out
            .violation
            .expect("dropping the invitation closure from obs⁺ should break step consistency (F2)");
        assert_eq!(v.observer, v.actor);
    }

    /// **Non-vacuity: `obs⁺` must carry control-edge *provenance*, not just presence (⑥ / F3).**
    /// Project `controls[a][·]` back down to a boolean and step consistency **breaks**: a `Root`
    /// edge (`a` created `c`) survives its delegator's teardown while a `Via` edge (`a` was
    /// delegated control of `c`) is cascaded away by `sweep_orphaned_control_edges`, so two
    /// present-but-differently-rooted edges take `DomainDestroy{target: delegator}` to different
    /// successors. Exactly ②′-(e)'s shape — an aggregate projection (`controls()`, like `refs`)
    /// hiding the detail the transition actually reads.
    #[test]
    fn dropping_control_provenance_from_obs_plus_breaks_step_consistency() {
        let out = check_step_consistency_with(&ni_cfg3_delegate(3), |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    provenance: false,
                    ..Surface::full()
                },
            )
        });
        assert!(
            out.violation.is_some(),
            "dropping control-edge provenance from obs⁺ should break step consistency (F3)"
        );
    }

    /// **The grant-map acquire guard is observed (⑥ / F6, depth-independent).** `grant_map` takes
    /// the backing page reference on the **grantor's** frame and hands the grantee the resulting
    /// `P2mError` verbatim — so a grantee learns whether a frame *it does not own* is currently a
    /// live page table. Two worlds differing only in whether the grantor pinned its granted frame
    /// as an L1 table are otherwise `obs⁺(grantee)`-equal, yet the grantee's writable `GrantMap`
    /// succeeds in one and is refused `TypePinned` in the other.
    ///
    /// **Observe, not remove** (design-lesson #62): the guard is write-xor-pagetable, load-bearing
    /// for isolation, and refusal strands nothing. The recorded tag comes from `p2m::can_acquire`,
    /// the seam `get`/`get_type` route through, so the observable cannot drift from the guard (#55).
    ///
    /// The depth-4 sweep found this; the depth-3 committed config could not reach it (it needs
    /// create + allocate + grant + pin before the map). This probe is depth-independent.
    #[test]
    fn the_grant_map_acquire_guard_is_observed() {
        use hv_core::p2m::PtLevel;
        use hv_core::HvCall;
        // dom1 owns frame 0 and grants it read-write to dom0; in one world it also pins that
        // frame as an L1 page table, which dom0 has no way to see except by mapping.
        fn world(pinned: bool) -> Hypervisor {
            let mut h = Hypervisor::new(2, 1, 1, 1, 1, 2, 2);
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: 1,
                    may_create: false,
                },
            )
            .unwrap();
            h.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).unwrap();
            h.dispatch(
                1,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 0,
                    frame: 0,
                    readonly: false,
                },
            )
            .unwrap();
            if pinned {
                h.dispatch(
                    1,
                    HvCall::P2mPin {
                        mfn: 0,
                        level: PtLevel::L1,
                    },
                )
                .unwrap();
            }
            h
        }
        let mut plain = world(false);
        let mut pinned = world(true);

        // Without the acquire tag the two worlds are indistinguishable to the grantee: the frame
        // is not dom0's, so none of `obs(0)`'s owned-frame fields cover it, and the read-cap
        // records only (grantor, gref, frame, ro, owns) — all identical.
        let bare = Surface {
            acquire_guard: false,
            ..Surface::full()
        };
        assert_eq!(
            obs_plus_impl(&plain, 0, bare),
            obs_plus_impl(&pinned, 0, bare),
            "the two worlds must be indistinguishable to the grantee without the acquire tag"
        );
        assert_ne!(
            obs_plus(&plain, 0),
            obs_plus(&pinned, 0),
            "obs⁺(grantee) must record the acquire outcome, or grant_map leaks the frame's type"
        );

        // And the guard outcome really does diverge.
        let map = HvCall::GrantMap {
            grantor: 1,
            gref: 0,
            writable: true,
        };
        assert_eq!(plain.dispatch(0, map), Ok(hv_core::HvOutcome::Handle(0)));
        assert_eq!(
            pinned.dispatch(0, map),
            Err(hv_core::HvError::P2m(hv_core::p2m::P2mError::TypePinned))
        );
    }

    /// **Non-vacuity: `obs⁺` must carry the acquire outcome (⑥ / F6).** Drop it and step
    /// consistency breaks over the page-table config — the sweep's confirmation of the probe above.
    #[test]
    fn dropping_the_acquire_guard_from_obs_plus_breaks_step_consistency() {
        let cfg = Config {
            pcpus: 2,
            mediated_frames: true,
            mediated_pcpus: true,
            ..ni_cfg(4)
        };
        let out = check_step_consistency_with(&cfg, |hv, a| {
            obs_plus_impl(
                hv,
                a,
                Surface {
                    acquire_guard: false,
                    ..Surface::full()
                },
            )
        });
        assert!(
            out.violation.is_some(),
            "dropping the acquire outcome from obs⁺ should break step consistency (F6)"
        );
    }

    /// **Incoming control-edge provenance is observed (⑥ / F5, depth-independent).** The first cut
    /// of ⑥ recorded provenance for `a`'s *outgoing* control edges only, arguing that `a` is
    /// passive in a delegation *to* it. The depth-4 delegation sweep refuted that: the
    /// orphan-sweep cascades away an incoming `Via(d)` edge when `d` is destroyed, while an
    /// incoming `Root` survives — so the provenance of an edge pointing *at* `a` decides whether
    /// `a`'s own controller set moves, and `a` observes that.
    ///
    /// Two worlds in which dom0's control of dom1 is `Root` versus `Via(2)`, otherwise
    /// `obs⁺(1)`-equal; destroying dom2 strips it in one and not the other.
    #[test]
    fn incoming_control_provenance_is_observed() {
        use hv_core::HvCall;
        // Both worlds end with dom1's incoming controller *set* equal — {dom0, dom2} — and differ
        // only in which of the two edges is the `Root`. (These are the deep sweep's own two
        // traces.) `via` names which world: false = dom0 holds `Root` over dom1, true = dom2 does
        // and dom0's edge is `Via(2)`.
        fn world(via: bool) -> Hypervisor {
            let mut h = Hypervisor::new(3, 1, 1, 1, 1, 2, 2);
            let mk = |t: u16, mc: bool| HvCall::DomainCreate {
                target: t,
                may_create: mc,
            };
            if via {
                h.dispatch(0, mk(2, true)).unwrap(); // controls[0][2] = Root
                h.dispatch(2, mk(1, false)).unwrap(); // controls[2][1] = Root
                h.dispatch(0, HvCall::ControlGrant { target: 2, to: 1 })
                    .unwrap();
                h.dispatch(2, HvCall::ControlGrant { target: 1, to: 0 })
                    .unwrap(); // controls[0][1] = Via(2)
            } else {
                h.dispatch(0, mk(1, false)).unwrap(); // controls[0][1] = Root
                h.dispatch(0, mk(2, true)).unwrap(); // controls[0][2] = Root
                h.dispatch(0, HvCall::ControlGrant { target: 1, to: 2 })
                    .unwrap(); // controls[2][1] = Via(0)
                h.dispatch(0, HvCall::ControlGrant { target: 2, to: 1 })
                    .unwrap();
            }
            h
        }
        let mut root = world(false);
        let mut via = world(true);

        // Both of dom1's controllers are present in both worlds, so the boolean projection of the
        // incoming row cannot separate them — only the provenance can.
        assert!(root.controls(0, 1) && via.controls(0, 1));
        assert!(root.controls(2, 1) && via.controls(2, 1));
        let bare = Surface {
            provenance: false,
            ..Surface::full()
        };
        assert_eq!(
            obs_plus_impl(&root, 1, bare),
            obs_plus_impl(&via, 1, bare),
            "the two worlds must be indistinguishable to dom1 without incoming provenance"
        );
        assert_ne!(
            obs_plus(&root, 1),
            obs_plus(&via, 1),
            "obs⁺ must record the provenance of edges pointing AT `a`, not just out of it"
        );

        // dom1 destroys dom2 (it controls it in both worlds). That clears every edge touching
        // dom2 — including `controls[2][1]` — and then orphan-sweeps whatever hung off it. In the
        // `root` world dom0's edge over dom1 is a `Root` and stands; in the `via` world it is
        // `Via(2)`, whose delegator just died, so it is swept. dom1's own controller set therefore
        // moves differently in the two worlds: the flow the boolean projection hid.
        let destroy = HvCall::DomainDestroy { target: 2, now: 1 };
        root.dispatch(1, destroy).unwrap();
        via.dispatch(1, destroy).unwrap();
        assert!(
            root.controls(0, 1),
            "a Root edge survives its peer's teardown"
        );
        assert!(
            !via.controls(0, 1),
            "a Via(2) edge is orphan-swept when its delegator dies"
        );
    }

    /// **Step consistency holds over the delegation forest (⑥ / F3, the repair).** With
    /// provenance observed, the whole `ControlGrant`/`ControlRevoke`/`DomainDestroy`-cascade
    /// universe is consistent — the first time the delegation guards have been step-consistency
    /// swept at all. Non-vacuous (six figures of witnessed key-classes).
    #[test]
    fn step_consistency_holds_over_the_delegation_forest() {
        let out = check_step_consistency(&ni_cfg3_delegate(3));
        assert!(
            out.violation.is_none(),
            "delegation step-consistency violation: {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 100_000);
    }

    /// **The page-table and grant-seam guards, step-consistency swept (⑥).** Every
    /// step-consistency config before ⑥ ran with `levels: vec![]`, so no `P2mPin`/`P2mLink` ever
    /// fired and the page-table guards were swept for *invariant preservation* (Tiers A–C) but
    /// never for confidentiality. This config turns the page tables on — two levels, so interior
    /// and leaf entries both arise — over a grant universe, and covers: the `Unauthorized`
    /// foreign-link guard, `WxConflict` (W^X), `SpanConflict`, the `StaleGrant` seam check, and
    /// the grant `InUse`/`WrongState`/`Overflow` family. All hold.
    ///
    /// Both shared resources are partitioned, so the two *known* contention channels
    /// ([`an_unmediated_allocator_breaks_step_consistency`],
    /// [`unpartitioned_pcpus_break_step_consistency`]) do not mask what this config is for.
    #[test]
    fn step_consistency_holds_over_the_page_table_guards() {
        let cfg = Config {
            pcpus: 2,
            mediated_frames: true,
            mediated_pcpus: true,
            ..ni_cfg(3)
        };
        let out = check_step_consistency(&cfg);
        assert!(
            out.violation.is_none(),
            "page-table/grant-seam step-consistency violation: {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 100_000);
    }

    /// **The async EL2 agent, step-consistency swept (⑥).** `async_agent: false` in every
    /// step-consistency config too, so `Transition::RaiseVcpuVirq` — the one non-guest transition —
    /// had been swept for local respect (Phase I-1c) but never for confidentiality. It holds:
    /// the raise reads only the target domain's own `(vcpu, virq)` port binding and sets its
    /// pending bit, with no guard over another principal's state. Both shared resources are
    /// partitioned so the known contention channels do not mask it.
    #[test]
    fn step_consistency_holds_with_the_async_agent() {
        let cfg = Config {
            pcpus: 2,
            mediated_frames: true,
            mediated_pcpus: true,
            ..ni_cfg_async(3)
        };
        let out = check_step_consistency(&cfg);
        assert!(
            out.violation.is_none(),
            "async-agent step-consistency violation: {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 100_000);
    }

    /// **Local respect holds over the delegation forest and the scheduler (⑥).** The two
    /// universes ⑥ added to the step-consistency side were absent from the *integrity* side too
    /// (`delegate: false`, and `sched` only ever swept for local respect at two domains), so the
    /// audit re-runs local respect over both. It holds under the unchanged channel relation:
    /// delegation moves only the `controls` matrix, which the integrity `obs` deliberately
    /// excludes (it is `a`'s power over others, not `a`'s protected state), and a peer's pCPU
    /// placement is likewise outside `obs(a)`. So ⑥'s `obs⁺` widenings are confidentiality-only,
    /// as design-lesson #58 requires — no [`Channels`] term was needed for either.
    #[test]
    fn local_respect_holds_over_delegation_and_the_scheduler() {
        for (name, cfg) in [
            ("delegation", ni_cfg3_delegate(3)),
            ("scheduler", ni_cfg_sched(5, true)),
        ] {
            let out = check(&cfg, Channels::full());
            assert!(
                out.violation.is_none(),
                "local-respect violation over {name}: {:?}",
                out.violation.unwrap()
            );
        }
    }

    /// **Step consistency over the delegation forest, deeper (deep sweep).** Ignored by default;
    /// run in the deep-verification workflow.
    #[test]
    #[ignore = "deep delegation step-consistency sweep — run in deep-verify.yml"]
    fn step_consistency_holds_over_the_delegation_forest_deep() {
        let out = check_step_consistency(&ni_cfg3_delegate(4));
        assert!(
            out.violation.is_none(),
            "delegation step-consistency violation (deep): {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 1_000_000);
    }

    /// **Step consistency over the page-table guards, deeper (deep sweep).** Ignored by default;
    /// run in the deep-verification workflow.
    #[test]
    #[ignore = "deep page-table step-consistency sweep — run in deep-verify.yml"]
    fn step_consistency_holds_over_the_page_table_guards_deep() {
        let cfg = Config {
            pcpus: 2,
            mediated_frames: true,
            mediated_pcpus: true,
            ..ni_cfg(4)
        };
        let out = check_step_consistency(&cfg);
        assert!(
            out.violation.is_none(),
            "page-table step-consistency violation (deep): {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 1_000_000);
    }

    /// **Unpartitioned pCPUs break step consistency (⑥ / F4, the counterexample).** `sched::run`
    /// refuses with `SchedError::PcpuBusy` when the named pCPU is occupied — a guard reading
    /// **which other domain is running**, precisely the global pcpu-occupancy vector `obs`
    /// excludes (§2.1). That exclusion was documented as an *abstraction*, but abstracting a
    /// channel out of `obs` does not make step consistency hold: it makes it **false**, and this
    /// is the machine-checked witness. It went unseen because no step-consistency config had ever
    /// enabled `sched`.
    ///
    /// The repair follows ②′-(b)'s precedent rather than #62's remove/observe fork, because this
    /// is the same *class*: contention for a **shared resource** nobody owns. The guard cannot be
    /// removed (two vCPUs cannot share a pCPU) and the occupant's identity is not the caller's to
    /// observe, so the resource is **partitioned** instead — see
    /// [`step_consistency_holds_with_partitioned_pcpus`], the scheduling twin of the mediated
    /// allocator, and what real hypervisors implement as pinning.
    #[test]
    fn unpartitioned_pcpus_break_step_consistency() {
        let out = check_step_consistency(&ni_cfg_sched(5, false));
        let v = out.violation.expect(
            "unpartitioned pCPUs should break step consistency — `PcpuBusy` reads the occupant",
        );
        assert_eq!(
            v.observer, v.actor,
            "the pcpu-contention channel is a SELF-observer violation"
        );
    }

    /// **Step consistency holds with partitioned pCPUs (⑥ / F4, the repair).** Pin each domain to
    /// its own physical CPU (`mediated_pcpus`) and the contention channel closes by construction:
    /// a `PcpuBusy` refusal can then only name the caller's *own* vCPU, whose placement
    /// `obs(caller)` already carries. The scheduling twin of
    /// [`step_consistency_holds_with_a_mediated_allocator`].
    #[test]
    fn step_consistency_holds_with_partitioned_pcpus() {
        let out = check_step_consistency(&ni_cfg_sched(5, true));
        assert!(
            out.violation.is_none(),
            "step-consistency violation under partitioned pCPUs: {:?}",
            out.violation.unwrap()
        );
        assert!(out.witnessed_classes > 1_000);
    }

    // ─── ②′-(c): the `DomainBusy` availability channel, closed by force-reclaim ──────────

    /// Build the four-domain `DomainBusy` configuration. `dom0` is the caller (it controls
    /// everyone it created), `c = 2` is the destroy target and owns frame 0, `a = 1` holds a
    /// read-cap on that frame (a grant from `c`), and `m = 3` is the **hidden fourth domain**
    /// whose hold over `c`'s frame used to decide whether the destroy fired at all. `m_holds`
    /// selects the two runs that must be indistinguishable.
    ///
    /// `hold` is the direction of `m`'s hold: a live grant *map*, or a live inward page-table
    /// *link*. Both were `DomainBusy` before ②′-(c); the link half is the one the Verus NI
    /// instantiation does *not* model (it rides invariant preservation), so witnessing it on
    /// real code matters most here.
    fn busy_channel_state(m_holds: bool, link_not_map: bool) -> Hypervisor {
        use hv_core::p2m::PtLevel;
        use hv_core::HvCall;
        let mut h = Hypervisor::new(4, 1, 2, 1, 1, 2, 2);
        for t in 1..4u16 {
            h.dispatch(
                0,
                HvCall::DomainCreate {
                    target: t,
                    may_create: false,
                },
            )
            .unwrap();
        }
        // `c` owns frame 0 and offers it to `a` (the read-cap under observation) and to `m`.
        h.dispatch(2, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        h.dispatch(
            2,
            HvCall::GrantAccess {
                gref: 0,
                grantee: 1,
                frame: 0,
                readonly: true,
            },
        )
        .unwrap();
        h.dispatch(
            2,
            HvCall::GrantAccess {
                gref: 1,
                grantee: 3,
                frame: 0,
                readonly: false,
            },
        )
        .unwrap();
        if m_holds {
            if link_not_map {
                // `m` maps `c`'s frame into its *own* page table — a live inward foreign link.
                h.dispatch(3, HvCall::P2mAllocate { mfn: 1 }).unwrap();
                h.dispatch(
                    3,
                    HvCall::P2mPin {
                        mfn: 1,
                        level: PtLevel::L1,
                    },
                )
                .unwrap();
                h.dispatch(
                    3,
                    HvCall::P2mLink {
                        parent: 1,
                        slot: 0,
                        child: 0,
                        writable: true,
                        leaf: true,
                        execute: false,
                    },
                )
                .unwrap();
            } else {
                // `m` takes a live grant map of `c`'s frame.
                h.dispatch(
                    3,
                    HvCall::GrantMap {
                        grantor: 2,
                        gref: 1,
                        writable: true,
                    },
                )
                .unwrap();
            }
        }
        h
    }

    /// The shared body: the two runs must be indistinguishable to both the observer `a` and the
    /// caller, before *and* after the destroy.
    fn assert_busy_channel_closed(link_not_map: bool) {
        use hv_core::{HvCall, HvOutcome};
        let (a, caller, c) = (1u16, 0u16, 2u16);
        let mut held = busy_channel_state(true, link_not_map);
        let mut free = busy_channel_state(false, link_not_map);

        // The hidden state is real, and it is *exactly* the old guard's trigger: the busy
        // predicate is true in one run and false in the other, so refuse-if-busy would have
        // fired in precisely one of them. (Without this the test could pass vacuously on two
        // identical states.)
        let busy =
            |h: &Hypervisor| h.grant().has_foreign_map(c) || h.p2m().has_foreign_link_into(c);
        assert!(busy(&held), "m should hold c's frame in the `held` run");
        assert!(!busy(&free), "m should hold nothing in the `free` run");

        // Yet neither the observer nor the caller can see the difference: `m`'s hold lives in
        // `c`'s grant row / `c`'s frame refcounts / `m`'s own tables, none of which are in
        // `obs⁺(a)` or `obs⁺(caller)`.
        assert_eq!(
            obs_plus(&held, a),
            obs_plus(&free, a),
            "m's hold on c's frame leaked into obs⁺(a) before the destroy"
        );
        assert_eq!(
            obs_plus(&held, caller),
            obs_plus(&free, caller),
            "m's hold on c's frame leaked into obs⁺(caller) before the destroy"
        );

        let before_a = obs_plus(&held, a);

        // The step: the caller destroys `c`. Under refuse-if-busy this returned `DomainBusy` in
        // the `held` run and `Done` in the `free` one — an availability difference decided by
        // `m`, which is the step-consistency violation. Force-reclaim makes it total.
        let call = HvCall::DomainDestroy { target: c, now: 0 };
        assert_eq!(held.dispatch(caller, call), Ok(HvOutcome::Done));
        assert_eq!(free.dispatch(caller, call), Ok(HvOutcome::Done));

        // Non-vacuity: the step must genuinely *move* `obs⁺(a)` — `a`'s read-cap on `c` is
        // dropped by the revoke. Without this the equality below could hold trivially because
        // nothing observable happened in either run, which is precisely the failure mode the
        // old design had in the `held` run (a refusal is a no-op).
        assert_ne!(
            before_a,
            obs_plus(&held, a),
            "the destroy left obs⁺(a) unchanged — the read-cap channel is not being exercised"
        );

        // Step consistency, discharged: `obs⁺`-equal states step to `obs⁺`-equal states. In
        // particular `a`'s read-cap on `c` is dropped in *both* runs — `m` can no longer decide
        // whether `a` keeps it.
        assert_eq!(
            obs_plus(&held, a),
            obs_plus(&free, a),
            "the destroy's effect on obs⁺(a) depended on m's hidden hold"
        );
        assert_eq!(
            obs_plus(&held, caller),
            obs_plus(&free, caller),
            "the destroy's effect on obs⁺(caller) depended on m's hidden hold"
        );
        // And the reclaim really happened rather than the hold being tolerated.
        assert!(!busy(&held) && !busy(&free));
        assert!(held.invariants_hold() && free.invariants_hold());
    }

    /// **②′-(c): force-reclaim closes the `DomainBusy` availability channel — the grant-map
    /// direction.** The residual (a) / (b) / (d) left standing: at ≥4 domains, whether a destroy
    /// of `c` *fired* depended on whether an unrelated fourth domain `m` held a live map of `c`'s
    /// frames — state neither the caller nor the observer `a` (a grantee of `c`) can see. Two
    /// `obs⁺`-equal runs therefore stepped to *different* `obs⁺`, since `a`'s read-cap on `c`
    /// survived in one and not the other: step consistency was **false** for the destroy channel.
    ///
    /// Making teardown force-reclaim instead of refuse closes it **by construction** — the
    /// destroy is now a total function of the actor's own observation, so there is nothing for
    /// `m` to modulate. Targeted rather than swept: reaching this configuration by brute
    /// enumeration needs four live domains, an allocation, two grants, a map and a destroy —
    /// about depth 9, far past what the sweep reaches (the deep 4-domain destroy sweep above
    /// runs at depth 5). Same channel, pinned directly.
    #[test]
    fn force_reclaim_closes_the_busy_channel_grant_map_direction() {
        assert_busy_channel_closed(false);
    }

    /// **②′-(e): the revoke guard's foreign-linked status is observed, not leaked.** Found while
    /// ruling on the ②′-(c) asymmetry (`GrantEndAccess` still refuses while a foreign entry relies
    /// on a grant, though `DomainDestroy` now force-reclaims). The refusal predicate is
    /// `p2m::is_foreign_linked_by(frame, grantee)` — *which* grantee linked — and the grantor could
    /// not distinguish that from `obs⁺` alone: two states in which **different** grantees of the
    /// same frame have linked it move the frame's aggregate `refs` identically. So `obs⁺(grantor)`
    /// was equal while `GrantEndAccess{gref:0}` refused in one and succeeded in the other — the same
    /// step-consistency shape as the `DomainBusy` residual, at a depth (~7) the sweep never reaches.
    ///
    /// Resolved the *opposite* way to ②′-(c), and that is the point: `DomainBusy` read **another
    /// domain's** frames, which the caller has no business observing, so the guard had to go;
    /// this guard reads the caller's **own** frame, so it is legitimate and merely had to be
    /// *observed*. `obs` now carries the per-row boolean — the faithful observable, since the
    /// grantor learns exactly this bit off `InUse` vs `Done`.
    #[test]
    fn the_revoke_guards_foreign_linked_status_is_in_obs() {
        use hv_core::p2m::PtLevel;
        use hv_core::{HvCall, HvOutcome};
        // caller = 1 owns frame 0 and grants it to BOTH dom2 (gref 0) and dom3 (gref 1).
        // Exactly one of them links it into its own table.
        fn linked_by(linker: Dom) -> Hypervisor {
            let mut h = Hypervisor::new(4, 1, 2, 1, 1, 2, 2);
            for t in 1..4u16 {
                h.dispatch(
                    0,
                    HvCall::DomainCreate {
                        target: t,
                        may_create: false,
                    },
                )
                .unwrap();
            }
            h.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).unwrap();
            for (gref, grantee) in [(0u32, 2u16), (1, 3)] {
                h.dispatch(
                    1,
                    HvCall::GrantAccess {
                        gref,
                        grantee,
                        frame: 0,
                        readonly: false,
                    },
                )
                .unwrap();
            }
            h.dispatch(linker, HvCall::P2mAllocate { mfn: 1 }).unwrap();
            h.dispatch(
                linker,
                HvCall::P2mPin {
                    mfn: 1,
                    level: PtLevel::L1,
                },
            )
            .unwrap();
            h.dispatch(
                linker,
                HvCall::P2mLink {
                    parent: 1,
                    slot: 0,
                    child: 0,
                    writable: true,
                    leaf: true,
                    execute: false,
                },
            )
            .unwrap();
            h
        }
        let mut by2 = linked_by(2);
        let mut by3 = linked_by(3);

        // The states really are the awkward pair: the frame's aggregate reference count — what
        // `obs` carried *before* the boolean — is identical, so nothing else distinguishes them.
        assert_eq!(
            by2.p2m().refs(0),
            by3.p2m().refs(0),
            "the two states must be indistinguishable by frame refcount alone"
        );
        // With the boolean, `obs⁺(grantor)` separates them — so the differing guard outcome is
        // determined by the observation, which is step consistency for this transition.
        assert_ne!(
            obs_plus(&by2, 1),
            obs_plus(&by3, 1),
            "obs⁺(grantor) must record WHICH grant is foreign-linked, or the revoke guard leaks"
        );
        assert_eq!(
            by2.dispatch(1, HvCall::GrantEndAccess { gref: 0 }),
            Err(hv_core::HvError::Grant(hv_core::grant::GrantError::InUse))
        );
        assert_eq!(
            by3.dispatch(1, HvCall::GrantEndAccess { gref: 0 }),
            Ok(HvOutcome::Done)
        );

        // Non-vacuity: the boolean is not constant-true — an unlinked grant reads false, and it
        // is per-row, not per-frame (gref 1 names dom3, who has not linked in the `by2` world).
        let clean = {
            let mut h = Hypervisor::new(4, 1, 2, 1, 1, 2, 2);
            for t in 1..4u16 {
                h.dispatch(
                    0,
                    HvCall::DomainCreate {
                        target: t,
                        may_create: false,
                    },
                )
                .unwrap();
            }
            h.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).unwrap();
            h.dispatch(
                1,
                HvCall::GrantAccess {
                    gref: 0,
                    grantee: 2,
                    frame: 0,
                    readonly: false,
                },
            )
            .unwrap();
            h
        };
        assert!(!clean.p2m().is_foreign_linked_by(0, 2));
    }

    /// **②′-(c), the page-table half — and the one this bridge is the *primary* evidence for.**
    /// The same channel with `m`'s hold being a live inward page-table link into `c`'s frame
    /// rather than a grant map. This direction is **not** modelled by the Verus NI instantiation
    /// (whose destroy carrier moves grants and frame-references, not page-table edges), so it
    /// rides invariant preservation there; the real-code bridge is what actually witnesses that
    /// the confidentiality direction is closed for it too.
    #[test]
    fn force_reclaim_closes_the_busy_channel_foreign_link_direction() {
        assert_busy_channel_closed(true);
    }
}
