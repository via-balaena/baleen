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
//! It is checked over a wider surface [`obs_plus`] (`obs⁺`) with two additions the integrity
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
//!   and the sweep finds a `DomainCreate` (or destroy/affinity) counterexample.
//!
//! Over three domains the read direction is live and step consistency **holds**, non-vacuously
//! (see the tests). The one honest edge — a fourth domain mapping `c`'s frame makes
//! `DomainBusy` (which refuses the destroy) depend on state neither `a` nor the actor observes,
//! so step consistency there rests on the instantiation's over-approximation of `DomainBusy`;
//! at ≤3 domains no such fourth mapper exists, so the sweep is clean.

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
    /// `b` controls some `c` that `a` holds an outbound reference to.
    pub teardown_reach: bool,
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
}

/// Whether `a` has an active grant entry whose grantee is `b`.
fn a_grants_to(hv: &Hypervisor, a: Dom, b: Dom) -> bool {
    let g = hv.grant();
    (0..g.entry_count(a) as u32)
        .any(|gref| matches!(g.grant_entry(a, gref), Some((grantee, ..)) if grantee == b))
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
    for gref in 0..g.entry_count(a) as u32 {
        match g.grant_entry(a, gref) {
            Some((grantee, frame, ro, maps, wmaps)) => k.extend([
                1,
                u64::from(grantee),
                u64::from(frame),
                ro as u64,
                u64::from(maps),
                u64::from(wmaps),
            ]),
            None => k.extend([0, 0, 0, 0, 0, 0]),
        }
    }
    k.push(0xD_0002);

    // The grant mappings `a` holds (`a` as grantee) — a canonical set (grantor, gref,
    // writable). Only `a`'s own map/unmap creates or drops these.
    let mut held: Vec<[u64; 3]> = Vec::new();
    for h in 0..g.handle_slots() as u32 {
        if let Some((grantee, grantor, gref, w)) = g.mapping_at(h) {
            if grantee == a {
                held.push([u64::from(grantor), u64::from(gref), w as u64]);
            }
        }
    }
    held.sort_unstable();
    k.push(held.len() as u64);
    for m in held {
        k.extend(m);
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
    obs_plus_impl(hv, a, true)
}

/// [`obs_plus`] with the authority projection toggleable — so the non-vacuity test can drop it and
/// watch step consistency *break* (the real-code form of the instantiation's finding #1).
fn obs_plus_impl(hv: &Hypervisor, a: Dom, authority: bool) -> Vec<u64> {
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
    if authority {
        k.push(0xD_0007);
        k.push(hv.may_create(a) as u64);
        for b in 0..n {
            k.push(hv.controls(b, a) as u64); // incoming: who controls a
        }
        for c in 0..n {
            k.push(hv.controls(a, c) as u64); // outgoing: whom a controls
        }
    }

    k.push(0xD_0006);
    let mut rcaps: Vec<[u64; 5]> = Vec::new();
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
                    rcaps.push([
                        u64::from(grantor),
                        u64::from(gref),
                        u64::from(frame),
                        ro as u64,
                        owns,
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
/// transition and every observer `a ≠ actor`, it verifies that `obs⁺(a)` after the step is a
/// **function of** `(obs⁺(a), obs⁺(actor))` before it: two reachable states that `a` and the actor
/// cannot tell apart are driven to the same successor observation. (This is exactly the unwinding
/// *step-consistency* condition; unlike local respect it needs no channel relation — it is a pure
/// determinism property.) This is where the `DomainDestroy` **read direction** lives: destroying
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

/// A step-consistency equivalence class: `(obs⁺(observer), obs⁺(actor))` before → the observed
/// `(obs⁺(observer) after, reproducing trace)`. Every state in a class must share the successor.
type ScClass = HashMap<(Vec<u64>, Vec<u64>), (Vec<u64>, Vec<Transition>)>;

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
            if a == actor {
                continue;
            }
            // key: (obs⁺(a), obs⁺(actor)) before → value: (obs⁺(a) after, trace).
            let mut class: ScClass = HashMap::new();
            for (hv, trace) in &states {
                let key = (proj(hv, a), proj(hv, actor));
                let mut h = hv.clone();
                let _: Result<TransitionOutcome, _> = h.apply(transition);
                let after = proj(&h, a);
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
            async_agent: false,
            drive_execute: false,
            mediated_frames: false,
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
            async_agent: false,
            drive_execute: false,
            mediated_frames: false,
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
        let out = check_step_consistency_with(&ni_cfg3(3), |hv, a| obs_plus_impl(hv, a, false));
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
            let mut h = Hypervisor::new(4, 1, 1, 0, 0, 1); // 4 domains, 1 frame
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
        let mut valid = Hypervisor::new(4, 1, 1, 0, 0, 1);
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
            async_agent: false,
            drive_execute: false,
            mediated_frames: true,
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
}
