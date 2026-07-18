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

use std::collections::HashMap;

use hv_core::evtchn::PortState;
use hv_core::p2m::PageType;
use hv_core::sched::RunState;
use hv_core::{HvCall, HvOutcome, Hypervisor};

use crate::enumerate::{ops, state_key, Config};

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
                u64::from(pt_refs),
                level_tag(ty),
                p.is_pinned(mfn) as u64,
            ]);
        }
    }
    k.push(0xD_0005);

    // The page-table edges rooted in `a`'s own tables (parent owned by `a`). Only `a`'s own
    // link/unlink touches these. A canonical (sorted) set.
    let mut edges: Vec<[u64; 5]> = p
        .link_edges()
        .into_iter()
        .filter(|&(parent, ..)| p.owner_of(parent) == Some(a))
        .map(|(par, slot, ch, w, leaf)| {
            [
                u64::from(par),
                u64::from(slot),
                u64::from(ch),
                w as u64,
                leaf as u64,
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

/// A local-respect counterexample: actor `actor` had no authorized channel to observer
/// `observer`, yet `call` changed `obs(observer)`.
#[derive(Clone, Debug)]
pub struct NiViolation {
    /// The domain that issued the transition.
    pub actor: Dom,
    /// The domain whose observation changed without authorization.
    pub observer: Dom,
    /// The hypercall that caused it.
    pub call: HvCall,
    /// The hypercall path from `new()` to the pre-state where it happened.
    pub trace: Vec<(Dom, HvCall)>,
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
fn reachable(cfg: &Config) -> Vec<(Hypervisor, Vec<(Dom, HvCall)>)> {
    let universe = ops(cfg);
    let init = Hypervisor::new(
        cfg.domains,
        cfg.ports,
        cfg.grants,
        cfg.vcpus,
        cfg.pcpus,
        cfg.frames,
    );
    let mut seen: HashMap<Vec<u64>, Vec<(Dom, HvCall)>> = HashMap::new();
    seen.insert(state_key(&init), Vec::new());
    let mut frontier = vec![(init, Vec::new())];
    for _ in 0..cfg.depth {
        let mut next = Vec::new();
        for (hv, trace) in &frontier {
            for &(caller, call) in &universe {
                let mut h = hv.clone();
                let _: Result<HvOutcome, _> = h.dispatch(caller, call);
                let key = state_key(&h);
                if !seen.contains_key(&key) {
                    if seen.len() >= cfg.max_states {
                        continue;
                    }
                    let mut t = trace.clone();
                    t.push((caller, call));
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
            for &(caller, call) in &trace {
                let _: Result<HvOutcome, _> = h.dispatch(caller, call);
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
    let universe = ops(cfg);
    let states = reachable(cfg);
    let n = cfg.domains as Dom;
    let mut checks = 0u64;
    let mut unauthorized_checks = 0u64;

    for (hv, trace) in &states {
        for &(caller, call) in &universe {
            // Project every observer's pre-image once, then compare against the post-image.
            let before: Vec<Vec<u64>> = (0..n).map(|a| obs(hv, a)).collect();
            let mut h = hv.clone();
            let _: Result<HvOutcome, _> = h.dispatch(caller, call);
            for a in 0..n {
                if a == caller {
                    continue;
                }
                checks += 1;
                if ch.authorized(hv, caller, a) {
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
                            actor: caller,
                            observer: a,
                            call,
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
            depth,
            max_states: 400_000,
            symmetry: false,
        }
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
}
