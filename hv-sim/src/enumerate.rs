// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Exhaustive small-state enumeration — bounded model checking on a laptop
//!
//! The seeded simulator ([`crate::scenario`]) *samples* the state space: it drives
//! [`hv_core::Hypervisor`] through random walks and trusts breadth-of-seeds for
//! coverage. This module does the opposite — for a *tiny* configuration (a couple of
//! domains, frames, ports, grants, vCPUs) it visits **every** reachable state and
//! proves the invariant holds at each one. Where a random walk says "no seed hit a
//! violation", this says "no reachable state *can*".
//!
//! **How.** Breadth-first from the initial state: at each state apply every
//! `(caller, HvCall)` over the tiny fixed universe, check
//! [`hv_core::Hypervisor::invariants_hold`], and enqueue each newly-seen state. Two
//! states are "the same" when their [`state_key`] matches — a *canonical* fingerprint
//! that keeps every behaviourally-live field (run states, refcounts, grant *handle
//! layout*, the page-table edge set) and drops the behaviourally-dead ones (a vCPU's
//! accrued `runtime`, an untyped frame's stale level). Every reference count grows by
//! at most one per hypercall, so within a `depth` bound all counts stay `<= depth` and
//! the reachable set is finite: the search terminates and the result is a *theorem* —
//! every state reachable in `<= depth` hypercalls from `new()` is invariant-safe.
//!
//! **Focus by seam.** Enabling every op group at once explodes the branching factor, so
//! [`Config`] selects which subsystems' hypercalls to enumerate. Running grant+p2m
//! together exhaustively covers the grant↔page-type and page-table↔grant seams;
//! evtchn+sched covers the lost-wakeup seam — each at a far larger depth than the full
//! cross-product would allow. Credit is orthogonal (it touches nothing else) and left
//! out.
//!
//! Not `no_std`: this is host-only harness code, like the rest of `hv-sim`.

use std::collections::HashMap;

use hv_core::evtchn::PortState;
use hv_core::p2m::{PageType, PtLevel};
use hv_core::sched::RunState;
use hv_core::{Control, HvCall, HvOutcome, Hypervisor};

/// Which subsystems' hypercalls the enumeration drives, plus the tiny universe sizes.
#[derive(Debug, Clone)]
pub struct Config {
    pub domains: usize,
    pub ports: usize,
    pub grants: usize,
    pub vcpus: usize,
    pub pcpus: usize,
    pub frames: usize,
    /// Page-table levels to try when pinning/typing (a subset of L1..L4).
    pub levels: Vec<PtLevel>,
    /// Grant-map handles to try unmapping (`0..handles`).
    pub handles: u32,
    /// Op groups to enumerate.
    pub evtchn: bool,
    pub grant: bool,
    pub sched: bool,
    pub p2m: bool,
    pub create: bool,
    pub destroy: bool,
    pub delegate: bool,
    /// Maximum hypercall depth from the initial state to explore.
    pub depth: u32,
    /// Safety cap: stop after this many distinct states (a partial result).
    pub max_states: usize,
}

impl Config {
    /// A minimal universe; callers flip on the op groups and sizes they want.
    pub fn tiny() -> Self {
        Config {
            domains: 2,
            ports: 2,
            grants: 2,
            vcpus: 1,
            pcpus: 1,
            frames: 2,
            levels: vec![PtLevel::L1, PtLevel::L2],
            handles: 3,
            evtchn: false,
            grant: false,
            sched: false,
            p2m: false,
            create: false,
            destroy: false,
            delegate: false,
            depth: 5,
            max_states: 1_500_000,
        }
    }
}

/// The result of an enumeration.
#[derive(Debug, Clone)]
pub struct EnumOutcome {
    /// Distinct reachable states visited.
    pub states: usize,
    /// True if the `max_states` cap was hit before the search closed (partial result).
    pub truncated: bool,
    /// A shortest counterexample: the hypercall path from `new()` to a state that
    /// violates the integrated invariant, or `None` if none exists within `depth`.
    pub violation: Option<Vec<(u16, HvCall)>>,
}

/// A canonical state fingerprint (see [`state_key`]).
type StateKey = Vec<u64>;
/// How each visited state was first reached: its parent state and the `(caller, call)`
/// that produced it, or `None` for the root — enough to reconstruct a counterexample.
type CameFrom = HashMap<StateKey, Option<(StateKey, u16, HvCall)>>;

/// The clock value stamped on every time-bearing op. Because `runtime`/`dispatched_at`
/// are excluded from [`state_key`], its exact value never creates a distinct state, so a
/// single constant suffices.
const NOW: u64 = 1;

/// Build the fixed `(caller, HvCall)` universe for a config — every operation the
/// enabled groups can express over the tiny sizes.
fn ops(cfg: &Config) -> Vec<(u16, HvCall)> {
    let mut v = Vec::new();
    let doms = cfg.domains as u16;
    let bools = [false, true];
    for caller in 0..doms {
        if cfg.evtchn {
            for remote in 0..doms {
                v.push((caller, HvCall::EvtchnAllocUnbound { remote }));
                for remote_port in 0..cfg.ports as u32 {
                    v.push((
                        caller,
                        HvCall::EvtchnBindInterdomain {
                            remote,
                            remote_port,
                        },
                    ));
                }
            }
            for vcpu in 0..cfg.vcpus as u32 {
                for virq in 0..2u8 {
                    v.push((caller, HvCall::EvtchnBindVirq { vcpu, virq }));
                }
                v.push((caller, HvCall::EvtchnBindIpi { vcpu }));
            }
            for port in 0..cfg.ports as u32 {
                v.push((caller, HvCall::EvtchnClose { port }));
                v.push((caller, HvCall::EvtchnSend { port }));
                v.push((caller, HvCall::EvtchnMask { port }));
                v.push((caller, HvCall::EvtchnUnmask { port }));
                v.push((caller, HvCall::EvtchnConsume { port }));
            }
        }
        if cfg.grant {
            for gref in 0..cfg.grants as u32 {
                for grantee in 0..doms {
                    for &readonly in &bools {
                        for frame in 0..cfg.frames as u32 {
                            v.push((
                                caller,
                                HvCall::GrantAccess {
                                    gref,
                                    grantee,
                                    frame,
                                    readonly,
                                },
                            ));
                        }
                    }
                }
                v.push((caller, HvCall::GrantEndAccess { gref }));
                for grantor in 0..doms {
                    for &writable in &bools {
                        v.push((
                            caller,
                            HvCall::GrantMap {
                                grantor,
                                gref,
                                writable,
                            },
                        ));
                        v.push((
                            caller,
                            HvCall::GrantCopy {
                                grantor,
                                gref,
                                write: writable,
                            },
                        ));
                    }
                }
            }
            for handle in 0..cfg.handles {
                v.push((caller, HvCall::GrantUnmap { handle }));
            }
        }
        if cfg.sched {
            for vcpu in 0..cfg.vcpus as u32 {
                v.push((caller, HvCall::SchedAdmit { vcpu }));
                v.push((caller, HvCall::SchedWake { vcpu }));
                v.push((caller, HvCall::SchedBlock { vcpu, now: NOW }));
                v.push((caller, HvCall::SchedPreempt { vcpu, now: NOW }));
                v.push((caller, HvCall::SchedOffline { vcpu, now: NOW }));
                for pcpu in 0..cfg.pcpus as u32 {
                    v.push((
                        caller,
                        HvCall::SchedRun {
                            vcpu,
                            pcpu,
                            now: NOW,
                        },
                    ));
                }
            }
        }
        if cfg.p2m {
            for mfn in 0..cfg.frames as u32 {
                v.push((caller, HvCall::P2mAllocate { mfn }));
                v.push((caller, HvCall::P2mFree { mfn }));
                v.push((caller, HvCall::P2mUnpin { mfn }));
                for &level in &cfg.levels {
                    v.push((caller, HvCall::P2mPin { mfn, level }));
                }
                for slot in 0..2u32 {
                    v.push((caller, HvCall::P2mUnlink { parent: mfn, slot }));
                    for child in 0..cfg.frames as u32 {
                        // Every (writable, leaf) shape. `writable`: a writable vs a read-only
                        // entry — the read-only leaf is the linear-map case, one that may point
                        // at a live page table. `leaf`: an interior entry (descends one level)
                        // vs a leaf (maps a page and terminates — a *superpage* when its parent
                        // is above `L1`). Driving both is what makes the model-checker build,
                        // and prove sound, an `L2`→leaf 2 MiB superpage as well as the interior
                        // `L2`→`L1` edge, over the same reachable-state sweep.
                        for &writable in &bools {
                            for &leaf in &bools {
                                v.push((
                                    caller,
                                    HvCall::P2mLink {
                                        parent: mfn,
                                        slot,
                                        child,
                                        writable,
                                        leaf,
                                    },
                                ));
                            }
                        }
                    }
                }
            }
        }
        if cfg.create {
            // Every (caller, target, may_create) triple — so the authority-denied path (a
            // caller without `may_create`, a no-op), the already-alive path, and the
            // authorized Dead→Live birth (including minting a `may_create` child) are all
            // explored. Only dom0 boots with `may_create`, so bringing a second domain up is
            // the *only* way the enumeration reaches any two-live-domain state (and the
            // creator gains control of it — the root of every control edge) — the
            // cross-domain seams and the per-target authority both depend on it.
            for target in 0..doms {
                for &may_create in &bools {
                    v.push((caller, HvCall::DomainCreate { target, may_create }));
                }
            }
        }
        if cfg.destroy {
            // Every (caller, target) pair — so both the authority-denied path (a caller with
            // no control of the peer, a no-op) and the authorized path (a controller or a
            // self-destroy) are exhaustively explored.
            for target in 0..doms {
                v.push((caller, HvCall::DomainDestroy { target, now: NOW }));
            }
        }
        if cfg.delegate {
            // Every (caller, target, other) triple for both delegate and revoke — so the
            // authority-denied paths (a caller that does not control `target`), the guards
            // (a Dead or self recipient), and the successful edge mutations are all explored.
            // Delegation makes the control matrix *mutable*, so this is what proves the
            // ControlEdgeDeadEndpoint invariant holds over every reachable edge configuration,
            // not just the ones creation alone can reach.
            for target in 0..doms {
                for other in 0..doms {
                    v.push((caller, HvCall::ControlGrant { target, to: other }));
                    v.push((
                        caller,
                        HvCall::ControlRevoke {
                            target,
                            from: other,
                        },
                    ));
                }
            }
        }
    }
    v
}

fn level_tag(ty: Option<PageType>) -> u64 {
    match ty {
        None => 0,
        Some(PageType::Writable) => 1,
        Some(PageType::PageTable(PtLevel::L1)) => 2,
        Some(PageType::PageTable(PtLevel::L2)) => 3,
        Some(PageType::PageTable(PtLevel::L3)) => 4,
        Some(PageType::PageTable(PtLevel::L4)) => 5,
    }
}

/// A canonical fingerprint of the whole integrated state. Two states share a key iff
/// they are behaviourally identical, so BFS deduplication on it neither merges distinct
/// states (which would drop coverage) nor splits equivalent ones needlessly. It keeps
/// every field a future transition can read and drops the ones none can — a vCPU's
/// accrued `runtime`/`dispatched_at` (gate nothing) and a frame's `pt_level` while it is
/// untyped (dead). Grant *handle* identity is kept (unmap targets a handle); page-table
/// edges are keyed by `(parent, slot)`, so their *set* — sorted here — is canonical.
pub fn state_key(hv: &Hypervisor) -> Vec<u64> {
    let mut k = Vec::new();

    let e = hv.evtchn();
    for dom in 0..e.domain_count() as u16 {
        for port in 0..e.port_count(dom) as u32 {
            let (tag, a, b) = match e.state_of(dom, port) {
                Some(PortState::Free) | None => (0, 0, 0),
                Some(PortState::Unbound { remote }) => (1, u64::from(remote), 0),
                Some(PortState::Interdomain {
                    remote,
                    remote_port,
                }) => (2, u64::from(remote), u64::from(remote_port)),
                Some(PortState::Virq { vcpu, virq }) => (3, u64::from(vcpu), u64::from(virq)),
                Some(PortState::Ipi { vcpu }) => (4, u64::from(vcpu), 0),
            };
            k.extend([
                tag,
                a,
                b,
                e.is_pending(dom, port) as u64,
                e.is_masked(dom, port) as u64,
            ]);
        }
    }
    k.push(0xFFFF_0001);

    let g = hv.grant();
    for dom in 0..g.domain_count() as u16 {
        for gref in 0..g.entry_count(dom) as u32 {
            match g.grant_entry(dom, gref) {
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
    }
    // Handle layout, trailing free slots trimmed (behaviourally irrelevant).
    let slots = g.handle_slots();
    let live = (0..slots)
        .rev()
        .find(|&h| g.mapping_at(h as u32).is_some())
        .map(|h| h + 1)
        .unwrap_or(0);
    for h in 0..live {
        match g.mapping_at(h as u32) {
            Some((ge, gr, gref, w)) => {
                k.extend([1, u64::from(ge), u64::from(gr), u64::from(gref), w as u64])
            }
            None => k.extend([0, 0, 0, 0, 0]),
        }
    }
    k.push(0xFFFF_0002);

    let s = hv.sched();
    for dom in 0..s.domain_count() as u16 {
        for vcpu in 0..s.vcpu_count(dom) as u32 {
            // Run state only — runtime and dispatched_at gate no transition.
            let (tag, p) = match s.state_of(dom, vcpu) {
                Some(RunState::Offline) | None => (0, 0),
                Some(RunState::Runnable) => (1, 0),
                Some(RunState::Running { pcpu }) => (2, u64::from(pcpu)),
                Some(RunState::Blocked) => (3, 0),
            };
            k.extend([tag, p]);
        }
    }
    for pcpu in 0..s.pcpu_count() as u32 {
        match s.occupant(pcpu) {
            Some((d, v)) => k.extend([1, u64::from(d), u64::from(v)]),
            None => k.extend([0, 0, 0]),
        }
    }
    k.push(0xFFFF_0003);

    let p = hv.p2m();
    for mfn in 0..p.frame_count() as u32 {
        match p.owner_of(mfn) {
            Some(owner) => {
                let ty = p.current_type(mfn);
                let pt_refs = match ty {
                    Some(pt @ PageType::PageTable(_)) => p.type_refs(mfn, pt).unwrap_or(0),
                    _ => 0,
                };
                k.extend([
                    1,
                    u64::from(owner),
                    u64::from(p.refs(mfn).unwrap_or(0)),
                    u64::from(p.type_refs(mfn, PageType::Writable).unwrap_or(0)),
                    u64::from(pt_refs),
                    level_tag(ty),
                    p.is_pinned(mfn) as u64,
                ]);
            }
            None => k.extend([0, 0, 0, 0, 0, 0, 0]),
        }
    }
    let mut edges = p.link_edges();
    edges.sort_unstable();
    k.push(edges.len() as u64);
    for (par, slot, ch, writable, leaf) in edges {
        k.extend([
            u64::from(par),
            u64::from(slot),
            u64::from(ch),
            writable as u64,
            // `leaf` is behaviourally live: it selects which reference `unlink` releases, and
            // it distinguishes a superpage (a leaf above `L1`) from an interior table pointer.
            // Two states that agree on every edge's (parent, slot, child, writable) but differ
            // in an edge's shape are *not* the same state — keep the bit so they never merge.
            leaf as u64,
        ]);
    }
    k.push(0xFFFF_0004);

    // Domain lifecycle & authority gate *every* transition (a Dead slot can do nothing;
    // only a `may_create` domain may create; only a controller may destroy a given peer),
    // so liveness, `may_create`, and the whole control matrix are behaviourally live and
    // must be part of the fingerprint — else two states differing only in who is alive, may
    // create, or controls whom would wrongly merge, dropping coverage.
    //
    // Note what is deliberately *absent*: no per-slot incarnation/generation. A slot taken
    // Live→Dead→Live with identical contents fingerprints identically to one never destroyed
    // — the two states are behaviourally the same, because domain-ID reuse soundness rests on
    // clearing stale references, not on distinguishing incarnations (there is no generation
    // counter to distinguish). That is what keeps the reachable set finite under
    // create/destroy/recreate cycling: an unbounded incarnation would split every rebirth into
    // a fresh state and the BFS would never close. The `DeadDomainReferenced` invariant is what
    // makes this sound — a reborn slot provably inherits nothing, so it *is* the same state.
    for dom in 0..hv.domain_count() as u16 {
        k.push(hv.is_live(dom) as u64);
        k.push(hv.may_create(dom) as u64);
    }
    // Fingerprint each control edge's *provenance*, not just its presence: two states
    // differing only in who delegated an edge are behaviourally distinct — they permit
    // different chain-restricted revokes (an ancestor may prune where a non-ancestor is
    // Denied) — so keying presence alone would wrongly merge them and drop coverage
    // (design-lesson #7). Absent=0, Root=1, Via(d)=2+d, an injective tag per cell value.
    for holder in 0..hv.domain_count() as u16 {
        for target in 0..hv.domain_count() as u16 {
            let tag = match hv.control_edge(holder, target) {
                Control::Absent => 0,
                Control::Root => 1,
                Control::Via(d) => 2 + u64::from(d),
            };
            k.push(tag);
        }
    }

    k
}

/// Exhaustively enumerate every state reachable within `cfg.depth` hypercalls, checking
/// the integrated invariant at each. Returns the distinct-state count and, if any state
/// violates the invariant, a shortest hypercall path to it.
pub fn enumerate(cfg: &Config) -> EnumOutcome {
    let universe = ops(cfg);
    let init = Hypervisor::new(
        cfg.domains,
        cfg.ports,
        cfg.grants,
        cfg.vcpus,
        cfg.pcpus,
        cfg.frames,
    );

    // Each visited state records how it was first reached, for counterexample traces.
    // The root maps to itself with no op.
    let mut came_from: CameFrom = HashMap::new();
    let mut frontier: Vec<(StateKey, Hypervisor)> = Vec::new();
    let root_key = state_key(&init);
    came_from.insert(root_key.clone(), None);
    frontier.push((root_key, init));
    let mut truncated = false;

    for _ in 0..cfg.depth {
        let mut next: Vec<(StateKey, Hypervisor)> = Vec::new();
        for (_, hv) in &frontier {
            for &(caller, call) in &universe {
                let mut h = hv.clone();
                let _: Result<HvOutcome, _> = h.dispatch(caller, call);
                if !h.invariants_hold() {
                    let key = state_key(&h);
                    came_from.insert(key.clone(), Some((state_key(hv), caller, call)));
                    return EnumOutcome {
                        states: came_from.len(),
                        truncated,
                        violation: Some(trace(&came_from, &key)),
                    };
                }
                let key = state_key(&h);
                if !came_from.contains_key(&key) {
                    if came_from.len() >= cfg.max_states {
                        truncated = true;
                        continue;
                    }
                    came_from.insert(key.clone(), Some((state_key(hv), caller, call)));
                    next.push((key, h));
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    EnumOutcome {
        states: came_from.len(),
        truncated,
        violation: None,
    }
}

/// Reconstruct the hypercall path from the root to `key` by walking parent links.
fn trace(came_from: &CameFrom, key: &[u64]) -> Vec<(u16, HvCall)> {
    let mut path = Vec::new();
    let mut cur = key.to_vec();
    while let Some(Some((parent, caller, call))) = came_from.get(&cur) {
        path.push((*caller, *call));
        cur = parent.clone();
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run an enumeration and assert it closed (not truncated) with no invariant
    // violation, returning the distinct-state count. For the CI-sized configs.
    fn expect_clean(cfg: &Config) -> usize {
        let out = enumerate(cfg);
        assert!(
            out.violation.is_none(),
            "invariant violated after: {:?}",
            out.violation.unwrap()
        );
        assert!(
            !out.truncated,
            "enumeration hit the {}-state cap before closing — raise max_states or lower depth",
            cfg.max_states
        );
        out.states
    }

    // For the deep on-demand sweeps: assert only that no reachable state violates an
    // invariant. Hitting the state cap is fine — millions of states proven clean is the
    // point — so truncation is tolerated (and reported).
    fn expect_no_violation(cfg: &Config) {
        let out = enumerate(cfg);
        assert!(
            out.violation.is_none(),
            "invariant violated after: {:?}",
            out.violation.unwrap()
        );
        eprintln!(
            "deep sweep: {} states explored{}",
            out.states,
            if out.truncated {
                " (hit the state cap — a lower bound)"
            } else {
                " (closed — complete for this depth)"
            }
        );
    }

    fn grant_p2m_cfg(depth: u32) -> Config {
        Config {
            grant: true,
            p2m: true,
            create: true,
            destroy: true,
            depth,
            ..Config::tiny()
        }
    }

    fn evtchn_sched_cfg(depth: u32) -> Config {
        Config {
            evtchn: true,
            sched: true,
            create: true,
            destroy: true,
            vcpus: 2,
            depth,
            ..Config::tiny()
        }
    }

    /// The domain lifecycle in focus: create + destroy + the cheapest way for a domain to
    /// *acquire* a resource (own a frame, pin it as a page table), so the standing
    /// lifecycle invariants have real content to check — a domain that allocates a frame
    /// and is then destroyed must return to a clean, unprivileged `Dead` shell. Small
    /// universe, so it runs deep: every reachable interleaving of birth, resource
    /// acquisition, and death is proven to leave every `Dead` slot clean and unprivileged
    /// (and to never let a domain self-elevate — no reachable state has privilege without a
    /// privileged creator behind it).
    fn lifecycle_cfg(depth: u32) -> Config {
        Config {
            p2m: true,
            create: true,
            destroy: true,
            delegate: true,
            depth,
            ..Config::tiny()
        }
    }

    /// The delegation forest in focus: create + destroy + delegate over *four* domains, every
    /// other subsystem off. Four is the smallest world that can form a depth-2 delegation chain
    /// over a fixed target (creator → delegate → sub-delegate = three controllers + the target),
    /// so it is the smallest world where chain-restricted revocation, subtree cascades, and
    /// delegator-death cascades have real content — a two-domain world cannot even *represent* a
    /// `Via` edge. The control matrix is orthogonal to frames/ports/vCPUs (they meet only
    /// through create/destroy liveness), so dropping p2m keeps the state space tractable while
    /// still covering the whole authority structure: every reachable delegation tree is proven
    /// to keep each edge live-endpointed *and* rooted acyclically
    /// (`ControlEdgeDeadEndpoint` + `ControlEdgeOrphaned`).
    fn delegation_cfg(depth: u32) -> Config {
        Config {
            domains: 4,
            create: true,
            destroy: true,
            delegate: true,
            depth,
            ..Config::tiny()
        }
    }

    /// Domain-ID reuse in focus: create + destroy + *both* cross-domain reference kinds
    /// (grants and interdomain event channels), so a slot can be granted to / opened a
    /// channel to, torn down, and reborn — the config that can even *represent* the reuse
    /// vectors. The lifecycle sweep has p2m but no evtchn/grant, so it could never build an
    /// inbound reference to a slot it then destroys (design-lesson #13f — the tiny universe
    /// must be big enough to hold the feature's witness). Here every reachable interleaving
    /// of birth, cross-domain referencing, death, and rebirth is proven to leave no stale
    /// reference naming a `Dead` slot (`DeadDomainReferenced`): the mint gate refuses one to a
    /// Dead target, and teardown sweeps away every one to a dying slot. Were either removed,
    /// this same sweep would surface a counterexample — the destroy-with-an-inbound-grant (or
    /// -channel) state that the pre-fix code left reachable. Two domains is the smallest world
    /// that forms a cross-domain reference and reuses a slot (dom0 creates and reuses slot 1).
    fn reuse_cfg(depth: u32) -> Config {
        Config {
            evtchn: true,
            grant: true,
            create: true,
            destroy: true,
            depth,
            ..Config::tiny()
        }
    }

    fn all_cfg(depth: u32) -> Config {
        Config {
            evtchn: true,
            grant: true,
            sched: true,
            p2m: true,
            create: true,
            destroy: true,
            delegate: true,
            depth,
            ..Config::tiny()
        }
    }

    // The CI-sized enumerations run at a shallow depth so the whole suite stays a few
    // seconds; the `#[ignore]`d twins below crank the same configs far deeper for an
    // on-demand exhaustive sweep (`cargo test --release -- --ignored`).

    /// The grant↔page-type and page-table↔grant seams, exhaustively: every reachable
    /// state of a 2-domain / 2-frame / 2-grant world under all grant and page-table
    /// hypercalls (including cross-domain foreign links and teardown) holds every
    /// invariant. A *proof* over the seam, not a sample. The CI depth is too shallow to
    /// reach a foreign *interior* node share (an `L2`→foreign-`L1` edge needs ~6 hypercalls
    /// to set up — create, allocate, pin an `L2`, allocate the peer's frame, grant it, then
    /// link); the deep twin below runs past that, so it exhaustively covers foreign node
    /// sharing, not just leaves.
    #[test]
    fn grant_and_p2m_seams_are_exhaustively_sound() {
        let states = expect_clean(&grant_p2m_cfg(4));
        assert!(states > 500, "suspiciously few states explored: {states}");
    }

    /// The event↔scheduler (lost-wakeup) seam, exhaustively: every reachable state under
    /// all event-channel and scheduler hypercalls keeps no deliverable event resting on a
    /// blocked vCPU.
    #[test]
    fn evtchn_and_sched_seam_is_exhaustively_sound() {
        let states = expect_clean(&evtchn_sched_cfg(4));
        assert!(states > 500, "suspiciously few states explored: {states}");
    }

    /// The whole integrated core at once, shallow: every state reachable in a few
    /// hypercalls under *every* subsystem holds the combined invariant. Depth is small
    /// because the full op set branches hard, but even a shallow all-subsystem sweep
    /// exercises cross-seam interleavings a per-seam run cannot.
    #[test]
    fn the_integrated_core_is_exhaustively_sound_shallow() {
        expect_clean(&all_cfg(3));
    }

    /// The domain lifecycle, exhaustively: every reachable interleaving of create, destroy,
    /// and frame ownership over a tiny world leaves every `Dead` slot a clean, unprivileged
    /// shell — teardown's postcondition proven as a standing invariant, and privilege proven
    /// to never materialise without a privileged creator.
    #[test]
    fn the_domain_lifecycle_is_exhaustively_sound() {
        let states = expect_clean(&lifecycle_cfg(6));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    /// The delegation forest, exhaustively (shallow): every reachable configuration of a
    /// four-domain create/destroy/delegate world keeps every control edge live-endpointed and
    /// rooted acyclically — a proof of `ControlEdgeOrphaned` (and its liveness cousin) over the
    /// full authority structure, including `Via` chains a two-domain world cannot form. The CI
    /// depth is kept modest so the suite stays quick; the deep twin below runs far enough to
    /// build, cascade, and prune depth-2 chains.
    #[test]
    fn the_delegation_forest_is_exhaustively_sound() {
        let states = expect_clean(&delegation_cfg(4));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    /// Domain-ID reuse, exhaustively (shallow): every reachable interleaving of a two-domain
    /// create/destroy world under *both* grants and interdomain event channels keeps no stale
    /// reference naming a `Dead` slot — a proof of `DeadDomainReferenced` over every way a
    /// slot can be referenced, torn down, and reborn. The CI depth is kept modest; the deep
    /// twin below runs far enough to grant-and-channel a slot, destroy it, and revive it.
    #[test]
    fn domain_id_reuse_is_exhaustively_sound() {
        let states = expect_clean(&reuse_cfg(4));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    /// The deep domain-ID-reuse sweep. Depth 8 is enough to bring up a slot, grant it a frame
    /// (or open an interdomain channel to it), destroy it, and recreate it — so it
    /// exhaustively proves the mint gate and teardown sweep leave no reachable state in which a
    /// grant or a half-open port names a Dead slot, across every create/destroy interleaving.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn domain_id_reuse_deep() {
        expect_no_violation(&reuse_cfg(8));
    }

    /// The deep grant↔page-type / page-table↔grant sweep. Depth 7 is enough to reach a
    /// cross-domain page-table *node* share (a foreign interior entry, an `L2` pointing at
    /// another domain's `L1` node) and everything under it, so this exhaustively proves the
    /// `UnauthorizedForeignLink` invariant over foreign subtrees as well as foreign leaves.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn grant_and_p2m_seams_deep() {
        expect_no_violation(&grant_p2m_cfg(7));
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn domain_lifecycle_deep() {
        expect_no_violation(&lifecycle_cfg(12));
    }

    /// The deep delegation-forest sweep. Depth 8 over four domains is enough to build a
    /// depth-2 delegation chain (create the target, create two intermediaries, delegate
    /// creator → A → B) and then exercise every revoke and destroy against it — so it
    /// exhaustively proves chain-restricted revocation, subtree cascades, and delegator-death
    /// cascades never leave an orphaned or cyclic edge.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn delegation_forest_deep() {
        expect_no_violation(&delegation_cfg(8));
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn evtchn_and_sched_seam_deep() {
        expect_no_violation(&evtchn_sched_cfg(8));
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn integrated_core_deep() {
        expect_no_violation(&all_cfg(5));
    }

    /// The dedup key is sound: distinct observable states must not collapse. A frame
    /// owned by domain 0 and the same frame owned by domain 1 are different states.
    #[test]
    fn state_key_separates_distinguishable_states() {
        let mut a = Hypervisor::new(2, 1, 1, 1, 1, 2);
        let mut b = Hypervisor::new(2, 1, 1, 1, 1, 2);
        // Domain 1 boots Dead, so bring it up before it can own a frame; dom0 already
        // owns frame 0 in `a`. (Creation itself makes the two states differ in liveness,
        // which is also part of what `state_key` must distinguish.)
        a.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        b.dispatch(
            0,
            HvCall::DomainCreate {
                target: 1,
                may_create: false,
            },
        )
        .unwrap();
        b.dispatch(1, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        assert_ne!(state_key(&a), state_key(&b));
        // ...but two paths to the *same* state share a key (a frame allocated then freed
        // equals one never allocated — modulo the handle/runtime fields we exclude).
        let mut c = Hypervisor::new(2, 1, 1, 1, 1, 2);
        c.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        c.dispatch(0, HvCall::P2mFree { mfn: 0 }).unwrap();
        assert_eq!(state_key(&c), state_key(&Hypervisor::new(2, 1, 1, 1, 1, 2)));
    }
}
